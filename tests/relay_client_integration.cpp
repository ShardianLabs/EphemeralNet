#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/network/RelayClient.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/protocol/Message.hpp"
#include "ephemeralnet/relay/EventLoop.hpp"
#include "ephemeralnet/relay/RelayServer.hpp"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <span>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t value) {
    ephemeralnet::PeerId id{};
    id.fill(value);
    return id;
}

void wait_for_registration(const ephemeralnet::network::RelayClient& client) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!client.has_active_allocation()) {
        if (std::chrono::steady_clock::now() > deadline) {
            throw std::runtime_error("RelayClient did not register in time");
        }
        std::this_thread::sleep_for(50ms);
    }
}

bool wait_for_sessions(ephemeralnet::network::SessionManager& manager) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (manager.active_session_count() == 0) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::this_thread::sleep_for(20ms);
    }
    return true;
}

}  // namespace

int main() {
    try {
        std::cout << "[relay-test] starting" << std::endl;
        constexpr std::uint16_t kRelayPort = 49800;

        ephemeralnet::relay::EventLoop loop;
        ephemeralnet::relay::RelayServerConfig relay_config;
        relay_config.listen_host = "127.0.0.1";
        relay_config.listen_port = kRelayPort;

        ephemeralnet::relay::RelayServer server(loop, relay_config);
        if (!server.start()) {
            throw std::runtime_error("Failed to start relay server");
        }

        std::cout << "[relay-test] server listening" << std::endl;
        std::thread loop_thread([&]() { loop.run(); });
        struct LoopGuard {
            std::thread& thread;
            ephemeralnet::relay::RelayServer& server;
            ephemeralnet::relay::EventLoop& loop;
            ~LoopGuard() {
                server.stop();
                loop.stop();
                if (thread.joinable()) {
                    thread.join();
                }
            }
        } loop_guard{loop_thread, server, loop};

        auto peer_a = make_peer_id(0xA1);
        auto peer_b = make_peer_id(0xB2);

        ephemeralnet::network::SessionManager session_a(peer_a);
        ephemeralnet::network::SessionManager session_b(peer_b);

        session_a.start(0);
        session_b.start(0);
        std::cout << "[relay-test] session managers started" << std::endl;

        std::array<std::uint8_t, 32> shared_key{};
        shared_key.fill(0x42);
        session_a.register_peer_key(peer_b, shared_key);
        session_b.register_peer_key(peer_a, shared_key);

        using HandshakeAcceptance = ephemeralnet::network::SessionManager::HandshakeAcceptance;
        auto handshake_handler = [&](const ephemeralnet::PeerId& expected_peer) {
            return [shared_key, expected_peer](const ephemeralnet::PeerId& peer_id,
                                              const ephemeralnet::protocol::TransportHandshakePayload& payload)
                       -> std::optional<HandshakeAcceptance> {
                if (peer_id != expected_peer) {
                    return std::nullopt;
                }

                const auto negotiated_version = std::clamp<std::uint8_t>(
                    payload.requested_version,
                    ephemeralnet::protocol::kMinimumMessageVersion,
                    ephemeralnet::protocol::kCurrentMessageVersion);

                ephemeralnet::protocol::Message ack{};
                ack.version = negotiated_version;
                ack.type = ephemeralnet::protocol::MessageType::HandshakeAck;
                ephemeralnet::protocol::HandshakeAckPayload ack_payload{};
                ack_payload.accepted = true;
                ack_payload.negotiated_version = negotiated_version;
                ack_payload.responder_public = payload.public_identity;
                ack.payload = ack_payload;

                const auto key_span = std::span<const std::uint8_t>(shared_key.data(), shared_key.size());
                auto encoded_ack = ephemeralnet::protocol::encode_signed(ack, key_span);

                HandshakeAcceptance acceptance{};
                acceptance.accepted = true;
                acceptance.session_key = shared_key;
                acceptance.ack_payload = std::move(encoded_ack);
                return acceptance;
            };
        };

        session_a.set_handshake_handler(handshake_handler(peer_b));
        session_b.set_handshake_handler(handshake_handler(peer_a));

        std::mutex message_mutex;
        std::condition_variable message_cv;
        std::vector<std::uint8_t> received_payload;

        session_a.set_message_handler([
            &](const ephemeralnet::network::TransportMessage& message) {
                if (message.peer_id != peer_b) {
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(message_mutex);
                    received_payload = message.payload;
                }
                message_cv.notify_one();
            });

        ephemeralnet::Config config_a;
        config_a.relay_enabled = true;
        config_a.relay_endpoints.push_back({"127.0.0.1", kRelayPort});

        ephemeralnet::Config config_b = config_a;

        ephemeralnet::network::RelayClient client_a(config_a, session_a, peer_a);
        ephemeralnet::network::RelayClient client_b(config_b, session_b, peer_b);

        client_a.start();
        std::cout << "[relay-test] relay client A started" << std::endl;
        wait_for_registration(client_a);
        std::cout << "[relay-test] client A registered" << std::endl;

        const auto hint = client_a.current_hint(10);
        if (!hint.has_value()) {
            throw std::runtime_error("RelayClient did not provide a discovery hint");
        }

        std::cout << "[relay-test] connecting client B via hint" << std::endl;
        if (!client_b.connect_via_hint(*hint, peer_a)) {
            throw std::runtime_error("connect_via_hint failed");
        }
        std::cout << "[relay-test] connect_via_hint returned true" << std::endl;

        if (!wait_for_sessions(session_a) || !wait_for_sessions(session_b)) {
            throw std::runtime_error("SessionManagers never observed an active session");
        }
        std::cout << "[relay-test] sessions established" << std::endl;

        const std::vector<std::uint8_t> payload{'r', 'e', 'l', 'a', 'y', '-', 't', 'e', 's', 't'};
        if (!session_b.send(peer_a, payload)) {
            throw std::runtime_error("Failed to send payload over relay session");
        }
        std::cout << "[relay-test] payload sent" << std::endl;

        {
            std::unique_lock<std::mutex> lock(message_mutex);
            if (!message_cv.wait_for(lock, 5s, [&]() { return received_payload == payload; })) {
                std::cout << "[relay-test] wait_for payload timed out" << std::endl;
                throw std::runtime_error("Relay session did not deliver payload to SessionManager A");
            }
            std::cout << "[relay-test] payload delivered" << std::endl;
        }

        std::cout << "[relay-test] stopping relay server" << std::endl;
        server.stop();
        loop.stop();
        if (loop_thread.joinable()) {
            loop_thread.join();
        }
        std::cout << "[relay-test] relay server stopped" << std::endl;

        std::cout << "[relay-test] stopping client A" << std::endl;
        client_a.stop();
        std::cout << "[relay-test] client A stopped" << std::endl;

        std::cout << "[relay-test] stopping client B" << std::endl;
        client_b.stop();
        std::cout << "[relay-test] clients stopped" << std::endl;

        session_a.stop();
        session_b.stop();
        std::cout << "[relay-test] session managers stopped" << std::endl;

        std::cout << "RelayClient integration test passed" << std::endl;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "RelayClient integration test failed: " << ex.what() << std::endl;
        return 1;
    }
}
