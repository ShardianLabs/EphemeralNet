#include "ephemeralnet/core/Node.hpp"
#include "test_access.hpp"

#include "ephemeralnet/network/SessionManager.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <span>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::Config make_config(std::uint32_t seed) {
    ephemeralnet::Config config{};
    config.handshake_cooldown = 1s;
    config.identity_seed = seed;
    return config;
}

}  // namespace

int main() {
    auto config_a = make_config(0x10u);
    auto config_b = make_config(0x20u);

    ephemeralnet::Node node_a{make_peer_id(0x01), config_a};
    ephemeralnet::Node node_b{make_peer_id(0x81), config_b};

    node_a.start_transport(0);
    node_b.start_transport(0);

    auto shutdown = [&]() {
        node_a.stop_transport();
        node_b.stop_transport();
    };

    auto require = [&](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "[SecureTransport] " << message << std::endl;
            shutdown();
            return false;
        }
        return true;
    };

    const auto port_a = node_a.transport_port();

    const auto pow_b = ephemeralnet::test::NodeTestAccess::handshake_work(node_b, node_a.id());
    const auto pow_a = ephemeralnet::test::NodeTestAccess::handshake_work(node_a, node_b.id());
    if (!require(pow_b.has_value(), "handshake work for node_b failed")) {
        return 1;
    }
    if (!require(pow_a.has_value(), "handshake work for node_a failed")) {
        return 1;
    }
    const bool handshake_ab = node_a.perform_handshake(node_b.id(), node_b.public_identity(), *pow_b);
    const bool handshake_ba = node_b.perform_handshake(node_a.id(), node_a.public_identity(), *pow_a);
    if (!require(handshake_ab, "node_a -> node_b handshake failed")) {
        return 1;
    }
    if (!require(handshake_ba, "node_b -> node_a handshake failed")) {
        return 1;
    }

    std::promise<std::vector<std::uint8_t>> promise;
    auto future = promise.get_future();
    std::atomic<bool> delivered{false};
    node_a.set_message_handler([&](const ephemeralnet::network::TransportMessage& message) {
        if (!delivered.exchange(true)) {
            promise.set_value(message.payload);
        }
    });

    std::this_thread::sleep_for(50ms);

    const bool connected = node_b.connect_peer(node_a.id(), "127.0.0.1", port_a);
    if (!require(connected, "node_b could not connect to node_a")) {
        return 1;
    }

    const std::vector<std::uint8_t> payload{'O', 'K', '!'};
    const bool sent = node_b.send_secure(node_a.id(), std::span<const std::uint8_t>(payload));
    if (!require(sent, "node_b failed to send secure payload")) {
        return 1;
    }

    const auto status = future.wait_for(2s);
    if (!require(status == std::future_status::ready, "timed out waiting for secure payload")) {
        return 1;
    }
    const auto received = future.get();
    if (!require(received == payload, "received payload does not match expected value")) {
        return 1;
    }

    shutdown();

    return 0;
}
