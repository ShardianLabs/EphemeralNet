#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/network/SessionManager.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
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

    const auto port_a = node_a.transport_port();

    const bool handshake_ab = node_a.perform_handshake(node_b.id(), node_b.public_identity());
    const bool handshake_ba = node_b.perform_handshake(node_a.id(), node_a.public_identity());
    assert(handshake_ab);
    assert(handshake_ba);

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
    assert(connected);

    const std::vector<std::uint8_t> payload{'O', 'K', '!'};
    const bool sent = node_b.send_secure(node_a.id(), std::span<const std::uint8_t>(payload));
    assert(sent);

    const auto status = future.wait_for(2s);
    assert(status == std::future_status::ready);
    const auto received = future.get();
    assert(received == payload);

    node_a.stop_transport();
    node_b.stop_transport();

    return 0;
}
