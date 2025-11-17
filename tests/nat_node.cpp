#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/network/NatTraversal.hpp"

#include <cassert>
#include <chrono>
#include <optional>
#include <string>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

}  // namespace

int main() {
    ephemeralnet::network::NatTraversalManager::TestHooks hooks{};
    hooks.stun_override = []() -> std::optional<ephemeralnet::network::NatTraversalManager::StunQueryResult> {
        ephemeralnet::network::NatTraversalManager::StunQueryResult result{};
        result.address = "203.0.113.9";
        result.reported_port = 47001;
        result.server = "test-stun";
        return result;
    };
    ephemeralnet::network::NatTraversalManager::set_test_hooks(&hooks);

    ephemeralnet::Config config{};
    config.identity_seed = 0xDEADBEEFu;
    config.nat_stun_enabled = true;
    config.nat_retry_interval = 1s;

    const auto node_id = make_peer_id(0x42);

    ephemeralnet::Node node(node_id, config);
    node.start_transport(0);

    const auto status = node.nat_status();
    assert(status.has_value());
    assert(!status->external_address.empty());
    assert(status->external_port > 0);
    assert(status->diagnostics.size() >= 2);
    assert(status->diagnostics[0].rfind("Initial endpoint assumption", 0) == 0);
    assert(status->diagnostics[1].rfind("STUN discovery succeeded", 0) == 0);

    const auto initial_diagnostics = status->diagnostics;
    node.tick();
    const auto status_after_tick = node.nat_status();
    assert(status_after_tick.has_value());
    assert(status_after_tick->diagnostics == initial_diagnostics);

    node.stop_transport();

    ephemeralnet::network::NatTraversalManager::set_test_hooks(nullptr);
    return 0;
}
