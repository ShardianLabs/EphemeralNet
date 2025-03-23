#include "ephemeralnet/core/Node.hpp"

#include <cassert>
#include <chrono>
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
    ephemeralnet::Config config{};
    config.identity_seed = 0xDEADBEEFu;
    config.nat_upnp_start_port = 44000;
    config.nat_upnp_end_port = 44010;
    config.nat_retry_interval = 1s;

    const auto node_id = make_peer_id(0x42);

    ephemeralnet::Node node(node_id, config);
    node.start_transport(0);

    const auto status = node.nat_status();
    assert(status.has_value());
    assert(!status->external_address.empty());
    assert(status->external_port > 0);
    assert(status->diagnostics.size() == 3);

    const auto initial_diagnostics = status->diagnostics;
    node.tick();
    const auto status_after_tick = node.nat_status();
    assert(status_after_tick.has_value());
    assert(status_after_tick->diagnostics == initial_diagnostics);

    node.stop_transport();

    return 0;
}
