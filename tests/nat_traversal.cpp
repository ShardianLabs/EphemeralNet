#include "ephemeralnet/network/NatTraversal.hpp"

#include "ephemeralnet/Config.hpp"

#include <cassert>

int main() {
    ephemeralnet::Config config{};
    config.identity_seed = 0x12345678u;
    config.nat_upnp_start_port = 41000;
    config.nat_upnp_end_port = 41010;

    ephemeralnet::network::NatTraversalManager manager{config};
    const auto result = manager.coordinate("192.168.1.10", 35000);

    assert(result.external_port >= config.nat_upnp_start_port);
    assert(result.external_port < config.nat_upnp_end_port);
    assert(!result.external_address.empty());
    assert(result.diagnostics.size() >= 3);

    return 0;
}
