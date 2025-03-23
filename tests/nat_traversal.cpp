#include "ephemeralnet/network/NatTraversal.hpp"

#include "ephemeralnet/Config.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace {

using ephemeralnet::Config;
using ephemeralnet::network::NatTraversalManager;
using ephemeralnet::network::NatTraversalResult;

std::optional<std::uint32_t> find_seed_matching(const Config& base_config,
                                                const std::function<bool(const NatTraversalResult&)>& predicate,
                                                std::uint32_t search_limit = 5000u) {
    for (std::uint32_t seed = 0; seed < search_limit; ++seed) {
        Config config = base_config;
        config.identity_seed = seed;
        NatTraversalManager manager{config};
        const auto result = manager.coordinate("10.0.0.5", 45000);
        if (predicate(result)) {
            return seed;
        }
    }
    return std::nullopt;
}

}  // namespace

int main() {
    {
        Config config{};
        config.identity_seed = 0x12345678u;
        config.nat_upnp_start_port = 41000;
        config.nat_upnp_end_port = 41010;

        NatTraversalManager manager{config};
        const auto first = manager.coordinate("192.168.1.10", 35000);

        assert(first.upnp_available);
        assert(first.external_port >= config.nat_upnp_start_port);
        assert(first.external_port < config.nat_upnp_end_port);
        assert(!first.external_address.empty());
        assert(first.diagnostics.size() == 3);

        const auto second = manager.coordinate("192.168.1.10", first.external_port);
        assert(second.upnp_available);
        assert(second.external_port == first.external_port);
        assert(second.diagnostics.size() == 3);
    }

    {
        Config config{};
        config.identity_seed = 0xCAFEBABEu;
        config.nat_upnp_start_port = 0;
        config.nat_upnp_end_port = 0;

        NatTraversalManager manager{config};
        const auto result = manager.coordinate("172.16.0.20", 47000);

        assert(!result.upnp_available);
        assert(result.external_port == 47000);
        const auto upnp_message = std::find_if(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("UPnP unavailable") != std::string::npos;
        });
        assert(upnp_message != result.diagnostics.end());
    }

    {
        Config base_config{};
        base_config.nat_upnp_start_port = 42000;
        base_config.nat_upnp_end_port = 42010;

        const auto stun_failure_seed = find_seed_matching(base_config, [](const NatTraversalResult& result) {
            return !result.stun_succeeded;
        });
        assert(stun_failure_seed.has_value());

        base_config.identity_seed = *stun_failure_seed;
        NatTraversalManager manager{base_config};
        const auto failure = manager.coordinate("10.1.1.1", 36000);
        assert(!failure.stun_succeeded);
        assert(!failure.external_address.empty());
        const auto stun_message = std::find_if(failure.diagnostics.begin(), failure.diagnostics.end(), [](const std::string& message) {
            return message.find("STUN discovery failed") != std::string::npos;
        });
        assert(stun_message != failure.diagnostics.end());
    }

    {
        Config base_config{};
        base_config.nat_upnp_start_port = 43000;
        base_config.nat_upnp_end_port = 43010;

        const auto punch_deferred_seed = find_seed_matching(base_config, [](const NatTraversalResult& result) {
            return !result.hole_punch_ready;
        });
        assert(punch_deferred_seed.has_value());

        base_config.identity_seed = *punch_deferred_seed;
        NatTraversalManager manager{base_config};
        const auto deferred = manager.coordinate("192.168.50.4", 38000);
        assert(!deferred.hole_punch_ready);
        const auto punch_message = std::find_if(deferred.diagnostics.begin(), deferred.diagnostics.end(), [](const std::string& message) {
            return message.find("Hole punching deferred") != std::string::npos;
        });
        assert(punch_message != deferred.diagnostics.end());
    }

    return 0;
}
