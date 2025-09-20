#include "ephemeralnet/network/AdvertiseDiscovery.hpp"
#include "ephemeralnet/network/NatTraversal.hpp"

#include "ephemeralnet/Config.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

using ephemeralnet::Config;
using ephemeralnet::network::NatTraversalManager;
using ephemeralnet::network::NatTraversalResult;
using ephemeralnet::network::AdvertiseDiscoveryResult;
using ephemeralnet::network::discover_control_advertise_candidates;
using ephemeralnet::network::select_public_advertise_candidate;

std::optional<std::uint32_t> find_seed_matching(const Config& base,
                                                const std::function<bool(const NatTraversalResult&)>& predicate,
                                                std::uint32_t search_limit = 10'000u) {
    for (std::uint32_t seed = 0; seed < search_limit; ++seed) {
        Config config = base;
        config.identity_seed = seed;
        NatTraversalManager manager{config};
        const auto result = manager.coordinate(config.control_host, config.control_port);
        if (predicate(result)) {
            return seed;
        }
    }
    return std::nullopt;
}

}  // namespace

int main() {
    Config base{};
    base.control_host = "10.0.0.5";
    base.control_port = 41000;

    const auto stun_seed = find_seed_matching(base, [](const NatTraversalResult& result) {
        return result.stun_succeeded;
    });
    assert(stun_seed.has_value());

    const auto failure_seed = find_seed_matching(base, [](const NatTraversalResult& result) {
        return !result.stun_succeeded;
    });
    assert(failure_seed.has_value());

    {
        Config config = base;
        config.identity_seed = *stun_seed;
        config.advertise_allow_private = true;
        const AdvertiseDiscoveryResult result = discover_control_advertise_candidates(config);
        assert(!result.candidates.empty());
        bool saw_upnp = false;
        bool saw_stun = false;
        for (const auto& candidate : result.candidates) {
            if (candidate.via == "upnp") {
                saw_upnp = true;
            }
            if (candidate.via == "stun") {
                saw_stun = true;
            }
            assert(!candidate.host.empty());
            assert(candidate.port != 0);
            assert(!candidate.diagnostics.empty());
        }
        assert(saw_upnp);
        assert(saw_stun);
        assert(result.conflict);
        assert(!result.warnings.empty());
    }

    {
        Config config = base;
        config.identity_seed = *stun_seed;
        const auto result = discover_control_advertise_candidates(config);
        assert(result.candidates.empty());
        assert(!result.conflict);
        assert(result.warnings.empty());
    }

    {
        Config config = base;
        config.identity_seed = *failure_seed;
        config.advertise_allow_private = true;
        const auto result = discover_control_advertise_candidates(config);
        assert(!result.candidates.empty());
        const auto has_https_echo = std::any_of(result.candidates.begin(), result.candidates.end(), [](const Config::AdvertiseCandidate& candidate) {
            return candidate.via == "https-echo";
        });
        assert(has_https_echo);
        assert(result.conflict);
        assert(!result.warnings.empty());
    }

    {
        AdvertiseDiscoveryResult synthetic;
        Config::AdvertiseCandidate https{};
        https.host = "198.51.100.4";
        https.port = 41000;
        https.via = "https-echo";
        synthetic.candidates.push_back(https);

        Config::AdvertiseCandidate stun{};
        stun.host = "203.0.113.9";
        stun.port = 41000;
        stun.via = "stun";
        synthetic.candidates.push_back(stun);

        Config::AdvertiseCandidate upnp{};
        upnp.host = "203.0.113.9";
        upnp.port = 41000;
        upnp.via = "upnp";
        synthetic.candidates.push_back(upnp);

        const auto candidate = select_public_advertise_candidate(synthetic);
        assert(candidate.has_value());
        assert(candidate->via == "upnp");
    }

    {
        AdvertiseDiscoveryResult synthetic;
        Config::AdvertiseCandidate stun{};
        stun.host = "203.0.113.20";
        stun.port = 42000;
        stun.via = "stun";
        synthetic.candidates.push_back(stun);

        const auto candidate = select_public_advertise_candidate(synthetic);
        assert(candidate.has_value());
        assert(candidate->via == "stun");
    }

    {
        AdvertiseDiscoveryResult synthetic;
        Config::AdvertiseCandidate https{};
        https.host = "198.51.100.10";
        https.port = 41000;
        https.via = "https-echo";
        synthetic.candidates.push_back(https);

        const auto candidate = select_public_advertise_candidate(synthetic);
        assert(!candidate.has_value());
    }

    return 0;
}
