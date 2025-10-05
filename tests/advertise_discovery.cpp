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
using ephemeralnet::network::build_transport_advertise_candidates;
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
    NatTraversalManager::TestHooks hooks{};
    const auto stun_success = []() -> std::optional<NatTraversalManager::StunQueryResult> {
        NatTraversalManager::StunQueryResult result{};
        result.address = "45.64.61.85";
        result.reported_port = 45000;
        result.server = "test-stun";
        return result;
    };
    const auto stun_failure = []() -> std::optional<NatTraversalManager::StunQueryResult> {
        return std::nullopt;
    };

    hooks.stun_override = stun_success;
    NatTraversalManager::set_test_hooks(&hooks);

    Config base{};
    base.control_host = "10.0.0.5";
    base.control_port = 41000;

    hooks.stun_override = stun_success;
    const auto stun_seed = find_seed_matching(base, [](const NatTraversalResult& result) {
        return result.stun_succeeded;
    });
    assert(stun_seed.has_value());

    hooks.stun_override = stun_failure;
    const auto failure_seed = find_seed_matching(base, [](const NatTraversalResult& result) {
        return !result.stun_succeeded;
    });
    assert(failure_seed.has_value());

    {
        hooks.stun_override = stun_success;
        Config config = base;
        config.identity_seed = *stun_seed;
        config.advertise_allow_private = true;
        const AdvertiseDiscoveryResult result = discover_control_advertise_candidates(config);
        assert(!result.candidates.empty());
        bool saw_stun = false;
        bool saw_local = false;
        for (const auto& candidate : result.candidates) {
            if (candidate.via == "stun") {
                saw_stun = true;
            }
            if (candidate.via == "local-fallback") {
                saw_local = true;
            }
            assert(!candidate.host.empty());
            assert(candidate.port != 0);
            assert(!candidate.diagnostics.empty());
        }
        assert(saw_stun);
        assert(saw_local);
        assert(result.conflict);
        assert(!result.warnings.empty());
    }

    {
        hooks.stun_override = stun_success;
        Config config = base;
        config.identity_seed = *stun_seed;
        const auto result = discover_control_advertise_candidates(config);
        assert(result.candidates.size() == 1);
        assert(result.candidates.front().via == "stun");
        assert(!result.conflict);
        assert(result.warnings.empty());
    }

    {
        hooks.stun_override = stun_failure;
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

        const auto candidate = select_public_advertise_candidate(synthetic);
        assert(candidate.has_value());
        assert(candidate->via == "stun");
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

    {
        Config config = base;
        config.advertise_allow_private = false;
        NatTraversalResult traversal{};
        traversal.external_address = "45.64.61.85";
        traversal.external_port = 45050;
        traversal.stun_succeeded = true;
        traversal.diagnostics.push_back("stun-ok");
        const auto result = build_transport_advertise_candidates(config, 47000, traversal);
        assert(result.candidates.size() == 1);
        assert(result.candidates.front().via == "stun");
        assert(!result.conflict);
    }

    {
        Config config = base;
        config.advertise_allow_private = true;
        NatTraversalResult traversal{};
        traversal.external_address.clear();
        traversal.external_port = 0;
        traversal.diagnostics.push_back("stun-missing");
        const auto result = build_transport_advertise_candidates(config, 48000, traversal);
        assert(!result.candidates.empty());
        const auto local = std::any_of(result.candidates.begin(), result.candidates.end(), [](const Config::AdvertiseCandidate& candidate) {
            return candidate.via == "local-fallback";
        });
        assert(local);
    }

    NatTraversalManager::set_test_hooks(nullptr);
    return 0;
}
