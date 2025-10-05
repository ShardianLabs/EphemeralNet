#pragma once

#include "ephemeralnet/Config.hpp"

#include <functional>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace ephemeralnet::network {

struct NatTraversalResult {
    std::string external_address;
    std::uint16_t external_port{0};
    bool stun_succeeded{false};
    std::vector<std::string> diagnostics;
};

class NatTraversalManager {
public:
    explicit NatTraversalManager(const Config& config);

    NatTraversalResult coordinate(const std::string& local_address, std::uint16_t local_port);

    struct StunQueryResult {
        std::string address;
        std::uint16_t reported_port{0};
        std::string server;
    };

    struct TestHooks {
        std::function<std::optional<StunQueryResult>()> stun_override;
    };

    static void set_test_hooks(const TestHooks* hooks);

private:
    const Config& config_;
    std::mt19937 rng_;

    std::optional<StunQueryResult> perform_stun_query();
};

}  // namespace ephemeralnet::network
