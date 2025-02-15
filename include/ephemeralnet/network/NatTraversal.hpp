#pragma once

#include "ephemeralnet/Config.hpp"

#include <optional>
#include <random>
#include <string>
#include <vector>

namespace ephemeralnet::network {

struct NatTraversalResult {
    std::string external_address;
    std::uint16_t external_port{0};
    bool upnp_available{false};
    bool stun_succeeded{false};
    bool hole_punch_ready{false};
    std::vector<std::string> diagnostics;
};

class NatTraversalManager {
public:
    explicit NatTraversalManager(const Config& config);

    NatTraversalResult coordinate(const std::string& local_address, std::uint16_t local_port);

private:
    const Config& config_;
    std::mt19937 rng_;
    std::optional<std::uint16_t> last_allocated_port_;

    std::uint16_t reserve_upnp_port(std::uint16_t preferred_port);
    std::string simulate_stun_query();
    bool simulate_hole_punch();
};

}  // namespace ephemeralnet::network
