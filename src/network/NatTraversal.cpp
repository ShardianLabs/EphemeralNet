#include "ephemeralnet/network/NatTraversal.hpp"

#include <algorithm>
#include <array>

namespace ephemeralnet::network {

namespace {
constexpr std::array<const char*, 3> kStunFallbackHosts{
    "stun1.example.net",
    "stun2.example.net",
    "stun3.example.net",
};
}

NatTraversalManager::NatTraversalManager(const Config& config)
    : config_(config),
      rng_(static_cast<std::mt19937::result_type>(config.identity_seed.value_or(0u) ^ 0x5A5A5A5Au)) {}

NatTraversalResult NatTraversalManager::coordinate(const std::string& local_address, std::uint16_t local_port) {
    NatTraversalResult result{};
    result.diagnostics.reserve(4);

    const auto mapped_port = reserve_upnp_port(local_port);
    if (mapped_port != 0) {
        result.upnp_available = true;
        result.external_port = mapped_port;
        result.diagnostics.emplace_back("UPnP mapping established");
    } else {
        result.external_port = local_port;
        result.diagnostics.emplace_back("UPnP unavailable, using local port");
    }

    const auto external_address = simulate_stun_query();
    if (!external_address.empty()) {
        result.external_address = external_address;
        result.stun_succeeded = true;
        result.diagnostics.emplace_back("STUN discovery succeeded");
    } else {
        result.external_address = local_address.empty() ? "0.0.0.0" : local_address;
        result.diagnostics.emplace_back("STUN discovery failed");
    }

    result.hole_punch_ready = simulate_hole_punch();
    result.diagnostics.emplace_back(result.hole_punch_ready ? "Hole punching prepared" : "Hole punching deferred");

    return result;
}

std::uint16_t NatTraversalManager::reserve_upnp_port(std::uint16_t preferred_port) {
    if (config_.nat_upnp_start_port == 0 || config_.nat_upnp_end_port <= config_.nat_upnp_start_port) {
        return 0;
    }

    const auto start = std::max<std::uint16_t>(config_.nat_upnp_start_port, config_.nat_upnp_start_port);
    const auto end = std::max<std::uint16_t>(config_.nat_upnp_end_port, static_cast<std::uint16_t>(start + 1));
    std::uniform_int_distribution<std::uint16_t> distribution(start, static_cast<std::uint16_t>(end - 1));
    const auto candidate = distribution(rng_);

    if (!last_allocated_port_.has_value()) {
        last_allocated_port_ = candidate;
        return candidate;
    }

    if (*last_allocated_port_ == preferred_port) {
        return preferred_port;
    }

    last_allocated_port_ = candidate;
    return candidate;
}

std::string NatTraversalManager::simulate_stun_query() {
    std::uniform_int_distribution<int> distribution(0, static_cast<int>(kStunFallbackHosts.size()));
    const auto selection = distribution(rng_);
    if (selection >= static_cast<int>(kStunFallbackHosts.size())) {
        return {};
    }

    const auto host_seed = static_cast<std::uint32_t>(selection + 1);
    const auto third_octet = static_cast<std::uint8_t>(60 + host_seed);
    const auto fourth_octet = static_cast<std::uint8_t>(80 + host_seed * 5);
    return "45.64." + std::to_string(third_octet) + '.' + std::to_string(fourth_octet);
}

bool NatTraversalManager::simulate_hole_punch() {
    std::uniform_int_distribution<int> distribution(0, 1);
    return distribution(rng_) == 1;
}

}  // namespace ephemeralnet::network
