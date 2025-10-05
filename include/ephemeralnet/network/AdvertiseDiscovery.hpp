#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/network/NatTraversal.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ephemeralnet::network {

struct AdvertiseDiscoveryResult {
	std::vector<Config::AdvertiseCandidate> candidates;
	std::vector<std::string> warnings;
	bool conflict{false};
};

// Discovers candidate control endpoints by combining STUN measurements with
// HTTPS echo fallbacks. Results are ordered by discovery priority but do not
// mutate manifests yet.
AdvertiseDiscoveryResult discover_control_advertise_candidates(const Config& config);

// Builds transport advertisement candidates from an existing NAT traversal
// snapshot, avoiding a second round of probes and reusing diagnostics.
AdvertiseDiscoveryResult build_transport_advertise_candidates(const Config& config,
                                                             std::uint16_t transport_port,
                                                             const NatTraversalResult& traversal);

// Returns the first candidate discovered via a routable STUN method so
// callers can decide whether to auto-expose the control plane.
std::optional<Config::AdvertiseCandidate> select_public_advertise_candidate(const AdvertiseDiscoveryResult& result);

}  // namespace ephemeralnet::network
