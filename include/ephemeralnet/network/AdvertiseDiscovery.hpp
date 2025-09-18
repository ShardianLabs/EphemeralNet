#pragma once

#include "ephemeralnet/Config.hpp"

#include <vector>

namespace ephemeralnet::network {

struct AdvertiseDiscoveryResult {
	std::vector<Config::AdvertiseCandidate> candidates;
	std::vector<std::string> warnings;
	bool conflict{false};
};

// Discovers candidate control endpoints by combining UPnP/NAT-PMP probes
// with STUN measurements and HTTPS echo fallbacks. Results are ordered by
// discovery priority but do not mutate manifests yet.
AdvertiseDiscoveryResult discover_control_advertise_candidates(const Config& config);

}  // namespace ephemeralnet::network
