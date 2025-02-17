#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <chrono>
#include <random>
#include <string>
#include <vector>

namespace ephemeralnet {

struct SwarmAssignment {
    PeerContact peer;
    std::vector<std::uint8_t> shard_indices;
};

struct SwarmDistributionPlan {
    ChunkId chunk_id{};
    std::vector<SwarmAssignment> assignments;
    std::chrono::steady_clock::time_point created_at{};
    std::chrono::steady_clock::time_point next_rebalance{};
    std::vector<std::string> diagnostics;
};

class SwarmCoordinator {
public:
    explicit SwarmCoordinator(const Config& config);

    SwarmDistributionPlan compute_plan(const ChunkId& chunk_id,
                                        const protocol::Manifest& manifest,
                                        const KademliaTable& table,
                                        const PeerId& self_id);

private:
    const Config& config_;
    std::mt19937 rng_;

    std::vector<PeerContact> candidate_peers(const ChunkId& chunk_id,
                                             const KademliaTable& table,
                                             const PeerId& self_id);
};

}  // namespace ephemeralnet
