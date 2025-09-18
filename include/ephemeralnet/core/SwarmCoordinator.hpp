#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <chrono>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
    std::chrono::steady_clock::time_point last_broadcast{};
    std::vector<std::string> diagnostics;
    std::unordered_set<std::string> delivered_peers;
    std::unordered_map<std::string, std::vector<std::string>> delivered_endpoints;
};

struct SwarmPeerLoad {
    std::size_t active_uploads{0};
    std::size_t pending_uploads{0};
    std::size_t active_downloads{0};
    std::size_t pending_downloads{0};
    std::size_t seed_roles{0};
    std::size_t leecher_roles{0};
    int reputation{0};
    bool has_reputation{false};
    bool is_choked{false};
};

using SwarmPeerLoadMap = std::unordered_map<std::string, SwarmPeerLoad>;

class SwarmCoordinator {
public:
    explicit SwarmCoordinator(const Config& config);

    SwarmDistributionPlan compute_plan(const ChunkId& chunk_id,
                                        const protocol::Manifest& manifest,
                                        const KademliaTable& table,
                                        const PeerId& self_id,
                                        const SwarmPeerLoadMap& load_snapshot);

private:
    const Config& config_;
    std::mt19937 rng_;

    std::vector<PeerContact> candidate_peers(const ChunkId& chunk_id,
                                             const KademliaTable& table,
                                             const PeerId& self_id);
};

}  // namespace ephemeralnet
