#include "ephemeralnet/core/SwarmCoordinator.hpp"

#include <algorithm>

namespace ephemeralnet {

namespace {
std::mt19937::result_type seed_from_config(const Config& config) {
    return static_cast<std::mt19937::result_type>(
        config.identity_seed.value_or(0xA5A5A5A5u) ^ 0x1F2E3D4Cu);
}
}

SwarmCoordinator::SwarmCoordinator(const Config& config)
    : config_(config),
      rng_(seed_from_config(config)) {}

SwarmDistributionPlan SwarmCoordinator::compute_plan(const ChunkId& chunk_id,
                                                      const protocol::Manifest& manifest,
                                                      const KademliaTable& table,
                                                      const PeerId& self_id) {
    SwarmDistributionPlan plan{};
    plan.chunk_id = chunk_id;
    plan.created_at = std::chrono::steady_clock::now();
    plan.next_rebalance = plan.created_at + config_.swarm_rebalance_interval;
    plan.last_broadcast = plan.created_at;

    if (manifest.shards.empty()) {
        plan.diagnostics.emplace_back("Manifest has no shards to distribute.");
        return plan;
    }

    auto candidates = candidate_peers(chunk_id, table, self_id);
    plan.diagnostics.emplace_back("Candidate peers discovered: " + std::to_string(candidates.size()));

    if (candidates.empty()) {
        plan.diagnostics.emplace_back("No remote peers available; retaining local exclusivity.");
        return plan;
    }

    std::shuffle(candidates.begin(), candidates.end(), rng_);

    const auto total_shards = static_cast<std::size_t>(manifest.shards.size());
    const auto min_config = static_cast<std::size_t>(config_.swarm_min_providers);
    const auto target_config = static_cast<std::size_t>(config_.swarm_target_replicas);
    const auto threshold_required = static_cast<std::size_t>(manifest.threshold);

    const auto min_providers = std::max(min_config, threshold_required);
    const auto clamped_min = std::min<std::size_t>({min_providers, candidates.size(), total_shards});
    const auto desired_target = std::max(target_config, clamped_min);
    const auto provider_count = std::min<std::size_t>({candidates.size(), desired_target, total_shards});

    if (provider_count == 0) {
        plan.diagnostics.emplace_back("Insufficient candidates to satisfy minimum provider requirement.");
        return plan;
    }

    if (provider_count < min_providers) {
        plan.diagnostics.emplace_back("Unable to satisfy configured minimum providers; proceeding with available peers.");
    }

    plan.assignments.reserve(provider_count);
    for (std::size_t i = 0; i < provider_count; ++i) {
        SwarmAssignment assignment{};
        assignment.peer = candidates[i];
        plan.assignments.push_back(assignment);
    }

    for (std::size_t shard_index = 0; shard_index < total_shards; ++shard_index) {
        const auto recipient = shard_index % provider_count;
        const auto shard_label = manifest.shards[shard_index].index;
        plan.assignments[recipient].shard_indices.push_back(shard_label);
    }

    plan.diagnostics.emplace_back("Swarm plan assignments: " + std::to_string(plan.assignments.size()));

    return plan;
}

std::vector<PeerContact> SwarmCoordinator::candidate_peers(const ChunkId& chunk_id,
                                                           const KademliaTable& table,
                                                           const PeerId& self_id) {
    const auto sample_limit = std::max<std::size_t>(static_cast<std::size_t>(config_.swarm_candidate_sample), 1);

    PeerId target{};
    std::copy(chunk_id.begin(), chunk_id.end(), target.begin());

    auto candidates = table.closest_peers(target, sample_limit);

    candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [&](const PeerContact& contact) {
                         return contact.id == self_id;
                     }),
        candidates.end());

    return candidates;
}

}  // namespace ephemeralnet
