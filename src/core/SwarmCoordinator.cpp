#include "ephemeralnet/core/SwarmCoordinator.hpp"

#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>

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
                                                      const PeerId& self_id,
                                                      const SwarmPeerLoadMap& load_snapshot) {
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

    struct EvaluatedCandidate {
        PeerContact contact;
        SwarmPeerLoad load;
        std::chrono::seconds ttl_remaining{0};
        double score{0.0};
    };

    std::vector<EvaluatedCandidate> evaluated;
    evaluated.reserve(candidates.size());

    const auto now = std::chrono::steady_clock::now();
    std::uniform_real_distribution<double> jitter(0.0, 1.0);

    for (const auto& contact : candidates) {
        EvaluatedCandidate candidate{};
        candidate.contact = contact;

        const auto key = peer_id_to_string(contact.id);
        if (const auto it = load_snapshot.find(key); it != load_snapshot.end()) {
            candidate.load = it->second;
        }

        if (contact.expires_at > now) {
            candidate.ttl_remaining = std::chrono::duration_cast<std::chrono::seconds>(contact.expires_at - now);
        }

        const double ttl_window = std::min<double>(static_cast<double>(candidate.ttl_remaining.count()), 900.0);
        const double availability_bonus = ttl_window * 0.02;
        const double reputation_bonus = candidate.load.has_reputation ? static_cast<double>(candidate.load.reputation) * 0.05 : 0.0;

        const double load_penalty = static_cast<double>(candidate.load.active_uploads) * 2.5
            + static_cast<double>(candidate.load.pending_uploads) * 1.5
            + static_cast<double>(candidate.load.active_downloads) * 1.0
            + static_cast<double>(candidate.load.pending_downloads) * 0.5;

        const double fairness_penalty = static_cast<double>(candidate.load.seed_roles) * 1.3
            + static_cast<double>(candidate.load.leecher_roles) * 0.6;

        const double choking_penalty = candidate.load.is_choked ? 25.0 : 0.0;
        const double random_jitter = jitter(rng_) * 0.01;

        candidate.score = availability_bonus + reputation_bonus + random_jitter - load_penalty - fairness_penalty - choking_penalty;
        evaluated.push_back(candidate);
    }

    std::sort(evaluated.begin(), evaluated.end(), [](const EvaluatedCandidate& lhs, const EvaluatedCandidate& rhs) {
        if (lhs.score != rhs.score) {
            return lhs.score > rhs.score;
        }
        if (lhs.ttl_remaining != rhs.ttl_remaining) {
            return lhs.ttl_remaining > rhs.ttl_remaining;
        }
        return lhs.contact.address < rhs.contact.address;
    });

    const auto total_shards = static_cast<std::size_t>(manifest.shards.size());
    const auto min_config = static_cast<std::size_t>(config_.swarm_min_providers);
    const auto target_config = static_cast<std::size_t>(config_.swarm_target_replicas);
    const auto threshold_required = static_cast<std::size_t>(manifest.threshold);

    const auto min_providers = std::max(min_config, threshold_required);
    const auto clamped_min = std::min<std::size_t>({min_providers, evaluated.size(), total_shards});
    const auto desired_target = std::max(target_config, clamped_min);
    const auto provider_count = std::min<std::size_t>({evaluated.size(), desired_target, total_shards});

    if (provider_count == 0) {
        plan.diagnostics.emplace_back("Insufficient candidates to satisfy minimum provider requirement.");
        return plan;
    }

    if (provider_count < min_providers) {
        plan.diagnostics.emplace_back("Unable to satisfy configured minimum providers; proceeding with available peers.");
    }

    plan.assignments.reserve(provider_count);
    for (std::size_t index = 0; index < provider_count; ++index) {
        SwarmAssignment assignment{};
        assignment.peer = evaluated[index].contact;
        plan.assignments.push_back(assignment);

        std::ostringstream oss;
        oss << "Selected peer " << peer_id_to_string(evaluated[index].contact.id)
            << " score=" << evaluated[index].score
            << " uploads=" << evaluated[index].load.active_uploads
            << " seeds=" << evaluated[index].load.seed_roles
            << " choked=" << (evaluated[index].load.is_choked ? "yes" : "no");
        plan.diagnostics.push_back(oss.str());
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
