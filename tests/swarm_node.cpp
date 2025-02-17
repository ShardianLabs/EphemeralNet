#include "ephemeralnet/core/Node.hpp"

#include <cassert>
#include <chrono>
#include <vector>

int main() {
    ephemeralnet::Config config{};
    config.identity_seed = 0x11111111u;
    config.swarm_target_replicas = 3;
    config.swarm_min_providers = 2;
    config.swarm_candidate_sample = 5;

    ephemeralnet::PeerId node_id{};
    node_id.fill(0x11);

    ephemeralnet::Node node(node_id, config);

    const auto now = std::chrono::steady_clock::now();
    for (int i = 0; i < 4; ++i) {
        ephemeralnet::PeerContact contact{};
        contact.id.fill(static_cast<std::uint8_t>(0x20 + i));
        contact.address = "192.0.2." + std::to_string(10 + i);
        contact.expires_at = now + std::chrono::minutes(5);
        node.register_peer_contact(contact);
    }

    ephemeralnet::ChunkId chunk_id{};
    chunk_id.fill(0xAB);

    std::vector<std::uint8_t> data(128, 0x42);
    node.store_chunk(chunk_id, data, std::chrono::seconds(120));

    const auto plan = node.swarm_plan(chunk_id);
    assert(plan.has_value());
    assert(!plan->assignments.empty());
    assert(plan->next_rebalance > plan->created_at);

    std::size_t total_assigned = 0;
    for (const auto& assignment : plan->assignments) {
        total_assigned += assignment.shard_indices.size();
    }

    assert(total_assigned == config.shard_total);

    return 0;
}
