#include "ephemeralnet/core/SwarmCoordinator.hpp"

#include <cassert>
#include <chrono>
#include <unordered_set>

int main() {
    ephemeralnet::Config config{};
    config.identity_seed = 0x42424242u;
    config.swarm_target_replicas = 3;
    config.swarm_min_providers = 2;
    config.swarm_candidate_sample = 6;
    config.swarm_rebalance_interval = std::chrono::seconds(30);

    ephemeralnet::PeerId self{};
    self.fill(0x01);

    ephemeralnet::KademliaTable table(self, config);

    const auto now = std::chrono::steady_clock::now();
    for (int i = 0; i < 5; ++i) {
        ephemeralnet::PeerContact contact{};
        contact.id.fill(static_cast<std::uint8_t>(i + 2));
        contact.address = "10.0.0." + std::to_string(10 + i);
        contact.expires_at = now + std::chrono::minutes(5);
        table.register_peer(contact);
    }

    ephemeralnet::protocol::Manifest manifest{};
    manifest.chunk_id.fill(0xAA);
    manifest.threshold = 2;
    manifest.total_shares = 4;
    manifest.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
    manifest.shards.resize(4);

    for (std::uint8_t i = 0; i < manifest.shards.size(); ++i) {
        manifest.shards[i].index = static_cast<std::uint8_t>(i + 1);
        manifest.shards[i].value.fill(i);
    }

    ephemeralnet::SwarmCoordinator coordinator(config);
    const ephemeralnet::SwarmPeerLoadMap loads{};
    const auto plan = coordinator.compute_plan(manifest.chunk_id, manifest, table, self, loads);

    assert(!plan.assignments.empty());
    assert(plan.assignments.size() >= 2);

    std::size_t total_assigned = 0;
    std::unordered_set<std::string> peers_seen;
    for (const auto& assignment : plan.assignments) {
        assert(!assignment.shard_indices.empty());
        total_assigned += assignment.shard_indices.size();
        peers_seen.insert(ephemeralnet::peer_id_to_string(assignment.peer.id));
    }

    assert(total_assigned == manifest.shards.size());
    assert(peers_seen.size() == plan.assignments.size());
    assert(!plan.diagnostics.empty());

    return 0;
}
