#include "ephemeralnet/core/SwarmCoordinator.hpp"

#include <cassert>
#include <chrono>
#include <unordered_set>

namespace {

void fill_peer(ephemeralnet::PeerId& id, std::uint8_t seed) {
    for (auto& byte : id) {
        byte = seed++;
    }
}

}  // namespace

int main() {
    ephemeralnet::Config config{};
    config.identity_seed = 0x13572468u;
    config.swarm_target_replicas = 2;
    config.swarm_min_providers = 2;
    config.swarm_candidate_sample = 5;
    config.swarm_rebalance_interval = std::chrono::seconds(30);
    config.upload_max_transfers_per_peer = 2;

    ephemeralnet::PeerId self{};
    fill_peer(self, 0x01);

    ephemeralnet::KademliaTable table(self, config);

    const auto now = std::chrono::steady_clock::now();

    ephemeralnet::PeerContact idle_peer{};
    fill_peer(idle_peer.id, 0x20);
    idle_peer.address = "10.0.0.10";
    idle_peer.expires_at = now + std::chrono::minutes(10);
    table.register_peer(idle_peer);

    ephemeralnet::PeerContact busy_peer{};
    fill_peer(busy_peer.id, 0x40);
    busy_peer.address = "10.0.0.11";
    busy_peer.expires_at = now + std::chrono::minutes(6);
    table.register_peer(busy_peer);

    ephemeralnet::PeerContact choked_peer{};
    fill_peer(choked_peer.id, 0x60);
    choked_peer.address = "10.0.0.12";
    choked_peer.expires_at = now + std::chrono::minutes(6);
    table.register_peer(choked_peer);

    ephemeralnet::protocol::Manifest manifest{};
    fill_peer(manifest.chunk_id, 0x90);
    manifest.threshold = 2;
    manifest.total_shares = 4;
    manifest.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
    manifest.shards.resize(4);
    for (std::uint8_t index = 0; index < manifest.shards.size(); ++index) {
        manifest.shards[index].index = static_cast<std::uint8_t>(index + 1);
        manifest.shards[index].value.fill(index);
    }

    ephemeralnet::SwarmPeerLoadMap load_snapshot;

    const auto idle_key = ephemeralnet::peer_id_to_string(idle_peer.id);
    auto& idle_load = load_snapshot[idle_key];
    idle_load.has_reputation = true;
    idle_load.reputation = 10;

    const auto busy_key = ephemeralnet::peer_id_to_string(busy_peer.id);
    auto& busy_load = load_snapshot[busy_key];
    busy_load.active_uploads = 1;
    busy_load.pending_uploads = 1;
    busy_load.seed_roles = 3;
    busy_load.has_reputation = true;
    busy_load.reputation = 5;

    const auto choked_key = ephemeralnet::peer_id_to_string(choked_peer.id);
    auto& choked_load = load_snapshot[choked_key];
    choked_load.active_uploads = 2;
    choked_load.pending_uploads = 2;
    choked_load.seed_roles = 2;
    choked_load.has_reputation = true;
    choked_load.reputation = 3;
    choked_load.is_choked = true;

    ephemeralnet::SwarmCoordinator coordinator(config);
    const auto plan = coordinator.compute_plan(manifest.chunk_id, manifest, table, self, load_snapshot);

    assert(plan.assignments.size() == 2);

    std::unordered_set<std::string> selected;
    for (const auto& assignment : plan.assignments) {
        selected.insert(ephemeralnet::peer_id_to_string(assignment.peer.id));
    }

    assert(selected.contains(idle_key));
    assert(!selected.contains(choked_key));

    return 0;
}
