#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::ChunkId make_chunk_id(std::uint8_t seed) {
    ephemeralnet::ChunkId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

}  // namespace

int main() {
    ephemeralnet::Config config{};
    config.announce_pow_difficulty = 4;
    config.default_chunk_ttl = 120s;

    const auto local_id = make_peer_id(0x10);
    ephemeralnet::Node node(local_id, config);

    const auto chunk_id = make_chunk_id(0x40);
    ephemeralnet::ChunkData data(64, 0x5au);
    const auto manifest = node.store_chunk(chunk_id, data, 90s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    const auto remote_peer = make_peer_id(0x90);

    ephemeralnet::protocol::AnnouncePayload base_payload{};
    base_payload.chunk_id = manifest.chunk_id;
    base_payload.peer_id = remote_peer;
    base_payload.endpoint = "203.0.113.10:4040";
    base_payload.ttl = 45s;
    base_payload.manifest_uri = manifest_uri;
    if (!manifest.shards.empty()) {
        base_payload.assigned_shards.push_back(manifest.shards.front().index);
    }

    auto payload = base_payload;
    payload.peer_id = make_peer_id(0x91);  // Deliberately mismatch sender to trigger failures deterministically.
    payload.work_nonce = 0;

    for (std::size_t attempt = 0; attempt < 3; ++attempt) {
        ephemeralnet::test::NodeTestAccess::handle_announce(node, payload, remote_peer);
    }

    assert(ephemeralnet::test::NodeTestAccess::announce_blocked(node, remote_peer));

    auto locked_score = node.reputation_score(remote_peer);

    auto valid_payload = base_payload;
    const bool pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(node, valid_payload);
    assert(pow_ready);

    ephemeralnet::test::NodeTestAccess::handle_announce(node, valid_payload, remote_peer);
    assert(ephemeralnet::test::NodeTestAccess::announce_blocked(node, remote_peer));
    auto after_locked_score = node.reputation_score(remote_peer);
    assert(after_locked_score <= locked_score);

    ephemeralnet::test::NodeTestAccess::expire_announce_lock(node, remote_peer);
    assert(!ephemeralnet::test::NodeTestAccess::announce_blocked(node, remote_peer));

    const auto score_before = node.reputation_score(remote_peer);
    ephemeralnet::test::NodeTestAccess::handle_announce(node, valid_payload, remote_peer);
    const auto score_after = node.reputation_score(remote_peer);
    assert(score_after > score_before);
    assert(!ephemeralnet::test::NodeTestAccess::announce_blocked(node, remote_peer));

    const auto snapshot = ephemeralnet::test::NodeTestAccess::swarm_snapshot(node, chunk_id);
    const auto remote_key = ephemeralnet::peer_id_to_string(remote_peer);
    const bool remote_recorded = std::find(snapshot.seeds.begin(), snapshot.seeds.end(), remote_key) != snapshot.seeds.end();
    assert(remote_recorded);

    return 0;
}
