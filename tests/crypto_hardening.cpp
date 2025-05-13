#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/crypto/CryptoManager.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>

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
    {
        const auto default_id = make_peer_id(0x70);
        ephemeralnet::Node hardened(default_id);
        const auto& hardened_config = hardened.config();
        assert(hardened_config.key_rotation_interval == 5min);
        assert(hardened_config.default_chunk_ttl == 6h);
        assert(hardened_config.min_manifest_ttl == 30s);
        assert(hardened_config.max_manifest_ttl == 6h);
        assert(hardened_config.announce_min_interval == 15s);
        assert(hardened_config.announce_burst_limit == 4);
        assert(hardened_config.announce_burst_window == 120s);
        assert(hardened_config.announce_pow_difficulty == 6);
    }

    ephemeralnet::Config config{};
    config.key_rotation_interval = std::chrono::seconds(0);
    config.min_manifest_ttl = 5s;
    config.max_manifest_ttl = 20s;
    config.default_chunk_ttl = 30s;
    config.announce_min_interval = 5s;
    config.announce_burst_limit = 1;
    config.announce_burst_window = 30s;

    const auto node_id = make_peer_id(0x01);
    ephemeralnet::Node node(node_id, config);
    const auto sanitized_interval = node.config().key_rotation_interval;

    const auto peer_id = make_peer_id(0x10);
    ephemeralnet::crypto::Key shared_secret{};
    shared_secret.bytes.fill(0x42u);
    node.register_shared_secret(peer_id, shared_secret);

    const auto rotation_now = std::chrono::steady_clock::now();
    if (sanitized_interval > 1s) {
        const auto before = ephemeralnet::test::NodeTestAccess::rotate_key(node, peer_id, rotation_now + sanitized_interval - 1s);
        assert(!before.has_value());
    }
    const auto after = ephemeralnet::test::NodeTestAccess::rotate_key(node, peer_id, rotation_now + sanitized_interval + 1s);
    assert(after.has_value());

    const auto chunk_id = make_chunk_id(0x20);
    ephemeralnet::ChunkData chunk_data(32, 0x33u);
    const auto stored_manifest = node.store_chunk(chunk_id, chunk_data, 120s);
    const auto ttl_after_store = std::chrono::duration_cast<std::chrono::seconds>(stored_manifest.expires_at - std::chrono::system_clock::now());
    assert(ttl_after_store <= node.config().max_manifest_ttl + 1s);
    assert(ttl_after_store >= node.config().min_manifest_ttl - 1s);

    ephemeralnet::protocol::Manifest short_manifest = stored_manifest;
    short_manifest.expires_at = std::chrono::system_clock::now() + 2s;
    const auto short_uri = ephemeralnet::protocol::encode_manifest(short_manifest);
    assert(!node.ingest_manifest(short_uri));

    ephemeralnet::protocol::Manifest remote_manifest = stored_manifest;
    remote_manifest.expires_at = std::chrono::system_clock::now() + 18s;
    const auto remote_uri = ephemeralnet::protocol::encode_manifest(remote_manifest);
    assert(node.ingest_manifest(remote_uri));

    ephemeralnet::protocol::AnnouncePayload announce{};
    announce.chunk_id = chunk_id;
    announce.peer_id = peer_id;
    announce.endpoint = "127.0.0.1:5000";
    announce.ttl = 15s;
    announce.manifest_uri = remote_uri;
    announce.assigned_shards.push_back(stored_manifest.shards.front().index);

    const bool announce_pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(node, announce);
    assert(announce_pow_ready);
    ephemeralnet::test::NodeTestAccess::handle_announce(node, announce, peer_id);
    const auto first_score = node.reputation_score(peer_id);
    assert(first_score > 0);
    const auto first_providers = ephemeralnet::test::NodeTestAccess::provider_count(node, chunk_id);
    assert(first_providers.has_value());
    assert(*first_providers == 1);

    ephemeralnet::test::NodeTestAccess::handle_announce(node, announce, peer_id);
    const auto second_score = node.reputation_score(peer_id);
    assert(second_score < first_score);
    const auto second_providers = ephemeralnet::test::NodeTestAccess::provider_count(node, chunk_id);
    assert(second_providers.has_value());
    assert(*second_providers == 1);

    ephemeralnet::Config pow_config = config;
    pow_config.announce_pow_difficulty = 12;
    const auto pow_node_id = make_peer_id(0x61);
    ephemeralnet::Node pow_node_fail(pow_node_id, pow_config);
    const auto pow_peer_id = make_peer_id(0x62);

    ephemeralnet::protocol::AnnouncePayload pow_announce = announce;
    pow_announce.peer_id = pow_peer_id;

    ephemeralnet::test::NodeTestAccess::handle_announce(pow_node_fail, pow_announce, pow_peer_id);
    assert(pow_node_fail.reputation_score(pow_peer_id) < 0);

    ephemeralnet::Node pow_node_success(make_peer_id(0x63), pow_config);
    auto valid_announce = pow_announce;
    const bool pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(pow_node_success, valid_announce);
    assert(pow_ready);
    const auto before_success = pow_node_success.reputation_score(pow_peer_id);
    ephemeralnet::test::NodeTestAccess::handle_announce(pow_node_success, valid_announce, pow_peer_id);
    const auto after_success = pow_node_success.reputation_score(pow_peer_id);
    assert(after_success > before_success);

    return 0;
}
