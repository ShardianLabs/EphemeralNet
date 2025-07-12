#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

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
    config.handshake_pow_difficulty = 4;
    config.announce_pow_difficulty = 4;
    config.handshake_cooldown = 0s;
    config.default_chunk_ttl = 120s;

    const auto local_id = make_peer_id(0x01);
    ephemeralnet::Node node(local_id, config);

    const auto remote_id = make_peer_id(0x21);
    ephemeralnet::Node remote(remote_id, config);

    // Handshake failure: deliberately provide an incorrect nonce.
    const bool first_handshake = node.perform_handshake(remote_id, remote.public_identity(), 0);
    assert(!first_handshake);

    // Handshake success with valid work from the remote node.
    const auto valid_nonce = ephemeralnet::test::NodeTestAccess::handshake_work(remote, node.id());
    assert(valid_nonce.has_value());
    const bool second_handshake = node.perform_handshake(remote_id, remote.public_identity(), *valid_nonce);
    assert(second_handshake);

    // Prepare local chunk/manifest for announce validation.
    ephemeralnet::ChunkData chunk_data(32, 0xAAu);
    const auto chunk_id = make_chunk_id(0x70);
    const auto manifest = node.store_chunk(chunk_id, chunk_data, 90s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    ephemeralnet::protocol::AnnouncePayload base_payload{};
    base_payload.chunk_id = manifest.chunk_id;
    base_payload.peer_id = remote_id;
    base_payload.endpoint = "198.51.100.5:4040";
    base_payload.ttl = 45s;
    base_payload.manifest_uri = manifest_uri;
    if (!manifest.shards.empty()) {
        base_payload.assigned_shards.push_back(manifest.shards.front().index);
    }

    auto valid_payload = base_payload;
    const bool pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(node, valid_payload);
    assert(pow_ready);

    auto invalid_payload = valid_payload;
    invalid_payload.work_nonce += 1;  // Guaranteed miss adjacent to valid solution.
    ephemeralnet::test::NodeTestAccess::handle_announce(node, invalid_payload, remote_id);

    ephemeralnet::test::NodeTestAccess::handle_announce(node, valid_payload, remote_id);

    const auto stats = ephemeralnet::test::NodeTestAccess::pow_stats(node);
    assert(stats.handshake_validations_failure >= 1);
    assert(stats.handshake_validations_success >= 1);
    assert(stats.announce_validations_failure >= 1);
    assert(stats.announce_validations_success >= 1);

    return 0;
}
