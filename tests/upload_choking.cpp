#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <string>
#include <thread>

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
    ephemeralnet::Config seeder_config{};
    seeder_config.identity_seed = 0x10u;
    seeder_config.upload_max_parallel_transfers = 1;
    seeder_config.upload_max_transfers_per_peer = 1;
    seeder_config.upload_transfer_timeout = std::chrono::seconds{3};
    seeder_config.upload_reconsider_interval = std::chrono::seconds{1};

    ephemeralnet::Config consumer_config{};
    consumer_config.identity_seed = 0x20u;
    consumer_config.fetch_max_parallel_requests = 1;
    consumer_config.fetch_retry_initial_backoff = std::chrono::seconds{1};
    consumer_config.fetch_retry_success_interval = std::chrono::seconds{1};
    consumer_config.fetch_availability_refresh = std::chrono::seconds{1};

    ephemeralnet::Config consumer_b_config = consumer_config;
    consumer_b_config.identity_seed = 0x30u;

    const auto seeder_id = make_peer_id(0xA0);
    const auto peer_a_id = make_peer_id(0xB0);
    const auto peer_b_id = make_peer_id(0xC0);

    ephemeralnet::Node seeder(seeder_id, seeder_config);
    ephemeralnet::Node peer_a(peer_a_id, consumer_config);
    ephemeralnet::Node peer_b(peer_b_id, consumer_b_config);

    seeder.start_transport(0);
    peer_a.start_transport(0);
    peer_b.start_transport(0);

    const bool hs_a = seeder.perform_handshake(peer_a_id, peer_a.public_identity());
    const bool hs_a_back = peer_a.perform_handshake(seeder_id, seeder.public_identity());
    const bool hs_b = seeder.perform_handshake(peer_b_id, peer_b.public_identity());
    const bool hs_b_back = peer_b.perform_handshake(seeder_id, seeder.public_identity());
    assert(hs_a && hs_a_back);
    assert(hs_b && hs_b_back);

    const auto chunk_id = make_chunk_id(0x55);
    ephemeralnet::ChunkData chunk_payload(64, 0xEFu);
    auto manifest = seeder.store_chunk(chunk_id, chunk_payload, 300s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    std::string endpoint = "127.0.0.1:" + std::to_string(seeder.transport_port());

    ephemeralnet::protocol::AnnouncePayload payload{};
    payload.chunk_id = chunk_id;
    payload.peer_id = seeder_id;
    payload.endpoint = endpoint;
    payload.ttl = 200s;
    payload.manifest_uri = manifest_uri;
    payload.assigned_shards.push_back(manifest.shards.front().index);

    ephemeralnet::test::NodeTestAccess::handle_announce(peer_a, payload, seeder_id);
    ephemeralnet::test::NodeTestAccess::handle_announce(peer_b, payload, seeder_id);

    auto deadline = std::chrono::steady_clock::now() + 10s;
    bool a_complete = false;
    bool b_complete = false;
    std::size_t max_active = 0;

    while (std::chrono::steady_clock::now() < deadline && (!a_complete || !b_complete)) {
        seeder.tick();
        peer_a.tick();
        peer_b.tick();

        max_active = std::max(max_active, ephemeralnet::test::NodeTestAccess::active_uploads(seeder));

        if (!a_complete) {
            const auto data = peer_a.fetch_chunk(chunk_id);
            a_complete = data.has_value() && *data == chunk_payload;
        }

        if (!b_complete) {
            const auto data = peer_b.fetch_chunk(chunk_id);
            b_complete = data.has_value() && *data == chunk_payload;
        }

        std::this_thread::sleep_for(30ms);
    }

    assert(a_complete);
    assert(b_complete);
    assert(max_active <= seeder_config.upload_max_parallel_transfers);
    assert(max_active >= 1);

    auto drain_deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < drain_deadline
           && (ephemeralnet::test::NodeTestAccess::active_uploads(seeder) > 0
               || ephemeralnet::test::NodeTestAccess::pending_uploads(seeder) > 0)) {
        seeder.tick();
        std::this_thread::sleep_for(30ms);
    }

    assert(ephemeralnet::test::NodeTestAccess::pending_uploads(seeder) == 0);
    assert(ephemeralnet::test::NodeTestAccess::active_uploads(seeder) == 0);
    assert(ephemeralnet::test::NodeTestAccess::active_uploads_for_peer(seeder, peer_a_id) == 0);
    assert(ephemeralnet::test::NodeTestAccess::active_uploads_for_peer(seeder, peer_b_id) == 0);

    seeder.stop_transport();
    peer_a.stop_transport();
    peer_b.stop_transport();

    return 0;
}
