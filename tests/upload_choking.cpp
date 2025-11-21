#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iostream>
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
    seeder_config.announce_pow_difficulty = 0;

    ephemeralnet::Config consumer_config{};
    consumer_config.identity_seed = 0x20u;
    consumer_config.fetch_max_parallel_requests = 1;
    consumer_config.fetch_retry_initial_backoff = std::chrono::seconds{1};
    consumer_config.fetch_retry_success_interval = std::chrono::seconds{1};
    consumer_config.fetch_availability_refresh = std::chrono::seconds{1};
    consumer_config.announce_pow_difficulty = 0;

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

    auto shutdown = [&]() {
        seeder.stop_transport();
        peer_a.stop_transport();
        peer_b.stop_transport();
    };

    auto require = [&](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "[UploadChoking] " << message << std::endl;
            shutdown();
            return false;
        }
        return true;
    };

    const auto pow_peer_a = ephemeralnet::test::NodeTestAccess::handshake_work(peer_a, seeder_id);
    const auto pow_seeder_a = ephemeralnet::test::NodeTestAccess::handshake_work(seeder, peer_a_id);
    const auto pow_peer_b = ephemeralnet::test::NodeTestAccess::handshake_work(peer_b, seeder_id);
    const auto pow_seeder_b = ephemeralnet::test::NodeTestAccess::handshake_work(seeder, peer_b_id);
    if (!require(pow_peer_a.has_value(), "peer A handshake work failed")) {
        return 1;
    }
    if (!require(pow_seeder_a.has_value(), "seeder handshake work for peer A failed")) {
        return 1;
    }
    if (!require(pow_peer_b.has_value(), "peer B handshake work failed")) {
        return 1;
    }
    if (!require(pow_seeder_b.has_value(), "seeder handshake work for peer B failed")) {
        return 1;
    }
    const bool hs_a = seeder.perform_handshake(peer_a_id, peer_a.public_identity(), *pow_peer_a);
    const bool hs_a_back = peer_a.perform_handshake(seeder_id, seeder.public_identity(), *pow_seeder_a);
    const bool hs_b = seeder.perform_handshake(peer_b_id, peer_b.public_identity(), *pow_peer_b);
    const bool hs_b_back = peer_b.perform_handshake(seeder_id, seeder.public_identity(), *pow_seeder_b);
    if (!require(hs_a && hs_a_back, "peer A handshake sequence failed")) {
        return 1;
    }
    if (!require(hs_b && hs_b_back, "peer B handshake sequence failed")) {
        return 1;
    }

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

    auto deadline = std::chrono::steady_clock::now() + 20s;
    bool a_complete = false;
    bool b_complete = false;
    bool observed_upload_activity = false;

    while (std::chrono::steady_clock::now() < deadline && (!a_complete || !b_complete)) {
        seeder.tick();
        peer_a.tick();
        peer_b.tick();

        const auto active_uploads = ephemeralnet::test::NodeTestAccess::active_uploads(seeder);
        const auto pending_uploads = ephemeralnet::test::NodeTestAccess::pending_uploads(seeder);
        const auto completed_uploads = ephemeralnet::test::NodeTestAccess::completed_uploads(seeder);
        if (active_uploads > 0 || pending_uploads > 0 || completed_uploads > 0) {
            observed_upload_activity = true;
        }

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

    if (!require(a_complete, "peer A failed to fetch chunk")) {
        return 1;
    }
    if (!require(b_complete, "peer B failed to fetch chunk")) {
        return 1;
    }
    auto settle_deadline = std::chrono::steady_clock::now() + 5s;
    // Give instrumentation counters time (and event loop ticks) to reflect the completed transfers.
    while (std::chrono::steady_clock::now() < settle_deadline
           && ephemeralnet::test::NodeTestAccess::completed_uploads(seeder) < 2) {
        seeder.tick();
        peer_a.tick();
        peer_b.tick();
        std::this_thread::sleep_for(20ms);
    }

    const auto peak_active = ephemeralnet::test::NodeTestAccess::peak_active_uploads(seeder);
    const auto total_completed = ephemeralnet::test::NodeTestAccess::completed_uploads(seeder);

    if (!require(peak_active <= seeder_config.upload_max_parallel_transfers, "upload concurrency exceeded limit")) {
        return 1;
    }
    if (!require(total_completed >= 2, "expected both peers to complete uploads")) {
        return 1;
    }
    if (!require(observed_upload_activity, "no upload activity was observed")) {
        return 1;
    }

    auto drain_deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < drain_deadline
           && (ephemeralnet::test::NodeTestAccess::active_uploads(seeder) > 0
               || ephemeralnet::test::NodeTestAccess::pending_uploads(seeder) > 0)) {
        seeder.tick();
        std::this_thread::sleep_for(30ms);
    }

    if (!require(ephemeralnet::test::NodeTestAccess::pending_uploads(seeder) == 0, "pending uploads failed to drain")) {
        return 1;
    }
    if (!require(ephemeralnet::test::NodeTestAccess::active_uploads(seeder) == 0, "active uploads failed to drain")) {
        return 1;
    }
    if (!require(ephemeralnet::test::NodeTestAccess::active_uploads_for_peer(seeder, peer_a_id) == 0, "peer A active uploads failed to drain")) {
        return 1;
    }
    if (!require(ephemeralnet::test::NodeTestAccess::active_uploads_for_peer(seeder, peer_b_id) == 0, "peer B active uploads failed to drain")) {
        return 1;
    }

    shutdown();
    return 0;
}
