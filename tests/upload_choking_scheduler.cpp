#include "ephemeralnet/core/Node.hpp"
#include "test_access.hpp"

#include <cassert>
#include <chrono>

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
    config.identity_seed = 0x10u;
    config.upload_max_parallel_transfers = 1;
    config.upload_max_transfers_per_peer = 1;
    config.upload_transfer_timeout = std::chrono::seconds{1};
    config.upload_reconsider_interval = std::chrono::seconds{1};

    const auto seeder_id = make_peer_id(0xA0);
    const auto peer_a_id = make_peer_id(0xB0);
    const auto peer_b_id = make_peer_id(0xC0);

    ephemeralnet::Node seeder(seeder_id, config);

    const auto chunk_id = make_chunk_id(0x55);
    ephemeralnet::ChunkData chunk_payload(32, 0xAAu);
    seeder.store_chunk(chunk_id, chunk_payload, 120s);

    const auto started_at = std::chrono::steady_clock::now() - 2s;
    ephemeralnet::test::NodeTestAccess::inject_active_upload(seeder, peer_a_id, chunk_id, started_at);
    ephemeralnet::test::NodeTestAccess::enqueue_upload(seeder, peer_b_id, chunk_id, chunk_payload.size());

    assert(ephemeralnet::test::NodeTestAccess::active_uploads(seeder) == 1);
    assert(ephemeralnet::test::NodeTestAccess::pending_uploads(seeder) == 1);

    ephemeralnet::test::NodeTestAccess::process_uploads(seeder);

    assert(ephemeralnet::test::NodeTestAccess::pending_uploads(seeder) == 0);
    assert(ephemeralnet::test::NodeTestAccess::active_uploads(seeder) == 0);
    assert(ephemeralnet::test::NodeTestAccess::active_uploads_for_peer(seeder, peer_a_id) == 0);

    return 0;
}
