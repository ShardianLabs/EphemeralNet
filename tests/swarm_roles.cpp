#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/Types.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <optional>
#include <thread>
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

bool contains(const std::vector<std::string>& values, const std::string& target) {
    return std::find(values.begin(), values.end(), target) != values.end();
}

}  // namespace

int main() {
    ephemeralnet::Config seeder_config{};
    seeder_config.identity_seed = 0x10u;
    ephemeralnet::Config leecher_config{};
    leecher_config.identity_seed = 0x20u;

    const auto seeder_id = make_peer_id(0xA0);
    const auto leecher_id = make_peer_id(0xB0);
    const auto chunk_id = make_chunk_id(0x55);

    ephemeralnet::Node seeder(seeder_id, seeder_config);
    ephemeralnet::Node leecher(leecher_id, leecher_config);

    seeder.start_transport(0);
    leecher.start_transport(0);

    const auto pow_leecher = ephemeralnet::test::NodeTestAccess::handshake_work(leecher, seeder_id);
    const auto pow_seeder = ephemeralnet::test::NodeTestAccess::handshake_work(seeder, leecher_id);
    assert(pow_leecher.has_value());
    assert(pow_seeder.has_value());
    const bool hs_ab = seeder.perform_handshake(leecher_id, leecher.public_identity(), *pow_leecher);
    const bool hs_ba = leecher.perform_handshake(seeder_id, seeder.public_identity(), *pow_seeder);
    assert(hs_ab && hs_ba);

    ephemeralnet::ChunkData payload(48, 0xEEu);
    auto manifest = seeder.store_chunk(chunk_id, payload, 600s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    auto seeder_snapshot = ephemeralnet::test::NodeTestAccess::swarm_snapshot(seeder, chunk_id);
    const auto seeder_key = ephemeralnet::peer_id_to_string(seeder_id);
    assert(seeder_snapshot.self_seed);
    assert(!seeder_snapshot.self_leecher);
    assert(seeder_snapshot.leechers.empty());
    assert(contains(seeder_snapshot.seeds, seeder_key));

    const bool request_ok = leecher.request_chunk(seeder_id, "127.0.0.1", seeder.transport_port(), manifest_uri);
    assert(request_ok);

    const auto leecher_key = ephemeralnet::peer_id_to_string(leecher_id);
    auto leecher_snapshot = ephemeralnet::test::NodeTestAccess::swarm_snapshot(leecher, chunk_id);
    assert(leecher_snapshot.self_leecher);
    assert(!leecher_snapshot.self_seed);
    assert(contains(leecher_snapshot.seeds, seeder_key));
    assert(contains(leecher_snapshot.leechers, leecher_key));

    std::optional<ephemeralnet::ChunkData> downloaded;
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
        seeder.tick();
        leecher.tick();
        downloaded = leecher.fetch_chunk(chunk_id);
        if (downloaded.has_value() && *downloaded == payload) {
            break;
        }
        std::this_thread::sleep_for(30ms);
    }

    assert(downloaded.has_value());
    assert(*downloaded == payload);

    auto final_seeder_snapshot = ephemeralnet::test::NodeTestAccess::swarm_snapshot(seeder, chunk_id);
    auto final_leecher_snapshot = ephemeralnet::test::NodeTestAccess::swarm_snapshot(leecher, chunk_id);
    assert(final_seeder_snapshot.leechers.empty());
    assert(contains(final_seeder_snapshot.seeds, seeder_key));
    assert(contains(final_seeder_snapshot.seeds, leecher_key));
    assert(final_leecher_snapshot.self_seed);
    assert(!final_leecher_snapshot.self_leecher);
    assert(contains(final_leecher_snapshot.seeds, seeder_key));
    assert(contains(final_leecher_snapshot.seeds, leecher_key));

    seeder.stop_transport();
    leecher.stop_transport();

    return 0;
}
