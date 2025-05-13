#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/Types.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
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

ephemeralnet::Config make_config() {
    ephemeralnet::Config config{};
    config.default_chunk_ttl = 1s;
    config.cleanup_interval = 1s;
    config.identity_seed = 0x55u;
    config.min_manifest_ttl = 1s;
    config.max_manifest_ttl = 45s;
    config.announce_pow_difficulty = 0;
    return config;
}

ephemeralnet::ChunkId make_chunk_id(std::uint8_t seed) {
    ephemeralnet::ChunkId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::ChunkData make_chunk(std::uint8_t seed) {
    return ephemeralnet::ChunkData{seed, static_cast<std::uint8_t>(seed + 1), static_cast<std::uint8_t>(seed + 2)};
}

}  // namespace

int main() {
    ephemeralnet::Node node{make_peer_id(0x10), make_config()};

    const auto chunk_id = make_chunk_id(0x20);
    node.store_chunk(chunk_id, make_chunk(0x30), 1s);

    const auto initial = node.audit_ttl();
    assert(initial.healthy());

    std::this_thread::sleep_for(1500ms);

    const auto after_expiry = node.audit_ttl();
    assert(!after_expiry.healthy());
    assert(!after_expiry.expired_local_chunks.empty());
    assert(!after_expiry.expired_locator_chunks.empty());
    assert(!after_expiry.expired_contacts.empty());

    node.tick();

    const auto post_cleanup = node.audit_ttl();
    assert(post_cleanup.healthy());

    const auto notifications = node.drain_cleanup_notifications();
    assert(notifications.size() == 1);
    assert(notifications.front() == ephemeralnet::chunk_id_to_string(chunk_id));

    return 0;
}
