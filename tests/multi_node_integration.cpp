#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
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

ephemeralnet::Config make_config(std::uint32_t seed) {
    ephemeralnet::Config config{};
    config.identity_seed = seed;
    config.handshake_cooldown = 1s;
    config.fetch_retry_initial_backoff = 1s;
    config.fetch_retry_max_backoff = 2s;
    config.fetch_retry_success_interval = 1s;
    config.fetch_retry_attempt_limit = 6;
    config.fetch_availability_refresh = 1s;
    config.upload_reconsider_interval = 1s;
    config.upload_transfer_timeout = 5s;
    config.swarm_rebalance_interval = 10s;
    config.default_chunk_ttl = 120s;
    config.min_manifest_ttl = 10s;
    config.max_manifest_ttl = 600s;
    config.key_rotation_interval = 30s;
    config.control_host = "127.0.0.1";
    config.announce_pow_difficulty = 0;
    config.nat_stun_enabled = false;
    return config;
}

struct Simulation {
    ephemeralnet::network::SessionManager::TestHooks hooks{};
    std::atomic<std::size_t> send_counter{0};
    std::atomic<std::size_t> dropped{0};
    std::mutex mutex;
    std::unordered_map<std::string, bool> drop_map;

    Simulation() {
        hooks.before_send = [this](const ephemeralnet::PeerId&, std::size_t) {
            const auto index = send_counter.fetch_add(1, std::memory_order_relaxed);
            const auto delay_ms = 5 + static_cast<int>(index % 5) * 5;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        };
        hooks.drop_receive = [this](const ephemeralnet::network::TransportMessage& message) -> bool {
            const auto key = ephemeralnet::peer_id_to_string(message.peer_id);
            std::scoped_lock lock(mutex);
            auto it = drop_map.find(key);
            if (it != drop_map.end() && !it->second) {
                it->second = true;
                dropped.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            return false;
        };
    }

    void drop_first_from(const ephemeralnet::PeerId& peer) {
        std::scoped_lock lock(mutex);
        drop_map.emplace(ephemeralnet::peer_id_to_string(peer), false);
    }
};

struct HookGuard {
    explicit HookGuard(std::shared_ptr<Simulation> sim)
        : simulation(std::move(sim)) {}

    ~HookGuard() {
        ephemeralnet::network::SessionManager::set_test_hooks(nullptr);
        // Allow in-flight callbacks to observe the cleared hook pointer.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        simulation.reset();
    }

    std::shared_ptr<Simulation> simulation;
};

}  // namespace

int main() {
    auto simulation = std::make_shared<Simulation>();
    ephemeralnet::network::SessionManager::set_test_hooks(&simulation->hooks);
    HookGuard guard{simulation};

    const auto seeder_id = make_peer_id(0x01);
    const auto leecher_a_id = make_peer_id(0x41);
    const auto leecher_b_id = make_peer_id(0x81);

    simulation->drop_first_from(leecher_a_id);

    auto seeder_config = make_config(0xAAAAB111u);
    auto leecher_a_config = make_config(0xAAAAB222u);
    auto leecher_b_config = make_config(0xAAAAB333u);

    ephemeralnet::Node seeder(seeder_id, seeder_config);
    ephemeralnet::Node leecher_a(leecher_a_id, leecher_a_config);
    ephemeralnet::Node leecher_b(leecher_b_id, leecher_b_config);

    seeder.start_transport(0);
    leecher_a.start_transport(0);
    leecher_b.start_transport(0);

    auto shutdown = [&]() {
        seeder.stop_transport();
        leecher_a.stop_transport();
        leecher_b.stop_transport();
    };

    auto require = [&](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "[MultiNodeIntegration] " << message << std::endl;
            shutdown();
            return false;
        }
        return true;
    };

    std::this_thread::sleep_for(100ms);

    const auto seeder_port = seeder.transport_port();
    const auto leecher_a_port = leecher_a.transport_port();
    const auto leecher_b_port = leecher_b.transport_port();

    if (!require(seeder_port != 0, "seeder transport failed to start")) {
        return 1;
    }
    if (!require(leecher_a_port != 0, "leecher A transport failed to start")) {
        return 1;
    }
    if (!require(leecher_b_port != 0, "leecher B transport failed to start")) {
        return 1;
    }

    const auto pow_leecher_a = ephemeralnet::test::NodeTestAccess::handshake_work(leecher_a, seeder.id());
    const auto pow_seeder_a = ephemeralnet::test::NodeTestAccess::handshake_work(seeder, leecher_a.id());
    const auto pow_leecher_b = ephemeralnet::test::NodeTestAccess::handshake_work(leecher_b, seeder.id());
    const auto pow_seeder_b = ephemeralnet::test::NodeTestAccess::handshake_work(seeder, leecher_b.id());
    if (!require(pow_leecher_a.has_value(), "leecher A handshake work failed")) {
        return 1;
    }
    if (!require(pow_seeder_a.has_value(), "seeder handshake work for leecher A failed")) {
        return 1;
    }
    if (!require(pow_leecher_b.has_value(), "leecher B handshake work failed")) {
        return 1;
    }
    if (!require(pow_seeder_b.has_value(), "seeder handshake work for leecher B failed")) {
        return 1;
    }
    const bool handshake_sa = seeder.perform_handshake(leecher_a.id(), leecher_a.public_identity(), *pow_leecher_a);
    const bool handshake_as = leecher_a.perform_handshake(seeder.id(), seeder.public_identity(), *pow_seeder_a);
    const bool handshake_sb = seeder.perform_handshake(leecher_b.id(), leecher_b.public_identity(), *pow_leecher_b);
    const bool handshake_bs = leecher_b.perform_handshake(seeder.id(), seeder.public_identity(), *pow_seeder_b);
    if (!require(handshake_sa && handshake_as, "leecher A handshake negotiation failed")) {
        return 1;
    }
    if (!require(handshake_sb && handshake_bs, "leecher B handshake negotiation failed")) {
        return 1;
    }

    ephemeralnet::ChunkId chunk_id{};
    chunk_id.fill(0x5Au);

    ephemeralnet::ChunkData chunk_payload(256, 0xABu);
    const auto manifest = seeder.store_chunk(chunk_id, chunk_payload, 180s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    ephemeralnet::protocol::AnnouncePayload announce_a{};
    announce_a.chunk_id = chunk_id;
    announce_a.peer_id = seeder_id;
    announce_a.endpoint = "127.0.0.1:" + std::to_string(seeder_port);
    announce_a.ttl = 120s;
    announce_a.manifest_uri = manifest_uri;
    announce_a.assigned_shards.push_back(manifest.shards.front().index);
    ephemeralnet::test::NodeTestAccess::handle_announce(leecher_a, announce_a, seeder_id);

    ephemeralnet::protocol::AnnouncePayload announce_b{};
    announce_b.chunk_id = chunk_id;
    announce_b.peer_id = seeder_id;
    announce_b.endpoint = "127.0.0.1:" + std::to_string(seeder_port);
    announce_b.ttl = 120s;
    announce_b.manifest_uri = manifest_uri;
    announce_b.assigned_shards.push_back(manifest.shards.back().index);
    ephemeralnet::test::NodeTestAccess::handle_announce(leecher_b, announce_b, seeder_id);

    auto start = std::chrono::steady_clock::now();
    std::optional<ephemeralnet::ChunkData> leecher_a_data;
    std::optional<ephemeralnet::ChunkData> leecher_b_data;

    while (std::chrono::steady_clock::now() - start < 15s) {
        seeder.tick();
        leecher_a.tick();
        leecher_b.tick();

        if (!leecher_a_data) {
            auto result = leecher_a.fetch_chunk(chunk_id);
            if (result.has_value()) {
                leecher_a_data = std::move(result);
            }
        }

        if (!leecher_b_data) {
            auto result = leecher_b.fetch_chunk(chunk_id);
            if (result.has_value()) {
                leecher_b_data = std::move(result);
            }
        }

        if (leecher_a_data && leecher_b_data) {
            break;
        }

        std::this_thread::sleep_for(100ms);
    }

    if (!require(leecher_a_data.has_value(), "leecher A failed to complete fetch")) {
        return 1;
    }
    if (!require(leecher_b_data.has_value(), "leecher B failed to complete fetch")) {
        return 1;
    }
    if (!require(*leecher_a_data == chunk_payload, "leecher A payload mismatch")) {
        return 1;
    }
    if (!require(*leecher_b_data == chunk_payload, "leecher B payload mismatch")) {
        return 1;
    }
    if (!require(simulation->dropped.load(std::memory_order_relaxed) >= 1, "expected network drops were not observed")) {
        return 1;
    }

    shutdown();
    return 0;
}
