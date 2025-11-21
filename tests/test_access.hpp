#pragma once

#include "ephemeralnet/core/Node.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ephemeralnet::test {

class NodeTestAccess {
public:
    struct SwarmSnapshot {
        bool self_seed{false};
        bool self_leecher{false};
        std::vector<std::string> seeds;
        std::vector<std::string> leechers;
        std::unordered_map<std::string, std::vector<std::string>> delivered_endpoints;
    };

    static void handle_announce(Node& node,
                                const protocol::AnnouncePayload& payload,
                                const PeerId& sender,
                                std::uint8_t version = protocol::kCurrentMessageVersion) {
        node.handle_announce(payload, sender, version);
    }

    static bool apply_pow(Node& node, protocol::AnnouncePayload& payload) {
        return node.apply_announce_pow(payload);
    }

    static std::optional<std::uint64_t> handshake_work(Node& initiator, const PeerId& responder) {
        return initiator.generate_handshake_work(responder);
    }

    static std::optional<std::size_t> pending_attempts(const Node& node, const ChunkId& chunk_id) {
        auto guard = lock_scheduler(node);
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it == node.pending_chunk_fetches_.end()) {
            return std::nullopt;
        }
        return it->second.attempts;
    }

    static bool has_pending_fetch(const Node& node, const ChunkId& chunk_id) {
        auto guard = lock_scheduler(node);
        const auto key = chunk_id_to_string(chunk_id);
        return node.pending_chunk_fetches_.find(key) != node.pending_chunk_fetches_.end();
    }

    static void register_chunk_provider(Node& node,
                                        const ChunkId& chunk_id,
                                        const PeerId& provider_id,
                                        std::chrono::seconds ttl = std::chrono::seconds(120),
                                        std::string address = "127.0.0.1:0") {
        auto guard = lock_scheduler(node);
        PeerContact contact{};
        contact.id = provider_id;
        contact.address = std::move(address);
        contact.expires_at = std::chrono::steady_clock::now() + ttl;
        node.dht_.add_contact(chunk_id, std::move(contact), ttl);
    }

    static void force_availability_refresh(Node& node, const ChunkId& chunk_id) {
        auto guard = lock_scheduler(node);
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it == node.pending_chunk_fetches_.end()) {
            return;
        }
        node.refresh_provider_count(it->second, std::chrono::steady_clock::now(), true);
    }

    static std::optional<std::size_t> provider_count(Node& node, const ChunkId& chunk_id) {
        auto guard = lock_scheduler(node);
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it != node.pending_chunk_fetches_.end()) {
            return it->second.provider_count;
        }
        return node.count_known_providers(chunk_id);
    }

    static std::size_t pending_uploads(const Node& node) {
        auto guard = lock_scheduler(node);
        return node.pending_uploads_.size();
    }

    static std::size_t active_uploads(const Node& node) {
        auto guard = lock_scheduler(node);
        return node.active_uploads_.size();
    }

    static std::size_t active_uploads_for_peer(const Node& node, const PeerId& peer_id) {
        auto guard = lock_scheduler(node);
        const auto key = peer_id_to_string(peer_id);
        const auto it = node.active_uploads_per_peer_.find(key);
        if (it == node.active_uploads_per_peer_.end()) {
            return 0;
        }
        return it->second;
    }

    static std::uint64_t completed_uploads(const Node& node) {
        return node.total_completed_uploads_.load(std::memory_order_relaxed);
    }

    static std::size_t peak_active_uploads(const Node& node) {
        return node.peak_active_uploads_.load(std::memory_order_relaxed);
    }

    static void enqueue_upload(Node& node,
                               const PeerId& peer_id,
                               const ChunkId& chunk_id,
                               std::size_t payload_size) {
        auto guard = lock_scheduler(node);
        Node::PendingUploadRequest request{};
        request.chunk_id = chunk_id;
        request.peer_id = peer_id;
        request.enqueue_time = std::chrono::steady_clock::now();
        request.payload_size = payload_size;
        node.pending_uploads_.push_back(std::move(request));
    }

    static void inject_active_upload(Node& node,
                                     const PeerId& peer_id,
                                     const ChunkId& chunk_id,
                                     std::chrono::steady_clock::time_point started_at) {
        auto guard = lock_scheduler(node);
        Node::ActiveUploadState state{};
        state.chunk_id = chunk_id;
        state.peer_id = peer_id;
        state.started_at = started_at;
        state.payload_size = 0;
        const auto key = node.make_upload_key(peer_id, chunk_id);
        node.active_uploads_[key] = state;
        node.active_uploads_per_peer_[peer_id_to_string(peer_id)] += 1;
    }

    static void process_uploads(Node& node) {
        node.process_pending_uploads();
    }

    static SwarmSnapshot swarm_snapshot(const Node& node, const ChunkId& chunk_id) {
        auto guard = lock_scheduler(node);
        SwarmSnapshot snapshot{};
        if (const auto* ledger = node.find_swarm_ledger(chunk_id)) {
            snapshot.self_seed = ledger->self_seed;
            snapshot.self_leecher = ledger->self_leecher;
            snapshot.seeds.assign(ledger->seeds.begin(), ledger->seeds.end());
            snapshot.leechers.assign(ledger->leechers.begin(), ledger->leechers.end());
            std::sort(snapshot.seeds.begin(), snapshot.seeds.end());
            std::sort(snapshot.leechers.begin(), snapshot.leechers.end());
        }
        if (const auto plan = swarm_plan(node, chunk_id)) {
            snapshot.delivered_endpoints = plan->delivered_endpoints;
        }
        return snapshot;
    }

    static std::optional<SwarmDistributionPlan> swarm_plan(const Node& node, const ChunkId& chunk_id) {
        auto guard = lock_scheduler(node);
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.swarm_plans_.find(key);
        if (it == node.swarm_plans_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    static void rebroadcast_manifest(Node& node, const ChunkId& chunk_id) {
        if (const auto manifest = node.manifest_for_chunk(chunk_id)) {
            node.broadcast_manifest(*manifest);
        }
    }

    static void withdraw_provider(Node& node, const ChunkId& chunk_id, const PeerId& provider) {
        auto guard = lock_scheduler(node);
        node.dht_.withdraw_contact(chunk_id, provider);
    }

    static std::optional<std::array<std::uint8_t, 32>> rotate_key(Node& node,
                                                                  const PeerId& peer_id,
                                                                  std::chrono::steady_clock::time_point when) {
        return node.key_manager_.rotate_if_needed(peer_id, when);
    }

    static bool announce_blocked(const Node& node, const PeerId& peer_id) {
        auto guard = lock_scheduler(node);
        const auto key = peer_id_to_string(peer_id);
        const auto it = node.peer_announce_lockouts_.find(key);
        if (it == node.peer_announce_lockouts_.end()) {
            return false;
        }
        return it->second > std::chrono::steady_clock::now();
    }

    static void expire_announce_lock(Node& node, const PeerId& peer_id) {
        auto guard = lock_scheduler(node);
        const auto key = peer_id_to_string(peer_id);
        const auto it = node.peer_announce_lockouts_.find(key);
        if (it != node.peer_announce_lockouts_.end()) {
            it->second = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        }
    }

    static Node::PowStatistics pow_stats(const Node& node) {
        return node.pow_statistics();
    }

    static std::vector<Config::AdvertisedEndpoint> advertised_endpoints(const Node& node) {
        auto guard = lock_scheduler(node);
        return node.config_.advertised_endpoints;
    }
private:
    static std::unique_lock<std::recursive_mutex> lock_scheduler(const Node& node) {
        return std::unique_lock<std::recursive_mutex>(node.scheduler_mutex_);
    }
};

}  // namespace ephemeralnet::test
