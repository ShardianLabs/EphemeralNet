#pragma once

#include "ephemeralnet/core/Node.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace ephemeralnet::test {

class NodeTestAccess {
public:
    struct SwarmSnapshot {
        bool self_seed{false};
        bool self_leecher{false};
        std::vector<std::string> seeds;
        std::vector<std::string> leechers;
    };

    static void handle_announce(Node& node,
                                const protocol::AnnouncePayload& payload,
                                const PeerId& sender) {
        node.handle_announce(payload, sender);
    }

    static std::optional<std::size_t> pending_attempts(const Node& node, const ChunkId& chunk_id) {
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it == node.pending_chunk_fetches_.end()) {
            return std::nullopt;
        }
        return it->second.attempts;
    }

    static bool has_pending_fetch(const Node& node, const ChunkId& chunk_id) {
        const auto key = chunk_id_to_string(chunk_id);
        return node.pending_chunk_fetches_.find(key) != node.pending_chunk_fetches_.end();
    }

    static void register_chunk_provider(Node& node,
                                        const ChunkId& chunk_id,
                                        const PeerId& provider_id,
                                        std::chrono::seconds ttl = std::chrono::seconds(120),
                                        std::string address = "127.0.0.1:0") {
        PeerContact contact{};
        contact.id = provider_id;
        contact.address = std::move(address);
        contact.expires_at = std::chrono::steady_clock::now() + ttl;
        node.dht_.add_contact(chunk_id, std::move(contact), ttl);
    }

    static void force_availability_refresh(Node& node, const ChunkId& chunk_id) {
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it == node.pending_chunk_fetches_.end()) {
            return;
        }
        node.refresh_provider_count(it->second, std::chrono::steady_clock::now(), true);
    }

    static std::optional<std::size_t> provider_count(Node& node, const ChunkId& chunk_id) {
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it != node.pending_chunk_fetches_.end()) {
            return it->second.provider_count;
        }
        return node.count_known_providers(chunk_id);
    }

    static std::size_t pending_uploads(const Node& node) {
        return node.pending_uploads_.size();
    }

    static std::size_t active_uploads(const Node& node) {
        return node.active_uploads_.size();
    }

    static std::size_t active_uploads_for_peer(const Node& node, const PeerId& peer_id) {
        const auto key = peer_id_to_string(peer_id);
        const auto it = node.active_uploads_per_peer_.find(key);
        if (it == node.active_uploads_per_peer_.end()) {
            return 0;
        }
        return it->second;
    }

    static void enqueue_upload(Node& node,
                               const PeerId& peer_id,
                               const ChunkId& chunk_id,
                               std::size_t payload_size) {
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
        SwarmSnapshot snapshot{};
        if (const auto* ledger = node.find_swarm_ledger(chunk_id)) {
            snapshot.self_seed = ledger->self_seed;
            snapshot.self_leecher = ledger->self_leecher;
            snapshot.seeds.assign(ledger->seeds.begin(), ledger->seeds.end());
            snapshot.leechers.assign(ledger->leechers.begin(), ledger->leechers.end());
            std::sort(snapshot.seeds.begin(), snapshot.seeds.end());
            std::sort(snapshot.leechers.begin(), snapshot.leechers.end());
        }
        return snapshot;
    }
};

}  // namespace ephemeralnet::test
