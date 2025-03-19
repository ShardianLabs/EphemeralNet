#pragma once

#include "ephemeralnet/core/Node.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace ephemeralnet::test {

class NodeTestAccess {
public:
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
};

}  // namespace ephemeralnet::test
