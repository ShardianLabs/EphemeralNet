#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/Types.hpp"

#include <iostream>
#include <utility>

namespace ephemeralnet {

Node::Node(PeerId id, Config config)
    : id_(id),
      config_(config),
      chunk_store_(config),
      dht_(config),
      sessions_(),
      last_cleanup_(std::chrono::steady_clock::now()) {}

void Node::announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl) {
    PeerContact self_contact{.id = id_, .address = peer_id_to_string(id_), .expires_at = std::chrono::steady_clock::now() + ttl};
    dht_.add_contact(chunk_id, self_contact, ttl);
}

void Node::store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl) {
    chunk_store_.put(chunk_id, std::move(data), ttl);
    announce_chunk(chunk_id, ttl);
}

std::optional<ChunkData> Node::fetch_chunk(const ChunkId& chunk_id) {
    if (auto local = chunk_store_.get(chunk_id)) {
        return local;
    }

    const auto providers = dht_.find_providers(chunk_id);
    if (providers.empty()) {
    std::cout << "[Node] No providers available for chunk " << chunk_id_to_string(chunk_id) << "\n";
        return std::nullopt;
    }

    std::cout << "[Node] Providers known for chunk " << chunk_id_to_string(chunk_id) << ": " << providers.size() << "\n";
    return std::nullopt;
}

void Node::tick() {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = now - last_cleanup_;
    if (elapsed >= config_.cleanup_interval) {
        chunk_store_.sweep_expired();
        dht_.sweep_expired();
        last_cleanup_ = now;
    }
}

}  
