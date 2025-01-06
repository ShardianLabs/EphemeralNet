#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/Types.hpp"

#include <iostream>
#include <span>
#include <utility>

namespace ephemeralnet {

Node::Node(PeerId id, Config config)
    : id_(id),
      config_(config),
      chunk_store_(config),
      dht_(config),
    sessions_(),
    crypto_(),
      last_cleanup_(std::chrono::steady_clock::now()) {}

void Node::announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl) {
    PeerContact self_contact{.id = id_, .address = peer_id_to_string(id_), .expires_at = std::chrono::steady_clock::now() + ttl};
    dht_.add_contact(chunk_id, self_contact, ttl);
}

void Node::store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl) {
    auto sealed = crypto_.encrypt(chunk_id, data);
    chunk_store_.put(chunk_id,
        std::move(sealed.data),
        ttl,
        sealed.nonce.bytes,
        sealed.encrypted);
    announce_chunk(chunk_id, ttl);
}

std::optional<ChunkData> Node::fetch_chunk(const ChunkId& chunk_id) {
    if (auto record = chunk_store_.get_record(chunk_id)) {
        if (record->encrypted) {
            const crypto::Nonce nonce{record->nonce};
            const std::span<const std::uint8_t> ciphertext{record->data};
            const auto maybe_plain = crypto_.decrypt(chunk_id, ciphertext, nonce);
            return maybe_plain;
        }
        return record->data;
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
