#include "ephemeralnet/storage/ChunkStore.hpp"

#include "ephemeralnet/Types.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace ephemeralnet {

namespace {
// Min TTL used when callers accidentally pass zero.
constexpr std::chrono::seconds kMinimumTtl{std::chrono::seconds{1}};
}

ChunkStore::ChunkStore(Config config)
    : config_(config) {}

void ChunkStore::put(const ChunkId& id,
                     ChunkData data,
                     std::chrono::seconds ttl,
                     std::array<std::uint8_t, 12> nonce,
                     bool encrypted) {
    const auto key = chunk_id_to_string(id);
    const auto effective_ttl = ttl.count() > 0 ? ttl : config_.default_chunk_ttl;
    const auto sanitized_ttl = std::max(effective_ttl, kMinimumTtl);

    ChunkRecord record{
        .data = std::move(data),
        .expires_at = compute_expiry(sanitized_ttl),
        .encrypted = encrypted,
        .nonce = nonce,
    };
    chunks_.insert_or_assign(key, std::move(record));
}

std::optional<ChunkData> ChunkStore::get(const ChunkId& id) {
    const auto record = get_record(id);
    if (!record.has_value()) {
        return std::nullopt;
    }
    return record->data;
}

std::optional<ChunkRecord> ChunkStore::get_record(const ChunkId& id) {
    const auto key = chunk_id_to_string(id);
    const auto it = chunks_.find(key);
    if (it == chunks_.end()) {
        return std::nullopt;
    }

    if (std::chrono::steady_clock::now() >= it->second.expires_at) {
        chunks_.erase(it);
        return std::nullopt;
    }

    return it->second;
}

void ChunkStore::sweep_expired() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = chunks_.begin(); it != chunks_.end();) {
        if (now >= it->second.expires_at) {
            it = chunks_.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t ChunkStore::size() const noexcept {
    return chunks_.size();
}

std::chrono::steady_clock::time_point ChunkStore::compute_expiry(std::chrono::seconds ttl) {
    return std::chrono::steady_clock::now() + ttl;
}

std::vector<ChunkStore::SnapshotEntry> ChunkStore::snapshot() const {
    std::vector<SnapshotEntry> result;
    result.reserve(chunks_.size());

    for (const auto& [key, record] : chunks_) {
        SnapshotEntry entry{};
        entry.key = key;
        entry.expires_at = record.expires_at;
        entry.encrypted = record.encrypted;
        entry.size = record.data.size();
        result.push_back(entry);
    }

    return result;
}

}  
