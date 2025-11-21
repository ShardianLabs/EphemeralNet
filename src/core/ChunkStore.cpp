#include "ephemeralnet/storage/ChunkStore.hpp"

#include "ephemeralnet/Types.hpp"

#include <algorithm>
#include <fstream>
#include <utility>
#include <vector>

namespace ephemeralnet {

namespace {
// Min TTL used when callers accidentally pass zero.
constexpr std::chrono::seconds kMinimumTtl{std::chrono::seconds{1}};
}

ChunkStore::ChunkStore(Config config)
    : config_(config),
      persistent_enabled_(config.storage_persistent_enabled),
      wipe_on_expiry_(config.storage_wipe_on_expiry),
      wipe_passes_(std::max<std::uint8_t>(config.storage_wipe_passes, static_cast<std::uint8_t>(1))) {
    if (persistent_enabled_) {
        storage_root_ = std::filesystem::path(config.storage_directory.empty() ? "storage" : config.storage_directory);
        if (!ensure_storage_directory()) {
            persistent_enabled_ = false;
        }
    }
}

void ChunkStore::put(const ChunkId& id,
                     ChunkData data,
                     std::chrono::seconds ttl,
                     std::array<std::uint8_t, 12> nonce,
                     bool encrypted) {
    std::scoped_lock lock(chunks_mutex_);
    const auto key = chunk_id_to_string(id);
    const auto effective_ttl = ttl.count() > 0 ? ttl : config_.default_chunk_ttl;
    const auto sanitized_ttl = std::max(effective_ttl, kMinimumTtl);

    const auto existing = chunks_.find(key);
    if (existing != chunks_.end()) {
        if (existing->second.persisted) {
            wipe_persisted_chunk(existing->second);
        }
    }

    ChunkRecord record{};
    record.id = id;
    record.data = std::move(data);
    record.expires_at = compute_expiry(sanitized_ttl);
    record.encrypted = encrypted;
    record.nonce = nonce;

    if (persistent_enabled_) {
        record.file_path = chunk_path_for_key(key);
        if (persist_chunk_to_disk(key, record)) {
            record.persisted = true;
        } else {
            record.persisted = false;
            record.file_path.clear();
        }
    }

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
    std::scoped_lock lock(chunks_mutex_);
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

std::vector<ChunkId> ChunkStore::sweep_expired() {
    std::scoped_lock lock(chunks_mutex_);
    const auto now = std::chrono::steady_clock::now();
    std::vector<ChunkId> removed;
    for (auto it = chunks_.begin(); it != chunks_.end();) {
        if (now >= it->second.expires_at) {
            if (it->second.persisted && wipe_on_expiry_) {
                wipe_persisted_chunk(it->second);
            }
            removed.push_back(it->second.id);
            it = chunks_.erase(it);
        } else {
            ++it;
        }
    }
    return removed;
}

std::size_t ChunkStore::size() const noexcept {
    std::scoped_lock lock(chunks_mutex_);
    return chunks_.size();
}

std::chrono::steady_clock::time_point ChunkStore::compute_expiry(std::chrono::seconds ttl) {
    return std::chrono::steady_clock::now() + ttl;
}

std::vector<ChunkStore::SnapshotEntry> ChunkStore::snapshot() const {
    std::scoped_lock lock(chunks_mutex_);
    std::vector<SnapshotEntry> result;
    result.reserve(chunks_.size());

    for (const auto& [key, record] : chunks_) {
        SnapshotEntry entry{};
        entry.id = record.id;
        entry.key = key;
        entry.expires_at = record.expires_at;
        entry.encrypted = record.encrypted;
        entry.size = record.data.size();
        result.push_back(entry);
    }

    return result;
}

std::filesystem::path ChunkStore::chunk_path_for_key(const std::string& key) const {
    if (!persistent_enabled_) {
        return {};
    }
    return storage_root_ / (key + ".chunk");
}

bool ChunkStore::ensure_storage_directory() {
    std::error_code ec;
    if (storage_root_.empty()) {
        storage_root_ = std::filesystem::current_path();
    }
    if (std::filesystem::exists(storage_root_, ec)) {
        if (!std::filesystem::is_directory(storage_root_, ec)) {
            return false;
        }
        return true;
    }
    return std::filesystem::create_directories(storage_root_, ec);
}

bool ChunkStore::persist_chunk_to_disk(const std::string& key, const ChunkRecord& record) {
    if (!persistent_enabled_) {
        return false;
    }
    if (!ensure_storage_directory()) {
        return false;
    }

    const auto path = chunk_path_for_key(key);
    if (std::filesystem::exists(path)) {
        secure_wipe_file(path);
    }

    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<const char*>(record.data.data()), static_cast<std::streamsize>(record.data.size()));
    stream.flush();
    if (!stream) {
        secure_wipe_file(path);
        return false;
    }
    return true;
}

bool ChunkStore::secure_wipe_file(const std::filesystem::path& path) const {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return true;
    }

    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return false;
    }

    std::fstream stream(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!stream) {
        return false;
    }

    std::vector<char> buffer(4096, 0);
    for (std::uint8_t pass = 0; pass < wipe_passes_; ++pass) {
        stream.seekp(0, std::ios::beg);
        std::uint64_t remaining = size;
        while (remaining > 0) {
            const auto chunk = static_cast<std::streamsize>(std::min<std::uint64_t>(buffer.size(), remaining));
            stream.write(buffer.data(), chunk);
            remaining -= static_cast<std::uint64_t>(chunk);
        }
        stream.flush();
        if (!stream) {
            break;
        }
    }
    stream.close();

    std::filesystem::remove(path, ec);
    return !std::filesystem::exists(path, ec);
}

void ChunkStore::wipe_persisted_chunk(const ChunkRecord& record) {
    if (!record.persisted) {
        return;
    }
    secure_wipe_file(record.file_path);
}

}  
