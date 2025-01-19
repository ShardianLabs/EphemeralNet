#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ephemeralnet {

struct ChunkRecord {
    ChunkId id{};
    ChunkData data;
    std::chrono::steady_clock::time_point expires_at{};
    bool encrypted{false};
    std::array<std::uint8_t, 12> nonce{};
};

class ChunkStore {
public:
    explicit ChunkStore(Config config = {});

    struct SnapshotEntry {
        ChunkId id{};
        std::string key;
        std::chrono::steady_clock::time_point expires_at{};
        bool encrypted{false};
        std::size_t size{0};
    };

    void put(const ChunkId& id,
             ChunkData data,
             std::chrono::seconds ttl,
             std::array<std::uint8_t, 12> nonce = {},
             bool encrypted = false);
    std::optional<ChunkData> get(const ChunkId& id);
    std::optional<ChunkRecord> get_record(const ChunkId& id);
    std::vector<ChunkId> sweep_expired();
    std::size_t size() const noexcept;
    std::vector<SnapshotEntry> snapshot() const;

private:
    Config config_;
    std::unordered_map<std::string, ChunkRecord> chunks_;

    static std::chrono::steady_clock::time_point compute_expiry(std::chrono::seconds ttl);
};

}  
