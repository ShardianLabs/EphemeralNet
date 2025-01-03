#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"

#include <chrono>
#include <optional>
#include <unordered_map>

namespace ephemeralnet {

struct ChunkRecord {
    ChunkData data;
    std::chrono::steady_clock::time_point expires_at{};
};

class ChunkStore {
public:
    explicit ChunkStore(Config config = {});

    void put(const ChunkId& id, ChunkData data, std::chrono::seconds ttl);
    std::optional<ChunkData> get(const ChunkId& id);
    void sweep_expired();
    std::size_t size() const noexcept;

private:
    Config config_;
    std::unordered_map<std::string, ChunkRecord> chunks_;

    static std::chrono::steady_clock::time_point compute_expiry(std::chrono::seconds ttl);
};

}  
