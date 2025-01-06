#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/CryptoManager.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/storage/ChunkStore.hpp"

#include <chrono>
#include <string>
#include <vector>
#include <optional>

namespace ephemeralnet {

class Node {
public:
    Node(PeerId id, Config config = {});

    void announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl);
    void store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl);
    std::optional<ChunkData> fetch_chunk(const ChunkId& chunk_id);

    void tick();

    const PeerId& id() const noexcept { return id_; }
    Config& config() noexcept { return config_; }
    const Config& config() const noexcept { return config_; }

private:
    PeerId id_{};
    Config config_{};
    ChunkStore chunk_store_;
    KademliaTable dht_;
    SessionManager sessions_;
    crypto::CryptoManager crypto_;
    std::chrono::steady_clock::time_point last_cleanup_{};
};

}  
