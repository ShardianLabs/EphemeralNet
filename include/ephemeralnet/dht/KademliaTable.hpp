#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"

#include <chrono>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ephemeralnet {

struct PeerContact {
    PeerId id{};
    std::string address;
    std::chrono::steady_clock::time_point expires_at{};
};

struct ChunkLocator {
    ChunkId id{};
    std::vector<PeerContact> holders;
    std::chrono::steady_clock::time_point expires_at{};
};

class KademliaTable {
public:
    explicit KademliaTable(Config config = {});

    void add_contact(const ChunkId& chunk_id, PeerContact contact, std::chrono::seconds ttl);
    std::vector<PeerContact> find_providers(const ChunkId& chunk_id);
    void sweep_expired();

private:
    Config config_;
    std::unordered_map<std::string, ChunkLocator> table_;
};

}  
