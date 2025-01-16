#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"

#include <array>
#include <bit>
#include <chrono>
#include <deque>
#include <optional>
#include <string>
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
    KademliaTable(PeerId self_id, Config config = {});

    void add_contact(const ChunkId& chunk_id, PeerContact contact, std::chrono::seconds ttl);
    std::vector<PeerContact> find_providers(const ChunkId& chunk_id);
    std::vector<PeerContact> closest_peers(const PeerId& target, std::size_t limit) const;
    void sweep_expired();
    std::vector<ChunkLocator> snapshot_locators() const;

private:
    static constexpr std::size_t kBucketSize = 16;
    static constexpr std::size_t kIdBits = PeerId{}.size() * 8;
    using Bucket = std::deque<PeerContact>;

    PeerId self_id_{};
    Config config_;
    std::unordered_map<std::string, ChunkLocator> table_;
    std::array<Bucket, kIdBits> buckets_{};

    void upsert_bucket(PeerContact contact);
    void sweep_buckets();
    static std::array<std::uint8_t, PeerId{}.size()> xor_distance(const PeerId& lhs, const PeerId& rhs);
    std::optional<std::size_t> bucket_index_for(const PeerId& peer) const;
};

}  
