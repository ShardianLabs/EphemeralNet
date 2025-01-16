#include "ephemeralnet/dht/KademliaTable.hpp"

#include "ephemeralnet/Types.hpp"

#include <algorithm>
#include <bit>
#include <utility>

namespace ephemeralnet {

namespace {
constexpr std::size_t kMaxProviders = 20;

bool expired(const PeerContact& contact, const std::chrono::steady_clock::time_point& now) {
    return now >= contact.expires_at;
}
}  // namespace

KademliaTable::KademliaTable(PeerId self_id, Config config)
    : self_id_(self_id),
      config_(config) {}

void KademliaTable::add_contact(const ChunkId& chunk_id, PeerContact contact, std::chrono::seconds ttl) {
    contact.expires_at = std::chrono::steady_clock::now() + ttl;
    upsert_bucket(contact);

    const auto key = chunk_id_to_string(chunk_id);
    auto& locator = table_[key];
    locator.id = chunk_id;
    locator.expires_at = contact.expires_at;

    auto& holders = locator.holders;
    holders.erase(std::remove_if(holders.begin(), holders.end(), [&](const PeerContact& existing) {
                          return existing.id == contact.id;
                      }),
        holders.end());

    holders.push_back(contact);

    if (holders.size() > kMaxProviders) {
        std::sort(holders.begin(), holders.end(), [](const PeerContact& lhs, const PeerContact& rhs) {
            return lhs.expires_at > rhs.expires_at;
        });
        holders.resize(kMaxProviders);
    }
}

std::vector<PeerContact> KademliaTable::find_providers(const ChunkId& chunk_id) {
    const auto key = chunk_id_to_string(chunk_id);
    const auto it = table_.find(key);
    if (it == table_.end()) {
        return {};
    }

    const auto now = std::chrono::steady_clock::now();
    auto& holders = it->second.holders;
    holders.erase(std::remove_if(holders.begin(), holders.end(), [&](const PeerContact& contact) {
                          return expired(contact, now);
                      }),
        holders.end());

    if (holders.empty()) {
        table_.erase(it);
        return {};
    }

    return holders;
}

std::vector<PeerContact> KademliaTable::closest_peers(const PeerId& target, std::size_t limit) const {
    struct Candidate {
        std::array<std::uint8_t, PeerId{}.size()> distance{};
        PeerContact contact;
    };

    const auto now = std::chrono::steady_clock::now();
    std::vector<Candidate> candidates;

    for (const auto& bucket : buckets_) {
        for (const auto& contact : bucket) {
            if (expired(contact, now)) {
                continue;
            }
            candidates.push_back(Candidate{xor_distance(contact.id, target), contact});
        }
    }

    std::sort(candidates.begin(), candidates.end(), [](const Candidate& lhs, const Candidate& rhs) {
        return lhs.distance < rhs.distance;
    });

    if (limit == 0) {
        return {};
    }

    const auto constrained = std::min(limit, candidates.size());
    std::vector<PeerContact> result;
    result.reserve(constrained);
    for (std::size_t i = 0; i < constrained; ++i) {
        result.push_back(candidates[i].contact);
    }

    return result;
}

void KademliaTable::sweep_expired() {
    sweep_buckets();

    const auto now = std::chrono::steady_clock::now();
    for (auto it = table_.begin(); it != table_.end();) {
        auto& locator = it->second;
        auto& holders = locator.holders;
        holders.erase(std::remove_if(holders.begin(), holders.end(), [&](const PeerContact& contact) {
                              return expired(contact, now);
                          }),
            holders.end());

        if (holders.empty() || now >= locator.expires_at) {
            it = table_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<ChunkLocator> KademliaTable::snapshot_locators() const {
    std::vector<ChunkLocator> result;
    result.reserve(table_.size());
    for (const auto& [_, locator] : table_) {
        result.push_back(locator);
    }
    return result;
}

void KademliaTable::upsert_bucket(PeerContact contact) {
    const auto index = bucket_index_for(contact.id);
    if (!index.has_value()) {
        return;
    }

    auto& bucket = buckets_[*index];
    const auto now = std::chrono::steady_clock::now();
    bucket.erase(std::remove_if(bucket.begin(), bucket.end(), [&](const PeerContact& entry) {
                       return expired(entry, now);
                   }),
        bucket.end());

    const auto existing = std::find_if(bucket.begin(), bucket.end(), [&](const PeerContact& entry) {
        return entry.id == contact.id;
    });

    if (existing != bucket.end()) {
        PeerContact refreshed = *existing;
        refreshed.address = contact.address;
        refreshed.expires_at = contact.expires_at;
        bucket.erase(existing);
        bucket.push_back(std::move(refreshed));
        return;
    }

    if (bucket.size() >= kBucketSize) {
        bucket.pop_front();
    }

    bucket.push_back(std::move(contact));
}

void KademliaTable::sweep_buckets() {
    const auto now = std::chrono::steady_clock::now();
    for (auto& bucket : buckets_) {
        bucket.erase(std::remove_if(bucket.begin(), bucket.end(), [&](const PeerContact& entry) {
                              return expired(entry, now);
                          }),
            bucket.end());
    }
}

std::array<std::uint8_t, PeerId{}.size()> KademliaTable::xor_distance(const PeerId& lhs, const PeerId& rhs) {
    std::array<std::uint8_t, PeerId{}.size()> distance{};
    for (std::size_t i = 0; i < distance.size(); ++i) {
        distance[i] = static_cast<std::uint8_t>(lhs[i] ^ rhs[i]);
    }
    return distance;
}

std::optional<std::size_t> KademliaTable::bucket_index_for(const PeerId& peer) const {
    std::size_t leading_zeros = 0;
    bool all_zero = true;

    for (std::size_t i = 0; i < peer.size(); ++i) {
        const auto diff = static_cast<std::uint8_t>(self_id_[i] ^ peer[i]);
        if (diff == 0) {
            leading_zeros += 8;
            continue;
        }

        all_zero = false;
        const auto diff32 = static_cast<unsigned int>(diff);
        const auto byte_leading = static_cast<std::size_t>(std::countl_zero(diff32) - 24);
        leading_zeros += byte_leading;
        break;
    }

    if (all_zero || leading_zeros >= kIdBits) {
        return std::nullopt;
    }

    const auto msb_index = kIdBits - leading_zeros - 1;
    return msb_index;
}

}  
