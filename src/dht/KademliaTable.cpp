#include "ephemeralnet/dht/KademliaTable.hpp"

#include "ephemeralnet/Types.hpp"

#include <algorithm>

namespace ephemeralnet {

namespace {
constexpr std::size_t kMaxProviders = 20;
}

KademliaTable::KademliaTable(Config config)
    : config_(config) {}

void KademliaTable::add_contact(const ChunkId& chunk_id, PeerContact contact, std::chrono::seconds ttl) {
    contact.expires_at = std::chrono::steady_clock::now() + ttl;

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
                          return now >= contact.expires_at;
                      }),
        holders.end());

    if (holders.empty()) {
        table_.erase(it);
        return {};
    }

    return holders;
}

void KademliaTable::sweep_expired() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = table_.begin(); it != table_.end();) {
        auto& locator = it->second;
        auto& holders = locator.holders;
        holders.erase(std::remove_if(holders.begin(), holders.end(), [&](const PeerContact& contact) {
                              return now >= contact.expires_at;
                          }),
            holders.end());

        if (holders.empty() || now >= locator.expires_at) {
            it = table_.erase(it);
        } else {
            ++it;
        }
    }
}

}  
