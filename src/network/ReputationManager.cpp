#include "ephemeralnet/network/ReputationManager.hpp"

#include "ephemeralnet/Types.hpp"

#include <algorithm>
#include <mutex>

namespace ephemeralnet::network {

ReputationManager::ReputationManager(int success_reward, int failure_penalty)
    : success_reward_(success_reward), failure_penalty_(failure_penalty) {}

void ReputationManager::record_success(const PeerId& peer_id) {
    std::scoped_lock lock(mutex_);
    auto& entry = entries_[key_for(peer_id)];
    entry.score = std::min(entry.score + success_reward_, kMaxScore);
    entry.last_update = std::chrono::steady_clock::now();
}

void ReputationManager::record_failure(const PeerId& peer_id) {
    std::scoped_lock lock(mutex_);
    auto& entry = entries_[key_for(peer_id)];
    entry.score = std::max(entry.score - failure_penalty_, kMinScore);
    entry.last_update = std::chrono::steady_clock::now();
}

int ReputationManager::score(const PeerId& peer_id) const {
    std::scoped_lock lock(mutex_);
    const auto it = entries_.find(key_for(peer_id));
    if (it == entries_.end()) {
        return 0;
    }
    return it->second.score;
}

std::size_t ReputationManager::peer_count() const noexcept {
    std::scoped_lock lock(mutex_);
    return entries_.size();
}

std::string ReputationManager::key_for(const PeerId& peer_id) {
    return peer_id_to_string(peer_id);
}

}  // namespace ephemeralnet::network
