#pragma once

#include "ephemeralnet/Types.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>

namespace ephemeralnet::network {

class ReputationManager {
public:
    ReputationManager(int success_reward = 1, int failure_penalty = 2);

    void record_success(const PeerId& peer_id);
    void record_failure(const PeerId& peer_id);
    int score(const PeerId& peer_id) const;
    std::size_t peer_count() const noexcept;

private:
    struct Entry {
        int score{0};
        std::chrono::steady_clock::time_point last_update{};
    };

    static constexpr int kMaxScore = 100;
    static constexpr int kMinScore = -100;

    int success_reward_;
    int failure_penalty_;
    std::unordered_map<std::string, Entry> entries_;
    mutable std::mutex mutex_;

    static std::string key_for(const PeerId& peer_id);
};

}  // namespace ephemeralnet::network
