#pragma once

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/CryptoManager.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace ephemeralnet::network {

struct SessionKeyContext {
    crypto::Key shared_secret{};
    std::array<std::uint8_t, 32> current_key{};
    std::uint64_t counter{0};
    std::chrono::steady_clock::time_point last_rotation{};
};

class KeyManager {
public:
    explicit KeyManager(std::chrono::seconds rotation_interval = std::chrono::minutes(15));

    void register_session(const PeerId& peer_id, const crypto::Key& shared_secret);
    void register_session_with_material(const PeerId& peer_id,
                                        const crypto::Key& shared_secret,
                                        std::span<const std::uint8_t> material,
                                        std::chrono::steady_clock::time_point reference_time);
    std::optional<std::array<std::uint8_t, 32>> current_key(const PeerId& peer_id) const;
    std::optional<std::array<std::uint8_t, 32>> rotate_if_needed(const PeerId& peer_id,
                                                                 std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    std::vector<PeerId> known_peers() const;

private:
    std::chrono::seconds rotation_interval_;
    std::unordered_map<std::string, SessionKeyContext> contexts_;

    static std::array<std::uint8_t, 32> derive_key(const crypto::Key& shared_secret,
                                                   std::uint64_t counter,
                                                   std::chrono::steady_clock::time_point timestamp);
};

}  // namespace ephemeralnet::network
