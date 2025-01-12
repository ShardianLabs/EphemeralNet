#include "ephemeralnet/network/KeyManager.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/HmacSha256.hpp"

#include <algorithm>
#include <chrono>

namespace ephemeralnet::network {

KeyManager::KeyManager(std::chrono::seconds rotation_interval)
    : rotation_interval_(rotation_interval) {}

void KeyManager::register_session(const PeerId& peer_id, const crypto::Key& shared_secret) {
    SessionKeyContext context{};
    context.shared_secret = shared_secret;
    context.last_rotation = std::chrono::steady_clock::now();
    context.current_key = derive_key(shared_secret, context.counter, context.last_rotation);

    contexts_[peer_id_to_string(peer_id)] = context;
}

std::optional<std::array<std::uint8_t, 32>> KeyManager::current_key(const PeerId& peer_id) const {
    const auto it = contexts_.find(peer_id_to_string(peer_id));
    if (it == contexts_.end()) {
        return std::nullopt;
    }
    return it->second.current_key;
}

std::optional<std::array<std::uint8_t, 32>> KeyManager::rotate_if_needed(const PeerId& peer_id,
                                                                         std::chrono::steady_clock::time_point now) {
    auto it = contexts_.find(peer_id_to_string(peer_id));
    if (it == contexts_.end()) {
        return std::nullopt;
    }

    auto& context = it->second;
    if (now - context.last_rotation < rotation_interval_) {
        return std::nullopt;
    }

    context.counter += 1;
    context.last_rotation = now;
    context.current_key = derive_key(context.shared_secret, context.counter, context.last_rotation);
    return context.current_key;
}

std::array<std::uint8_t, 32> KeyManager::derive_key(const crypto::Key& shared_secret,
                                                    std::uint64_t counter,
                                                    std::chrono::steady_clock::time_point timestamp) {
    std::array<std::uint8_t, 16> material{};

    for (int i = 0; i < 8; ++i) {
        material[7 - i] = static_cast<std::uint8_t>((counter >> (i * 8)) & 0xFFu);
    }

    const auto ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(timestamp.time_since_epoch()).count();
    for (int i = 0; i < 8; ++i) {
        material[15 - i] = static_cast<std::uint8_t>((ticks >> (i * 8)) & 0xFFu);
    }

    const auto key_span = std::span<const std::uint8_t>(shared_secret.bytes);
    const auto data_span = std::span<const std::uint8_t>(material);
    const auto mac = crypto::HmacSha256::compute(key_span, data_span);
    return mac;
}

}  // namespace ephemeralnet::network
