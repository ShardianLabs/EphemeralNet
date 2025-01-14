#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace ephemeralnet {

struct Config {
    std::chrono::seconds default_chunk_ttl{std::chrono::hours(24)};
    std::chrono::seconds announce_interval{std::chrono::minutes(15)};
    std::chrono::seconds cleanup_interval{std::chrono::minutes(5)};
    std::chrono::seconds handshake_cooldown{std::chrono::seconds(5)};
    std::optional<std::uint32_t> identity_seed{};
};

}  
