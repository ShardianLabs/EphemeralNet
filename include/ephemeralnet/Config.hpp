#pragma once

#include "ephemeralnet/Types.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ephemeralnet {

struct Config {
    std::chrono::seconds default_chunk_ttl{std::chrono::hours(24)};
    std::chrono::seconds announce_interval{std::chrono::minutes(15)};
    std::chrono::seconds cleanup_interval{std::chrono::minutes(5)};
    std::chrono::seconds handshake_cooldown{std::chrono::seconds(5)};
    std::optional<std::uint32_t> identity_seed{};
    std::uint8_t shard_threshold{3};
    std::uint8_t shard_total{5};
    std::chrono::seconds bootstrap_contact_ttl{std::chrono::minutes(15)};

    struct BootstrapNode {
        PeerId id{};
        std::string host;
        std::uint16_t port{0};
        std::optional<std::uint32_t> public_identity{};
    };

    std::vector<BootstrapNode> bootstrap_nodes;
};

}  
