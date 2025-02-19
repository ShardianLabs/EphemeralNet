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
    std::chrono::seconds nat_retry_interval{std::chrono::seconds(30)};
    std::uint16_t nat_upnp_start_port{45000};
    std::uint16_t nat_upnp_end_port{45099};
    std::uint16_t swarm_target_replicas{3};
    std::uint16_t swarm_min_providers{2};
    std::uint16_t swarm_candidate_sample{8};
    std::chrono::seconds swarm_rebalance_interval{std::chrono::minutes(30)};
    bool storage_persistent_enabled{false};
    bool storage_wipe_on_expiry{true};
    std::uint8_t storage_wipe_passes{1};
    std::string storage_directory{"storage"};
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
