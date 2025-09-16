#pragma once

#include "ephemeralnet/Types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ephemeralnet {

struct Config {
    std::chrono::seconds default_chunk_ttl{std::chrono::hours(6)};
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
    std::chrono::seconds fetch_retry_initial_backoff{std::chrono::seconds(3)};
    std::chrono::seconds fetch_retry_max_backoff{std::chrono::seconds(60)};
    std::chrono::seconds fetch_retry_success_interval{std::chrono::seconds(15)};
    std::uint8_t fetch_retry_attempt_limit{5};
    std::uint16_t fetch_max_parallel_requests{3};
    std::chrono::seconds fetch_availability_refresh{std::chrono::seconds(10)};
    std::uint16_t upload_max_parallel_transfers{3};
    std::uint16_t upload_max_transfers_per_peer{1};
    std::chrono::seconds upload_reconsider_interval{std::chrono::seconds(2)};
    std::chrono::seconds upload_transfer_timeout{std::chrono::seconds(30)};
    bool storage_persistent_enabled{false};
    bool storage_wipe_on_expiry{true};
    std::uint8_t storage_wipe_passes{1};
    std::string storage_directory{"storage"};
    std::string control_host{"127.0.0.1"};
    std::uint16_t control_port{47777};
    std::optional<std::string> control_token{};
    std::size_t control_stream_max_bytes{32ull * 1024ull * 1024ull};
    std::optional<std::uint32_t> identity_seed{};
    std::optional<std::string> advertise_control_host{};
    std::optional<std::uint16_t> advertise_control_port{};
    std::uint8_t shard_threshold{3};
    std::uint8_t shard_total{5};
    std::chrono::seconds bootstrap_contact_ttl{std::chrono::minutes(15)};
    std::uint8_t protocol_message_version{0};
    std::uint8_t protocol_min_supported_version{1};
    std::chrono::seconds min_manifest_ttl{std::chrono::seconds(30)};
    std::chrono::seconds max_manifest_ttl{std::chrono::hours(6)};
    std::chrono::seconds key_rotation_interval{std::chrono::minutes(5)};
    std::chrono::seconds announce_min_interval{std::chrono::seconds(15)};
    std::size_t announce_burst_limit{4};
    std::chrono::seconds announce_burst_window{std::chrono::seconds(120)};
    std::uint8_t announce_pow_difficulty{6};
    std::uint8_t handshake_pow_difficulty{4};
    std::uint8_t store_pow_difficulty{6};

    struct BootstrapNode {
        PeerId id{};
        std::string host;
        std::uint16_t port{0};
        std::optional<std::uint32_t> public_identity{};
    };

    std::vector<BootstrapNode> bootstrap_nodes;
};

}  
