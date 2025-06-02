#pragma once

#include "ephemeralnet/Types.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ephemeralnet::security {

struct StoreWorkInput {
    ChunkId chunk_id{};
    std::uint64_t payload_size{0};
    std::string_view filename_hint{};
};

constexpr std::uint8_t kMaxStorePowDifficulty = 24;
constexpr std::uint64_t kDefaultStorePowMaxAttempts = 500'000;

ChunkId derive_chunk_id(std::span<const std::uint8_t> data);

std::optional<std::string> sanitize_filename_hint(std::string_view raw_path);

bool store_pow_valid(const StoreWorkInput& input,
                     std::uint64_t nonce,
                     std::uint8_t difficulty_bits);

std::optional<std::uint64_t> compute_store_pow(const StoreWorkInput& input,
                                               std::uint8_t difficulty_bits,
                                               std::uint64_t max_attempts = kDefaultStorePowMaxAttempts);

}  // namespace ephemeralnet::security
