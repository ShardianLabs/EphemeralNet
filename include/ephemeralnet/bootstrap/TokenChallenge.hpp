#pragma once

#include "ephemeralnet/protocol/Manifest.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace ephemeralnet::bootstrap {

bool digest_meets_difficulty(std::span<const std::uint8_t> digest,
                             std::uint8_t difficulty_bits);

std::optional<std::uint64_t> solve_token_challenge(const protocol::Manifest& manifest,
                                                   const protocol::DiscoveryHint& hint,
                                                   std::uint8_t difficulty_bits,
                                                   std::uint64_t max_attempts = 500'000);

}  // namespace ephemeralnet::bootstrap
