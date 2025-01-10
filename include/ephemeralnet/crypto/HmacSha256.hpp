#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace ephemeralnet::crypto {

class HmacSha256 {
public:
    static constexpr std::size_t kBlockSize = 64;
    static constexpr std::size_t kDigestSize = 32;

    static std::array<std::uint8_t, kDigestSize> compute(std::span<const std::uint8_t> key,
                                                         std::span<const std::uint8_t> data);

    static bool verify(std::span<const std::uint8_t> key,
                       std::span<const std::uint8_t> data,
                       std::span<const std::uint8_t> mac);
};

}  // namespace ephemeralnet::crypto
