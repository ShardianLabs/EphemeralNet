#pragma once

#include "ephemeralnet/Types.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace ephemeralnet::crypto {

struct ShamirShare {
    std::uint8_t index{0};
    std::array<std::uint8_t, 32> value{};
};

class Shamir {
public:
    static std::vector<ShamirShare> split(const std::array<std::uint8_t, 32>& secret,
                                          std::uint8_t threshold,
                                          std::uint8_t share_count);

    static std::array<std::uint8_t, 32> combine(const std::vector<ShamirShare>& shares,
                                                std::uint8_t threshold);
};

}  // namespace ephemeralnet::crypto
