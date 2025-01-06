#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace ephemeralnet::crypto {

struct Key {
    std::array<std::uint8_t, 32> bytes{};
};

struct Nonce {
    std::array<std::uint8_t, 12> bytes{};
};

class ChaCha20 {
public:
    static void apply(const Key& key,
                      const Nonce& nonce,
                      std::span<const std::uint8_t> input,
                      std::vector<std::uint8_t>& output,
                      std::uint32_t counter = 0);
};

}  // namespace ephemeralnet::crypto
