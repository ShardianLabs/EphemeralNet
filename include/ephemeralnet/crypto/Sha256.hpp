#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace ephemeralnet::crypto {

class Sha256 {
public:
    Sha256();

    void update(std::span<const std::uint8_t> data);
    std::array<std::uint8_t, 32> finalize();

    static std::array<std::uint8_t, 32> digest(std::span<const std::uint8_t> data);

private:
    void transform(const std::uint8_t block[64]);

    std::array<std::uint32_t, 8> state_{};
    std::vector<std::uint8_t> buffer_;
    std::uint64_t bit_len_{0};
};

}  // namespace ephemeralnet::crypto
