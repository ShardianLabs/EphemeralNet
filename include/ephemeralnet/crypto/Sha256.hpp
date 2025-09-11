#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

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
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_size_{0};
    std::uint64_t bit_len_{0};
};

}  // namespace ephemeralnet::crypto
