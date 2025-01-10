#include "ephemeralnet/crypto/HmacSha256.hpp"

#include "ephemeralnet/crypto/Sha256.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace ephemeralnet::crypto {

std::array<std::uint8_t, HmacSha256::kDigestSize> HmacSha256::compute(std::span<const std::uint8_t> key,
                                                                      std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, kBlockSize> key_block{};

    if (key.size() > kBlockSize) {
        const auto hashed = Sha256::digest(key);
        std::copy(hashed.begin(), hashed.end(), key_block.begin());
    } else {
        std::copy(key.begin(), key.end(), key_block.begin());
    }

    std::array<std::uint8_t, kBlockSize> o_key_pad{};
    std::array<std::uint8_t, kBlockSize> i_key_pad{};

    for (std::size_t i = 0; i < kBlockSize; ++i) {
        o_key_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5c);
        i_key_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36);
    }

    Sha256 inner;
    inner.update(i_key_pad);
    inner.update(data);
    const auto inner_hash = inner.finalize();

    Sha256 outer;
    outer.update(o_key_pad);
    outer.update(inner_hash);
    return outer.finalize();
}

bool HmacSha256::verify(std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> data,
                        std::span<const std::uint8_t> mac) {
    if (mac.size() != kDigestSize) {
        return false;
    }

    const auto expected = compute(key, data);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        diff |= static_cast<std::uint8_t>(expected[i] ^ mac[i]);
    }
    return diff == 0;
}

}  // namespace ephemeralnet::crypto
