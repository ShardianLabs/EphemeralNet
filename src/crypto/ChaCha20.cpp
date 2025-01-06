#include "ephemeralnet/crypto/ChaCha20.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>

namespace ephemeralnet::crypto {

namespace {
constexpr std::array<std::uint32_t, 4> kSigma{
    0x61707865u,
    0x3320646eu,
    0x79622d32u,
    0x6b206574u,
};

constexpr std::size_t kBlockSize = 64;

[[nodiscard]] constexpr std::uint32_t rotl32(std::uint32_t value, int shift) noexcept {
    return static_cast<std::uint32_t>((value << shift) | (value >> (32 - shift)));
}

[[nodiscard]] std::uint32_t load32_le(const std::uint8_t* data) noexcept {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

void store32_le(std::uint8_t* dst, std::uint32_t value) noexcept {
    dst[0] = static_cast<std::uint8_t>(value & 0xFFu);
    dst[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    dst[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    dst[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

void quarter_round(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) noexcept {
    a += b;
    d ^= a;
    d = rotl32(d, 16);

    c += d;
    b ^= c;
    b = rotl32(b, 12);

    a += b;
    d ^= a;
    d = rotl32(d, 8);

    c += d;
    b ^= c;
    b = rotl32(b, 7);
}

void chacha20_block(const Key& key, const Nonce& nonce, std::uint32_t counter, std::array<std::uint8_t, kBlockSize>& buffer) noexcept {
    std::array<std::uint32_t, 16> state{};

    state[0] = kSigma[0];
    state[1] = kSigma[1];
    state[2] = kSigma[2];
    state[3] = kSigma[3];

    for (std::size_t i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(&key.bytes[i * 4]);
    }

    state[12] = counter;
    state[13] = load32_le(&nonce.bytes[0]);
    state[14] = load32_le(&nonce.bytes[4]);
    state[15] = load32_le(&nonce.bytes[8]);

    auto working_state = state;

    for (int i = 0; i < 10; ++i) {
        quarter_round(working_state[0], working_state[4], working_state[8], working_state[12]);
        quarter_round(working_state[1], working_state[5], working_state[9], working_state[13]);
        quarter_round(working_state[2], working_state[6], working_state[10], working_state[14]);
        quarter_round(working_state[3], working_state[7], working_state[11], working_state[15]);

        quarter_round(working_state[0], working_state[5], working_state[10], working_state[15]);
        quarter_round(working_state[1], working_state[6], working_state[11], working_state[12]);
        quarter_round(working_state[2], working_state[7], working_state[8], working_state[13]);
        quarter_round(working_state[3], working_state[4], working_state[9], working_state[14]);
    }

    for (std::size_t i = 0; i < state.size(); ++i) {
        working_state[i] += state[i];
    }

    for (std::size_t i = 0; i < working_state.size(); ++i) {
        store32_le(&buffer[i * 4], working_state[i]);
    }
}

}  // namespace

void ChaCha20::apply(const Key& key,
                     const Nonce& nonce,
                     std::span<const std::uint8_t> input,
                     std::vector<std::uint8_t>& output,
                     std::uint32_t counter) {
    output.resize(input.size());

    std::array<std::uint8_t, kBlockSize> keystream{};
    std::size_t processed = 0;

    while (processed < input.size()) {
        chacha20_block(key, nonce, counter, keystream);
        ++counter;

        const auto block_size = std::min(kBlockSize, input.size() - processed);
        for (std::size_t i = 0; i < block_size; ++i) {
            output[processed + i] = static_cast<std::uint8_t>(input[processed + i] ^ keystream[i]);
        }

        processed += block_size;
    }

    std::fill(keystream.begin(), keystream.end(), std::uint8_t{0});
}

}  // namespace ephemeralnet::crypto
