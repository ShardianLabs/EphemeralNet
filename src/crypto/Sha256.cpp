#include "ephemeralnet/crypto/Sha256.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace ephemeralnet::crypto {

namespace {
constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t value, int shift) noexcept {
    return (value >> shift) | (value << (32 - shift));
}

constexpr std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ ((~x) & z);
}

constexpr std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

std::uint32_t read_be32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

void write_be32(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    out[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

}  // namespace

Sha256::Sha256()
    : state_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u},
      buffer_{},
      buffer_size_(0),
      bit_len_(0) {}

void Sha256::update(std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return;
    }

    bit_len_ += static_cast<std::uint64_t>(data.size()) * 8;

    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto space = static_cast<std::size_t>(64 - buffer_size_);
        const auto chunk = std::min<std::size_t>(space, data.size() - offset);
        std::memcpy(buffer_.data() + buffer_size_, data.data() + offset, chunk);
        buffer_size_ += chunk;
        offset += chunk;

        if (buffer_size_ == 64) {
            transform(buffer_.data());
            buffer_size_ = 0;
        }
    }
}

std::array<std::uint8_t, 32> Sha256::finalize() {
    // Append the 0x80 terminator.
    buffer_[buffer_size_++] = 0x80;

    if (buffer_size_ > 56) {
        // Fill the current block with zeros and process it.
        std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.end(), 0);
        transform(buffer_.data());
        buffer_size_ = 0;
    }

    // Pad with zeros until we have 56 bytes (leaving room for the length field).
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.begin() + 56, 0);
    buffer_size_ = 56;

    // Append the message length in bits as big-endian.
    for (int i = 7; i >= 0; --i) {
        buffer_[buffer_size_++] = static_cast<std::uint8_t>((bit_len_ >> (i * 8)) & 0xFFu);
    }

    transform(buffer_.data());
    buffer_size_ = 0;

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < state_.size(); ++i) {
        write_be32(digest.data() + static_cast<std::ptrdiff_t>(i * 4), state_[i]);
    }

    buffer_.fill(0);
    buffer_size_ = 0;
    bit_len_ = 0;
    return digest;
}

std::array<std::uint8_t, 32> Sha256::digest(std::span<const std::uint8_t> data) {
    Sha256 hasher;
    hasher.update(data);
    return hasher.finalize();
}

void Sha256::transform(const std::uint8_t block[64]) {
    std::array<std::uint32_t, 64> schedule;

    for (std::size_t i = 0; i < 16; ++i) {
        schedule[i] = read_be32(block + static_cast<std::ptrdiff_t>(i * 4));
    }

    for (std::size_t i = 16; i < schedule.size(); ++i) {
        schedule[i] = small_sigma1(schedule[i - 2]) + schedule[i - 7] + small_sigma0(schedule[i - 15]) + schedule[i - 16];
    }

    auto a = state_[0];
    auto b = state_[1];
    auto c = state_[2];
    auto d = state_[3];
    auto e = state_[4];
    auto f = state_[5];
    auto g = state_[6];
    auto h = state_[7];

    for (std::size_t i = 0; i < schedule.size(); ++i) {
        const auto temp1 = h + big_sigma1(e) + ch(e, f, g) + kRoundConstants[i] + schedule[i];
        const auto temp2 = big_sigma0(a) + maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

}  // namespace ephemeralnet::crypto
