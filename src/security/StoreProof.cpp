#include "ephemeralnet/security/StoreProof.hpp"

#include "ephemeralnet/crypto/Sha256.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <limits>
#include <random>

namespace ephemeralnet::security {

namespace {

std::array<std::uint8_t, 8> to_big_endian(std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const std::size_t shift = (bytes.size() - 1 - i) * 8;
        bytes[i] = static_cast<std::uint8_t>((value >> shift) & 0xFF);
    }
    return bytes;
}

void update_length_prefixed(ephemeralnet::crypto::Sha256& hasher, std::span<const std::uint8_t> data) {
    const auto length = static_cast<std::uint32_t>(std::min<std::size_t>(data.size(), std::numeric_limits<std::uint32_t>::max()));
    std::array<std::uint8_t, 4> prefix{};
    prefix[0] = static_cast<std::uint8_t>((length >> 24) & 0xFF);
    prefix[1] = static_cast<std::uint8_t>((length >> 16) & 0xFF);
    prefix[2] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
    prefix[3] = static_cast<std::uint8_t>(length & 0xFF);
    hasher.update(prefix);
    if (!data.empty()) {
        hasher.update(data);
    }
}

std::array<std::uint8_t, 32> pow_digest(const StoreWorkInput& input, std::uint64_t nonce) {
    ephemeralnet::crypto::Sha256 hasher;
    hasher.update(input.chunk_id);
    hasher.update(to_big_endian(input.payload_size));
    if (!input.filename_hint.empty()) {
        update_length_prefixed(hasher,
                               std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(input.filename_hint.data()),
                                                              input.filename_hint.size()));
    } else {
        update_length_prefixed(hasher, {});
    }
    hasher.update(to_big_endian(nonce));
    return hasher.finalize();
}

std::size_t count_leading_zero_bits(std::span<const std::uint8_t> digest) {
    std::size_t total = 0;
    for (const auto byte : digest) {
        if (byte == 0) {
            total += 8;
            continue;
        }
        std::size_t leading = 0;
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte >> bit) & 0x1) {
                break;
            }
            ++leading;
        }
        total += leading;
        break;
    }
    return total;
}

}  // namespace

ChunkId derive_chunk_id(std::span<const std::uint8_t> data) {
    const auto digest = crypto::Sha256::digest(data);
    ChunkId id{};
    std::copy(digest.begin(), digest.end(), id.begin());
    return id;
}

std::optional<std::string> sanitize_filename_hint(std::string_view raw_path) {
    if (raw_path.empty()) {
        return std::nullopt;
    }
    std::filesystem::path provided(raw_path);
    const auto base = provided.filename().string();
    if (base.empty() || base == "." || base == "..") {
        return std::nullopt;
    }
    constexpr std::size_t kMaxFilenameLength = 255;
    if (base.size() <= kMaxFilenameLength) {
        return base;
    }
    return base.substr(0, kMaxFilenameLength);
}

bool store_pow_valid(const StoreWorkInput& input,
                     std::uint64_t nonce,
                     std::uint8_t difficulty_bits) {
    if (difficulty_bits == 0) {
        return true;
    }
    if (difficulty_bits > kMaxStorePowDifficulty) {
        difficulty_bits = kMaxStorePowDifficulty;
    }
    const auto digest = pow_digest(input, nonce);
    return count_leading_zero_bits(digest) >= difficulty_bits;
}

std::optional<std::uint64_t> compute_store_pow(const StoreWorkInput& input,
                                               std::uint8_t difficulty_bits,
                                               std::uint64_t max_attempts) {
    if (difficulty_bits == 0) {
        return std::uint64_t{0};
    }
    if (difficulty_bits > kMaxStorePowDifficulty) {
        difficulty_bits = kMaxStorePowDifficulty;
    }
    if (max_attempts == 0) {
        max_attempts = kDefaultStorePowMaxAttempts;
    }

    const auto seed_digest = pow_digest(input, 0);
    std::uint64_t seed = 0;
    std::memcpy(&seed, seed_digest.data(), sizeof(seed));
    std::mt19937_64 rng(seed);

    for (std::uint64_t attempt = 0; attempt < max_attempts; ++attempt) {
        const auto candidate = rng();
        if (store_pow_valid(input, candidate, difficulty_bits)) {
            return candidate;
        }
    }
    return std::nullopt;
}

}  // namespace ephemeralnet::security
