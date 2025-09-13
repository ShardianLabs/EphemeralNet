#include "ephemeralnet/bootstrap/TokenChallenge.hpp"

#include "ephemeralnet/crypto/Sha256.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ephemeralnet::bootstrap {

namespace {

void write_nonce(std::vector<std::uint8_t>& buffer,
                 std::size_t offset,
                 std::uint64_t nonce) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer[offset++] = static_cast<std::uint8_t>((nonce >> shift) & 0xFFu);
    }
}

}  // namespace

bool digest_meets_difficulty(std::span<const std::uint8_t> digest,
                             std::uint8_t difficulty_bits) {
    if (difficulty_bits == 0) {
        return true;
    }

    const std::size_t full_bytes = difficulty_bits / 8;
    const std::uint8_t remaining_bits = static_cast<std::uint8_t>(difficulty_bits % 8);

    if (full_bytes > digest.size()) {
        return false;
    }

    for (std::size_t i = 0; i < full_bytes; ++i) {
        if (digest[i] != 0) {
            return false;
        }
    }

    if (remaining_bits == 0) {
        return true;
    }

    if (full_bytes >= digest.size()) {
        return false;
    }

    const auto mask = static_cast<std::uint8_t>(0xFFu << (8 - remaining_bits));
    return (digest[full_bytes] & mask) == 0;
}

std::optional<std::uint64_t> solve_token_challenge(const protocol::Manifest& manifest,
                                                   const protocol::DiscoveryHint& hint,
                                                   std::uint8_t difficulty_bits,
                                                   std::uint64_t max_attempts) {
    if (difficulty_bits == 0) {
        return std::uint64_t{0};
    }
    if (hint.endpoint.empty() || max_attempts == 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> material;
    material.reserve(manifest.chunk_id.size() + manifest.chunk_hash.size() + hint.endpoint.size() + sizeof(std::uint64_t));
    material.insert(material.end(), manifest.chunk_id.begin(), manifest.chunk_id.end());
    material.insert(material.end(), manifest.chunk_hash.begin(), manifest.chunk_hash.end());
    material.insert(material.end(), hint.endpoint.begin(), hint.endpoint.end());

    const auto nonce_offset = material.size();
    material.resize(material.size() + sizeof(std::uint64_t));

    for (std::uint64_t attempt = 0; attempt < max_attempts; ++attempt) {
        write_nonce(material, nonce_offset, attempt);
        const auto digest = crypto::Sha256::digest(std::span<const std::uint8_t>(material.data(), material.size()));
        if (digest_meets_difficulty(digest, difficulty_bits)) {
            return attempt;
        }
    }

    return std::nullopt;
}

}  // namespace ephemeralnet::bootstrap
