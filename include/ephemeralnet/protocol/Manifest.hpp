#pragma once

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/ChaCha20.hpp"
#include "ephemeralnet/crypto/Shamir.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>

namespace ephemeralnet::protocol {

struct KeyShard {
    std::uint8_t index{0};
    std::array<std::uint8_t, 32> value{};
};

struct Manifest {
    ChunkId chunk_id{};
    std::array<std::uint8_t, 32> chunk_hash{};
    crypto::Nonce nonce{};
    std::uint8_t threshold{0};
    std::uint8_t total_shares{0};
    std::chrono::system_clock::time_point expires_at{};
    std::vector<KeyShard> shards;
    std::map<std::string, std::string> metadata;
};

std::string encode_manifest(const Manifest& manifest);
Manifest decode_manifest(const std::string& uri);

std::string chunk_id_to_uri_component(const ChunkId& id);

}  // namespace ephemeralnet::protocol
