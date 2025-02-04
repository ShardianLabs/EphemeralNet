#include "ephemeralnet/protocol/Manifest.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace ephemeralnet::protocol {

namespace {

constexpr std::uint8_t kManifestVersion = 1;
constexpr char kScheme[] = "eph://";

constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<std::uint8_t>& input) {
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 2 < input.size()) {
        const auto triple = (static_cast<std::uint32_t>(input[i]) << 16) |
                            (static_cast<std::uint32_t>(input[i + 1]) << 8) |
                            static_cast<std::uint32_t>(input[i + 2]);
        output.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
        output.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
        output.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
        output.push_back(kBase64Alphabet[triple & 0x3F]);
        i += 3;
    }

    if (i < input.size()) {
        std::uint32_t triple = static_cast<std::uint32_t>(input[i]) << 16;
        if (i + 1 < input.size()) {
            triple |= static_cast<std::uint32_t>(input[i + 1]) << 8;
        }

        output.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
        output.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);

        if (i + 1 < input.size()) {
            output.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
        } else {
            output.push_back('=');
        }

        output.push_back('=');
    }

    return output;
}

std::vector<std::uint8_t> base64_decode(const std::string& input) {
    if (input.size() % 4 != 0) {
        throw std::invalid_argument("invalid base64 input length");
    }

    std::array<int, 256> decode{};
    decode.fill(-1);
    for (int i = 0; i < 64; ++i) {
        decode[static_cast<unsigned char>(kBase64Alphabet[i])] = i;
    }
    decode['='] = 0;

    std::vector<std::uint8_t> output;
    output.reserve((input.size() / 4) * 3);

    for (std::size_t i = 0; i < input.size(); i += 4) {
        const auto a = decode[static_cast<unsigned char>(input[i])];
        const auto b = decode[static_cast<unsigned char>(input[i + 1])];
        const auto c = decode[static_cast<unsigned char>(input[i + 2])];
        const auto d = decode[static_cast<unsigned char>(input[i + 3])];

        if (a < 0 || b < 0 || c < 0 || d < 0) {
            throw std::invalid_argument("invalid base64 character");
        }

        const auto triple = (a << 18) | (b << 12) | (c << 6) | d;

        output.push_back(static_cast<std::uint8_t>((triple >> 16) & 0xFF));
        if (input[i + 2] != '=') {
            output.push_back(static_cast<std::uint8_t>((triple >> 8) & 0xFF));
        }
        if (input[i + 3] != '=') {
            output.push_back(static_cast<std::uint8_t>(triple & 0xFF));
        }
    }

    return output;
}

void append_u64(std::vector<std::uint8_t>& buffer, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    std::uint64_t value = 0;
    for (int shift = 56; shift >= 0; shift -= 8) {
        value |= static_cast<std::uint64_t>(buffer[offset++]) << shift;
    }
    return value;
}

}  // namespace

std::string encode_manifest(const Manifest& manifest) {
    std::vector<std::uint8_t> buffer;
    buffer.reserve(1 + ChunkId{}.size() + 32 + sizeof(manifest.nonce.bytes) + 8 + 3 + manifest.shards.size() * 33);

    buffer.push_back(kManifestVersion);
    buffer.insert(buffer.end(), manifest.chunk_id.begin(), manifest.chunk_id.end());
    buffer.insert(buffer.end(), manifest.chunk_hash.begin(), manifest.chunk_hash.end());
    buffer.insert(buffer.end(), manifest.nonce.bytes.begin(), manifest.nonce.bytes.end());

    const auto expires = std::chrono::duration_cast<std::chrono::seconds>(manifest.expires_at.time_since_epoch()).count();
    append_u64(buffer, static_cast<std::uint64_t>(expires));

    buffer.push_back(manifest.threshold);
    buffer.push_back(manifest.total_shares);
    buffer.push_back(static_cast<std::uint8_t>(manifest.shards.size()));

    for (const auto& shard : manifest.shards) {
        buffer.push_back(shard.index);
        buffer.insert(buffer.end(), shard.value.begin(), shard.value.end());
    }

    return std::string{kScheme} + base64_encode(buffer);
}

Manifest decode_manifest(const std::string& uri) {
    if (uri.rfind(kScheme, 0) != 0) {
        throw std::invalid_argument("manifest URI must start with eph://");
    }
    const auto encoded = uri.substr(std::strlen(kScheme));
    const auto payload = base64_decode(encoded);

    std::size_t offset = 0;
    if (payload.size() < 1 + ChunkId{}.size() + 32 + sizeof(crypto::Nonce::bytes) + 8 + 3) {
        throw std::invalid_argument("manifest payload too small");
    }

    const auto version = payload[offset++];
    if (version != kManifestVersion) {
        throw std::invalid_argument("unsupported manifest version");
    }

    Manifest manifest{};
    std::copy_n(payload.begin() + offset, ChunkId{}.size(), manifest.chunk_id.begin());
    offset += ChunkId{}.size();

    std::copy_n(payload.begin() + offset, manifest.chunk_hash.size(), manifest.chunk_hash.begin());
    offset += manifest.chunk_hash.size();

    std::copy_n(payload.begin() + offset, manifest.nonce.bytes.size(), manifest.nonce.bytes.begin());
    offset += manifest.nonce.bytes.size();

    const auto expires = read_u64(payload, offset);
    offset += 8;
    manifest.expires_at = std::chrono::system_clock::time_point{std::chrono::seconds{expires}};

    manifest.threshold = payload[offset++];
    manifest.total_shares = payload[offset++];
    const auto shard_count = payload[offset++];

    if (offset + shard_count * 33 > payload.size()) {
        throw std::invalid_argument("manifest shard data truncated");
    }

    manifest.shards.reserve(shard_count);
    for (std::size_t i = 0; i < shard_count; ++i) {
        KeyShard shard{};
        shard.index = payload[offset++];
        std::copy_n(payload.begin() + offset, shard.value.size(), shard.value.begin());
        offset += shard.value.size();
        manifest.shards.push_back(shard);
    }

    return manifest;
}

std::string chunk_id_to_uri_component(const ChunkId& id) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase;
    for (const auto byte : id) {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

}  // namespace ephemeralnet::protocol
