#include "ephemeralnet/protocol/Manifest.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <limits>
#include <stdexcept>

namespace ephemeralnet::protocol {

namespace {

constexpr std::uint8_t kManifestVersion = 3;
constexpr char kScheme[] = "eph://";
constexpr std::size_t kAttestationDigestSize = 32;

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

void append_u16(std::vector<std::uint8_t>& buffer, std::uint16_t value) {
    buffer.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    buffer.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    std::uint64_t value = 0;
    for (int shift = 56; shift >= 0; shift -= 8) {
        value |= static_cast<std::uint64_t>(buffer[offset++]) << shift;
    }
    return value;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    if (offset + 1 >= buffer.size()) {
        throw std::invalid_argument("manifest metadata truncated");
    }
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(buffer[offset]) << 8) |
                                      static_cast<std::uint16_t>(buffer[offset + 1]));
}

}  // namespace

std::string encode_manifest(const Manifest& manifest) {
    if (manifest.metadata.size() > std::numeric_limits<std::uint8_t>::max()) {
        throw std::length_error("manifest metadata entry count exceeds limit");
    }

    std::size_t metadata_bytes = 1;  // entry count byte
    for (const auto& entry : manifest.metadata) {
        const auto& key = entry.first;
        const auto& value = entry.second;
        if (key.size() > std::numeric_limits<std::uint8_t>::max()) {
            throw std::length_error("manifest metadata key too long");
        }
        if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::length_error("manifest metadata value too long");
        }
        metadata_bytes += 1 + key.size() + 2 + value.size();
    }

    if (manifest.discovery_hints.size() > std::numeric_limits<std::uint8_t>::max()) {
        throw std::length_error("manifest discovery hint count exceeds limit");
    }

    std::size_t discovery_bytes = 1;  // count byte
    for (const auto& hint : manifest.discovery_hints) {
        if (hint.transport.size() > std::numeric_limits<std::uint8_t>::max()) {
            throw std::length_error("manifest discovery transport too long");
        }
        if (hint.endpoint.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::length_error("manifest discovery endpoint too long");
        }
        discovery_bytes += 1 + hint.transport.size();   // transport length + data
        discovery_bytes += 2 + hint.endpoint.size();     // endpoint length + data
        discovery_bytes += 1;                            // priority
    }

    if (manifest.fallback_hints.size() > std::numeric_limits<std::uint8_t>::max()) {
        throw std::length_error("manifest fallback hint count exceeds limit");
    }

    std::size_t fallback_bytes = 1;  // count byte
    for (const auto& hint : manifest.fallback_hints) {
        if (hint.uri.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::length_error("manifest fallback uri too long");
        }
        fallback_bytes += 2 + hint.uri.size();  // length + bytes
        fallback_bytes += 1;                    // priority
    }

    if (manifest.security.advisory.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::length_error("manifest security advisory too long");
    }

    const std::size_t security_bytes = 1 +                       // token bits
                                       2 + manifest.security.advisory.size() +
                                       1 +                       // digest flag
                                       (manifest.security.has_attestation_digest ? kAttestationDigestSize : 0);

    std::vector<std::uint8_t> buffer;
    buffer.reserve(1 + ChunkId{}.size() + 32 + sizeof(manifest.nonce.bytes) + 8 + 3 + manifest.shards.size() * 33 + metadata_bytes + discovery_bytes + security_bytes + fallback_bytes);

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

    buffer.push_back(static_cast<std::uint8_t>(manifest.metadata.size()));
    for (const auto& entry : manifest.metadata) {
        const auto& key = entry.first;
        const auto& value = entry.second;
        buffer.push_back(static_cast<std::uint8_t>(key.size()));
        buffer.insert(buffer.end(), key.begin(), key.end());
        append_u16(buffer, static_cast<std::uint16_t>(value.size()));
        buffer.insert(buffer.end(), value.begin(), value.end());
    }

    buffer.push_back(static_cast<std::uint8_t>(manifest.discovery_hints.size()));
    for (const auto& hint : manifest.discovery_hints) {
        buffer.push_back(static_cast<std::uint8_t>(hint.transport.size()));
        buffer.insert(buffer.end(), hint.transport.begin(), hint.transport.end());
        append_u16(buffer, static_cast<std::uint16_t>(hint.endpoint.size()));
        buffer.insert(buffer.end(), hint.endpoint.begin(), hint.endpoint.end());
        buffer.push_back(hint.priority);
    }

    buffer.push_back(manifest.security.token_challenge_bits);
    append_u16(buffer, static_cast<std::uint16_t>(manifest.security.advisory.size()));
    buffer.insert(buffer.end(), manifest.security.advisory.begin(), manifest.security.advisory.end());
    buffer.push_back(manifest.security.has_attestation_digest ? 1 : 0);
    if (manifest.security.has_attestation_digest) {
        buffer.insert(buffer.end(),
                      manifest.security.attestation_digest.begin(),
                      manifest.security.attestation_digest.end());
    }

    buffer.push_back(static_cast<std::uint8_t>(manifest.fallback_hints.size()));
    for (const auto& hint : manifest.fallback_hints) {
        append_u16(buffer, static_cast<std::uint16_t>(hint.uri.size()));
        buffer.insert(buffer.end(), hint.uri.begin(), hint.uri.end());
        buffer.push_back(hint.priority);
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
    if (version != 1 && version != kManifestVersion) {
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

    manifest.metadata.clear();

    if (version == 1) {
        return manifest;
    }

    if (offset >= payload.size()) {
        throw std::invalid_argument("manifest metadata missing");
    }

    const auto metadata_count = payload[offset++];
    for (std::size_t index = 0; index < metadata_count; ++index) {
        if (offset >= payload.size()) {
            throw std::invalid_argument("manifest metadata truncated");
        }
        const auto key_length = payload[offset++];
        if (offset + key_length > payload.size()) {
            throw std::invalid_argument("manifest metadata key truncated");
        }
        std::string key(payload.begin() + offset, payload.begin() + offset + key_length);
        offset += key_length;

        if (offset + 1 >= payload.size()) {
            throw std::invalid_argument("manifest metadata value truncated");
        }
        const auto value_length = read_u16(payload, offset);
        offset += 2;
        if (offset + value_length > payload.size()) {
            throw std::invalid_argument("manifest metadata value truncated");
        }
        std::string value(payload.begin() + offset, payload.begin() + offset + value_length);
        offset += value_length;
        manifest.metadata.emplace(std::move(key), std::move(value));
    }

    if (version == 2) {
        return manifest;
    }

    if (offset >= payload.size()) {
        throw std::invalid_argument("manifest discovery data missing");
    }

    const auto discovery_count = payload[offset++];
    manifest.discovery_hints.clear();
    manifest.discovery_hints.reserve(discovery_count);
    for (std::size_t i = 0; i < discovery_count; ++i) {
        if (offset >= payload.size()) {
            throw std::invalid_argument("manifest discovery transport truncated");
        }
        const auto transport_length = payload[offset++];
        if (offset + transport_length > payload.size()) {
            throw std::invalid_argument("manifest discovery transport truncated");
        }
        std::string transport(payload.begin() + offset, payload.begin() + offset + transport_length);
        offset += transport_length;

        if (offset + 1 >= payload.size()) {
            throw std::invalid_argument("manifest discovery endpoint truncated");
        }
        const auto endpoint_length = read_u16(payload, offset);
        offset += 2;
        if (offset + endpoint_length > payload.size()) {
            throw std::invalid_argument("manifest discovery endpoint truncated");
        }
        std::string endpoint(payload.begin() + offset, payload.begin() + offset + endpoint_length);
        offset += endpoint_length;

        if (offset >= payload.size()) {
            throw std::invalid_argument("manifest discovery priority missing");
        }
        DiscoveryHint hint{};
        hint.transport = std::move(transport);
        hint.endpoint = std::move(endpoint);
        hint.priority = payload[offset++];
        manifest.discovery_hints.push_back(std::move(hint));
    }

    if (offset >= payload.size()) {
        throw std::invalid_argument("manifest security section missing");
    }

    manifest.security.token_challenge_bits = payload[offset++];

    if (offset + 1 >= payload.size()) {
        throw std::invalid_argument("manifest security advisory truncated");
    }
    const auto advisory_length = read_u16(payload, offset);
    offset += 2;
    if (offset + advisory_length > payload.size()) {
        throw std::invalid_argument("manifest security advisory truncated");
    }
    manifest.security.advisory.assign(payload.begin() + offset, payload.begin() + offset + advisory_length);
    offset += advisory_length;

    if (offset >= payload.size()) {
        throw std::invalid_argument("manifest security digest flag missing");
    }
    manifest.security.has_attestation_digest = payload[offset++] != 0;
    if (manifest.security.has_attestation_digest) {
        if (offset + kAttestationDigestSize > payload.size()) {
            throw std::invalid_argument("manifest attestation digest truncated");
        }
        std::copy_n(payload.begin() + offset,
                    manifest.security.attestation_digest.size(),
                    manifest.security.attestation_digest.begin());
        offset += manifest.security.attestation_digest.size();
    } else {
        manifest.security.attestation_digest.fill(0);
    }

    if (offset >= payload.size()) {
        throw std::invalid_argument("manifest fallback section missing");
    }

    const auto fallback_count = payload[offset++];
    manifest.fallback_hints.clear();
    manifest.fallback_hints.reserve(fallback_count);
    for (std::size_t i = 0; i < fallback_count; ++i) {
        if (offset + 1 >= payload.size()) {
            throw std::invalid_argument("manifest fallback uri truncated");
        }
        const auto uri_length = read_u16(payload, offset);
        offset += 2;
        if (offset + uri_length > payload.size()) {
            throw std::invalid_argument("manifest fallback uri truncated");
        }
        std::string uri(payload.begin() + offset, payload.begin() + offset + uri_length);
        offset += uri_length;
        if (offset >= payload.size()) {
            throw std::invalid_argument("manifest fallback priority missing");
        }
        FallbackHint hint{};
        hint.uri = std::move(uri);
        hint.priority = payload[offset++];
        manifest.fallback_hints.push_back(std::move(hint));
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
