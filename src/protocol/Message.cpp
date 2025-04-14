#include "ephemeralnet/protocol/Message.hpp"

#include "ephemeralnet/crypto/HmacSha256.hpp"

#include <array>
#include <cstring>
#include <span>

namespace ephemeralnet::protocol {

namespace {

constexpr std::size_t kChunkIdSize = ChunkId{}.size();
constexpr std::size_t kPeerIdSize = PeerId{}.size();

std::uint8_t clamp_version(std::uint8_t version) {
    if (version < kMinimumMessageVersion) {
        return kMinimumMessageVersion;
    }
    if (version > kCurrentMessageVersion) {
        return kCurrentMessageVersion;
    }
    return version;
}

std::vector<std::uint8_t> serialize_chunk_id(const ChunkId& id) {
    return std::vector<std::uint8_t>(id.begin(), id.end());
}

std::vector<std::uint8_t> serialize_peer_id(const PeerId& id) {
    return std::vector<std::uint8_t>(id.begin(), id.end());
}

ChunkId parse_chunk_id(const std::uint8_t* data) {
    ChunkId id{};
    std::memcpy(id.data(), data, id.size());
    return id;
}

PeerId parse_peer_id(const std::uint8_t* data) {
    PeerId id{};
    std::memcpy(id.data(), data, id.size());
    return id;
}

void write_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

std::uint32_t read_u32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

std::optional<Payload> decode_payload_v1(MessageType type,
                                         const std::uint8_t* data,
                                         std::size_t remaining) {
    switch (type) {
        case MessageType::Announce: {
            const auto header_bytes = 4u * 4u;
            if (remaining < header_bytes + kChunkIdSize + kPeerIdSize) {
                return std::nullopt;
            }

            std::size_t cursor = 0;
            const auto ttl = read_u32(data + cursor);
            cursor += 4;
            const auto endpoint_len = read_u32(data + cursor);
            cursor += 4;
            const auto manifest_len = read_u32(data + cursor);
            cursor += 4;
            const auto assignments_len = read_u32(data + cursor);
            cursor += 4;

            const auto expected_size = cursor + kChunkIdSize + kPeerIdSize + endpoint_len + manifest_len + assignments_len;
            if (remaining < expected_size) {
                return std::nullopt;
            }

            AnnouncePayload payload{};
            payload.ttl = std::chrono::seconds(ttl);
            payload.chunk_id = parse_chunk_id(data + cursor);
            cursor += kChunkIdSize;
            payload.peer_id = parse_peer_id(data + cursor);
            cursor += kPeerIdSize;

            payload.endpoint.assign(reinterpret_cast<const char*>(data + cursor), endpoint_len);
            cursor += endpoint_len;

            payload.manifest_uri.assign(reinterpret_cast<const char*>(data + cursor), manifest_len);
            cursor += manifest_len;

            payload.assigned_shards.assign(data + cursor, data + cursor + assignments_len);
            return Payload{std::move(payload)};
        }
        case MessageType::Request: {
            const auto needed = kChunkIdSize + kPeerIdSize;
            if (remaining < needed) {
                return std::nullopt;
            }
            RequestPayload payload{};
            payload.chunk_id = parse_chunk_id(data);
            payload.requester = parse_peer_id(data + kChunkIdSize);
            return Payload{payload};
        }
        case MessageType::Chunk: {
            if (remaining < 8 + kChunkIdSize) {
                return std::nullopt;
            }
            const auto ttl = read_u32(data);
            const auto data_len = read_u32(data + 4);
            const auto expected = 8 + kChunkIdSize + data_len;
            if (remaining < expected) {
                return std::nullopt;
            }
            ChunkPayload payload{};
            payload.ttl = std::chrono::seconds(ttl);
            payload.chunk_id = parse_chunk_id(data + 8);
            payload.data.assign(data + 8 + kChunkIdSize, data + 8 + kChunkIdSize + data_len);
            return Payload{std::move(payload)};
        }
        case MessageType::Acknowledge: {
            const auto needed = 1 + kChunkIdSize + kPeerIdSize;
            if (remaining < needed) {
                return std::nullopt;
            }
            AcknowledgePayload payload{};
            payload.accepted = *(data) != 0;
            payload.chunk_id = parse_chunk_id(data + 1);
            payload.peer_id = parse_peer_id(data + 1 + kChunkIdSize);
            return Payload{payload};
        }
        default:
            return std::nullopt;
    }
}

}  // namespace

bool is_supported_message_version(std::uint8_t version) noexcept {
    return version >= kMinimumMessageVersion && version <= kCurrentMessageVersion;
}

std::vector<std::uint8_t> encode(const Message& message) {
    std::vector<std::uint8_t> out{};
    out.reserve(128);
    out.push_back(clamp_version(message.version));
    out.push_back(static_cast<std::uint8_t>(message.type));

    std::visit(
        [&](const auto& payload) {
            using PayloadType = std::decay_t<decltype(payload)>;

            if constexpr (std::is_same_v<PayloadType, AnnouncePayload>) {
                const auto chunk_bytes = serialize_chunk_id(payload.chunk_id);
                const auto peer_bytes = serialize_peer_id(payload.peer_id);
                const auto endpoint_len = static_cast<std::uint32_t>(payload.endpoint.size());
                const auto manifest_len = static_cast<std::uint32_t>(payload.manifest_uri.size());
                const auto assignments_len = static_cast<std::uint32_t>(payload.assigned_shards.size());

                write_u32(out, static_cast<std::uint32_t>(payload.ttl.count()));
                write_u32(out, endpoint_len);
                write_u32(out, manifest_len);
                write_u32(out, assignments_len);

                out.insert(out.end(), chunk_bytes.begin(), chunk_bytes.end());
                out.insert(out.end(), peer_bytes.begin(), peer_bytes.end());
                out.insert(out.end(), payload.endpoint.begin(), payload.endpoint.end());
                out.insert(out.end(), payload.manifest_uri.begin(), payload.manifest_uri.end());
                out.insert(out.end(), payload.assigned_shards.begin(), payload.assigned_shards.end());
            } else if constexpr (std::is_same_v<PayloadType, RequestPayload>) {
                const auto chunk_bytes = serialize_chunk_id(payload.chunk_id);
                const auto peer_bytes = serialize_peer_id(payload.requester);
                out.insert(out.end(), chunk_bytes.begin(), chunk_bytes.end());
                out.insert(out.end(), peer_bytes.begin(), peer_bytes.end());
            } else if constexpr (std::is_same_v<PayloadType, ChunkPayload>) {
                const auto chunk_bytes = serialize_chunk_id(payload.chunk_id);
                write_u32(out, static_cast<std::uint32_t>(payload.ttl.count()));
                write_u32(out, static_cast<std::uint32_t>(payload.data.size()));
                out.insert(out.end(), chunk_bytes.begin(), chunk_bytes.end());
                out.insert(out.end(), payload.data.begin(), payload.data.end());
            } else if constexpr (std::is_same_v<PayloadType, AcknowledgePayload>) {
                const auto chunk_bytes = serialize_chunk_id(payload.chunk_id);
                const auto peer_bytes = serialize_peer_id(payload.peer_id);
                out.push_back(static_cast<std::uint8_t>(payload.accepted ? 1 : 0));
                out.insert(out.end(), chunk_bytes.begin(), chunk_bytes.end());
                out.insert(out.end(), peer_bytes.begin(), peer_bytes.end());
            }
        },
        message.payload);

    return out;
}

std::optional<Message> decode(std::span<const std::uint8_t> buffer) {
    if (buffer.size() < 2) {
        return std::nullopt;
    }

    const auto version = buffer[0];
    const auto type = static_cast<MessageType>(buffer[1]);

    if (!is_supported_message_version(version)) {
        return std::nullopt;
    }

    const auto* data = buffer.data() + 2;
    const auto remaining = buffer.size() - 2;

    std::optional<Payload> payload{};
    switch (version) {
        case kMinimumMessageVersion:
            [[fallthrough]];
        case kCurrentMessageVersion:
            payload = decode_payload_v1(type, data, remaining);
            break;
        default:
            return std::nullopt;
    }

    if (!payload.has_value()) {
        return std::nullopt;
    }

    Message message{};
    message.version = version;
    message.type = type;
    message.payload = std::move(*payload);
    return message;
}

std::vector<std::uint8_t> encode_signed(const Message& message,
                                        std::span<const std::uint8_t> shared_key) {
    auto encoded = encode(message);
    const auto mac = crypto::HmacSha256::compute(shared_key, encoded);
    encoded.insert(encoded.end(), mac.begin(), mac.end());
    return encoded;
}

std::optional<Message> decode_signed(std::span<const std::uint8_t> buffer,
                                     std::span<const std::uint8_t> shared_key) {
    if (buffer.size() < crypto::HmacSha256::kDigestSize) {
        return std::nullopt;
    }

    const auto message_size = buffer.size() - crypto::HmacSha256::kDigestSize;
    const auto message_span = buffer.first(message_size);
    const auto mac_span = buffer.last(crypto::HmacSha256::kDigestSize);

    if (!crypto::HmacSha256::verify(shared_key, message_span, mac_span)) {
        return std::nullopt;
    }

    return decode(message_span);
}

}  // namespace ephemeralnet::protocol
