#pragma once

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <array>

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace ephemeralnet::protocol {

inline constexpr std::uint8_t kMinimumMessageVersion = 1;
inline constexpr std::uint8_t kCurrentMessageVersion = 4;

bool is_supported_message_version(std::uint8_t version) noexcept;

enum class MessageType : std::uint8_t {
    Announce = 0x01,
    Request = 0x02,
    Chunk = 0x03,
    Acknowledge = 0x04,
    TransportHandshake = 0x05,
    HandshakeAck = 0x06,
};

struct AnnouncePayload {
    ChunkId chunk_id{};
    PeerId peer_id{};
    std::string endpoint;
    std::chrono::seconds ttl{0};
    std::string manifest_uri;
    std::vector<std::uint8_t> assigned_shards;
    std::uint64_t work_nonce{0};
};

struct RequestPayload {
    ChunkId chunk_id{};
    PeerId requester{};
};

struct ChunkPayload {
    ChunkId chunk_id{};
    std::vector<std::uint8_t> data;
    std::chrono::seconds ttl{0};
};

struct AcknowledgePayload {
    ChunkId chunk_id{};
    PeerId peer_id{};
    bool accepted{false};
};

struct TransportHandshakePayload {
    std::uint32_t public_identity{0};
    std::uint64_t work_nonce{0};
    std::uint8_t requested_version{kCurrentMessageVersion};
};

struct HandshakeAckPayload {
    bool accepted{false};
    std::uint8_t negotiated_version{kMinimumMessageVersion};
    std::uint32_t responder_public{0};
};

using Payload = std::variant<AnnouncePayload,
                             RequestPayload,
                             ChunkPayload,
                             AcknowledgePayload,
                             TransportHandshakePayload,
                             HandshakeAckPayload>;

struct Message {
    std::uint8_t version{kCurrentMessageVersion};
    MessageType type{MessageType::Announce};
    Payload payload{};
};

std::vector<std::uint8_t> encode(const Message& message);
std::optional<Message> decode(std::span<const std::uint8_t> buffer);

std::vector<std::uint8_t> encode_signed(const Message& message,
                                        std::span<const std::uint8_t> shared_key);
std::optional<Message> decode_signed(std::span<const std::uint8_t> buffer,
                                     std::span<const std::uint8_t> shared_key);

}  // namespace ephemeralnet::protocol
