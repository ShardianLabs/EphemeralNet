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

enum class MessageType : std::uint8_t {
    Announce = 0x01,
    Request = 0x02,
    Chunk = 0x03,
    Acknowledge = 0x04,
};

struct AnnouncePayload {
    ChunkId chunk_id{};
    PeerId peer_id{};
    std::string endpoint;
    std::chrono::seconds ttl{0};
    std::string manifest_uri;
    std::vector<std::uint8_t> assigned_shards;
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

using Payload = std::variant<AnnouncePayload, RequestPayload, ChunkPayload, AcknowledgePayload>;

struct Message {
    std::uint8_t version{1};
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
