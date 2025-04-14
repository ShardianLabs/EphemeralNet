#include "ephemeralnet/protocol/Message.hpp"

#include <cassert>
#include <chrono>
#include <type_traits>

using namespace ephemeralnet;
using namespace ephemeralnet::protocol;

namespace {

ChunkId make_chunk_id(std::uint8_t seed) {
    ChunkId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

PeerId make_peer_id(std::uint8_t seed) {
    PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

void round_trip(const Message& message) {
    const auto encoded = encode(message);
    const auto decoded = decode(encoded);
    assert(decoded.has_value());
    assert(decoded->version == message.version);
    assert(decoded->type == message.type);
    assert(decoded->payload.index() == message.payload.index());

    std::visit(
        [&](const auto& expected_payload) {
            using PayloadType = std::decay_t<decltype(expected_payload)>;
            const auto* actual_payload = std::get_if<PayloadType>(&decoded->payload);
            assert(actual_payload != nullptr);

            if constexpr (std::is_same_v<PayloadType, AnnouncePayload>) {
                assert(actual_payload->chunk_id == expected_payload.chunk_id);
                assert(actual_payload->peer_id == expected_payload.peer_id);
                assert(actual_payload->endpoint == expected_payload.endpoint);
                assert(actual_payload->ttl == expected_payload.ttl);
                assert(actual_payload->manifest_uri == expected_payload.manifest_uri);
                assert(actual_payload->assigned_shards == expected_payload.assigned_shards);
            } else if constexpr (std::is_same_v<PayloadType, RequestPayload>) {
                assert(actual_payload->chunk_id == expected_payload.chunk_id);
                assert(actual_payload->requester == expected_payload.requester);
            } else if constexpr (std::is_same_v<PayloadType, ChunkPayload>) {
                assert(actual_payload->chunk_id == expected_payload.chunk_id);
                assert(actual_payload->data == expected_payload.data);
                assert(actual_payload->ttl == expected_payload.ttl);
            } else if constexpr (std::is_same_v<PayloadType, AcknowledgePayload>) {
                assert(actual_payload->chunk_id == expected_payload.chunk_id);
                assert(actual_payload->peer_id == expected_payload.peer_id);
                assert(actual_payload->accepted == expected_payload.accepted);
            }
        },
        message.payload);
}

}  // namespace

int main() {
    Message announce{};
    announce.type = MessageType::Announce;
    announce.payload = AnnouncePayload{
        .chunk_id = make_chunk_id(0x10),
        .peer_id = make_peer_id(0x20),
        .endpoint = "127.0.0.1:4000",
        .ttl = std::chrono::seconds{3600},
        .manifest_uri = "eph://chunk/abc123",
        .assigned_shards = std::vector<std::uint8_t>{1, 7, 9},
    };
    round_trip(announce);

    Message request{};
    request.type = MessageType::Request;
    request.payload = RequestPayload{
        .chunk_id = make_chunk_id(0x30),
        .requester = make_peer_id(0x40),
    };
    round_trip(request);

    Message legacy_request = request;
    legacy_request.version = kMinimumMessageVersion;
    round_trip(legacy_request);

    Message chunk{};
    chunk.type = MessageType::Chunk;
    chunk.payload = ChunkPayload{
        .chunk_id = make_chunk_id(0x50),
        .data = std::vector<std::uint8_t>{1, 2, 3, 4, 5},
        .ttl = std::chrono::seconds{120},
    };
    round_trip(chunk);

    Message ack{};
    ack.type = MessageType::Acknowledge;
    ack.payload = AcknowledgePayload{
        .chunk_id = make_chunk_id(0x60),
        .peer_id = make_peer_id(0x70),
        .accepted = true,
    };
    round_trip(ack);

    {
        auto encoded = encode(request);
        encoded[0] = static_cast<std::uint8_t>(kMinimumMessageVersion - 1);
        assert(!decode(encoded).has_value());
    }

    {
        auto encoded = encode(request);
        encoded[0] = static_cast<std::uint8_t>(kCurrentMessageVersion + 1);
        assert(!decode(encoded).has_value());
    }

    return 0;
}
