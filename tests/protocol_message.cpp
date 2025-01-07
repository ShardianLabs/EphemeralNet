#include "ephemeralnet/protocol/Message.hpp"

#include <cassert>
#include <chrono>

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
    };
    round_trip(announce);

    Message request{};
    request.type = MessageType::Request;
    request.payload = RequestPayload{
        .chunk_id = make_chunk_id(0x30),
        .requester = make_peer_id(0x40),
    };
    round_trip(request);

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

    return 0;
}
