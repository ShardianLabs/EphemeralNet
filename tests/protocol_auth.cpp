#include "ephemeralnet/protocol/Message.hpp"

#include <array>
#include <cassert>

using namespace ephemeralnet;
using namespace ephemeralnet::protocol;

namespace {

ChunkId chunk_id_fill(std::uint8_t seed) {
    ChunkId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

PeerId peer_id_fill(std::uint8_t seed) {
    PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

}  // namespace

int main() {
    Message message{};
    message.type = MessageType::Request;
    message.payload = RequestPayload{
        .chunk_id = chunk_id_fill(0x0A),
        .requester = peer_id_fill(0x0B),
    };

    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }

    const auto signed_bytes = encode_signed(message, key);
    const auto decoded = decode_signed(signed_bytes, key);
    assert(decoded.has_value());
    assert(decoded->type == MessageType::Request);

    // Tamper the payload and ensure verification fails.
    auto tampered = signed_bytes;
    tampered[5] = static_cast<std::uint8_t>(tampered[5] ^ 0xFF);
    const auto rejected = decode_signed(tampered, key);
    assert(!rejected.has_value());

    return 0;
}
