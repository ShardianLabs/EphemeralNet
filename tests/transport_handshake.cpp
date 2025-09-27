#include "ephemeralnet/protocol/Message.hpp"

#include <array>
#include <cassert>
#include <span>
#include <vector>

int main() {
    ephemeralnet::protocol::Message handshake{};
    handshake.version = ephemeralnet::protocol::kCurrentMessageVersion;
    handshake.type = ephemeralnet::protocol::MessageType::TransportHandshake;

    ephemeralnet::protocol::TransportHandshakePayload handshake_payload{};
    handshake_payload.public_identity = 0x12345678u;
    handshake_payload.work_nonce = 0x00FF00AA55ull;
    handshake_payload.requested_version = ephemeralnet::protocol::kCurrentMessageVersion - 1;
    handshake.payload = handshake_payload;

    const auto encoded_handshake = ephemeralnet::protocol::encode(handshake);
    const auto decoded_handshake = ephemeralnet::protocol::decode(
        std::span<const std::uint8_t>(encoded_handshake.data(), encoded_handshake.size()));
    assert(decoded_handshake.has_value());
    assert(decoded_handshake->version == handshake.version);
    assert(decoded_handshake->type == handshake.type);
    const auto* decoded_handshake_payload =
        std::get_if<ephemeralnet::protocol::TransportHandshakePayload>(&decoded_handshake->payload);
    assert(decoded_handshake_payload);
    assert(decoded_handshake_payload->public_identity == handshake_payload.public_identity);
    assert(decoded_handshake_payload->work_nonce == handshake_payload.work_nonce);
    assert(decoded_handshake_payload->requested_version == handshake_payload.requested_version);

    ephemeralnet::protocol::Message ack{};
    ack.version = ephemeralnet::protocol::kCurrentMessageVersion;
    ack.type = ephemeralnet::protocol::MessageType::HandshakeAck;

    ephemeralnet::protocol::HandshakeAckPayload ack_payload{};
    ack_payload.accepted = true;
    ack_payload.negotiated_version = ephemeralnet::protocol::kCurrentMessageVersion - 2;
    ack_payload.responder_public = 0x87654321u;
    ack.payload = ack_payload;

    std::array<std::uint8_t, 32> shared_key{};
    shared_key.fill(0x42u);

    const auto encoded_ack = ephemeralnet::protocol::encode_signed(
        ack,
        std::span<const std::uint8_t>(shared_key.data(), shared_key.size()));
    const auto decoded_ack = ephemeralnet::protocol::decode_signed(
        std::span<const std::uint8_t>(encoded_ack.data(), encoded_ack.size()),
        std::span<const std::uint8_t>(shared_key.data(), shared_key.size()));
    assert(decoded_ack.has_value());
    assert(decoded_ack->version == ack.version);
    assert(decoded_ack->type == ack.type);
    const auto* decoded_ack_payload =
        std::get_if<ephemeralnet::protocol::HandshakeAckPayload>(&decoded_ack->payload);
    assert(decoded_ack_payload);
    assert(decoded_ack_payload->accepted == ack_payload.accepted);
    assert(decoded_ack_payload->negotiated_version == ack_payload.negotiated_version);
    assert(decoded_ack_payload->responder_public == ack_payload.responder_public);

    return 0;
}
