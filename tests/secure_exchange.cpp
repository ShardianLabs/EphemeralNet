#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <optional>
#include <thread>

using namespace std::chrono_literals;

namespace {

constexpr auto kHost = "127.0.0.1";

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::ChunkId make_chunk_id(std::uint8_t seed) {
    ephemeralnet::ChunkId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::ChunkData make_payload(std::uint8_t seed) {
    ephemeralnet::ChunkData data(32);
    std::generate(data.begin(), data.end(), [&]() { return seed++; });
    return data;
}

}  // namespace

int main() {
    ephemeralnet::Config producer_config{};
    producer_config.identity_seed = 0x10;

    ephemeralnet::Config consumer_config{};
    consumer_config.identity_seed = 0x90;

    const auto producer_id = make_peer_id(0x01);
    const auto consumer_id = make_peer_id(0x81);
    const auto chunk_id = make_chunk_id(0x55);
    const auto payload = make_payload(0xAA);

    ephemeralnet::Node producer{producer_id, producer_config};
    ephemeralnet::Node consumer{consumer_id, consumer_config};

    producer.start_transport(0);
    consumer.start_transport(0);

    const auto manifest = producer.store_chunk(chunk_id, payload, 120s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    const auto pow_consumer = ephemeralnet::test::NodeTestAccess::handshake_work(consumer, producer.id());
    const auto pow_producer = ephemeralnet::test::NodeTestAccess::handshake_work(producer, consumer_id);
    assert(pow_consumer.has_value());
    assert(pow_producer.has_value());
    const bool handshake_ab = producer.perform_handshake(consumer_id, consumer.public_identity(), *pow_consumer);
    const bool handshake_ba = consumer.perform_handshake(producer_id, producer.public_identity(), *pow_producer);
    assert(handshake_ab);
    assert(handshake_ba);

    const auto producer_port = producer.transport_port();

    const bool request_sent = consumer.request_chunk(producer_id, kHost, producer_port, manifest_uri);
    assert(request_sent);

    auto start = std::chrono::steady_clock::now();
    std::optional<ephemeralnet::ChunkData> received;
    while (std::chrono::steady_clock::now() - start < 2s) {
        received = consumer.fetch_chunk(chunk_id);
        if (received.has_value()) {
            break;
        }
        std::this_thread::sleep_for(20ms);
    }

    assert(received.has_value());
    assert(*received == payload);

    producer.stop_transport();
    consumer.stop_transport();

    return 0;
}
