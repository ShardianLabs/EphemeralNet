#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/protocol/Message.hpp"
#include "test_access.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <optional>
#include <span>
#include <thread>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

}  // namespace

int main() {
    ephemeralnet::Config producer_config{};
    producer_config.identity_seed = 0x33u;
    producer_config.announce_pow_difficulty = 0;

    ephemeralnet::Config consumer_config{};
    consumer_config.identity_seed = 0x44u;
    consumer_config.fetch_retry_initial_backoff = std::chrono::seconds(1);
    consumer_config.fetch_retry_max_backoff = std::chrono::seconds(2);
    consumer_config.fetch_retry_success_interval = std::chrono::seconds(1);
    consumer_config.fetch_retry_attempt_limit = 4;
    consumer_config.announce_pow_difficulty = 0;

    const auto producer_id = make_peer_id(0x10);
    const auto consumer_id = make_peer_id(0x80);

    ephemeralnet::Node producer(producer_id, producer_config);
    ephemeralnet::Node consumer(consumer_id, consumer_config);

    producer.start_transport(0);
    consumer.start_transport(0);

    const auto producer_port = producer.transport_port();
    assert(producer_port != 0);

    ephemeralnet::ChunkId chunk_id{};
    chunk_id.fill(0xBA);

    ephemeralnet::ChunkData data(64, 0x7Cu);
    const auto manifest = producer.store_chunk(chunk_id, data, 300s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    ephemeralnet::protocol::AnnouncePayload payload{};
    payload.chunk_id = chunk_id;
    payload.peer_id = producer_id;
    payload.endpoint = "127.0.0.1:" + std::to_string(producer_port);
    payload.ttl = 180s;
    payload.manifest_uri = manifest_uri;
    payload.assigned_shards.push_back(manifest.shards.front().index);

    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, payload, producer_id);

    const auto initial_attempt = ephemeralnet::test::NodeTestAccess::pending_attempts(consumer, chunk_id);
    assert(initial_attempt.has_value());
    assert(*initial_attempt == 1);

    const bool handshake_ab = producer.perform_handshake(consumer_id, consumer.public_identity());
    const bool handshake_ba = consumer.perform_handshake(producer_id, producer.public_identity());
    assert(handshake_ab);
    assert(handshake_ba);

    std::atomic<std::size_t> request_count{0};
    producer.set_message_handler([&](const ephemeralnet::network::TransportMessage& message) {
        if (message.peer_id != consumer_id) {
            return;
        }
        auto key = producer.session_key(message.peer_id);
        if (!key.has_value()) {
            return;
        }
        const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
        const auto decoded = ephemeralnet::protocol::decode_signed(message.payload, key_span);
        if (!decoded.has_value()) {
            return;
        }
        if (decoded->type == ephemeralnet::protocol::MessageType::Request) {
            request_count.fetch_add(1, std::memory_order_relaxed);
        }
    });

    auto start = std::chrono::steady_clock::now();
    std::optional<ephemeralnet::ChunkData> fetched;
    while (std::chrono::steady_clock::now() - start < 5s) {
        consumer.tick();
        producer.tick();
        fetched = consumer.fetch_chunk(chunk_id);
        if (fetched.has_value()) {
            break;
        }
        std::this_thread::sleep_for(100ms);
    }

    assert(fetched.has_value());
    assert(*fetched == data);
    assert(request_count.load(std::memory_order_relaxed) == 1);
    assert(!ephemeralnet::test::NodeTestAccess::has_pending_fetch(consumer, chunk_id));

    producer.stop_transport();
    consumer.stop_transport();

    return 0;
}
