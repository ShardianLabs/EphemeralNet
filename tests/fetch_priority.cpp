#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/protocol/Message.hpp"
#include "test_access.hpp"

#include <cassert>
#include <chrono>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

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

}  // namespace

int main() {
    ephemeralnet::Config producer_config{};
    producer_config.identity_seed = 0x41u;

    ephemeralnet::Config consumer_config{};
    consumer_config.identity_seed = 0x51u;
    consumer_config.fetch_max_parallel_requests = 1;
    consumer_config.fetch_retry_initial_backoff = std::chrono::seconds(1);
    consumer_config.fetch_retry_success_interval = std::chrono::seconds(2);

    const auto producer_id = make_peer_id(0x10);
    const auto consumer_id = make_peer_id(0x90);

    ephemeralnet::Node producer(producer_id, producer_config);
    ephemeralnet::Node consumer(consumer_id, consumer_config);

    producer.start_transport(0);
    consumer.start_transport(0);

    const bool handshake_ab = producer.perform_handshake(consumer_id, consumer.public_identity());
    const bool handshake_ba = consumer.perform_handshake(producer_id, producer.public_identity());
    assert(handshake_ab);
    assert(handshake_ba);

    const auto producer_port = producer.transport_port();
    assert(producer_port != 0);

    const auto urgent_chunk = make_chunk_id(0x70);
    const auto background_chunk = make_chunk_id(0x80);

    ephemeralnet::ChunkData urgent_data(64, 0x11u);
    ephemeralnet::ChunkData background_data(64, 0x22u);

    const auto urgent_manifest = producer.store_chunk(urgent_chunk, urgent_data, 45s);
    const auto background_manifest = producer.store_chunk(background_chunk, background_data, 240s);

    const auto urgent_uri = ephemeralnet::protocol::encode_manifest(urgent_manifest);
    const auto background_uri = ephemeralnet::protocol::encode_manifest(background_manifest);

    std::vector<std::string> request_log;
    std::mutex request_mutex;

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
        if (decoded->type != ephemeralnet::protocol::MessageType::Request) {
            return;
        }
        const auto* payload = std::get_if<ephemeralnet::protocol::RequestPayload>(&decoded->payload);
        if (!payload) {
            return;
        }
        std::lock_guard<std::mutex> lock(request_mutex);
        request_log.push_back(ephemeralnet::chunk_id_to_string(payload->chunk_id));
    });

    ephemeralnet::protocol::AnnouncePayload urgent_payload{};
    urgent_payload.chunk_id = urgent_chunk;
    urgent_payload.peer_id = producer_id;
    urgent_payload.endpoint = "127.0.0.1:" + std::to_string(producer_port);
    urgent_payload.ttl = 40s;
    urgent_payload.manifest_uri = urgent_uri;
    urgent_payload.assigned_shards.push_back(urgent_manifest.shards.front().index);

    ephemeralnet::protocol::AnnouncePayload background_payload{};
    background_payload.chunk_id = background_chunk;
    background_payload.peer_id = producer_id;
    background_payload.endpoint = "127.0.0.1:" + std::to_string(producer_port);
    background_payload.ttl = 200s;
    background_payload.manifest_uri = background_uri;
    background_payload.assigned_shards.push_back(background_manifest.shards.front().index);

    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, urgent_payload, producer_id);
    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, background_payload, producer_id);

    std::optional<ephemeralnet::ChunkData> urgent_fetched;
    std::optional<ephemeralnet::ChunkData> background_fetched;

    const auto deadline = std::chrono::steady_clock::now() + 6s;
    while ((!urgent_fetched.has_value() || !background_fetched.has_value())
           && std::chrono::steady_clock::now() < deadline) {
        consumer.tick();
        producer.tick();
        if (!urgent_fetched) {
            urgent_fetched = consumer.fetch_chunk(urgent_chunk);
        }
        if (!background_fetched) {
            background_fetched = consumer.fetch_chunk(background_chunk);
        }
        std::this_thread::sleep_for(50ms);
    }

    assert(urgent_fetched.has_value());
    assert(*urgent_fetched == urgent_data);
    assert(background_fetched.has_value());
    assert(*background_fetched == background_data);

    std::vector<std::string> log_copy;
    {
        std::lock_guard<std::mutex> lock(request_mutex);
        log_copy = request_log;
    }

    assert(log_copy.size() == 2);
    assert(log_copy.front() == ephemeralnet::chunk_id_to_string(urgent_chunk));

    producer.stop_transport();
    consumer.stop_transport();

    return 0;
}
