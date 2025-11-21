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
#include <iostream>
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
    consumer_config.fetch_availability_refresh = std::chrono::seconds(1);
    consumer_config.announce_min_interval = std::chrono::seconds::zero();

    ephemeralnet::Config replica_config{};
    replica_config.identity_seed = 0x61u;

    ephemeralnet::Config replica_b_config{};
    replica_b_config.identity_seed = 0x62u;

    std::vector<std::string> request_log;
    std::mutex request_mutex;

    const auto producer_id = make_peer_id(0x10);
    const auto consumer_id = make_peer_id(0x90);
    const auto replica_id = make_peer_id(0x30);
    const auto replica_b_id = make_peer_id(0x40);

    ephemeralnet::Node producer(producer_id, producer_config);
    ephemeralnet::Node consumer(consumer_id, consumer_config);
    ephemeralnet::Node replica(replica_id, replica_config);
    ephemeralnet::Node replica_b(replica_b_id, replica_b_config);

    producer.start_transport(0);
    consumer.start_transport(0);
    replica.start_transport(0);
    replica_b.start_transport(0);

    auto shutdown = [&]() {
        producer.stop_transport();
        consumer.stop_transport();
        replica.stop_transport();
        replica_b.stop_transport();
    };

    auto require = [&](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "[FetchPriority] " << message << std::endl;
            shutdown();
            return false;
        }
        return true;
    };

    const auto pow_from_consumer_for_producer = ephemeralnet::test::NodeTestAccess::handshake_work(consumer, producer_id);
    const auto pow_from_producer_for_consumer = ephemeralnet::test::NodeTestAccess::handshake_work(producer, consumer_id);
    const auto pow_from_replica_for_consumer = ephemeralnet::test::NodeTestAccess::handshake_work(replica, consumer_id);
    const auto pow_from_consumer_for_replica = ephemeralnet::test::NodeTestAccess::handshake_work(consumer, replica_id);
    const auto pow_from_replica_b_for_consumer = ephemeralnet::test::NodeTestAccess::handshake_work(replica_b, consumer_id);
    const auto pow_from_consumer_for_replica_b = ephemeralnet::test::NodeTestAccess::handshake_work(consumer, replica_b_id);
    if (!require(pow_from_consumer_for_producer.has_value(), "consumer->producer handshake work failed")) {
        return 1;
    }
    if (!require(pow_from_producer_for_consumer.has_value(), "producer->consumer handshake work failed")) {
        return 1;
    }
    if (!require(pow_from_replica_for_consumer.has_value(), "replica->consumer handshake work failed")) {
        return 1;
    }
    if (!require(pow_from_consumer_for_replica.has_value(), "consumer->replica handshake work failed")) {
        return 1;
    }
    if (!require(pow_from_replica_b_for_consumer.has_value(), "replica-b->consumer handshake work failed")) {
        return 1;
    }
    if (!require(pow_from_consumer_for_replica_b.has_value(), "consumer->replica-b handshake work failed")) {
        return 1;
    }
    const bool handshake_ab = producer.perform_handshake(consumer_id, consumer.public_identity(), *pow_from_consumer_for_producer);
    const bool handshake_ba = consumer.perform_handshake(producer_id, producer.public_identity(), *pow_from_producer_for_consumer);
    const bool handshake_cr = consumer.perform_handshake(replica_id, replica.public_identity(), *pow_from_replica_for_consumer);
    const bool handshake_rc = replica.perform_handshake(consumer_id, consumer.public_identity(), *pow_from_consumer_for_replica);
    const bool handshake_crb = consumer.perform_handshake(replica_b_id, replica_b.public_identity(), *pow_from_replica_b_for_consumer);
    const bool handshake_rb = replica_b.perform_handshake(consumer_id, consumer.public_identity(), *pow_from_consumer_for_replica_b);
    if (!require(handshake_ab && handshake_ba, "consumer<->producer handshake failed")) {
        return 1;
    }
    if (!require(handshake_cr && handshake_rc, "consumer<->replica handshake failed")) {
        return 1;
    }
    if (!require(handshake_crb && handshake_rb, "consumer<->replica-b handshake failed")) {
        return 1;
    }

    const auto producer_port = producer.transport_port();
    if (!require(producer_port != 0, "producer transport did not start")) {
        return 1;
    }
    const auto replica_port = replica.transport_port();
    if (!require(replica_port != 0, "replica transport did not start")) {
        return 1;
    }
    const auto replica_b_port = replica_b.transport_port();
    if (!require(replica_b_port != 0, "replica B transport did not start")) {
        return 1;
    }

    const auto urgent_chunk = make_chunk_id(0x70);
    const auto background_chunk = make_chunk_id(0x80);

    ephemeralnet::ChunkData urgent_data(64, 0x11u);
    ephemeralnet::ChunkData background_data(64, 0x22u);

    const auto urgent_manifest = producer.store_chunk(urgent_chunk, urgent_data, 180s);
    const auto background_manifest = producer.store_chunk(background_chunk, background_data, 180s);
    const auto urgent_uri = ephemeralnet::protocol::encode_manifest(urgent_manifest);
    const auto background_uri = ephemeralnet::protocol::encode_manifest(background_manifest);
    const auto producer_background_record = producer.export_chunk_record(background_chunk);
    if (!require(producer_background_record.has_value(), "producer missing background chunk")) {
        return 1;
    }
    auto background_ciphertext_primary = producer_background_record->data;
    auto background_ciphertext_secondary = producer_background_record->data;

    const bool replica_ingested_manifest = replica.ingest_manifest(background_uri);
    if (!require(replica_ingested_manifest, "replica failed to ingest manifest")) {
        return 1;
    }
    const auto replica_plaintext = replica.receive_chunk(background_uri, std::move(background_ciphertext_primary));
    if (!require(replica_plaintext.has_value(), "replica failed to decrypt chunk")) {
        return 1;
    }
    if (!require(*replica_plaintext == background_data, "replica chunk mismatch")) {
        return 1;
    }

    const bool replica_b_ingested_manifest = replica_b.ingest_manifest(background_uri);
    if (!require(replica_b_ingested_manifest, "replica B failed to ingest manifest")) {
        return 1;
    }
    const auto replica_b_plaintext = replica_b.receive_chunk(background_uri, std::move(background_ciphertext_secondary));
    if (!require(replica_b_plaintext.has_value(), "replica B failed to decrypt chunk")) {
        return 1;
    }
    if (!require(*replica_b_plaintext == background_data, "replica B chunk mismatch")) {
        return 1;
    }

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

    ephemeralnet::protocol::AnnouncePayload replica_payload{};
    replica_payload.chunk_id = background_chunk;
    replica_payload.peer_id = replica_id;
    replica_payload.endpoint = "127.0.0.1:" + std::to_string(replica_port);
    replica_payload.ttl = 200s;
    replica_payload.manifest_uri = background_uri;
    replica_payload.assigned_shards.push_back(background_manifest.shards.front().index);

    ephemeralnet::protocol::AnnouncePayload replica_b_payload{};
    replica_b_payload.chunk_id = background_chunk;
    replica_b_payload.peer_id = replica_b_id;
    replica_b_payload.endpoint = "127.0.0.1:" + std::to_string(replica_b_port);
    replica_b_payload.ttl = 200s;
    replica_b_payload.manifest_uri = background_uri;
    replica_b_payload.assigned_shards.push_back(background_manifest.shards.front().index);

    const bool urgent_pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(consumer, urgent_payload);
    assert(urgent_pow_ready);
    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, urgent_payload, producer_id);

    const bool background_pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(consumer, background_payload);
    assert(background_pow_ready);
    const bool replica_pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(consumer, replica_payload);
    assert(replica_pow_ready);
    const bool replica_b_pow_ready = ephemeralnet::test::NodeTestAccess::apply_pow(consumer, replica_b_payload);
    assert(replica_b_pow_ready);
    const bool background_manifest_accepted = consumer.ingest_manifest(background_uri);
    assert(background_manifest_accepted);
    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, background_payload, producer_id);
    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, replica_payload, replica_id);
    ephemeralnet::test::NodeTestAccess::handle_announce(consumer, replica_b_payload, replica_b_id);
    ephemeralnet::test::NodeTestAccess::force_availability_refresh(consumer, urgent_chunk);
    ephemeralnet::test::NodeTestAccess::force_availability_refresh(consumer, background_chunk);

    const auto urgent_known = ephemeralnet::test::NodeTestAccess::provider_count(consumer, urgent_chunk);
    const auto background_known = ephemeralnet::test::NodeTestAccess::provider_count(consumer, background_chunk);
    if (!require(urgent_known.has_value(), "consumer missing urgent providers")) {
        return 1;
    }
    if (!require(background_known.has_value(), "consumer missing background providers")) {
        return 1;
    }
    if (!require(*urgent_known < *background_known, "provider counts not biased toward background chunk")) {
        return 1;
    }

    std::optional<ephemeralnet::ChunkData> urgent_fetched;
    std::optional<ephemeralnet::ChunkData> background_fetched;

    const auto deadline = std::chrono::steady_clock::now() + 6s;
    while ((!urgent_fetched.has_value() || !background_fetched.has_value())
           && std::chrono::steady_clock::now() < deadline) {
        consumer.tick();
        producer.tick();
        replica.tick();
        replica_b.tick();
        if (!urgent_fetched) {
            urgent_fetched = consumer.fetch_chunk(urgent_chunk);
        }
        if (!background_fetched) {
            background_fetched = consumer.fetch_chunk(background_chunk);
        }
        std::this_thread::sleep_for(50ms);
    }

    if (!require(urgent_fetched.has_value(), "urgent chunk was never fetched")) {
        return 1;
    }
    if (!require(*urgent_fetched == urgent_data, "urgent chunk payload mismatch")) {
        return 1;
    }
    if (!require(background_fetched.has_value(), "background chunk was never fetched")) {
        return 1;
    }
    if (!require(*background_fetched == background_data, "background chunk payload mismatch")) {
        return 1;
    }

    std::vector<std::string> log_copy;
    {
        std::lock_guard<std::mutex> lock(request_mutex);
        log_copy = request_log;
    }

    if (!require(!log_copy.empty(), "producer request log is empty")) {
        return 1;
    }
    if (!require(log_copy.front() == ephemeralnet::chunk_id_to_string(urgent_chunk), "urgent chunk was not requested first")) {
        return 1;
    }
    shutdown();
    return 0;
}
