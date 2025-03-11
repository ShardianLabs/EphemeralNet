#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/protocol/Message.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <optional>
#include <span>
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

}  // namespace

int main() {
    ephemeralnet::Config producer_config{};
    producer_config.identity_seed = 0x22u;
    producer_config.swarm_target_replicas = 1;
    producer_config.swarm_min_providers = 1;

    ephemeralnet::Config consumer_config{};
    consumer_config.identity_seed = 0x44u;

    const auto producer_id = make_peer_id(0x10);
    const auto consumer_id = make_peer_id(0xA0);

    ephemeralnet::Node producer(producer_id, producer_config);
    ephemeralnet::Node consumer(consumer_id, consumer_config);

    producer.start_transport(0);
    consumer.start_transport(0);

    const bool handshake_ab = producer.perform_handshake(consumer_id, consumer.public_identity());
    const bool handshake_ba = consumer.perform_handshake(producer_id, producer.public_identity());
    assert(handshake_ab);
    assert(handshake_ba);

    const auto consumer_port = consumer.transport_port();
    assert(consumer_port != 0);

    const auto now = std::chrono::steady_clock::now();
    ephemeralnet::PeerContact consumer_contact{};
    consumer_contact.id = consumer_id;
    consumer_contact.address = "127.0.0.1:" + std::to_string(consumer_port);
    consumer_contact.expires_at = now + std::chrono::minutes(5);
    producer.register_peer_contact(consumer_contact);

    std::atomic<bool> delivered{false};
    std::promise<ephemeralnet::protocol::AnnouncePayload> promise;
    auto future = promise.get_future();

    consumer.set_message_handler([&](const ephemeralnet::network::TransportMessage& message) {
        if (delivered.load()) {
            return;
        }
        if (message.peer_id != producer_id) {
            return;
        }
        auto key = consumer.session_key(message.peer_id);
        if (!key.has_value()) {
            return;
        }
        const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
        const auto decoded = ephemeralnet::protocol::decode_signed(message.payload, key_span);
        if (!decoded.has_value()) {
            return;
        }
        if (decoded->type != ephemeralnet::protocol::MessageType::Announce) {
            return;
        }
        if (const auto* payload = std::get_if<ephemeralnet::protocol::AnnouncePayload>(&decoded->payload)) {
            bool expected = false;
            if (!delivered.compare_exchange_strong(expected, true)) {
                return;
            }
            promise.set_value(*payload);
        }
    });

    ephemeralnet::ChunkId chunk_id{};
    chunk_id.fill(0x55);

    ephemeralnet::ChunkData data(64, 0x5Au);
    const auto manifest = producer.store_chunk(chunk_id, data, 120s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    const auto status = future.wait_for(2s);
    assert(status == std::future_status::ready);
    const auto payload = future.get();

    assert(payload.chunk_id == manifest.chunk_id);
    assert(payload.peer_id == producer_id);
    assert(payload.ttl.count() > 0);
    assert(payload.manifest_uri == manifest_uri);
    assert(!payload.endpoint.empty());
    assert(!payload.assigned_shards.empty());

    auto start = std::chrono::steady_clock::now();
    std::optional<ephemeralnet::SwarmDistributionPlan> plan;
    while (std::chrono::steady_clock::now() - start < 2s) {
        plan = consumer.swarm_plan(chunk_id);
        if (plan.has_value()) {
            break;
        }
        std::this_thread::sleep_for(20ms);
    }
    assert(plan.has_value());

    producer.stop_transport();
    consumer.stop_transport();

    return 0;
}
