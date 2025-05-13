#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <cassert>
#include <chrono>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::ChunkData make_payload(std::uint8_t seed) {
    ephemeralnet::ChunkData data(16);
    for (auto& byte : data) {
        byte = seed++;
    }
    return data;
}

}  // namespace

int main() {
    ephemeralnet::Config producer_config{};
    producer_config.shard_threshold = 3;
    producer_config.shard_total = 5;
    producer_config.min_manifest_ttl = 5s;
    producer_config.max_manifest_ttl = 1h;

    ephemeralnet::Config consumer_config{};
    consumer_config.shard_threshold = 3;
    consumer_config.shard_total = 5;
    consumer_config.min_manifest_ttl = 5s;
    consumer_config.max_manifest_ttl = 1h;

    const auto chunk_id = make_peer_id(0x10);
    const auto payload = make_payload(0x30);

    ephemeralnet::Node producer{make_peer_id(0x01), producer_config};
    ephemeralnet::Node consumer{make_peer_id(0xA1), consumer_config};

    const auto manifest = producer.store_chunk(chunk_id, payload, 30s);
    const auto manifest_uri = ephemeralnet::protocol::encode_manifest(manifest);

    const auto exported_record = producer.export_chunk_record(chunk_id);
    assert(exported_record.has_value());
    assert(exported_record->encrypted);

    const bool shards_announced = consumer.ingest_manifest(manifest_uri);
    assert(shards_announced);

    const auto decrypted = consumer.receive_chunk(manifest_uri, exported_record->data);
    assert(decrypted.has_value());
    assert(*decrypted == payload);

    const auto fetched = consumer.fetch_chunk(chunk_id);
    assert(fetched.has_value());
    assert(*fetched == payload);

    return 0;
}
