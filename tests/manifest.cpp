#include "ephemeralnet/protocol/Manifest.hpp"

#include "ephemeralnet/Types.hpp"

#include <cassert>
#include <chrono>

using namespace std::chrono_literals;

int main() {
    ephemeralnet::protocol::Manifest manifest{};
    manifest.chunk_id.fill(0x11);
    manifest.chunk_hash.fill(0x22);
    manifest.nonce.bytes.fill(0x33);
    manifest.threshold = 3;
    manifest.total_shares = 5;
    manifest.expires_at = std::chrono::system_clock::now() + 3600s;

    ephemeralnet::protocol::KeyShard shard{};
    shard.index = 1;
    shard.value.fill(0x44);
    manifest.shards.push_back(shard);

    const auto uri = ephemeralnet::protocol::encode_manifest(manifest);
    const auto decoded = ephemeralnet::protocol::decode_manifest(uri);

    assert(decoded.chunk_id == manifest.chunk_id);
    assert(decoded.chunk_hash == manifest.chunk_hash);
    assert(decoded.nonce.bytes == manifest.nonce.bytes);
    assert(decoded.threshold == manifest.threshold);
    assert(decoded.total_shares == manifest.total_shares);
    assert(decoded.shards.size() == manifest.shards.size());
    assert(decoded.shards[0].index == shard.index);
    assert(decoded.shards[0].value == shard.value);

    return 0;
}
