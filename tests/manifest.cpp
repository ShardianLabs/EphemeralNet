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

    manifest.metadata["filename"] = "secret.bin";

    ephemeralnet::protocol::DiscoveryHint hint{};
    hint.transport = "control";
    hint.endpoint = "198.51.100.10:47777";
    hint.priority = 3;
    manifest.discovery_hints.push_back(hint);

    manifest.security.token_challenge_bits = 8;
    manifest.security.advisory = "Bootstrap nodes enforce an 8-bit PoW token.";
    manifest.security.has_attestation_digest = true;
    manifest.security.attestation_digest.fill(0xAA);

    ephemeralnet::protocol::FallbackHint fallback{};
    fallback.uri = "https://mirror.example.invalid/object";
    fallback.priority = 5;
    manifest.fallback_hints.push_back(fallback);

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
    assert(decoded.metadata == manifest.metadata);
    assert(decoded.discovery_hints.size() == 1);
    assert(decoded.discovery_hints[0].transport == hint.transport);
    assert(decoded.discovery_hints[0].endpoint == hint.endpoint);
    assert(decoded.discovery_hints[0].priority == hint.priority);
    assert(decoded.security.token_challenge_bits == manifest.security.token_challenge_bits);
    assert(decoded.security.advisory == manifest.security.advisory);
    assert(decoded.security.has_attestation_digest == manifest.security.has_attestation_digest);
    assert(decoded.security.attestation_digest == manifest.security.attestation_digest);
    assert(decoded.fallback_hints.size() == 1);
    assert(decoded.fallback_hints[0].uri == fallback.uri);
    assert(decoded.fallback_hints[0].priority == fallback.priority);

    return 0;
}
