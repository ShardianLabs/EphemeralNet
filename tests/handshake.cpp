#include "ephemeralnet/core/Node.hpp"
#include "test_access.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>

using ephemeralnet::ChunkId;
using ephemeralnet::Config;
using ephemeralnet::Node;
using ephemeralnet::PeerId;

namespace {

PeerId make_peer_id(std::uint8_t seed) {
    PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

Config make_config(std::uint32_t seed, std::chrono::seconds cooldown) {
    Config config{};
    config.identity_seed = seed;
    config.handshake_cooldown = cooldown;
    return config;
}

}  // namespace

int main() {
    auto config_a = make_config(0x01u, std::chrono::seconds(2));
    auto config_b = make_config(0x02u, std::chrono::seconds(2));

    Node node_a{make_peer_id(0x10), config_a};
    Node node_b{make_peer_id(0x80), config_b};

    const auto pow_b = ephemeralnet::test::NodeTestAccess::handshake_work(node_b, node_a.id());
    assert(pow_b.has_value());
    const bool initiated = node_a.perform_handshake(node_b.id(), node_b.public_identity(), *pow_b);
    assert(initiated);
    const auto pow_a = ephemeralnet::test::NodeTestAccess::handshake_work(node_a, node_b.id());
    assert(pow_a.has_value());
    const bool accepted = node_b.perform_handshake(node_a.id(), node_a.public_identity(), *pow_a);
    assert(accepted);

    const auto key_a = node_a.session_key(node_b.id());
    const auto key_b = node_b.session_key(node_a.id());
    assert(key_a.has_value());
    assert(key_b.has_value());
    assert(*key_a == *key_b);

    const auto reputation_a = node_a.reputation_score(node_b.id());
    const auto reputation_b = node_b.reputation_score(node_a.id());
    assert(reputation_a > 0);
    assert(reputation_b > 0);

    const auto last_success = node_a.last_handshake_success(node_b.id());
    assert(last_success.has_value() && *last_success);

    const auto score_before_retry = node_a.reputation_score(node_b.id());
    const bool repeated = node_a.perform_handshake(node_b.id(), node_b.public_identity(), *pow_b);
    assert(repeated);
    const auto score_after_retry = node_a.reputation_score(node_b.id());
    assert(score_before_retry == score_after_retry);

    const auto invalid_peer = make_peer_id(0x33);
    const bool failed = node_a.perform_handshake(invalid_peer, 0u, 0u);
    assert(!failed);
    const auto missing_key = node_a.session_key(invalid_peer);
    assert(!missing_key.has_value());
    const auto reputation_failure = node_a.reputation_score(invalid_peer);
    assert(reputation_failure < 0);

    return 0;
}
