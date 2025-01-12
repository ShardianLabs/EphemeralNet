#include "ephemeralnet/network/KeyManager.hpp"

#include <array>
#include <cassert>
#include <chrono>

using namespace std::chrono_literals;

using ephemeralnet::PeerId;
using ephemeralnet::crypto::Key;
using ephemeralnet::network::KeyManager;

namespace {

PeerId make_peer_id(std::uint8_t seed) {
    PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

Key make_secret(std::uint8_t seed) {
    Key key{};
    for (auto& byte : key.bytes) {
        byte = seed++;
    }
    return key;
}

}  // namespace

int main() {
    KeyManager manager{1s};
    const auto peer = make_peer_id(0x10);
    const auto secret = make_secret(0x20);

    manager.register_session(peer, secret);

    const auto initial = manager.current_key(peer);
    assert(initial.has_value());

    const auto no_rotate = manager.rotate_if_needed(peer);
    assert(!no_rotate.has_value());

    const auto future = std::chrono::steady_clock::now() + 2s;
    const auto rotated = manager.rotate_if_needed(peer, future);
    assert(rotated.has_value());
    const auto updated = manager.current_key(peer);
    assert(updated.has_value());
    assert(*updated != *initial);

    const auto missing = manager.current_key(make_peer_id(0x80));
    assert(!missing.has_value());

    return 0;
}
