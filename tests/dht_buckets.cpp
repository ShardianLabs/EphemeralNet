#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"

#include <cassert>
#include <chrono>
#include <string>

using namespace std::chrono_literals;

using ephemeralnet::ChunkId;
using ephemeralnet::Config;
using ephemeralnet::KademliaTable;
using ephemeralnet::PeerContact;
using ephemeralnet::PeerId;

namespace {

PeerId make_peer_id(std::uint8_t head, std::uint8_t tail) {
    PeerId id{};
    id.fill(head);
    id.back() = tail;
    return id;
}

ChunkId make_chunk_id(std::uint8_t seed) {
    ChunkId id{};
    for (auto& byte : id) {
        byte = seed;
        ++seed;
    }
    return id;
}

}  // namespace

int main() {
    Config config{};
    PeerId self{};
    self.fill(0x11);

    KademliaTable table{self, config};

    // Insert a contact and ensure updates refresh metadata.
    PeerContact primary{};
    primary.id = make_peer_id(0x80, 0x01);
    primary.address = "peer://initial";
    table.add_contact(make_chunk_id(0x01), primary, 60s);

    primary.address = "peer://updated";
    table.add_contact(make_chunk_id(0x01), primary, 60s);

    const auto closest_primary = table.closest_peers(primary.id, 1);
    assert(closest_primary.size() == 1);
    assert(closest_primary.front().address == "peer://updated");

    // Insert many contacts that fall into the same bucket to test eviction policy.
    for (std::uint8_t idx = 0; idx < 32; ++idx) {
        PeerContact contact{};
        contact.id = make_peer_id(static_cast<std::uint8_t>(0x80 | 0x01), idx);
        contact.address = "peer://" + std::to_string(idx);
        table.add_contact(make_chunk_id(static_cast<std::uint8_t>(0x10 + idx)), contact, 120s);
    }

    const auto closest_many = table.closest_peers(self, 64);
    assert(closest_many.size() <= 16);

    return 0;
}
