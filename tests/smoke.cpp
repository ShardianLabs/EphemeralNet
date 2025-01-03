#include "ephemeralnet/core/Node.hpp"

#include <cassert>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

using ephemeralnet::ChunkData;
using ephemeralnet::ChunkId;
using ephemeralnet::Node;
using ephemeralnet::PeerId;

namespace {

ChunkId make_chunk_id(std::uint8_t seed) {
    ChunkId id{};
    for (auto& byte : id) {
        byte = static_cast<std::uint8_t>(seed++);
    }
    return id;
}

ChunkData make_chunk(std::uint8_t value) {
    return ChunkData{value, static_cast<std::uint8_t>(value + 1), static_cast<std::uint8_t>(value + 2)};
}

}  // namespace

int main() {
    PeerId peer{};
    peer.fill(0xAA);

    Node node{peer};

    const auto chunk_id = make_chunk_id(0x10);
    node.store_chunk(chunk_id, make_chunk(0x01), 1s);

    auto data = node.fetch_chunk(chunk_id);
    assert(data.has_value());
    assert(data->size() == 3);

    std::this_thread::sleep_for(2s);
    node.tick();

    data = node.fetch_chunk(chunk_id);
    assert(!data.has_value());

    return 0;
}
