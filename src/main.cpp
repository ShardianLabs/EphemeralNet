#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/core/Node.hpp"

#include <chrono>
#include <iostream>

namespace {

using namespace std::chrono_literals;

ephemeralnet::ChunkId make_chunk_id(std::uint8_t seed) {
    ephemeralnet::ChunkId id{};
    for (auto& byte : id) {
        byte = static_cast<std::uint8_t>(seed++);
    }
    return id;
}

ephemeralnet::ChunkData make_chunk_data() {
    const auto message = std::string{"EphemeralNet example payload"};
    return {message.begin(), message.end()};
}

}  // namespace

int main() {
    auto config = ephemeralnet::Config{};
    config.default_chunk_ttl = std::chrono::hours(24);

    ephemeralnet::PeerId peer{};
    peer.fill(0x42);

    ephemeralnet::Node node{peer, config};

    const auto chunk_id = make_chunk_id(0x10);
    node.store_chunk(chunk_id, make_chunk_data(), 1h);

    if (const auto data = node.fetch_chunk(chunk_id)) {
        std::cout << "Chunk present locally with size: " << data->size() << " bytes\n";
    }

    node.tick();

    std::cout << "EphemeralNet bootstrap node ready." << std::endl;
    return 0;
}
