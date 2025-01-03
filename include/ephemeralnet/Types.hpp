#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ephemeralnet {

using ChunkId = std::array<std::uint8_t, 32>;
using PeerId = std::array<std::uint8_t, 32>;
using ChunkData = std::vector<std::uint8_t>;

std::string chunk_id_to_string(const ChunkId& id);
std::string peer_id_to_string(const PeerId& id);

}  
