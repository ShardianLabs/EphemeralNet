#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ephemeralnet {

using ChunkId = std::array<std::uint8_t, 32>;
using PeerId = std::array<std::uint8_t, 32>;
using ChunkData = std::vector<std::uint8_t>;

std::string chunk_id_to_string(const ChunkId& id);
std::string peer_id_to_string(const PeerId& id);
std::optional<PeerId> peer_id_from_string(const std::string& text);

}  
