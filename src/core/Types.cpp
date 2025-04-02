#include "ephemeralnet/Types.hpp"

#include <iomanip>
#include <optional>
#include <sstream>

namespace ephemeralnet {

namespace {
std::string to_hex(const std::uint8_t value) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<int>(value);
    return oss.str();
}

std::string array_to_hex_string(const std::array<std::uint8_t, 32>& array) {
    std::ostringstream oss;
    for (const auto byte : array) {
        oss << to_hex(byte);
    }
    return oss.str();
}

}  // namespace

std::string chunk_id_to_string(const ChunkId& id) {
    return array_to_hex_string(id);
}

std::string peer_id_to_string(const PeerId& id) {
    return array_to_hex_string(id);
}

std::optional<PeerId> peer_id_from_string(const std::string& text) {
    if (text.size() != PeerId{}.size() * 2) {
        return std::nullopt;
    }

    PeerId id{};
    for (std::size_t index = 0; index < id.size(); ++index) {
        const auto offset = index * 2;
        const auto byte_text = text.substr(offset, 2);
        std::istringstream iss(byte_text);
        int value = 0;
        iss >> std::hex >> value;
        if (iss.fail() || value < 0 || value > 0xFF) {
            return std::nullopt;
        }
        id[index] = static_cast<std::uint8_t>(value);
    }
    return id;
}

}  
