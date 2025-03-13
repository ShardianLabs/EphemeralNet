#pragma once

#include "ephemeralnet/core/Node.hpp"

#include <optional>

namespace ephemeralnet::test {

class NodeTestAccess {
public:
    static void handle_announce(Node& node,
                                const protocol::AnnouncePayload& payload,
                                const PeerId& sender) {
        node.handle_announce(payload, sender);
    }

    static std::optional<std::size_t> pending_attempts(const Node& node, const ChunkId& chunk_id) {
        const auto key = chunk_id_to_string(chunk_id);
        const auto it = node.pending_chunk_fetches_.find(key);
        if (it == node.pending_chunk_fetches_.end()) {
            return std::nullopt;
        }
        return it->second.attempts;
    }

    static bool has_pending_fetch(const Node& node, const ChunkId& chunk_id) {
        const auto key = chunk_id_to_string(chunk_id);
        return node.pending_chunk_fetches_.find(key) != node.pending_chunk_fetches_.end();
    }
};

}  // namespace ephemeralnet::test
