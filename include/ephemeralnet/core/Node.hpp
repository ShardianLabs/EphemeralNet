#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/network/KeyManager.hpp"
#include "ephemeralnet/network/ReputationManager.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/crypto/CryptoManager.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "ephemeralnet/storage/ChunkStore.hpp"

#include <array>
#include <chrono>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>

namespace ephemeralnet {

class Node {
public:
    Node(PeerId id, Config config = {});

    void announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl);
    void store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl);
    std::optional<ChunkData> fetch_chunk(const ChunkId& chunk_id);

    void register_shared_secret(const PeerId& peer_id, const crypto::Key& shared_secret);
    std::optional<std::array<std::uint8_t, 32>> session_key(const PeerId& peer_id) const;
    std::optional<std::array<std::uint8_t, 32>> rotate_session_key(const PeerId& peer_id);

    std::uint32_t public_identity() const noexcept { return identity_public_; }
    bool perform_handshake(const PeerId& peer_id, std::uint32_t remote_public_key);
    int reputation_score(const PeerId& peer_id) const;
    std::optional<bool> last_handshake_success(const PeerId& peer_id) const;

    struct TtlAuditReport {
        std::vector<std::string> expired_local_chunks;
        std::vector<std::string> expired_locator_chunks;
        std::vector<std::string> expired_contacts;
        std::vector<std::string> missing_announcements;
        std::vector<std::string> orphan_announcements;

        bool healthy() const {
            return expired_local_chunks.empty() && expired_locator_chunks.empty() && expired_contacts.empty()
                && missing_announcements.empty() && orphan_announcements.empty();
        }
    };

    [[nodiscard]] TtlAuditReport audit_ttl() const;


    void tick();

    const PeerId& id() const noexcept { return id_; }
    Config& config() noexcept { return config_; }
    const Config& config() const noexcept { return config_; }

private:
    PeerId id_{};
    Config config_{};
    ChunkStore chunk_store_;
    KademliaTable dht_;
    network::KeyManager key_manager_;
    network::ReputationManager reputation_;
    SessionManager sessions_;
    crypto::CryptoManager crypto_;
    std::uint32_t identity_scalar_{0};
    std::uint32_t identity_public_{0};
    struct HandshakeRecord {
        std::chrono::steady_clock::time_point last_attempt{};
        bool success{false};
        std::uint32_t remote_public{0};
    };
    std::unordered_map<std::string, HandshakeRecord> handshake_state_;
    std::chrono::steady_clock::time_point last_cleanup_{};
};

}  
