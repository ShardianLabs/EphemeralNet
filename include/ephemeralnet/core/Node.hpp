#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/CryptoManager.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "ephemeralnet/network/KeyManager.hpp"
#include "ephemeralnet/network/ReputationManager.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/network/NatTraversal.hpp"
#include "ephemeralnet/core/SwarmCoordinator.hpp"
#include "ephemeralnet/protocol/Message.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/storage/ChunkStore.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace ephemeralnet {

namespace test {
class NodeTestAccess;
}

class Node {
public:
    Node(PeerId id, Config config = {});
    ~Node();

    void announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl);
    protocol::Manifest store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl);
    bool ingest_manifest(const std::string& manifest_uri);
    std::optional<ChunkData> receive_chunk(const std::string& manifest_uri, ChunkData ciphertext);
    std::optional<ChunkRecord> export_chunk_record(const ChunkId& chunk_id);
    bool request_chunk(const PeerId& peer_id,
                       const std::string& host,
                       std::uint16_t port,
                       const std::string& manifest_uri);
    std::optional<ChunkData> fetch_chunk(const ChunkId& chunk_id);

    void register_shared_secret(const PeerId& peer_id, const crypto::Key& shared_secret);
    std::optional<std::array<std::uint8_t, 32>> session_key(const PeerId& peer_id) const;
    std::optional<std::array<std::uint8_t, 32>> rotate_session_key(const PeerId& peer_id);
    std::optional<network::NatTraversalResult> nat_status() const { return nat_status_; }
    std::optional<SwarmDistributionPlan> swarm_plan(const ChunkId& chunk_id) const;

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
    std::vector<std::string> drain_cleanup_notifications();

    void start_transport(std::uint16_t port = 0);
    void stop_transport();
    std::uint16_t transport_port() const;
    void set_message_handler(network::SessionManager::MessageHandler handler);
    bool connect_peer(const PeerId& peer_id, const std::string& host, std::uint16_t port);
    bool send_secure(const PeerId& peer_id, std::span<const std::uint8_t> payload);
    void register_peer_contact(PeerContact contact);
    std::vector<ChunkStore::SnapshotEntry> stored_chunks() const;
    std::size_t connected_peer_count() const;


    void tick();

    const PeerId& id() const noexcept { return id_; }
    Config& config() noexcept { return config_; }
    const Config& config() const noexcept { return config_; }

private:
    friend class test::NodeTestAccess;

    PeerId id_{};
    Config config_{};
    ChunkStore chunk_store_;
    KademliaTable dht_;
    network::KeyManager key_manager_;
    network::ReputationManager reputation_;
    network::SessionManager sessions_;
    network::NatTraversalManager nat_manager_;
    std::optional<network::NatTraversalResult> nat_status_;
    SwarmCoordinator swarm_;
    crypto::CryptoManager crypto_;
    std::uint32_t identity_scalar_{0};
    std::uint32_t identity_public_{0};
    struct HandshakeRecord {
        std::chrono::steady_clock::time_point last_attempt{};
        bool success{false};
        std::uint32_t remote_public{0};
    };
    struct PendingFetchState {
        ChunkId chunk_id{};
        PeerId peer_id{};
        std::string endpoint;
        std::string manifest_uri;
        std::chrono::steady_clock::time_point next_attempt{};
        std::size_t attempts{0};
        std::chrono::system_clock::time_point manifest_expires{};
        std::chrono::steady_clock::time_point enqueue_time{};
        std::chrono::steady_clock::time_point last_dispatch{};
        bool in_flight{false};
    };
    std::unordered_map<std::string, HandshakeRecord> handshake_state_;
    std::vector<std::string> cleanup_notifications_;
    std::chrono::steady_clock::time_point last_cleanup_{};
    std::unordered_map<std::string, protocol::Manifest> manifest_cache_;
    network::SessionManager::MessageHandler external_handler_{};
    std::unordered_map<std::string, Config::BootstrapNode> bootstrap_nodes_;
    std::unordered_map<std::string, SwarmDistributionPlan> swarm_plans_;
    std::unordered_map<std::string, PendingFetchState> pending_chunk_fetches_;

    void initialize_transport_handler();
    void handle_transport_message(const network::TransportMessage& message);
    void handle_protocol_message(const protocol::Message& message, const network::TransportMessage& transport);
    void handle_request(const protocol::RequestPayload& payload, const PeerId& sender);
    void handle_chunk(const protocol::ChunkPayload& payload, const PeerId& sender);
    void handle_acknowledge(const protocol::AcknowledgePayload& payload, const PeerId& sender);
    void handle_announce(const protocol::AnnouncePayload& payload, const PeerId& sender);
    std::optional<std::array<std::uint8_t, 32>> session_shared_key(const PeerId& peer_id) const;
    std::optional<protocol::Manifest> manifest_for_chunk(const ChunkId& chunk_id) const;
    void seed_bootstrap_contacts();
    void attempt_bootstrap_handshakes();
    void ensure_bootstrap_handshake(const PeerId& peer_id);
    void update_swarm_plan(const protocol::Manifest& manifest);
    void rebalance_swarm_plans();
    void broadcast_manifest(const protocol::Manifest& manifest);
    bool deliver_manifest(const protocol::Manifest& manifest,
                          const SwarmAssignment& assignment,
                          const std::string& manifest_uri,
                          std::chrono::seconds ttl,
                          const std::string& endpoint);
    std::string self_endpoint() const;
    void schedule_assigned_fetch(const protocol::AnnouncePayload& payload);
    bool send_chunk_request_direct(const ChunkId& chunk_id, const PeerId& peer_id);
    void process_pending_fetches();
    bool dispatch_pending_fetch(PendingFetchState& state);
    void schedule_next_fetch_attempt(PendingFetchState& state, bool success);
};

}  
