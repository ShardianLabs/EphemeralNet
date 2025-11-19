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
#include <deque>
#include <chrono>
#include <cstddef>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <atomic>
#include <memory>

namespace ephemeralnet {

namespace test {
class NodeTestAccess;
}

namespace network {
class RelayClient;
}

class Node {
public:
    Node(PeerId id, Config config = {});
    ~Node();

    void announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl);
    protocol::Manifest store_chunk(const ChunkId& chunk_id,
                                   ChunkData data,
                                   std::chrono::seconds ttl,
                                   std::optional<std::string> original_name = std::nullopt);
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
    bool perform_handshake(const PeerId& peer_id,
                           std::uint32_t remote_public_key,
                           std::uint64_t remote_work_nonce);
    std::optional<std::uint64_t> generate_handshake_work(const PeerId& peer_id) const;
    int reputation_score(const PeerId& peer_id) const;
    std::optional<bool> last_handshake_success(const PeerId& peer_id) const;

    struct PowStatistics {
        std::uint64_t handshake_validations_success{0};
        std::uint64_t handshake_validations_failure{0};
        std::uint64_t announce_validations_success{0};
        std::uint64_t announce_validations_failure{0};
    };

    PowStatistics pow_statistics() const;

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

    struct ConnectivityReport {
        std::string nat_type;
        std::optional<std::string> public_endpoint;
        std::vector<std::pair<std::string, bool>> bootstrap_status;
        std::size_t active_peers{0};
    };

    ConnectivityReport diagnose_connectivity();

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

    struct ControlEndpoint {
        std::string host;
        std::uint16_t port{0};
        bool manual{false};
    };

    PeerId id_{};
    Config config_{};
    ChunkStore chunk_store_;
    KademliaTable dht_;
    network::KeyManager key_manager_;
    network::ReputationManager reputation_;
    network::SessionManager sessions_;
    network::NatTraversalManager nat_manager_;
    std::unique_ptr<network::RelayClient> relay_client_;
    std::optional<network::NatTraversalResult> nat_status_;
    SwarmCoordinator swarm_;
    crypto::CryptoManager crypto_;
    std::uint32_t identity_scalar_{0};
    std::uint32_t identity_public_{0};
    struct HandshakeRecord {
        std::chrono::steady_clock::time_point last_attempt{};
        bool success{false};
        std::uint32_t remote_public{0};
        std::uint64_t remote_pow_nonce{0};
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
        std::size_t provider_count{std::numeric_limits<std::size_t>::max()};
        std::chrono::steady_clock::time_point last_availability_check{};
    };
    struct PendingUploadRequest {
        ChunkId chunk_id{};
        PeerId peer_id{};
        std::chrono::steady_clock::time_point enqueue_time{};
        std::size_t payload_size{0};
    };
    struct ActiveUploadState {
        ChunkId chunk_id{};
        PeerId peer_id{};
        std::chrono::steady_clock::time_point started_at{};
        std::size_t payload_size{0};
    };
    struct SwarmRoleLedger {
        std::unordered_set<std::string> seeds;
        std::unordered_set<std::string> leechers;
        bool self_seed{false};
        bool self_leecher{false};
    };
    std::unordered_map<std::string, HandshakeRecord> handshake_state_;
    std::vector<std::string> cleanup_notifications_;
    std::chrono::steady_clock::time_point last_cleanup_{};
    std::unordered_map<std::string, protocol::Manifest> manifest_cache_;
    network::SessionManager::MessageHandler external_handler_{};
    std::unordered_map<std::string, Config::BootstrapNode> bootstrap_nodes_;
    std::unordered_map<std::string, SwarmDistributionPlan> swarm_plans_;
    std::unordered_map<std::string, PendingFetchState> pending_chunk_fetches_;
    std::unordered_map<std::string, std::size_t> active_peer_requests_;
    std::deque<PendingUploadRequest> pending_uploads_;
    std::unordered_map<std::string, ActiveUploadState> active_uploads_;
    std::unordered_map<std::string, std::size_t> active_uploads_per_peer_;
    std::chrono::steady_clock::time_point last_upload_rotation_{};
    std::atomic<std::uint64_t> total_completed_uploads_{0};
    std::atomic<std::size_t> peak_active_uploads_{0};
    std::unordered_map<std::string, SwarmRoleLedger> swarm_roles_;
    std::unordered_map<std::string, std::uint8_t> peer_message_versions_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> peer_announce_history_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> peer_announce_failure_history_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> peer_announce_lockouts_;
    mutable std::recursive_mutex scheduler_mutex_;
    struct PowCounters {
        std::atomic<std::uint64_t> handshake_success{0};
        std::atomic<std::uint64_t> handshake_failure{0};
        std::atomic<std::uint64_t> announce_success{0};
        std::atomic<std::uint64_t> announce_failure{0};
    } mutable pow_counters_{};

    void initialize_transport_handler();
    void handle_transport_message(const network::TransportMessage& message);
    void handle_protocol_message(const protocol::Message& message, const network::TransportMessage& transport);
    std::optional<network::SessionManager::HandshakeAcceptance> handle_transport_handshake(
        const PeerId& peer_id,
        const protocol::TransportHandshakePayload& payload);
    void handle_request(const protocol::RequestPayload& payload, const PeerId& sender);
    void handle_chunk(const protocol::ChunkPayload& payload, const PeerId& sender);
    void handle_acknowledge(const protocol::AcknowledgePayload& payload, const PeerId& sender);
    void handle_announce(const protocol::AnnouncePayload& payload,
                         const PeerId& sender,
                         std::uint8_t message_version);
    std::optional<std::array<std::uint8_t, 32>> session_shared_key(const PeerId& peer_id) const;
    std::optional<protocol::Manifest> manifest_for_chunk(const ChunkId& chunk_id) const;
    void seed_bootstrap_contacts();
    void attempt_bootstrap_handshakes();
    void ensure_bootstrap_handshake(const PeerId& peer_id);
    std::optional<network::SessionManager::OutboundHandshake> build_transport_handshake(const PeerId& peer_id) const;
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
    bool can_dispatch_fetch(const PendingFetchState& state) const;
    void note_dispatch_start(const PendingFetchState& state);
    void note_dispatch_end(const PendingFetchState& state);
    void clear_pending_fetch(const std::string& key);
    void refresh_provider_count(PendingFetchState& state,
                                std::chrono::steady_clock::time_point now,
                                bool force);
    std::size_t count_known_providers(const ChunkId& chunk_id);
    void enqueue_upload_request(const protocol::RequestPayload& payload,
                                const PeerId& sender,
                                std::size_t payload_size);
    void process_pending_uploads();
    bool can_accept_more_uploads() const;
    bool can_dispatch_upload(const PeerId& peer_id) const;
    bool dispatch_upload(const PendingUploadRequest& request);
    void note_upload_start(const PendingUploadRequest& request,
                           std::size_t payload_size);
    void note_upload_end(const PeerId& peer_id,
                         const ChunkId& chunk_id,
                         bool success);
    std::string make_upload_key(const PeerId& peer_id, const ChunkId& chunk_id) const;
    void prune_stale_uploads(std::chrono::steady_clock::time_point now);
    void send_negative_ack(const PeerId& peer_id, const ChunkId& chunk_id);
    SwarmRoleLedger& ensure_swarm_ledger(const ChunkId& chunk_id);
    [[nodiscard]] const SwarmRoleLedger* find_swarm_ledger(const ChunkId& chunk_id) const;
    void retire_swarm_ledger(const ChunkId& chunk_id);
    void note_local_seed(const ChunkId& chunk_id);
    void note_local_leecher(const ChunkId& chunk_id);
    void note_peer_seed(const ChunkId& chunk_id, const PeerId& peer_id);
    void note_peer_leecher(const ChunkId& chunk_id, const PeerId& peer_id);
    std::uint8_t preferred_message_version() const;
    std::uint8_t outbound_message_version_for(const PeerId& peer_id) const;
    bool is_message_version_supported(std::uint8_t version) const;
    void note_peer_message_version(const PeerId& peer_id, std::uint8_t version);
    bool register_incoming_announce(const PeerId& peer_id, std::chrono::steady_clock::time_point now);
    void rotate_session_keys(std::chrono::steady_clock::time_point now);
    SwarmPeerLoadMap gather_peer_load() const;
    bool apply_announce_pow(protocol::AnnouncePayload& payload) const;
    bool verify_announce_pow(const protocol::AnnouncePayload& payload, std::uint8_t message_version) const;
    bool announce_sender_locked(const PeerId& peer_id, std::chrono::steady_clock::time_point now);
    void record_announce_failure(const PeerId& peer_id, std::chrono::steady_clock::time_point now);
    void clear_announce_failures(const PeerId& peer_id);
    std::vector<ControlEndpoint> preferred_control_endpoints() const;
    void refresh_advertised_endpoints();
};

}
