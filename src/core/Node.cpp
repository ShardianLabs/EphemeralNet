#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/network/KeyExchange.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"
#include "ephemeralnet/crypto/Shamir.hpp"
#include "ephemeralnet/protocol/Message.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <iostream>
#include <random>
#include <span>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>

namespace ephemeralnet {

namespace {

std::uint32_t generate_identity_scalar(const Config& config) {
    std::mt19937 generator;
    if (config.identity_seed.has_value()) {
        generator.seed(*config.identity_seed);
    } else {
        std::random_device rd;
        generator.seed(rd());
    }

    std::uniform_int_distribution<std::uint32_t> distribution(2u, network::KeyExchange::kPrime - 2u);
    return distribution(generator);
}

std::array<std::uint8_t, 8> make_handshake_material(std::uint32_t local_public,
                                                     std::uint32_t remote_public) {
    std::array<std::uint32_t, 2> ordered{local_public, remote_public};
    std::sort(ordered.begin(), ordered.end());

    std::array<std::uint8_t, 8> material{};
    for (std::size_t index = 0; index < ordered.size(); ++index) {
        const auto value = ordered[index];
        for (std::size_t byte = 0; byte < 4; ++byte) {
            const auto shift = static_cast<std::uint32_t>((3 - byte) * 8);
            material[index * 4 + byte] = static_cast<std::uint8_t>((value >> shift) & 0xFFu);
        }
    }
    return material;
}

std::optional<std::chrono::seconds> manifest_ttl(const protocol::Manifest& manifest) {
    const auto now = std::chrono::system_clock::now();
    if (manifest.expires_at <= now) {
        return std::nullopt;
    }

    auto ttl = std::chrono::duration_cast<std::chrono::seconds>(manifest.expires_at - now);
    if (ttl <= std::chrono::seconds{0}) {
        ttl = std::chrono::seconds{1};
    }
    return ttl;
}

bool validate_shards(const protocol::Manifest& manifest) {
    return manifest.threshold > 0 && manifest.shards.size() >= manifest.threshold;
}

}  // namespace

Node::Node(PeerId id, Config config)
        : id_(id),
            config_(config),
            chunk_store_(config),
            dht_(id, config),
            key_manager_(config.announce_interval),
            reputation_(),
            sessions_(id),
            nat_manager_(config),
            swarm_(config),
            crypto_(),
            identity_scalar_(generate_identity_scalar(config)),
            identity_public_(network::KeyExchange::compute_public(identity_scalar_)),
            handshake_state_(),
            cleanup_notifications_(),
            last_cleanup_(std::chrono::steady_clock::now()) {
        for (const auto& entry : config_.bootstrap_nodes) {
            bootstrap_nodes_[peer_id_to_string(entry.id)] = entry;
        }
        initialize_transport_handler();
        seed_bootstrap_contacts();
        attempt_bootstrap_handshakes();
}

Node::~Node() {
        stop_transport();
}

void Node::announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl) {
    PeerContact self_contact{.id = id_, .address = peer_id_to_string(id_), .expires_at = std::chrono::steady_clock::now() + ttl};
    dht_.add_contact(chunk_id, self_contact, ttl);
}

protocol::Manifest Node::store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl) {
    const auto threshold = std::max<std::uint8_t>(std::uint8_t{1}, config_.shard_threshold);
    const auto total_shares = std::max(threshold, config_.shard_total);

    const auto effective_ttl = ttl.count() > 0 ? ttl : config_.default_chunk_ttl;
    const auto sanitized_ttl = std::max(effective_ttl, std::chrono::seconds{1});

    const auto chunk_hash = crypto::Sha256::digest(std::span<const std::uint8_t>{data});

    const auto chunk_key = crypto::CryptoManager::generate_key();
    auto sealed = crypto::CryptoManager::encrypt_with_key(chunk_key, chunk_id, data);

    chunk_store_.put(chunk_id,
        std::move(sealed.data),
        sanitized_ttl,
        sealed.nonce.bytes,
        sealed.encrypted);

    const auto shares = crypto::Shamir::split(chunk_key.bytes, threshold, total_shares);
    std::vector<protocol::KeyShard> protocol_shards;
    protocol_shards.reserve(shares.size());
    for (const auto& share : shares) {
        protocol::KeyShard key_shard{};
        key_shard.index = share.index;
        key_shard.value = share.value;
        protocol_shards.push_back(key_shard);
    }

    protocol::Manifest manifest{};
    manifest.chunk_id = chunk_id;
    manifest.chunk_hash = chunk_hash;
    manifest.nonce = sealed.nonce;
    manifest.threshold = threshold;
    manifest.total_shares = total_shares;
    manifest.expires_at = std::chrono::system_clock::now() + sanitized_ttl;
    manifest.shards = protocol_shards;

    manifest_cache_[chunk_id_to_string(chunk_id)] = manifest;
    dht_.publish_shards(chunk_id, manifest.shards, manifest.threshold, manifest.total_shares, sanitized_ttl);
    announce_chunk(chunk_id, sanitized_ttl);
    update_swarm_plan(manifest);

    return manifest;
}

bool Node::ingest_manifest(const std::string& manifest_uri) {
    protocol::Manifest manifest{};
    try {
        manifest = protocol::decode_manifest(manifest_uri);
    } catch (const std::exception&) {
        return false;
    }

    if (!validate_shards(manifest)) {
        return false;
    }

    const auto ttl = manifest_ttl(manifest);
    if (!ttl.has_value()) {
        return false;
    }

    manifest_cache_[chunk_id_to_string(manifest.chunk_id)] = manifest;
    dht_.publish_shards(manifest.chunk_id, manifest.shards, manifest.threshold, manifest.total_shares, *ttl);
    update_swarm_plan(manifest);
    return true;
}

std::optional<ChunkData> Node::receive_chunk(const std::string& manifest_uri, ChunkData ciphertext) {
    protocol::Manifest manifest{};
    try {
        manifest = protocol::decode_manifest(manifest_uri);
    } catch (const std::exception&) {
        return std::nullopt;
    }

    if (!validate_shards(manifest)) {
        return std::nullopt;
    }

    const auto ttl = manifest_ttl(manifest);
    if (!ttl.has_value()) {
        return std::nullopt;
    }

    std::vector<crypto::ShamirShare> shares;
    shares.reserve(manifest.shards.size());
    for (const auto& shard : manifest.shards) {
        crypto::ShamirShare share{};
        share.index = shard.index;
        share.value = shard.value;
        shares.push_back(share);
    }

    crypto::Key chunk_key{};
    chunk_key.bytes = crypto::Shamir::combine(shares, manifest.threshold);

    const auto plaintext = crypto::CryptoManager::decrypt_with_key(chunk_key,
                                                                  manifest.chunk_id,
                                                                  std::span<const std::uint8_t>(ciphertext),
                                                                  manifest.nonce);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }

    const auto hash = crypto::Sha256::digest(std::span<const std::uint8_t>(*plaintext));
    if (hash != manifest.chunk_hash) {
        return std::nullopt;
    }

    manifest_cache_[chunk_id_to_string(manifest.chunk_id)] = manifest;
    dht_.publish_shards(manifest.chunk_id, manifest.shards, manifest.threshold, manifest.total_shares, *ttl);
    announce_chunk(manifest.chunk_id, *ttl);
    chunk_store_.put(manifest.chunk_id,
                     std::move(ciphertext),
                     *ttl,
                     manifest.nonce.bytes,
                     true);

    return plaintext;
}

std::optional<ChunkRecord> Node::export_chunk_record(const ChunkId& chunk_id) {
    return chunk_store_.get_record(chunk_id);
}

bool Node::request_chunk(const PeerId& peer_id,
                         const std::string& host,
                         std::uint16_t port,
                         const std::string& manifest_uri) {
    if (!ingest_manifest(manifest_uri)) {
        return false;
    }

    std::string resolved_host = host;
    std::uint16_t resolved_port = port;
    const auto peer_key = peer_id_to_string(peer_id);
    const auto bootstrap_it = bootstrap_nodes_.find(peer_key);
    if (bootstrap_it != bootstrap_nodes_.end()) {
        if (resolved_host.empty()) {
            resolved_host = bootstrap_it->second.host;
        }
        if (resolved_port == 0) {
            resolved_port = bootstrap_it->second.port;
        }
    }

    if (resolved_host.empty() || resolved_port == 0) {
        return false;
    }

    protocol::Manifest manifest{};
    try {
        manifest = protocol::decode_manifest(manifest_uri);
    } catch (const std::exception&) {
        return false;
    }

    manifest_cache_[chunk_id_to_string(manifest.chunk_id)] = manifest;

    ensure_bootstrap_handshake(peer_id);

    if (!connect_peer(peer_id, resolved_host, resolved_port)) {
        return false;
    }

    const auto key = session_shared_key(peer_id);
    if (!key.has_value()) {
        return false;
    }

    protocol::Message message{};
    message.version = 1;
    message.type = protocol::MessageType::Request;
    message.payload = protocol::RequestPayload{manifest.chunk_id, id_};

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    auto encoded = protocol::encode_signed(message, key_span);
    const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
    return send_secure(peer_id, payload_span);
}

std::optional<ChunkData> Node::fetch_chunk(const ChunkId& chunk_id) {
    if (auto record = chunk_store_.get_record(chunk_id)) {
        if (record->encrypted) {
            const auto shard_info = dht_.shard_record(chunk_id);
            if (!shard_info.has_value() || shard_info->threshold == 0 || shard_info->shards.size() < shard_info->threshold) {
                return std::nullopt;
            }

            std::vector<crypto::ShamirShare> shares;
            shares.reserve(shard_info->shards.size());
            for (const auto& shard : shard_info->shards) {
                crypto::ShamirShare share{};
                share.index = shard.index;
                share.value = shard.value;
                shares.push_back(share);
            }

            const auto secret_bytes = crypto::Shamir::combine(shares, shard_info->threshold);
            crypto::Key chunk_key{};
            chunk_key.bytes = secret_bytes;

            const crypto::Nonce nonce{record->nonce};
            const std::span<const std::uint8_t> ciphertext{record->data};
            return crypto::CryptoManager::decrypt_with_key(chunk_key, chunk_id, ciphertext, nonce);
        }
        return record->data;
    }

    const auto providers = dht_.find_providers(chunk_id);
    if (providers.empty()) {
        std::cout << "[Node] No providers available for chunk " << chunk_id_to_string(chunk_id) << "\n";
        return std::nullopt;
    }

    std::cout << "[Node] Providers known for chunk " << chunk_id_to_string(chunk_id) << ": " << providers.size() << "\n";
    return std::nullopt;
}

void Node::register_shared_secret(const PeerId& peer_id, const crypto::Key& shared_secret) {
    key_manager_.register_session(peer_id, shared_secret);
    if (const auto key = key_manager_.current_key(peer_id)) {
        sessions_.register_peer_key(peer_id, *key);
    }
}

std::optional<std::array<std::uint8_t, 32>> Node::session_key(const PeerId& peer_id) const {
    return key_manager_.current_key(peer_id);
}

std::optional<std::array<std::uint8_t, 32>> Node::rotate_session_key(const PeerId& peer_id) {
    if (const auto rotated = key_manager_.rotate_if_needed(peer_id)) {
        sessions_.register_peer_key(peer_id, *rotated);
        return rotated;
    }
    return std::nullopt;
}

std::optional<SwarmDistributionPlan> Node::swarm_plan(const ChunkId& chunk_id) const {
    const auto it = swarm_plans_.find(chunk_id_to_string(chunk_id));
    if (it == swarm_plans_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool Node::perform_handshake(const PeerId& peer_id, std::uint32_t remote_public_key) {
    const auto now = std::chrono::steady_clock::now();
    const auto key = peer_id_to_string(peer_id);

    const auto existing = handshake_state_.find(key);
    if (existing != handshake_state_.end()) {
        const auto elapsed = now - existing->second.last_attempt;
        if (elapsed < config_.handshake_cooldown) {
            return existing->second.success;
        }
    }

    HandshakeRecord record{};
    record.last_attempt = now;
    record.remote_public = remote_public_key;

    if (!network::KeyExchange::validate_public(remote_public_key)) {
        record.success = false;
        handshake_state_[key] = record;
        reputation_.record_failure(peer_id);
        return false;
    }

    const auto shared_secret = network::KeyExchange::derive_shared_secret(identity_scalar_, remote_public_key);
    const auto material = make_handshake_material(identity_public_, remote_public_key);
    key_manager_.register_session_with_material(peer_id, shared_secret, material, now);
    if (const auto key = key_manager_.current_key(peer_id)) {
        sessions_.register_peer_key(peer_id, *key);
    }

    reputation_.record_success(peer_id);
    record.success = true;
    handshake_state_[key] = record;
    return true;
}

int Node::reputation_score(const PeerId& peer_id) const {
    return reputation_.score(peer_id);
}

std::optional<bool> Node::last_handshake_success(const PeerId& peer_id) const {
    const auto it = handshake_state_.find(peer_id_to_string(peer_id));
    if (it == handshake_state_.end()) {
        return std::nullopt;
    }
    return it->second.success;
}

std::vector<std::string> Node::drain_cleanup_notifications() {
    std::vector<std::string> notifications;
    notifications.swap(cleanup_notifications_);
    return notifications;
}

Node::TtlAuditReport Node::audit_ttl() const {
    TtlAuditReport report{};
    const auto now = std::chrono::steady_clock::now();

    const auto local_entries = chunk_store_.snapshot();
    std::unordered_set<std::string> local_keys;
    local_keys.reserve(local_entries.size());
    for (const auto& entry : local_entries) {
        local_keys.insert(entry.key);
        if (now >= entry.expires_at) {
            report.expired_local_chunks.push_back(entry.key);
        }
    }

    const auto locators = dht_.snapshot_locators();
    std::unordered_map<std::string, bool> locator_has_self;
    locator_has_self.reserve(locators.size());

    for (const auto& locator : locators) {
        const auto key = chunk_id_to_string(locator.id);
        bool has_self = false;

        if (now >= locator.expires_at) {
            report.expired_locator_chunks.push_back(key);
        }

        for (const auto& holder : locator.holders) {
            if (now >= holder.expires_at) {
                report.expired_contacts.push_back(key + "/" + peer_id_to_string(holder.id));
            }
            if (holder.id == id_) {
                has_self = true;
            }
        }

        locator_has_self[key] = has_self;

        if (has_self && !local_keys.contains(key)) {
            report.orphan_announcements.push_back(key);
        }
    }

    for (const auto& key : local_keys) {
        const auto it = locator_has_self.find(key);
        const bool has_self = it != locator_has_self.end() && it->second;
        if (!has_self) {
            report.missing_announcements.push_back(key);
        }
    }

    return report;
}

void Node::tick() {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = now - last_cleanup_;
    if (elapsed >= config_.cleanup_interval) {
        const auto expired_chunks = chunk_store_.sweep_expired();
        for (const auto& chunk_id : expired_chunks) {
            const auto key = chunk_id_to_string(chunk_id);
            cleanup_notifications_.push_back(key);
            dht_.withdraw_contact(chunk_id, id_);
        }
        dht_.sweep_expired();
        last_cleanup_ = now;
    }
    rebalance_swarm_plans();
}

void Node::start_transport(std::uint16_t port) {
    sessions_.start(port);
    nat_status_ = nat_manager_.coordinate("0.0.0.0", sessions_.listening_port());
}

void Node::stop_transport() {
    sessions_.stop();
}

std::uint16_t Node::transport_port() const {
    return sessions_.listening_port();
}

void Node::set_message_handler(network::SessionManager::MessageHandler handler) {
    external_handler_ = std::move(handler);
}

bool Node::connect_peer(const PeerId& peer_id, const std::string& host, std::uint16_t port) {
    return sessions_.connect(peer_id, host, port);
}

bool Node::send_secure(const PeerId& peer_id, std::span<const std::uint8_t> payload) {
    const auto key = key_manager_.current_key(peer_id);
    if (!key.has_value()) {
        return false;
    }
    sessions_.register_peer_key(peer_id, *key);
    return sessions_.send(peer_id, payload);
}

void Node::register_peer_contact(PeerContact contact) {
    dht_.register_peer(std::move(contact));
}

void Node::initialize_transport_handler() {
    sessions_.set_message_handler([this](const network::TransportMessage& message) {
        handle_transport_message(message);
        if (external_handler_) {
            external_handler_(message);
        }
    });
}

void Node::handle_transport_message(const network::TransportMessage& message) {
    const auto key = session_shared_key(message.peer_id);
    if (!key.has_value()) {
        return;
    }

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    const auto decoded = protocol::decode_signed(message.payload, key_span);
    if (!decoded.has_value()) {
        return;
    }

    handle_protocol_message(*decoded, message);
}

void Node::handle_protocol_message(const protocol::Message& message, const network::TransportMessage& transport) {
    switch (message.type) {
        case protocol::MessageType::Request: {
            if (const auto* payload = std::get_if<protocol::RequestPayload>(&message.payload)) {
                handle_request(*payload, transport.peer_id);
            }
            break;
        }
        case protocol::MessageType::Chunk: {
            if (const auto* payload = std::get_if<protocol::ChunkPayload>(&message.payload)) {
                handle_chunk(*payload, transport.peer_id);
            }
            break;
        }
        case protocol::MessageType::Acknowledge: {
            if (const auto* payload = std::get_if<protocol::AcknowledgePayload>(&message.payload)) {
                handle_acknowledge(*payload, transport.peer_id);
            }
            break;
        }
        case protocol::MessageType::Announce:
        default:
            break;
    }
}

void Node::handle_request(const protocol::RequestPayload& payload, const PeerId& sender) {
    const auto key = session_shared_key(sender);
    if (!key.has_value()) {
        return;
    }

    const auto manifest = manifest_for_chunk(payload.chunk_id);
    const auto record = chunk_store_.get_record(payload.chunk_id);
    bool accepted = manifest.has_value() && record.has_value();
    std::chrono::seconds ttl{0};
    if (manifest.has_value()) {
        const auto ttl_opt = manifest_ttl(*manifest);
        if (!ttl_opt.has_value()) {
            accepted = false;
        } else {
            ttl = *ttl_opt;
        }
    }

    if (accepted) {
        protocol::Message response{};
        response.version = 1;
        response.type = protocol::MessageType::Chunk;
        protocol::ChunkPayload chunk_payload{};
        chunk_payload.chunk_id = payload.chunk_id;
        chunk_payload.data = record->data;
        chunk_payload.ttl = ttl;
        response.payload = std::move(chunk_payload);

        const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
        auto encoded = protocol::encode_signed(response, key_span);
        const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
        send_secure(sender, payload_span);
    } else {
        protocol::Message response{};
        response.version = 1;
        response.type = protocol::MessageType::Acknowledge;
        protocol::AcknowledgePayload ack{};
        ack.chunk_id = payload.chunk_id;
        ack.peer_id = id_;
        ack.accepted = false;
        response.payload = ack;

        const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
        auto encoded = protocol::encode_signed(response, key_span);
        const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
        send_secure(sender, payload_span);
    }
}

void Node::handle_chunk(const protocol::ChunkPayload& payload, const PeerId& sender) {
    const auto key = session_shared_key(sender);
    if (!key.has_value()) {
        return;
    }

    const auto manifest = manifest_for_chunk(payload.chunk_id);
    bool accepted = false;
    if (manifest.has_value()) {
        auto ciphertext = payload.data;
        const auto manifest_uri = protocol::encode_manifest(*manifest);
        const auto plaintext = receive_chunk(manifest_uri, std::move(ciphertext));
        accepted = plaintext.has_value();
    }

    protocol::Message ack_message{};
    ack_message.version = 1;
    ack_message.type = protocol::MessageType::Acknowledge;
    protocol::AcknowledgePayload ack{};
    ack.chunk_id = payload.chunk_id;
    ack.peer_id = id_;
    ack.accepted = accepted;
    ack_message.payload = ack;

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    auto encoded = protocol::encode_signed(ack_message, key_span);
    const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
    send_secure(sender, payload_span);
}

void Node::handle_acknowledge(const protocol::AcknowledgePayload& payload, const PeerId& sender) {
    if (payload.accepted) {
        reputation_.record_success(sender);
    } else {
        reputation_.record_failure(sender);
    }
}

std::optional<std::array<std::uint8_t, 32>> Node::session_shared_key(const PeerId& peer_id) const {
    return key_manager_.current_key(peer_id);
}

std::optional<protocol::Manifest> Node::manifest_for_chunk(const ChunkId& chunk_id) const {
    const auto key = chunk_id_to_string(chunk_id);
    const auto it = manifest_cache_.find(key);
    if (it == manifest_cache_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void Node::update_swarm_plan(const protocol::Manifest& manifest) {
    const auto key = chunk_id_to_string(manifest.chunk_id);
    auto plan = swarm_.compute_plan(manifest.chunk_id, manifest, dht_, id_);
    if (plan.assignments.empty()) {
        plan.diagnostics.emplace_back("Swarm coordinator produced no assignments.");
    }
    swarm_plans_[key] = std::move(plan);
}

void Node::rebalance_swarm_plans() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> stale_keys;
    stale_keys.reserve(swarm_plans_.size());

    for (auto& [key, plan] : swarm_plans_) {
        if (now < plan.next_rebalance) {
            continue;
        }

        const auto manifest_it = manifest_cache_.find(key);
        if (manifest_it == manifest_cache_.end()) {
            stale_keys.push_back(key);
            continue;
        }

        auto refreshed = swarm_.compute_plan(manifest_it->second.chunk_id, manifest_it->second, dht_, id_);
        refreshed.diagnostics.emplace_back("Plan recomputed after rebalance interval.");
        plan = std::move(refreshed);
    }

    for (const auto& key : stale_keys) {
        swarm_plans_.erase(key);
    }
}

void Node::seed_bootstrap_contacts() {
    const auto now = std::chrono::steady_clock::now();
    for (const auto& entry : config_.bootstrap_nodes) {
        PeerContact contact{};
        contact.id = entry.id;
        contact.address = entry.host + ":" + std::to_string(entry.port);
        contact.expires_at = now + config_.bootstrap_contact_ttl;
        dht_.register_peer(contact);
    }
}

void Node::attempt_bootstrap_handshakes() {
    for (const auto& entry : config_.bootstrap_nodes) {
        ensure_bootstrap_handshake(entry.id);
    }
}

void Node::ensure_bootstrap_handshake(const PeerId& peer_id) {
    const auto key = peer_id_to_string(peer_id);
    const auto it = bootstrap_nodes_.find(key);
    if (it == bootstrap_nodes_.end()) {
        return;
    }

    if (!it->second.public_identity.has_value()) {
        return;
    }

    perform_handshake(peer_id, *it->second.public_identity);
}

}  
