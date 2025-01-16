#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/network/KeyExchange.hpp"

#include <algorithm>
#include <array>
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

}  // namespace

Node::Node(PeerId id, Config config)
        : id_(id),
            config_(config),
            chunk_store_(config),
            dht_(id, config),
            key_manager_(config.announce_interval),
            reputation_(),
            sessions_(),
            crypto_(),
            identity_scalar_(generate_identity_scalar(config)),
            identity_public_(network::KeyExchange::compute_public(identity_scalar_)),
            handshake_state_(),
            last_cleanup_(std::chrono::steady_clock::now()) {}

void Node::announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl) {
    PeerContact self_contact{.id = id_, .address = peer_id_to_string(id_), .expires_at = std::chrono::steady_clock::now() + ttl};
    dht_.add_contact(chunk_id, self_contact, ttl);
}

void Node::store_chunk(const ChunkId& chunk_id, ChunkData data, std::chrono::seconds ttl) {
    auto sealed = crypto_.encrypt(chunk_id, data);
    chunk_store_.put(chunk_id,
        std::move(sealed.data),
        ttl,
        sealed.nonce.bytes,
        sealed.encrypted);
    announce_chunk(chunk_id, ttl);
}

std::optional<ChunkData> Node::fetch_chunk(const ChunkId& chunk_id) {
    if (auto record = chunk_store_.get_record(chunk_id)) {
        if (record->encrypted) {
            const crypto::Nonce nonce{record->nonce};
            const std::span<const std::uint8_t> ciphertext{record->data};
            const auto maybe_plain = crypto_.decrypt(chunk_id, ciphertext, nonce);
            return maybe_plain;
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
}

std::optional<std::array<std::uint8_t, 32>> Node::session_key(const PeerId& peer_id) const {
    return key_manager_.current_key(peer_id);
}

std::optional<std::array<std::uint8_t, 32>> Node::rotate_session_key(const PeerId& peer_id) {
    return key_manager_.rotate_if_needed(peer_id);
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
        chunk_store_.sweep_expired();
        dht_.sweep_expired();
        last_cleanup_ = now;
    }
}

}  
