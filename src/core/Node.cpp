#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/network/KeyExchange.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"
#include "ephemeralnet/crypto/Shamir.hpp"
#include "ephemeralnet/protocol/Message.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <exception>
#include <filesystem>
#include <iostream>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

namespace ephemeralnet {

namespace {

using SchedulerLock = std::unique_lock<std::recursive_mutex>;

constexpr std::chrono::seconds kMinKeyRotationInterval{std::chrono::seconds{5}};
constexpr std::chrono::seconds kMaxKeyRotationInterval{std::chrono::hours{1}};
constexpr std::chrono::seconds kMinAllowedManifestTtl{std::chrono::seconds{1}};
constexpr std::chrono::seconds kMaxAllowedManifestTtl{std::chrono::hours{24}};
constexpr std::chrono::seconds kMinAnnounceInterval{std::chrono::seconds{1}};
constexpr std::chrono::seconds kMaxAnnounceWindow{std::chrono::hours{1}};
constexpr std::uint8_t kMaxAnnouncePowDifficulty{24};
constexpr std::uint64_t kMaxAnnouncePowAttempts{500'000};

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

std::chrono::seconds sanitize_key_rotation_interval(std::chrono::seconds interval) {
    if (interval <= std::chrono::seconds::zero()) {
        interval = kMinKeyRotationInterval;
    }
    if (interval < kMinKeyRotationInterval) {
        interval = kMinKeyRotationInterval;
    }
    if (interval > kMaxKeyRotationInterval) {
        interval = kMaxKeyRotationInterval;
    }
    return interval;
}

std::chrono::seconds sanitize_manifest_min(std::chrono::seconds value) {
    if (value < kMinAllowedManifestTtl) {
        return kMinAllowedManifestTtl;
    }
    if (value > kMaxAllowedManifestTtl) {
        return kMaxAllowedManifestTtl;
    }
    return value;
}

std::chrono::seconds sanitize_manifest_max(std::chrono::seconds value, std::chrono::seconds min_value) {
    if (value < min_value) {
        value = min_value;
    }
    if (value < kMinAllowedManifestTtl) {
        value = kMinAllowedManifestTtl;
    }
    if (value > kMaxAllowedManifestTtl) {
        value = kMaxAllowedManifestTtl;
    }
    return value;
}

std::chrono::seconds sanitize_announce_interval(std::chrono::seconds value) {
    if (value <= std::chrono::seconds::zero()) {
        return kMinAnnounceInterval;
    }
    if (value < kMinAnnounceInterval) {
        return kMinAnnounceInterval;
    }
    return value;
}

std::chrono::seconds sanitize_announce_window(std::chrono::seconds value) {
    if (value <= std::chrono::seconds::zero()) {
        return kMinAnnounceInterval;
    }
    if (value > kMaxAnnounceWindow) {
        return kMaxAnnounceWindow;
    }
    return value;
}

std::array<std::uint8_t, 8> to_big_endian_bytes(std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (int index = 0; index < 8; ++index) {
        const int shift = 56 - index * 8;
        bytes[index] = static_cast<std::uint8_t>((value >> shift) & 0xFFu);
    }
    return bytes;
}

void update_with_span(crypto::Sha256& hasher, std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return;
    }
    hasher.update(data);
}

void update_length_prefixed(crypto::Sha256& hasher, std::span<const std::uint8_t> data) {
    const auto length_bytes = to_big_endian_bytes(static_cast<std::uint64_t>(data.size()));
    hasher.update(length_bytes);
    update_with_span(hasher, data);
}

std::array<std::uint8_t, 32> announce_pow_digest(const protocol::AnnouncePayload& payload) {
    crypto::Sha256 hasher;
    update_length_prefixed(hasher, std::span<const std::uint8_t>(payload.chunk_id.data(), payload.chunk_id.size()));
    update_length_prefixed(hasher, std::span<const std::uint8_t>(payload.peer_id.data(), payload.peer_id.size()));

    update_length_prefixed(hasher,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(payload.endpoint.data()), payload.endpoint.size()));
    update_length_prefixed(hasher,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(payload.manifest_uri.data()), payload.manifest_uri.size()));
    update_length_prefixed(hasher, std::span<const std::uint8_t>(payload.assigned_shards.data(), payload.assigned_shards.size()));

    const auto ttl_bytes = to_big_endian_bytes(static_cast<std::uint64_t>(payload.ttl.count()));
    hasher.update(ttl_bytes);

    const auto nonce_bytes = to_big_endian_bytes(payload.work_nonce);
    hasher.update(nonce_bytes);

    return hasher.finalize();
}

std::size_t count_leading_zero_bits(const std::array<std::uint8_t, 32>& digest) {
    std::size_t total = 0;
    for (const auto byte : digest) {
        if (byte == 0) {
            total += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte >> bit) & 0x1u) {
                return total;
            }
            ++total;
        }
        return total;
    }
    return total;
}

bool announce_pow_valid(const protocol::AnnouncePayload& payload, std::uint8_t difficulty) {
    if (difficulty == 0) {
        return true;
    }
    const auto digest = announce_pow_digest(payload);
    return count_leading_zero_bits(digest) >= difficulty;
}

std::uint64_t derive_pow_seed(const protocol::AnnouncePayload& payload) {
    protocol::AnnouncePayload seed_payload = payload;
    seed_payload.work_nonce = 0;
    const auto digest = announce_pow_digest(seed_payload);
    std::uint64_t seed = 0;
    for (int index = 0; index < 8; ++index) {
        seed = (seed << 8) | static_cast<std::uint64_t>(digest[index]);
    }
    return seed;
}

bool compute_announce_pow(protocol::AnnouncePayload& payload, std::uint8_t difficulty) {
    if (difficulty == 0) {
        payload.work_nonce = 0;
        return true;
    }

    const auto seed = derive_pow_seed(payload);
    std::mt19937_64 generator(seed);
    std::uniform_int_distribution<std::uint64_t> distribution(0, std::numeric_limits<std::uint64_t>::max());
    const auto start = distribution(generator);

    for (std::uint64_t attempt = 0; attempt < kMaxAnnouncePowAttempts; ++attempt) {
        payload.work_nonce = start + attempt;
        if (announce_pow_valid(payload, difficulty)) {
            return true;
        }
    }
    return false;
}

std::chrono::seconds clamp_chunk_ttl(std::chrono::seconds ttl,
                                     std::chrono::seconds min_ttl,
                                     std::chrono::seconds max_ttl) {
    if (ttl < min_ttl) {
        ttl = min_ttl;
    }
    if (ttl > max_ttl) {
        ttl = max_ttl;
    }
    if (ttl <= std::chrono::seconds::zero()) {
        ttl = kMinAllowedManifestTtl;
    }
    return ttl;
}

std::optional<std::chrono::seconds> enforce_manifest_ttl(std::chrono::seconds ttl,
                                                          std::chrono::seconds min_ttl,
                                                          std::chrono::seconds max_ttl) {
    if (ttl < min_ttl) {
        return std::nullopt;
    }
    if (ttl > max_ttl) {
        ttl = max_ttl;
    }
    if (ttl <= std::chrono::seconds::zero()) {
        return std::nullopt;
    }
    return ttl;
}

std::optional<std::chrono::seconds> manifest_ttl(const protocol::Manifest& manifest,
                                                  const Config& config) {
    const auto now = std::chrono::system_clock::now();
    if (manifest.expires_at <= now) {
        return std::nullopt;
    }

    auto ttl = std::chrono::duration_cast<std::chrono::seconds>(manifest.expires_at - now);
    if (ttl <= std::chrono::seconds::zero()) {
        return std::nullopt;
    }

    const auto min_ttl = config.min_manifest_ttl;
    const auto max_ttl = config.max_manifest_ttl;
    return enforce_manifest_ttl(ttl, min_ttl, max_ttl);
}

Config sanitize_config(Config config) {
    config.key_rotation_interval = sanitize_key_rotation_interval(config.key_rotation_interval);
    config.min_manifest_ttl = sanitize_manifest_min(config.min_manifest_ttl);
    config.max_manifest_ttl = sanitize_manifest_max(config.max_manifest_ttl, config.min_manifest_ttl);
    if (config.default_chunk_ttl < config.min_manifest_ttl) {
        config.default_chunk_ttl = config.min_manifest_ttl;
    }
    if (config.default_chunk_ttl > config.max_manifest_ttl) {
        config.default_chunk_ttl = config.max_manifest_ttl;
    }
    config.announce_min_interval = sanitize_announce_interval(config.announce_min_interval);
    if (config.announce_burst_limit == 0) {
        config.announce_burst_limit = 1;
    }
    config.announce_burst_window = sanitize_announce_window(config.announce_burst_window);
    if (config.announce_burst_window < config.announce_min_interval) {
        config.announce_burst_window = config.announce_min_interval;
    }
    if (config.announce_pow_difficulty > kMaxAnnouncePowDifficulty) {
        config.announce_pow_difficulty = kMaxAnnouncePowDifficulty;
    }
    return config;
}

bool validate_shards(const protocol::Manifest& manifest) {
    return manifest.threshold > 0 && manifest.shards.size() >= manifest.threshold;
}

std::optional<std::pair<std::string, std::uint16_t>> parse_endpoint(const std::string& address) {
    if (address.empty()) {
        return std::nullopt;
    }

    const auto pos = address.find_last_of(':');
    if (pos == std::string::npos) {
        return std::nullopt;
    }

    auto host = address.substr(0, pos);
    auto port_text = address.substr(pos + 1);

    if (host.empty() || port_text.empty()) {
        return std::nullopt;
    }

    try {
        const auto numeric = std::stoul(port_text);
        if (numeric == 0 || numeric > 65535u) {
            return std::nullopt;
        }
        return std::make_pair(std::move(host), static_cast<std::uint16_t>(numeric));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace

void Node::schedule_assigned_fetch(const protocol::AnnouncePayload& payload) {
    if (payload.assigned_shards.empty()) {
        return;
    }

    if (chunk_store_.get_record(payload.chunk_id).has_value()) {
        return;
    }

    protocol::Manifest manifest{};
    if (const auto cached = manifest_for_chunk(payload.chunk_id)) {
        manifest = *cached;
    } else {
        try {
            manifest = protocol::decode_manifest(payload.manifest_uri);
        } catch (const std::exception&) {
            return;
        }
        manifest_cache_[chunk_id_to_string(payload.chunk_id)] = manifest;
    }

    note_peer_seed(payload.chunk_id, payload.peer_id);
    note_local_leecher(payload.chunk_id);

    const auto key = chunk_id_to_string(payload.chunk_id);
    const auto now = std::chrono::steady_clock::now();

    SchedulerLock lock(scheduler_mutex_);

    auto [it, inserted] = pending_chunk_fetches_.try_emplace(key);
    auto& state = it->second;

    if (inserted) {
        state.chunk_id = payload.chunk_id;
        state.enqueue_time = now;
        state.attempts = 0;
    } else if (state.peer_id != payload.peer_id) {
        state.attempts = 0;
    }

    state.peer_id = payload.peer_id;
    if (!payload.endpoint.empty()) {
        state.endpoint = payload.endpoint;
    }
    state.manifest_uri = payload.manifest_uri;
    state.manifest_expires = manifest.expires_at;
    state.next_attempt = now;
    state.in_flight = false;
    state.last_dispatch = std::chrono::steady_clock::time_point{};
    state.provider_count = std::numeric_limits<std::size_t>::max();
    state.last_availability_check = std::chrono::steady_clock::time_point{};

    refresh_provider_count(state, now, true);

    process_pending_fetches();
}

bool Node::send_chunk_request_direct(const ChunkId& chunk_id, const PeerId& peer_id) {
    const auto key = session_shared_key(peer_id);
    if (!key.has_value()) {
        return false;
    }

    protocol::Message message{};
    message.version = outbound_message_version_for(peer_id);
    message.type = protocol::MessageType::Request;
    protocol::RequestPayload request{};
    request.chunk_id = chunk_id;
    request.requester = id_;
    message.payload = request;

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    auto encoded = protocol::encode_signed(message, key_span);
    const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
    return send_secure(peer_id, payload_span);
}

void Node::schedule_next_fetch_attempt(PendingFetchState& state, bool success) {
    const auto now = std::chrono::steady_clock::now();

    if (success) {
        auto interval = config_.fetch_retry_success_interval;
        if (interval <= std::chrono::seconds::zero()) {
            interval = std::chrono::seconds{1};
        }
        state.next_attempt = now + interval;
        return;
    }

    const auto limit = static_cast<std::size_t>(config_.fetch_retry_attempt_limit);
    if (limit > 0 && state.attempts >= limit) {
        state.next_attempt = std::chrono::steady_clock::time_point::max();
        return;
    }

    auto base = config_.fetch_retry_initial_backoff;
    if (base <= std::chrono::seconds::zero()) {
        base = std::chrono::seconds{1};
    }

    const std::size_t exponent = state.attempts > 0 ? state.attempts - 1 : 0;
    const std::size_t clamped_exponent = std::min<std::size_t>(exponent, 8);
    const auto factor = static_cast<int>(1 << clamped_exponent);

    auto backoff = base * factor;
    if (config_.fetch_retry_max_backoff > std::chrono::seconds::zero() && backoff > config_.fetch_retry_max_backoff) {
        backoff = config_.fetch_retry_max_backoff;
    }
    if (backoff <= std::chrono::seconds::zero()) {
        backoff = std::chrono::seconds{1};
    }

    state.next_attempt = now + backoff;
}

bool Node::dispatch_pending_fetch(PendingFetchState& state) {
    SchedulerLock lock(scheduler_mutex_);

    const auto dispatch_time = std::chrono::steady_clock::now();

    bool dispatched = send_chunk_request_direct(state.chunk_id, state.peer_id);
    if (!dispatched) {
        std::string host;
        std::uint16_t port = 0;
        if (!state.endpoint.empty()) {
            const auto endpoint = parse_endpoint(state.endpoint);
            if (endpoint.has_value()) {
                host = endpoint->first;
                port = endpoint->second;
            }
        }
        dispatched = request_chunk(state.peer_id, host, port, state.manifest_uri);
    }

    state.attempts += 1;
    schedule_next_fetch_attempt(state, dispatched);
    state.last_dispatch = dispatch_time;
    if (dispatched) {
        note_dispatch_start(state);
    }
    state.in_flight = dispatched;

    return dispatched;
}

void Node::process_pending_fetches() {
    SchedulerLock lock(scheduler_mutex_);

    if (pending_chunk_fetches_.empty()) {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto wall_now = std::chrono::system_clock::now();

    struct ReadyFetch {
        std::string key;
        PendingFetchState* state;
        std::chrono::seconds ttl;
    };

    std::vector<std::string> completed;
    completed.reserve(pending_chunk_fetches_.size());
    std::vector<ReadyFetch> ready;
    ready.reserve(pending_chunk_fetches_.size());

    std::size_t inflight_count = 0;

    for (auto& [key, state] : pending_chunk_fetches_) {
        if (chunk_store_.get_record(state.chunk_id).has_value()) {
            completed.push_back(key);
            continue;
        }

        refresh_provider_count(state, now, false);

        if (state.manifest_expires != std::chrono::system_clock::time_point{}
            && wall_now >= state.manifest_expires) {
            completed.push_back(key);
            continue;
        }

        if (state.next_attempt == std::chrono::steady_clock::time_point::max()) {
            completed.push_back(key);
            continue;
        }

        if (state.in_flight) {
            if (now >= state.next_attempt) {
                note_dispatch_end(state);
                state.in_flight = false;
            } else {
                ++inflight_count;
                continue;
            }
        }

        if (now < state.next_attempt) {
            continue;
        }

        auto ttl_remaining = std::chrono::seconds::max();
        if (state.manifest_expires != std::chrono::system_clock::time_point{}) {
            if (state.manifest_expires <= wall_now) {
                ttl_remaining = std::chrono::seconds::zero();
            } else {
                ttl_remaining = std::chrono::duration_cast<std::chrono::seconds>(state.manifest_expires - wall_now);
            }
        }

        ready.push_back(ReadyFetch{key, &state, ttl_remaining});
    }

    if (ready.empty()) {
        for (const auto& key : completed) {
            clear_pending_fetch(key);
        }
        return;
    }

    std::sort(ready.begin(), ready.end(), [](const ReadyFetch& lhs, const ReadyFetch& rhs) {
        if (lhs.state->provider_count != rhs.state->provider_count) {
            return lhs.state->provider_count < rhs.state->provider_count;
        }
        if (lhs.ttl != rhs.ttl) {
            return lhs.ttl < rhs.ttl;
        }
        if (lhs.state->attempts != rhs.state->attempts) {
            return lhs.state->attempts > rhs.state->attempts;
        }
        return lhs.state->enqueue_time < rhs.state->enqueue_time;
    });

    auto limit = static_cast<std::size_t>(config_.fetch_max_parallel_requests);
    if (limit == 0) {
        limit = std::numeric_limits<std::size_t>::max();
    }

    std::vector<std::string> exhausted;
    exhausted.reserve(ready.size());

    for (auto& entry : ready) {
        if (inflight_count >= limit) {
            break;
        }

        auto& state = *entry.state;
        if (!can_dispatch_fetch(state)) {
            continue;
        }
        const bool dispatched = dispatch_pending_fetch(state);
        if (dispatched) {
            ++inflight_count;
        }

        const auto attempt_limit = static_cast<std::size_t>(config_.fetch_retry_attempt_limit);
        if (!dispatched && attempt_limit > 0 && state.attempts >= attempt_limit) {
            exhausted.push_back(entry.key);
        }
    }

    completed.insert(completed.end(), exhausted.begin(), exhausted.end());
    for (const auto& key : completed) {
        clear_pending_fetch(key);
    }
}

bool Node::can_dispatch_fetch(const PendingFetchState& state) const {
    SchedulerLock lock(scheduler_mutex_);

    if (config_.fetch_max_parallel_requests == 0) {
        return true;
    }

    const auto peer_key = peer_id_to_string(state.peer_id);
    const auto it = active_peer_requests_.find(peer_key);
    if (it == active_peer_requests_.end()) {
        return true;
    }
    return it->second < config_.fetch_max_parallel_requests;
}

void Node::note_dispatch_start(const PendingFetchState& state) {
    SchedulerLock lock(scheduler_mutex_);

    const auto peer_key = peer_id_to_string(state.peer_id);
    active_peer_requests_[peer_key] += 1;
}

void Node::note_dispatch_end(const PendingFetchState& state) {
    SchedulerLock lock(scheduler_mutex_);

    const auto peer_key = peer_id_to_string(state.peer_id);
    auto it = active_peer_requests_.find(peer_key);
    if (it == active_peer_requests_.end()) {
        return;
    }

    if (it->second <= 1) {
        active_peer_requests_.erase(it);
    } else {
        it->second -= 1;
    }
}

void Node::clear_pending_fetch(const std::string& key) {
    SchedulerLock lock(scheduler_mutex_);

    auto it = pending_chunk_fetches_.find(key);
    if (it == pending_chunk_fetches_.end()) {
        return;
    }

    if (it->second.in_flight) {
        note_dispatch_end(it->second);
    }

    pending_chunk_fetches_.erase(it);
}

std::size_t Node::count_known_providers(const ChunkId& chunk_id) {
    SchedulerLock lock(scheduler_mutex_);

    auto providers = dht_.find_providers(chunk_id);
    if (providers.empty()) {
        return 0;
    }

    const auto now = std::chrono::steady_clock::now();
    std::unordered_set<std::string> unique;
    unique.reserve(providers.size());

    for (const auto& contact : providers) {
        if (contact.id == id_) {
            continue;
        }
        if (now >= contact.expires_at) {
            continue;
        }
        unique.insert(peer_id_to_string(contact.id));
    }

    return unique.size();
}

void Node::enqueue_upload_request(const protocol::RequestPayload& payload,
                                  const PeerId& sender,
                                  std::size_t payload_size) {
    SchedulerLock lock(scheduler_mutex_);

    PendingUploadRequest request{};
    request.chunk_id = payload.chunk_id;
    request.peer_id = sender;
    request.enqueue_time = std::chrono::steady_clock::now();
    request.payload_size = payload_size;
    pending_uploads_.push_back(std::move(request));
}

bool Node::can_accept_more_uploads() const {
    SchedulerLock lock(scheduler_mutex_);

    if (config_.upload_max_parallel_transfers == 0) {
        return true;
    }
    return active_uploads_.size() < config_.upload_max_parallel_transfers;
}

bool Node::can_dispatch_upload(const PeerId& peer_id) const {
    SchedulerLock lock(scheduler_mutex_);

    if (!can_accept_more_uploads()) {
        return false;
    }
    if (config_.upload_max_transfers_per_peer == 0) {
        return true;
    }
    const auto peer_key = peer_id_to_string(peer_id);
    const auto it = active_uploads_per_peer_.find(peer_key);
    if (it == active_uploads_per_peer_.end()) {
        return true;
    }
    return it->second < config_.upload_max_transfers_per_peer;
}

std::string Node::make_upload_key(const PeerId& peer_id, const ChunkId& chunk_id) const {
    return peer_id_to_string(peer_id) + ":" + chunk_id_to_string(chunk_id);
}

void Node::note_upload_start(const PendingUploadRequest& request, std::size_t payload_size) {
    SchedulerLock lock(scheduler_mutex_);

    const auto key = make_upload_key(request.peer_id, request.chunk_id);
    ActiveUploadState state{};
    state.chunk_id = request.chunk_id;
    state.peer_id = request.peer_id;
    state.started_at = std::chrono::steady_clock::now();
    state.payload_size = payload_size;
    active_uploads_[key] = state;

    const auto peer_key = peer_id_to_string(request.peer_id);
    active_uploads_per_peer_[peer_key] += 1;
}

void Node::note_upload_end(const PeerId& peer_id, const ChunkId& chunk_id, bool /*success*/) {
    SchedulerLock lock(scheduler_mutex_);

    const auto key = make_upload_key(peer_id, chunk_id);
    const auto it = active_uploads_.find(key);
    if (it == active_uploads_.end()) {
        return;
    }

    const auto peer_key = peer_id_to_string(peer_id);
    auto peer_it = active_uploads_per_peer_.find(peer_key);
    if (peer_it != active_uploads_per_peer_.end()) {
        if (peer_it->second <= 1) {
            active_uploads_per_peer_.erase(peer_it);
        } else {
            peer_it->second -= 1;
        }
    }

    active_uploads_.erase(it);
}

void Node::prune_stale_uploads(std::chrono::steady_clock::time_point now) {
    SchedulerLock lock(scheduler_mutex_);

    const auto timeout = config_.upload_transfer_timeout;
    if (timeout <= std::chrono::seconds::zero()) {
        return;
    }

    std::vector<std::pair<PeerId, ChunkId>> expired;
    expired.reserve(active_uploads_.size());
    for (const auto& entry : active_uploads_) {
        const auto& state = entry.second;
        if (now - state.started_at >= timeout) {
            expired.emplace_back(state.peer_id, state.chunk_id);
        }
    }

    for (const auto& entry : expired) {
        note_upload_end(entry.first, entry.second, false);
    }
}

void Node::send_negative_ack(const PeerId& peer_id, const ChunkId& chunk_id) {
    const auto key = session_shared_key(peer_id);
    if (!key.has_value()) {
        return;
    }

    protocol::Message response{};
    response.version = outbound_message_version_for(peer_id);
    response.type = protocol::MessageType::Acknowledge;
    protocol::AcknowledgePayload ack{};
    ack.chunk_id = chunk_id;
    ack.peer_id = id_;
    ack.accepted = false;
    response.payload = ack;

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    auto encoded = protocol::encode_signed(response, key_span);
    const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
    send_secure(peer_id, payload_span);
}

Node::SwarmRoleLedger& Node::ensure_swarm_ledger(const ChunkId& chunk_id) {
    const auto key = chunk_id_to_string(chunk_id);
    return swarm_roles_[key];
}

const Node::SwarmRoleLedger* Node::find_swarm_ledger(const ChunkId& chunk_id) const {
    const auto key = chunk_id_to_string(chunk_id);
    const auto it = swarm_roles_.find(key);
    if (it == swarm_roles_.end()) {
        return nullptr;
    }
    return &it->second;
}

void Node::retire_swarm_ledger(const ChunkId& chunk_id) {
    SchedulerLock lock(scheduler_mutex_);

    const auto key = chunk_id_to_string(chunk_id);
    swarm_roles_.erase(key);
}

void Node::note_local_seed(const ChunkId& chunk_id) {
    SchedulerLock lock(scheduler_mutex_);

    auto& ledger = ensure_swarm_ledger(chunk_id);
    const auto self_key = peer_id_to_string(id_);
    ledger.self_seed = true;
    ledger.self_leecher = false;
    ledger.leechers.erase(self_key);
    ledger.seeds.insert(self_key);
}

void Node::note_local_leecher(const ChunkId& chunk_id) {
    SchedulerLock lock(scheduler_mutex_);

    auto& ledger = ensure_swarm_ledger(chunk_id);
    if (ledger.self_seed) {
        ledger.self_leecher = false;
        return;
    }
    const auto self_key = peer_id_to_string(id_);
    ledger.self_leecher = true;
    ledger.leechers.insert(self_key);
}

void Node::note_peer_seed(const ChunkId& chunk_id, const PeerId& peer_id) {
    SchedulerLock lock(scheduler_mutex_);

    if (peer_id == id_) {
        note_local_seed(chunk_id);
        return;
    }
    auto& ledger = ensure_swarm_ledger(chunk_id);
    const auto peer_key = peer_id_to_string(peer_id);
    ledger.leechers.erase(peer_key);
    ledger.seeds.insert(peer_key);
}

void Node::note_peer_leecher(const ChunkId& chunk_id, const PeerId& peer_id) {
    SchedulerLock lock(scheduler_mutex_);

    if (peer_id == id_) {
        note_local_leecher(chunk_id);
        return;
    }
    auto& ledger = ensure_swarm_ledger(chunk_id);
    const auto peer_key = peer_id_to_string(peer_id);
    if (!ledger.seeds.contains(peer_key)) {
        ledger.leechers.insert(peer_key);
    }
}

std::uint8_t Node::preferred_message_version() const {
    const auto minimum = std::max<std::uint8_t>(config_.protocol_min_supported_version, protocol::kMinimumMessageVersion);
    std::uint8_t version = config_.protocol_message_version;
    if (version == 0) {
        version = protocol::kCurrentMessageVersion;
    }
    if (!protocol::is_supported_message_version(version)) {
        version = protocol::kCurrentMessageVersion;
    }
    if (version < minimum) {
        version = minimum;
    }
    return version;
}

std::uint8_t Node::outbound_message_version_for(const PeerId& peer_id) const {
    SchedulerLock lock(scheduler_mutex_);
    const auto preferred = preferred_message_version();
    const auto minimum = std::max<std::uint8_t>(config_.protocol_min_supported_version, protocol::kMinimumMessageVersion);
    const auto key = peer_id_to_string(peer_id);
    const auto it = peer_message_versions_.find(key);
    if (it != peer_message_versions_.end()) {
        const auto remote_version = it->second;
        if (remote_version < preferred) {
            return std::max(remote_version, minimum);
        }
    }
    return preferred;
}

bool Node::is_message_version_supported(std::uint8_t version) const {
    const auto minimum = std::max<std::uint8_t>(config_.protocol_min_supported_version, protocol::kMinimumMessageVersion);
    return version >= minimum && protocol::is_supported_message_version(version);
}

void Node::note_peer_message_version(const PeerId& peer_id, std::uint8_t version) {
    if (!is_message_version_supported(version)) {
        return;
    }
    SchedulerLock lock(scheduler_mutex_);
    const auto key = peer_id_to_string(peer_id);
    peer_message_versions_[key] = std::max<std::uint8_t>(version, config_.protocol_min_supported_version);
}

bool Node::register_incoming_announce(const PeerId& peer_id, std::chrono::steady_clock::time_point now) {
    SchedulerLock lock(scheduler_mutex_);

    const auto key = peer_id_to_string(peer_id);
    auto& history = peer_announce_history_[key];

    if (config_.announce_burst_window > std::chrono::seconds::zero()) {
        const auto window_start = now - config_.announce_burst_window;
        while (!history.empty() && history.front() < window_start) {
            history.pop_front();
        }
    }

    if (!history.empty() && config_.announce_min_interval > std::chrono::seconds::zero()) {
        const auto since_last = now - history.back();
        if (since_last < config_.announce_min_interval) {
            return false;
        }
    }

    if (config_.announce_burst_limit > 0 && history.size() >= config_.announce_burst_limit) {
        return false;
    }

    history.push_back(now);
    return true;
}

bool Node::apply_announce_pow(protocol::AnnouncePayload& payload) const {
    return compute_announce_pow(payload, config_.announce_pow_difficulty);
}

bool Node::verify_announce_pow(const protocol::AnnouncePayload& payload, std::uint8_t message_version) const {
    if (config_.announce_pow_difficulty == 0) {
        return true;
    }
    if (message_version < 3) {
        return false;
    }
    return announce_pow_valid(payload, config_.announce_pow_difficulty);
}

void Node::rotate_session_keys(std::chrono::steady_clock::time_point now) {
    const auto peers = key_manager_.known_peers();
    for (const auto& peer : peers) {
        if (const auto rotated = key_manager_.rotate_if_needed(peer, now)) {
            sessions_.register_peer_key(peer, *rotated);
        }
    }
}

SwarmPeerLoadMap Node::gather_peer_load() const {
    SchedulerLock lock(scheduler_mutex_);

    SwarmPeerLoadMap loads;

    auto ensure_entry = [&](const PeerId& peer_id) -> SwarmPeerLoad& {
        const auto key = peer_id_to_string(peer_id);
        auto& entry = loads[key];
        if (!entry.has_reputation) {
            entry.reputation = reputation_.score(peer_id);
            entry.has_reputation = true;
        }
        return entry;
    };

    for (const auto& upload_entry : active_uploads_) {
        const auto& state = upload_entry.second;
        auto& entry = ensure_entry(state.peer_id);
        entry.active_uploads += 1;
    }

    for (const auto& request : pending_uploads_) {
        auto& entry = ensure_entry(request.peer_id);
        entry.pending_uploads += 1;
    }

    for (const auto& fetch_entry : pending_chunk_fetches_) {
        const auto& state = fetch_entry.second;
        auto& entry = ensure_entry(state.peer_id);
        if (state.in_flight) {
            entry.active_downloads += 1;
        } else {
            entry.pending_downloads += 1;
        }
    }

    for (const auto& [peer_key, count] : active_uploads_per_peer_) {
        if (count == 0) {
            continue;
        }
        auto& entry = loads[peer_key];
        entry.active_uploads = std::max(entry.active_uploads, count);
        if (!entry.has_reputation) {
            if (const auto peer_id = peer_id_from_string(peer_key)) {
                entry.reputation = reputation_.score(*peer_id);
                entry.has_reputation = true;
            }
        }
    }

    for (const auto& [chunk_key, ledger] : swarm_roles_) {
        (void)chunk_key;
        for (const auto& seed_key : ledger.seeds) {
            auto& entry = loads[seed_key];
            entry.seed_roles += 1;
            if (!entry.has_reputation) {
                if (const auto peer_id = peer_id_from_string(seed_key)) {
                    entry.reputation = reputation_.score(*peer_id);
                    entry.has_reputation = true;
                }
            }
        }
        for (const auto& leecher_key : ledger.leechers) {
            auto& entry = loads[leecher_key];
            entry.leecher_roles += 1;
            if (!entry.has_reputation) {
                if (const auto peer_id = peer_id_from_string(leecher_key)) {
                    entry.reputation = reputation_.score(*peer_id);
                    entry.has_reputation = true;
                }
            }
        }
    }

    if (config_.upload_max_transfers_per_peer > 0) {
        for (auto& [key, entry] : loads) {
            if (!entry.is_choked && entry.active_uploads >= static_cast<std::size_t>(config_.upload_max_transfers_per_peer)) {
                entry.is_choked = true;
            }
        }
    }

    return loads;
}

bool Node::dispatch_upload(const PendingUploadRequest& request) {
    const auto manifest = manifest_for_chunk(request.chunk_id);
    const auto record = chunk_store_.get_record(request.chunk_id);
    if (!manifest.has_value() || !record.has_value()) {
        send_negative_ack(request.peer_id, request.chunk_id);
        return false;
    }

    const auto ttl_opt = manifest_ttl(*manifest, config_);
    if (!ttl_opt.has_value()) {
        send_negative_ack(request.peer_id, request.chunk_id);
        return false;
    }

    protocol::Message response{};
    response.version = outbound_message_version_for(request.peer_id);
    response.type = protocol::MessageType::Chunk;
    protocol::ChunkPayload chunk_payload{};
    chunk_payload.chunk_id = request.chunk_id;
    chunk_payload.data = record->data;
    chunk_payload.ttl = *ttl_opt;
    response.payload = std::move(chunk_payload);

    const auto key = session_shared_key(request.peer_id);
    if (!key.has_value()) {
        return false;
    }

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    auto encoded = protocol::encode_signed(response, key_span);
    const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
    const bool dispatched = send_secure(request.peer_id, payload_span);
    if (!dispatched) {
        send_negative_ack(request.peer_id, request.chunk_id);
        return false;
    }

    note_upload_start(request, record->data.size());
    return true;
}

void Node::process_pending_uploads() {
    SchedulerLock lock(scheduler_mutex_);

    if (pending_uploads_.empty()) {
        prune_stale_uploads(std::chrono::steady_clock::now());
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    prune_stale_uploads(now);

    if (pending_uploads_.empty()) {
        return;
    }

    const auto interval = config_.upload_reconsider_interval;
    if (pending_uploads_.size() > 1 && interval > std::chrono::seconds::zero()) {
        if (now - last_upload_rotation_ >= interval) {
            auto rotated = pending_uploads_.front();
            pending_uploads_.pop_front();
            pending_uploads_.push_back(rotated);
            last_upload_rotation_ = now;
        }
    }

    std::size_t iterations = pending_uploads_.size();
    while (iterations-- > 0) {
        if (!can_accept_more_uploads()) {
            break;
        }

        auto request = pending_uploads_.front();
        pending_uploads_.pop_front();

        if (!can_dispatch_upload(request.peer_id)) {
            pending_uploads_.push_back(std::move(request));
            continue;
        }

        if (!dispatch_upload(request)) {
            continue;
        }
    }
}

void Node::refresh_provider_count(PendingFetchState& state,
                                  std::chrono::steady_clock::time_point now,
                                  bool force) {
    SchedulerLock lock(scheduler_mutex_);

    const auto interval = config_.fetch_availability_refresh;
    if (!force && state.last_availability_check != std::chrono::steady_clock::time_point{}) {
        if (interval > std::chrono::seconds::zero()) {
            const auto elapsed = now - state.last_availability_check;
            if (elapsed < interval) {
                return;
            }
        }
    }

    state.provider_count = count_known_providers(state.chunk_id);
    state.last_availability_check = now;
}

Node::Node(PeerId id, Config config)
        : id_(id),
            config_(sanitize_config(config)),
            chunk_store_(config_),
            dht_(id, config_),
            key_manager_(config_.key_rotation_interval),
            reputation_(),
            sessions_(id),
            nat_manager_(config_),
            swarm_(config_),
            crypto_(),
            identity_scalar_(generate_identity_scalar(config_)),
            identity_public_(network::KeyExchange::compute_public(identity_scalar_)),
            handshake_state_(),
            cleanup_notifications_(),
            last_cleanup_(std::chrono::steady_clock::now()),
            last_upload_rotation_(std::chrono::steady_clock::now()) {
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

protocol::Manifest Node::store_chunk(const ChunkId& chunk_id,
                                     ChunkData data,
                                     std::chrono::seconds ttl,
                                     std::optional<std::string> original_name) {
    const auto threshold = std::max<std::uint8_t>(std::uint8_t{1}, config_.shard_threshold);
    const auto total_shares = std::max(threshold, config_.shard_total);

    const auto effective_ttl = ttl.count() > 0 ? ttl : config_.default_chunk_ttl;
    const auto sanitized_ttl = clamp_chunk_ttl(effective_ttl, config_.min_manifest_ttl, config_.max_manifest_ttl);

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

    if (original_name.has_value()) {
        auto sanitize_filename = [](std::string value) {
            value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
                              return std::iscntrl(ch);
                          }), value.end());
            for (auto& ch : value) {
                if (ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|') {
                    ch = '_';
                }
            }
            if (value == "." || value == "..") {
                value.clear();
            }
            return value;
        };

        constexpr std::size_t kMaxSuggestedNameLength = 255;
        std::filesystem::path candidate(*original_name);
        auto base = sanitize_filename(candidate.filename().string());
        if (!base.empty()) {
            if (base.size() > kMaxSuggestedNameLength) {
                base.resize(kMaxSuggestedNameLength);
            }
            manifest.metadata["filename"] = base;
        }
    }

    manifest_cache_[chunk_id_to_string(chunk_id)] = manifest;
    dht_.publish_shards(chunk_id, manifest.shards, manifest.threshold, manifest.total_shares, sanitized_ttl);
    announce_chunk(chunk_id, sanitized_ttl);
    update_swarm_plan(manifest);
    broadcast_manifest(manifest);
    note_local_seed(chunk_id);

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

    const auto ttl = manifest_ttl(manifest, config_);
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

    const auto ttl = manifest_ttl(manifest, config_);
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
    clear_pending_fetch(chunk_id_to_string(manifest.chunk_id));
    note_local_seed(manifest.chunk_id);

    broadcast_manifest(manifest);

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
    note_peer_seed(manifest.chunk_id, peer_id);
    note_local_leecher(manifest.chunk_id);

    ensure_bootstrap_handshake(peer_id);

    if (!connect_peer(peer_id, resolved_host, resolved_port)) {
        return false;
    }

    const auto key = session_shared_key(peer_id);
    if (!key.has_value()) {
        return false;
    }

    protocol::Message message{};
    message.version = outbound_message_version_for(peer_id);
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
            retire_swarm_ledger(chunk_id);
        }
        dht_.sweep_expired();
        last_cleanup_ = now;
    }
    rebalance_swarm_plans();
    process_pending_uploads();
    process_pending_fetches();
    rotate_session_keys(now);
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

std::vector<ChunkStore::SnapshotEntry> Node::stored_chunks() const {
    return chunk_store_.snapshot();
}

std::size_t Node::connected_peer_count() const {
    return sessions_.active_session_count();
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

    if (!is_message_version_supported(decoded->version)) {
        return;
    }

    note_peer_message_version(message.peer_id, decoded->version);

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
        case protocol::MessageType::Announce: {
            if (const auto* payload = std::get_if<protocol::AnnouncePayload>(&message.payload)) {
                handle_announce(*payload, transport.peer_id, message.version);
            }
            break;
        }
        default:
            break;
    }
}

void Node::handle_request(const protocol::RequestPayload& payload, const PeerId& sender) {
    const auto key = session_shared_key(sender);
    if (!key.has_value()) {
        return;
    }

    note_peer_leecher(payload.chunk_id, sender);

    const auto manifest = manifest_for_chunk(payload.chunk_id);
    const auto record = chunk_store_.get_record(payload.chunk_id);
    bool accepted = manifest.has_value() && record.has_value();
    if (manifest.has_value()) {
        const auto ttl_opt = manifest_ttl(*manifest, config_);
        if (!ttl_opt.has_value()) {
            accepted = false;
        }
    }

    if (!accepted) {
        send_negative_ack(sender, payload.chunk_id);
        return;
    }

    enqueue_upload_request(payload, sender, record->data.size());
    process_pending_uploads();
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

    if (accepted) {
        note_peer_seed(payload.chunk_id, sender);
    }

    protocol::Message ack_message{};
    ack_message.version = outbound_message_version_for(sender);
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
        note_peer_seed(payload.chunk_id, sender);
    } else {
        reputation_.record_failure(sender);
        note_peer_leecher(payload.chunk_id, sender);
    }
    note_upload_end(sender, payload.chunk_id, payload.accepted);
    process_pending_uploads();
}

void Node::handle_announce(const protocol::AnnouncePayload& payload,
                           const PeerId& sender,
                           std::uint8_t message_version) {
    if (payload.peer_id != sender) {
        reputation_.record_failure(sender);
        return;
    }

    if (payload.manifest_uri.empty()) {
        reputation_.record_failure(sender);
        return;
    }

    if (!verify_announce_pow(payload, message_version)) {
        reputation_.record_failure(sender);
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    if (!register_incoming_announce(sender, now)) {
        reputation_.record_failure(sender);
        return;
    }

    protocol::Manifest manifest{};
    try {
        manifest = protocol::decode_manifest(payload.manifest_uri);
    } catch (const std::exception&) {
        reputation_.record_failure(sender);
        return;
    }

    if (manifest.chunk_id != payload.chunk_id) {
        reputation_.record_failure(sender);
        return;
    }

    if (!validate_shards(manifest)) {
        reputation_.record_failure(sender);
        return;
    }

    const auto ttl_opt = manifest_ttl(manifest, config_);
    if (!ttl_opt.has_value()) {
        reputation_.record_failure(sender);
        return;
    }

    const bool shards_valid = payload.assigned_shards.empty() ||
        std::all_of(payload.assigned_shards.begin(), payload.assigned_shards.end(), [&](std::uint8_t index) {
            return std::any_of(manifest.shards.begin(), manifest.shards.end(), [&](const protocol::KeyShard& shard) {
                return shard.index == index;
            });
        });

    if (!shards_valid) {
        reputation_.record_failure(sender);
        return;
    }

    const auto chunk_key = chunk_id_to_string(manifest.chunk_id);
    manifest_cache_[chunk_key] = manifest;
    dht_.publish_shards(manifest.chunk_id, manifest.shards, manifest.threshold, manifest.total_shares, *ttl_opt);
    update_swarm_plan(manifest);
    note_peer_seed(manifest.chunk_id, sender);

    auto advertised_ttl = payload.ttl.count() > 0 ? payload.ttl : *ttl_opt;
    if (advertised_ttl > *ttl_opt) {
        advertised_ttl = *ttl_opt;
    }
    advertised_ttl = clamp_chunk_ttl(advertised_ttl, config_.min_manifest_ttl, config_.max_manifest_ttl);
    if (!payload.endpoint.empty()) {
        PeerContact contact{};
        contact.id = sender;
        contact.address = payload.endpoint;
        contact.expires_at = now + advertised_ttl;
        dht_.add_contact(payload.chunk_id, std::move(contact), advertised_ttl);
    }

    schedule_assigned_fetch(payload);

    broadcast_manifest(manifest);

    reputation_.record_success(sender);
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
    const auto load_snapshot = gather_peer_load();
    auto plan = swarm_.compute_plan(manifest.chunk_id, manifest, dht_, id_, load_snapshot);

    if (const auto existing = swarm_plans_.find(key); existing != swarm_plans_.end()) {
        for (const auto& assignment : plan.assignments) {
            const auto peer_key = peer_id_to_string(assignment.peer.id);
            if (existing->second.delivered_peers.contains(peer_key)) {
                plan.delivered_peers.insert(peer_key);
            }
        }
        plan.last_broadcast = existing->second.last_broadcast;
    }

    if (plan.assignments.empty()) {
        plan.diagnostics.emplace_back("Swarm coordinator produced no assignments.");
    }

    swarm_plans_[key] = std::move(plan);
}

void Node::rebalance_swarm_plans() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> stale_keys;
    stale_keys.reserve(swarm_plans_.size());

    const auto load_snapshot = gather_peer_load();
    for (auto& [key, plan] : swarm_plans_) {
        if (now < plan.next_rebalance) {
            continue;
        }

        const auto manifest_it = manifest_cache_.find(key);
        if (manifest_it == manifest_cache_.end()) {
            stale_keys.push_back(key);
            continue;
        }

        auto refreshed = swarm_.compute_plan(manifest_it->second.chunk_id, manifest_it->second, dht_, id_, load_snapshot);
        refreshed.diagnostics.emplace_back("Plan recomputed after rebalance interval.");
        for (const auto& assignment : refreshed.assignments) {
            const auto peer_key = peer_id_to_string(assignment.peer.id);
            if (plan.delivered_peers.contains(peer_key)) {
                refreshed.delivered_peers.insert(peer_key);
            }
        }
        refreshed.last_broadcast = plan.last_broadcast;
        plan = std::move(refreshed);
    }

    for (const auto& key : stale_keys) {
        swarm_plans_.erase(key);
    }
}

void Node::broadcast_manifest(const protocol::Manifest& manifest) {
    const auto port = sessions_.listening_port();
    if (port == 0) {
        return;
    }

    const auto ttl_opt = manifest_ttl(manifest, config_);
    if (!ttl_opt.has_value()) {
        return;
    }

    const auto key = chunk_id_to_string(manifest.chunk_id);
    const auto plan_it = swarm_plans_.find(key);
    if (plan_it == swarm_plans_.end()) {
        return;
    }

    auto& plan = plan_it->second;

    const auto endpoint = self_endpoint();
    if (endpoint.empty()) {
        return;
    }

    const auto manifest_uri = protocol::encode_manifest(manifest);

    bool any_delivered = false;
    for (const auto& assignment : plan.assignments) {
        if (assignment.peer.id == id_) {
            continue;
        }
        if (assignment.shard_indices.empty()) {
            continue;
        }
        const auto peer_key = peer_id_to_string(assignment.peer.id);
        if (plan.delivered_peers.contains(peer_key)) {
            continue;
        }
        if (deliver_manifest(manifest, assignment, manifest_uri, *ttl_opt, endpoint)) {
            plan.delivered_peers.insert(peer_key);
            any_delivered = true;
        }
    }

    if (any_delivered) {
        plan.last_broadcast = std::chrono::steady_clock::now();
    }
}

bool Node::deliver_manifest(const protocol::Manifest& manifest,
                            const SwarmAssignment& assignment,
                            const std::string& manifest_uri,
                            std::chrono::seconds ttl,
                            const std::string& endpoint) {
    const auto target = parse_endpoint(assignment.peer.address);
    if (!target.has_value()) {
        return false;
    }

    const auto& [host, port] = *target;
    if (host.empty() || port == 0) {
        return false;
    }

    const auto key = session_shared_key(assignment.peer.id);
    if (!key.has_value()) {
        return false;
    }

    connect_peer(assignment.peer.id, host, port);

    protocol::Message announce{};
    auto announce_version = outbound_message_version_for(assignment.peer.id);
    if (config_.announce_pow_difficulty > 0 && announce_version < 3) {
        return false;
    }
    announce.version = announce_version;
    announce.type = protocol::MessageType::Announce;

    protocol::AnnouncePayload payload{};
    payload.chunk_id = manifest.chunk_id;
    payload.peer_id = id_;
    payload.endpoint = endpoint;
    payload.ttl = ttl;
    payload.manifest_uri = manifest_uri;
    payload.assigned_shards = assignment.shard_indices;
    if (!apply_announce_pow(payload)) {
        return false;
    }
    announce.payload = std::move(payload);

    const auto key_span = std::span<const std::uint8_t>(key->data(), key->size());
    auto encoded = protocol::encode_signed(announce, key_span);
    const std::span<const std::uint8_t> payload_span(encoded.data(), encoded.size());
    return send_secure(assignment.peer.id, payload_span);
}

std::string Node::self_endpoint() const {
    const auto port = sessions_.listening_port();
    if (port == 0) {
        return {};
    }

    if (nat_status_.has_value() && !nat_status_->external_address.empty() && nat_status_->external_port != 0) {
        return nat_status_->external_address + ":" + std::to_string(nat_status_->external_port);
    }

    const auto& host = !config_.control_host.empty() ? config_.control_host : std::string{"127.0.0.1"};
    return host + ":" + std::to_string(port);
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
