#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/network/SessionManager.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace ephemeralnet::network {

class SessionManager;

class RelayClient {
public:
    using HandshakeBuilder = std::function<std::optional<SessionManager::OutboundHandshake>(const PeerId&)>;

    RelayClient(const Config& config,
                SessionManager& sessions,
                const PeerId& self_id);
    ~RelayClient();

    RelayClient(const RelayClient&) = delete;
    RelayClient& operator=(const RelayClient&) = delete;

    void start();
    void stop();

    bool has_active_allocation() const;
    std::optional<protocol::DiscoveryHint> current_hint(std::uint8_t priority) const;

    bool connect_via_hint(const protocol::DiscoveryHint& hint,
                          const PeerId& target_peer);

    void set_handshake_builder(HandshakeBuilder builder);

private:
    struct RelayState;

    void registration_loop();
    bool register_with_endpoint(const Config::RelayEndpoint& endpoint);
    void clear_active_allocation();
    void track_active_socket(std::intptr_t handle);
    void clear_tracked_socket();
    void interrupt_active_socket();
    std::optional<SessionManager::OutboundHandshake> build_handshake(const PeerId& peer_id,
                                                                     bool& builder_present) const;
    static constexpr std::intptr_t kInvalidSocketHandle = static_cast<std::intptr_t>(-1);

    const Config& config_;
    SessionManager& sessions_;
    PeerId self_id_{};

    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<std::intptr_t> active_socket_{kInvalidSocketHandle};

    mutable std::mutex state_mutex_;
    std::unique_ptr<RelayState> state_;
    mutable std::mutex handshake_mutex_;
    HandshakeBuilder handshake_builder_{};
};

}  // namespace ephemeralnet::network
