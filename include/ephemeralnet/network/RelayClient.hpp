#pragma once

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace ephemeralnet::network {

class SessionManager;

class RelayClient {
public:
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

private:
    struct RelayState;

    void registration_loop();
    bool register_with_endpoint(const Config::RelayEndpoint& endpoint);
    void clear_active_allocation();

    const Config& config_;
    SessionManager& sessions_;
    PeerId self_id_{};

    std::thread worker_;
    std::atomic<bool> running_{false};

    mutable std::mutex state_mutex_;
    std::unique_ptr<RelayState> state_;
};

}  // namespace ephemeralnet::network
