#pragma once

#include "ephemeralnet/Types.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ephemeralnet::network {

struct TransportMessage {
    PeerId peer_id{};
    std::vector<std::uint8_t> payload;
    std::string endpoint;
};

class SessionManager {
public:
    using MessageHandler = std::function<void(const TransportMessage&)>;
    using SocketHandle = intptr_t;
    static constexpr SocketHandle INVALID_SOCKET_HANDLE = static_cast<SocketHandle>(-1);

    explicit SessionManager(PeerId self_id);
    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    void start(std::uint16_t port);
    void stop();

    std::uint16_t listening_port() const noexcept;

    void set_message_handler(MessageHandler handler);

    void register_peer_key(const PeerId& peer_id, const std::array<std::uint8_t, 32>& key);

    bool connect(const PeerId& peer_id, const std::string& host, std::uint16_t port);
    bool send(const PeerId& peer_id, std::span<const std::uint8_t> payload);

    std::size_t active_session_count() const;

    struct TestHooks {
        std::function<void(const PeerId&, std::size_t)> before_send;
        std::function<bool(const TransportMessage&)> drop_receive;
    };

    static void set_test_hooks(const TestHooks* hooks);

private:
    struct Session {
        SocketHandle socket{INVALID_SOCKET_HANDLE};
        std::array<std::uint8_t, 32> key{};
        std::string endpoint;
        std::thread reader;
        std::atomic<bool> running{false};
    };

    PeerId self_id_{};
    mutable std::mutex handler_mutex_;
    MessageHandler handler_{};

    std::atomic<bool> running_{false};
    SocketHandle listen_socket_{INVALID_SOCKET_HANDLE};
    std::thread accept_thread_;
    std::uint16_t bound_port_{0};

    mutable std::mutex sessions_mutex_;
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
    std::unordered_map<std::string, std::array<std::uint8_t, 32>> keys_;

    void accept_loop();
    void receive_loop(const PeerId& peer_id, std::shared_ptr<Session> session);
    void teardown_sessions();
    std::optional<std::array<std::uint8_t, 32>> peer_key(const PeerId& peer_id) const;
    static std::string peer_key_string(const PeerId& peer_id);

    static bool send_all(SocketHandle socket, const std::uint8_t* data, std::size_t length);
    static bool recv_all(SocketHandle socket, std::uint8_t* buffer, std::size_t length);
    static void close_socket(SocketHandle socket);
    static bool configure_socket(SocketHandle socket, bool server_mode);
    static SocketHandle create_socket();
    static std::string endpoint_string(SocketHandle socket);
};

}  // namespace ephemeralnet::network
