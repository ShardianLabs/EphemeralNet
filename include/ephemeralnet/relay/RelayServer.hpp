#pragma once

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/relay/EventLoop.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>

namespace ephemeralnet::relay {

struct RelayServerConfig {
    std::string listen_host{"0.0.0.0"};
    std::uint16_t listen_port{9750};
    std::chrono::seconds handshake_timeout{10};
};

class RelayServer {
public:
    RelayServer(EventLoop& loop, RelayServerConfig config);
    ~RelayServer();

    RelayServer(const RelayServer&) = delete;
    RelayServer& operator=(const RelayServer&) = delete;

    bool start();
    void stop();

private:
    enum class SessionState {
        AwaitingCommand,
        Registered,
        AwaitingIdentity,
        Bridged
    };

    struct ClientSession {
        explicit ClientSession(int fd);

        int fd{-1};
        SessionState state{SessionState::AwaitingCommand};
        std::string read_buffer;
        std::string write_buffer;
        std::string peer_hex;
        PeerId peer_id{};
        std::string connect_self;
        std::weak_ptr<ClientSession> partner;
        bool closing{false};
    };

    void configure_socket(int fd);
    void on_accept(int fd, std::uint32_t events);
    void accept_new_clients();
    void on_client_event(const std::shared_ptr<ClientSession>& session, std::uint32_t events);
    bool handle_read(const std::shared_ptr<ClientSession>& session);
    bool handle_write(const std::shared_ptr<ClientSession>& session);
    void process_protocol(const std::shared_ptr<ClientSession>& session);
    void handle_line(const std::shared_ptr<ClientSession>& session, const std::string& line);
    void handle_register(const std::shared_ptr<ClientSession>& session, const std::string& peer_hex);
    void handle_connect(const std::shared_ptr<ClientSession>& session,
                        const std::string& self_hex,
                        const std::string& target_hex);
    void handle_identity_ready(const std::shared_ptr<ClientSession>& session);
    void forward_to_partner(const std::shared_ptr<ClientSession>& session, const char* data, std::size_t size);

    void queue_text(const std::shared_ptr<ClientSession>& session, const std::string& text);
    void queue_binary(const std::shared_ptr<ClientSession>& session, const char* data, std::size_t size);
    void update_interest(const std::shared_ptr<ClientSession>& session);
    void close_session(const std::shared_ptr<ClientSession>& session);
    void detach_partner(const std::shared_ptr<ClientSession>& session);
    void remove_registration(const std::shared_ptr<ClientSession>& session);
    std::shared_ptr<ClientSession> find_registered(const std::string& peer_hex);

    EventLoop& loop_;
    RelayServerConfig config_{};
    int listen_fd_{-1};

    std::unordered_map<int, std::shared_ptr<ClientSession>> sessions_;
    std::unordered_map<std::string, std::weak_ptr<ClientSession>> registered_;
};

}  // namespace ephemeralnet::relay
