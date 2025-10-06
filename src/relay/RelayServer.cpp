#include "ephemeralnet/relay/RelayServer.hpp"

#include "ephemeralnet/Types.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <iostream>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace ephemeralnet::relay {

namespace {
constexpr std::size_t kPeerIdBytes = sizeof(PeerId);

bool is_hex_string(const std::string& text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

std::pair<std::string, std::string> split_command(const std::string& line) {
    const auto space = line.find(' ');
    if (space == std::string::npos) {
        return {line, {}};
    }
    std::string command = line.substr(0, space);
    std::string remaining = line.substr(space + 1);
    return std::make_pair(std::move(command), std::move(remaining));
}

std::vector<std::string> split_arguments(const std::string& text) {
    std::vector<std::string> tokens;
    std::string current;
    for (char ch : text) {
        if (ch == ' ') {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        tokens.push_back(current);
    }
    return tokens;
}

}  // namespace

RelayServer::ClientSession::ClientSession(int socket_fd)
    : fd(socket_fd) {}

RelayServer::RelayServer(EventLoop& loop, RelayServerConfig config)
    : loop_(loop),
      config_(std::move(config)) {}

RelayServer::~RelayServer() {
    stop();
}

bool RelayServer::start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::perror("socket");
        return false;
    }

    int enable = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    configure_socket(listen_fd_);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.listen_port);
    if (::inet_pton(AF_INET, config_.listen_host.c_str(), &address.sin_addr) != 1) {
        std::cerr << "Invalid listen host: " << config_.listen_host << "\n";
        return false;
    }

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        std::perror("bind");
        return false;
    }

    if (::listen(listen_fd_, SOMAXCONN) != 0) {
        std::perror("listen");
        return false;
    }

    auto callback = [this](int fd, std::uint32_t events) {
        (void)events;
        if (fd == listen_fd_) {
            accept_new_clients();
        }
    };

    loop_.add(listen_fd_, EventLoop::kEventReadable, callback);
    std::cout << "Relay server listening on " << config_.listen_host << ":" << config_.listen_port
              << "\n";
    return true;
}

void RelayServer::stop() {
    if (listen_fd_ >= 0) {
        loop_.remove(listen_fd_);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    auto sessions = std::move(sessions_);
    for (auto& entry : sessions) {
        close_session(entry.second);
    }
    registered_.clear();
}

void RelayServer::configure_socket(int fd) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    int opts = ::fcntl(fd, F_GETFD, 0);
    if (opts >= 0) {
        ::fcntl(fd, F_SETFD, opts | FD_CLOEXEC);
    }
}

void RelayServer::accept_new_clients() {
    while (true) {
        sockaddr_in remote{};
        socklen_t len = sizeof(remote);
        int client_fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&remote), &len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            std::perror("accept");
            break;
        }
        configure_socket(client_fd);
        auto session = std::make_shared<ClientSession>(client_fd);
        sessions_.emplace(client_fd, session);
        auto callback = [this, weak = std::weak_ptr<ClientSession>(session)](int fd, std::uint32_t events) {
            auto locked = weak.lock();
            if (!locked) {
                loop_.remove(fd);
                return;
            }
            on_client_event(locked, events);
        };
        loop_.add(client_fd, EventLoop::kEventReadable, callback);
    }
}

void RelayServer::on_client_event(const std::shared_ptr<ClientSession>& session, std::uint32_t events) {
    if (events & EventLoop::kEventError) {
        close_session(session);
        return;
    }
    if ((events & EventLoop::kEventReadable) && !handle_read(session)) {
        return;
    }
    if (events & EventLoop::kEventWritable) {
        handle_write(session);
    }
}

bool RelayServer::handle_read(const std::shared_ptr<ClientSession>& session) {
    std::array<char, 4096> buffer{};
    while (true) {
        const auto received = ::recv(session->fd, buffer.data(), buffer.size(), 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            close_session(session);
            return false;
        }
        if (received == 0) {
            close_session(session);
            return false;
        }
        if (session->state == SessionState::Bridged) {
            forward_to_partner(session, buffer.data(), static_cast<std::size_t>(received));
            continue;
        }
        session->read_buffer.append(buffer.data(), static_cast<std::size_t>(received));
        process_protocol(session);
    }
    return true;
}

bool RelayServer::handle_write(const std::shared_ptr<ClientSession>& session) {
    while (!session->write_buffer.empty()) {
        const auto sent = ::send(session->fd, session->write_buffer.data(), session->write_buffer.size(), 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            close_session(session);
            return false;
        }
        session->write_buffer.erase(0, static_cast<std::size_t>(sent));
    }
    update_interest(session);
    return true;
}

void RelayServer::process_protocol(const std::shared_ptr<ClientSession>& session) {
    bool progress = true;
    while (progress) {
        progress = false;
        if (session->state == SessionState::AwaitingIdentity) {
            if (session->read_buffer.size() >= kPeerIdBytes) {
                progress = true;
                handle_identity_ready(session);
            }
            continue;
        }
        const auto pos = session->read_buffer.find('\n');
        if (pos == std::string::npos) {
            break;
        }
        std::string line = session->read_buffer.substr(0, pos);
        session->read_buffer.erase(0, pos + 1);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        progress = true;
        handle_line(session, line);
    }
}

void RelayServer::handle_line(const std::shared_ptr<ClientSession>& session, const std::string& line) {
    if (line.empty()) {
        return;
    }
    const auto [command, arguments] = split_command(line);
    if (command == "REGISTER") {
        handle_register(session, arguments);
    } else if (command == "CONNECT") {
        const auto tokens = split_arguments(arguments);
        if (tokens.size() != 2) {
            queue_text(session, "ERROR invalid-args\n");
            return;
        }
        handle_connect(session, tokens[0], tokens[1]);
    } else if (command == "PONG") {
        // Keep-alive acknowledgement; nothing to do yet.
    } else {
        queue_text(session, "ERROR unknown-command\n");
    }
}

void RelayServer::handle_register(const std::shared_ptr<ClientSession>& session,
                                  const std::string& peer_hex) {
    if (!is_hex_string(peer_hex)) {
        queue_text(session, "ERROR invalid-peer\n");
        return;
    }
    const auto peer = peer_id_from_string(peer_hex);
    if (!peer.has_value()) {
        queue_text(session, "ERROR invalid-peer\n");
        return;
    }

    remove_registration(session);
    session->peer_id = *peer;
    session->peer_hex = peer_id_to_string(session->peer_id);
    session->state = SessionState::Registered;
    registered_[session->peer_hex] = session;
    queue_text(session, "OK\n");
}

void RelayServer::handle_connect(const std::shared_ptr<ClientSession>& session,
                                 const std::string& self_hex,
                                 const std::string& target_hex) {
    if (session->state == SessionState::Registered) {
        queue_text(session, "ERROR already-registered\n");
        return;
    }
    if (!is_hex_string(self_hex) || !is_hex_string(target_hex)) {
        queue_text(session, "ERROR invalid-peer\n");
        return;
    }
    if (self_hex == target_hex) {
        queue_text(session, "ERROR invalid-target\n");
        return;
    }
    auto target = find_registered(target_hex);
    if (!target) {
        queue_text(session, "ERROR target-unavailable\n");
        return;
    }
    registered_.erase(target_hex);
    session->state = SessionState::AwaitingIdentity;
    session->connect_self = self_hex;
    session->partner = target;
    target->partner = session;
    queue_text(session, "OK\n");
}

void RelayServer::handle_identity_ready(const std::shared_ptr<ClientSession>& session) {
    if (session->state != SessionState::AwaitingIdentity) {
        return;
    }
    if (session->read_buffer.size() < kPeerIdBytes) {
        return;
    }
    auto target = session->partner.lock();
    if (!target) {
        queue_text(session, "ERROR target-unavailable\n");
        close_session(session);
        return;
    }

    std::string identity_chunk = session->read_buffer.substr(0, kPeerIdBytes);
    session->read_buffer.erase(0, kPeerIdBytes);

    const std::string begin_line = "BEGIN " + session->connect_self + "\n";
    queue_text(target, begin_line);

    session->state = SessionState::Bridged;
    target->state = SessionState::Bridged;

    queue_binary(target, identity_chunk.data(), identity_chunk.size());
    if (!session->read_buffer.empty()) {
        queue_binary(target, session->read_buffer.data(), session->read_buffer.size());
        session->read_buffer.clear();
    }
}

void RelayServer::forward_to_partner(const std::shared_ptr<ClientSession>& session,
                                     const char* data,
                                     std::size_t size) {
    auto partner = session->partner.lock();
    if (!partner) {
        close_session(session);
        return;
    }
    if (partner->closing) {
        close_session(session);
        return;
    }
    queue_binary(partner, data, size);
}

void RelayServer::queue_text(const std::shared_ptr<ClientSession>& session, const std::string& text) {
    queue_binary(session, text.data(), text.size());
}

void RelayServer::queue_binary(const std::shared_ptr<ClientSession>& session,
                               const char* data,
                               std::size_t size) {
    session->write_buffer.append(data, size);
    update_interest(session);
}

void RelayServer::update_interest(const std::shared_ptr<ClientSession>& session) {
    std::uint32_t mask = EventLoop::kEventReadable;
    if (!session->write_buffer.empty()) {
        mask |= EventLoop::kEventWritable;
    }
    loop_.update(session->fd, mask);
}

void RelayServer::close_session(const std::shared_ptr<ClientSession>& session) {
    if (session->closing) {
        return;
    }
    session->closing = true;
    remove_registration(session);
    detach_partner(session);
    loop_.remove(session->fd);
    ::close(session->fd);
    sessions_.erase(session->fd);
}

void RelayServer::detach_partner(const std::shared_ptr<ClientSession>& session) {
    auto partner = session->partner.lock();
    if (!partner) {
        return;
    }
    partner->partner.reset();
    if (partner->state == SessionState::AwaitingIdentity || partner->state == SessionState::Bridged) {
        close_session(partner);
    } else if (partner->state == SessionState::Registered && !partner->peer_hex.empty()) {
        registered_[partner->peer_hex] = partner;
    }
}

void RelayServer::remove_registration(const std::shared_ptr<ClientSession>& session) {
    if (session->peer_hex.empty()) {
        return;
    }
    auto it = registered_.find(session->peer_hex);
    if (it != registered_.end()) {
        if (auto existing = it->second.lock()) {
            if (existing.get() == session.get()) {
                registered_.erase(it);
            }
        } else {
            registered_.erase(it);
        }
    }
}

std::shared_ptr<RelayServer::ClientSession> RelayServer::find_registered(const std::string& peer_hex) {
    auto it = registered_.find(peer_hex);
    if (it == registered_.end()) {
        return nullptr;
    }
    auto session = it->second.lock();
    if (!session || session->state != SessionState::Registered) {
        registered_.erase(it);
        return nullptr;
    }
    return session;
}

}  // namespace ephemeralnet::relay
