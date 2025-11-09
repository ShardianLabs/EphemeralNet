#include "ephemeralnet/network/RelayClient.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/network/SessionManager.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace ephemeralnet::network {

namespace {

using SocketHandle = std::intptr_t;

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

struct WinsockGuard {
    WinsockGuard() {
        WSADATA data{};
        WSAStartup(MAKEWORD(2, 2), &data);
    }

    ~WinsockGuard() {
        WSACleanup();
    }
};

WinsockGuard& winsock_guard() {
    static WinsockGuard guard;
    return guard;
}

void close_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        closesocket(socket);
    }
}

void shutdown_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::shutdown(socket, SD_BOTH);
    }
}

#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

void winsock_guard() {}

void close_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::close(socket);
    }
}

void shutdown_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::shutdown(socket, SHUT_RDWR);
    }
}

#endif

constexpr SocketHandle kEncodedInvalidSocket = static_cast<SocketHandle>(-1);

SocketHandle encode_socket(NativeSocket socket) {
    if (socket == kInvalidSocket) {
        return kEncodedInvalidSocket;
    }
    return static_cast<SocketHandle>(socket);
}

NativeSocket decode_socket(SocketHandle handle) {
    if (handle == kEncodedInvalidSocket) {
        return kInvalidSocket;
    }
    return static_cast<NativeSocket>(handle);
}

bool send_all(NativeSocket socket, const std::uint8_t* data, std::size_t length) {
    std::size_t total = 0;
    while (total < length) {
#ifdef _WIN32
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data + total),
                                 static_cast<int>(length - total), 0);
#else
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data + total),
                                 length - total, 0);
#endif
        if (sent <= 0) {
            return false;
        }
        total += static_cast<std::size_t>(sent);
    }
    return true;
}

bool send_line(NativeSocket socket, std::string_view line) {
    return send_all(socket, reinterpret_cast<const std::uint8_t*>(line.data()), line.size());
}

std::optional<std::string> read_line(NativeSocket socket, std::chrono::milliseconds timeout) {
    const bool apply_timeout = timeout.count() > 0;
#ifdef _WIN32
    DWORD value = static_cast<DWORD>(timeout.count());
    if (apply_timeout) {
        if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
            return std::nullopt;
        }
    }
#else
    if (apply_timeout) {
        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
        if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv)) != 0) {
            return std::nullopt;
        }
    }
#endif

    std::string buffer;
    buffer.reserve(64);
    char ch = '\0';
    while (true) {
#ifdef _WIN32
        const auto received = ::recv(socket, &ch, 1, 0);
#else
        const auto received = ::recv(socket, &ch, 1, 0);
#endif
        if (received <= 0) {
            return std::nullopt;
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            buffer.push_back(ch);
        }
    }

    if (apply_timeout) {
#ifdef _WIN32
        value = 0;
        ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&value), sizeof(value));
#else
        timeval zero{};
        ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&zero), sizeof(zero));
#endif
    }

    return buffer;
}

std::optional<std::pair<std::string, std::uint16_t>> parse_endpoint(const std::string& endpoint) {
    const auto pos = endpoint.find(':');
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    std::string host = endpoint.substr(0, pos);
    std::string port_text = endpoint.substr(pos + 1);
    if (host.empty() || port_text.empty()) {
        return std::nullopt;
    }

    std::uint32_t port_value = 0;
    try {
        port_value = static_cast<std::uint32_t>(std::stoul(port_text));
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (port_value == 0 || port_value > 65535u) {
        return std::nullopt;
    }
    return std::make_pair(std::move(host), static_cast<std::uint16_t>(port_value));
}

struct ParsedRelayEndpoint {
    std::string host;
    std::uint16_t port{0};
    std::optional<PeerId> remote;
};

std::optional<ParsedRelayEndpoint> parse_relay_endpoint(const std::string& endpoint) {
    const auto query_pos = endpoint.find('?');
    std::string address = endpoint.substr(0, query_pos);
    auto base = parse_endpoint(address);
    if (!base.has_value()) {
        return std::nullopt;
    }

    ParsedRelayEndpoint parsed{};
    parsed.host = std::move(base->first);
    parsed.port = base->second;

    if (query_pos != std::string::npos) {
        const auto query = endpoint.substr(query_pos + 1);
        constexpr std::string_view kPeerKey{"peer="};
        if (query.rfind(kPeerKey, 0) == 0 && query.size() > kPeerKey.size()) {
            const auto hex = query.substr(kPeerKey.size());
            if (const auto peer = peer_id_from_string(hex)) {
                parsed.remote = *peer;
            }
        }
    }

    return parsed;
}

NativeSocket open_socket(const std::string& host, std::uint16_t port) {
    winsock_guard();

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
        if (result) {
            ::freeaddrinfo(result);
        }
        return kInvalidSocket;
    }

    NativeSocket socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == kInvalidSocket) {
        ::freeaddrinfo(result);
        return kInvalidSocket;
    }

    sockaddr_in address = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
    address.sin_port = htons(port);
    ::freeaddrinfo(result);

    if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        close_socket(socket);
        return kInvalidSocket;
    }

    return socket;
}

std::array<std::uint8_t, sizeof(PeerId)> peer_id_bytes(const PeerId& peer_id) {
    std::array<std::uint8_t, sizeof(PeerId)> bytes{};
    std::copy(peer_id.begin(), peer_id.end(), bytes.begin());
    return bytes;
}

SessionManager::SocketHandle to_handle(NativeSocket socket) {
    return static_cast<SessionManager::SocketHandle>(socket);
}

}  // namespace

struct RelayClient::RelayState {
    std::string host;
    std::uint16_t port{0};
    std::string hint;
    NativeSocket socket{kInvalidSocket};
};

RelayClient::RelayClient(const Config& config,
                         SessionManager& sessions,
                         const PeerId& self_id)
    : config_(config),
      sessions_(sessions),
      self_id_(self_id) {}

RelayClient::~RelayClient() {
    stop();
}

void RelayClient::start() {
    if (!config_.relay_enabled || config_.relay_endpoints.empty()) {
        return;
    }
    if (running_.exchange(true)) {
        return;
    }
    worker_ = std::thread(&RelayClient::registration_loop, this);
}

void RelayClient::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    interrupt_active_socket();
    {
        std::scoped_lock lock(state_mutex_);
        if (state_ && state_->socket != kInvalidSocket) {
            close_socket(state_->socket);
            state_->socket = kInvalidSocket;
        }
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    clear_active_allocation();
}

bool RelayClient::has_active_allocation() const {
    std::scoped_lock lock(state_mutex_);
    return state_ != nullptr;
}

std::optional<protocol::DiscoveryHint> RelayClient::current_hint(std::uint8_t priority) const {
    std::scoped_lock lock(state_mutex_);
    if (!state_) {
        return std::nullopt;
    }
    protocol::DiscoveryHint hint{};
    hint.scheme = "transport";
    hint.transport = "relay";
    hint.endpoint = state_->hint;
    hint.priority = priority;
    return hint;
}

bool RelayClient::connect_via_hint(const protocol::DiscoveryHint& hint, const PeerId& target_peer) {
    if (!config_.relay_enabled) {
        return false;
    }
    if (hint.transport != "relay") {
        return false;
    }

    const auto parsed = parse_relay_endpoint(hint.endpoint);
    if (!parsed.has_value()) {
        return false;
    }
    if (parsed->remote.has_value() && *parsed->remote != target_peer) {
        return false;
    }

    auto socket = open_socket(parsed->host, parsed->port);
    if (socket == kInvalidSocket) {
        return false;
    }

    const auto self_hex = peer_id_to_string(self_id_);
    const auto target_hex = peer_id_to_string(target_peer);
    std::string connect_line = "CONNECT " + self_hex + " " + target_hex + "\n";
    if (!send_line(socket, connect_line)) {
        close_socket(socket);
        return false;
    }

    auto ack = read_line(socket, std::chrono::milliseconds{5000});
    if (!ack.has_value() || *ack != "OK") {
        close_socket(socket);
        return false;
    }

    const auto identity = peer_id_bytes(self_id_);
    if (!send_all(socket, identity.data(), identity.size())) {
        close_socket(socket);
        return false;
    }

    const auto handle = to_handle(socket);
    if (!sessions_.adopt_outbound_socket(target_peer, handle, true)) {
        close_socket(socket);
        return false;
    }

    // Ownership of the socket transferred to SessionManager.
    return true;
}

void RelayClient::registration_loop() {
    while (running_) {
        bool registered = false;
        for (const auto& endpoint : config_.relay_endpoints) {
            if (!running_) {
                break;
            }
            if (register_with_endpoint(endpoint)) {
                registered = true;
            }
            if (!running_) {
                break;
            }
        }
        if (!running_) {
            break;
        }
        if (!registered) {
            clear_active_allocation();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

bool RelayClient::register_with_endpoint(const Config::RelayEndpoint& endpoint) {
    auto socket = open_socket(endpoint.host, endpoint.port);
    if (socket == kInvalidSocket) {
        return false;
    }
    track_active_socket(encode_socket(socket));

    const auto self_hex = peer_id_to_string(self_id_);
    std::string register_line = "REGISTER " + self_hex + "\n";
    if (!send_line(socket, register_line)) {
        close_socket(socket);
        clear_tracked_socket();
        return false;
    }

    auto ack = read_line(socket, std::chrono::milliseconds{5000});
    if (!ack.has_value() || *ack != "OK") {
        close_socket(socket);
        clear_tracked_socket();
        return false;
    }

    {
        std::scoped_lock lock(state_mutex_);
        auto state = std::make_unique<RelayState>();
        state->host = endpoint.host;
        state->port = endpoint.port;
        state->hint = endpoint.host + ":" + std::to_string(endpoint.port) + "?peer=" + peer_id_to_string(self_id_);
        state->socket = socket;
        state_ = std::move(state);
    }

    while (running_) {
        auto line = read_line(socket, std::chrono::milliseconds{0});
        if (!line.has_value()) {
            break;
        }
        if (*line == "PING") {
            send_line(socket, "PONG\n");
            continue;
        }
        constexpr std::string_view kBeginPrefix{"BEGIN "};
        if (line->rfind(kBeginPrefix, 0) == 0) {
            const auto peer_hex = line->substr(kBeginPrefix.size());
            const auto remote = peer_id_from_string(peer_hex);
            if (!remote.has_value()) {
                break;
            }

            const auto handle = to_handle(socket);
            const bool adopted = sessions_.adopt_inbound_socket(handle, remote);
            if (!adopted) {
                close_socket(socket);
                clear_tracked_socket();
                socket = kInvalidSocket;
                break;
            }

            // Handoff succeeded: SessionManager now owns the socket and will drive the handshake.
            {
                std::scoped_lock lock(state_mutex_);
                if (state_) {
                    state_->socket = kInvalidSocket;
                }
            }
            clear_tracked_socket();
            socket = kInvalidSocket;
            break;
        }
    }

    if (socket != kInvalidSocket) {
        close_socket(socket);
        clear_tracked_socket();
        {
            std::scoped_lock lock(state_mutex_);
            if (state_) {
                state_->socket = kInvalidSocket;
            }
        }
    }
    clear_active_allocation();
    return running_;
}

void RelayClient::clear_active_allocation() {
    std::scoped_lock lock(state_mutex_);
    if (state_ && state_->socket != kInvalidSocket) {
        close_socket(state_->socket);
        state_->socket = kInvalidSocket;
    }
    state_.reset();
    clear_tracked_socket();
}

void RelayClient::track_active_socket(SocketHandle handle) {
    active_socket_.store(handle, std::memory_order_release);
}

void RelayClient::clear_tracked_socket() {
    active_socket_.store(kInvalidSocketHandle, std::memory_order_release);
}

void RelayClient::interrupt_active_socket() {
    const auto handle = active_socket_.load(std::memory_order_acquire);
    const auto socket = decode_socket(handle);
    if (socket != kInvalidSocket) {
        shutdown_socket(socket);
    }
}

}  // namespace ephemeralnet::network
