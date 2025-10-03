#include "ephemeralnet/network/SessionManager.hpp"

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/ChaCha20.hpp"
#include "ephemeralnet/protocol/Message.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <random>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>
#include <utility>
#ifndef _WIN32
#include <cerrno>
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidNativeSocket = INVALID_SOCKET;

class WinsockRuntime {
public:
    WinsockRuntime() {
        WSADATA data{};
        const auto result = WSAStartup(MAKEWORD(2, 2), &data);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }

    ~WinsockRuntime() {
        WSACleanup();
    }
};

WinsockRuntime& winsock_runtime() {
    static WinsockRuntime runtime;
    return runtime;
}

inline int last_network_error() {
    return WSAGetLastError();
}

#else
using NativeSocket = int;
constexpr NativeSocket kInvalidNativeSocket = -1;

inline void winsock_runtime() {}

inline int last_network_error() {
    return errno;
}
#endif

constexpr std::size_t kPeerIdSize = sizeof(ephemeralnet::PeerId);
constexpr std::size_t kNonceSize = sizeof(ephemeralnet::crypto::Nonce::bytes);
constexpr std::size_t kLengthFieldSize = sizeof(std::uint32_t);
constexpr std::size_t kMaxPayloadSize = 1 * 1024 * 1024;  // 1 MiB
constexpr std::size_t kMaxHandshakePayload = 2048;
constexpr std::chrono::milliseconds kHandshakeTimeout{2000};

std::array<std::uint8_t, kPeerIdSize> peer_id_bytes(const ephemeralnet::PeerId& peer_id) {
    std::array<std::uint8_t, kPeerIdSize> bytes{};
    std::copy(peer_id.begin(), peer_id.end(), bytes.begin());
    return bytes;
}

std::atomic<const ephemeralnet::network::SessionManager::TestHooks*> g_test_hooks{nullptr};

}  // namespace

namespace ephemeralnet::network {

namespace {

NativeSocket to_native(SessionManager::SocketHandle handle) {
    return static_cast<NativeSocket>(handle);
}

SessionManager::SocketHandle from_native(NativeSocket socket) {
    return static_cast<SessionManager::SocketHandle>(socket);
}

void set_non_blocking(NativeSocket socket, bool enable) {
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    ioctlsocket(socket, FIONBIO, &mode);
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) {
        return;
    }
    if (enable) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    fcntl(socket, F_SETFL, flags);
#endif
}

}  // namespace

SessionManager::SessionManager(PeerId self_id)
    : self_id_(self_id) {
    winsock_runtime();
}

SessionManager::~SessionManager() {
    stop();
}

void SessionManager::start(std::uint16_t port) {
    if (running_) {
        return;
    }

    NativeSocket server_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == kInvalidNativeSocket) {
        throw std::runtime_error("Failed to create listen socket");
    }

    if (!configure_socket(from_native(server_socket), true)) {
        close_socket(from_native(server_socket));
        throw std::runtime_error("Failed to configure listen socket");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (::bind(server_socket, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const auto error = last_network_error();
        close_socket(from_native(server_socket));
        throw std::runtime_error("Failed to bind listen socket: error " + std::to_string(error));
    }

    if (::listen(server_socket, SOMAXCONN) < 0) {
        const auto error = last_network_error();
        close_socket(from_native(server_socket));
        throw std::runtime_error("Failed to listen on socket: error " + std::to_string(error));
    }

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (::getsockname(server_socket, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
        bound_port_ = ntohs(bound.sin_port);
    } else {
        bound_port_ = port;
    }

    listen_socket_ = from_native(server_socket);
    running_ = true;
    accept_thread_ = std::thread(&SessionManager::accept_loop, this);
}

void SessionManager::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    close_socket(listen_socket_);
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    listen_socket_ = INVALID_SOCKET_HANDLE;

    teardown_sessions();
}

std::uint16_t SessionManager::listening_port() const noexcept {
    return bound_port_;
}

void SessionManager::set_message_handler(MessageHandler handler) {
    std::scoped_lock lock(handler_mutex_);
    handler_ = std::move(handler);
}

void SessionManager::set_handshake_handler(HandshakeHandler handler) {
    std::scoped_lock lock(handler_mutex_);
    handshake_handler_ = std::move(handler);
}

std::size_t SessionManager::active_session_count() const {
    std::scoped_lock lock(sessions_mutex_);
    return sessions_.size();
}

void SessionManager::register_peer_key(const PeerId& peer_id, const std::array<std::uint8_t, 32>& key) {
    std::scoped_lock lock(sessions_mutex_);
    keys_[peer_key_string(peer_id)] = key;

    const auto it = sessions_.find(peer_key_string(peer_id));
    if (it != sessions_.end() && it->second) {
        it->second->key = key;
    }
}

bool SessionManager::connect(const PeerId& peer_id, const std::string& host, std::uint16_t port) {
    const auto key = peer_key(peer_id);
    if (!key.has_value()) {
        return false;
    }

    NativeSocket socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == kInvalidNativeSocket) {
        return false;
    }

    if (!configure_socket(from_native(socket), false)) {
        close_socket(from_native(socket));
        return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    if (const auto err = ::getaddrinfo(host.c_str(), nullptr, &hints, &result); err != 0 || result == nullptr) {
        if (result) {
            ::freeaddrinfo(result);
        }
        close_socket(from_native(socket));
        return false;
    }

    sockaddr_in address = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
    address.sin_port = htons(port);
    ::freeaddrinfo(result);

    if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        close_socket(from_native(socket));
        return false;
    }

    const auto identity = peer_id_bytes(self_id_);
    if (!send_all(from_native(socket), identity.data(), identity.size())) {
        close_socket(from_native(socket));
        return false;
    }

    auto session = std::make_shared<Session>();
    session->socket = from_native(socket);
    session->key = *key;
    session->endpoint = endpoint_string(from_native(socket));
    session->running.store(true);

    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_[peer_key_string(peer_id)] = session;
    }

    session->reader = std::thread(&SessionManager::receive_loop, this, peer_id, session);
    session->reader.detach();
    return true;
}

bool SessionManager::send(const PeerId& peer_id, std::span<const std::uint8_t> payload) {
    std::shared_ptr<Session> session;
    {
        std::scoped_lock lock(sessions_mutex_);
        const auto it = sessions_.find(peer_key_string(peer_id));
        if (it == sessions_.end()) {
            return false;
        }
        session = it->second;
    }

    if (!session || !session->running.load()) {
        return false;
    }

    if (const auto* hooks = g_test_hooks.load(std::memory_order_acquire)) {
        if (hooks->before_send) {
            hooks->before_send(peer_id, payload.size());
        }
    }

    if (payload.size() > kMaxPayloadSize) {
        return false;
    }

    crypto::Key key{};
    key.bytes = session->key;

    crypto::Nonce nonce{};
    {
        std::random_device rd;
        for (auto& byte : nonce.bytes) {
            byte = static_cast<std::uint8_t>(rd());
        }
    }

    std::vector<std::uint8_t> ciphertext(payload.size());
    crypto::ChaCha20::apply(key, nonce, payload, ciphertext, 0u);

    std::vector<std::uint8_t> buffer(kNonceSize + kLengthFieldSize + ciphertext.size());
    std::copy(nonce.bytes.begin(), nonce.bytes.end(), buffer.begin());

    const auto length = static_cast<std::uint32_t>(ciphertext.size());
    buffer[kNonceSize + 0] = static_cast<std::uint8_t>((length >> 24) & 0xFFu);
    buffer[kNonceSize + 1] = static_cast<std::uint8_t>((length >> 16) & 0xFFu);
    buffer[kNonceSize + 2] = static_cast<std::uint8_t>((length >> 8) & 0xFFu);
    buffer[kNonceSize + 3] = static_cast<std::uint8_t>(length & 0xFFu);

    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + kNonceSize + kLengthFieldSize);

    return send_all(session->socket, buffer.data(), buffer.size());
}

bool SessionManager::adopt_outbound_socket(const PeerId& peer_id, SocketHandle socket, bool identity_sent) {
    const auto key = peer_key(peer_id);
    if (!key.has_value()) {
        close_socket(socket);
        return false;
    }

    if (!identity_sent) {
        const auto identity = peer_id_bytes(self_id_);
        if (!send_all(socket, identity.data(), identity.size())) {
            close_socket(socket);
            return false;
        }
    }

    auto session = std::make_shared<Session>();
    session->socket = socket;
    session->key = *key;
    session->endpoint = endpoint_string(socket);
    session->running.store(true);

    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_[peer_key_string(peer_id)] = session;
    }

    session->reader = std::thread(&SessionManager::receive_loop, this, peer_id, session);
    session->reader.detach();
    return true;
}

bool SessionManager::adopt_inbound_socket(SocketHandle socket, const std::optional<PeerId>& expected_peer) {
    std::array<std::uint8_t, kPeerIdSize> peer_bytes{};
    if (!recv_all(socket, peer_bytes.data(), peer_bytes.size())) {
        close_socket(socket);
        return false;
    }

    PeerId peer_id{};
    std::copy(peer_bytes.begin(), peer_bytes.end(), peer_id.begin());

    if (expected_peer.has_value() && peer_id != *expected_peer) {
        close_socket(socket);
        return false;
    }

    const auto key = peer_key(peer_id);
    if (!key.has_value()) {
        if (!handle_pending_handshake(peer_id, socket)) {
            close_socket(socket);
            return false;
        }
        return true;
    }

    auto session = std::make_shared<Session>();
    session->socket = socket;
    session->key = *key;
    session->endpoint = endpoint_string(socket);
    session->running.store(true);

    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_[peer_key_string(peer_id)] = session;
    }

    session->reader = std::thread(&SessionManager::receive_loop, this, peer_id, session);
    session->reader.detach();
    return true;
}

bool SessionManager::handle_pending_handshake(const PeerId& peer_id, SocketHandle socket) {
    HandshakeHandler handler_copy;
    {
        std::scoped_lock lock(handler_mutex_);
        handler_copy = handshake_handler_;
    }

    if (!handler_copy) {
        return false;
    }

    std::vector<std::uint8_t> raw_message;
    if (!read_handshake_payload(socket, raw_message, kHandshakeTimeout)) {
        return false;
    }

    const auto decoded = protocol::decode(raw_message);
    if (!decoded.has_value() || decoded->type != protocol::MessageType::TransportHandshake) {
        return false;
    }

    const auto* payload = std::get_if<protocol::TransportHandshakePayload>(&decoded->payload);
    if (payload == nullptr) {
        return false;
    }

    const auto acceptance = handler_copy(peer_id, *payload);
    if (!acceptance.has_value() || !acceptance->accepted) {
        return false;
    }

    if (!acceptance->ack_payload.empty()) {
        if (!send_encrypted(socket, acceptance->session_key, acceptance->ack_payload)) {
            return false;
        }
    }

    auto session = std::make_shared<Session>();
    session->socket = socket;
    session->key = acceptance->session_key;
    session->endpoint = endpoint_string(socket);
    session->running.store(true);

    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_[peer_key_string(peer_id)] = session;
        keys_[peer_key_string(peer_id)] = acceptance->session_key;
    }

    session->reader = std::thread(&SessionManager::receive_loop, this, peer_id, session);
    session->reader.detach();
    return true;
}

void SessionManager::accept_loop() {
    while (running_) {
        sockaddr_in remote{};
        socklen_t len = sizeof(remote);
        NativeSocket client_socket = ::accept(to_native(listen_socket_), reinterpret_cast<sockaddr*>(&remote), &len);
        if (client_socket == kInvalidNativeSocket) {
            if (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            continue;
        }

        std::array<std::uint8_t, kPeerIdSize> peer_bytes{};
        if (!recv_all(from_native(client_socket), peer_bytes.data(), peer_bytes.size())) {
            close_socket(from_native(client_socket));
            continue;
        }

        PeerId peer_id{};
        std::copy(peer_bytes.begin(), peer_bytes.end(), peer_id.begin());

        const auto socket_handle = from_native(client_socket);
        const auto key = peer_key(peer_id);
        if (!key.has_value()) {
            if (!handle_pending_handshake(peer_id, socket_handle)) {
                close_socket(socket_handle);
            }
            continue;
        }

        auto session = std::make_shared<Session>();
        session->socket = socket_handle;
        session->key = *key;
        session->endpoint = endpoint_string(socket_handle);
        session->running.store(true);

        {
            std::scoped_lock lock(sessions_mutex_);
            sessions_[peer_key_string(peer_id)] = session;
        }

        session->reader = std::thread(&SessionManager::receive_loop, this, peer_id, session);
        session->reader.detach();
    }
}

bool SessionManager::read_handshake_payload(SocketHandle socket,
                                            std::vector<std::uint8_t>& buffer,
                                            std::chrono::milliseconds timeout) const {
    if (timeout.count() > 0) {
        if (!set_recv_timeout(socket, timeout)) {
            return false;
        }
    }

    std::array<std::uint8_t, kLengthFieldSize> length_bytes{};
    if (!recv_all(socket, length_bytes.data(), length_bytes.size())) {
        set_recv_timeout(socket, std::chrono::milliseconds::zero());
        return false;
    }

    const auto length = (static_cast<std::uint32_t>(length_bytes[0]) << 24)
        | (static_cast<std::uint32_t>(length_bytes[1]) << 16)
        | (static_cast<std::uint32_t>(length_bytes[2]) << 8)
        | (static_cast<std::uint32_t>(length_bytes[3]));

    if (length == 0 || length > kMaxHandshakePayload) {
        set_recv_timeout(socket, std::chrono::milliseconds::zero());
        return false;
    }

    buffer.resize(length);
    if (!recv_all(socket, buffer.data(), buffer.size())) {
        set_recv_timeout(socket, std::chrono::milliseconds::zero());
        return false;
    }

    set_recv_timeout(socket, std::chrono::milliseconds::zero());
    return true;
}

bool SessionManager::send_encrypted(SocketHandle socket,
                                    const std::array<std::uint8_t, 32>& key_bytes,
                                    std::span<const std::uint8_t> payload) {
    if (payload.size() > kMaxPayloadSize) {
        return false;
    }

    crypto::Key key{};
    key.bytes = key_bytes;

    crypto::Nonce nonce{};
    {
        std::random_device rd;
        for (auto& byte : nonce.bytes) {
            byte = static_cast<std::uint8_t>(rd());
        }
    }

    std::vector<std::uint8_t> ciphertext(payload.size());
    crypto::ChaCha20::apply(key, nonce, payload, ciphertext, 0u);

    std::vector<std::uint8_t> buffer(kNonceSize + kLengthFieldSize + ciphertext.size());
    std::copy(nonce.bytes.begin(), nonce.bytes.end(), buffer.begin());

    const auto length = static_cast<std::uint32_t>(ciphertext.size());
    buffer[kNonceSize + 0] = static_cast<std::uint8_t>((length >> 24) & 0xFFu);
    buffer[kNonceSize + 1] = static_cast<std::uint8_t>((length >> 16) & 0xFFu);
    buffer[kNonceSize + 2] = static_cast<std::uint8_t>((length >> 8) & 0xFFu);
    buffer[kNonceSize + 3] = static_cast<std::uint8_t>(length & 0xFFu);

    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + kNonceSize + kLengthFieldSize);

    return send_all(socket, buffer.data(), buffer.size());
}

void SessionManager::receive_loop(const PeerId& peer_id, std::shared_ptr<Session> session) {
    while (session->running.load()) {
        std::array<std::uint8_t, kNonceSize> nonce_buffer{};
        if (!recv_all(session->socket, nonce_buffer.data(), nonce_buffer.size())) {
            break;
        }

        std::array<std::uint8_t, kLengthFieldSize> length_buffer{};
        if (!recv_all(session->socket, length_buffer.data(), length_buffer.size())) {
            break;
        }

        const auto length = (static_cast<std::uint32_t>(length_buffer[0]) << 24)
            | (static_cast<std::uint32_t>(length_buffer[1]) << 16)
            | (static_cast<std::uint32_t>(length_buffer[2]) << 8)
            | (static_cast<std::uint32_t>(length_buffer[3]));

        if (length > kMaxPayloadSize) {
            break;
        }

        std::vector<std::uint8_t> ciphertext(length);
        if (!ciphertext.empty()) {
            if (!recv_all(session->socket, ciphertext.data(), ciphertext.size())) {
                break;
            }
        }

        crypto::Key key{};
        key.bytes = session->key;

        crypto::Nonce nonce{};
        std::copy(nonce_buffer.begin(), nonce_buffer.end(), nonce.bytes.begin());

        std::vector<std::uint8_t> plaintext(ciphertext.size());
        crypto::ChaCha20::apply(key, nonce, ciphertext, plaintext, 0u);

        MessageHandler handler_copy;
        {
            std::scoped_lock lock(handler_mutex_);
            handler_copy = handler_;
        }

        if (handler_copy) {
            TransportMessage message{};
            message.peer_id = peer_id;
            message.endpoint = session->endpoint;
            message.payload = std::move(plaintext);
            bool drop = false;
            if (const auto* hooks = g_test_hooks.load(std::memory_order_acquire)) {
                if (hooks->drop_receive) {
                    drop = hooks->drop_receive(message);
                }
            }
            if (drop) {
                continue;
            }
            handler_copy(message);
        }
    }

    session->running.store(false);
    close_socket(session->socket);

    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_.erase(peer_key_string(peer_id));
    }
}

void SessionManager::teardown_sessions() {
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_copy;
    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_copy = sessions_;
        sessions_.clear();
    }

    for (auto& [_, session] : sessions_copy) {
        if (!session) {
            continue;
        }
        session->running.store(false);
        close_socket(session->socket);

        auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (session->running.load() && std::chrono::steady_clock::now() < wait_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

std::optional<std::array<std::uint8_t, 32>> SessionManager::peer_key(const PeerId& peer_id) const {
    const auto key_string = peer_key_string(peer_id);
    std::scoped_lock lock(sessions_mutex_);
    const auto it = keys_.find(key_string);
    if (it == keys_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::string SessionManager::peer_key_string(const PeerId& peer_id) {
    return peer_id_to_string(peer_id);
}

bool SessionManager::send_all(SocketHandle handle, const std::uint8_t* data, std::size_t length) {
    auto socket = to_native(handle);
    std::size_t sent_total = 0;
    while (sent_total < length) {
#ifdef _WIN32
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data + sent_total), static_cast<int>(length - sent_total), 0);
#else
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data + sent_total), length - sent_total, 0);
#endif
        if (sent <= 0) {
            return false;
        }
        sent_total += static_cast<std::size_t>(sent);
    }
    return true;
}

bool SessionManager::recv_all(SocketHandle handle, std::uint8_t* buffer, std::size_t length) {
    auto socket = to_native(handle);
    std::size_t received_total = 0;
    while (received_total < length) {
#ifdef _WIN32
        const auto received = ::recv(socket, reinterpret_cast<char*>(buffer + received_total), static_cast<int>(length - received_total), 0);
#else
        const auto received = ::recv(socket, reinterpret_cast<char*>(buffer + received_total), length - received_total, 0);
#endif
        if (received <= 0) {
            return false;
        }
        received_total += static_cast<std::size_t>(received);
    }
    return true;
}

bool SessionManager::set_recv_timeout(SocketHandle handle, std::chrono::milliseconds timeout) {
    auto socket = to_native(handle);
#ifdef _WIN32
    DWORD value = static_cast<DWORD>(timeout.count());
    if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&value), sizeof(value)) < 0) {
        return false;
    }
#else
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv)) < 0) {
        return false;
    }
#endif
    return true;
}

void SessionManager::close_socket(SocketHandle handle) {
    if (handle == INVALID_SOCKET_HANDLE) {
        return;
    }
    auto socket = to_native(handle);
#ifdef _WIN32
    ::shutdown(socket, SD_BOTH);
    ::closesocket(socket);
#else
    ::shutdown(socket, SHUT_RDWR);
    ::close(socket);
#endif
}

bool SessionManager::configure_socket(SocketHandle handle, bool server_mode) {
    auto socket = to_native(handle);

    int opt = 1;
    if (::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) < 0) {
        return false;
    }

    if (!server_mode) {
        set_non_blocking(socket, false);
    }

    return true;
}

void SessionManager::set_test_hooks(const TestHooks* hooks) {
    g_test_hooks.store(hooks, std::memory_order_release);
}

SessionManager::SocketHandle SessionManager::create_socket() {
    return from_native(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
}

std::string SessionManager::endpoint_string(SocketHandle handle) {
    auto socket = to_native(handle);
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (::getpeername(socket, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
        char buffer[INET_ADDRSTRLEN]{};
        const char* text = ::inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer));
        const auto port = ntohs(addr.sin_port);
        if (text) {
            return std::string(text) + ":" + std::to_string(port);
        }
    }
    return "unknown";
}

}  // namespace ephemeralnet::network
