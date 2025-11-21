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
#include <sstream>
#include <unordered_map>
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
std::atomic<std::uint64_t> g_session_debug_ids{0};
std::mutex g_live_sessions_mutex;
std::unordered_map<std::uint64_t, std::string> g_live_sessions;

thread_local int g_last_recv_error = 0;
thread_local std::size_t g_last_recv_expected = 0;
thread_local std::size_t g_last_recv_obtained = 0;

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

bool SessionManager::is_connected(const PeerId& peer_id) const {
    std::scoped_lock lock(sessions_mutex_);
    const auto it = sessions_.find(peer_key_string(peer_id));
    return it != sessions_.end() && it->second && it->second->running.load();
}

void SessionManager::register_peer_key(const PeerId& peer_id, const std::array<std::uint8_t, 32>& key) {
    std::scoped_lock lock(sessions_mutex_);
    keys_[peer_key_string(peer_id)] = key;

    const auto it = sessions_.find(peer_key_string(peer_id));
    if (it != sessions_.end() && it->second) {
        it->second->key = key;
    }
}

bool SessionManager::connect(const PeerId& peer_id,
                             const std::string& host,
                             std::uint16_t port,
                             const OutboundHandshake* handshake) {
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

    if (handshake) {
        if (!send_transport_handshake(from_native(socket), *handshake)) {
            close_socket(from_native(socket));
            return false;
        }
        if (handshake->expect_ack) {
            if (!receive_transport_handshake_ack(from_native(socket), *handshake)) {
                close_socket(from_native(socket));
                return false;
            }
        }
    }

    auto session = std::make_shared<Session>();
    session->socket = from_native(socket);
    session->key = *key;
    session->endpoint = endpoint_string(from_native(socket));
    session->running.store(true);
    session->alive.store(true);
    session->debug_id = g_session_debug_ids.fetch_add(1, std::memory_order_relaxed) + 1;
    session->debug_peer = peer_key_string(peer_id);
    session->debug_origin = "connect";

    {
        std::lock_guard<std::mutex> lock(g_live_sessions_mutex);
        g_live_sessions[session->debug_id] = session->debug_peer + "@" + session->endpoint +
            " origin=" + session->debug_origin + " stage=registered";
    }

    std::cerr << "[SessionManager] register session id=" << session->debug_id
              << " peer=" << session->debug_peer
              << " endpoint=" << session->endpoint
              << " origin=" << session->debug_origin << std::endl;

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
    session->alive.store(true);
    session->debug_id = g_session_debug_ids.fetch_add(1, std::memory_order_relaxed) + 1;
    session->debug_peer = peer_key_string(peer_id);
    session->debug_origin = "adopt-outbound";

    {
        std::lock_guard<std::mutex> lock(g_live_sessions_mutex);
        g_live_sessions[session->debug_id] = session->debug_peer + "@" + session->endpoint +
            " origin=" + session->debug_origin + " stage=registered";
    }

    std::cerr << "[SessionManager] register session id=" << session->debug_id
              << " peer=" << session->debug_peer
              << " endpoint=" << session->endpoint
              << " origin=" << session->debug_origin << std::endl;

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

    if (!handle_pending_handshake(peer_id, socket)) {
        close_socket(socket);
        return false;
    }
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
    session->alive.store(true);
    session->debug_id = g_session_debug_ids.fetch_add(1, std::memory_order_relaxed) + 1;
    session->debug_peer = peer_key_string(peer_id);
    session->debug_origin = "inbound-handshake";

    {
        std::lock_guard<std::mutex> lock(g_live_sessions_mutex);
        g_live_sessions[session->debug_id] = session->debug_peer + "@" + session->endpoint +
            " origin=" + session->debug_origin + " stage=registered";
    }

    std::cerr << "[SessionManager] register session id=" << session->debug_id
              << " peer=" << session->debug_peer
              << " endpoint=" << session->endpoint
              << " origin=" << session->debug_origin << std::endl;

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
        
        // Always perform handshake on new connections.
        if (!handle_pending_handshake(peer_id, socket_handle)) {
            close_socket(socket_handle);
        }
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

bool SessionManager::send_transport_handshake(SocketHandle socket, const OutboundHandshake& handshake) {
    protocol::Message message{};
    message.version = protocol::kCurrentMessageVersion;
    message.type = protocol::MessageType::TransportHandshake;
    message.payload = handshake.payload;

    const auto encoded = protocol::encode(message);
    std::vector<std::uint8_t> frame(kLengthFieldSize + encoded.size());
    const auto length = static_cast<std::uint32_t>(encoded.size());
    frame[0] = static_cast<std::uint8_t>((length >> 24) & 0xFFu);
    frame[1] = static_cast<std::uint8_t>((length >> 16) & 0xFFu);
    frame[2] = static_cast<std::uint8_t>((length >> 8) & 0xFFu);
    frame[3] = static_cast<std::uint8_t>(length & 0xFFu);
    std::copy(encoded.begin(), encoded.end(), frame.begin() + kLengthFieldSize);

    return send_all(socket, frame.data(), frame.size());
}

bool SessionManager::receive_transport_handshake_ack(SocketHandle socket, const OutboundHandshake& handshake) {
    std::array<std::uint8_t, kNonceSize> nonce_buffer{};
    if (!recv_all(socket, nonce_buffer.data(), nonce_buffer.size())) {
        return false;
    }

    std::array<std::uint8_t, kLengthFieldSize> length_buffer{};
    if (!recv_all(socket, length_buffer.data(), length_buffer.size())) {
        return false;
    }

    const auto length = (static_cast<std::uint32_t>(length_buffer[0]) << 24)
        | (static_cast<std::uint32_t>(length_buffer[1]) << 16)
        | (static_cast<std::uint32_t>(length_buffer[2]) << 8)
        | (static_cast<std::uint32_t>(length_buffer[3]));

    if (length == 0 || length > kMaxPayloadSize) {
        return false;
    }

    std::vector<std::uint8_t> ciphertext(length);
    if (!ciphertext.empty()) {
        if (!recv_all(socket, ciphertext.data(), ciphertext.size())) {
            return false;
        }
    }

    crypto::Key key{};
    key.bytes = handshake.session_key;

    crypto::Nonce nonce{};
    std::copy(nonce_buffer.begin(), nonce_buffer.end(), nonce.bytes.begin());

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    if (!ciphertext.empty()) {
        crypto::ChaCha20::apply(key, nonce, ciphertext, plaintext, 0u);
    }

    const auto key_span = std::span<const std::uint8_t>(handshake.session_key.data(), handshake.session_key.size());
    const auto ack_message = protocol::decode_signed(plaintext, key_span);
    if (!ack_message.has_value() || ack_message->type != protocol::MessageType::HandshakeAck) {
        return false;
    }

    const auto* payload = std::get_if<protocol::HandshakeAckPayload>(&ack_message->payload);
    if (payload == nullptr || !payload->accepted) {
        return false;
    }

    return true;
}

void SessionManager::receive_loop(const PeerId& peer_id, std::shared_ptr<Session> session) {
    session->alive.store(true);
    const auto thread_id = std::this_thread::get_id();
    std::ostringstream thread_stream;
    thread_stream << thread_id;
    const std::string thread_label = thread_stream.str();

    std::cerr << "[SessionManager] receive_loop start id=" << session->debug_id
              << " peer=" << session->debug_peer
              << " endpoint=" << session->endpoint
              << " origin=" << session->debug_origin
              << " thread=" << thread_label << std::endl;

    auto record_state = [&](const std::string& state) {
        {
            std::lock_guard<std::mutex> lock(g_live_sessions_mutex);
            g_live_sessions[session->debug_id] = session->debug_peer + "@" + session->endpoint +
                " origin=" + session->debug_origin + " thread=" + thread_label + " " + state;
        }
        std::cerr << "[SessionManager] state id=" << session->debug_id
                  << " peer=" << session->debug_peer
                  << " endpoint=" << session->endpoint
                  << " origin=" << session->debug_origin
                  << " thread=" << thread_label
                  << " " << state << std::endl;
    };

    record_state("loop=0 stage=start");

    std::uint64_t loop_index = 0;
    while (session->running.load()) {
        const auto current_loop = ++loop_index;
        auto loop_state = [&](const std::string& detail) {
            std::ostringstream oss;
            oss << "loop=" << current_loop << " " << detail;
            return oss.str();
        };

        record_state(loop_state("stage=await-nonce len=" + std::to_string(kNonceSize)));

        std::array<std::uint8_t, kNonceSize> nonce_buffer{};
        if (!recv_all(session->socket, nonce_buffer.data(), nonce_buffer.size())) {
            std::ostringstream fail;
            fail << "stage=nonce-fail expected=" << g_last_recv_expected
                 << " received=" << g_last_recv_obtained
                 << " err=" << g_last_recv_error;
            record_state(loop_state(fail.str()));
            std::cerr << "[SessionManager] recv_all nonce failed id=" << session->debug_id
                      << " endpoint=" << session->endpoint << std::endl;
            break;
        }

        record_state(loop_state("stage=nonce-ok"));

        std::array<std::uint8_t, kLengthFieldSize> length_buffer{};
        record_state(loop_state("stage=await-length len=" + std::to_string(kLengthFieldSize)));
        if (!recv_all(session->socket, length_buffer.data(), length_buffer.size())) {
            std::ostringstream fail;
            fail << "stage=length-fail expected=" << g_last_recv_expected
                 << " received=" << g_last_recv_obtained
                 << " err=" << g_last_recv_error;
            record_state(loop_state(fail.str()));
            std::cerr << "[SessionManager] recv_all length failed id=" << session->debug_id
                      << " endpoint=" << session->endpoint << std::endl;
            break;
        }

        const auto length = (static_cast<std::uint32_t>(length_buffer[0]) << 24)
            | (static_cast<std::uint32_t>(length_buffer[1]) << 16)
            | (static_cast<std::uint32_t>(length_buffer[2]) << 8)
            | (static_cast<std::uint32_t>(length_buffer[3]));

        {
            std::ostringstream length_state;
            length_state << "stage=length-ok value=" << length;
            record_state(loop_state(length_state.str()));
        }

        if (length > kMaxPayloadSize) {
            std::ostringstream oversized_state;
            oversized_state << "stage=oversized size=" << length;
            record_state(loop_state(oversized_state.str()));
            std::cerr << "[SessionManager] oversized payload from "
                      << session->endpoint << " size=" << length << std::endl;
            break;
        }

        std::vector<std::uint8_t> ciphertext(length);
        if (!ciphertext.empty()) {
            std::ostringstream wait_payload;
            wait_payload << "stage=await-payload len=" << length;
            record_state(loop_state(wait_payload.str()));

            if (!recv_all(session->socket, ciphertext.data(), ciphertext.size())) {
                std::ostringstream fail;
                fail << "stage=payload-fail expected=" << g_last_recv_expected
                     << " received=" << g_last_recv_obtained
                     << " err=" << g_last_recv_error;
                record_state(loop_state(fail.str()));
                std::cerr << "[SessionManager] recv_all payload failed id=" << session->debug_id
                          << " endpoint=" << session->endpoint
                          << " bytes=" << ciphertext.size() << std::endl;
                break;
            }

            std::ostringstream payload_ok;
            payload_ok << "stage=payload-ok len=" << length;
            record_state(loop_state(payload_ok.str()));
        } else {
            record_state(loop_state("stage=payload-empty"));
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
                std::ostringstream drop_state;
                drop_state << "stage=message-dropped size=" << message.payload.size();
                record_state(loop_state(drop_state.str()));
                continue;
            }
            handler_copy(message);
            std::ostringstream handled_state;
            handled_state << "stage=message-handled size=" << message.payload.size();
            record_state(loop_state(handled_state.str()));
        } else {
            record_state(loop_state("stage=message-ignored"));
        }
    }

    const bool loop_was_running = session->running.load();
    if (loop_was_running) {
        record_state("loop=" + std::to_string(loop_index) + " stage=loop-ended-break");
    } else {
        record_state("loop=" + std::to_string(loop_index) + " stage=loop-ended-stop");
    }

    session->running.store(false);
    close_session_socket(session);

    {
        std::scoped_lock lock(sessions_mutex_);
        sessions_.erase(peer_key_string(peer_id));
    }
    session->alive.store(false);

    {
        std::lock_guard<std::mutex> lock(g_live_sessions_mutex);
        g_live_sessions.erase(session->debug_id);
    }

    std::cerr << "[SessionManager] receive_loop exit id=" << session->debug_id
              << " peer=" << session->debug_peer
              << " endpoint=" << session->endpoint
              << " origin=" << session->debug_origin
              << " thread=" << thread_label << std::endl;
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
        std::cerr << "[SessionManager] teardown signal id=" << session->debug_id
                  << " origin=" << session->debug_origin
                  << " peer=" << session->debug_peer
                  << " endpoint=" << session->endpoint
                  << " running=" << session->running.load()
                  << " alive=" << session->alive.load() << std::endl;
        session->running.store(false);
        close_session_socket(session);

        auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (session->alive.load() && std::chrono::steady_clock::now() < wait_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (session->alive.load()) {
            std::cerr << "[SessionManager] timeout waiting for session "
                      << session->endpoint << " to terminate (id=" << session->debug_id
                      << " peer=" << session->debug_peer
                      << " origin=" << session->debug_origin << ')'
                      << std::endl;
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_live_sessions_mutex);
        if (!g_live_sessions.empty()) {
            std::cerr << "[SessionManager] live sessions after teardown:" << std::endl;
            for (const auto& [id, details] : g_live_sessions) {
                std::cerr << "  id=" << id << " " << details << std::endl;
            }
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
    g_last_recv_error = 0;
    g_last_recv_expected = length;
    g_last_recv_obtained = 0;
    while (received_total < length) {
#ifdef _WIN32
    const auto received = ::recv(socket, reinterpret_cast<char*>(buffer + received_total), static_cast<int>(length - received_total), 0);
#else
        const auto received = ::recv(socket, reinterpret_cast<char*>(buffer + received_total), length - received_total, 0);
#endif
        if (received <= 0) {
#ifdef _WIN32
        const auto error = WSAGetLastError();
#else
        const auto error = errno;
#endif
        g_last_recv_error = error;
        g_last_recv_obtained = received_total;
        std::cerr << "[SessionManager] recv_all failure length=" << length
              << " received=" << received_total
              << " error=" << error << std::endl;
            return false;
        }
        received_total += static_cast<std::size_t>(received);
        g_last_recv_obtained = received_total;
    }
    g_last_recv_error = 0;
    g_last_recv_expected = length;
    g_last_recv_obtained = received_total;
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

void SessionManager::close_session_socket(const std::shared_ptr<Session>& session) {
    if (!session) {
        return;
    }
    bool expected = false;
    if (session->socket_closed.compare_exchange_strong(expected, true)) {
        close_socket(session->socket);
    }
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
