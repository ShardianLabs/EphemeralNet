#include "ephemeralnet/network/NatTraversal.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <numeric>
#include <optional>
#include <random>
#include <stdexcept>

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
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ephemeralnet::network {

namespace {
constexpr std::array<const char*, 2> kStunFallbackHosts{
    "stun.shardian.com",
    "turn.shardian.com",
};
constexpr std::uint16_t kStunPort = 3478;
constexpr std::uint32_t kStunMagicCookie = 0x2112A442;
constexpr std::chrono::milliseconds kStunTimeout{1500};

std::atomic<const NatTraversalManager::TestHooks*> g_test_hooks{nullptr};

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

class WinsockRuntime {
public:
    WinsockRuntime() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
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

inline void close_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        closesocket(socket);
    }
}

#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

inline void winsock_runtime() {}

inline void close_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::close(socket);
    }
}
#endif

struct SocketHandle {
    SocketHandle() = default;
    explicit SocketHandle(NativeSocket socket) : socket_(socket) {}
    ~SocketHandle() {
        reset();
    }

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept : socket_(other.socket_) {
        other.socket_ = kInvalidSocket;
    }

    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            reset();
            socket_ = other.socket_;
            other.socket_ = kInvalidSocket;
        }
        return *this;
    }

    NativeSocket get() const {
        return socket_;
    }

    bool valid() const {
        return socket_ != kInvalidSocket;
    }

    void reset(NativeSocket replacement = kInvalidSocket) {
        if (valid()) {
            close_socket(socket_);
        }
        socket_ = replacement;
    }

private:
    NativeSocket socket_{kInvalidSocket};
};

void set_receive_timeout(NativeSocket socket, std::chrono::milliseconds timeout) {
#ifdef _WIN32
    const DWORD value = static_cast<DWORD>(timeout.count());
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&value), sizeof(value));
#else
    timeval tv{};
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

struct StunParserResult {
    std::string address;
    std::uint16_t port{0};
};

std::optional<StunParserResult> parse_stun_response(const std::uint8_t* data,
                                                    std::size_t length,
                                                    const std::array<std::uint8_t, 12>& transaction_id) {
    if (length < 20) {
        return std::nullopt;
    }

    const auto type = static_cast<std::uint16_t>((data[0] << 8) | data[1]);
    const auto message_length = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
    const auto total_length = static_cast<std::size_t>(20 + message_length);
    if (type != 0x0101 || length < total_length) {
        return std::nullopt;
    }

    if (!std::equal(transaction_id.begin(), transaction_id.end(), data + 8)) {
        return std::nullopt;
    }

    std::size_t offset = 20;
    std::size_t remaining = message_length;
    while (remaining >= 4 && offset + 4 <= length) {
        const auto attr_type = static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
        const auto attr_length = static_cast<std::uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
        if (attr_length > remaining || offset + 4 + attr_length > length) {
            break;
        }

        const std::uint8_t* value = data + offset + 4;
        const bool xor_address = (attr_type == 0x0020);
        if ((attr_type == 0x0001 || attr_type == 0x0020) && attr_length >= 4) {
            const auto family = value[1];
            std::uint16_t port = static_cast<std::uint16_t>((value[2] << 8) | value[3]);
            if (xor_address) {
                port ^= static_cast<std::uint16_t>((kStunMagicCookie >> 16) & 0xFFFF);
            }

            if (family == 0x01 && attr_length >= 8) {
                std::uint32_t addr_network = 0;
                std::memcpy(&addr_network, value + 4, sizeof(addr_network));
                if (xor_address) {
                    const std::uint32_t cookie = htonl(kStunMagicCookie);
                    addr_network ^= cookie;
                }

                in_addr addr{};
                addr.s_addr = addr_network;
                char buffer[INET_ADDRSTRLEN]{};
                if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) != nullptr) {
                    return StunParserResult{buffer, port};
                }
            } else if (family == 0x02 && attr_length >= 20) {
                std::array<std::uint8_t, 16> addr_bytes{};
                std::memcpy(addr_bytes.data(), value + 4, addr_bytes.size());
                if (xor_address) {
                    addr_bytes[0] ^= static_cast<std::uint8_t>((kStunMagicCookie >> 24) & 0xFF);
                    addr_bytes[1] ^= static_cast<std::uint8_t>((kStunMagicCookie >> 16) & 0xFF);
                    addr_bytes[2] ^= static_cast<std::uint8_t>((kStunMagicCookie >> 8) & 0xFF);
                    addr_bytes[3] ^= static_cast<std::uint8_t>(kStunMagicCookie & 0xFF);
                    for (std::size_t i = 0; i < transaction_id.size() && (4 + i) < addr_bytes.size(); ++i) {
                        addr_bytes[4 + i] ^= transaction_id[i];
                    }
                }

                in6_addr addr{};
                std::memcpy(&addr, addr_bytes.data(), addr_bytes.size());
                char buffer[INET6_ADDRSTRLEN]{};
                if (inet_ntop(AF_INET6, &addr, buffer, sizeof(buffer)) != nullptr) {
                    return StunParserResult{buffer, port};
                }
            }
        }

        const std::size_t padded_length = (attr_length + 3u) & ~0x3u;
        offset += 4 + padded_length;
        if (remaining < 4 + padded_length) {
            break;
        }
        remaining -= 4 + padded_length;
    }

    return std::nullopt;
}

}  // namespace

void NatTraversalManager::set_test_hooks(const TestHooks* hooks) {
    g_test_hooks.store(hooks, std::memory_order_release);
}

NatTraversalManager::NatTraversalManager(const Config& config)
    : config_(config),
      rng_(static_cast<std::mt19937::result_type>(config.identity_seed.value_or(0u) ^ 0x5A5A5A5Au)) {}

NatTraversalResult NatTraversalManager::coordinate(const std::string& local_address, std::uint16_t local_port) {
    NatTraversalResult result{};
    result.diagnostics.reserve(4);

    result.external_address = local_address.empty() ? std::string{"0.0.0.0"} : local_address;
    result.external_port = local_port;
    const std::string initial_endpoint = result.external_address + ":" + std::to_string(result.external_port);
    result.diagnostics.emplace_back("Initial endpoint assumption " + initial_endpoint);

    if (config_.nat_stun_enabled) {
        const auto stun_result = perform_stun_query();
        if (stun_result.has_value()) {
            result.external_address = stun_result->address;
            result.stun_succeeded = true;
            result.diagnostics.emplace_back("STUN discovery succeeded via " + stun_result->server);

            if (stun_result->reported_port != 0 && stun_result->reported_port != local_port) {
                result.diagnostics.emplace_back("STUN reported external port " +
                                                std::to_string(stun_result->reported_port) +
                                                " but transport listener uses " +
                                                std::to_string(local_port) +
                                                "; advertising listener port");
            }
        } else {
            result.diagnostics.emplace_back("STUN discovery failed (strict firewall suspected)");
        }
    } else {
        result.diagnostics.emplace_back("STUN discovery skipped (disabled)");
    }

    if (!result.stun_succeeded) {
        result.diagnostics.emplace_back("Relay fallback required; expose node via relay_host or bootstrap tunnels");
    }

    return result;
}

std::optional<NatTraversalManager::StunQueryResult> NatTraversalManager::perform_stun_query() {
    if (const auto* hooks = g_test_hooks.load(std::memory_order_acquire); hooks != nullptr) {
        if (hooks->stun_override) {
            return hooks->stun_override();
        }
    }

    winsock_runtime();

    std::array<std::size_t, kStunFallbackHosts.size()> ordering{};
    std::iota(ordering.begin(), ordering.end(), 0);
    std::shuffle(ordering.begin(), ordering.end(), rng_);

    for (const auto index : ordering) {
        const auto* host = kStunFallbackHosts[index];
        addrinfo hints{};
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_family = AF_UNSPEC;

        addrinfo* resolved = nullptr;
        if (getaddrinfo(host, nullptr, &hints, &resolved) != 0 || resolved == nullptr) {
            continue;
        }

        struct AddrinfoDeleter {
            void operator()(addrinfo* ptr) const {
                if (ptr != nullptr) {
                    freeaddrinfo(ptr);
                }
            }
        };

        std::unique_ptr<addrinfo, AddrinfoDeleter> guard(resolved);
        for (auto* entry = resolved; entry != nullptr; entry = entry->ai_next) {
            SocketHandle socket{::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol)};
            if (!socket.valid()) {
                continue;
            }

            if (entry->ai_family == AF_INET) {
                reinterpret_cast<sockaddr_in*>(entry->ai_addr)->sin_port = htons(kStunPort);
            } else if (entry->ai_family == AF_INET6) {
                reinterpret_cast<sockaddr_in6*>(entry->ai_addr)->sin6_port = htons(kStunPort);
            }

            set_receive_timeout(socket.get(), kStunTimeout);

            if (connect(socket.get(), entry->ai_addr, static_cast<int>(entry->ai_addrlen)) != 0) {
                continue;
            }

            std::array<std::uint8_t, 20> request{};
            request[1] = 0x01;  // Binding Request
            request[4] = 0x21;
            request[5] = 0x12;
            request[6] = 0xA4;
            request[7] = 0x42;

            std::array<std::uint8_t, 12> transaction{};
            std::uniform_int_distribution<int> byte_distribution(0, 255);
            for (auto& byte : transaction) {
                byte = static_cast<std::uint8_t>(byte_distribution(rng_));
            }
            std::copy(transaction.begin(), transaction.end(), request.begin() + 8);

            const auto sent = send(socket.get(), reinterpret_cast<const char*>(request.data()), static_cast<int>(request.size()), 0);
            if (sent != static_cast<int>(request.size())) {
                continue;
            }

            std::array<std::uint8_t, 512> response{};
            const auto received = recv(socket.get(), reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0);
            if (received <= 0) {
                continue;
            }

            const auto parsed = parse_stun_response(response.data(), static_cast<std::size_t>(received), transaction);
            if (parsed.has_value()) {
                StunQueryResult result{};
                result.address = parsed->address;
                result.reported_port = parsed->port;
                result.server = host;
                return result;
            }
        }
    }

    return std::nullopt;
}

}  // namespace ephemeralnet::network
