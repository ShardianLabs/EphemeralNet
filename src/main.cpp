#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/core/UpdateCheck.hpp"
#include "ephemeralnet/crypto/CryptoManager.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"
#include "ephemeralnet/crypto/Shamir.hpp"
#include "ephemeralnet/daemon/ControlPlane.hpp"
#include "ephemeralnet/daemon/StructuredLogger.hpp"
#include "ephemeralnet/security/StoreProof.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/bootstrap/TokenChallenge.hpp"
#include "ephemeralnet/network/AdvertiseDiscovery.hpp"
#include "ephemeralnet/network/KeyExchange.hpp"
#include "ephemeralnet/crypto/HmacSha256.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cerrno>
#ifndef _WIN32
#include <signal.h>
#endif
#include <cstring>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <system_error>
#include <initializer_list>
#include <iostream>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <windows.h>
#include <winhttp.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif

#ifndef EPHEMERALNET_VERSION
#define EPHEMERALNET_VERSION "v1.0.2"
#endif

namespace {

constexpr std::string_view kEphemeralNetVersion = EPHEMERALNET_VERSION;
constexpr std::uint16_t kDefaultTransportPort = 45000;
constexpr std::string_view kUpdateMetadataUrl = "https://eph.shardian.com/latest.json";

std::string_view current_platform_slug() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

bool parse_floating_token(const char* begin, const char* end, double& value) {
    // libc++ on macOS still lacks std::from_chars for floating point; fall back to strtod.
    std::string buffer(begin, end);
    if (buffer.empty()) {
        return false;
    }
    char* parsed_end = nullptr;
    errno = 0;
    value = std::strtod(buffer.c_str(), &parsed_end);
    if (parsed_end != buffer.c_str() + buffer.size()) {
        return false;
    }
    return errno != ERANGE;
}

struct BootstrapSeedConfig {
    const char* host;
    std::uint16_t port;
    std::uint32_t identity_seed;
};

constexpr std::array<BootstrapSeedConfig, 2> kShardianBootstrapSeeds{std::array<BootstrapSeedConfig, 2>{
    BootstrapSeedConfig{"bootstrap1.shardian.com", 45000, 0x53485241u},
    BootstrapSeedConfig{"bootstrap2.shardian.com", 45000, 0x53485242u},
}};

ephemeralnet::PeerId peer_id_from_identity_seed(std::uint32_t seed) {
    std::array<std::uint8_t, 4> seed_bytes{};
    seed_bytes[0] = static_cast<std::uint8_t>((seed >> 24) & 0xFFu);
    seed_bytes[1] = static_cast<std::uint8_t>((seed >> 16) & 0xFFu);
    seed_bytes[2] = static_cast<std::uint8_t>((seed >> 8) & 0xFFu);
    seed_bytes[3] = static_cast<std::uint8_t>(seed & 0xFFu);
    const auto digest = ephemeralnet::crypto::Sha256::digest(std::span<const std::uint8_t>(seed_bytes.data(), seed_bytes.size()));
    ephemeralnet::PeerId id{};
    std::copy(digest.begin(), digest.end(), id.begin());
    return id;
}

std::uint32_t derive_public_identity_from_seed(std::uint32_t seed) {
    std::mt19937 generator;
    generator.seed(seed);
    std::uniform_int_distribution<std::uint32_t> distribution(2u, ephemeralnet::network::KeyExchange::kPrime - 2u);
    const auto scalar = distribution(generator);
    return ephemeralnet::network::KeyExchange::compute_public(scalar);
}

struct RelaySeedConfig {
    const char* host;
    std::uint16_t port;
};

constexpr std::array<RelaySeedConfig, 2> kShardianRelaySeeds{
    RelaySeedConfig{"turn.shardian.com", 47000},
    RelaySeedConfig{"turn2.shardian.com", 47000},
};

std::vector<ephemeralnet::Config::BootstrapNode> shardian_bootstrap_nodes() {
    std::vector<ephemeralnet::Config::BootstrapNode> nodes;
    nodes.reserve(kShardianBootstrapSeeds.size());
    for (const auto& seed : kShardianBootstrapSeeds) {
        ephemeralnet::Config::BootstrapNode node{};
        node.host = seed.host;
        node.port = seed.port;
        node.id = peer_id_from_identity_seed(seed.identity_seed);
        node.public_identity = derive_public_identity_from_seed(seed.identity_seed);
        nodes.push_back(std::move(node));
    }
    return nodes;
}

std::vector<ephemeralnet::Config::RelayEndpoint> shardian_relay_endpoints() {
    std::vector<ephemeralnet::Config::RelayEndpoint> endpoints;
    endpoints.reserve(kShardianRelaySeeds.size());
    for (const auto& seed : kShardianRelaySeeds) {
        ephemeralnet::Config::RelayEndpoint endpoint{};
        endpoint.host = seed.host;
        endpoint.port = seed.port;
        endpoints.push_back(std::move(endpoint));
    }
    return endpoints;
}

namespace protocol = ephemeralnet::protocol;
namespace bootstrap = ephemeralnet::bootstrap;

using namespace std::chrono_literals;

struct GlobalOptions {
    bool persistent{false};
    bool persistent_set{false};
    bool wipe{true};
    bool wipe_set{false};
    std::uint8_t wipe_passes{1};
    bool wipe_passes_set{false};
    std::optional<std::string> storage_dir{};
    std::optional<std::uint32_t> identity_seed{};
    std::optional<std::string> peer_id_hex{};
    std::optional<std::uint64_t> default_ttl_seconds{};
    std::optional<std::uint64_t> min_ttl_seconds{};
    std::optional<std::uint64_t> max_ttl_seconds{};
    std::optional<std::uint64_t> key_rotation_seconds{};
    std::optional<std::uint64_t> announce_interval_seconds{};
    std::optional<std::uint64_t> announce_burst_limit{};
    std::optional<std::uint64_t> announce_window_seconds{};
    std::optional<std::uint64_t> announce_pow_difficulty{};
    std::optional<std::string> control_host{};
    std::optional<std::uint16_t> control_port{};
    bool control_expose_requested{false};
    std::optional<std::string> control_token{};
    std::optional<std::uint64_t> control_stream_max_bytes{};
    std::optional<std::uint16_t> fetch_parallel{};
    std::optional<std::uint16_t> upload_parallel{};
    std::optional<std::string> fetch_default_directory{};
    bool fetch_use_manifest_name{true};
    bool fetch_use_manifest_name_set{false};
    bool assume_yes{false};
    bool assume_yes_set{false};
    std::optional<std::string> config_path{};
    std::optional<std::string> profile_name{};
    std::optional<std::string> environment{};
    bool advertise_control_set{false};
    std::optional<std::string> advertise_control_host{};
    std::optional<std::uint16_t> advertise_control_port{};
    bool advertise_allow_private{false};
    std::optional<ephemeralnet::Config::AdvertiseAutoMode> advertise_auto_mode{};
    std::optional<std::uint16_t> transport_listen_port{};
};

std::string trim(std::string value);
std::string to_lower(std::string value);
std::string strip_quotes(std::string value);

bool try_parse_advertise_auto_mode(std::string value,
                                   ephemeralnet::Config::AdvertiseAutoMode& mode) {
    value = to_lower(trim(value));
    if (value == "on" || value.empty()) {
        mode = ephemeralnet::Config::AdvertiseAutoMode::On;
        return true;
    }
    if (value == "warn") {
        mode = ephemeralnet::Config::AdvertiseAutoMode::Warn;
        return true;
    }
    if (value == "off") {
        mode = ephemeralnet::Config::AdvertiseAutoMode::Off;
        return true;
    }
    return false;
}

std::string_view advertise_auto_mode_to_string(ephemeralnet::Config::AdvertiseAutoMode mode) {
    switch (mode) {
        case ephemeralnet::Config::AdvertiseAutoMode::On:
            return "on";
        case ephemeralnet::Config::AdvertiseAutoMode::Warn:
            return "warn";
        case ephemeralnet::Config::AdvertiseAutoMode::Off:
            return "off";
    }
    return "on";
}

class CliException : public std::exception {
public:
    CliException(std::string code, std::string message, std::string hint = {})
        : code_(std::move(code)), message_(std::move(message)), hint_(std::move(hint)) {
        formatted_ = code_.empty() ? message_ : ("[" + code_ + "] " + message_);
    }

    const char* what() const noexcept override {
        return formatted_.c_str();
    }

    const std::string& code() const& {
        return code_;
    }

    const std::string& message() const& {
        return message_;
    }

    const std::string& hint() const& {
        return hint_;
    }

private:
    std::string code_;
    std::string message_;
    std::string hint_;
    std::string formatted_;
};

[[noreturn]] void throw_cli_error(std::string code, std::string message, std::string hint = {}) {
    throw CliException(std::move(code), std::move(message), std::move(hint));
}

[[noreturn]] void throw_daemon_unreachable() {
    throw_cli_error("E_DAEMON_UNREACHABLE",
                    "Could not contact the daemon.",
                    "Start it with 'eph start' or 'eph serve' in another terminal, and verify --control-host/--control-port");
}

std::string trim(std::string value) {
    const auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](unsigned char ch) { return !is_space(ch); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char ch) { return !is_space(ch); }).base(), value.end());
    return value;
}

bool has_whitespace(std::string_view text) {
    return text.find_first_of(" \t\r\n") != std::string_view::npos;
}

bool stdin_is_interactive() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}


bool confirm_action(const std::string& prompt, bool default_yes, bool assume_yes) {
    if (assume_yes || !stdin_is_interactive()) {
        return default_yes;
    }

    const std::string suffix = default_yes ? " [Y/n]: " : " [y/N]: ";
    while (true) {
        std::cout << prompt << suffix;
        std::cout.flush();
        std::string input;
        if (!std::getline(std::cin, input)) {
            return default_yes;
        }
        input = to_lower(trim(input));
        if (input.empty()) {
            return default_yes;
        }
        if (input == "y" || input == "yes" || input == "s" || input == "si" || input == "sí") {
            return true;
        }
        if (input == "n" || input == "no") {
            return false;
        }
        std::cout << "Unrecognized answer. Type 'y' for yes or 'n' for no." << std::endl;
    }
}

bool acknowledge_control_exposure(const GlobalOptions& options, const ephemeralnet::Config& config) {
    if (!options.control_expose_requested) {
        return true;
    }

    const std::string endpoint = config.control_host + ':' + std::to_string(config.control_port);
    const std::string prompt =
        "WARNING: the control plane will listen on " + endpoint + " and accept remote connections. Proceed?";

    if (!options.assume_yes) {
        const bool proceed = confirm_action(prompt, false, false);
        if (!proceed) {
            std::cout << "Aborting; control plane will stay on loopback." << std::endl;
            return false;
        }
    } else {
        std::cout << "WARNING: exposing control plane on " << endpoint << " (auto-approved by --yes)." << std::endl;
    }

    if (!config.control_token.has_value()) {
        std::cout << "Hint: set --control-token or control.token in your profile to avoid unauthenticated remote commands." << std::endl;
    }

    return true;
}

void print_daemon_failure(const ephemeralnet::daemon::ControlResponse& response) {
    const auto code_it = response.fields.find("CODE");
    const auto message_it = response.fields.find("MESSAGE");
    const auto hint_it = response.fields.find("HINT");

    const std::string code = code_it != response.fields.end() && !code_it->second.empty()
                                 ? code_it->second
                                 : std::string{"ERR_DAEMON_UNKNOWN"};
    const std::string message = message_it != response.fields.end() && !message_it->second.empty()
                                    ? message_it->second
                                    : std::string{"Daemon operation failed"};

    std::cerr << "Daemon error [" << code << "]: " << message << std::endl;
    if (hint_it != response.fields.end() && !hint_it->second.empty()) {
        std::cerr << "Hint: " << hint_it->second << std::endl;
    }
}

void print_daemon_hint(const ephemeralnet::daemon::ControlResponse& response) {
    const auto hint_it = response.fields.find("HINT");
    if (hint_it != response.fields.end() && !hint_it->second.empty()) {
        std::cout << "Hint: " << hint_it->second << std::endl;
    }
}

void print_cli_error(const CliException& ex) {
    std::cerr << ex.what() << std::endl;
    if (!ex.hint().empty()) {
        std::cerr << "Hint: " << ex.hint() << std::endl;
    }
}

std::string format_bytes(std::size_t bytes) {
    constexpr std::array<const char*, 5> kUnits{"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit_index = 0;
    while (value >= 1024.0 && unit_index + 1 < kUnits.size()) {
        value /= 1024.0;
        ++unit_index;
    }

    std::ostringstream oss;
    oss << std::fixed;
    if (unit_index == 0 || value >= 100.0) {
        oss << std::setprecision(0);
    } else {
        oss << std::setprecision(1);
    }
    oss << value << ' ' << kUnits[unit_index];
    return oss.str();
}

struct FetchDiscoveryOptions {
    bool direct_only{false};
    bool auto_token{true};
    bool transport_only{false};
    bool control_fallback_only{false};
    std::uint64_t max_attempts{250'000};
    std::optional<std::string> token_override{};
};

struct BootstrapAttemptLog {
    std::string endpoint;
    std::string message;
};

std::optional<std::pair<std::string, std::uint16_t>> parse_control_endpoint(const std::string& endpoint) {
    if (endpoint.empty()) {
        return std::nullopt;
    }
    const auto pos = endpoint.find_last_of(':');
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    std::string host = endpoint.substr(0, pos);
    std::string port_text = endpoint.substr(pos + 1);
    if (host.empty() || port_text.empty()) {
        return std::nullopt;
    }
    try {
        const auto numeric = std::stoul(port_text);
        if (numeric == 0 || numeric > std::numeric_limits<std::uint16_t>::max()) {
            return std::nullopt;
        }
        return std::make_pair(host, static_cast<std::uint16_t>(numeric));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string describe_endpoint(const std::string& host, std::uint16_t port) {
    return host + ":" + std::to_string(port);
}

std::optional<std::pair<std::string, std::uint16_t>> parse_control_uri(const std::string& uri) {
    constexpr std::string_view kScheme{"control://"};
    if (uri.rfind(kScheme, 0) != 0) {
        return std::nullopt;
    }
    const auto address = uri.substr(kScheme.size());
    return parse_control_endpoint(address);
}

std::optional<std::string> split_advertise_control_endpoint(const std::string& raw,
                                                            std::string& host_out,
                                                            std::optional<std::uint16_t>& port_out);
std::string format_advertise_control_argument(const std::string& host,
                                              const std::optional<std::uint16_t>& port);

std::optional<std::string> compute_bootstrap_token(const protocol::Manifest& manifest,
                                                   const protocol::DiscoveryHint& hint,
                                                   const FetchDiscoveryOptions& options) {
    if (options.token_override.has_value()) {
        return options.token_override;
    }
    if (manifest.security.token_challenge_bits == 0) {
        return std::string{"0"};
    }
    if (!options.auto_token) {
        return std::nullopt;
    }
    const auto solved = bootstrap::solve_token_challenge(manifest,
                                                         hint,
                                                         manifest.security.token_challenge_bits,
                                                         options.max_attempts);
    if (!solved.has_value()) {
        return std::nullopt;
    }
    return std::to_string(*solved);
}

constexpr std::size_t kTransportMaxPayloadSize = 1 * 1024 * 1024;
constexpr std::size_t kTransportNonceSize = ephemeralnet::crypto::Nonce{}.bytes.size();
constexpr std::size_t kTransportLengthFieldSize = sizeof(std::uint32_t);
constexpr std::uint64_t kTransportPowMaxAttempts = 500'000;
constexpr std::chrono::milliseconds kTransportHandshakeTimeout{2000};
constexpr std::chrono::milliseconds kTransportResponseTimeout{15000};

bool parse_uint32(std::string_view text, std::uint32_t& value);

std::size_t count_leading_zero_bits(std::span<const std::uint8_t> digest) {
    std::size_t total = 0;
    for (const auto byte : digest) {
        if (byte == 0) {
            total += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte >> bit) & 0x01u) {
                return total;
            }
            ++total;
        }
        return total;
    }
    return total;
}

std::array<std::uint8_t, 8> to_big_endian_bytes(std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (int index = 0; index < 8; ++index) {
        const auto shift = 56 - index * 8;
        bytes[index] = static_cast<std::uint8_t>((value >> shift) & 0xFFu);
    }
    return bytes;
}

void update_length_prefixed(ephemeralnet::crypto::Sha256& hasher, std::span<const std::uint8_t> data) {
    const auto length_bytes = to_big_endian_bytes(static_cast<std::uint64_t>(data.size()));
    hasher.update(length_bytes);
    if (!data.empty()) {
        hasher.update(data);
    }
}

std::array<std::uint8_t, 32> transport_handshake_digest(const ephemeralnet::PeerId& initiator,
                                                         const ephemeralnet::PeerId& responder,
                                                         std::uint32_t initiator_public,
                                                         std::uint64_t nonce) {
    ephemeralnet::crypto::Sha256 hasher;
    update_length_prefixed(hasher, std::span<const std::uint8_t>(initiator.data(), initiator.size()));
    update_length_prefixed(hasher, std::span<const std::uint8_t>(responder.data(), responder.size()));
    const auto public_bytes = to_big_endian_bytes(static_cast<std::uint64_t>(initiator_public));
    hasher.update(public_bytes);
    const auto nonce_bytes = to_big_endian_bytes(nonce);
    hasher.update(nonce_bytes);
    return hasher.finalize();
}

bool transport_pow_valid(const ephemeralnet::PeerId& initiator,
                         const ephemeralnet::PeerId& responder,
                         std::uint32_t initiator_public,
                         std::uint64_t nonce,
                         std::uint8_t difficulty) {
    if (difficulty == 0) {
        return true;
    }
    const auto digest = transport_handshake_digest(initiator, responder, initiator_public, nonce);
    return count_leading_zero_bits(std::span<const std::uint8_t>(digest.data(), digest.size())) >= difficulty;
}

std::optional<std::uint64_t> compute_transport_pow(const ephemeralnet::PeerId& initiator,
                                                   const ephemeralnet::PeerId& responder,
                                                   std::uint32_t initiator_public,
                                                   std::uint8_t difficulty) {
    if (difficulty == 0) {
        return std::uint64_t{0};
    }
    const auto digest = transport_handshake_digest(initiator, responder, initiator_public, 0);
    std::uint64_t seed = 0;
    for (int index = 0; index < 8; ++index) {
        seed = (seed << 8) | static_cast<std::uint64_t>(digest[index]);
    }
    std::mt19937_64 generator(seed);
    std::uniform_int_distribution<std::uint64_t> distribution(0, std::numeric_limits<std::uint64_t>::max());
    const auto start = distribution(generator);
    for (std::uint64_t attempt = 0; attempt < kTransportPowMaxAttempts; ++attempt) {
        const auto candidate = start + attempt;
        if (transport_pow_valid(initiator, responder, initiator_public, candidate, difficulty)) {
            return candidate;
        }
    }
    return std::nullopt;
}

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidNativeSocket = INVALID_SOCKET;

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

WinsockRuntime& ensure_winsock_runtime() {
    static WinsockRuntime runtime;
    return runtime;
}

int last_socket_error() {
    return WSAGetLastError();
}
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidNativeSocket = -1;

void ensure_winsock_runtime() {}

int last_socket_error() {
    return errno;
}
#endif

class ScopedSocket {
public:
    ScopedSocket() = default;
    explicit ScopedSocket(NativeSocket handle) : handle_(handle) {}
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;
    ScopedSocket(ScopedSocket&& other) noexcept : handle_(other.handle_) {
        other.handle_ = kInvalidNativeSocket;
    }
    ScopedSocket& operator=(ScopedSocket&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = kInvalidNativeSocket;
        }
        return *this;
    }
    ~ScopedSocket() { reset(); }

    NativeSocket get() const { return handle_; }
    bool valid() const { return handle_ != kInvalidNativeSocket; }
    explicit operator bool() const { return valid(); }

    void reset(NativeSocket handle = kInvalidNativeSocket) {
        if (handle_ != kInvalidNativeSocket) {
#ifdef _WIN32
            ::shutdown(handle_, SD_BOTH);
            ::closesocket(handle_);
#else
            ::shutdown(handle_, SHUT_RDWR);
            ::close(handle_);
#endif
        }
        handle_ = handle;
    }

private:
    NativeSocket handle_{kInvalidNativeSocket};
};

bool socket_send_all(NativeSocket socket, const std::uint8_t* data, std::size_t length) {
    std::size_t sent_total = 0;
    while (sent_total < length) {
#ifdef _WIN32
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data + sent_total),
                                 static_cast<int>(length - sent_total), 0);
#else
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data + sent_total),
                                 length - sent_total, 0);
#endif
        if (sent <= 0) {
            return false;
        }
        sent_total += static_cast<std::size_t>(sent);
    }
    return true;
}

bool socket_recv_all(NativeSocket socket, std::uint8_t* buffer, std::size_t length) {
    std::size_t received_total = 0;
    while (received_total < length) {
#ifdef _WIN32
        const auto received = ::recv(socket, reinterpret_cast<char*>(buffer + received_total),
                                     static_cast<int>(length - received_total), 0);
#else
        const auto received = ::recv(socket, reinterpret_cast<char*>(buffer + received_total),
                                     length - received_total, 0);
#endif
        if (received <= 0) {
            return false;
        }
        received_total += static_cast<std::size_t>(received);
    }
    return true;
}

bool socket_set_timeout(NativeSocket socket, std::chrono::milliseconds timeout) {
#ifdef _WIN32
    const DWORD value = static_cast<DWORD>(timeout.count());
    return ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
#else
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    return ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#endif
}

std::string socket_endpoint(NativeSocket socket) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (::getpeername(socket, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
        char buffer[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer))) {
            return std::string(buffer) + ":" + std::to_string(ntohs(addr.sin_port));
        }
    }
    return std::string{"unknown"};
}

std::string format_socket_error(const std::string& prefix) {
    const auto code = last_socket_error();
#ifdef _WIN32
    return prefix + " (WSA" + std::to_string(code) + ")";
#else
    return prefix + " (errno " + std::to_string(code) + ": " + std::strerror(code) + ")";
#endif
}

std::optional<ScopedSocket> open_transport_socket(const std::string& host, std::uint16_t port) {
    ensure_winsock_runtime();

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    if (const auto err = ::getaddrinfo(host.c_str(), nullptr, &hints, &result); err != 0 || result == nullptr) {
        if (result) {
            ::freeaddrinfo(result);
        }
        return std::nullopt;
    }

    ScopedSocket socket{};
    NativeSocket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == kInvalidNativeSocket) {
        ::freeaddrinfo(result);
        return std::nullopt;
    }

    socket.reset(handle);

    sockaddr_in address = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
    address.sin_port = htons(port);
    ::freeaddrinfo(result);

    if (::connect(socket.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        return std::nullopt;
    }

    return socket;
}

struct PublisherIdentityMetadata {
    ephemeralnet::PeerId peer_id{};
    std::uint32_t public_identity{0};
};

std::optional<PublisherIdentityMetadata> extract_publisher_identity(const protocol::Manifest& manifest) {
    const auto peer_it = manifest.metadata.find("publisher_peer");
    const auto public_it = manifest.metadata.find("publisher_public");
    if (peer_it == manifest.metadata.end() || public_it == manifest.metadata.end()) {
        return std::nullopt;
    }

    const auto peer = ephemeralnet::peer_id_from_string(peer_it->second);
    if (!peer.has_value()) {
        return std::nullopt;
    }

    std::uint32_t public_identity = 0;
    if (!parse_uint32(public_it->second, public_identity)) {
        return std::nullopt;
    }

    PublisherIdentityMetadata metadata{};
    metadata.peer_id = *peer;
    metadata.public_identity = public_identity;
    return metadata;
}

std::optional<ephemeralnet::ChunkData> decrypt_chunk_with_manifest(const protocol::Manifest& manifest,
                                                                   const protocol::ChunkPayload& payload) {
    if (manifest.threshold == 0 || manifest.shards.size() < manifest.threshold) {
        return std::nullopt;
    }

    std::vector<ephemeralnet::crypto::ShamirShare> shares;
    shares.reserve(manifest.shards.size());
    for (const auto& shard : manifest.shards) {
        ephemeralnet::crypto::ShamirShare share{};
        share.index = shard.index;
        share.value = shard.value;
        shares.push_back(share);
    }

    const auto secret = ephemeralnet::crypto::Shamir::combine(shares, manifest.threshold);
    ephemeralnet::crypto::Key chunk_key{};
    chunk_key.bytes = secret;

    const auto plaintext = ephemeralnet::crypto::CryptoManager::decrypt_with_key(
        chunk_key,
        manifest.chunk_id,
        std::span<const std::uint8_t>(payload.data.data(), payload.data.size()),
        manifest.nonce);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }

    const auto digest = ephemeralnet::crypto::Sha256::digest(std::span<const std::uint8_t>(plaintext->data(), plaintext->size()));
    if (digest != manifest.chunk_hash) {
        return std::nullopt;
    }

    return plaintext;
}

bool manifest_expired(const protocol::Manifest& manifest) {
    const auto now = std::chrono::system_clock::now();
    return manifest.expires_at <= now;
}

bool write_payload_to_file(const std::filesystem::path& destination,
                           std::span<const std::uint8_t> payload) {
    try {
        std::ofstream out(destination, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
        if (!payload.empty()) {
            out.write(reinterpret_cast<const char*>(payload.data()),
                      static_cast<std::streamsize>(payload.size()));
        }
        out.flush();
        return static_cast<bool>(out);
    } catch (const std::exception&) {
        return false;
    }
}

struct TransportIdentityContext {
    ephemeralnet::PeerId peer_id{};
    std::uint32_t private_scalar{0};
    std::uint32_t public_scalar{0};
};

struct TransportSessionContext {
    ScopedSocket socket;
    std::array<std::uint8_t, 32> session_key{};
    std::uint8_t negotiated_version{protocol::kMinimumMessageVersion};
};

std::optional<std::vector<std::uint8_t>> read_encrypted_message(NativeSocket socket,
                                                                const std::array<std::uint8_t, 32>& key,
                                                                std::chrono::milliseconds timeout) {
    if (!socket_set_timeout(socket, timeout)) {
        return std::nullopt;
    }

    std::array<std::uint8_t, kTransportNonceSize> nonce_buffer{};
    if (!socket_recv_all(socket, nonce_buffer.data(), nonce_buffer.size())) {
        socket_set_timeout(socket, std::chrono::milliseconds::zero());
        return std::nullopt;
    }

    std::array<std::uint8_t, kTransportLengthFieldSize> length_buffer{};
    if (!socket_recv_all(socket, length_buffer.data(), length_buffer.size())) {
        socket_set_timeout(socket, std::chrono::milliseconds::zero());
        return std::nullopt;
    }

    const auto length = (static_cast<std::uint32_t>(length_buffer[0]) << 24)
        | (static_cast<std::uint32_t>(length_buffer[1]) << 16)
        | (static_cast<std::uint32_t>(length_buffer[2]) << 8)
        | static_cast<std::uint32_t>(length_buffer[3]);

    if (length > kTransportMaxPayloadSize) {
        socket_set_timeout(socket, std::chrono::milliseconds::zero());
        return std::nullopt;
    }

    std::vector<std::uint8_t> ciphertext(length);
    if (length > 0 && !socket_recv_all(socket, ciphertext.data(), ciphertext.size())) {
        socket_set_timeout(socket, std::chrono::milliseconds::zero());
        return std::nullopt;
    }

    socket_set_timeout(socket, std::chrono::milliseconds::zero());

    ephemeralnet::crypto::Key key_material{};
    key_material.bytes = key;
    ephemeralnet::crypto::Nonce nonce{};
    std::copy(nonce_buffer.begin(), nonce_buffer.end(), nonce.bytes.begin());

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    ephemeralnet::crypto::ChaCha20::apply(key_material, nonce, ciphertext, plaintext, 0u);
    return plaintext;
}

bool send_encrypted_message(NativeSocket socket,
                            const std::array<std::uint8_t, 32>& key,
                            std::span<const std::uint8_t> payload) {
    if (payload.size() > kTransportMaxPayloadSize) {
        return false;
    }

    ephemeralnet::crypto::Key key_material{};
    key_material.bytes = key;

    ephemeralnet::crypto::Nonce nonce{};
    std::random_device rd;
    for (auto& byte : nonce.bytes) {
        byte = static_cast<std::uint8_t>(rd());
    }

    std::vector<std::uint8_t> ciphertext(payload.size());
    ephemeralnet::crypto::ChaCha20::apply(key_material, nonce, payload, ciphertext, 0u);

    std::vector<std::uint8_t> buffer(kTransportNonceSize + kTransportLengthFieldSize + ciphertext.size());
    std::copy(nonce.bytes.begin(), nonce.bytes.end(), buffer.begin());

    const auto length = static_cast<std::uint32_t>(ciphertext.size());
    buffer[kTransportNonceSize + 0] = static_cast<std::uint8_t>((length >> 24) & 0xFFu);
    buffer[kTransportNonceSize + 1] = static_cast<std::uint8_t>((length >> 16) & 0xFFu);
    buffer[kTransportNonceSize + 2] = static_cast<std::uint8_t>((length >> 8) & 0xFFu);
    buffer[kTransportNonceSize + 3] = static_cast<std::uint8_t>(length & 0xFFu);
    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + kTransportNonceSize + kTransportLengthFieldSize);

    return socket_send_all(socket, buffer.data(), buffer.size());
}

std::optional<std::string> socket_read_line(NativeSocket socket, std::chrono::milliseconds timeout) {
    const bool with_timeout = timeout.count() > 0;
    if (with_timeout && !socket_set_timeout(socket, timeout)) {
        return std::nullopt;
    }

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
            if (with_timeout) {
                socket_set_timeout(socket, std::chrono::milliseconds{0});
            }
            return std::nullopt;
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            buffer.push_back(ch);
        }
    }

    if (with_timeout) {
        socket_set_timeout(socket, std::chrono::milliseconds{0});
    }
    return buffer;
}

struct RelayHintEndpoint {
    std::string host;
    std::uint16_t port{0};
    std::optional<ephemeralnet::PeerId> remote_peer;
};

std::optional<RelayHintEndpoint> parse_relay_hint_endpoint(const std::string& endpoint) {
    const auto query_pos = endpoint.find('?');
    const auto address = endpoint.substr(0, query_pos);
    const auto parsed = parse_control_endpoint(address);
    if (!parsed.has_value()) {
        return std::nullopt;
    }

    RelayHintEndpoint details{};
    details.host = parsed->first;
    details.port = parsed->second;

    if (query_pos != std::string::npos && query_pos + 1 < endpoint.size()) {
        const auto query = endpoint.substr(query_pos + 1);
        constexpr std::string_view kPeerPrefix{"peer="};
        if (query.rfind(kPeerPrefix, 0) == 0 && query.size() > kPeerPrefix.size()) {
            const auto hex = query.substr(kPeerPrefix.size());
            if (const auto remote = ephemeralnet::peer_id_from_string(hex)) {
                details.remote_peer = *remote;
            } else {
                return std::nullopt;
            }
        }
    }

    return details;
}

std::optional<TransportSessionContext> complete_transport_handshake(ScopedSocket socket,
                                                                     const TransportIdentityContext& local,
                                                                     const PublisherIdentityMetadata& remote,
                                                                     std::uint64_t work_nonce,
                                                                     std::string* error_out) {
    if (!socket_send_all(socket.get(), local.peer_id.data(), local.peer_id.size())) {
        if (error_out) {
            *error_out = format_socket_error("Failed to send identity");
        }
        return std::nullopt;
    }

    protocol::Message handshake{};
    handshake.version = protocol::kCurrentMessageVersion;
    handshake.type = protocol::MessageType::TransportHandshake;
    protocol::TransportHandshakePayload handshake_payload{};
    handshake_payload.public_identity = local.public_scalar;
    handshake_payload.work_nonce = work_nonce;
    handshake_payload.requested_version = protocol::kCurrentMessageVersion;
    handshake.payload = handshake_payload;

    const auto encoded = protocol::encode(handshake);
    std::vector<std::uint8_t> frame(sizeof(std::uint32_t) + encoded.size());
    const auto length = static_cast<std::uint32_t>(encoded.size());
    frame[0] = static_cast<std::uint8_t>((length >> 24) & 0xFFu);
    frame[1] = static_cast<std::uint8_t>((length >> 16) & 0xFFu);
    frame[2] = static_cast<std::uint8_t>((length >> 8) & 0xFFu);
    frame[3] = static_cast<std::uint8_t>(length & 0xFFu);
    std::copy(encoded.begin(), encoded.end(), frame.begin() + sizeof(std::uint32_t));

    if (!socket_send_all(socket.get(), frame.data(), frame.size())) {
        if (error_out) {
            *error_out = format_socket_error("Failed to send handshake");
        }
        return std::nullopt;
    }

    const auto shared = ephemeralnet::network::KeyExchange::derive_shared_secret(local.private_scalar,
                                                                                 remote.public_identity);
    
    std::array<std::uint32_t, 2> ordered_publics{local.public_scalar, remote.public_identity};
    std::sort(ordered_publics.begin(), ordered_publics.end());

    std::array<std::uint8_t, 8> material{};
    for (std::size_t index = 0; index < ordered_publics.size(); ++index) {
        const auto value = ordered_publics[index];
        for (std::size_t byte = 0; byte < 4; ++byte) {
            const auto shift = static_cast<std::uint32_t>((3 - byte) * 8);
            material[index * 4 + byte] = static_cast<std::uint8_t>((value >> shift) & 0xFFu);
        }
    }

    const auto shared_span = std::span<const std::uint8_t>(shared.bytes);
    const auto material_span = std::span<const std::uint8_t>(material);
    const auto derived_key = ephemeralnet::crypto::HmacSha256::compute(shared_span, material_span);
    std::array<std::uint8_t, 32> session_key = derived_key;

    auto ack_plaintext = read_encrypted_message(socket.get(), session_key, kTransportHandshakeTimeout);
    if (!ack_plaintext.has_value()) {
        if (error_out) {
            *error_out = "Timed out waiting for handshake ACK";
        }
        return std::nullopt;
    }

    const auto key_span = std::span<const std::uint8_t>(session_key.data(), session_key.size());
    const auto ack_message = protocol::decode_signed(*ack_plaintext, key_span);
    if (!ack_message.has_value() || ack_message->type != protocol::MessageType::HandshakeAck) {
        if (error_out) {
            *error_out = "Invalid handshake ACK";
        }
        return std::nullopt;
    }
    const auto* ack_payload = std::get_if<protocol::HandshakeAckPayload>(&ack_message->payload);
    if (!ack_payload || !ack_payload->accepted) {
        if (error_out) {
            *error_out = "Peer rejected transport handshake";
        }
        return std::nullopt;
    }

    const auto negotiated_version = ack_payload->negotiated_version;
    TransportSessionContext context{};
    context.socket = std::move(socket);
    context.session_key = session_key;
    context.negotiated_version = std::clamp<std::uint8_t>(negotiated_version,
                                                          protocol::kMinimumMessageVersion,
                                                          protocol::kCurrentMessageVersion);
    return context;
}

std::optional<TransportSessionContext> establish_transport_session(const TransportIdentityContext& local,
                                                                   const PublisherIdentityMetadata& remote,
                                                                   std::uint64_t work_nonce,
                                                                   const std::string& host,
                                                                   std::uint16_t port,
                                                                   std::string* error_out = nullptr) {
    auto socket_opt = open_transport_socket(host, port);
    if (!socket_opt.has_value()) {
        if (error_out) {
            *error_out = "Unable to connect";
        }
        return std::nullopt;
    }

    return complete_transport_handshake(std::move(*socket_opt),
                                        local,
                                        remote,
                                        work_nonce,
                                        error_out);
}

bool send_protocol_message(NativeSocket socket,
                           const std::array<std::uint8_t, 32>& session_key,
                           protocol::Message& message) {
    const auto key_span = std::span<const std::uint8_t>(session_key.data(), session_key.size());
    auto encoded = protocol::encode_signed(message, key_span);
    return send_encrypted_message(socket, session_key, encoded);
}

std::optional<protocol::Message> receive_protocol_message(NativeSocket socket,
                                                          const std::array<std::uint8_t, 32>& session_key,
                                                          std::chrono::milliseconds timeout) {
    const auto plaintext = read_encrypted_message(socket, session_key, timeout);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }
    const auto key_span = std::span<const std::uint8_t>(session_key.data(), session_key.size());
    return protocol::decode_signed(*plaintext, key_span);
}

class ProgressPrinter {
public:
    explicit ProgressPrinter(std::string label) : label_(std::move(label)) {}

    void update(std::size_t current, std::size_t total) {
        if (finished_) {
            return;
        }
        started_ = true;
        const double ratio = total == 0
                                  ? 1.0
                                  : std::clamp(static_cast<double>(current) / static_cast<double>(total), 0.0, 1.0);
        const int percent = static_cast<int>(std::round(ratio * 100.0));
        if (percent == last_percent_ && current < total) {
            return;
        }
        last_percent_ = percent;
        std::cout << '\r' << label_ << ": "
                  << std::setw(3) << percent << "% ("
                  << format_bytes(current) << " / "
                  << format_bytes(total) << ')'
                  << std::flush;
        if (current >= total || total == 0) {
            std::cout << std::endl;
            finished_ = true;
        }
    }

    void finish(std::size_t total) {
        if (!started_) {
            started_ = true;
        }
        if (!finished_) {
            update(total, total);
        }
    }

    void cancel() {
        if (started_ && !finished_) {
            std::cout << std::endl;
            finished_ = true;
        }
    }

    bool started() const noexcept { return started_; }
    bool finished() const noexcept { return finished_; }

private:
    std::string label_;
    int last_percent_{-1};
    bool started_{false};
    bool finished_{false};
};

namespace config {

enum class ValueType {
    Null,
    Boolean,
    Integer,
    Double,
    String,
    Object,
    Array
};

struct Value {
    ValueType type{ValueType::Null};
    bool boolean_value{false};
    std::int64_t integer_value{0};
    double double_value{0.0};
    std::string string_value;
    std::map<std::string, Value> object_value;
    std::vector<Value> array_value;

    Value() = default;
    explicit Value(bool value) : type(ValueType::Boolean), boolean_value(value) {}
    explicit Value(std::int64_t value) : type(ValueType::Integer), integer_value(value) {}
    explicit Value(double value) : type(ValueType::Double), double_value(value) {}
    explicit Value(std::string value) : type(ValueType::String), string_value(std::move(value)) {}
    Value(const char* value) : Value(std::string(value)) {}

    static Value make_object() {
        Value value;
        value.type = ValueType::Object;
        return value;
    }

    static Value make_array() {
        Value value;
        value.type = ValueType::Array;
        return value;
    }

    bool is_null() const { return type == ValueType::Null; }
    bool is_boolean() const { return type == ValueType::Boolean; }
    bool is_integer() const { return type == ValueType::Integer; }
    bool is_double() const { return type == ValueType::Double; }
    bool is_number() const { return is_integer() || is_double(); }
    bool is_string() const { return type == ValueType::String; }
    bool is_object() const { return type == ValueType::Object; }
    bool is_array() const { return type == ValueType::Array; }

    std::map<std::string, Value>& ensure_object() {
        if (type != ValueType::Object) {
            type = ValueType::Object;
            object_value.clear();
            array_value.clear();
            string_value.clear();
        }
        return object_value;
    }

    std::vector<Value>& ensure_array() {
        if (type != ValueType::Array) {
            type = ValueType::Array;
            array_value.clear();
            object_value.clear();
            string_value.clear();
        }
        return array_value;
    }

    const std::map<std::string, Value>& as_object() const {
        static const std::map<std::string, Value> empty{};
        return type == ValueType::Object ? object_value : empty;
    }

    std::map<std::string, Value>& as_object() { return ensure_object(); }

    const std::vector<Value>& as_array() const {
        static const std::vector<Value> empty{};
        return type == ValueType::Array ? array_value : empty;
    }

    std::vector<Value>& as_array() { return ensure_array(); }
};

struct ConfigError : public std::exception {
    std::string code;
    std::string message;
    std::string hint;
    std::string formatted;

    ConfigError(std::string c, std::string m, std::string h = {})
        : code(std::move(c)), message(std::move(m)), hint(std::move(h)) {
        if (!code.empty()) {
            formatted = "[" + code + "] " + message;
        } else {
            formatted = message;
        }
    }

    const char* what() const noexcept override { return formatted.c_str(); }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& text) : text_(text) {}

    Value parse() {
        skip_whitespace();
        Value value = parse_value();
        skip_whitespace();
        if (!at_end()) {
            throw ConfigError("E_CONFIG_PARSE", "Unexpected trailing content in JSON config");
        }
        return value;
    }

private:
    const std::string& text_;
    std::size_t position_{0};

    bool at_end() const { return position_ >= text_.size(); }

    char peek() const { return at_end() ? '\0' : text_[position_]; }

    char get() { return at_end() ? '\0' : text_[position_++]; }

    void skip_whitespace() {
        while (!at_end()) {
            const char ch = peek();
            if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
                ++position_;
            } else {
                break;
            }
        }
    }

    Value parse_value() {
        skip_whitespace();
        if (at_end()) {
            throw ConfigError("E_CONFIG_PARSE", "Unexpected end of JSON while parsing value");
        }

        const char ch = peek();
        if (ch == '{') {
            return parse_object();
        }
        if (ch == '[') {
            return parse_array();
        }
        if (ch == '"') {
            return Value(parse_string());
        }
        if (ch == 't' || ch == 'f') {
            return Value(parse_boolean());
        }
        if (ch == 'n') {
            parse_null();
            return Value();
        }
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch))) {
            return parse_number();
        }
        throw ConfigError("E_CONFIG_PARSE", "Unexpected token in JSON value");
    }

    Value parse_object() {
        Value object = Value::make_object();
        get();  // consume '{'
        skip_whitespace();
        if (peek() == '}') {
            get();
            return object;
        }

        auto& fields = object.as_object();
        while (true) {
            skip_whitespace();
            if (peek() != '"') {
                throw ConfigError("E_CONFIG_PARSE", "Expected string key in JSON object");
            }

            std::string key = parse_string();
            skip_whitespace();
            if (get() != ':') {
                throw ConfigError("E_CONFIG_PARSE", "Expected ':' after key in JSON object");
            }

            Value value = parse_value();
            fields.emplace(std::move(key), std::move(value));

            skip_whitespace();
            if (at_end()) {
                throw ConfigError("E_CONFIG_PARSE", "Unexpected end of JSON while parsing object");
            }
            const char ch = get();
            if (ch == '}') {
                break;
            }
            if (ch != ',') {
                throw ConfigError("E_CONFIG_PARSE", "Expected ',' or '}' in JSON object");
            }
            skip_whitespace();
        }
        return object;
    }

    Value parse_array() {
        Value array = Value::make_array();
        get();  // consume '['
        skip_whitespace();
        if (peek() == ']') {
            get();
            return array;
        }

        auto& elements = array.as_array();
        while (true) {
            elements.push_back(parse_value());
            skip_whitespace();
            if (at_end()) {
                throw ConfigError("E_CONFIG_PARSE", "Unexpected end of JSON while parsing array");
            }
            const char ch = get();
            if (ch == ']') {
                break;
            }
            if (ch != ',') {
                throw ConfigError("E_CONFIG_PARSE", "Expected ',' or ']' in JSON array");
            }
            skip_whitespace();
        }
        return array;
    }

    std::string parse_string() {
        if (get() != '"') {
            throw ConfigError("E_CONFIG_PARSE", "Expected opening quote for JSON string");
        }

        std::string result;
        while (!at_end()) {
            char ch = get();
            if (ch == '"') {
                return result;
            }

            if (ch == '\\') {
                if (at_end()) {
                    throw ConfigError("E_CONFIG_PARSE", "Incomplete escape sequence in JSON string");
                }

                const char esc = get();
                switch (esc) {
                case '"':
                case '\\':
                case '/':
                    result.push_back(esc);
                    break;
                case 'b':
                    result.push_back('\b');
                    break;
                case 'f':
                    result.push_back('\f');
                    break;
                case 'n':
                    result.push_back('\n');
                    break;
                case 'r':
                    result.push_back('\r');
                    break;
                case 't':
                    result.push_back('\t');
                    break;
                case 'u':
                    result += parse_unicode_escape();
                    break;
                default:
                    throw ConfigError("E_CONFIG_PARSE", "Unsupported escape sequence in JSON string");
                }
            } else {
                if (static_cast<unsigned char>(ch) < 0x20) {
                    throw ConfigError("E_CONFIG_PARSE", "Control characters must be escaped in JSON strings");
                }
                result.push_back(ch);
            }
        }

        throw ConfigError("E_CONFIG_PARSE", "Unterminated JSON string literal");
    }

    std::string parse_unicode_escape() {
        if (position_ + 4 > text_.size()) {
            throw ConfigError("E_CONFIG_PARSE", "Incomplete unicode escape in JSON string");
        }
        unsigned int code_point = 0;
        for (int i = 0; i < 4; ++i) {
            const char ch = text_[position_++];
            code_point <<= 4;
            if (ch >= '0' && ch <= '9') {
                code_point += static_cast<unsigned int>(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                code_point += 10u + static_cast<unsigned int>(ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                code_point += 10u + static_cast<unsigned int>(ch - 'A');
            } else {
                throw ConfigError("E_CONFIG_PARSE", "Invalid hex digit in unicode escape");
            }
        }

        std::string utf8;
        if (code_point <= 0x7F) {
            utf8.push_back(static_cast<char>(code_point));
        } else if (code_point <= 0x7FF) {
            utf8.push_back(static_cast<char>(0xC0 | ((code_point >> 6) & 0x1F)));
            utf8.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
        } else {
            utf8.push_back(static_cast<char>(0xE0 | ((code_point >> 12) & 0x0F)));
            utf8.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
        }
        return utf8;
    }

    Value parse_number() {
        const std::size_t start = position_;
        if (peek() == '-') {
            ++position_;
        }
        while (std::isdigit(static_cast<unsigned char>(peek()))) {
            ++position_;
        }
        bool is_fractional = false;
        if (peek() == '.') {
            is_fractional = true;
            ++position_;
            while (std::isdigit(static_cast<unsigned char>(peek()))) {
                ++position_;
            }
        }
        if (peek() == 'e' || peek() == 'E') {
            is_fractional = true;
            ++position_;
            if (peek() == '+' || peek() == '-') {
                ++position_;
            }
            while (std::isdigit(static_cast<unsigned char>(peek()))) {
                ++position_;
            }
        }
        const std::string_view token(text_.data() + start, position_ - start);
        const char* token_begin = token.data();
        const char* token_end = token_begin + token.size();
        if (is_fractional) {
            double value{};
            if (!parse_floating_token(token_begin, token_end, value)) {
                throw ConfigError("E_CONFIG_PARSE", "Invalid floating point number in JSON");
            }
            return Value(value);
        }
        std::int64_t int_value{};
        auto result = std::from_chars(token_begin, token_end, int_value);
        if (result.ec != std::errc{}) {
            throw ConfigError("E_CONFIG_PARSE", "Invalid integer number in JSON");
        }
        return Value(int_value);
    }

    bool parse_boolean() {
        if (text_.compare(position_, 4, "true") == 0) {
            position_ += 4;
            return true;
        }
        if (text_.compare(position_, 5, "false") == 0) {
            position_ += 5;
            return false;
        }
        throw ConfigError("E_CONFIG_PARSE", "Invalid boolean literal in JSON");
    }

    void parse_null() {
        if (text_.compare(position_, 4, "null") != 0) {
            throw ConfigError("E_CONFIG_PARSE", "Invalid null literal in JSON");
        }
        position_ += 4;
    }
};

static std::string trim_left(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
                    return !std::isspace(ch);
                }));
    return value;
}

static std::string trim_right(std::string value) {
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
                    return !std::isspace(ch);
                }).base(),
                value.end());
    return value;
}

static std::string trim_copy(const std::string& value) {
    std::string result = trim_left(value);
    return trim_right(result);
}

Value parse_yaml_scalar(const std::string& text) {
    const std::string trimmed = trim_copy(text);
    if (trimmed.empty()) {
        return Value();
    }
    if ((trimmed.front() == '"' && trimmed.back() == '"') || (trimmed.front() == '\'' && trimmed.back() == '\'')) {
        const char quote = trimmed.front();
        std::string inner = trimmed.substr(1, trimmed.size() - 2);
        if (quote == '\'') {
            return Value(inner);
        }
        std::string synthetic = "\"" + inner + "\"";
        JsonParser parser(synthetic);
        Value parsed = parser.parse();
        if (!parsed.is_string()) {
            throw ConfigError("E_CONFIG_PARSE", "Expected string literal in YAML value");
        }
        return Value(parsed.string_value);
    }
    if (trimmed == "true" || trimmed == "True") {
        return Value(true);
    }
    if (trimmed == "false" || trimmed == "False") {
        return Value(false);
    }
    if (trimmed == "null" || trimmed == "~") {
        return Value();
    }
    bool is_number = true;
    bool fractional = false;
    std::size_t index = 0;
    if (trimmed[0] == '-' || trimmed[0] == '+') {
        index = 1;
    }
    for (; index < trimmed.size(); ++index) {
        const char ch = trimmed[index];
        if (ch == '.') {
            fractional = true;
            continue;
        }
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            is_number = false;
            break;
        }
    }
    if (is_number) {
        if (fractional) {
            double value{};
            if (parse_floating_token(trimmed.data(), trimmed.data() + trimmed.size(), value)) {
                return Value(value);
            }
        } else {
            std::int64_t value{};
            auto result = std::from_chars(trimmed.data(), trimmed.data() + trimmed.size(), value);
            if (result.ec == std::errc{} && result.ptr == trimmed.data() + trimmed.size()) {
                return Value(value);
            }
        }
    }
    return Value(trimmed);
}

Value parse_yaml(const std::string& text) {
    Value root = Value::make_object();
    struct Context {
        std::size_t indent;
        Value* node;
    };
    std::vector<Context> stack;
    stack.push_back({0, &root});

    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        std::string trimmed_line = trim_right(line);
        std::size_t comment_pos = std::string::npos;
        bool in_single = false;
        bool in_double = false;
        for (std::size_t i = 0; i < trimmed_line.size(); ++i) {
            char ch = trimmed_line[i];
            if (ch == '"' && !in_single) {
                in_double = !in_double;
            } else if (ch == '\'' && !in_double) {
                in_single = !in_single;
            } else if (ch == '#' && !in_single && !in_double) {
                comment_pos = i;
                break;
            }
        }
        if (comment_pos != std::string::npos) {
            trimmed_line = trimmed_line.substr(0, comment_pos);
        }
        trimmed_line = trim_right(trimmed_line);
        if (trimmed_line.empty()) {
            continue;
        }

        std::size_t indent = 0;
        while (indent < trimmed_line.size() && trimmed_line[indent] == ' ') {
            ++indent;
        }
        if (indent % 2 != 0) {
            throw ConfigError("E_CONFIG_PARSE", "YAML indentation must be multiples of two spaces");
        }
        std::string content = trim_left(trimmed_line.substr(indent));

        while (!stack.empty() && indent < stack.back().indent) {
            stack.pop_back();
        }
        if (stack.empty()) {
            throw ConfigError("E_CONFIG_PARSE", "Invalid indentation in YAML config");
        }

        Value* current_node = stack.back().node;
        if (!content.empty() && content.front() == '-') {
            std::string item = trim_copy(content.substr(1));
            auto& array = current_node->ensure_array();
            if (item.empty()) {
                array.emplace_back(Value::make_object());
                stack.push_back({indent + 2, &array.back()});
                continue;
            }
            const auto colon = item.find(':');
            if (colon != std::string::npos) {
                std::string key = trim_copy(item.substr(0, colon));
                std::string value_part = trim_copy(item.substr(colon + 1));
                Value object_item = Value::make_object();
                if (!value_part.empty()) {
                    object_item.as_object()[key] = parse_yaml_scalar(value_part);
                } else {
                    object_item.as_object()[key] = Value::make_object();
                    stack.push_back({indent + 2, &object_item.as_object()[key]});
                }
                array.push_back(std::move(object_item));
                if (!value_part.empty()) {
                    stack.push_back({indent + 2, &array.back()});
                }
                continue;
            }
            array.push_back(parse_yaml_scalar(item));
            continue;
        }

        const auto colon = content.find(':');
        if (colon == std::string::npos) {
            throw ConfigError("E_CONFIG_PARSE", "Expected ':' in YAML mapping entry");
        }
        std::string key = trim_copy(content.substr(0, colon));
        std::string value_part = trim_copy(content.substr(colon + 1));

        auto& object = current_node->ensure_object();
        if (value_part.empty()) {
            Value& child = object[key];
            if (child.is_null()) {
                child = Value::make_object();
            }
            stack.push_back({indent + 2, &child});
        } else {
            object[key] = parse_yaml_scalar(value_part);
        }
    }

    return root;
}

Value merge_objects(const Value& base, const Value& overlay) {
    if (!overlay.is_object()) {
        return overlay;
    }
    Value result = base;
    if (!result.is_object()) {
        result = Value::make_object();
    }
    for (const auto& [key, value] : overlay.as_object()) {
        if (value.is_object() && result.as_object().contains(key) && result.as_object()[key].is_object()) {
            result.as_object()[key] = merge_objects(result.as_object()[key], value);
        } else {
            result.as_object()[key] = value;
        }
    }
    return result;
}

const Value* find_path(const Value& root, const std::vector<std::string>& path) {
    const Value* node = &root;
    for (const auto& segment : path) {
        if (!node->is_object()) {
            return nullptr;
        }
        const auto it = node->as_object().find(segment);
        if (it == node->as_object().end()) {
            return nullptr;
        }
        node = &it->second;
    }
    return node;
}

Value remove_key(const Value& object, const std::string& key) {
    if (!object.is_object()) {
        return object;
    }
    Value filtered = Value::make_object();
    for (const auto& [k, v] : object.as_object()) {
        if (k == key) {
            continue;
        }
        filtered.as_object()[k] = v;
    }
    return filtered;
}

Value resolve_profile(const Value& profiles, const std::string& profile_name, std::set<std::string>& visiting);

Value resolve_profile(const Value& profiles, const std::string& profile_name) {
    std::set<std::string> visiting;
    return resolve_profile(profiles, profile_name, visiting);
}

Value resolve_profile(const Value& profiles, const std::string& profile_name, std::set<std::string>& visiting) {
    if (!profiles.is_object()) {
        throw ConfigError("E_CONFIG_STRUCTURE", "'profiles' section must be a mapping");
    }
    const auto it = profiles.as_object().find(profile_name);
    if (it == profiles.as_object().end()) {
        throw ConfigError("E_CONFIG_PROFILE", "Profile not found: " + profile_name,
                          "Available profiles: " + [&]() {
                              std::string names;
                              bool first = true;
                              for (const auto& [name, _] : profiles.as_object()) {
                                  if (!first) {
                                      names += ", ";
                                  }
                                  names += name;
                                  first = false;
                              }
                              return names.empty() ? std::string{"<none>"} : names;
                          }());
    }
    if (!it->second.is_object()) {
        throw ConfigError("E_CONFIG_STRUCTURE", "Profile must be a mapping: " + profile_name);
    }
    if (visiting.contains(profile_name)) {
        throw ConfigError("E_CONFIG_PROFILE", "Profile inheritance cycle detected at " + profile_name);
    }
    visiting.insert(profile_name);

    Value result = Value::make_object();
    const auto extends_it = it->second.as_object().find("extends");
    if (extends_it != it->second.as_object().end()) {
        if (!extends_it->second.is_string()) {
            throw ConfigError("E_CONFIG_PROFILE", "'extends' must be a string in profile " + profile_name);
        }
        result = resolve_profile(profiles, extends_it->second.string_value, visiting);
    }

    Value filtered = remove_key(it->second, "extends");
    result = merge_objects(result, filtered);
    visiting.erase(profile_name);
    return result;
}

Value collect_environment_overrides(const Value& environment_node) {
    if (!environment_node.is_object()) {
        return Value();
    }
    Value overrides = Value::make_object();
    for (const auto& [key, value] : environment_node.as_object()) {
        if (key == "profile") {
            continue;
        }
        if (key == "overrides" && value.is_object()) {
            overrides = merge_objects(overrides, value);
            continue;
        }
        overrides.as_object()[key] = value;
    }
    return overrides;
}

std::string join_path(const std::vector<std::string>& path) {
    if (path.empty()) {
        return "<root>";
    }
    std::string combined;
    for (std::size_t i = 0; i < path.size(); ++i) {
        combined += path[i];
        if (i + 1 < path.size()) {
            combined += '.';
        }
    }
    return combined;
}

std::optional<std::string> get_string(const Value& root, const std::vector<std::string>& path) {
    const Value* node = find_path(root, path);
    if (!node) {
        return std::nullopt;
    }
    if (node->is_string()) {
        return node->string_value;
    }
    throw ConfigError("E_CONFIG_TYPE", "Expected string at config path " + join_path(path));
}

std::optional<bool> get_bool(const Value& root, const std::vector<std::string>& path) {
    const Value* node = find_path(root, path);
    if (!node) {
        return std::nullopt;
    }
    if (node->is_boolean()) {
        return node->boolean_value;
    }
    if (node->is_string()) {
        std::string lowered = node->string_value;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        if (lowered == "true" || lowered == "yes" || lowered == "on") {
            return true;
        }
        if (lowered == "false" || lowered == "no" || lowered == "off") {
            return false;
        }
    }
    throw ConfigError("E_CONFIG_TYPE", "Expected boolean at config path " + join_path(path));
}

std::optional<std::int64_t> get_int64(const Value& root, const std::vector<std::string>& path) {
    const Value* node = find_path(root, path);
    if (!node) {
        return std::nullopt;
    }
    if (node->is_integer()) {
        return node->integer_value;
    }
    if (node->is_double()) {
        const double value = node->double_value;
        const double rounded = std::floor(value + 0.5);
        if (std::abs(value - rounded) < 1e-9) {
            return static_cast<std::int64_t>(rounded);
        }
    }
    throw ConfigError("E_CONFIG_TYPE", "Expected integer at config path " + join_path(path));
}

std::optional<std::vector<Value>> get_array(const Value& root, const std::vector<std::string>& path) {
    const Value* node = find_path(root, path);
    if (!node) {
        return std::nullopt;
    }
    if (!node->is_array()) {
        throw ConfigError("E_CONFIG_TYPE", "Expected array at config path " + join_path(path));
    }
    return node->as_array();
}

std::optional<std::string> get_string_any(const Value& root, std::initializer_list<std::vector<std::string>> paths) {
    for (const auto& path : paths) {
        if (auto value = get_string(root, path)) {
            return value;
        }
    }
    return std::nullopt;
}

std::optional<bool> get_bool_any(const Value& root, std::initializer_list<std::vector<std::string>> paths) {
    for (const auto& path : paths) {
        if (auto value = get_bool(root, path)) {
            return value;
        }
    }
    return std::nullopt;
}

std::optional<std::int64_t> get_int64_any(const Value& root, std::initializer_list<std::vector<std::string>> paths) {
    for (const auto& path : paths) {
        if (auto value = get_int64(root, path)) {
            return value;
        }
    }
    return std::nullopt;
}

Value load_document(const std::filesystem::path& path) {
    std::filesystem::path absolute = std::filesystem::absolute(path);
    std::ifstream input(absolute);
    if (!input) {
        throw ConfigError("E_CONFIG_NOT_FOUND", "Configuration file not found: " + absolute.string(),
                          "Verify the path or provide an absolute path");
    }
    std::stringstream buffer;
    buffer << input.rdbuf();
    const std::string contents = buffer.str();

    const auto first_non_space = std::find_if(contents.begin(), contents.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    });
    const bool looks_like_json = path.extension() == ".json" ||
                                 (first_non_space != contents.end() && (*first_non_space == '{' || *first_non_space == '['));
    Value document = looks_like_json ? JsonParser(contents).parse() : parse_yaml(contents);
    if (!document.is_object()) {
        throw ConfigError("E_CONFIG_STRUCTURE", "Configuration root must be an object");
    }
    return document;
}

}  // namespace config

void apply_profile_to_options(const config::Value& profile, GlobalOptions& options) {
    if (!profile.is_object()) {
        throw config::ConfigError("E_CONFIG_STRUCTURE", "Profile configuration must be a mapping");
    }

    auto get_uint16 = [](std::int64_t value, const char* key) -> std::uint16_t {
        if (value <= 0 || value > std::numeric_limits<std::uint16_t>::max()) {
            throw config::ConfigError("E_CONFIG_VALUE", std::string(key) + " must be between 1 and 65535");
        }
        return static_cast<std::uint16_t>(value);
    };

    if (!options.storage_dir) {
        if (auto storage_dir = config::get_string_any(profile, {{"storage", "directory"}, {"storage-directory"}})) {
            options.storage_dir = *storage_dir;
        }
    }

    if (!options.persistent_set) {
        if (auto persistent = config::get_bool_any(profile, {{"storage", "persistent"}, {"storage", "enable_persistent"}})) {
            options.persistent = *persistent;
            options.persistent_set = true;
        }
    }

    if (!options.wipe_set) {
        if (auto wipe = config::get_bool_any(profile, {{"storage", "wipe_on_expiry"}, {"storage", "wipe-on-expiry"}})) {
            options.wipe = *wipe;
            options.wipe_set = true;
        }
    }

    if (!options.wipe_passes_set) {
        if (auto passes = config::get_int64_any(profile, {{"storage", "wipe_passes"}, {"storage", "wipe-passes"}})) {
            if (*passes <= 0 || *passes > 255) {
                throw config::ConfigError("E_CONFIG_VALUE", "storage.wipe_passes must be between 1 and 255");
            }
            options.wipe_passes = static_cast<std::uint8_t>(*passes);
            options.wipe_passes_set = true;
        }
    }

    if (!options.control_host) {
        if (auto host = config::get_string_any(profile, {{"control", "host"}, {"network", "control_host"}})) {
            options.control_host = *host;
        }
    }

    if (!options.control_port) {
        if (auto port = config::get_int64_any(profile, {{"control", "port"}, {"network", "control_port"}})) {
            options.control_port = get_uint16(*port, "control.port");
        }
    }

    if (!options.transport_listen_port) {
        if (auto port = config::get_int64_any(profile,
                                              {{"transport", "port"},
                                               {"network", "transport_port"},
                                               {"node", "transport_port"}})) {
            options.transport_listen_port = get_uint16(*port, "transport.port");
        }
    }

    if (!options.control_token) {
        if (auto token = config::get_string_any(profile, {{"control", "token"}, {"control-token"}})) {
            options.control_token = *token;
        }
    }

    if (!options.advertise_control_set) {
        auto apply_advertise = [&](const std::string& host,
                                   std::optional<std::uint16_t> port) {
            options.advertise_control_host = host;
            options.advertise_control_port = port;
            options.advertise_control_set = true;
        };

        if (auto endpoint = config::get_string_any(profile,
                                                   {{"control", "advertise"},
                                                    {"control", "advertise_endpoint"}})) {
            std::string host;
            std::optional<std::uint16_t> port;
            if (auto error = split_advertise_control_endpoint(*endpoint, host, port)) {
                throw config::ConfigError("E_CONFIG_VALUE",
                                          "control.advertise_endpoint: " + *error);
            }
            apply_advertise(host, port);
        } else {
            if (auto host = config::get_string_any(profile,
                                                   {{"control", "advertise_host"},
                                                    {"control", "advertise-host"}})) {
                auto trimmed = trim(*host);
                if (trimmed.empty()) {
                    throw config::ConfigError("E_CONFIG_VALUE",
                                              "control.advertise_host must not be empty");
                }
                if (has_whitespace(trimmed)) {
                    throw config::ConfigError("E_CONFIG_VALUE",
                                              "control.advertise_host must not contain whitespace");
                }
                std::optional<std::uint16_t> port{};
                if (auto port_value = config::get_int64_any(profile,
                                                            {{"control", "advertise_port"},
                                                             {"control", "advertise-port"}})) {
                    if (*port_value <= 0 || *port_value > std::numeric_limits<std::uint16_t>::max()) {
                        throw config::ConfigError("E_CONFIG_VALUE",
                                                  "control.advertise_port must be between 1 and 65535");
                    }
                    port = static_cast<std::uint16_t>(*port_value);
                }
                apply_advertise(trimmed, port);
            } else if (config::get_int64_any(profile,
                                             {{"control", "advertise_port"},
                                              {"control", "advertise-port"}})) {
                throw config::ConfigError("E_CONFIG_VALUE",
                                          "control.advertise_port requires control.advertise_host");
            }
        }
    }

    if (!options.advertise_allow_private) {
        if (auto allow_private = config::get_bool_any(profile,
                                                      {{"control", "advertise_allow_private"},
                                                       {"control", "advertise-allow-private"}})) {
            options.advertise_allow_private = *allow_private;
        }
    }

    if (!options.advertise_auto_mode) {
        if (auto mode_text = config::get_string_any(profile,
                                                    {{"control", "advertise_auto"},
                                                     {"control", "advertise-auto"}})) {
            ephemeralnet::Config::AdvertiseAutoMode parsed_mode;
            if (!try_parse_advertise_auto_mode(*mode_text, parsed_mode)) {
                throw config::ConfigError("E_CONFIG_VALUE",
                                          "control.advertise_auto must be one of on|off|warn");
            }
            options.advertise_auto_mode = parsed_mode;
        }
    }

    if (!options.control_stream_max_bytes) {
        if (auto limit = config::get_int64_any(profile, {{"control", "stream_max_bytes"}, {"control", "max_stream_bytes"}, {"control", "max_store_bytes"}})) {
            if (*limit < 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "control.stream_max_bytes must be non-negative");
            }
            options.control_stream_max_bytes = static_cast<std::uint64_t>(*limit);
        }
    }

    if (!options.identity_seed) {
        if (auto seed = config::get_int64_any(profile, {{"node", "identity_seed"}, {"identity", "seed"}})) {
            if (*seed < 0 || *seed > std::numeric_limits<std::uint32_t>::max()) {
                throw config::ConfigError("E_CONFIG_VALUE", "node.identity_seed must fit within 32 bits");
            }
            options.identity_seed = static_cast<std::uint32_t>(*seed);
        }
    }

    if (!options.default_ttl_seconds) {
        if (auto ttl = config::get_int64_any(profile, {{"node", "default_ttl_seconds"}, {"node", "default_ttl"}})) {
            if (*ttl <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "node.default_ttl_seconds must be positive");
            }
            options.default_ttl_seconds = static_cast<std::uint64_t>(*ttl);
        }
    }

    if (!options.min_ttl_seconds) {
        if (auto min_ttl = config::get_int64_any(profile, {{"node", "min_ttl_seconds"}, {"node", "min_ttl"}})) {
            if (*min_ttl <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "node.min_ttl_seconds must be positive");
            }
            options.min_ttl_seconds = static_cast<std::uint64_t>(*min_ttl);
        }
    }

    if (!options.max_ttl_seconds) {
        if (auto max_ttl = config::get_int64_any(profile, {{"node", "max_ttl_seconds"}, {"node", "max_ttl"}})) {
            if (*max_ttl <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "node.max_ttl_seconds must be positive");
            }
            options.max_ttl_seconds = static_cast<std::uint64_t>(*max_ttl);
        }
    }

    if (!options.key_rotation_seconds) {
        if (auto rotation = config::get_int64_any(profile, {{"node", "key_rotation_seconds"}, {"node", "key_rotation_interval"}, {"security", "key_rotation_seconds"}, {"security", "key_rotation_interval"}})) {
            if (*rotation <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "key rotation interval must be positive");
            }
            options.key_rotation_seconds = static_cast<std::uint64_t>(*rotation);
        }
    }

    if (!options.fetch_parallel) {
        if (auto fetch_parallel = config::get_int64_any(profile, {{"node", "fetch_max_parallel"}, {"node", "fetch", "max_parallel"}, {"fetch", "max_parallel"}})) {
            if (*fetch_parallel < 0 || *fetch_parallel > std::numeric_limits<std::uint16_t>::max()) {
                throw config::ConfigError("E_CONFIG_VALUE", "fetch.max_parallel must be between 0 and 65535");
            }
            options.fetch_parallel = static_cast<std::uint16_t>(*fetch_parallel);
        }
    }

    if (!options.announce_interval_seconds) {
        if (auto announce_interval = config::get_int64_any(profile, {{"announce", "min_interval"}, {"node", "announce_min_interval"}})) {
            if (*announce_interval <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "announce.min_interval must be positive");
            }
            options.announce_interval_seconds = static_cast<std::uint64_t>(*announce_interval);
        }
    }

    if (!options.announce_burst_limit) {
        if (auto announce_burst = config::get_int64_any(profile, {{"announce", "burst_limit"}, {"node", "announce_burst_limit"}})) {
            if (*announce_burst <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "announce.burst_limit must be positive");
            }
            options.announce_burst_limit = static_cast<std::uint64_t>(*announce_burst);
        }
    }

    if (!options.announce_window_seconds) {
        if (auto announce_window = config::get_int64_any(profile, {{"announce", "burst_window"}, {"node", "announce_burst_window"}})) {
            if (*announce_window <= 0) {
                throw config::ConfigError("E_CONFIG_VALUE", "announce.burst_window must be positive");
            }
            options.announce_window_seconds = static_cast<std::uint64_t>(*announce_window);
        }
    }

    if (!options.announce_pow_difficulty) {
        if (auto pow = config::get_int64_any(profile, {{"announce", "pow_difficulty"}, {"node", "announce_pow_difficulty"}})) {
            if (*pow < 0 || *pow > 24) {
                throw config::ConfigError("E_CONFIG_VALUE", "announce.pow_difficulty must be between 0 and 24");
            }
            options.announce_pow_difficulty = static_cast<std::uint64_t>(*pow);
        }
    }

    if (!options.upload_parallel) {
        if (auto upload_parallel = config::get_int64_any(profile, {{"node", "upload_max_parallel"}, {"node", "upload", "max_parallel"}, {"upload", "max_parallel"}})) {
            if (*upload_parallel < 0 || *upload_parallel > std::numeric_limits<std::uint16_t>::max()) {
                throw config::ConfigError("E_CONFIG_VALUE", "upload.max_parallel must be between 0 and 65535");
            }
            options.upload_parallel = static_cast<std::uint16_t>(*upload_parallel);
        }
    }

    if (!options.peer_id_hex) {
        if (auto peer_id = config::get_string_any(profile, {{"node", "peer_id"}, {"node", "peer-id"}})) {
            options.peer_id_hex = *peer_id;
        }
    }

    if (!options.assume_yes_set) {
        if (auto assume = config::get_bool_any(profile, {{"cli", "assume_yes"}, {"cli", "assume-yes"}, {"assume_yes"}})) {
            options.assume_yes = *assume;
            options.assume_yes_set = true;
        }
    }

    if (!options.fetch_default_directory) {
        if (auto fetch_dir = config::get_string_any(profile, {{"cli", "fetch", "default_directory"}, {"cli", "fetch", "default-directory"}, {"fetch", "default_directory"}, {"fetch", "default-directory"}})) {
            options.fetch_default_directory = *fetch_dir;
        }
    }

    if (!options.fetch_use_manifest_name_set) {
        if (auto use_name = config::get_bool_any(profile, {{"cli", "fetch", "use_manifest_name"}, {"cli", "fetch", "use-manifest-name"}})) {
            options.fetch_use_manifest_name = *use_name;
            options.fetch_use_manifest_name_set = true;
        }
    }
}

void load_configuration(GlobalOptions& options) {
    if (!options.config_path) {
        return;
    }

    config::Value document = config::load_document(*options.config_path);
    const auto* profiles = config::find_path(document, {"profiles"});
    if (!profiles) {
        throw config::ConfigError("E_CONFIG_STRUCTURE", "Configuration file is missing 'profiles' section",
                                  "Define at least a 'default' profile under 'profiles'");
    }

    std::string selected_profile = options.profile_name.value_or("default");
    config::Value overrides = config::Value::make_object();
    if (options.environment) {
        const auto* environments = config::find_path(document, {"environments"});
        if (!environments || environments->is_null()) {
            throw config::ConfigError("E_CONFIG_ENVIRONMENT",
                                      "Environment section not defined while --env was provided",
                                      "Add an 'environments' map to the configuration file");
        }
        if (!environments->is_object()) {
            throw config::ConfigError("E_CONFIG_ENVIRONMENT", "'environments' section must be a mapping");
        }
        const auto it = environments->as_object().find(*options.environment);
        if (it == environments->as_object().end()) {
            throw config::ConfigError("E_CONFIG_ENVIRONMENT", "Environment not found: " + *options.environment);
        }
        if (!it->second.is_object()) {
            throw config::ConfigError("E_CONFIG_ENVIRONMENT", "Environment entry must be a mapping: " + *options.environment);
        }
        if (!options.profile_name) {
            if (auto env_profile = config::get_string(it->second, std::vector<std::string>{"profile"})) {
                selected_profile = *env_profile;
            }
        }
        overrides = config::collect_environment_overrides(it->second);
    }

    config::Value base_profile = config::resolve_profile(*profiles, selected_profile);
    config::Value effective_profile = config::merge_objects(base_profile, overrides);
    apply_profile_to_options(effective_profile, options);
}
enum class ShutdownReason {
    None,
    Signal,
    Control
};

std::atomic<bool> g_run_loop{false};
std::atomic<ShutdownReason> g_shutdown_reason{ShutdownReason::None};

void request_shutdown(ShutdownReason reason) noexcept {
    g_shutdown_reason.store(reason, std::memory_order_release);
    g_run_loop.store(false, std::memory_order_release);
}

extern "C" void signal_handler(int signal_code) {
    switch (signal_code) {
    case SIGINT:
    case SIGTERM:
#ifdef SIGQUIT
    case SIGQUIT:
#endif
#ifdef SIGBREAK
    case SIGBREAK:
#endif
        request_shutdown(ShutdownReason::Signal);
        break;
    default:
        break;
    }
}

#ifdef _WIN32
BOOL WINAPI windows_console_ctrl_handler(DWORD control_type) {
    switch (control_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        request_shutdown(ShutdownReason::Signal);
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

void install_termination_handlers() {
#ifdef _WIN32
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#ifdef SIGBREAK
    std::signal(SIGBREAK, signal_handler);
#endif
    SetConsoleCtrlHandler(windows_console_ctrl_handler, TRUE);
#else
    auto install = [](int sig) {
        struct sigaction action{};
        action.sa_handler = signal_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(sig, &action, nullptr);
    };
    install(SIGINT);
    install(SIGTERM);
#ifdef SIGQUIT
    install(SIGQUIT);
#endif
#endif
}

void uninstall_termination_handlers() {
#ifdef _WIN32
    SetConsoleCtrlHandler(windows_console_ctrl_handler, FALSE);
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
#ifdef SIGBREAK
    std::signal(SIGBREAK, SIG_DFL);
#endif
#else
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
#ifdef SIGQUIT
    std::signal(SIGQUIT, SIG_DFL);
#endif
#endif
}

void print_usage() {
    std::cout << "EphemeralNet CLI" << std::endl;
    std::cout << "Usage: eph [options] <command> [args]\n\n";
    std::cout << "Global options:\n"
              << "  --storage-dir <path>      Directory for persistent chunks (default ./storage)\n"
              << "  --persistent              Enable persistent storage\n"
              << "  --no-persistent           Disable persistent storage\n"
              << "  --no-wipe                 Disable secure wipe on expiry\n"
              << "  --wipe-passes <n>         Number of passes for secure wipe (>=1)\n"
              << "  --identity-seed <n>       Deterministic seed for node identity\n"
              << "  --peer-id <hex>           Node identifier (64 hexadecimal characters)\n"
              << "  --default-ttl <sec>       Default TTL for new chunks\n"
              << "  --min-ttl <sec>           Minimum TTL enforced for manifests\n"
              << "  --max-ttl <sec>           Maximum TTL permitted for manifests\n"
              << "  --key-rotation <sec>      Session key rotation cadence\n"
              << "  --announce-interval <sec> Minimum spacing between ANNOUNCE messages\n"
              << "  --announce-burst <count>  Maximum ANNOUNCEs permitted per window\n"
              << "  --announce-window <sec>   Rolling window for ANNOUNCE burst tracking\n"
              << "  --announce-pow <bits>     Proof-of-work difficulty for ANNOUNCE (0-24)\n"
              << "  --control-host <host>     Control socket host (default 127.0.0.1)\n"
              << "  --control-expose          Bind control socket on 0.0.0.0 for remote access\n"
              << "  --control-loopback        Force control socket to stay on 127.0.0.1\n"
              << "  --control-port <port>     Control socket port (default 47777)\n"
              << "  --transport-port <port>  Transport listening port (default 45000)\n"
              << "  --control-token <secret>  Pre-shared token for control-plane authentication\n"
              << "  --advertise-control <ep>  Host[:port] advertised inside manifests for remote fetches\n"
              << "  --advertise-allow-private Allow auto-advertise of private/control addresses\n"
              << "  --advertise-auto on|off|warn\n"
              << "                           Control whether auto-detected endpoints are used (default: on)\n"
              << "  --max-store-bytes <n>     Control-plane upload cap in bytes (0 = unlimited)\n"
              << "  --fetch-parallel <n>      Fetch concurrency limit (0 = unlimited)\n"
              << "  --upload-parallel <n>     Upload concurrency limit (0 = unlimited)\n"
              << "  --fetch-default-dir <path>\n"
              << "                           Default directory when fetch --out is omitted\n"
              << "  --fetch-use-manifest-name\n"
              << "                           Preserve stored filenames when fetching (default)\n"
              << "  --fetch-ignore-manifest-name\n"
              << "                           Ignore stored filenames when fetching\n"
              << "  --config <file>          Load configuration from YAML/JSON file\n"
              << "  --profile <name>         Select configuration profile (default: default)\n"
              << "  --env <name>             Apply environment overrides from config\n"
              << "  --version                Print the CLI version and exit\n"
              << "  --help                   Print this help message\n\n";
    std::cout << "Commands:\n"
              << "  start                     Launch the daemon in the background\n"
              << "  stop                      Ask the daemon to shut down\n"
              << "  status                    Query daemon status\n"
              << "  store <file> [--ttl <duration>]\n"
              << "                           Ask the daemon to store a file and return eph://\n"
              << "  fetch <eph://...> [--out] <path>\n"
              << "                           Retrieve a file (defaults to current directory)\n"
              << "  list                      List chunks stored locally\n"
              << "  defaults                  Show daemon default limits and timers\n"
              << "  update-check              Query eph.shardian.com for the latest release\n"
              << "  man                       Display the integrated manual\n"
              << "  serve                     Start the daemon in the foreground (Ctrl+C to exit)\n"
              << "  help                      Alias for --help\n";
}

bool is_help_flag(std::string_view value) {
    return value == "--help" || value == "-h";
}

void print_start_usage() {
    std::cout << "Usage: eph start\n"
              << "Launch the daemon in the background, wait for readiness, and detach." << std::endl;
}

void print_stop_usage() {
    std::cout << "Usage: eph stop\n"
              << "Request a graceful shutdown of the running daemon." << std::endl;
}

void print_status_usage() {
    std::cout << "Usage: eph status\n"
              << "Display connected peers, stored chunks, and the transport port." << std::endl;
}

void print_list_usage() {
    std::cout << "Usage: eph list\n"
              << "List locally stored chunks with size, encryption flag, and TTL." << std::endl;
}

void print_store_usage() {
    std::cout << "Usage: eph store <file> [--ttl <duration>]\n"
              << "Stream a local file to the daemon and receive an eph:// manifest (TTL defaults to daemon configuration)." << std::endl;
}

void print_fetch_usage() {
    std::cout << "Usage: eph fetch <eph://...> [--out <path>] [options]\n"
              << "Download a manifest's payload to a specific file or directory (defaults to the current directory when omitted).\n"
              << "Options:\n"
              << "  --out <path>                  Destination file or directory (default: current dir).\n"
              << "  --direct-only                Only use discovery hints/fallbacks; skip DHT/swarm fallback.\n"
              << "  --transport-only             Only attempt transport/tcp hints (disables control + daemon fallback).\n"
              << "  --control-fallback          Skip transport hints and use control/fallback paths immediately.\n"
              << "  --bootstrap-token <value>    Provide a precomputed PoW token for direct discovery endpoints.\n"
              << "  --bootstrap-max-attempts <n> Limit PoW search iterations when solving tokens automatically.\n"
              << "  --no-bootstrap-auto-token    Disable automatic PoW solving (requires --bootstrap-token)." << std::endl;
}

void print_serve_usage() {
    std::cout << "Usage: eph serve\n"
              << "Run the daemon in the foreground until interrupted." << std::endl;
}

void print_defaults_usage() {
    std::cout << "Usage: eph defaults\n"
              << "Display the daemon's current default TTL, bounds, and control endpoint." << std::endl;
}

void print_update_check_usage() {
    std::cout << "Usage: eph update-check [--url <endpoint>]\n"
              << "Check eph.shardian.com/latest.json (or a custom --url / EPH_UPDATE_URL) for newer releases." << std::endl;
}

void print_manual() {
    std::cout << "EPH(1)                          User Commands                         EPH(1)\n\n";
    std::cout << "NAME\n"
              << "    eph - EphemeralNet control-plane client and node launcher\n\n";
    std::cout << "SYNOPSIS\n"
              << "    eph [options] <command> [args]\n"
              << "    eph --help\n"
              << "    eph --version\n\n";
    std::cout << "DESCRIPTION\n"
              << "    The eph CLI manages an EphemeralNet daemon. It can start or stop the node,\n"
              << "    store and fetch files, and inspect daemon defaults. Global options apply to\n"
              << "    all commands and can be defined on the command line or via configuration\n"
              << "    profiles.\n\n";
    std::cout << "GLOBAL OPTIONS\n"
              << "    --storage-dir <path>   Directory for persistent chunks.\n"
              << "    --persistent           Enable persistent storage (default off).\n"
              << "    --no-persistent        Disable persistent storage.\n"
              << "    --no-wipe              Disable secure wipe once TTL expires.\n"
              << "    --wipe-passes <n>      Secure wipe passes (1-255).\n"
              << "    --identity-seed <n>    Deterministic peer identity seed.\n"
              << "    --peer-id <hex>        Explicit peer id (64 hex chars).\n"
              << "    --default-ttl <sec>    Default TTL for stored chunks.\n"
              << "    --min-ttl <sec>        Minimum TTL accepted for manifests.\n"
              << "    --max-ttl <sec>        Maximum TTL advertised for manifests.\n"
              << "    --key-rotation <sec>   Session key rotation interval.\n"
              << "    --announce-interval <sec>\n"
              << "                          Minimum spacing between ANNOUNCE messages.\n"
              << "    --announce-burst <n>  Maximum ANNOUNCE count permitted per window.\n"
              << "    --announce-window <sec>\n"
              << "                          Rolling window length for burst enforcement.\n"
              << "    --announce-pow <bits> Proof-of-work difficulty for ANNOUNCE (0-24).\n"
              << "    --control-host <host>  Control socket host.\n"
              << "    --control-expose       Bind control socket on 0.0.0.0 (prompts for confirmation).\n"
              << "    --control-loopback     Force control socket onto 127.0.0.1 even if profile overrides it.\n"
              << "    --control-port <port>  Control socket port.\n"
              << "    --transport-port <port>  Transport layer listening port.\n"
              << "    --control-token <tok>  Control-plane authentication token.\n"
              << "    --advertise-control <ep>\n"
              << "                          Host[:port] embedded into manifests for direct fetches.\n"
              << "    --max-store-bytes <n>  Control-plane upload cap in bytes (0 = unlimited).\n"
              << "    --fetch-parallel <n>   Fetch concurrency (0 = unlimited).\n"
              << "    --upload-parallel <n>  Upload concurrency (0 = unlimited).\n"
              << "    --fetch-default-dir <path>\n"
              << "                          Default directory when fetch --out is omitted.\n"
              << "    --fetch-use-manifest-name / --fetch-ignore-manifest-name\n"
              << "                          Toggle filename hints during fetch.\n"
              << "    --config <file>       Load layered JSON/YAML configuration.\n"
              << "    --profile <name>      Select configuration profile.\n"
              << "    --env <name>          Apply environment overrides.\n"
              << "    --yes                 Assume yes for prompts.\n"
              << "    --help                Show command summary.\n"
              << "    --version             Print CLI version and exit.\n\n";
    std::cout << "COMMANDS\n"
              << "    serve                  Run the daemon in the foreground.\n"
              << "    start                  Launch the daemon in the background.\n"
              << "    stop                   Stop the running daemon.\n"
              << "    status                 Show peer counts, chunks, and transport port.\n"
              << "    list                   List local chunks with TTL and encryption status.\n"
              << "    store <file> [--ttl <duration>]   Upload a file and receive an eph:// manifest.\n"
              << "    fetch <manifest> [--out] <path>\n"
              << "                          Retrieve payload into a file or directory.\n"
              << "    defaults               Display daemon TTL bounds and concurrency limits.\n"
              << "    update-check          Check eph.shardian.com for new releases.\n"
              << "    man                    Display this manual.\n"
              << "    help                   Alias for --help.\n\n";
    std::cout << "FILES\n"
              << "    profiles in configuration files define reusable daemon settings. See\n"
              << "    docs/deployment-guide.md for examples.\n\n";
    std::cout << "EXAMPLES\n"
              << "    eph --storage-dir ./data serve\n"
              << "    eph store secret.bin --ttl 3600\n"
              << "    eph store secret.bin --ttl 30m\n"
              << "    eph fetch eph://... --out ./file.bin\n"
              << "    eph defaults\n"
              << "    eph --version\n\n";
    std::cout << "SEE ALSO\n"
              << "    docs/README.md, docs/deployment-guide.md within the source tree.\n\n";
    std::cout << "EphemeralNet " << kEphemeralNetVersion << "                         EPH(1)" << std::endl;
}

bool parse_uint64(std::string_view text, std::uint64_t& value) {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

bool parse_uint32(std::string_view text, std::uint32_t& value) {
    std::uint64_t temp{};
    if (!parse_uint64(text, temp) || temp > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    value = static_cast<std::uint32_t>(temp);
    return true;
}

bool parse_uint16(std::string_view text, std::uint16_t& value) {
    std::uint64_t temp{};
    if (!parse_uint64(text, temp) || temp > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    value = static_cast<std::uint16_t>(temp);
    return true;
}

bool parse_duration_seconds(std::string_view text, std::uint64_t& seconds) {
    if (text.empty()) {
        return false;
    }
    char suffix = '\0';
    if (!std::isdigit(static_cast<unsigned char>(text.back()))) {
        suffix = static_cast<char>(std::tolower(static_cast<unsigned char>(text.back())));
        text.remove_suffix(1);
    }
    if (text.empty()) {
        return false;
    }

    if (!parse_uint64(text, seconds)) {
        return false;
    }
    std::uint64_t multiplier = 1;
    switch (suffix) {
    case '\0':
    case 's':
        multiplier = 1;
        break;
    case 'm':
        multiplier = 60;
        break;
    case 'h':
        multiplier = 60 * 60;
        break;
    case 'd':
        multiplier = 60 * 60 * 24;
        break;
    default:
        return false;
    }
    if (multiplier != 1) {
        if (seconds > std::numeric_limits<std::uint64_t>::max() / multiplier) {
            return false;
        }
        seconds *= multiplier;
    }
    return true;
}

std::optional<std::string> split_advertise_control_endpoint(const std::string& raw,
                                                            std::string& host_out,
                                                            std::optional<std::uint16_t>& port_out) {
    std::string value = trim(raw);
    if (value.empty()) {
        return std::string{"Advertise control endpoint requires a host"};
    }
    if (has_whitespace(value)) {
        return std::string{"Advertise control endpoint must not contain whitespace"};
    }

    auto parse_port = [&](std::string_view text) -> std::optional<std::string> {
        if (text.empty()) {
            return std::string{"Advertise control endpoint is missing a port after ':'"};
        }
        std::uint16_t parsed{};
        if (!parse_uint16(text, parsed)) {
            return std::string{"Advertise control port must be between 1 and 65535"};
        }
        port_out = parsed;
        return std::nullopt;
    };

    std::string host;
    port_out.reset();

    if (!value.empty() && value.front() == '[') {
        const auto closing = value.find(']');
        if (closing == std::string::npos) {
            return std::string{"Advertise control endpoint has an unterminated IPv6 host"};
        }
        host = value.substr(1, closing - 1);
        if (host.empty()) {
            return std::string{"Advertise control endpoint requires a host"};
        }
        const auto remainder = value.substr(closing + 1);
        if (!remainder.empty()) {
            if (remainder.front() != ':') {
                return std::string{"Advertise control endpoint must place ':' immediately after ']'."};
            }
            if (auto err = parse_port(std::string_view(remainder).substr(1))) {
                return err;
            }
        }
    } else {
        const auto first_colon = value.find(':');
        const auto last_colon = value.find_last_of(':');
        if (first_colon != std::string::npos && first_colon != last_colon) {
            return std::string{"IPv6 advertise endpoints must be wrapped like [2001:db8::1]:47777"};
        }
        if (last_colon != std::string::npos) {
            host = value.substr(0, last_colon);
            if (auto err = parse_port(std::string_view(value).substr(last_colon + 1))) {
                return err;
            }
        } else {
            host = value;
        }
    }

    if (host.empty()) {
        return std::string{"Advertise control endpoint requires a host"};
    }

    host_out = host;
    return std::nullopt;
}

std::string format_advertise_control_argument(const std::string& host,
                                              const std::optional<std::uint16_t>& port) {
    std::string formatted;
    const bool needs_brackets = host.find(':') != std::string::npos;
    if (needs_brackets) {
        formatted.push_back('[');
    }
    formatted += host;
    if (needs_brackets) {
        formatted.push_back(']');
    }
    if (port.has_value()) {
        formatted.push_back(':');
        formatted += std::to_string(*port);
    }
    return formatted;
}

std::optional<std::uint8_t> parse_hex_byte(char high, char low) {
    auto hex_to_int = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    const int hi = hex_to_int(high);
    const int lo = hex_to_int(low);
    if (hi < 0 || lo < 0) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>((hi << 4) | lo);
}

template <typename ArrayType>
std::optional<ArrayType> parse_hex_array(const std::string& hex) {
    if (hex.size() != ArrayType{}.size() * 2) {
        return std::nullopt;
    }
    ArrayType result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        const auto byte = parse_hex_byte(hex[2 * i], hex[2 * i + 1]);
        if (!byte.has_value()) {
            return std::nullopt;
        }
        result[i] = *byte;
    }
    return result;
}

std::string strip_quotes(std::string value) {
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substr(1, value.size() - 2);
        }
    }
    return value;
}

void validate_global_options(GlobalOptions& options) {
    if (options.storage_dir) {
        auto raw = strip_quotes(*options.storage_dir);
        raw = trim(raw);
        if (raw.empty()) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "--storage-dir cannot be empty",
                            "Provide a directory path, e.g. --storage-dir ./data");
        }
        if (has_whitespace(raw)) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "--storage-dir must not contain whitespace",
                            "Wrap the path in quotes or use a path without spaces");
        }
        std::filesystem::path absolute;
        try {
            absolute = std::filesystem::absolute(std::filesystem::path(raw));
        } catch (const std::exception&) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "Failed to resolve --storage-dir",
                            "Ensure the path is valid on this platform and try again");
        }
        if (std::filesystem::exists(absolute) && !std::filesystem::is_directory(absolute)) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "--storage-dir points to a file",
                            "Select a directory or remove the existing file at " + absolute.string());
        }
        const auto parent = absolute.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "Parent directory does not exist for --storage-dir",
                            "Create " + parent.string() + " first or choose an existing location");
        }
        options.storage_dir = absolute.string();
    }

    if (options.control_host) {
        auto host = strip_quotes(*options.control_host);
        host = trim(host);
        if (host.empty()) {
            throw_cli_error("E_INVALID_CONTROL_HOST",
                            "--control-host cannot be empty",
                            "Use an IP address or hostname, e.g. --control-host 127.0.0.1");
        }
        if (has_whitespace(host)) {
            throw_cli_error("E_INVALID_CONTROL_HOST",
                            "--control-host must not contain spaces",
                            "If you need to specify an IPv6 address, wrap it in [brackets]");
        }
        options.control_host = host;
    }

    if (options.control_port) {
        if (*options.control_port == 0) {
            throw_cli_error("E_INVALID_CONTROL_PORT",
                            "--control-port must be between 1 and 65535",
                            "Choose a TCP port greater than zero, e.g. --control-port 47777");
        }
    }

    if (options.transport_listen_port) {
        if (*options.transport_listen_port == 0) {
            throw_cli_error("E_INVALID_TRANSPORT_PORT",
                            "--transport-port must be between 1 and 65535",
                            "Choose a transport port greater than zero, e.g. --transport-port 45000");
        }
    }

    if (options.control_token) {
        auto token = strip_quotes(*options.control_token);
        token = trim(token);
        if (token.empty()) {
            throw_cli_error("E_INVALID_CONTROL_TOKEN",
                            "--control-token cannot be empty",
                            "Provide a non-empty secret or omit the flag to disable authentication");
        }
        if (has_whitespace(token)) {
            throw_cli_error("E_INVALID_CONTROL_TOKEN",
                            "--control-token must not contain whitespace",
                            "Use a token without spaces or encode it (e.g. base64)");
        }
        options.control_token = token;
    }

    if (options.advertise_control_host) {
        auto host = trim(*options.advertise_control_host);
        if (host.empty()) {
            throw_cli_error("E_INVALID_ADVERTISE_CONTROL",
                            "Advertise control endpoint requires a host",
                            "Provide host[:port], e.g. example.com:47777 or [2001:db8::1]:47777");
        }
        if (has_whitespace(host)) {
            throw_cli_error("E_INVALID_ADVERTISE_CONTROL",
                            "Advertise control endpoint must not contain whitespace",
                            "Wrap IPv6 hosts in brackets, e.g. --advertise-control [2001:db8::1]:47777");
        }
        options.advertise_control_host = host;
    }
    if (options.advertise_control_port && !options.advertise_control_host) {
        throw_cli_error("E_INVALID_ADVERTISE_CONTROL",
                        "--advertise-control port provided without a host",
                        "Specify a host along with the port, e.g. --advertise-control example.com:47777");
    }

    if (options.control_stream_max_bytes) {
        const auto requested = *options.control_stream_max_bytes;
        if (requested > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            throw_cli_error("E_INVALID_STORE_LIMIT",
                            "--max-store-bytes exceeds this platform's size_t range",
                            "Choose a value up to " + std::to_string(std::numeric_limits<std::size_t>::max()));
        }
    }

    if (options.peer_id_hex) {
        auto candidate = strip_quotes(*options.peer_id_hex);
        candidate = trim(candidate);
        if (candidate.size() != ephemeralnet::PeerId{}.size() * 2) {
            throw_cli_error("E_INVALID_PEER_ID",
                            "--peer-id must be exactly 64 hexadecimal characters",
                            "Example: --peer-id 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        }
        for (char ch : candidate) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) {
                throw_cli_error("E_INVALID_PEER_ID",
                                "--peer-id accepts hexadecimal characters only",
                                "Remove invalid characters or omit --peer-id to auto-generate one");
            }
        }
        options.peer_id_hex = candidate;
    }

    if (options.fetch_default_directory) {
        auto raw = strip_quotes(*options.fetch_default_directory);
        raw = trim(raw);
        if (raw.empty()) {
            throw_cli_error("E_INVALID_FETCH_DEFAULT_DIR",
                            "--fetch-default-dir cannot be empty",
                            "Provide a directory path, e.g. --fetch-default-dir ./downloads");
        }
        std::filesystem::path absolute;
        try {
            absolute = std::filesystem::absolute(std::filesystem::path(raw));
        } catch (const std::exception&) {
            throw_cli_error("E_INVALID_FETCH_DEFAULT_DIR",
                            "Failed to resolve --fetch-default-dir",
                            "Ensure the path is valid on this platform and try again");
        }
        if (std::filesystem::exists(absolute) && !std::filesystem::is_directory(absolute)) {
            throw_cli_error("E_INVALID_FETCH_DEFAULT_DIR",
                            "--fetch-default-dir must point to a directory",
                            "Select a directory or remove the existing file at " + absolute.string());
        }
        options.fetch_default_directory = absolute.string();
    }

    if (options.min_ttl_seconds && *options.min_ttl_seconds == 0) {
        throw_cli_error("E_INVALID_MIN_TTL",
                        "--min-ttl must be positive",
                        "Provide a value greater than zero");
    }
    if (options.max_ttl_seconds && *options.max_ttl_seconds == 0) {
        throw_cli_error("E_INVALID_MAX_TTL",
                        "--max-ttl must be positive",
                        "Provide a value greater than zero");
    }
    if (options.key_rotation_seconds && *options.key_rotation_seconds == 0) {
        throw_cli_error("E_INVALID_KEY_ROTATION",
                        "--key-rotation must be a positive integer",
                        "Provide the interval in seconds, e.g. --key-rotation 300");
    }
    if (options.announce_interval_seconds && *options.announce_interval_seconds == 0) {
        throw_cli_error("E_INVALID_ANNOUNCE_INTERVAL",
                        "--announce-interval must be a positive integer",
                        "Set a value greater than zero seconds");
    }
    if (options.announce_burst_limit && *options.announce_burst_limit == 0) {
        throw_cli_error("E_INVALID_ANNOUNCE_BURST",
                        "--announce-burst must be a positive integer",
                        "Provide a burst limit greater than zero");
    }
    if (options.announce_window_seconds && *options.announce_window_seconds == 0) {
        throw_cli_error("E_INVALID_ANNOUNCE_WINDOW",
                        "--announce-window must be a positive integer",
                        "Provide the rolling window in seconds");
    }
    if (options.announce_pow_difficulty && *options.announce_pow_difficulty > 24) {
        throw_cli_error("E_INVALID_ANNOUNCE_POW",
                        "--announce-pow must be between 0 and 24",
                        "Use 0 to disable proof-of-work or a small integer");
    }
    if (options.min_ttl_seconds && options.max_ttl_seconds && *options.min_ttl_seconds > *options.max_ttl_seconds) {
        throw_cli_error("E_INVALID_TTL_WINDOW",
                        "--min-ttl must be less than or equal to --max-ttl",
                        "Adjust the TTL window so the minimum does not exceed the maximum");
    }
    if (options.default_ttl_seconds && options.min_ttl_seconds && *options.default_ttl_seconds < *options.min_ttl_seconds) {
        throw_cli_error("E_INVALID_DEFAULT_TTL",
                        "--default-ttl must be greater than or equal to --min-ttl",
                        "Increase the default TTL or lower the minimum bound");
    }
    if (options.default_ttl_seconds && options.max_ttl_seconds && *options.default_ttl_seconds > *options.max_ttl_seconds) {
        throw_cli_error("E_INVALID_DEFAULT_TTL",
                        "--default-ttl must be less than or equal to --max-ttl",
                        "Reduce the default TTL or raise the maximum bound");
    }
}

ephemeralnet::PeerId make_peer_id(const GlobalOptions& options) {
    if (options.peer_id_hex) {
        if (auto parsed = parse_hex_array<ephemeralnet::PeerId>(*options.peer_id_hex)) {
            return *parsed;
        }
        throw_cli_error("E_INVALID_PEER_ID",
                        "--peer-id must be exactly 64 hexadecimal characters",
                        "Example: --peer-id 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    }

    if (options.identity_seed) {
        std::array<std::uint8_t, 4> seed_bytes{};
        const auto seed = *options.identity_seed;
        seed_bytes[0] = static_cast<std::uint8_t>((seed >> 24) & 0xFF);
        seed_bytes[1] = static_cast<std::uint8_t>((seed >> 16) & 0xFF);
        seed_bytes[2] = static_cast<std::uint8_t>((seed >> 8) & 0xFF);
        seed_bytes[3] = static_cast<std::uint8_t>(seed & 0xFF);

        const auto digest = ephemeralnet::crypto::Sha256::digest(std::span<const std::uint8_t>(seed_bytes.data(), seed_bytes.size()));
        ephemeralnet::PeerId id{};
        std::copy(digest.begin(), digest.end(), id.begin());
        return id;
    }

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<std::uint32_t> distribution(0, std::numeric_limits<std::uint32_t>::max());
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = static_cast<std::uint8_t>(distribution(generator) & 0xFF);
    }
    return id;
}

std::uint32_t make_identity_scalar(const GlobalOptions& options) {
    std::mt19937 generator;
    if (options.identity_seed.has_value()) {
        generator.seed(*options.identity_seed);
    } else {
        std::random_device rd;
        generator.seed(rd());
    }

    std::uniform_int_distribution<std::uint32_t> distribution(2u, ephemeralnet::network::KeyExchange::kPrime - 2u);
    return distribution(generator);
}

ephemeralnet::Config build_config(const GlobalOptions& options) {
    ephemeralnet::Config config;
    if (options.persistent_set) {
        config.storage_persistent_enabled = options.persistent;
    }
    if (options.wipe_set) {
        config.storage_wipe_on_expiry = options.wipe;
    }
    if (options.wipe_passes_set) {
        config.storage_wipe_passes = options.wipe_passes;
    }
    if (options.storage_dir) {
        config.storage_directory = strip_quotes(*options.storage_dir);
    }
    if (options.identity_seed) {
        config.identity_seed = options.identity_seed;
    }
    if (options.default_ttl_seconds) {
        config.default_chunk_ttl = std::chrono::seconds(*options.default_ttl_seconds);
    }
    if (options.min_ttl_seconds) {
        config.min_manifest_ttl = std::chrono::seconds(*options.min_ttl_seconds);
    }
    if (options.max_ttl_seconds) {
        config.max_manifest_ttl = std::chrono::seconds(*options.max_ttl_seconds);
    }
    if (options.key_rotation_seconds) {
        config.key_rotation_interval = std::chrono::seconds(*options.key_rotation_seconds);
    }
    if (options.announce_interval_seconds) {
        config.announce_min_interval = std::chrono::seconds(*options.announce_interval_seconds);
    }
    if (options.announce_burst_limit) {
        config.announce_burst_limit = static_cast<std::size_t>(*options.announce_burst_limit);
    }
    if (options.announce_window_seconds) {
        config.announce_burst_window = std::chrono::seconds(*options.announce_window_seconds);
    }
    if (options.announce_pow_difficulty) {
        config.announce_pow_difficulty = static_cast<std::uint8_t>(std::min<std::uint64_t>(*options.announce_pow_difficulty, 24));
    }
    if (options.control_host) {
        config.control_host = strip_quotes(*options.control_host);
    }
    if (options.control_port) {
        config.control_port = *options.control_port;
    }
    if (options.transport_listen_port) {
        config.transport_listen_port = *options.transport_listen_port;
    }
    if (options.control_token) {
        config.control_token = strip_quotes(*options.control_token);
    }
    if (options.control_stream_max_bytes) {
        config.control_stream_max_bytes = static_cast<std::size_t>(*options.control_stream_max_bytes);
    }
    if (options.advertise_control_host) {
        config.advertise_control_host = options.advertise_control_host;
        config.advertise_control_port = options.advertise_control_port;
    }
    if (options.advertise_auto_mode) {
        config.advertise_auto_mode = *options.advertise_auto_mode;
    }
    config.advertise_allow_private = options.advertise_allow_private || options.control_expose_requested
        || config.control_host == "0.0.0.0";
    if (config.advertise_control_host) {
        ephemeralnet::Config::AdvertisedEndpoint endpoint{};
        endpoint.host = *config.advertise_control_host;
        endpoint.port = config.advertise_control_port.value_or(config.control_port);
        endpoint.manual = true;
        endpoint.source = "manual";
        config.advertised_endpoints.push_back(std::move(endpoint));
    }
    if (options.fetch_parallel) {
        config.fetch_max_parallel_requests = *options.fetch_parallel;
    }
    if (options.upload_parallel) {
        config.upload_max_parallel_transfers = *options.upload_parallel;
    }
    if (config.bootstrap_nodes.empty()) {
        config.bootstrap_nodes = shardian_bootstrap_nodes();
    }
    if (config.relay_enabled && config.relay_endpoints.empty()) {
        config.relay_endpoints = shardian_relay_endpoints();
    }
    if (config.transport_listen_port == 0) {
        config.transport_listen_port = kDefaultTransportPort;
    }
    return config;
}

std::vector<std::string> build_daemon_arguments(const GlobalOptions& options) {
    std::vector<std::string> args;
    if (options.storage_dir) {
        args.emplace_back("--storage-dir");
        args.emplace_back(strip_quotes(*options.storage_dir));
    }
    if (options.persistent_set) {
        args.emplace_back(options.persistent ? "--persistent" : "--no-persistent");
    }
    if (options.wipe_set && !options.wipe) {
        args.emplace_back("--no-wipe");
    }
    if (options.wipe_passes_set) {
        args.emplace_back("--wipe-passes");
        args.emplace_back(std::to_string(options.wipe_passes));
    }
    if (options.identity_seed) {
        args.emplace_back("--identity-seed");
        args.emplace_back(std::to_string(*options.identity_seed));
    }
    if (options.peer_id_hex) {
        args.emplace_back("--peer-id");
        args.emplace_back(strip_quotes(*options.peer_id_hex));
    }
    if (options.default_ttl_seconds) {
        args.emplace_back("--default-ttl");
        args.emplace_back(std::to_string(*options.default_ttl_seconds));
    }
    if (options.min_ttl_seconds) {
        args.emplace_back("--min-ttl");
        args.emplace_back(std::to_string(*options.min_ttl_seconds));
    }
    if (options.max_ttl_seconds) {
        args.emplace_back("--max-ttl");
        args.emplace_back(std::to_string(*options.max_ttl_seconds));
    }
    if (options.key_rotation_seconds) {
        args.emplace_back("--key-rotation");
        args.emplace_back(std::to_string(*options.key_rotation_seconds));
    }
    if (options.announce_interval_seconds) {
        args.emplace_back("--announce-interval");
        args.emplace_back(std::to_string(*options.announce_interval_seconds));
    }
    if (options.announce_burst_limit) {
        args.emplace_back("--announce-burst");
        args.emplace_back(std::to_string(*options.announce_burst_limit));
    }
    if (options.announce_window_seconds) {
        args.emplace_back("--announce-window");
        args.emplace_back(std::to_string(*options.announce_window_seconds));
    }
    if (options.announce_pow_difficulty) {
        args.emplace_back("--announce-pow");
        args.emplace_back(std::to_string(*options.announce_pow_difficulty));
    }
    if (options.control_host) {
        args.emplace_back("--control-host");
        args.emplace_back(strip_quotes(*options.control_host));
    }
    if (options.control_port) {
        args.emplace_back("--control-port");
        args.emplace_back(std::to_string(*options.control_port));
    }
    if (options.transport_listen_port) {
        args.emplace_back("--transport-port");
        args.emplace_back(std::to_string(*options.transport_listen_port));
    }
    if (options.control_token) {
        args.emplace_back("--control-token");
        args.emplace_back(strip_quotes(*options.control_token));
    }
    if (options.advertise_control_host) {
        args.emplace_back("--advertise-control");
        args.emplace_back(format_advertise_control_argument(*options.advertise_control_host,
                                                            options.advertise_control_port));
    }
    if (options.advertise_allow_private) {
        args.emplace_back("--advertise-allow-private");
    }
    if (options.advertise_auto_mode) {
        args.emplace_back("--advertise-auto");
        args.emplace_back(std::string(advertise_auto_mode_to_string(*options.advertise_auto_mode)));
    }
    if (options.control_stream_max_bytes) {
        args.emplace_back("--max-store-bytes");
        args.emplace_back(std::to_string(*options.control_stream_max_bytes));
    }
    if (options.fetch_parallel) {
        args.emplace_back("--fetch-parallel");
        args.emplace_back(std::to_string(*options.fetch_parallel));
    }
    if (options.upload_parallel) {
        args.emplace_back("--upload-parallel");
        args.emplace_back(std::to_string(*options.upload_parallel));
    }
    args.emplace_back("serve");
    return args;
}

std::filesystem::path executable_path(const char* argv0 = nullptr) {
#ifdef _WIN32
    std::wstring buffer(512, L'\0');
    DWORD length = 0;
    while (true) {
        length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            throw std::runtime_error("Could not resolve executable path");
        }
        if (length < buffer.size() - 1) {
            buffer.resize(length);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    return std::filesystem::path(buffer);
#else
#ifdef __APPLE__
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) == -1) {
        std::string storage(size, '\0');
        if (_NSGetExecutablePath(storage.data(), &size) == 0) {
            std::error_code ec;
            const auto canonical = std::filesystem::canonical(storage, ec);
            if (!ec) {
                return canonical;
            }
            return std::filesystem::path(storage);
        }
    }
#endif
    std::error_code ec;
    const auto proc_path = std::filesystem::canonical("/proc/self/exe", ec);
    if (!ec) {
        return proc_path;
    }
    if (argv0 && std::strlen(argv0) > 0) {
        std::error_code argv_ec;
        std::filesystem::path candidate(argv0);
        if (!candidate.is_absolute()) {
            candidate = std::filesystem::absolute(candidate, argv_ec);
        }
        if (!argv_ec) {
            const auto resolved = std::filesystem::canonical(candidate, argv_ec);
            if (!argv_ec) {
                return resolved;
            }
        }
        return candidate;
    }
    throw std::runtime_error("Could not resolve executable path");
#endif
}

bool launch_detached(const std::filesystem::path& exe, const std::vector<std::string>& args) {
#ifdef _WIN32
    auto widen = [](const std::string& input) -> std::wstring {
        if (input.empty()) {
            return std::wstring{};
        }
        int length = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (length == 0) {
            length = MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, nullptr, 0);
            if (length == 0) {
                throw std::runtime_error("Could not convert argument to UTF-16");
            }
            std::wstring result(static_cast<std::size_t>(length - 1), L'\0');
            MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, result.data(), length);
            return result;
        }
        std::wstring result(static_cast<std::size_t>(length - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(), length);
        return result;
    };

    auto quote_argument = [](const std::wstring& argument) -> std::wstring {
        if (argument.empty()) {
            return L"\"\"";
        }
        bool needs_quotes = argument.find_first_of(L" \t\"") != std::wstring::npos;
        if (!needs_quotes) {
            return argument;
        }
        std::wstring quoted;
        quoted.reserve(argument.size() + 2);
        quoted.push_back(L'"');
        unsigned backslashes = 0;
        for (wchar_t ch : argument) {
            if (ch == L'\\') {
                ++backslashes;
            } else if (ch == L'"') {
                quoted.append(backslashes * 2 + 1, L'\\');
                quoted.push_back(L'"');
                backslashes = 0;
            } else {
                if (backslashes > 0) {
                    quoted.append(backslashes, L'\\');
                    backslashes = 0;
                }
                quoted.push_back(ch);
            }
        }
        if (backslashes > 0) {
            quoted.append(backslashes * 2, L'\\');
        }
        quoted.push_back(L'"');
        return quoted;
    };

    std::wstring application = exe.wstring();
    std::wstring command_line = quote_argument(application);
    for (const auto& arg : args) {
        command_line.push_back(L' ');
        command_line += quote_argument(widen(arg));
    }

    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);
    PROCESS_INFORMATION process_info{};

    BOOL created = CreateProcessW(
        application.empty() ? nullptr : application.data(),
        mutable_command.data(),
        nullptr,
        nullptr,
        FALSE,
        DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        nullptr,
        &startup_info,
        &process_info);

    if (created) {
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
    } else {
        const DWORD error = GetLastError();
        LPWSTR message_buffer = nullptr;
        const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        if (FormatMessageW(flags,
                           nullptr,
                           error,
                           0,
                           reinterpret_cast<LPWSTR>(&message_buffer),
                           0,
                           nullptr) && message_buffer) {
            std::wcerr << message_buffer;
            LocalFree(message_buffer);
        }
    }

    return created != FALSE;
#else
    pid_t first = ::fork();
    if (first < 0) {
        return false;
    }
    if (first > 0) {
        int status = 0;
        if (::waitpid(first, &status, 0) < 0) {
            return false;
        }
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    if (::setsid() < 0) {
        _exit(1);
    }

    pid_t second = ::fork();
    if (second < 0) {
        _exit(1);
    }
    if (second > 0) {
        _exit(0);
    }

    const int dev_null = ::open("/dev/null", O_RDWR);
    if (dev_null >= 0) {
        ::dup2(dev_null, STDIN_FILENO);
        ::dup2(dev_null, STDOUT_FILENO);
        ::dup2(dev_null, STDERR_FILENO);
        if (dev_null > STDERR_FILENO) {
            ::close(dev_null);
        }
    }

    std::vector<std::string> argv_storage;
    argv_storage.reserve(args.size() + 1);
    argv_storage.push_back(exe.string());
    for (const auto& arg : args) {
        argv_storage.push_back(arg);
    }

    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(argv_storage.size() + 1);
    for (auto& value : argv_storage) {
        argv_ptrs.push_back(value.data());
    }
    argv_ptrs.push_back(nullptr);

    ::execv(argv_storage.front().c_str(), argv_ptrs.data());
    _exit(127);
#endif
}

bool wait_for_daemon(ephemeralnet::daemon::ControlClient& client, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto response = client.send("PING"); response && response->success) {
            return true;
        }
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

bool wait_for_daemon_shutdown(ephemeralnet::daemon::ControlClient& client, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto response = client.send("PING"); !response || !response->success) {
            return true;
        }
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

void print_list_response(const ephemeralnet::daemon::ControlResponse& response) {
    const auto count_it = response.fields.find("COUNT");
    const auto entries_it = response.fields.find("ENTRIES");
    std::vector<std::array<std::string, 4>> entries;

    if (entries_it != response.fields.end() && !entries_it->second.empty()) {
        std::istringstream lines(entries_it->second);
        std::string line;
        while (std::getline(lines, line)) {
            if (line.empty()) {
                continue;
            }
            std::vector<std::string> tokens;
            std::size_t start = 0;
            while (start <= line.size()) {
                const auto pos = line.find(',', start);
                if (pos == std::string::npos) {
                    tokens.emplace_back(line.substr(start));
                    break;
                }
                tokens.emplace_back(line.substr(start, pos - start));
                start = pos + 1;
            }
            if (tokens.size() == 4) {
                entries.push_back({tokens[0], tokens[1], tokens[2], tokens[3]});
            }
        }
    }

    std::optional<std::size_t> reported_count;
    if (count_it != response.fields.end()) {
        try {
            reported_count = static_cast<std::size_t>(std::stoull(count_it->second));
        } catch (...) {
            reported_count.reset();
        }
    }

    const std::size_t entry_count = entries.size();
    const std::size_t display_count = reported_count.has_value() && *reported_count == entry_count
                                          ? *reported_count
                                          : entry_count;

    std::cout << "Local chunks: " << display_count << std::endl;
    if (entries.empty()) {
        return;
    }
    for (const auto& entry : entries) {
        std::cout << "  ID=" << entry[0]
                  << " size=" << entry[1] << " bytes"
                  << ", state=" << entry[2]
                  << ", ttl=" << entry[3] << "s" << std::endl;
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::vector<std::string_view> args;
        args.reserve(static_cast<std::size_t>(argc));
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }

        GlobalOptions options{};
        std::size_t index = 0;

        auto require_value = [&](std::string_view option) -> std::string {
            if (index >= args.size()) {
                throw_cli_error("E_MISSING_VALUE",
                                std::string(option) + " requires a value",
                                "Provide an argument immediately after " + std::string(option));
            }
            return std::string(args[index++]);
        };

        std::optional<std::string> extracted_command;

        while (index < args.size()) {
            if (!args[index].starts_with("-")) {
                if (!extracted_command) {
                    extracted_command = std::string(args[index++]);
                    continue;
                }
                break;
            }

            const auto opt = args[index++];
            if (opt == "--help" || opt == "-h") {
                if (extracted_command) {
                    --index;
                    break;
                }
                print_usage();
                return 0;
            }
            if (opt == "--version") {
                std::cout << "EphemeralNet " << kEphemeralNetVersion << std::endl;
                return 0;
            }
            if (opt == "--yes" || opt == "-y") {
                options.assume_yes = true;
                options.assume_yes_set = true;
                continue;
            }
            if (opt == "--config") {
                if (options.config_path.has_value()) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Option --config specified multiple times",
                                    "Provide the configuration file only once");
                }
                options.config_path = require_value(opt);
                continue;
            }
            if (opt == "--profile") {
                if (options.profile_name.has_value()) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Option --profile specified multiple times",
                                    "Select a single profile");
                }
                options.profile_name = require_value(opt);
                continue;
            }
            if (opt == "--env") {
                if (options.environment.has_value()) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Option --env specified multiple times",
                                    "Select a single environment override");
                }
                options.environment = require_value(opt);
                continue;
            }
            if (opt == "--storage-dir") {
                if (options.storage_dir.has_value()) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Option --storage-dir specified multiple times",
                                    "Provide the storage directory only once");
                }
                options.storage_dir = require_value(opt);
                continue;
            }
            if (opt == "--persistent") {
                if (options.persistent_set) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Persistence options specified multiple times",
                                    "Use either --persistent or --no-persistent once");
                }
                options.persistent = true;
                options.persistent_set = true;
                continue;
            }
            if (opt == "--no-persistent") {
                if (options.persistent_set) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Persistence options specified multiple times",
                                    "Use either --persistent or --no-persistent once");
                }
                options.persistent = false;
                options.persistent_set = true;
                continue;
            }
            if (opt == "--no-wipe") {
                options.wipe = false;
                options.wipe_set = true;
                continue;
            }
            if (opt == "--wipe-passes") {
                const auto value = require_value(opt);
                std::uint64_t parsed{};
                if (!parse_uint64(value, parsed) || parsed == 0 || parsed > 255) {
                    throw_cli_error("E_INVALID_WIPE_PASSES",
                                    "--wipe-passes must be between 1 and 255",
                                    "Use a small positive integer, e.g. --wipe-passes 3");
                }
                options.wipe_passes = static_cast<std::uint8_t>(parsed);
                options.wipe_passes_set = true;
                continue;
            }
            if (opt == "--identity-seed") {
                const auto value = require_value(opt);
                std::uint32_t seed{};
                if (!parse_uint32(value, seed)) {
                    throw_cli_error("E_INVALID_IDENTITY_SEED",
                                    "--identity-seed must be an unsigned integer",
                                    "For example: --identity-seed 123456");
                }
                options.identity_seed = seed;
                continue;
            }
            if (opt == "--peer-id") {
                options.peer_id_hex = require_value(opt);
                continue;
            }
            if (opt == "--default-ttl") {
                const auto value = require_value(opt);
                std::uint64_t ttl{};
                if (!parse_duration_seconds(value, ttl) || ttl == 0) {
                    throw_cli_error("E_INVALID_DEFAULT_TTL",
                                    "--default-ttl must be a positive duration (accepts s/m/h/d suffixes)",
                                    "Examples: --default-ttl 3600, --default-ttl 30m, --default-ttl 2h");
                }
                options.default_ttl_seconds = ttl;
                continue;
            }
            if (opt == "--min-ttl") {
                const auto value = require_value(opt);
                std::uint64_t ttl{};
                if (!parse_duration_seconds(value, ttl) || ttl == 0) {
                    throw_cli_error("E_INVALID_MIN_TTL",
                                    "--min-ttl must be a positive duration (accepts s/m/h/d suffixes)",
                                    "Examples: --min-ttl 30s, --min-ttl 30m");
                }
                options.min_ttl_seconds = ttl;
                continue;
            }
            if (opt == "--max-ttl") {
                const auto value = require_value(opt);
                std::uint64_t ttl{};
                if (!parse_duration_seconds(value, ttl) || ttl == 0) {
                    throw_cli_error("E_INVALID_MAX_TTL",
                                    "--max-ttl must be a positive duration (accepts s/m/h/d suffixes)",
                                    "Examples: --max-ttl 86400, --max-ttl 24h");
                }
                options.max_ttl_seconds = ttl;
                continue;
            }
            if (opt == "--key-rotation") {
                const auto value = require_value(opt);
                std::uint64_t interval{};
                if (!parse_duration_seconds(value, interval) || interval == 0) {
                    throw_cli_error("E_INVALID_KEY_ROTATION",
                                    "--key-rotation must be a positive duration (accepts s/m/h/d suffixes)",
                                    "Examples: --key-rotation 300, --key-rotation 5m");
                }
                options.key_rotation_seconds = interval;
                continue;
            }
            if (opt == "--announce-interval") {
                const auto value = require_value(opt);
                std::uint64_t interval{};
                if (!parse_duration_seconds(value, interval) || interval == 0) {
                    throw_cli_error("E_INVALID_ANNOUNCE_INTERVAL",
                                    "--announce-interval must be a positive duration (accepts s/m/h/d suffixes)",
                                    "Examples: --announce-interval 15, --announce-interval 2m");
                }
                options.announce_interval_seconds = interval;
                continue;
            }
            if (opt == "--announce-burst") {
                const auto value = require_value(opt);
                std::uint64_t limit{};
                if (!parse_uint64(value, limit) || limit == 0) {
                    throw_cli_error("E_INVALID_ANNOUNCE_BURST",
                                    "--announce-burst must be a positive integer",
                                    "Specify how many announces are allowed per window, e.g. --announce-burst 4");
                }
                options.announce_burst_limit = limit;
                continue;
            }
            if (opt == "--announce-window") {
                const auto value = require_value(opt);
                std::uint64_t window{};
                if (!parse_duration_seconds(value, window) || window == 0) {
                    throw_cli_error("E_INVALID_ANNOUNCE_WINDOW",
                                    "--announce-window must be a positive duration (accepts s/m/h/d suffixes)",
                                    "Examples: --announce-window 120, --announce-window 5m");
                }
                options.announce_window_seconds = window;
                continue;
            }
            if (opt == "--announce-pow") {
                const auto value = require_value(opt);
                std::uint64_t difficulty{};
                if (!parse_uint64(value, difficulty) || difficulty > 24) {
                    throw_cli_error("E_INVALID_ANNOUNCE_POW",
                                    "--announce-pow must be between 0 and 24",
                                    "Use 0 to disable proof-of-work or a small integer number of leading zero bits");
                }
                options.announce_pow_difficulty = difficulty;
                continue;
            }
            if (opt == "--control-host") {
                options.control_host = require_value(opt);
                options.control_expose_requested = false;
                continue;
            }
            if (opt == "--control-expose") {
                options.control_host = "0.0.0.0";
                options.control_expose_requested = true;
                continue;
            }
            if (opt == "--control-loopback") {
                options.control_host = "127.0.0.1";
                options.control_expose_requested = false;
                continue;
            }
            if (opt == "--control-port") {
                const auto value = require_value(opt);
                std::uint16_t port{};
                if (!parse_uint16(value, port)) {
                    throw_cli_error("E_INVALID_CONTROL_PORT",
                                    "--control-port must be an integer between 1 and 65535",
                                    "For example: --control-port 47777");
                }
                options.control_port = port;
                continue;
            }
            if (opt == "--transport-port") {
                const auto value = require_value(opt);
                std::uint16_t port{};
                if (!parse_uint16(value, port)) {
                    throw_cli_error("E_INVALID_TRANSPORT_PORT",
                                    "--transport-port must be an integer between 1 and 65535",
                                    "For example: --transport-port 45000");
                }
                options.transport_listen_port = port;
                continue;
            }
            if (opt == "--control-token") {
                if (options.control_token.has_value()) {
                    throw_cli_error("E_DUPLICATE_OPTION",
                                    "Option --control-token specified multiple times",
                                    "Provide the token only once");
                }
                options.control_token = require_value(opt);
                continue;
            }
            if (opt == "--advertise-control") {
                const auto raw = strip_quotes(require_value(opt));
                std::string advertise_host;
                std::optional<std::uint16_t> advertise_port;
                if (auto error = split_advertise_control_endpoint(raw, advertise_host, advertise_port)) {
                    throw_cli_error("E_INVALID_ADVERTISE_CONTROL",
                                    *error,
                                    "Use host[:port], e.g. example.com:47777 or [2001:db8::1]:47777");
                }
                options.advertise_control_host = advertise_host;
                options.advertise_control_port = advertise_port;
                options.advertise_control_set = true;
                continue;
            }
            if (opt == "--advertise-allow-private") {
                options.advertise_allow_private = true;
                continue;
            }
            if (opt == "--advertise-auto") {
                if (index >= args.size()) {
                    throw_cli_error("E_MISSING_ADVERTISE_AUTO",
                                    "--advertise-auto requires a value (on|off|warn)",
                                    "Example: --advertise-auto warn");
                }
                const auto mode_value = args[index++];
                ephemeralnet::Config::AdvertiseAutoMode mode;
                if (!try_parse_advertise_auto_mode(std::string(mode_value), mode)) {
                    throw_cli_error("E_INVALID_ADVERTISE_AUTO",
                                    "--advertise-auto accepts only on|off|warn",
                                    "Example: --advertise-auto warn");
                }
                options.advertise_auto_mode = mode;
                continue;
            }
            if (opt.rfind("--advertise-auto=", 0) == 0) {
                const auto value = opt.substr(std::string("--advertise-auto=").size());
                ephemeralnet::Config::AdvertiseAutoMode mode;
                if (!try_parse_advertise_auto_mode(std::string(value), mode)) {
                    throw_cli_error("E_INVALID_ADVERTISE_AUTO",
                                    "--advertise-auto accepts only on|off|warn",
                                    "Example: --advertise-auto warn");
                }
                options.advertise_auto_mode = mode;
                continue;
            }
            if (opt == "--max-store-bytes") {
                const auto value = require_value(opt);
                std::uint64_t limit{};
                if (!parse_uint64(value, limit)) {
                    throw_cli_error("E_INVALID_STORE_LIMIT",
                                    "--max-store-bytes must be zero or a positive integer",
                                    "Use 0 to disable the limit or specify the maximum payload size in bytes");
                }
                options.control_stream_max_bytes = limit;
                continue;
            }
            if (opt == "--fetch-parallel") {
                const auto value = require_value(opt);
                std::uint64_t parallel{};
                if (!parse_uint64(value, parallel) || parallel > std::numeric_limits<std::uint16_t>::max()) {
                    throw_cli_error("E_INVALID_FETCH_PARALLEL",
                                    "--fetch-parallel must be between 0 and 65535",
                                    "Use 0 for unlimited or a small positive integer");
                }
                options.fetch_parallel = static_cast<std::uint16_t>(parallel);
                continue;
            }
            if (opt == "--upload-parallel") {
                const auto value = require_value(opt);
                std::uint64_t parallel{};
                if (!parse_uint64(value, parallel) || parallel > std::numeric_limits<std::uint16_t>::max()) {
                    throw_cli_error("E_INVALID_UPLOAD_PARALLEL",
                                    "--upload-parallel must be between 0 and 65535",
                                    "Use 0 for unlimited or a small positive integer");
                }
                options.upload_parallel = static_cast<std::uint16_t>(parallel);
                continue;
            }
            if (opt == "--fetch-default-dir") {
                options.fetch_default_directory = require_value(opt);
                continue;
            }
            if (opt == "--fetch-use-manifest-name") {
                options.fetch_use_manifest_name = true;
                options.fetch_use_manifest_name_set = true;
                continue;
            }
            if (opt == "--fetch-ignore-manifest-name") {
                options.fetch_use_manifest_name = false;
                options.fetch_use_manifest_name_set = true;
                continue;
            }

            if (extracted_command) {
                --index;
                break;
            }

            throw_cli_error("E_UNKNOWN_OPTION",
                            "Unknown option: " + std::string(opt),
                            "Run 'eph --help' to view available options");
        }

        try {
            load_configuration(options);
        } catch (const config::ConfigError& ex) {
            throw_cli_error(ex.code, ex.message, ex.hint);
        }

        validate_global_options(options);

        const auto self_peer_id = make_peer_id(options);

        std::string command;
        if (extracted_command) {
            command = to_lower(*extracted_command);
        } else {
            if (index >= args.size()) {
                print_usage();
                return 1;
            }
            command = to_lower(std::string(args[index++]));
        }
        if (command == "help") {
            print_usage();
            return 0;
        }

        if (command == "man") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_manual();
                    return 0;
                }
                throw_cli_error("E_MAN_UNEXPECTED_ARGUMENT",
                                "man does not accept additional arguments",
                                "Run 'eph man' or 'eph man --help'");
            }
            print_manual();
            return 0;
        }

        auto config = build_config(options);
        ephemeralnet::daemon::set_max_control_stream_bytes(config.control_stream_max_bytes);

        if (command == "serve") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_serve_usage();
                    return 0;
                }
                throw_cli_error("E_SERVE_UNKNOWN_OPTION",
                                "Unknown option for serve: " + std::string(args[index]),
                                "Run 'eph serve --help' to view usage");
            }
            if (!acknowledge_control_exposure(options, config)) {
                return 1;
            }

            const auto peer_id = self_peer_id;
            ephemeralnet::Node node(peer_id, config);


            std::mutex node_mutex;
            g_shutdown_reason.store(ShutdownReason::None, std::memory_order_release);
            g_run_loop.store(true, std::memory_order_release);
            ephemeralnet::daemon::ControlServer control_server(
                node,
                node_mutex,
                []() { request_shutdown(ShutdownReason::Control); });
            control_server.start(config.control_host, config.control_port);

            install_termination_handlers();

            std::vector<std::string> runtime_auto_advertise_warnings;
            bool runtime_auto_advertise_conflict = false;
            {
                std::scoped_lock lock(node_mutex);
                node.start_transport(config.transport_listen_port);
                runtime_auto_advertise_warnings = node.config().auto_advertise_warnings;
                runtime_auto_advertise_conflict = node.config().auto_advertise_conflict;
            }

            if (!runtime_auto_advertise_warnings.empty()) {
                for (const auto& warning : runtime_auto_advertise_warnings) {
                    std::cout << "[auto-advertise] " << warning << std::endl;
                }
                for (const auto& warning : runtime_auto_advertise_warnings) {
                    ephemeralnet::daemon::StructuredLogger::FieldList fields{{"warning", warning}};
                    fields.emplace_back("conflict", runtime_auto_advertise_conflict ? "1" : "0");
                    ephemeralnet::daemon::StructuredLogger::instance().log(
                        ephemeralnet::daemon::StructuredLogger::Level::Warning,
                        "auto_advertise.warning",
                        std::move(fields));
                }
            }

            std::cout << "Daemon running. Control at " << config.control_host << ':' << config.control_port << std::endl;
            std::cout << "Transport port: " << node.transport_port() << std::endl;
            std::cout << "Press Ctrl+C or run 'eph stop' to exit." << std::endl;

            while (true) {
                if (!g_run_loop.load(std::memory_order_acquire)) {
                    break;
                }
                {
                    std::scoped_lock lock(node_mutex);
                    node.tick();
                }
                std::this_thread::sleep_for(1s);
            }

            const auto shutdown_reason = g_shutdown_reason.exchange(ShutdownReason::None, std::memory_order_acq_rel);
            if (shutdown_reason == ShutdownReason::Signal) {
                std::cout << "\nInterrupt received, shutting down..." << std::endl;
            }

            {
                std::scoped_lock lock(node_mutex);
                std::cout << "Stopping transport..." << std::endl;
                node.stop_transport();
            }
            std::cout << "Transport stopped." << std::endl;

            std::cout << "Stopping control server..." << std::endl;
            control_server.stop();
            std::cout << "Control server stopped." << std::endl;
            uninstall_termination_handlers();
            std::cout << "Daemon stopped." << std::endl;
            return 0;
        }

        ephemeralnet::daemon::ControlClient client(config.control_host, config.control_port, config.control_token);

        if (command == "start") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_start_usage();
                    return 0;
                }
                throw_cli_error("E_START_UNKNOWN_OPTION",
                                "Unknown option for start: " + std::string(args[index]),
                                "Run 'eph start --help' to view usage");
            }
            if (auto ping = client.send("PING"); ping && ping->success) {
                std::cout << "Daemon is already running." << std::endl;
                return 0;
            }

            if (!acknowledge_control_exposure(options, config)) {
                return 1;
            }

            const auto exe = executable_path(argc > 0 ? argv[0] : nullptr);
            const auto args_to_launch = build_daemon_arguments(options);
            if (!launch_detached(exe, args_to_launch)) {
                std::cerr << "Failed to launch the daemon in the background." << std::endl;
                return 1;
            }

            if (!wait_for_daemon(client, 5s)) {
                std::cerr << "Daemon did not respond after startup." << std::endl;
                return 1;
            }

            std::cout << "Daemon started in the background." << std::endl;
            return 0;
        }

        if (command == "stop") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_stop_usage();
                    return 0;
                }
                throw_cli_error("E_STOP_UNKNOWN_OPTION",
                                "Unknown option for stop: " + std::string(args[index]),
                                "Run 'eph stop --help' to view usage");
            }
            const auto response = client.send("STOP");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }
            const auto message_it = response->fields.find("MESSAGE");
            if (message_it != response->fields.end() && !message_it->second.empty()) {
                std::cout << message_it->second << std::endl;
            }

            print_daemon_hint(*response);

            if (!wait_for_daemon_shutdown(client, 5s)) {
                std::cerr << "Daemon did not shut down cleanly." << std::endl;
                return 1;
            }

            std::cout << "Daemon stopped" << std::endl;
            return 0;
        }

        if (command == "status") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_status_usage();
                    return 0;
                }
                throw_cli_error("E_STATUS_UNKNOWN_OPTION",
                                "Unknown option for status: " + std::string(args[index]),
                                "Run 'eph status --help' to view usage");
            }
            const auto response = client.send("STATUS");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }
            const auto peers = response->fields.contains("PEERS") ? response->fields.at("PEERS") : "0";
            const auto chunks = response->fields.contains("CHUNKS") ? response->fields.at("CHUNKS") : "0";
            const auto port = response->fields.contains("TRANSPORT_PORT") ? response->fields.at("TRANSPORT_PORT") : "0";
            std::cout << "Daemon active" << std::endl;
            std::cout << "  Connected peers:  " << peers << std::endl;
            std::cout << "  Local chunks:     " << chunks << std::endl;
            std::cout << "  Transport port:   " << port << std::endl;
            bool printed_auto_advertise_header = false;
            if (const auto warnings_it = response->fields.find("AUTO_ADVERTISE_WARNINGS");
                warnings_it != response->fields.end() && !warnings_it->second.empty()) {
                std::cout << "Auto-advertise warnings:" << std::endl;
                printed_auto_advertise_header = true;
                std::istringstream warning_stream(warnings_it->second);
                std::string warning_line;
                while (std::getline(warning_stream, warning_line)) {
                    if (warning_line.empty()) {
                        continue;
                    }
                    std::cout << "  - " << warning_line << std::endl;
                }
            }
            bool auto_advertise_conflict = false;
            if (const auto conflict_it = response->fields.find("AUTO_ADVERTISE_CONFLICT");
                conflict_it != response->fields.end()) {
                auto_advertise_conflict = conflict_it->second == "1";
            }
            if (auto_advertise_conflict) {
                if (!printed_auto_advertise_header) {
                    std::cout << "Auto-advertise warnings:" << std::endl;
                    printed_auto_advertise_header = true;
                }
                std::cout << "  - Conflicting endpoints detected across gateways/interfaces. "
                          << "Set --advertise-control-host/--advertise-control-port to pin one." << std::endl;
            }
            print_daemon_hint(*response);
            return 0;
        }

        if (command == "diagnostics") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    std::cout << "Usage: eph diagnostics" << std::endl;
                    std::cout << "Run connectivity diagnostics on the daemon." << std::endl;
                    return 0;
                }
                throw_cli_error("E_DIAGNOSTICS_UNKNOWN_OPTION",
                                "Unknown option for diagnostics: " + std::string(args[index]),
                                "Run 'eph diagnostics --help' to view usage");
            }
            const auto response = client.send("DIAGNOSTICS");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }

            std::cout << "Connectivity Diagnostics" << std::endl;
            const auto nat_type = response->fields.contains("NAT_TYPE") ? response->fields.at("NAT_TYPE") : "Unknown";
            const auto public_endpoint = response->fields.contains("PUBLIC_ENDPOINT") ? response->fields.at("PUBLIC_ENDPOINT") : "Unknown";
            const auto active_peers = response->fields.contains("ACTIVE_PEERS") ? response->fields.at("ACTIVE_PEERS") : "0";
            const auto bootstrap_status = response->fields.contains("BOOTSTRAP_STATUS") ? response->fields.at("BOOTSTRAP_STATUS") : "";

            std::cout << "  NAT Type:         " << nat_type << std::endl;
            std::cout << "  Public Endpoint:  " << public_endpoint << std::endl;
            std::cout << "  Active Peers:     " << active_peers << std::endl;

            if (!bootstrap_status.empty()) {
                std::cout << "  Bootstrap Nodes:" << std::endl;
                std::istringstream stream(bootstrap_status);
                std::string segment;
                while (std::getline(stream, segment, ',')) {
                    std::cout << "    - " << segment << std::endl;
                }
            } else {
                std::cout << "  Bootstrap Nodes:  None configured or reported" << std::endl;
            }

            print_daemon_hint(*response);
            return 0;
        }

        if (command == "list") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_list_usage();
                    return 0;
                }
                throw_cli_error("E_LIST_UNKNOWN_OPTION",
                                "Unknown option for list: " + std::string(args[index]),
                                "Run 'eph list --help' to view usage");
            }
            const auto response = client.send("LIST");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }
            print_list_response(*response);
            print_daemon_hint(*response);
            return 0;
        }

        if (command == "defaults") {
            if (index < args.size()) {
                if (is_help_flag(args[index])) {
                    print_defaults_usage();
                    return 0;
                }
                throw_cli_error("E_DEFAULTS_UNKNOWN_OPTION",
                                "Unknown option for defaults: " + std::string(args[index]),
                                "Run 'eph defaults --help' to view usage");
            }
            const auto response = client.send("DEFAULTS");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }

            std::cout << "Daemon defaults" << std::endl;
            const auto default_ttl = response->fields.contains("DEFAULT_TTL") ? response->fields.at("DEFAULT_TTL") : std::string("0");
            const auto min_ttl = response->fields.contains("MIN_TTL") ? response->fields.at("MIN_TTL") : std::string("0");
            const auto max_ttl = response->fields.contains("MAX_TTL") ? response->fields.at("MAX_TTL") : std::string("0");
            const auto key_rotation = response->fields.contains("KEY_ROTATION") ? response->fields.at("KEY_ROTATION") : std::string("0");
            const auto announce_interval = response->fields.contains("ANNOUNCE_INTERVAL") ? response->fields.at("ANNOUNCE_INTERVAL") : std::string("0");
            const auto announce_burst = response->fields.contains("ANNOUNCE_BURST") ? response->fields.at("ANNOUNCE_BURST") : std::string("0");
            const auto announce_window = response->fields.contains("ANNOUNCE_WINDOW") ? response->fields.at("ANNOUNCE_WINDOW") : std::string("0");
            const auto announce_pow = response->fields.contains("ANNOUNCE_POW") ? response->fields.at("ANNOUNCE_POW") : std::string("0");
            const auto handshake_pow = response->fields.contains("HANDSHAKE_POW") ? response->fields.at("HANDSHAKE_POW") : std::string("0");
            const auto store_pow = response->fields.contains("STORE_POW") ? response->fields.at("STORE_POW") : std::string("0");
            const auto control_host = response->fields.contains("CONTROL_HOST") ? response->fields.at("CONTROL_HOST") : std::string("127.0.0.1");
            const auto control_port = response->fields.contains("CONTROL_PORT") ? response->fields.at("CONTROL_PORT") : std::string("47777");
            const auto transport_port = response->fields.contains("TRANSPORT_PORT")
                                            ? response->fields.at("TRANSPORT_PORT")
                                            : std::to_string(kDefaultTransportPort);
            const auto control_stream_max = response->fields.contains("CONTROL_STREAM_MAX") ? response->fields.at("CONTROL_STREAM_MAX") : std::string("0");
            const auto storage_persistent = response->fields.contains("STORAGE_PERSISTENT") ? response->fields.at("STORAGE_PERSISTENT") : std::string("0");
            const auto storage_dir = response->fields.contains("STORAGE_DIR") ? response->fields.at("STORAGE_DIR") : std::string("storage");
            const auto fetch_parallel = response->fields.contains("FETCH_MAX_PARALLEL") ? response->fields.at("FETCH_MAX_PARALLEL") : std::string("0");
            const auto upload_parallel = response->fields.contains("UPLOAD_MAX_PARALLEL") ? response->fields.at("UPLOAD_MAX_PARALLEL") : std::string("0");
            const auto advertise_auto = response->fields.contains("ADVERTISE_AUTO_MODE")
                                            ? response->fields.at("ADVERTISE_AUTO_MODE")
                                            : std::string("on");
            const auto advertise_endpoints = response->fields.contains("ADVERTISE_ENDPOINTS")
                                                 ? response->fields.at("ADVERTISE_ENDPOINTS")
                                                 : std::string();
            const auto bootstrap_nodes = response->fields.contains("BOOTSTRAP_NODES")
                                              ? response->fields.at("BOOTSTRAP_NODES")
                                              : std::string();

            std::cout << "  Default TTL:        " << default_ttl << " seconds" << std::endl;
            std::cout << "  TTL window:         " << min_ttl << "s - " << max_ttl << "s" << std::endl;
            std::cout << "  Key rotation:       " << key_rotation << " seconds" << std::endl;
            std::cout << "  Announce interval:  every " << announce_interval << " seconds" << std::endl;
            std::cout << "  Announce burst:     " << announce_burst << " events / " << announce_window << "s window" << std::endl;
            std::cout << "  Announce PoW:       " << announce_pow << " leading zero bits" << std::endl;
            std::cout << "  Handshake PoW:      " << handshake_pow << " leading zero bits" << std::endl;
            std::cout << "  Store PoW:          " << store_pow << " leading zero bits" << std::endl;
            std::cout << "  Control endpoint:   " << control_host << ':' << control_port << std::endl;
            std::cout << "  Transport port:     " << transport_port << std::endl;
            std::cout << "  Advertise auto:     " << advertise_auto << std::endl;
            if (!advertise_endpoints.empty()) {
                std::cout << "  Advertised endpoints:" << std::endl;
                std::istringstream endpoints_stream(advertise_endpoints);
                std::string line;
                while (std::getline(endpoints_stream, line)) {
                    if (!line.empty()) {
                        std::cout << "    - " << line << std::endl;
                    }
                }
            }
            if (!bootstrap_nodes.empty()) {
                std::cout << "  Bootstrap seeds:" << std::endl;
                std::istringstream seeds_stream(bootstrap_nodes);
                std::string line;
                while (std::getline(seeds_stream, line)) {
                    if (!line.empty()) {
                        std::cout << "    - " << line << std::endl;
                    }
                }
            }
            std::cout << "  Control cap:        " << control_stream_max << " bytes (0 = unlimited)" << std::endl;
            std::cout << "  Persistent storage: "
                      << (storage_persistent == "1" ? "enabled" : "disabled")
                      << std::endl;
            std::cout << "  Storage directory:  " << storage_dir << std::endl;
            std::cout << "  Fetch concurrency:  " << fetch_parallel << std::endl;
            std::cout << "  Upload concurrency: " << upload_parallel << std::endl;
            std::cout << std::endl;
            std::cout << "CLI fetch defaults" << std::endl;
            const auto cli_dest = options.fetch_default_directory
                                       ? *options.fetch_default_directory
                                       : std::filesystem::current_path().string();
            std::cout << "  Output directory:  " << cli_dest << std::endl;
            std::cout << "  Use stored names:  "
                      << (options.fetch_use_manifest_name ? "enabled" : "disabled")
                      << std::endl;
            print_daemon_hint(*response);
            return 0;
        }

        if (command == "store") {
            if (index < args.size() && is_help_flag(args[index])) {
                print_store_usage();
                return 0;
            }
            if (index >= args.size()) {
                throw_cli_error("E_STORE_MISSING_PATH",
                                "store expects the path to a file",
                                "Example: eph store ./file.txt --ttl 3600");
            }
            const auto input_path = std::filesystem::absolute(std::filesystem::path(args[index++]));
            if (!std::filesystem::exists(input_path)) {
                throw_cli_error("E_STORE_FILE_NOT_FOUND",
                                "File not found: " + input_path.string(),
                                "Check the path or provide an absolute path");
            }
            if (!std::filesystem::is_regular_file(input_path)) {
                throw_cli_error("E_STORE_INVALID_FILE",
                                "store expects a regular file",
                                "Provide a path to a readable file, not a directory or device");
            }

            std::optional<std::uint64_t> ttl_override;
            while (index < args.size()) {
                const auto opt = args[index++];
                if (opt == "--ttl") {
                    if (index >= args.size()) {
                        throw_cli_error("E_STORE_MISSING_TTL",
                                        "--ttl requires a value",
                                        "Examples: --ttl 3600, --ttl 30m, --ttl 2h");
                    }
                    std::uint64_t ttl{};
                    if (!parse_duration_seconds(args[index++], ttl) || ttl == 0) {
                        throw_cli_error("E_STORE_INVALID_TTL",
                                        "--ttl must be a positive duration (accepts s/m/h/d suffixes)",
                                        "Examples: --ttl 1800, --ttl 30m, --ttl 2h");
                    }
                    ttl_override = ttl;
                    continue;
                }
                if (is_help_flag(opt)) {
                    print_store_usage();
                    return 0;
                }
                throw_cli_error("E_STORE_UNKNOWN_OPTION",
                                "Unknown option for store: " + std::string(opt),
                                "Run 'eph store --help' to see valid modifiers");
            }

            const auto file_size = std::filesystem::file_size(input_path);
            const auto stream_limit = config.control_stream_max_bytes;
            if (stream_limit != 0 && file_size > stream_limit) {
                throw_cli_error("E_STORE_PAYLOAD_TOO_LARGE",
                                "File exceeds the daemon control-plane upload cap",
                                "Increase --max-store-bytes (current cap: " + std::to_string(stream_limit) +
                                    ") or set it to 0 for unlimited uploads");
            }

            std::uint8_t store_pow_difficulty = 0;
            std::optional<std::size_t> daemon_stream_limit;
            if (const auto defaults = client.send("DEFAULTS"); defaults) {
                if (!defaults->success) {
                    print_daemon_failure(*defaults);
                    return 1;
                }
                if (const auto pow_it = defaults->fields.find("STORE_POW"); pow_it != defaults->fields.end()) {
                    std::uint64_t parsed = 0;
                    if (parse_uint64(pow_it->second, parsed)) {
                        if (parsed > ephemeralnet::security::kMaxStorePowDifficulty) {
                            parsed = ephemeralnet::security::kMaxStorePowDifficulty;
                        }
                        store_pow_difficulty = static_cast<std::uint8_t>(parsed);
                    }
                }
                if (const auto limit_it = defaults->fields.find("CONTROL_STREAM_MAX"); limit_it != defaults->fields.end()) {
                    std::uint64_t parsed = 0;
                    if (parse_uint64(limit_it->second, parsed)) {
                        daemon_stream_limit = static_cast<std::size_t>(parsed);
                    }
                }
            } else {
                throw_daemon_unreachable();
            }

            if (daemon_stream_limit.has_value() && *daemon_stream_limit != 0 && file_size > *daemon_stream_limit) {
                throw_cli_error("E_STORE_SERVER_CAP",
                                "File exceeds the daemon control-plane upload cap",
                                "Restart the daemon with --max-store-bytes 0 or a larger value to upload this file");
            }

            if (!confirm_action("Store " + input_path.filename().string() + " (" + std::to_string(file_size) +
                                    " bytes). Continue?",
                                true,
                                options.assume_yes)) {
                std::cout << "Operation cancelled by the user." << std::endl;
                return 0;
            }

            std::vector<std::uint8_t> payload(static_cast<std::size_t>(file_size));
            ProgressPrinter read_progress("Reading file");
            if (file_size > 0) {
                std::ifstream input_stream(input_path, std::ios::binary);
                if (!input_stream) {
                    throw_cli_error("E_STORE_READ_FAILED",
                                    "Failed to open file for reading",
                                    "Verify permissions and that the path is accessible");
                }
                constexpr std::size_t kReadChunk = 1 * 1024 * 1024;
                std::size_t offset = 0;
                while (offset < payload.size()) {
                    const auto remaining = payload.size() - offset;
                    const auto to_read = remaining < kReadChunk ? remaining : kReadChunk;
                    input_stream.read(reinterpret_cast<char*>(payload.data() + offset),
                                      static_cast<std::streamsize>(to_read));
                    const auto read_count = static_cast<std::size_t>(input_stream.gcount());
                    if (read_count == 0) {
                        throw_cli_error("E_STORE_READ_FAILED",
                                        "Could not read the entire file",
                                        "Ensure the file is not locked and try again");
                    }
                    offset += read_count;
                    read_progress.update(offset, payload.size());
                    if (read_count < to_read && offset < payload.size()) {
                        throw_cli_error("E_STORE_READ_FAILED",
                                        "Could not read the entire file",
                                        "Ensure the file is not locked and try again");
                    }
                }
                if (!input_stream && !input_stream.eof()) {
                    throw_cli_error("E_STORE_READ_FAILED",
                                    "Failed to read file contents",
                                    "Check for hardware or filesystem errors");
                }
            }
            read_progress.finish(payload.size());

            const auto chunk_id = ephemeralnet::security::derive_chunk_id(
                std::span<const std::uint8_t>(payload.data(), payload.size()));
            const auto filename_hint = ephemeralnet::security::sanitize_filename_hint(input_path.string());
            const ephemeralnet::security::StoreWorkInput pow_input{
                chunk_id,
                static_cast<std::uint64_t>(payload.size()),
                filename_hint ? std::string_view(*filename_hint) : std::string_view{}
            };

            std::optional<std::uint64_t> store_pow_nonce;
            if (store_pow_difficulty > 0) {
                store_pow_nonce = ephemeralnet::security::compute_store_pow(pow_input, store_pow_difficulty);
                if (!store_pow_nonce.has_value()) {
                    throw_cli_error("E_STORE_POW_SEARCH_EXHAUSTED",
                                    "Unable to satisfy the daemon's proof-of-work requirement",
                                    "Retry the command or lower the store PoW difficulty on the daemon");
                }
            } else {
                store_pow_nonce = std::uint64_t{0};
            }

            ephemeralnet::daemon::ControlFields fields{{"PATH", input_path.string()}};
            if (ttl_override) {
                fields["TTL"] = std::to_string(*ttl_override);
            }
            if (store_pow_nonce.has_value()) {
                fields["STORE-POW"] = std::to_string(*store_pow_nonce);
            }

            ProgressPrinter upload_progress("Uploading");
            ephemeralnet::daemon::ControlTransferProgress transfer_progress{};
            transfer_progress.on_upload = [&upload_progress](std::size_t current, std::size_t total) {
                upload_progress.update(current, total);
            };

            const auto response = client.send("STORE",
                                              fields,
                                              std::span<const std::uint8_t>(payload.data(), payload.size()),
                                              &transfer_progress);
            if (!response) {
                upload_progress.cancel();
                throw_daemon_unreachable();
            }
            upload_progress.finish(payload.size());
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }

            const auto manifest = response->fields.contains("MANIFEST") ? response->fields.at("MANIFEST") : "";
            const auto size = response->fields.contains("SIZE") ? response->fields.at("SIZE") : "0";
            const auto ttl = response->fields.contains("TTL") ? response->fields.at("TTL") : "0";
            const auto suggested_name = response->fields.contains("FILENAME") ? response->fields.at("FILENAME") : std::string{};
            std::cout << "File stored" << std::endl;
            std::cout << "  Size: " << size << " bytes" << std::endl;
            std::cout << "  Remaining TTL: " << ttl << " seconds" << std::endl;
            if (!suggested_name.empty()) {
                std::cout << "  Suggested filename: " << suggested_name << std::endl;
            }
            std::cout << "  Manifest: " << manifest << std::endl;
            print_daemon_hint(*response);
            return 0;
        }

        if (command == "fetch") {
            if (index < args.size() && is_help_flag(args[index])) {
                print_fetch_usage();
                return 0;
            }
            if (index >= args.size()) {
                throw_cli_error("E_FETCH_MISSING_MANIFEST",
                                "fetch expects an eph:// manifest",
                                "Example: eph fetch eph://... --out ./file.bin");
            }
            const std::string manifest_uri(args[index++]);
            if (manifest_uri.rfind("eph://", 0) != 0) {
                throw_cli_error("E_FETCH_INVALID_MANIFEST",
                                "fetch requires a manifest prefixed with eph://",
                                "Make sure you paste the full URI generated by 'store'");
            }

            std::optional<protocol::Manifest> decoded_manifest;
            try {
                decoded_manifest = protocol::decode_manifest(manifest_uri);
            } catch (const std::exception&) {
                decoded_manifest = std::nullopt;
            }

            std::optional<std::filesystem::path> output_spec;
            FetchDiscoveryOptions discovery_options{};
            while (index < args.size()) {
                const auto& opt = args[index];
                if (opt == "--out") {
                    ++index;
                    if (index >= args.size()) {
                        throw_cli_error("E_FETCH_MISSING_OUT",
                                        "--out requires a path",
                                        "Example: --out ./download.bin");
                    }
                    if (output_spec.has_value()) {
                        throw_cli_error("E_FETCH_OUT_DUPLICATE",
                                        "Multiple output destinations provided",
                                        "Supply only one output path or directory");
                    }
                    output_spec = std::filesystem::absolute(std::filesystem::path(args[index++]));
                    continue;
                }
                if (opt == "--direct-only") {
                    discovery_options.direct_only = true;
                    ++index;
                    continue;
                }
                if (opt == "--transport-only") {
                    if (discovery_options.control_fallback_only) {
                        throw_cli_error("E_FETCH_MODE_CONFLICT",
                                        "--transport-only cannot be combined with --control-fallback",
                                        "Choose one discovery mode flag or omit both to allow automatic fallback.");
                    }
                    discovery_options.transport_only = true;
                    discovery_options.direct_only = true;
                    ++index;
                    continue;
                }
                if (opt == "--control-fallback") {
                    if (discovery_options.transport_only) {
                        throw_cli_error("E_FETCH_MODE_CONFLICT",
                                        "--control-fallback cannot be combined with --transport-only",
                                        "Choose one discovery mode flag or omit both to allow automatic fallback.");
                    }
                    discovery_options.control_fallback_only = true;
                    ++index;
                    continue;
                }
                if (opt == "--bootstrap-token") {
                    ++index;
                    if (index >= args.size()) {
                        throw_cli_error("E_FETCH_BOOTSTRAP_TOKEN_MISSING",
                                        "--bootstrap-token expects a value",
                                        "Example: --bootstrap-token 123456");
                    }
                    discovery_options.token_override = args[index++];
                    continue;
                }
                if (opt == "--bootstrap-max-attempts") {
                    ++index;
                    if (index >= args.size()) {
                        throw_cli_error("E_FETCH_BOOTSTRAP_ATTEMPTS_MISSING",
                                        "--bootstrap-max-attempts expects an integer",
                                        "Example: --bootstrap-max-attempts 100000");
                    }
                    std::uint64_t attempts = 0;
                    if (!parse_uint64(args[index], attempts) || attempts == 0) {
                        throw_cli_error("E_FETCH_BOOTSTRAP_ATTEMPTS_INVALID",
                                        "--bootstrap-max-attempts must be a positive integer",
                                        "Set a value greater than zero (default 250000)");
                    }
                    discovery_options.max_attempts = attempts;
                    ++index;
                    continue;
                }
                if (opt == "--no-bootstrap-auto-token") {
                    discovery_options.auto_token = false;
                    ++index;
                    continue;
                }
                if (is_help_flag(opt)) {
                    print_fetch_usage();
                    return 0;
                }
                if (!opt.empty() && opt[0] != '-') {
                    if (output_spec.has_value()) {
                        throw_cli_error("E_FETCH_OUT_DUPLICATE",
                                        "Multiple output destinations provided",
                                        "Supply only one output path or directory");
                    }
                    output_spec = std::filesystem::absolute(std::filesystem::path(args[index++]));
                    continue;
                }
                throw_cli_error("E_FETCH_UNKNOWN_OPTION",
                                "Unknown option for fetch: " + std::string(opt),
                                "Run 'eph --help' to see permitted modifiers");
            }

            bool using_cli_default_directory = false;
            if (!output_spec) {
                if (options.fetch_default_directory) {
                    output_spec = std::filesystem::path(*options.fetch_default_directory);
                    using_cli_default_directory = true;
                } else {
                    output_spec = std::filesystem::current_path();
                }
            }

            auto destination = *output_spec;
            const bool destination_exists = std::filesystem::exists(destination);
            const bool destination_is_directory = destination_exists && std::filesystem::is_directory(destination);
            const bool trailing_slash_directory = !destination_exists && !destination.has_filename();
            const bool treat_as_directory = destination_is_directory || trailing_slash_directory || using_cli_default_directory;

            std::filesystem::path resolved_output = destination;
            if (treat_as_directory) {
                std::string inferred_name;
                auto sanitize_filename = [](const std::string& candidate) {
                    std::filesystem::path candidate_path(candidate);
                    auto base = candidate_path.filename().string();
                    base.erase(std::remove_if(base.begin(), base.end(), [](unsigned char ch) {
                                  return std::iscntrl(ch);
                              }), base.end());
                    for (auto& ch : base) {
                        if (ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|') {
                            ch = '_';
                        }
                    }
                    if (base.empty() || base == "." || base == "..") {
                        return std::string{};
                    }
                    constexpr std::size_t kMaxSuggestedNameLength = 255;
                    if (base.size() > kMaxSuggestedNameLength) {
                        base.resize(kMaxSuggestedNameLength);
                    }
                    return base;
                };

                if (decoded_manifest.has_value() && options.fetch_use_manifest_name) {
                    if (const auto meta_it = decoded_manifest->metadata.find("filename"); meta_it != decoded_manifest->metadata.end()) {
                        inferred_name = sanitize_filename(meta_it->second);
                    }
                    if (inferred_name.empty()) {
                        inferred_name = ephemeralnet::chunk_id_to_string(decoded_manifest->chunk_id);
                    }
                }
                if (inferred_name.empty()) {
                    const auto stamp = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    inferred_name = "chunk_" + std::to_string(stamp);
                }
                resolved_output /= inferred_name;
            }

            if (std::filesystem::exists(resolved_output) && std::filesystem::is_directory(resolved_output)) {
                throw_cli_error("E_FETCH_OUT_IS_DIRECTORY",
                                "Destination resolves to a directory",
                                "Provide a writable file path or an existing directory");
            }

            const auto parent = resolved_output.parent_path();
            if (!parent.empty() && !std::filesystem::exists(parent)) {
                if (treat_as_directory) {
                    std::error_code ec;
                    std::filesystem::create_directories(parent, ec);
                    if (ec && !std::filesystem::exists(parent)) {
                        throw_cli_error("E_FETCH_OUT_PARENT_MISSING",
                                        "Destination directory does not exist",
                                        "Create " + parent.string() + " or choose an accessible path");
                    }
                } else {
                    throw_cli_error("E_FETCH_OUT_PARENT_MISSING",
                                    "Destination directory does not exist",
                                    "Create " + parent.string() + " or choose an existing path");
                }
            }

            if (std::filesystem::exists(resolved_output) &&
                !confirm_action("File " + resolved_output.string() + " already exists. Overwrite?",
                                false,
                                options.assume_yes)) {
                std::cout << "Operation cancelled by the user." << std::endl;
                return 0;
            }

            TransportIdentityContext transport_identity{};
            transport_identity.peer_id = self_peer_id;
            transport_identity.private_scalar = make_identity_scalar(options);
            transport_identity.public_scalar = ephemeralnet::network::KeyExchange::compute_public(transport_identity.private_scalar);

            ephemeralnet::daemon::ControlFields base_fields{{"MANIFEST", manifest_uri},
                                                            {"STREAM", "client"}};

            auto finalize_fetch = [&](const ephemeralnet::daemon::ControlResponse& response) {
                const auto reported_size = response.fields.contains("SIZE") ? response.fields.at("SIZE") : "0";
                if (response.has_payload) {
                    try {
                        std::ofstream out(resolved_output, std::ios::binary | std::ios::trunc);
                        if (!out) {
                            throw std::runtime_error("Failed to open output file");
                        }
                        if (!response.payload.empty()) {
                            out.write(reinterpret_cast<const char*>(response.payload.data()),
                                      static_cast<std::streamsize>(response.payload.size()));
                        }
                        out.flush();
                        if (!out) {
                            throw std::runtime_error("Failed to write complete payload");
                        }
                    } catch (const std::exception& ex) {
                        throw_cli_error("E_FETCH_WRITE_FAILED",
                                        ex.what(),
                                        "Verify write permissions for " + resolved_output.string());
                    }

                    const auto local_size = !response.payload.empty()
                                                ? std::to_string(response.payload.size())
                                                : reported_size;
                    std::cout << "File retrieved to " << resolved_output.string() << " (" << local_size << " bytes)" << std::endl;
                } else {
                    const auto output = response.fields.contains("OUTPUT") ? response.fields.at("OUTPUT")
                                                                             : resolved_output.string();
                    std::cout << "File retrieved to " << output << " (" << reported_size << " bytes)" << std::endl;
                    if (output != resolved_output.string()) {
                        std::cout << "Hint: File was written on the daemon host; copy it manually if needed." << std::endl;
                    }
                }
            };

            auto perform_fetch_request = [&](ephemeralnet::daemon::ControlClient& target_client,
                                            ephemeralnet::daemon::ControlFields request_fields,
                                            const std::string& progress_label,
                                            std::string* error_out)
                                            -> std::optional<ephemeralnet::daemon::ControlResponse> {
                ProgressPrinter progress(progress_label);
                ephemeralnet::daemon::ControlTransferProgress transfer_progress{};
                transfer_progress.on_download = [&progress](std::size_t current, std::size_t total) {
                    progress.update(current, total);
                };

                const auto response = target_client.send("FETCH", request_fields, {}, &transfer_progress);
                if (!response) {
                    progress.cancel();
                    if (error_out) {
                        *error_out = "Remote control endpoint unreachable";
                    }
                    return std::nullopt;
                }
                if (progress.started() && !progress.finished()) {
                    if (response->has_payload) {
                        progress.finish(response->payload.size());
                    } else {
                        progress.cancel();
                    }
                }
                return response;
            };

            auto format_direct_attempt_log = [](const std::vector<BootstrapAttemptLog>& entries) -> std::string {
                if (entries.empty()) {
                    return {};
                }
                std::ostringstream oss;
                oss << "Direct discovery exhausted:";
                for (const auto& entry : entries) {
                    oss << "\n  - " << (entry.endpoint.empty() ? std::string{"<unknown>"} : entry.endpoint)
                        << ": " << entry.message;
                }
                return oss.str();
            };

            struct DirectFetchOutcome {
                bool attempted{false};
                bool success{false};
                bool had_hints{false};
                std::vector<BootstrapAttemptLog> logs;
            };

            auto attempt_direct_fetch = [&](const protocol::Manifest& manifest) -> DirectFetchOutcome {
                DirectFetchOutcome outcome{};
                std::vector<BootstrapAttemptLog> attempt_log;
                const auto publisher_identity = extract_publisher_identity(manifest);
                std::optional<std::uint64_t> transport_pow_nonce;

                auto attempt_transport_hint = [&](const protocol::DiscoveryHint& hint,
                                                  const std::string& label) -> bool {
                    outcome.attempted = true;
                    const std::string friendly_label = label.empty() ? hint.endpoint : label;
                    if (hint.endpoint.empty()) {
                        attempt_log.push_back({friendly_label, "Transport hint missing endpoint"});
                        return false;
                    }
                    const std::string scheme = hint.scheme.empty() ? hint.transport : hint.scheme;
                    const bool is_relay_transport = (hint.transport == "relay" || scheme == "relay");
                    const bool is_supported_transport = is_relay_transport || hint.transport == "tcp" || hint.transport == "transport";
                    if (!is_supported_transport) {
                        attempt_log.push_back({friendly_label, "Unsupported transport hint"});
                        return false;
                    }
                    if (!publisher_identity.has_value()) {
                        attempt_log.push_back({friendly_label, "Manifest missing publisher identity metadata"});
                        return false;
                    }
                    if (manifest_expired(manifest)) {
                        attempt_log.push_back({friendly_label, "Manifest expired"});
                        return false;
                    }
                    if (!transport_pow_nonce.has_value()) {
                        attempt_log.push_back({friendly_label,
                                               manifest.security.token_challenge_bits > 0
                                                   ? "Unable to satisfy transport proof-of-work target"
                                                   : "Failed to initialize transport handshake"});
                        return false;
                    }
                    std::optional<TransportSessionContext> session;
                    std::string endpoint_desc;
                    std::string handshake_error;

                    if (is_relay_transport) {
                        const auto relay = parse_relay_hint_endpoint(hint.endpoint);
                        if (!relay.has_value()) {
                            attempt_log.push_back({friendly_label, "Invalid relay endpoint"});
                            return false;
                        }
                        if (relay->remote_peer.has_value() && *relay->remote_peer != publisher_identity->peer_id) {
                            attempt_log.push_back({friendly_label, "Relay hint targets a different peer"});
                            return false;
                        }

                        auto socket_opt = open_transport_socket(relay->host, relay->port);
                        if (!socket_opt.has_value()) {
                            attempt_log.push_back({friendly_label, "Failed to contact relay endpoint"});
                            return false;
                        }

                        const std::string connect_line = "CONNECT " + ephemeralnet::peer_id_to_string(transport_identity.peer_id) +
                                                         " " + ephemeralnet::peer_id_to_string(publisher_identity->peer_id) + "\n";
                        if (!socket_send_all(socket_opt->get(),
                                             reinterpret_cast<const std::uint8_t*>(connect_line.data()),
                                             connect_line.size())) {
                            attempt_log.push_back({friendly_label, format_socket_error("Failed to send relay CONNECT")});
                            return false;
                        }

                        auto ok_line = socket_read_line(socket_opt->get(), std::chrono::milliseconds{5000});
                        if (!ok_line.has_value() || *ok_line != "OK") {
                            attempt_log.push_back({friendly_label, "Relay did not acknowledge CONNECT"});
                            return false;
                        }

                        session = complete_transport_handshake(std::move(*socket_opt),
                                                               transport_identity,
                                                               *publisher_identity,
                                                               *transport_pow_nonce,
                                                               &handshake_error);
                        endpoint_desc = describe_endpoint(relay->host, relay->port) + " (relay)";
                    } else {
                        const auto parsed = parse_control_endpoint(hint.endpoint);
                        if (!parsed.has_value()) {
                            attempt_log.push_back({friendly_label, "Invalid transport endpoint"});
                            return false;
                        }
                        const auto host = parsed->first;
                        const auto port = parsed->second;
                        endpoint_desc = describe_endpoint(host, port);

                        std::string error_text;
                        session = establish_transport_session(transport_identity,
                                                              *publisher_identity,
                                                              *transport_pow_nonce,
                                                              host,
                                                              port,
                                                              &error_text);
                        if (!session.has_value()) {
                            attempt_log.push_back({friendly_label,
                                                   error_text.empty() ? std::string{"Transport handshake failed"}
                                                                      : error_text});
                            return false;
                        }
                    }

                    if (!session.has_value()) {
                        attempt_log.push_back({friendly_label,
                                               handshake_error.empty() ? std::string{"Transport handshake failed"}
                                                                        : handshake_error});
                        return false;
                    }

                    protocol::Message request{};
                    request.version = session->negotiated_version;
                    request.type = protocol::MessageType::Request;
                    protocol::RequestPayload payload{};
                    payload.chunk_id = manifest.chunk_id;
                    payload.requester = transport_identity.peer_id;
                    request.payload = payload;

                    if (!send_protocol_message(session->socket.get(), session->session_key, request)) {
                        attempt_log.push_back({friendly_label, "Failed to send transport request"});
                        return false;
                    }

                    auto reply = receive_protocol_message(session->socket.get(),
                                                          session->session_key,
                                                          kTransportResponseTimeout);
                    if (!reply.has_value()) {
                        attempt_log.push_back({friendly_label, "Timed out waiting for transport response"});
                        return false;
                    }

                    if (reply->type == protocol::MessageType::Chunk) {
                        const auto* chunk_payload = std::get_if<protocol::ChunkPayload>(&reply->payload);
                        if (!chunk_payload) {
                            attempt_log.push_back({friendly_label, "Malformed chunk payload"});
                            return false;
                        }
                        const auto plaintext = decrypt_chunk_with_manifest(manifest, *chunk_payload);
                        if (!plaintext.has_value()) {
                            attempt_log.push_back({friendly_label, "Failed to decrypt chunk"});
                            return false;
                        }

                        ephemeralnet::daemon::ControlResponse synthetic{};
                        synthetic.success = true;
                        synthetic.has_payload = true;
                        synthetic.payload = *plaintext;
                        synthetic.fields["SIZE"] = std::to_string(plaintext->size());

                        finalize_fetch(synthetic);
                        std::cout << "Direct fetch succeeded via " << endpoint_desc << " (transport)" << std::endl;
                        outcome.success = true;
                        outcome.logs = attempt_log;
                        return true;
                    }

                    if (reply->type == protocol::MessageType::Acknowledge) {
                        const auto* ack_payload = std::get_if<protocol::AcknowledgePayload>(&reply->payload);
                        if (ack_payload && !ack_payload->accepted) {
                            attempt_log.push_back({friendly_label, "Peer rejected chunk request"});
                        } else {
                            attempt_log.push_back({friendly_label, "Unexpected acknowledge response"});
                        }
                        return false;
                    }

                    attempt_log.push_back({friendly_label, "Unexpected transport response"});
                    return false;
                };

                auto attempt_control_hint = [&](const protocol::DiscoveryHint& hint,
                                                const std::string& label,
                                                bool from_fallback) -> bool {
                    outcome.attempted = true;
                    const std::string friendly_label = label.empty() ? hint.endpoint : label;
                    const std::string scheme = hint.scheme.empty() ? hint.transport : hint.scheme;
                    if (scheme != "control") {
                        attempt_log.push_back({friendly_label, "Unsupported scheme for this build"});
                        return false;
                    }
                    if (hint.transport != "control") {
                        attempt_log.push_back({friendly_label, "Unsupported transport for this build"});
                        return false;
                    }

                    const auto parsed = parse_control_endpoint(hint.endpoint);
                    if (!parsed.has_value()) {
                        attempt_log.push_back({friendly_label, "Invalid control endpoint"});
                        return false;
                    }
                    const auto& [host, port] = *parsed;
                    const auto endpoint_desc = describe_endpoint(host, port);

                    const auto token_value = compute_bootstrap_token(manifest, hint, discovery_options);
                    if (manifest.security.token_challenge_bits > 0 && !token_value.has_value()) {
                        attempt_log.push_back({friendly_label,
                                               "Token challenge not satisfied. Provide --bootstrap-token or enable auto solving."});
                        return false;
                    }

                    ephemeralnet::daemon::ControlClient remote_client(host, port, token_value);
                    auto request_fields = base_fields;
                    request_fields["BOOTSTRAP"] = "1";
                    request_fields["DISCOVERY-ENDPOINT"] = friendly_label;
                    request_fields["DISCOVERY-SCHEME"] = scheme;
                    request_fields["DISCOVERY-TRANSPORT"] = hint.transport;
                    request_fields["DISCOVERY-PRIORITY"] = std::to_string(hint.priority);
                    if (from_fallback) {
                        request_fields["FALLBACK"] = "1";
                        request_fields["DISCOVERY-RESOLVED"] = hint.endpoint;
                    }

                    std::string error_text;
                    const auto response = perform_fetch_request(remote_client,
                                                                request_fields,
                                                                from_fallback ? "Fallback download" : "Direct download",
                                                                &error_text);
                    if (!response) {
                        attempt_log.push_back({friendly_label,
                                               error_text.empty() ? std::string{"Remote control endpoint unreachable"}
                                                                  : error_text});
                        return false;
                    }
                    if (!response->success) {
                        const auto message_it = response->fields.find("MESSAGE");
                        const std::string reason = message_it != response->fields.end() ? message_it->second
                                                                                         : "Remote daemon rejected request";
                        attempt_log.push_back({friendly_label, reason});
                        return false;
                    }

                    finalize_fetch(*response);
                    if (from_fallback) {
                        std::cout << "Fallback fetch succeeded via " << endpoint_desc << std::endl;
                    } else {
                        std::cout << "Direct fetch succeeded via " << endpoint_desc << std::endl;
                    }
                    print_daemon_hint(*response);
                    outcome.success = true;
                    outcome.logs = attempt_log;
                    return true;
                };

                std::vector<protocol::DiscoveryHint> transport_hints;
                std::vector<protocol::DiscoveryHint> control_hints;
                transport_hints.reserve(manifest.discovery_hints.size());
                control_hints.reserve(manifest.discovery_hints.size());
                for (const auto& hint : manifest.discovery_hints) {
                    const auto scheme = hint.scheme.empty() ? hint.transport : hint.scheme;
                    if (scheme == "transport" || hint.transport == "tcp" || hint.transport == "transport") {
                        transport_hints.push_back(hint);
                    } else {
                        control_hints.push_back(hint);
                    }
                }

                const bool has_transport_paths = !transport_hints.empty();
                const bool has_control_paths = !control_hints.empty() || !manifest.fallback_hints.empty();
                if (discovery_options.transport_only) {
                    outcome.had_hints = has_transport_paths;
                } else if (discovery_options.control_fallback_only) {
                    outcome.had_hints = has_control_paths;
                } else {
                    outcome.had_hints = has_transport_paths || has_control_paths;
                }
                if (!outcome.had_hints) {
                    return outcome;
                }

                if (!discovery_options.control_fallback_only && publisher_identity.has_value() && has_transport_paths) {
                    transport_pow_nonce = compute_transport_pow(transport_identity.peer_id,
                                                                publisher_identity->peer_id,
                                                                transport_identity.public_scalar,
                                                                manifest.security.token_challenge_bits);
                }

                auto sort_by_priority = [](std::vector<protocol::DiscoveryHint>& hints) {
                    std::stable_sort(hints.begin(), hints.end(), [](const auto& lhs, const auto& rhs) {
                        return lhs.priority < rhs.priority;
                    });
                };

                sort_by_priority(transport_hints);
                sort_by_priority(control_hints);

                if (!discovery_options.control_fallback_only) {
                    for (const auto& hint : transport_hints) {
                        if (attempt_transport_hint(hint, hint.endpoint)) {
                            return outcome;
                        }
                    }
                } else if (!transport_hints.empty()) {
                    attempt_log.push_back({"transport", "Skipped transport hints due to --control-fallback"});
                }

                if (!discovery_options.transport_only) {
                    for (const auto& hint : control_hints) {
                        if (attempt_control_hint(hint, hint.endpoint, false)) {
                            return outcome;
                        }
                    }
                } else if (!control_hints.empty()) {
                    attempt_log.push_back({"control", "Skipped control hints due to --transport-only"});
                }

                if (!discovery_options.transport_only && !manifest.fallback_hints.empty()) {
                    auto fallback_hints = manifest.fallback_hints;
                    std::stable_sort(fallback_hints.begin(), fallback_hints.end(), [](const auto& lhs, const auto& rhs) {
                        return lhs.priority < rhs.priority;
                    });
                    for (const auto& fallback : fallback_hints) {
                        const auto parsed = parse_control_uri(fallback.uri);
                        if (!parsed.has_value()) {
                            attempt_log.push_back({fallback.uri,
                                                   "Unsupported fallback scheme (only control:// is implemented)"});
                            continue;
                        }
                        protocol::DiscoveryHint synthetic{};
                        synthetic.scheme = "control";
                        synthetic.transport = "control";
                        synthetic.endpoint = describe_endpoint(parsed->first, parsed->second);
                        synthetic.priority = fallback.priority;
                        if (attempt_control_hint(synthetic, fallback.uri, true)) {
                            return outcome;
                        }
                    }
                } else if (discovery_options.transport_only && !manifest.fallback_hints.empty()) {
                    attempt_log.push_back({"fallback",
                                           "Skipped fallback URIs due to --transport-only"});
                }

                outcome.logs = std::move(attempt_log);
                return outcome;
            };

            if (discovery_options.direct_only && !decoded_manifest.has_value()) {
                throw_cli_error("E_FETCH_DIRECT_ONLY_MANIFEST",
                                "Manifest decoding failed; direct-only fetch cannot proceed",
                                "Retry with the original eph:// URI or omit --direct-only.");
            }

            std::optional<DirectFetchOutcome> direct_outcome;
            if (decoded_manifest.has_value()) {
                direct_outcome = attempt_direct_fetch(*decoded_manifest);
                if (direct_outcome->success) {
                    return 0;
                }
                if (direct_outcome->had_hints && direct_outcome->attempted && !direct_outcome->logs.empty()) {
                    const auto summary = format_direct_attempt_log(direct_outcome->logs);
                    if (!summary.empty()) {
                        std::cout << summary << std::endl;
                        std::cout << "Falling back to swarm discovery via the local daemon..." << std::endl;
                    }
                } else if (direct_outcome->had_hints && !direct_outcome->attempted) {
                    std::cout << "Discovery hints were present but could not be attempted; falling back to swarm discovery." << std::endl;
                } else if (!direct_outcome->had_hints) {
                    std::cout << "Manifest lacks discovery hints; falling back to swarm discovery." << std::endl;
                }
            }

            if (discovery_options.direct_only) {
                if (!direct_outcome.has_value() || !direct_outcome->had_hints) {
                    if (discovery_options.transport_only) {
                        throw_cli_error("E_FETCH_DIRECT_ONLY_NO_HINTS",
                                        "Manifest does not advertise transport/tcp hints",
                                        "Re-store the payload from a node that publishes transport endpoints or drop --transport-only.");
                    }
                    throw_cli_error("E_FETCH_DIRECT_ONLY_NO_HINTS",
                                    "Manifest does not contain discovery hints or fallbacks",
                                    "Store the payload from a node that advertises discovery metadata or remove --direct-only.");
                }
                const auto summary = format_direct_attempt_log(direct_outcome->logs);
                throw_cli_error("E_FETCH_DIRECT_FAILED",
                                "Direct discovery did not reach the publishing peer",
                                summary.empty() ? std::string{"Verify port forwarding or relay availability before retrying."}
                                                : summary);
            }

            std::string local_error;
            const auto local_response = perform_fetch_request(client, base_fields, "Downloading", &local_error);
            if (local_response && local_response->success) {
                finalize_fetch(*local_response);
                print_daemon_hint(*local_response);
                return 0;
            }

            if (local_response && !local_response->success) {
                const auto message_it = local_response->fields.find("MESSAGE");
                if (message_it != local_response->fields.end() && !message_it->second.empty()) {
                    local_error = message_it->second;
                }
                print_daemon_failure(*local_response);
            } else if (!local_response && local_error.empty()) {
                local_error = "Local daemon unreachable";
            }

            std::string hint = local_error;
            if (direct_outcome.has_value()) {
                if (!direct_outcome->had_hints) {
                    if (!hint.empty()) {
                        hint += "\n";
                    }
                    hint += "Manifest does not contain discovery hints.";
                } else if (!direct_outcome->logs.empty()) {
                    const auto summary = format_direct_attempt_log(direct_outcome->logs);
                    if (!summary.empty()) {
                        if (!hint.empty()) {
                            hint += "\n";
                        }
                        hint += summary;
                    }
                }
            }

            throw_cli_error("E_FETCH_FAILED",
                            "Fetch request failed",
                            hint.empty() ? std::string{"Check the daemon logs for additional details."} : hint);
        }

        throw_cli_error("E_UNKNOWN_COMMAND",
                        "Unknown command: " + command,
                        "Run 'eph --help' to see the list of available commands");

    } catch (const CliException& ex) {
        print_cli_error(ex);
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error [E_UNEXPECTED]: " << ex.what() << std::endl;
        return 1;
    }
}
