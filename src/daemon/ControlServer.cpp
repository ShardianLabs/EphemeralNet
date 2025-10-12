#include "ephemeralnet/daemon/ControlPlane.hpp"
#include "ephemeralnet/daemon/StructuredLogger.hpp"
#include "ephemeralnet/core/Node.hpp"

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"
#include "ephemeralnet/security/StoreProof.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <charconv>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <iomanip>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ephemeralnet::daemon {

namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

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

void close_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        closesocket(socket);
    }
}

#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

void winsock_runtime() {}

void close_socket(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::close(socket);
    }
}

#endif

constexpr std::size_t kMaxLineLength = 16 * 1024;
constexpr std::chrono::seconds kStoreRateWindow{std::chrono::seconds(30)};
constexpr std::size_t kStoreRateBurstLimit = 6;
constexpr std::chrono::seconds kStorePowFailureWindow{std::chrono::seconds(120)};
constexpr std::size_t kStorePowFailureLimit = 3;
constexpr std::chrono::seconds kFetchStreamRateWindow{std::chrono::seconds(30)};
constexpr std::size_t kFetchStreamBurstLimit = 12;

const char* advertise_auto_mode_to_string(Config::AdvertiseAutoMode mode) {
    switch (mode) {
        case Config::AdvertiseAutoMode::On:
            return "on";
        case Config::AdvertiseAutoMode::Warn:
            return "warn";
        case Config::AdvertiseAutoMode::Off:
            return "off";
    }
    return "on";
}

bool send_all(NativeSocket socket, const char* data, std::size_t length) {
    std::size_t total_sent = 0;
    while (total_sent < length) {
#ifdef _WIN32
        const auto sent = send(socket, data + total_sent, static_cast<int>(length - total_sent), 0);
#else
        const auto sent = send(socket, data + total_sent, length - total_sent, 0);
#endif
        if (sent <= 0) {
            return false;
        }
        total_sent += static_cast<std::size_t>(sent);
    }
    return true;
}

bool recv_line(NativeSocket socket, std::string& line) {
    line.clear();
    char ch = 0;
    std::size_t count = 0;
    while (true) {
#ifdef _WIN32
        const auto received = recv(socket, &ch, 1, 0);
#else
        const auto received = recv(socket, &ch, 1, 0);
#endif
        if (received <= 0) {
            return false;
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            line.push_back(ch);
            if (++count > kMaxLineLength) {
                return false;
            }
        }
    }
    return true;
}

bool recv_exact(NativeSocket socket, std::uint8_t* buffer, std::size_t length) {
    std::size_t received_total = 0;
    while (received_total < length) {
#ifdef _WIN32
        const auto received = recv(socket, reinterpret_cast<char*>(buffer) + received_total,
                                   static_cast<int>(length - received_total), 0);
#else
        const auto received = recv(socket, reinterpret_cast<char*>(buffer) + received_total,
                                   length - received_total, 0);
#endif
        if (received <= 0) {
            return false;
        }
        received_total += static_cast<std::size_t>(received);
    }
    return true;
}

std::string to_upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::optional<std::uint64_t> parse_uint64(const std::string& text) {
    std::uint64_t value{};
    auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

bool constant_time_equal(const std::string& expected, const std::string& provided) {
    if (expected.size() != provided.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        diff |= static_cast<unsigned char>(expected[i] ^ provided[i]);
    }
    return diff == 0;
}

std::string hashed_token_identity(const std::string& token) {
    if (token.empty()) {
        return "token:empty";
    }
    const auto digest = crypto::Sha256::digest(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(token.data()), token.size()));
    std::ostringstream oss;
    oss << "token:";
    oss << std::hex << std::setfill('0');
    for (const auto byte : digest) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

struct ParsedRequest {
    ControlFields fields;
    std::vector<std::uint8_t> payload;
    bool payload_header_present{false};
};

struct ParseResult {
    bool success{false};
    bool connection_closed{false};
    ParsedRequest request;
    std::string error_code;
    std::string error_message;
    std::string error_hint;
};

ParseResult parse_request(NativeSocket client) {
    ParseResult result;
    std::string line;
    std::optional<std::size_t> payload_length;
    bool saw_any_lines = false;

    while (recv_line(client, line)) {
        if (line.empty()) {
            break;
        }
        saw_any_lines = true;
        const auto pos = line.find(':');
        if (pos == std::string::npos) {
            result.error_code = "ERR_CONTROL_HEADER";
            result.error_message = "Malformed control header";
            result.error_hint = "Use the official CLI to interact with the daemon";
            return result;
        }
        const auto key = to_upper(line.substr(0, pos));
        const auto value = line.substr(pos + 1);
        if (key == "PAYLOAD-LENGTH") {
            const auto parsed = parse_uint64(value);
            if (!parsed.has_value()) {
                result.error_code = "ERR_CONTROL_PAYLOAD_LENGTH";
                result.error_message = "Invalid PAYLOAD-LENGTH";
                result.error_hint = "Upgrade the CLI and retry";
                return result;
            }
            const auto stream_limit = max_control_stream_bytes();
            if (*parsed > stream_limit) {
                result.error_code = "ERR_CONTROL_PAYLOAD_TOO_LARGE";
                result.error_message = "Payload exceeds server allowance";
                result.error_hint = "Lower the payload size or raise --max-store-bytes";
                return result;
            }
            payload_length = static_cast<std::size_t>(*parsed);
            result.request.payload_header_present = true;
        }
        result.request.fields[key] = value;
    }

    if (!saw_any_lines) {
        result.connection_closed = true;
        return result;
    }

    if (!payload_length.has_value()) {
        payload_length = 0;
    }

    if (*payload_length > 0) {
        result.request.payload.resize(*payload_length);
        if (!recv_exact(client, result.request.payload.data(), *payload_length)) {
            result.error_code = "ERR_CONTROL_PAYLOAD_TRUNCATED";
            result.error_message = "Truncated control payload";
            result.error_hint = "Retry the command";
            return result;
        }
    } else {
        result.request.payload.clear();
    }

    result.success = true;
    return result;
}

void write_file_bytes(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    if (const auto parent = path.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent);
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("No se pudo escribir el archivo: " + path.string());
    }
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::int64_t ttl_seconds_remaining(const std::chrono::steady_clock::time_point& expires_at) {
    const auto now = std::chrono::steady_clock::now();
    if (expires_at <= now) {
        return 0;
    }
    return std::chrono::duration_cast<std::chrono::seconds>(expires_at - now).count();
}

ControlFields make_ok(std::string_view code = "OK") {
    ControlFields fields;
    fields["CODE"] = std::string(code);
    return fields;
}

ControlFields make_error(std::string_view code, std::string_view message, std::string_view hint = {}) {
    ControlFields fields;
    fields["CODE"] = std::string(code);
    fields["MESSAGE"] = std::string(message);
    if (!hint.empty()) {
        fields["HINT"] = std::string(hint);
    }
    return fields;
}

void log_event(StructuredLogger::Level level,
               std::string_view event,
               StructuredLogger::FieldList fields = {}) {
    StructuredLogger::instance().log(level, event, std::move(fields));
}

struct Metrics {
    std::atomic<std::uint64_t> control_connections_total{0};
    std::atomic<std::uint64_t> control_parse_failures_total{0};
    std::atomic<std::uint64_t> control_unsupported_total{0};
    std::atomic<std::uint64_t> command_ping_requests_total{0};
    std::atomic<std::uint64_t> command_status_requests_total{0};
    std::atomic<std::uint64_t> command_list_requests_total{0};
    std::atomic<std::uint64_t> command_defaults_requests_total{0};
    std::atomic<std::uint64_t> command_stop_requests_total{0};
    std::atomic<std::uint64_t> command_metrics_requests_total{0};
    std::atomic<std::uint64_t> command_store_requests_total{0};
    std::atomic<std::uint64_t> command_store_success_total{0};
    std::atomic<std::uint64_t> command_store_bytes_total{0};
    std::atomic<std::uint64_t> command_store_rate_limited_total{0};
    std::atomic<std::uint64_t> command_store_auth_failures_total{0};
    std::atomic<std::uint64_t> command_store_pow_failures_total{0};
    std::atomic<std::uint64_t> command_fetch_requests_total{0};
    std::atomic<std::uint64_t> command_fetch_success_total{0};
    std::atomic<std::uint64_t> command_fetch_stream_success_total{0};
    std::atomic<std::uint64_t> command_fetch_bytes_total{0};
    std::atomic<std::uint64_t> command_fetch_rate_limited_total{0};
    std::atomic<std::uint64_t> command_fetch_auth_failures_total{0};

    std::string render_prometheus(const Config& config, const Node::PowStatistics& pow_stats) const {
        std::ostringstream oss;
        auto emit_counter = [&](std::string_view name, std::string_view help, std::uint64_t value) {
            oss << "# HELP " << name << ' ' << help << "\n";
            oss << "# TYPE " << name << " counter\n";
            oss << name << ' ' << value << "\n";
        };

        auto emit_gauge = [&](std::string_view name, std::string_view help, std::uint64_t value) {
            oss << "# HELP " << name << ' ' << help << "\n";
            oss << "# TYPE " << name << " gauge\n";
            oss << name << ' ' << value << "\n";
        };

        emit_counter("ephemeralnet_control_connections_total",
                      "Total control connections accepted.",
                      control_connections_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_control_parse_failures_total",
                      "Control requests rejected during parsing.",
                      control_parse_failures_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_control_unsupported_total",
                      "Unsupported control commands received.",
                      control_unsupported_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_ping_requests_total",
                      "PING commands processed.",
                      command_ping_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_status_requests_total",
                      "STATUS commands processed.",
                      command_status_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_list_requests_total",
                      "LIST commands processed.",
                      command_list_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_defaults_requests_total",
                      "DEFAULTS commands processed.",
                      command_defaults_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_stop_requests_total",
                      "STOP commands processed.",
                      command_stop_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_metrics_requests_total",
                      "METRICS commands processed.",
                      command_metrics_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_store_requests_total",
                      "STORE commands processed.",
                      command_store_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_store_success_total",
                      "Successful STORE commands.",
                      command_store_success_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_store_bytes_total",
                      "Bytes uploaded via STORE.",
                      command_store_bytes_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_store_rate_limited_total",
                      "STORE commands rejected by rate limiting.",
                      command_store_rate_limited_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_store_auth_failures_total",
                      "STORE commands rejected by authentication.",
                      command_store_auth_failures_total.load(std::memory_order_relaxed));
      emit_counter("ephemeralnet_command_store_pow_failures_total",
                "STORE commands rejected due to invalid proof-of-work.",
                command_store_pow_failures_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_fetch_requests_total",
                      "FETCH commands processed.",
                      command_fetch_requests_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_fetch_success_total",
                      "Successful FETCH commands.",
                      command_fetch_success_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_fetch_stream_success_total",
                      "Successful streaming FETCH commands.",
                      command_fetch_stream_success_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_fetch_bytes_total",
                      "Bytes transferred via FETCH.",
                      command_fetch_bytes_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_fetch_rate_limited_total",
                      "FETCH commands rejected by rate limiting.",
                      command_fetch_rate_limited_total.load(std::memory_order_relaxed));
        emit_counter("ephemeralnet_command_fetch_auth_failures_total",
                      "FETCH commands rejected by authentication.",
                      command_fetch_auth_failures_total.load(std::memory_order_relaxed));

        emit_gauge("ephemeralnet_handshake_pow_difficulty_bits",
                    "Configured handshake proof-of-work difficulty (leading zero bits).",
                    config.handshake_pow_difficulty);
        emit_gauge("ephemeralnet_store_pow_difficulty_bits",
                    "Configured store proof-of-work difficulty (leading zero bits).",
                    config.store_pow_difficulty);
        emit_gauge("ephemeralnet_announce_pow_difficulty_bits",
                    "Configured announce proof-of-work difficulty (leading zero bits).",
                    config.announce_pow_difficulty);

        emit_counter("ephemeralnet_handshake_pow_success_total",
                      "Remote handshakes passing proof-of-work validation.",
                      pow_stats.handshake_validations_success);
        emit_counter("ephemeralnet_handshake_pow_failure_total",
                      "Remote handshakes failing proof-of-work validation.",
                      pow_stats.handshake_validations_failure);
        emit_counter("ephemeralnet_announce_pow_success_total",
                      "Announce messages passing proof-of-work validation.",
                      pow_stats.announce_validations_success);
        emit_counter("ephemeralnet_announce_pow_failure_total",
                      "Announce messages failing proof-of-work validation.",
                      pow_stats.announce_validations_failure);

        return oss.str();
    }
};

}  // namespace

class ControlServer::Impl {
public:
    Impl(Node& node, std::mutex& node_mutex, StopCallback stop_callback)
        : node_(node), node_mutex_(node_mutex), stop_callback_(std::move(stop_callback)) {
        winsock_runtime();
        set_max_control_stream_bytes(node_.config().control_stream_max_bytes);
    }

    ~Impl() {
        stop();
    }

    void start(const std::string& host, std::uint16_t port) {
        if (running_) {
            return;
        }

        NativeSocket server = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server == kInvalidSocket) {
            throw std::runtime_error("Failed to create control socket");
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (host.empty() || host == "0.0.0.0") {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
#ifdef _WIN32
            if (InetPtonA(AF_INET, host.c_str(), &addr.sin_addr) != 1)
#else
            if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
#endif
            {
                close_socket(server);
                throw std::runtime_error("Invalid control host: " + host);
            }
        }

        const int opt = 1;
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

        if (::bind(server, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
            close_socket(server);
            throw std::runtime_error("Failed to bind control socket");
        }

        if (::listen(server, SOMAXCONN) < 0) {
            close_socket(server);
            throw std::runtime_error("Failed to listen on control socket");
        }

        listen_socket_ = server;
        running_.store(true, std::memory_order_release);
        accept_thread_ = std::thread(&Impl::accept_loop, this);
    }

    void stop() {
        if (!running_) {
            return;
        }
        running_.store(false, std::memory_order_release);
        const auto socket = listen_socket_;
        listen_socket_ = kInvalidSocket;
#ifdef _WIN32
        if (socket != kInvalidSocket) {
            ::shutdown(socket, SD_BOTH);
        }
#else
        if (socket != kInvalidSocket) {
            ::shutdown(socket, SHUT_RDWR);
        }
#endif
        close_socket(socket);
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
    }

    bool running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

private:
    Node& node_;
    std::mutex& node_mutex_;
    StopCallback stop_callback_;
    Metrics metrics_{};
    std::atomic<bool> running_{false};
    NativeSocket listen_socket_{kInvalidSocket};
    std::thread accept_thread_;
    std::atomic<bool> transport_stopped_{false};
    std::mutex rate_mutex_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> store_history_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> fetch_history_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> store_pow_failures_;

    bool allow_store_request(const std::string& identity) {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(rate_mutex_);
        auto& history = store_history_[identity];
        history.erase(std::remove_if(history.begin(), history.end(), [&](const auto& timestamp) {
                          return now - timestamp > kStoreRateWindow;
                      }),
                      history.end());
        if (history.size() >= kStoreRateBurstLimit) {
            return false;
        }
        history.push_back(now);
        return true;
    }

    bool note_store_pow_failure(const std::string& identity) {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(rate_mutex_);
        auto& history = store_pow_failures_[identity];
        history.erase(std::remove_if(history.begin(), history.end(), [&](const auto& timestamp) {
                          return now - timestamp > kStorePowFailureWindow;
                      }),
                      history.end());
        history.push_back(now);
        return history.size() >= kStorePowFailureLimit;
    }

    void clear_store_pow_failures(const std::string& identity) {
        std::scoped_lock lock(rate_mutex_);
        store_pow_failures_.erase(identity);
    }

    bool allow_stream_fetch(const std::string& identity) {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(rate_mutex_);
        auto& history = fetch_history_[identity];
        history.erase(std::remove_if(history.begin(), history.end(), [&](const auto& timestamp) {
                          return now - timestamp > kFetchStreamRateWindow;
                      }),
                      history.end());
        if (history.size() >= kFetchStreamBurstLimit) {
            return false;
        }
        history.push_back(now);
        return true;
    }

    void accept_loop() {
    while (running_.load(std::memory_order_acquire)) {
            sockaddr_in client_addr{};
#ifdef _WIN32
            int addr_len = sizeof(client_addr);
#else
            socklen_t addr_len = sizeof(client_addr);
#endif
            const auto client = ::accept(listen_socket_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client == kInvalidSocket) {
                if (running_.load(std::memory_order_acquire)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                continue;
            }
            std::string remote_address{"unknown"};
            char buffer[INET_ADDRSTRLEN] = {0};
#ifdef _WIN32
            if (InetNtopA(AF_INET, &client_addr.sin_addr, buffer, sizeof(buffer)) != nullptr) {
                remote_address = buffer;
            }
#else
            if (inet_ntop(AF_INET, &client_addr.sin_addr, buffer, sizeof(buffer)) != nullptr) {
                remote_address = buffer;
            }
#endif
            metrics_.control_connections_total.fetch_add(1, std::memory_order_relaxed);
            log_event(StructuredLogger::Level::Info,
                      "control.connection.accepted",
                      {{"remote", remote_address}});
            handle_client(client, remote_address);
            close_socket(client);
        }
    }

    static void send_response(NativeSocket client, ControlFields fields, bool success, std::span<const std::uint8_t> payload = {}) {
        const bool has_payload = payload.data() != nullptr || payload.size() > 0;
        if (has_payload) {
            fields["PAYLOAD-LENGTH"] = std::to_string(payload.size());
        }
        std::ostringstream oss;
        oss << "STATUS:" << (success ? "OK" : "ERROR") << "\n";
        for (const auto& [key, value] : fields) {
            oss << key << ':' << value << "\n";
        }
        oss << "\n";
        const auto response = oss.str();
        send_all(client, response.c_str(), response.size());
        if (has_payload && payload.size() > 0) {
            send_all(client, reinterpret_cast<const char*>(payload.data()), payload.size());
        }
    }

    void handle_client(NativeSocket client, const std::string& remote_identity) {
        const auto parse = parse_request(client);
        if (parse.connection_closed) {
            return;
        }
        if (!parse.success) {
            metrics_.control_parse_failures_total.fetch_add(1, std::memory_order_relaxed);
            auto error = make_error(parse.error_code.empty() ? "ERR_CONTROL_REQUEST"
                                                             : parse.error_code,
                                     parse.error_message.empty() ? "Malformed control request"
                                                                 : parse.error_message,
                                     parse.error_hint);
            log_event(StructuredLogger::Level::Warning,
                      "control.request.parse_error",
                      {{"remote", remote_identity},
                       {"code", error.count("CODE") ? error.at("CODE") : std::string("ERR_CONTROL_REQUEST")}});
            send_response(client, std::move(error), false);
            return;
        }

        auto request = std::move(parse.request);
        const auto it = request.fields.find("COMMAND");
        if (it == request.fields.end()) {
            metrics_.control_parse_failures_total.fetch_add(1, std::memory_order_relaxed);
            auto error = make_error("ERR_MISSING_COMMAND",
                                    "COMMAND header missing",
                                    "Include the COMMAND header in the request");
            log_event(StructuredLogger::Level::Warning,
                      "control.request.missing_command",
                      {{"remote", remote_identity}});
            send_response(client, error, false);
            return;
        }

        const auto command = to_upper(it->second);
        if (command == "PING") {
            metrics_.command_ping_requests_total.fetch_add(1, std::memory_order_relaxed);
            auto fields = make_ok("OK_PING");
            fields["MESSAGE"] = "pong";
            send_response(client, fields, true);
            log_event(StructuredLogger::Level::Info,
                      "control.command.ping",
                      {{"remote", remote_identity},
                       {"code", fields.at("CODE")}});
            return;
        }
        if (command == "STATUS") {
            metrics_.command_status_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_status(client, remote_identity);
            return;
        }
        if (command == "STOP") {
            metrics_.command_stop_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_stop(client, remote_identity);
            return;
        }
        if (command == "LIST") {
            metrics_.command_list_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_list(client, remote_identity);
            return;
        }
        if (command == "DEFAULTS") {
            metrics_.command_defaults_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_defaults(client, remote_identity);
            return;
        }
        if (command == "METRICS") {
            metrics_.command_metrics_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_metrics(client, remote_identity);
            return;
        }
        if (command == "STORE") {
            metrics_.command_store_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_store(client, std::move(request), remote_identity);
            return;
        }
        if (command == "FETCH") {
            metrics_.command_fetch_requests_total.fetch_add(1, std::memory_order_relaxed);
            handle_fetch(client, request, remote_identity);
            return;
        }

        metrics_.control_unsupported_total.fetch_add(1, std::memory_order_relaxed);
        auto error = make_error("ERR_UNSUPPORTED_COMMAND",
                                "Unsupported command",
                                "Check the control API documentation");
        log_event(StructuredLogger::Level::Warning,
                  "control.command.unsupported",
                  {{"remote", remote_identity},
                   {"command", command}});
        send_response(client, error, false);
    }

    void handle_status(NativeSocket client, const std::string& remote_identity) {
        std::size_t peers = 0;
        std::size_t chunks = 0;
        std::uint16_t port = 0;
        Config config_copy{};
        {
            std::scoped_lock lock(node_mutex_);
            peers = node_.connected_peer_count();
            chunks = node_.stored_chunks().size();
            port = node_.transport_port();
            config_copy = node_.config();
        }

        ControlFields fields{{"CODE", "OK_STATUS"},
                             {"PEERS", std::to_string(peers)},
                             {"CHUNKS", std::to_string(chunks)},
                             {"TRANSPORT_PORT", std::to_string(port)}};

        if (!config_copy.auto_advertise_warnings.empty()) {
            std::ostringstream warnings_stream;
            for (const auto& warning : config_copy.auto_advertise_warnings) {
                warnings_stream << warning << '\n';
            }
            fields["AUTO_ADVERTISE_WARNINGS"] = warnings_stream.str();
            fields["AUTO_ADVERTISE_CONFLICT"] = config_copy.auto_advertise_conflict ? "1" : "0";
        }

        send_response(client, fields, true);

        StructuredLogger::FieldList log_fields{{"remote", remote_identity},
                                               {"peers", std::to_string(peers)},
                                               {"chunks", std::to_string(chunks)},
                                               {"transport_port", std::to_string(port)}};
        if (!config_copy.auto_advertise_warnings.empty()) {
            log_fields.emplace_back("auto_advertise_warning_count",
                                    std::to_string(config_copy.auto_advertise_warnings.size()));
            log_fields.emplace_back("auto_advertise_conflict",
                                    config_copy.auto_advertise_conflict ? "1" : "0");
        }
        log_event(StructuredLogger::Level::Info,
                  "control.command.status",
                  std::move(log_fields));
    }

    void handle_stop(NativeSocket client, const std::string& remote_identity) {
        bool stopped_now = false;
        {
            std::scoped_lock lock(node_mutex_);
            const bool already_stopped = transport_stopped_.load(std::memory_order_acquire);
            if (!already_stopped) {
                node_.stop_transport();
                transport_stopped_.store(true, std::memory_order_release);
                stopped_now = true;
            }
        }

        auto fields = make_ok("OK_STOP");
        fields["MESSAGE"] = "Stopping daemon";
        if (stopped_now) {
            fields["TRANSPORT"] = "STOPPED";
        }
        send_response(client, fields, true);
        log_event(StructuredLogger::Level::Info,
                  "control.command.stop",
                  {{"remote", remote_identity}, {"transport_stopped", stopped_now ? "1" : "0"}});
        if (stop_callback_) {
            stop_callback_();
        }
    }

    void handle_list(NativeSocket client, const std::string& remote_identity) {
        std::vector<ChunkStore::SnapshotEntry> snapshot;
        {
            std::scoped_lock lock(node_mutex_);
            snapshot = node_.stored_chunks();
        }

        ControlFields fields;
        fields["CODE"] = "OK_LIST";
        fields["COUNT"] = std::to_string(snapshot.size());

        std::ostringstream entries;
        for (const auto& entry : snapshot) {
            entries << ephemeralnet::chunk_id_to_string(entry.id) << ','
                    << entry.size << ','
                    << (entry.encrypted ? "encrypted" : "plain") << ','
                    << ttl_seconds_remaining(entry.expires_at);
            entries << '\n';
        }

        fields["ENTRIES"] = entries.str();
        send_response(client, fields, true);
        log_event(StructuredLogger::Level::Info,
                  "control.command.list",
                  {{"remote", remote_identity},
                   {"count", std::to_string(snapshot.size())}});
    }

    void handle_defaults(NativeSocket client, const std::string& remote_identity) {
        Config config_copy{};
        {
            std::scoped_lock lock(node_mutex_);
            config_copy = node_.config();
        }

        ControlFields fields{{"CODE", "OK_DEFAULTS"},
                             {"DEFAULT_TTL", std::to_string(config_copy.default_chunk_ttl.count())},
                             {"MIN_TTL", std::to_string(config_copy.min_manifest_ttl.count())},
                             {"MAX_TTL", std::to_string(config_copy.max_manifest_ttl.count())},
                             {"KEY_ROTATION", std::to_string(config_copy.key_rotation_interval.count())},
                             {"ANNOUNCE_INTERVAL", std::to_string(config_copy.announce_min_interval.count())},
                             {"ANNOUNCE_BURST", std::to_string(config_copy.announce_burst_limit)},
                             {"ANNOUNCE_WINDOW", std::to_string(config_copy.announce_burst_window.count())},
                             {"ANNOUNCE_POW", std::to_string(config_copy.announce_pow_difficulty)},
                             {"HANDSHAKE_POW", std::to_string(config_copy.handshake_pow_difficulty)},
                             {"STORE_POW", std::to_string(config_copy.store_pow_difficulty)},
                             {"CONTROL_HOST", config_copy.control_host},
                             {"CONTROL_PORT", std::to_string(config_copy.control_port)},
                             {"TRANSPORT_PORT", std::to_string(config_copy.transport_listen_port)},
                             {"CONTROL_STREAM_MAX", std::to_string(config_copy.control_stream_max_bytes)},
                             {"STORAGE_PERSISTENT", config_copy.storage_persistent_enabled ? "1" : "0"},
                             {"STORAGE_DIR", config_copy.storage_directory},
                             {"FETCH_MAX_PARALLEL", std::to_string(config_copy.fetch_max_parallel_requests)},
                             {"UPLOAD_MAX_PARALLEL", std::to_string(config_copy.upload_max_parallel_transfers)},
                             {"ADVERTISE_AUTO_MODE", advertise_auto_mode_to_string(config_copy.advertise_auto_mode)}};

        if (config_copy.advertise_control_host) {
            fields["ADVERTISE_HOST"] = *config_copy.advertise_control_host;
        }
        if (config_copy.advertise_control_port) {
            fields["ADVERTISE_PORT"] = std::to_string(*config_copy.advertise_control_port);
        }
        if (!config_copy.advertised_endpoints.empty()) {
            std::ostringstream serialized;
            bool first = true;
            for (const auto& endpoint : config_copy.advertised_endpoints) {
                if (endpoint.host.empty()) {
                    continue;
                }
                const auto port = endpoint.port != 0 ? endpoint.port : config_copy.control_port;
                if (!first) {
                    serialized << '\n';
                }
                first = false;
                serialized << endpoint.host << ':' << port;
                if (!endpoint.source.empty()) {
                    serialized << " (" << endpoint.source << ')';
                }
            }
            fields["ADVERTISE_ENDPOINTS"] = serialized.str();
        }

        if (!config_copy.bootstrap_nodes.empty()) {
            std::ostringstream bootstrap_stream;
            bool first = true;
            for (const auto& node : config_copy.bootstrap_nodes) {
                if (node.host.empty()) {
                    continue;
                }
                if (!first) {
                    bootstrap_stream << '\n';
                }
                first = false;
                bootstrap_stream << ephemeralnet::peer_id_to_string(node.id) << '@' << node.host << ':' << node.port;
                if (node.public_identity) {
                    bootstrap_stream << " pub=" << *node.public_identity;
                }
            }
            fields["BOOTSTRAP_NODES"] = bootstrap_stream.str();
        }

        send_response(client, fields, true);
        log_event(StructuredLogger::Level::Info,
                  "control.command.defaults",
                  {{"remote", remote_identity}});
    }

    void handle_metrics(NativeSocket client, const std::string& remote_identity) {
        Config config_copy{};
        Node::PowStatistics pow_stats{};
        {
            std::scoped_lock lock(node_mutex_);
            config_copy = node_.config();
            pow_stats = node_.pow_statistics();
        }

        const auto snapshot = metrics_.render_prometheus(config_copy, pow_stats);
        ControlFields fields{{"CODE", "OK_METRICS"}};
        const auto payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(snapshot.data()), snapshot.size());
        send_response(client, fields, true, payload);
        log_event(StructuredLogger::Level::Info,
                  "control.command.metrics",
                  {{"remote", remote_identity},
                   {"bytes", std::to_string(snapshot.size())}});
    }

    void handle_store(NativeSocket client, ParsedRequest request, const std::string& remote_identity) {
        auto respond_error = [&](ControlFields fields,
                                 std::string_view reason,
                                 bool auth_failure = false,
                                 bool rate_limited = false) {
            if (auth_failure) {
                metrics_.command_store_auth_failures_total.fetch_add(1, std::memory_order_relaxed);
            }
            if (rate_limited) {
                metrics_.command_store_rate_limited_total.fetch_add(1, std::memory_order_relaxed);
            }
            StructuredLogger::FieldList log_fields;
            log_fields.emplace_back("remote", remote_identity);
            log_fields.emplace_back("status", "error");
            const auto code_it = fields.find("CODE");
            log_fields.emplace_back("code", code_it != fields.end() ? code_it->second : std::string("UNKNOWN"));
            log_fields.emplace_back("reason", std::string(reason));
            log_event(StructuredLogger::Level::Warning, "control.command.store", std::move(log_fields));
            send_response(client, std::move(fields), false);
        };

        if (!request.payload_header_present) {
            auto error = make_error("ERR_STORE_PAYLOAD_REQUIRED",
                                    "STORE requires a streamed payload",
                                    "Upgrade the CLI and retry the command");
            respond_error(std::move(error), "payload_missing");
            return;
        }

        const auto stream_limit = max_control_stream_bytes();
        if (request.payload.size() > stream_limit) {
            auto error = make_error("ERR_STORE_PAYLOAD_TOO_LARGE",
                                    "Payload exceeds server allowance",
                                    "Lower the payload size or adjust --max-store-bytes");
            respond_error(std::move(error), "payload_too_large");
            return;
        }

        std::chrono::seconds default_ttl{};
        std::chrono::seconds min_ttl{};
        std::chrono::seconds max_ttl{};
        std::optional<std::string> control_token;
        std::uint8_t store_pow_difficulty{0};
        {
            std::scoped_lock lock(node_mutex_);
            const auto& cfg = node_.config();
            default_ttl = cfg.default_chunk_ttl;
            min_ttl = cfg.min_manifest_ttl;
            max_ttl = cfg.max_manifest_ttl;
            control_token = cfg.control_token;
            store_pow_difficulty = cfg.store_pow_difficulty;
        }

        const auto token_it = request.fields.find("TOKEN");
        std::string rate_identity = remote_identity;
        if (control_token.has_value()) {
            if (token_it == request.fields.end()) {
                auto error = make_error("ERR_STORE_UNAUTHENTICATED",
                                        "Control token required",
                                        "Provide --control-token when invoking the CLI");
                respond_error(std::move(error), "auth_missing", true, false);
                return;
            }
            if (!constant_time_equal(*control_token, token_it->second)) {
                auto error = make_error("ERR_STORE_UNAUTHENTICATED",
                                        "Invalid control token",
                                        "Verify the shared secret configured on the daemon");
                respond_error(std::move(error), "auth_invalid", true, false);
                return;
            }
            rate_identity = hashed_token_identity(token_it->second);
        } else if (token_it != request.fields.end()) {
            rate_identity = hashed_token_identity(token_it->second);
        }

        std::chrono::seconds ttl = default_ttl;
        if (const auto ttl_it = request.fields.find("TTL"); ttl_it != request.fields.end()) {
            const auto parsed = parse_uint64(ttl_it->second);
            if (!parsed.has_value()) {
                auto error = make_error("ERR_STORE_TTL_INVALID",
                                        "Invalid TTL",
                                        "Use a positive integer value in seconds");
                respond_error(std::move(error), "ttl_invalid");
                return;
            }
            ttl = std::chrono::seconds(*parsed);
        }

        if (ttl < min_ttl || ttl > max_ttl) {
            auto error = make_error("ERR_STORE_TTL_OUT_OF_RANGE",
                                    "TTL outside permitted bounds",
                                    "Allowed range: " + std::to_string(min_ttl.count()) +
                                        "s - " + std::to_string(max_ttl.count()) + "s");
            respond_error(std::move(error), "ttl_out_of_range");
            return;
        }

        if (!allow_store_request(rate_identity)) {
            auto error = make_error("ERR_STORE_RATE_LIMITED",
                                    "Too many STORE requests",
                                    "Wait a few seconds before retrying");
            respond_error(std::move(error), "rate_limited", false, true);
            return;
        }

        const auto payload_span = std::span<const std::uint8_t>(request.payload.data(), request.payload.size());
        const auto chunk_id = security::derive_chunk_id(payload_span);
        auto data = std::move(request.payload);
        const auto data_size = data.size();

        std::optional<std::string> filename_hint;
        if (const auto name_it = request.fields.find("PATH"); name_it != request.fields.end()) {
            filename_hint = security::sanitize_filename_hint(name_it->second);
        }

        security::StoreWorkInput pow_input{chunk_id,
                                           static_cast<std::uint64_t>(data_size),
                                           filename_hint ? std::string_view(*filename_hint) : std::string_view{}};

        if (store_pow_difficulty > 0) {
            const auto pow_field = request.fields.find("STORE-POW");
            if (pow_field == request.fields.end()) {
                metrics_.command_store_pow_failures_total.fetch_add(1, std::memory_order_relaxed);
                const bool locked = note_store_pow_failure(rate_identity);
                auto error = make_error(locked ? "ERR_STORE_POW_LOCKED" : "ERR_STORE_POW_REQUIRED",
                                        locked ? "Repeated invalid proofs-of-work detected"
                                               : "Proof-of-work nonce required",
                                        locked ? "Wait two minutes before retrying"
                                               : "Upgrade the CLI and retry the command");
                respond_error(std::move(error), locked ? "pow_missing_locked" : "pow_missing");
                return;
            }
            const auto parsed_pow = parse_uint64(pow_field->second);
            if (!parsed_pow.has_value()) {
                metrics_.command_store_pow_failures_total.fetch_add(1, std::memory_order_relaxed);
                const bool locked = note_store_pow_failure(rate_identity);
                auto error = make_error(locked ? "ERR_STORE_POW_LOCKED" : "ERR_STORE_POW_INVALID",
                                        locked ? "Repeated invalid proofs-of-work detected"
                                               : "Malformed proof-of-work nonce",
                                        locked ? "Wait two minutes before retrying"
                                               : "Retry the store command to generate new work");
                respond_error(std::move(error), locked ? "pow_invalid_locked" : "pow_invalid_parse");
                return;
            }
            if (!security::store_pow_valid(pow_input, *parsed_pow, store_pow_difficulty)) {
                metrics_.command_store_pow_failures_total.fetch_add(1, std::memory_order_relaxed);
                const bool locked = note_store_pow_failure(rate_identity);
                auto error = make_error(locked ? "ERR_STORE_POW_LOCKED" : "ERR_STORE_POW_INVALID",
                                        locked ? "Repeated invalid proofs-of-work detected"
                                               : "Proof-of-work verification failed",
                                        locked ? "Wait two minutes before retrying"
                                               : "Retry the store command to generate new work");
                respond_error(std::move(error), locked ? "pow_invalid_locked" : "pow_invalid");
                return;
            }
        }
        clear_store_pow_failures(rate_identity);

        std::optional<std::string> original_name = filename_hint;

        protocol::Manifest manifest{};
        {
            std::scoped_lock lock(node_mutex_);
            manifest = node_.store_chunk(chunk_id, std::move(data), ttl, original_name);
        }

        const auto manifest_uri = protocol::encode_manifest(manifest);
        const auto expires_in = std::max<std::int64_t>(
            0,
            std::chrono::duration_cast<std::chrono::seconds>(
                manifest.expires_at - std::chrono::system_clock::now())
                .count());

        ControlFields fields{{"CODE", "OK_STORE"},
                             {"MANIFEST", manifest_uri},
                             {"SIZE", std::to_string(data_size)},
                             {"TTL", std::to_string(expires_in)}};

        if (const auto name_it = request.fields.find("PATH"); name_it != request.fields.end()) {
            fields["SOURCE"] = name_it->second;
        }

        if (const auto meta_it = manifest.metadata.find("filename"); meta_it != manifest.metadata.end()) {
            fields["FILENAME"] = meta_it->second;
        }

        metrics_.command_store_success_total.fetch_add(1, std::memory_order_relaxed);
        metrics_.command_store_bytes_total.fetch_add(data_size, std::memory_order_relaxed);

        StructuredLogger::FieldList log_fields;
        log_fields.emplace_back("remote", remote_identity);
        log_fields.emplace_back("status", "ok");
        log_fields.emplace_back("size", std::to_string(data_size));
        log_fields.emplace_back("ttl", std::to_string(expires_in));
        if (original_name.has_value()) {
            log_fields.emplace_back("filename", *original_name);
        }
        log_event(StructuredLogger::Level::Info, "control.command.store", std::move(log_fields));

        send_response(client, fields, true);
    }

    void handle_fetch(NativeSocket client, const ParsedRequest& request, const std::string& remote_identity) {
        auto respond_error = [&](ControlFields fields,
                                 std::string_view reason,
                                 bool auth_failure = false,
                                 bool rate_limited = false) {
            if (auth_failure) {
                metrics_.command_fetch_auth_failures_total.fetch_add(1, std::memory_order_relaxed);
            }
            if (rate_limited) {
                metrics_.command_fetch_rate_limited_total.fetch_add(1, std::memory_order_relaxed);
            }
            StructuredLogger::FieldList log_fields;
            log_fields.emplace_back("remote", remote_identity);
            log_fields.emplace_back("status", "error");
            const auto code_it = fields.find("CODE");
            log_fields.emplace_back("code", code_it != fields.end() ? code_it->second : std::string("UNKNOWN"));
            log_fields.emplace_back("reason", std::string(reason));
            log_event(StructuredLogger::Level::Warning, "control.command.fetch", std::move(log_fields));
            send_response(client, std::move(fields), false);
        };

        const auto& fields = request.fields;
        const auto manifest_it = fields.find("MANIFEST");
        if (manifest_it == fields.end()) {
            auto error = make_error("ERR_FETCH_MANIFEST_REQUIRED",
                                    "FETCH requires MANIFEST",
                                    "Include MANIFEST:eph://... in the request");
            respond_error(std::move(error), "manifest_missing");
            return;
        }

        protocol::Manifest manifest{};
        try {
            manifest = protocol::decode_manifest(manifest_it->second);
        } catch (const std::exception&) {
            auto error = make_error("ERR_FETCH_MANIFEST_INVALID",
                                    "Invalid manifest",
                                    "Ensure the eph:// URI is complete");
            respond_error(std::move(error), "manifest_invalid");
            return;
        }

        std::optional<std::filesystem::path> output_path;
        if (const auto out_it = fields.find("OUT"); out_it != fields.end()) {
            output_path = std::filesystem::absolute(std::filesystem::path(out_it->second));
        }

        bool stream_to_client = false;
        if (const auto stream_it = fields.find("STREAM"); stream_it != fields.end()) {
            const auto mode = to_upper(stream_it->second);
            if (mode == "CLIENT" || mode == "1" || mode == "TRUE" || mode == "YES") {
                stream_to_client = true;
            }
        }

        if (!stream_to_client && !output_path.has_value()) {
            auto error = make_error("ERR_FETCH_OUT_REQUIRED",
                                    "FETCH requires OUT",
                                    "Add OUT:destination_path to the request or STREAM:client for streaming");
            respond_error(std::move(error), "destination_required");
            return;
        }

        std::optional<ChunkData> chunk;
        {
            std::scoped_lock lock(node_mutex_);
            if (!node_.ingest_manifest(manifest_it->second)) {
                auto error = make_error("ERR_FETCH_MANIFEST_REGISTRATION",
                                        "Failed to register manifest",
                                        "The chunk TTL may have expired");
                respond_error(std::move(error), "manifest_registration_failed");
                return;
            }
            chunk = node_.fetch_chunk(manifest.chunk_id);
        }

        if (!chunk.has_value()) {
            auto error = make_error("ERR_FETCH_CHUNK_MISSING",
                                    "Chunk not available locally",
                                    "Wait for it to arrive from the swarm or verify connectivity");
            respond_error(std::move(error), "chunk_missing");
            return;
        }

        if (stream_to_client) {
            std::optional<std::string> control_token;
            {
                std::scoped_lock lock(node_mutex_);
                control_token = node_.config().control_token;
            }

            const auto token_it = fields.find("TOKEN");
            std::string rate_identity = remote_identity;
            if (control_token.has_value()) {
                if (token_it == fields.end()) {
                    auto error = make_error("ERR_FETCH_UNAUTHENTICATED",
                                            "Control token required",
                                            "Provide --control-token when invoking the CLI");
                    respond_error(std::move(error), "auth_missing", true, false);
                    return;
                }
                if (!constant_time_equal(*control_token, token_it->second)) {
                    auto error = make_error("ERR_FETCH_UNAUTHENTICATED",
                                            "Invalid control token",
                                            "Verify the shared secret configured on the daemon");
                    respond_error(std::move(error), "auth_invalid", true, false);
                    return;
                }
                rate_identity = hashed_token_identity(token_it->second);
            } else if (token_it != fields.end()) {
                rate_identity = hashed_token_identity(token_it->second);
            }

            if (!allow_stream_fetch(rate_identity)) {
                auto error = make_error("ERR_FETCH_RATE_LIMITED",
                                        "Too many FETCH requests",
                                        "Wait a few seconds before retrying");
                respond_error(std::move(error), "rate_limited", false, true);
                return;
            }

            const auto stream_limit = max_control_stream_bytes();
            if (chunk->size() > stream_limit) {
                auto error = make_error("ERR_FETCH_PAYLOAD_TOO_LARGE",
                                        "Chunk exceeds streaming allowance",
                                        "Adjust --max-store-bytes or fetch locally on the daemon host");
                respond_error(std::move(error), "payload_too_large");
                return;
            }

            ControlFields response_fields{{"CODE", "OK_FETCH"},
                                          {"SIZE", std::to_string(chunk->size())},
                                          {"STREAM", "CLIENT"}};
            metrics_.command_fetch_success_total.fetch_add(1, std::memory_order_relaxed);
            metrics_.command_fetch_stream_success_total.fetch_add(1, std::memory_order_relaxed);
            metrics_.command_fetch_bytes_total.fetch_add(static_cast<std::uint64_t>(chunk->size()), std::memory_order_relaxed);

            StructuredLogger::FieldList log_fields;
            log_fields.emplace_back("remote", remote_identity);
            log_fields.emplace_back("status", "ok");
            log_fields.emplace_back("mode", "stream");
            log_fields.emplace_back("size", std::to_string(chunk->size()));
            log_fields.emplace_back("chunk_id", ephemeralnet::chunk_id_to_string(manifest.chunk_id));
            log_event(StructuredLogger::Level::Info, "control.command.fetch", std::move(log_fields));

            send_response(client,
                          std::move(response_fields),
                          true,
                          std::span<const std::uint8_t>(chunk->data(), chunk->size()));
            return;
        }

        try {
            write_file_bytes(*output_path, std::span<const std::uint8_t>(chunk->data(), chunk->size()));
        } catch (const std::exception& ex) {
            auto error = make_error("ERR_FETCH_WRITE_FAILED",
                                    ex.what(),
                                    "Verify write permissions and free disk space");
            respond_error(std::move(error), "write_failed");
            return;
        }

        ControlFields response_fields{{"CODE", "OK_FETCH"},
                                      {"OUTPUT", output_path->string()},
                                      {"SIZE", std::to_string(chunk->size())}};
        metrics_.command_fetch_success_total.fetch_add(1, std::memory_order_relaxed);
        metrics_.command_fetch_bytes_total.fetch_add(static_cast<std::uint64_t>(chunk->size()), std::memory_order_relaxed);

        StructuredLogger::FieldList log_fields;
        log_fields.emplace_back("remote", remote_identity);
        log_fields.emplace_back("status", "ok");
        log_fields.emplace_back("mode", "file");
        log_fields.emplace_back("size", std::to_string(chunk->size()));
    log_fields.emplace_back("chunk_id", ephemeralnet::chunk_id_to_string(manifest.chunk_id));
        log_fields.emplace_back("output", output_path->string());
        log_event(StructuredLogger::Level::Info, "control.command.fetch", std::move(log_fields));

        send_response(client, std::move(response_fields), true);
    }
};

ControlServer::ControlServer(Node& node, std::mutex& node_mutex, StopCallback stop_callback)
    : impl_(std::make_unique<Impl>(node, node_mutex, std::move(stop_callback))) {}

ControlServer::~ControlServer() = default;

void ControlServer::start(const std::string& host, std::uint16_t port) {
    impl_->start(host, port);
}

void ControlServer::stop() {
    impl_->stop();
}

bool ControlServer::running() const noexcept {
    return impl_->running();
}

}  // namespace ephemeralnet::daemon
