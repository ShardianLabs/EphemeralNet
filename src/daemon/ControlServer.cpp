#include "ephemeralnet/daemon/ControlPlane.hpp"

#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

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
constexpr std::size_t kMaxStreamPayloadBytes = kMaxControlStreamBytes;
constexpr std::chrono::seconds kStoreRateWindow{std::chrono::seconds(30)};
constexpr std::size_t kStoreRateBurstLimit = 6;
constexpr std::chrono::seconds kFetchStreamRateWindow{std::chrono::seconds(30)};
constexpr std::size_t kFetchStreamBurstLimit = 12;

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
            if (*parsed > kMaxControlStreamBytes) {
                result.error_code = "ERR_CONTROL_PAYLOAD_TOO_LARGE";
                result.error_message = "Payload exceeds server allowance";
                result.error_hint = "Reduce the file below 32 MiB";
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

ChunkId chunk_id_from_data(std::span<const std::uint8_t> data) {
    const auto digest = crypto::Sha256::digest(data);
    ChunkId id{};
    std::copy(digest.begin(), digest.end(), id.begin());
    return id;
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

}  // namespace

class ControlServer::Impl {
public:
    Impl(Node& node, std::mutex& node_mutex, StopCallback stop_callback)
        : node_(node), node_mutex_(node_mutex), stop_callback_(std::move(stop_callback)) {
        winsock_runtime();
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
        running_ = true;
        accept_thread_ = std::thread(&Impl::accept_loop, this);
    }

    void stop() {
        if (!running_) {
            return;
        }
        running_ = false;
        close_socket(listen_socket_);
        listen_socket_ = kInvalidSocket;
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
    }

    bool running() const noexcept {
        return running_.load();
    }

private:
    Node& node_;
    std::mutex& node_mutex_;
    StopCallback stop_callback_;
    std::atomic<bool> running_{false};
    NativeSocket listen_socket_{kInvalidSocket};
    std::thread accept_thread_;
    std::mutex rate_mutex_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> store_history_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> fetch_history_;

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
        while (running_) {
            sockaddr_in client_addr{};
#ifdef _WIN32
            int addr_len = sizeof(client_addr);
#else
            socklen_t addr_len = sizeof(client_addr);
#endif
            const auto client = ::accept(listen_socket_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client == kInvalidSocket) {
                if (running_) {
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
            auto error = make_error(parse.error_code.empty() ? "ERR_CONTROL_REQUEST"
                                                             : parse.error_code,
                                     parse.error_message.empty() ? "Malformed control request"
                                                                 : parse.error_message,
                                     parse.error_hint);
            send_response(client, std::move(error), false);
            return;
        }

        auto request = std::move(parse.request);
        const auto it = request.fields.find("COMMAND");
        if (it == request.fields.end()) {
            auto error = make_error("ERR_MISSING_COMMAND",
                                    "COMMAND header missing",
                                    "Include the COMMAND header in the request");
            send_response(client, error, false);
            return;
        }

        const auto command = to_upper(it->second);
        if (command == "PING") {
            auto fields = make_ok("OK_PING");
            fields["MESSAGE"] = "pong";
            send_response(client, fields, true);
            return;
        }
        if (command == "STATUS") {
            handle_status(client);
            return;
        }
        if (command == "STOP") {
            handle_stop(client);
            return;
        }
        if (command == "LIST") {
            handle_list(client);
            return;
        }
        if (command == "STORE") {
            handle_store(client, std::move(request), remote_identity);
            return;
        }
        if (command == "FETCH") {
            handle_fetch(client, request, remote_identity);
            return;
        }

        auto error = make_error("ERR_UNSUPPORTED_COMMAND",
                                "Unsupported command",
                                "Check the control API documentation");
        send_response(client, error, false);
    }

    void handle_status(NativeSocket client) {
        std::size_t peers = 0;
        std::size_t chunks = 0;
        std::uint16_t port = 0;
        {
            std::scoped_lock lock(node_mutex_);
            peers = node_.connected_peer_count();
            chunks = node_.stored_chunks().size();
            port = node_.transport_port();
        }

        ControlFields fields{{"CODE", "OK_STATUS"},
                             {"PEERS", std::to_string(peers)},
                             {"CHUNKS", std::to_string(chunks)},
                             {"TRANSPORT_PORT", std::to_string(port)}};
        send_response(client, fields, true);
    }

    void handle_stop(NativeSocket client) {
        auto fields = make_ok("OK_STOP");
        fields["MESSAGE"] = "Stopping daemon";
        send_response(client, fields, true);
        if (stop_callback_) {
            stop_callback_();
        }
    }

    void handle_list(NativeSocket client) {
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
    }

    void handle_store(NativeSocket client, ParsedRequest request, const std::string& remote_identity) {
        if (!request.payload_header_present) {
            auto error = make_error("ERR_STORE_PAYLOAD_REQUIRED",
                                    "STORE requires a streamed payload",
                                    "Upgrade the CLI and retry the command");
            send_response(client, error, false);
            return;
        }

        if (request.payload.size() > kMaxControlStreamBytes) {
            auto error = make_error("ERR_STORE_PAYLOAD_TOO_LARGE",
                                    "Payload exceeds server allowance",
                                    "Reduce the file below 32 MiB");
            send_response(client, error, false);
            return;
        }

        std::chrono::seconds default_ttl{};
        std::chrono::seconds min_ttl{};
        std::chrono::seconds max_ttl{};
        std::optional<std::string> control_token;
        {
            std::scoped_lock lock(node_mutex_);
            const auto& cfg = node_.config();
            default_ttl = cfg.default_chunk_ttl;
            min_ttl = cfg.min_manifest_ttl;
            max_ttl = cfg.max_manifest_ttl;
            control_token = cfg.control_token;
        }

        const auto token_it = request.fields.find("TOKEN");
        std::string rate_identity = remote_identity;
        if (control_token.has_value()) {
            if (token_it == request.fields.end()) {
                auto error = make_error("ERR_STORE_UNAUTHENTICATED",
                                        "Control token required",
                                        "Provide --control-token when invoking the CLI");
                send_response(client, error, false);
                return;
            }
            if (!constant_time_equal(*control_token, token_it->second)) {
                auto error = make_error("ERR_STORE_UNAUTHENTICATED",
                                        "Invalid control token",
                                        "Verify the shared secret configured on the daemon");
                send_response(client, error, false);
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
                send_response(client, error, false);
                return;
            }
            ttl = std::chrono::seconds(*parsed);
        }

        if (ttl < min_ttl || ttl > max_ttl) {
            auto error = make_error("ERR_STORE_TTL_OUT_OF_RANGE",
                                    "TTL outside permitted bounds",
                                    "Allowed range: " + std::to_string(min_ttl.count()) +
                                        "s - " + std::to_string(max_ttl.count()) + "s");
            send_response(client, error, false);
            return;
        }

        if (!allow_store_request(rate_identity)) {
            auto error = make_error("ERR_STORE_RATE_LIMITED",
                                    "Too many STORE requests",
                                    "Wait a few seconds before retrying");
            send_response(client, error, false);
            return;
        }

        const auto payload_span = std::span<const std::uint8_t>(request.payload.data(), request.payload.size());
        const auto chunk_id = chunk_id_from_data(payload_span);
        auto data = std::move(request.payload);
        const auto data_size = data.size();

        protocol::Manifest manifest{};
        {
            std::scoped_lock lock(node_mutex_);
            manifest = node_.store_chunk(chunk_id, std::move(data), ttl);
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

        send_response(client, fields, true);
    }

    void handle_fetch(NativeSocket client, const ParsedRequest& request, const std::string& remote_identity) {
        const auto& fields = request.fields;
        const auto manifest_it = fields.find("MANIFEST");
        if (manifest_it == fields.end()) {
            auto error = make_error("ERR_FETCH_MANIFEST_REQUIRED",
                                    "FETCH requires MANIFEST",
                                    "Include MANIFEST:eph://... in the request");
            send_response(client, error, false);
            return;
        }

        protocol::Manifest manifest{};
        try {
            manifest = protocol::decode_manifest(manifest_it->second);
        } catch (const std::exception&) {
            auto error = make_error("ERR_FETCH_MANIFEST_INVALID",
                                    "Invalid manifest",
                                    "Ensure the eph:// URI is complete");
            send_response(client, error, false);
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
            send_response(client, error, false);
            return;
        }

        std::optional<ChunkData> chunk;
        {
            std::scoped_lock lock(node_mutex_);
            if (!node_.ingest_manifest(manifest_it->second)) {
                auto error = make_error("ERR_FETCH_MANIFEST_REGISTRATION",
                                        "Failed to register manifest",
                                        "The chunk TTL may have expired");
                send_response(client, error, false);
                return;
            }
            chunk = node_.fetch_chunk(manifest.chunk_id);
        }

        if (!chunk.has_value()) {
            auto error = make_error("ERR_FETCH_CHUNK_MISSING",
                                    "Chunk not available locally",
                                    "Wait for it to arrive from the swarm or verify connectivity");
            send_response(client, error, false);
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
                    send_response(client, error, false);
                    return;
                }
                if (!constant_time_equal(*control_token, token_it->second)) {
                    auto error = make_error("ERR_FETCH_UNAUTHENTICATED",
                                            "Invalid control token",
                                            "Verify the shared secret configured on the daemon");
                    send_response(client, error, false);
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
                send_response(client, error, false);
                return;
            }

            if (chunk->size() > kMaxStreamPayloadBytes) {
                auto error = make_error("ERR_FETCH_PAYLOAD_TOO_LARGE",
                                        "Chunk exceeds streaming allowance",
                                        "Adjust the payload limit or fetch locally on the daemon host");
                send_response(client, error, false);
                return;
            }

            ControlFields response_fields{{"CODE", "OK_FETCH"},
                                          {"SIZE", std::to_string(chunk->size())},
                                          {"STREAM", "CLIENT"}};
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
            send_response(client, error, false);
            return;
        }

    ControlFields response_fields{{"CODE", "OK_FETCH"},
                      {"OUTPUT", output_path->string()},
                      {"SIZE", std::to_string(chunk->size())}};
    send_response(client, response_fields, true);
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
