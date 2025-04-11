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
#include <utility>
#include <vector>

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

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("No se pudo abrir el archivo: " + path.string());
    }
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return data;
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
            handle_client(client);
            close_socket(client);
        }
    }

    static ControlFields parse_request(NativeSocket client) {
        ControlFields fields;
        std::string line;
        while (recv_line(client, line)) {
            if (line.empty()) {
                break;
            }
            const auto pos = line.find(':');
            if (pos == std::string::npos) {
                continue;
            }
            const auto key = to_upper(line.substr(0, pos));
            const auto value = line.substr(pos + 1);
            fields[key] = value;
        }
        return fields;
    }

    static void send_response(NativeSocket client, const ControlFields& fields, bool success) {
        std::ostringstream oss;
        oss << "STATUS:" << (success ? "OK" : "ERROR") << "\n";
        for (const auto& [key, value] : fields) {
            oss << key << ':' << value << "\n";
        }
        oss << "\n";
        const auto response = oss.str();
        send_all(client, response.c_str(), response.size());
    }

    void handle_client(NativeSocket client) {
        const auto request = parse_request(client);
        const auto it = request.find("COMMAND");
        if (it == request.end()) {
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
            handle_store(client, request);
            return;
        }
        if (command == "FETCH") {
            handle_fetch(client, request);
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

    void handle_store(NativeSocket client, const ControlFields& request) {
        const auto path_it = request.find("PATH");
        if (path_it == request.end()) {
            auto error = make_error("ERR_STORE_PATH_REQUIRED",
                                    "STORE requires PATH",
                                    "Include PATH with the absolute file path");
            send_response(client, error, false);
            return;
        }

        const std::filesystem::path input = std::filesystem::absolute(std::filesystem::path(path_it->second));
        if (!std::filesystem::exists(input)) {
            auto error = make_error("ERR_STORE_FILE_NOT_FOUND",
                                    "File does not exist",
                                    "Check PATH:" + input.string());
            send_response(client, error, false);
            return;
        }

        std::chrono::seconds default_ttl{};
        {
            std::scoped_lock lock(node_mutex_);
            default_ttl = node_.config().default_chunk_ttl;
        }

        std::chrono::seconds ttl = default_ttl;
        const auto ttl_it = request.find("TTL");
        if (ttl_it != request.end()) {
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

        std::vector<std::uint8_t> data;
        try {
            data = read_file_bytes(input);
        } catch (const std::exception& ex) {
            auto error = make_error("ERR_STORE_READ_FAILED",
                                    ex.what(),
                                    "Verify read permissions and available disk space");
            send_response(client, error, false);
            return;
        }

        const auto data_size = data.size();
        const auto chunk_id = chunk_id_from_data(std::span<const std::uint8_t>(data.data(), data.size()));
        protocol::Manifest manifest{};
        {
            std::scoped_lock lock(node_mutex_);
            manifest = node_.store_chunk(chunk_id, std::move(data), ttl);
        }

        const auto manifest_uri = protocol::encode_manifest(manifest);
        const auto expires_in = std::max<std::int64_t>(0,
            std::chrono::duration_cast<std::chrono::seconds>(manifest.expires_at - std::chrono::system_clock::now()).count());
        ControlFields fields{{"CODE", "OK_STORE"},
                             {"MANIFEST", manifest_uri},
                             {"SIZE", std::to_string(data_size)},
                             {"TTL", std::to_string(expires_in)}};
        send_response(client, fields, true);
    }

    void handle_fetch(NativeSocket client, const ControlFields& request) {
        const auto manifest_it = request.find("MANIFEST");
        if (manifest_it == request.end()) {
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
        const auto out_it = request.find("OUT");
        if (out_it != request.end()) {
            output_path = std::filesystem::absolute(std::filesystem::path(out_it->second));
        }

        if (!output_path.has_value()) {
            auto error = make_error("ERR_FETCH_OUT_REQUIRED",
                                    "FETCH requires OUT",
                                    "Add OUT:destination_path to the request");
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

        try {
            write_file_bytes(*output_path, std::span<const std::uint8_t>(chunk->data(), chunk->size()));
        } catch (const std::exception& ex) {
            auto error = make_error("ERR_FETCH_WRITE_FAILED",
                                    ex.what(),
                                    "Verify write permissions and free disk space");
            send_response(client, error, false);
            return;
        }

        ControlFields fields{{"CODE", "OK_FETCH"},
                             {"OUTPUT", output_path->string()},
                             {"SIZE", std::to_string(chunk->size())}};
        send_response(client, fields, true);
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
