#include "ephemeralnet/daemon/ControlPlane.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <system_error>
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
std::string to_upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
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

ControlResponse parse_response(NativeSocket socket) {
    ControlResponse response{};
    std::string line;
    bool status_seen = false;
    std::optional<std::size_t> payload_length;

    while (recv_line(socket, line)) {
        if (line.empty()) {
            break;
        }
        const auto pos = line.find(':');
        if (pos == std::string::npos) {
            continue;
        }
        const auto key = to_upper(line.substr(0, pos));
        const auto value = line.substr(pos + 1);
        if (key == "STATUS") {
            status_seen = true;
            response.success = (to_upper(value) == "OK");
        } else if (key == "PAYLOAD-LENGTH") {
            std::uint64_t length = 0;
            const auto* start = value.data();
            const auto* end = value.data() + value.size();
            const auto result = std::from_chars(start, end, length);
            if (result.ec == std::errc() && result.ptr == end) {
                response.fields[key] = value;
                payload_length = static_cast<std::size_t>(length);
            } else {
                response.success = false;
                response.fields["MESSAGE"] = "Invalid payload length";
                break;
            }
        } else {
            response.fields[key] = value;
        }
    }

    if (!status_seen) {
        response.success = false;
        response.fields["MESSAGE"] = "Respuesta incompleta del daemon";
    }

    if (payload_length.has_value()) {
        const auto limit = max_control_stream_bytes();
        if (*payload_length > limit) {
            response.success = false;
            response.has_payload = false;
            response.payload.clear();
            response.fields["MESSAGE"] = "Payload exceeds client limit";
            return response;
        }

        response.has_payload = true;
        response.payload.resize(*payload_length);
        if (*payload_length > 0) {
            if (!recv_exact(socket, response.payload.data(), *payload_length)) {
                response.success = false;
                response.has_payload = false;
                response.payload.clear();
                response.fields["MESSAGE"] = "Truncated control payload";
            }
        }
    }

    return response;
}

}  // namespace

class ControlClient::Impl {
public:
    Impl(std::string host, std::uint16_t port, std::optional<std::string> token)
        : host_(std::move(host)), port_(port), token_(std::move(token)) {
        winsock_runtime();
    }

    std::optional<ControlResponse> send(const std::string& command,
                                        const ControlFields& fields,
                                        std::span<const std::uint8_t> payload) {
        const bool include_payload = payload.data() != nullptr || payload.size() > 0;
        const auto limit = max_control_stream_bytes();
        if (include_payload && payload.size() > limit) {
            return std::nullopt;
        }

        const auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket == kInvalidSocket) {
            return std::nullopt;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        if (host_.empty() || host_ == "0.0.0.0") {
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else {
#ifdef _WIN32
            if (InetPtonA(AF_INET, host_.c_str(), &addr.sin_addr) != 1)
#else
            if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1)
#endif
            {
                close_socket(socket);
                return std::nullopt;
            }
        }

        if (::connect(socket, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
            close_socket(socket);
            return std::nullopt;
        }

        std::ostringstream request;
        request << "COMMAND:" << to_upper(command) << "\n";
        if (token_.has_value()) {
            request << "TOKEN:" << *token_ << "\n";
        }
        for (const auto& [key, value] : fields) {
            request << to_upper(key) << ':' << value << "\n";
        }
        if (include_payload) {
            request << "PAYLOAD-LENGTH:" << payload.size() << "\n";
        }
        request << "\n";

        const auto serialized = request.str();
        if (!send_all(socket, serialized.c_str(), serialized.size())) {
            close_socket(socket);
            return std::nullopt;
        }

        if (include_payload && payload.size() > 0) {
            if (!send_all(socket,
                          reinterpret_cast<const char*>(payload.data()),
                          payload.size())) {
                close_socket(socket);
                return std::nullopt;
            }
        }

        const auto response = parse_response(socket);
        close_socket(socket);
        return response;
    }

private:
    std::string host_;
    std::uint16_t port_;
    std::optional<std::string> token_;
};

ControlClient::ControlClient(std::string host, std::uint16_t port, std::optional<std::string> token)
    : impl_(std::make_unique<Impl>(std::move(host), port, std::move(token))) {}

ControlClient::~ControlClient() = default;

std::optional<ControlResponse> ControlClient::send(const std::string& command,
                                                   const ControlFields& fields,
                                                   std::span<const std::uint8_t> payload) {
    return impl_->send(command, fields, payload);
}

}  // namespace ephemeralnet::daemon
