#pragma once

#include "ephemeralnet/core/Node.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace ephemeralnet::daemon {

using ControlFields = std::unordered_map<std::string, std::string>;

constexpr std::size_t kDefaultControlStreamBytes = 32 * 1024 * 1024;

// Returns the current control-plane stream ceiling in bytes (std::numeric_limits<size_t>::max for unlimited).
std::size_t max_control_stream_bytes();

// Sets the control-plane stream ceiling; pass 0 to disable the limit entirely.
void set_max_control_stream_bytes(std::size_t bytes);

struct ControlResponse {
    bool success{false};
    ControlFields fields;
    bool has_payload{false};
    std::vector<std::uint8_t> payload;
};

struct ControlTransferProgress {
    std::function<void(std::size_t current, std::size_t total)> on_upload;
    std::function<void(std::size_t current, std::size_t total)> on_download;
};

class ControlServer {
public:
    using StopCallback = std::function<void()>;

    ControlServer(Node& node, std::mutex& node_mutex, StopCallback stop_callback);
    ~ControlServer();

    ControlServer(const ControlServer&) = delete;
    ControlServer& operator=(const ControlServer&) = delete;

    void start(const std::string& host, std::uint16_t port);
    void stop();
    [[nodiscard]] bool running() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class ControlClient {
public:
    ControlClient(std::string host, std::uint16_t port, std::optional<std::string> token = std::nullopt);
    ~ControlClient();

    ControlClient(const ControlClient&) = delete;
    ControlClient& operator=(const ControlClient&) = delete;

    std::optional<ControlResponse> send(const std::string& command,
                                        const ControlFields& fields = {},
                                        std::span<const std::uint8_t> payload = {},
                                        const ControlTransferProgress* progress = nullptr);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace ephemeralnet::daemon
