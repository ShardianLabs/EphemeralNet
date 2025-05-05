#pragma once

#include "ephemeralnet/core/Node.hpp"

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

constexpr std::size_t kMaxControlStreamBytes = 32 * 1024 * 1024;

struct ControlResponse {
    bool success{false};
    ControlFields fields;
    bool has_payload{false};
    std::vector<std::uint8_t> payload;
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
                                        std::span<const std::uint8_t> payload = {});

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace ephemeralnet::daemon
