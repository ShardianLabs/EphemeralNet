#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <unordered_map>

namespace ephemeralnet::relay {

class EventLoop {
public:
    using EventCallback = std::function<void(int fd, std::uint32_t events)>;

    static constexpr std::uint32_t kEventNone = 0;
    static constexpr std::uint32_t kEventReadable = 1u << 0;
    static constexpr std::uint32_t kEventWritable = 1u << 1;
    static constexpr std::uint32_t kEventError = 1u << 2;

    EventLoop();
    ~EventLoop();

    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;

    void add(int fd, std::uint32_t events, EventCallback callback);
    void update(int fd, std::uint32_t events);
    void remove(int fd);

    void run();
    void stop();

private:
    struct Watcher {
        std::uint32_t events{0};
        EventCallback callback;
    };

    void wake();
    std::uint32_t translate_events(std::uint32_t backend_mask) const;

#ifdef __linux__
    int backend_fd_{-1};
    int wake_fd_{-1};
#elif defined(__APPLE__)
    int backend_fd_{-1};
    int wake_pipe_[2]{-1, -1};
#else
#error "EventLoop currently supports Linux and macOS only."
#endif

    std::unordered_map<int, Watcher> watchers_;
    std::atomic<bool> running_{false};
};

}  // namespace ephemeralnet::relay
