#include "ephemeralnet/relay/EventLoop.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <stdexcept>
#include <system_error>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace ephemeralnet::relay {

namespace {
constexpr int kMaxEvents = 64;

#ifdef __APPLE__
int make_pipe(int fds[2]) {
    if (::pipe(fds) != 0) {
        return -1;
    }
    for (int i = 0; i < 2; ++i) {
        int flags = ::fcntl(fds[i], F_GETFL, 0);
        if (flags == -1) {
            return -1;
        }
        if (::fcntl(fds[i], F_SETFL, flags | O_NONBLOCK) == -1) {
            return -1;
        }
        int cloexec = ::fcntl(fds[i], F_GETFD, 0);
        if (cloexec == -1) {
            return -1;
        }
        ::fcntl(fds[i], F_SETFD, cloexec | FD_CLOEXEC);
    }
    return 0;
}
#endif

}  // namespace

EventLoop::EventLoop() {
#ifdef __linux__
    backend_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (backend_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_create1 failed");
    }
    wake_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "eventfd failed");
    }
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = wake_fd_;
    if (::epoll_ctl(backend_fd_, EPOLL_CTL_ADD, wake_fd_, &event) != 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl ADD wake_fd failed");
    }
#elif defined(__APPLE__)
    backend_fd_ = ::kqueue();
    if (backend_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "kqueue failed");
    }
    if (make_pipe(wake_pipe_) != 0) {
        throw std::system_error(errno, std::generic_category(), "pipe failed");
    }
    struct kevent kev{};
    EV_SET(&kev, wake_pipe_[0], EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (::kevent(backend_fd_, &kev, 1, nullptr, 0, nullptr) != 0) {
        throw std::system_error(errno, std::generic_category(), "kevent add wake pipe failed");
    }
#endif
}

EventLoop::~EventLoop() {
    stop();
#ifdef __linux__
    if (wake_fd_ >= 0) {
        ::close(wake_fd_);
    }
    if (backend_fd_ >= 0) {
        ::close(backend_fd_);
    }
#elif defined(__APPLE__)
    if (wake_pipe_[0] >= 0) {
        ::close(wake_pipe_[0]);
    }
    if (wake_pipe_[1] >= 0) {
        ::close(wake_pipe_[1]);
    }
    if (backend_fd_ >= 0) {
        ::close(backend_fd_);
    }
#endif
}

void EventLoop::add(int fd, std::uint32_t events, EventCallback callback) {
    Watcher watcher;
    watcher.events = events;
    watcher.callback = std::move(callback);
    watchers_[fd] = watcher;
#ifdef __linux__
    epoll_event event{};
    event.events = 0;
    if (events & kEventReadable) {
        event.events |= EPOLLIN;
    }
    if (events & kEventWritable) {
        event.events |= EPOLLOUT;
    }
    event.data.fd = fd;
    if (::epoll_ctl(backend_fd_, EPOLL_CTL_ADD, fd, &event) != 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl ADD failed");
    }
#elif defined(__APPLE__)
    std::array<struct kevent, 2> changes{};
    int change_count = 0;
    if (events & kEventReadable) {
        EV_SET(&changes[change_count++], fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
    }
    if (events & kEventWritable) {
        EV_SET(&changes[change_count++], fd, EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
    }
    if (change_count > 0 && ::kevent(backend_fd_, changes.data(), change_count, nullptr, 0, nullptr) != 0) {
        throw std::system_error(errno, std::generic_category(), "kevent add failed");
    }
#endif
}

void EventLoop::update(int fd, std::uint32_t events) {
    auto it = watchers_.find(fd);
    if (it == watchers_.end()) {
        return;
    }
    it->second.events = events;
#ifdef __linux__
    epoll_event event{};
    event.events = 0;
    if (events & kEventReadable) {
        event.events |= EPOLLIN;
    }
    if (events & kEventWritable) {
        event.events |= EPOLLOUT;
    }
    event.data.fd = fd;
    ::epoll_ctl(backend_fd_, EPOLL_CTL_MOD, fd, &event);
#elif defined(__APPLE__)
    std::array<struct kevent, 4> changes{};
    int change_count = 0;
    auto update_filter = [&](short filter, bool enabled) {
        EV_SET(&changes[change_count++], fd, filter, enabled ? EV_ADD : EV_DELETE, 0, 0, nullptr);
    };
    const bool want_read = (events & kEventReadable) != 0;
    const bool want_write = (events & kEventWritable) != 0;
    update_filter(EVFILT_READ, want_read);
    update_filter(EVFILT_WRITE, want_write);
    ::kevent(backend_fd_, changes.data(), change_count, nullptr, 0, nullptr);
#endif
}

void EventLoop::remove(int fd) {
    watchers_.erase(fd);
#ifdef __linux__
    ::epoll_ctl(backend_fd_, EPOLL_CTL_DEL, fd, nullptr);
#elif defined(__APPLE__)
    std::array<struct kevent, 2> changes{};
    EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(backend_fd_, changes.data(), 2, nullptr, 0, nullptr);
#endif
}

void EventLoop::run() {
    running_.store(true);
#ifdef __linux__
    std::array<epoll_event, kMaxEvents> events;
    while (running_.load()) {
        const int ready = ::epoll_wait(backend_fd_, events.data(), events.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < ready; ++i) {
            const int fd = events[i].data.fd;
            if (fd == wake_fd_) {
                std::uint64_t value = 0;
                const auto consumed = ::read(wake_fd_, &value, sizeof(value));
                (void)consumed;
                continue;
            }
            auto it = watchers_.find(fd);
            if (it == watchers_.end()) {
                continue;
            }
            const auto mask = translate_events(events[i].events);
            if (mask == kEventNone) {
                continue;
            }
            it->second.callback(fd, mask);
        }
    }
#elif defined(__APPLE__)
    std::array<struct kevent, kMaxEvents> events;
    while (running_.load()) {
        const int ready = ::kevent(backend_fd_, nullptr, 0, events.data(), events.size(), nullptr);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        std::unordered_map<int, std::uint32_t> aggregated;
        for (int i = 0; i < ready; ++i) {
            const auto& ev = events[i];
            if (static_cast<int>(ev.ident) == wake_pipe_[0]) {
                char buf[32];
                const auto consumed = ::read(wake_pipe_[0], buf, sizeof(buf));
                (void)consumed;
                continue;
            }
            auto& mask = aggregated[static_cast<int>(ev.ident)];
            if (ev.filter == EVFILT_READ) {
                mask |= kEventReadable;
            } else if (ev.filter == EVFILT_WRITE) {
                mask |= kEventWritable;
            }
            if (ev.flags & EV_EOF) {
                mask |= kEventError;
            }
        }
        for (const auto& entry : aggregated) {
            auto it = watchers_.find(entry.first);
            if (it == watchers_.end()) {
                continue;
            }
            if (entry.second == kEventNone) {
                continue;
            }
            it->second.callback(entry.first, entry.second);
        }
    }
#endif
}

void EventLoop::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    wake();
}

void EventLoop::wake() {
#ifdef __linux__
    if (wake_fd_ >= 0) {
        const std::uint64_t value = 1;
        const auto written = ::write(wake_fd_, &value, sizeof(value));
        (void)written;
    }
#elif defined(__APPLE__)
    if (wake_pipe_[1] >= 0) {
        const char byte = 1;
        const auto written = ::write(wake_pipe_[1], &byte, sizeof(byte));
        (void)written;
    }
#endif
}

std::uint32_t EventLoop::translate_events(std::uint32_t backend_mask) const {
    std::uint32_t mask = kEventNone;
#ifdef __linux__
    if (backend_mask & EPOLLIN) {
        mask |= kEventReadable;
    }
    if (backend_mask & EPOLLOUT) {
        mask |= kEventWritable;
    }
    if (backend_mask & (EPOLLERR | EPOLLHUP)) {
        mask |= kEventError;
    }
#else
    (void)backend_mask;
#endif
    return mask;
}

}  // namespace ephemeralnet::relay
