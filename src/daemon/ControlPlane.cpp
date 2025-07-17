#include "ephemeralnet/daemon/ControlPlane.hpp"

#include <atomic>
#include <limits>

namespace {
std::atomic<std::size_t> g_control_stream_limit{ephemeralnet::daemon::kDefaultControlStreamBytes};
}

namespace ephemeralnet::daemon {

std::size_t max_control_stream_bytes() {
    return g_control_stream_limit.load(std::memory_order_relaxed);
}

void set_max_control_stream_bytes(std::size_t bytes) {
    const auto effective = bytes == 0 ? std::numeric_limits<std::size_t>::max() : bytes;
    g_control_stream_limit.store(effective, std::memory_order_relaxed);
}

}  // namespace ephemeralnet::daemon
