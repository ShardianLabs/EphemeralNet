#pragma once

#include <chrono>

namespace ephemeralnet {

struct Config {
    std::chrono::seconds default_chunk_ttl{std::chrono::hours(24)};
    std::chrono::seconds announce_interval{std::chrono::minutes(15)};
    std::chrono::seconds cleanup_interval{std::chrono::minutes(5)};
};

}  
