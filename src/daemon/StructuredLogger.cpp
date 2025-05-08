#include "ephemeralnet/daemon/StructuredLogger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ephemeralnet::daemon {

namespace {

std::string escape_control_characters(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"':
                escaped.append("\\\"");
                break;
            case '\\':
                escaped.append("\\\\");
                break;
            case '\b':
                escaped.append("\\b");
                break;
            case '\f':
                escaped.append("\\f");
                break;
            case '\n':
                escaped.append("\\n");
                break;
            case '\r':
                escaped.append("\\r");
                break;
            case '\t':
                escaped.append("\\t");
                break;
            default:
                if (ch < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                        << static_cast<int>(ch);
                    escaped.append(oss.str());
                } else {
                    escaped.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    return escaped;
}

}  // namespace

StructuredLogger& StructuredLogger::instance() {
    static StructuredLogger logger;
    return logger;
}

void StructuredLogger::log(Level level, std::string_view event, FieldList fields) {
    std::scoped_lock lock(mutex_);
    if (!enabled_) {
        return;
    }

    const auto timestamp = format_timestamp();
    std::ostringstream oss;
    oss << '{'
        << "\"ts\":\"" << escape_json(timestamp) << "\",";
    oss << "\"level\":\"" << escape_json(level_to_string(level)) << "\",";
    oss << "\"event\":\"" << escape_json(event) << "\"";

    if (!fields.empty()) {
        oss << ",\"fields\":{";
        for (std::size_t i = 0; i < fields.size(); ++i) {
            const auto& [key, value] = fields[i];
            oss << "\"" << escape_json(key) << "\":\"" << escape_json(value) << "\"";
            if (i + 1 < fields.size()) {
                oss << ',';
            }
        }
        oss << '}';
    }

    oss << "}\n";
    std::clog << oss.str();
    std::clog.flush();
}

void StructuredLogger::set_enabled(bool enabled) {
    std::scoped_lock lock(mutex_);
    enabled_ = enabled;
}

bool StructuredLogger::enabled() const noexcept {
    std::scoped_lock lock(mutex_);
    return enabled_;
}

std::string StructuredLogger::level_to_string(Level level) {
    switch (level) {
        case Level::Info:
            return "info";
        case Level::Warning:
            return "warning";
        case Level::Error:
            return "error";
    }
    return "info";
}

std::string StructuredLogger::escape_json(std::string_view value) {
    return escape_control_characters(value);
}

std::string StructuredLogger::format_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto fractional = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
    const std::time_t now_c = std::chrono::system_clock::to_time_t(seconds);

    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &now_c);
#else
    gmtime_r(&now_c, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setw(3) << std::setfill('0') << fractional << 'Z';
    return oss.str();
}

}  // namespace ephemeralnet::daemon
