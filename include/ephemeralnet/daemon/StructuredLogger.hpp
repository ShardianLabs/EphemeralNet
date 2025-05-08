#pragma once

#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ephemeralnet::daemon {

class StructuredLogger {
public:
    enum class Level {
        Info,
        Warning,
        Error
    };

    using Field = std::pair<std::string, std::string>;
    using FieldList = std::vector<Field>;

    static StructuredLogger& instance();

    void log(Level level, std::string_view event, FieldList fields = {});

    void set_enabled(bool enabled);
    [[nodiscard]] bool enabled() const noexcept;

private:
    StructuredLogger() = default;

    StructuredLogger(const StructuredLogger&) = delete;
    StructuredLogger& operator=(const StructuredLogger&) = delete;

    static std::string level_to_string(Level level);
    static std::string escape_json(std::string_view value);

    std::string format_timestamp();

    bool enabled_{true};
    mutable std::mutex mutex_;
};

}  // namespace ephemeralnet::daemon
