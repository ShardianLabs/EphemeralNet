#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ephemeralnet::update {

struct DownloadInfo {
    std::string platform;
    std::string url;
    std::optional<std::string> sha256;
    std::string arch;
    std::string format;
};

struct Metadata {
    std::string version;       // e.g., 1.0.0
    std::string tag;           // e.g., v1.0.0
    std::string commit;        // git sha
    std::string channel;       // e.g., stable
    std::string generated_at;  // ISO-8601
    std::optional<std::string> notes_url;
    std::vector<DownloadInfo> downloads;

    const DownloadInfo* find_download(std::string_view platform) const;
};

struct SemVer {
    int major{0};
    int minor{0};
    int patch{0};
};

bool parse_update_metadata(std::string_view json, Metadata& output, std::string& error_message);
std::optional<SemVer> parse_semver(std::string_view text);
int compare_semver(const SemVer& lhs, const SemVer& rhs);

bool download_to_string(std::string_view url, std::string& output, std::string& error_message);

}  // namespace ephemeralnet::update
