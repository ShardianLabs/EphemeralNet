#include "ephemeralnet/core/UpdateCheck.hpp"

#include <cassert>
#include <string>

int main() {
    const std::string sample = R"JSON({
  "version": "1.2.3",
  "tag": "v1.2.3",
  "commit": "abc123",
  "channel": "stable",
  "generated_at": "2025-11-24T00:00:00Z",
  "notes_url": "https://example.com/release",
  "downloads": {
    "linux": {
      "url": "https://example.com/linux",
      "arch": "x64",
      "format": "tar.gz",
      "sha256": "deadbeef"
    }
  }
})JSON";

    ephemeralnet::update::Metadata metadata;
    std::string error;
    assert(ephemeralnet::update::parse_update_metadata(sample, metadata, error));
    assert(metadata.version == "1.2.3");
    assert(metadata.tag == "v1.2.3");
    assert(metadata.downloads.size() == 1);
    const auto* linux_download = metadata.find_download("linux");
    assert(linux_download);
    assert(linux_download->url == "https://example.com/linux");

    const auto current = ephemeralnet::update::parse_semver("v1.2.3");
    const auto latest = ephemeralnet::update::parse_semver("1.3.0");
    assert(current && latest);
    assert(ephemeralnet::update::compare_semver(*current, *latest) < 0);

    const auto parsed = ephemeralnet::update::parse_semver("1.2");
    assert(parsed);
    assert(parsed->major == 1 && parsed->minor == 2 && parsed->patch == 0);

    return 0;
}
