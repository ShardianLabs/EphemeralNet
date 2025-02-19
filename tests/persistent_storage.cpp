#include "ephemeralnet/storage/ChunkStore.hpp"
#include "ephemeralnet/Types.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <thread>
#include <vector>

int main() {
    ephemeralnet::Config config{};
    config.storage_persistent_enabled = true;
    config.storage_directory = "test_persistent_store";
    config.storage_wipe_on_expiry = true;
    config.storage_wipe_passes = 1;
    config.default_chunk_ttl = std::chrono::seconds(1);

    ephemeralnet::ChunkStore store(config);

    ephemeralnet::ChunkId chunk_id{};
    chunk_id.fill(0x5Au);

    std::vector<std::uint8_t> payload(1024, 0xABu);
    store.put(chunk_id, payload, std::chrono::seconds(1));

    const auto key = ephemeralnet::chunk_id_to_string(chunk_id);
    const auto path = std::filesystem::path(config.storage_directory) / (key + ".chunk");
    assert(std::filesystem::exists(path));

    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    auto removed = store.sweep_expired();
    assert(!removed.empty());
    assert(!std::filesystem::exists(path));

    std::filesystem::remove_all(config.storage_directory);

    return 0;
}
