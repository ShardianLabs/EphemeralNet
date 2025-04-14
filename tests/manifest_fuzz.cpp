#include "ephemeralnet/protocol/Manifest.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace proto = ephemeralnet::protocol;

proto::Manifest make_seed_manifest() {
    proto::Manifest manifest{};
    manifest.chunk_id.fill(0xABu);
    manifest.chunk_hash.fill(0x42u);
    manifest.nonce.bytes.fill(0x11u);
    manifest.threshold = 3;
    manifest.total_shares = 5;
    manifest.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);

    proto::KeyShard shard{};
    shard.index = 1;
    shard.value.fill(0x24u);
    manifest.shards.push_back(shard);

    shard.index = 2;
    shard.value.fill(0x35u);
    manifest.shards.push_back(shard);

    return manifest;
}

std::string make_random_string(std::mt19937& rng, std::size_t max_size) {
    std::uniform_int_distribution<std::size_t> size_dist(0, max_size);
    const auto size = size_dist(rng);
    std::string text(size, '\0');
    for (auto& ch : text) {
        ch = static_cast<char>(rng() & 0xFFu);
    }
    return text;
}

void mutate_manifest(std::string& uri, std::mt19937& rng) {
    if (uri.size() <= 6) {
        return;
    }

    std::uniform_int_distribution<std::size_t> mutation_count_dist(1, 4);
    const auto mutation_count = mutation_count_dist(rng);
    for (std::size_t i = 0; i < mutation_count; ++i) {
        const auto index = 6 + static_cast<std::size_t>(rng() % (uri.size() - 6));
        const auto mask = static_cast<char>((rng() >> (i % 8)) & 0xFFu);
        uri[index] ^= mask;
    }
}

}  // namespace

int main() {
    auto manifest = make_seed_manifest();
    const auto encoded = proto::encode_manifest(manifest);

    // Sanity check that decoding succeeds for the seed manifest.
    try {
    const auto decoded = proto::decode_manifest(encoded);
        if (decoded.shards.size() != manifest.shards.size()) {
            return EXIT_FAILURE;
        }
    } catch (...) {
        return EXIT_FAILURE;
    }

    std::mt19937 rng{0xA5A5A5u};
    constexpr std::size_t kIterations = 1500;

    for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
        std::string candidate;
        if (iteration % 3 == 0) {
            candidate = encoded;
            mutate_manifest(candidate, rng);
        } else {
            candidate = make_random_string(rng, 512);
            if (candidate.size() >= 6) {
                candidate[0] = 'e';
                candidate[1] = 'p';
                candidate[2] = 'h';
                candidate[3] = ':';
                candidate[4] = '/';
                candidate[5] = '/';
            }
        }

        try {
            static_cast<void>(proto::decode_manifest(candidate));
        } catch (const std::invalid_argument&) {
            // Expected for malformed inputs.
        } catch (...) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
