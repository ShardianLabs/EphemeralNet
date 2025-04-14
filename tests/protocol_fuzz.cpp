#include "ephemeralnet/protocol/Message.hpp"
#include "ephemeralnet/crypto/HmacSha256.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <span>
#include <vector>

namespace {

namespace proto = ephemeralnet::protocol;

std::vector<std::uint8_t> make_random_buffer(std::mt19937& rng, std::size_t max_size) {
    std::uniform_int_distribution<std::size_t> size_dist(0, max_size);
    const auto size = size_dist(rng);
    std::vector<std::uint8_t> data(size);
    for (auto& byte : data) {
        byte = static_cast<std::uint8_t>(rng() & 0xFFu);
    }
    return data;
}

std::array<std::uint8_t, 32> make_random_key(std::mt19937& rng) {
    std::array<std::uint8_t, 32> key{};
    for (auto& byte : key) {
        byte = static_cast<std::uint8_t>(rng() & 0xFFu);
    }
    return key;
}

proto::Message make_seed_message(std::mt19937& rng) {
    proto::Message message{};
    message.version = proto::kCurrentMessageVersion;
    message.type = proto::MessageType::Request;

    proto::RequestPayload payload{};
    for (std::size_t index = 0; index < payload.chunk_id.size(); ++index) {
        payload.chunk_id[index] = static_cast<std::uint8_t>((rng() >> (index % 8)) & 0xFFu);
    }
    for (std::size_t index = 0; index < payload.requester.size(); ++index) {
        payload.requester[index] = static_cast<std::uint8_t>((rng() >> ((index + 3) % 8)) & 0xFFu);
    }

    message.payload = payload;
    return message;
}

void mutate_buffer(std::vector<std::uint8_t>& buffer, std::mt19937& rng) {
    if (buffer.empty()) {
        return;
    }
    std::uniform_int_distribution<std::size_t> mutation_count_dist(1, 3);
    const auto mutation_count = mutation_count_dist(rng);
    for (std::size_t i = 0; i < mutation_count; ++i) {
        const auto index = static_cast<std::size_t>(rng() % buffer.size());
        const auto mask = static_cast<std::uint8_t>((rng() >> (i % 8)) & 0xFFu);
        buffer[index] ^= mask;
    }
}

}  // namespace

int main() {
    std::mt19937 rng{0xC0FFEEu};

    constexpr std::size_t kIterations = 2000;

    for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
        auto buffer = make_random_buffer(rng, 512);
        std::span<const std::uint8_t> random_view(buffer.data(), buffer.size());

        try {
            static_cast<void>(proto::decode(random_view));
        } catch (...) {
            return EXIT_FAILURE;
        }

        const auto key = make_random_key(rng);
        const std::span<const std::uint8_t> key_span(key.data(), key.size());

        try {
            static_cast<void>(proto::decode_signed(random_view, key_span));
        } catch (...) {
            return EXIT_FAILURE;
        }

        if (iteration % 5 == 0) {
            auto message = make_seed_message(rng);
            auto encoded = proto::encode(message);
            mutate_buffer(encoded, rng);

            try {
                static_cast<void>(proto::decode(std::span<const std::uint8_t>(encoded.data(), encoded.size())));
            } catch (...) {
                return EXIT_FAILURE;
            }
        }

        if (iteration % 11 == 0) {
            auto message = make_seed_message(rng);
            auto encoded = proto::encode(message);
            const auto key_for_signed = make_random_key(rng);
            const std::span<const std::uint8_t> signed_key_span(key_for_signed.data(), key_for_signed.size());
            auto signed_payload = proto::encode_signed(message, signed_key_span);
            mutate_buffer(signed_payload, rng);

            try {
                static_cast<void>(proto::decode_signed(std::span<const std::uint8_t>(signed_payload.data(), signed_payload.size()), signed_key_span));
            } catch (...) {
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
}
