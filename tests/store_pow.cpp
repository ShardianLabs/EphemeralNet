#include "ephemeralnet/security/StoreProof.hpp"

#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

int main() {
    const std::string filename = "C:/temp/payload.bin";
    const std::vector<std::uint8_t> payload{'e', 'p', 'h', 'e', 'm'};
    const auto chunk_id = ephemeralnet::security::derive_chunk_id(std::span<const std::uint8_t>(payload.data(), payload.size()));
    const auto hint = ephemeralnet::security::sanitize_filename_hint(filename);
    if (!hint.has_value() || *hint != "payload.bin") {
        std::cerr << "Filename hint sanitization failed" << std::endl;
        return 1;
    }

    const ephemeralnet::security::StoreWorkInput input{
        chunk_id,
        static_cast<std::uint64_t>(payload.size()),
        std::string_view(*hint)
    };

    const auto zero_pow = ephemeralnet::security::compute_store_pow(input, 0);
    if (!zero_pow.has_value() || *zero_pow != 0) {
        std::cerr << "Expected deterministic nonce for zero difficulty" << std::endl;
        return 1;
    }

    const auto nonce = ephemeralnet::security::compute_store_pow(input, 6);
    if (!nonce.has_value()) {
        std::cerr << "Failed to find proof-of-work with difficulty 6" << std::endl;
        return 1;
    }
    if (!ephemeralnet::security::store_pow_valid(input, *nonce, 6)) {
        std::cerr << "Generated nonce does not satisfy difficulty" << std::endl;
        return 1;
    }

    if (ephemeralnet::security::store_pow_valid(input, *nonce + 1, 6)) {
        std::cerr << "Adjacent nonce unexpectedly valid" << std::endl;
        return 1;
    }

    return 0;
}
