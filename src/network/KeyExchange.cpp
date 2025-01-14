#include "ephemeralnet/network/KeyExchange.hpp"

#include "ephemeralnet/crypto/Sha256.hpp"

#include <array>

namespace ephemeralnet::network {

std::uint32_t KeyExchange::modexp(std::uint64_t base, std::uint32_t exponent, std::uint32_t modulus) {
    std::uint64_t result = 1 % modulus;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1u) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1u;
    }
    return static_cast<std::uint32_t>(result % modulus);
}

std::uint32_t KeyExchange::compute_public(std::uint32_t private_key) {
    return modexp(kGenerator, private_key, kPrime);
}

KeyPair KeyExchange::make_keypair(std::uint32_t private_key) {
    return KeyPair{private_key, compute_public(private_key)};
}

bool KeyExchange::validate_public(std::uint32_t candidate) {
    return candidate > 1u && candidate < kPrime;
}

crypto::Key KeyExchange::derive_shared_secret(std::uint32_t private_key, std::uint32_t remote_public) {
    const auto valid_public = remote_public % kPrime;
    const auto shared_scalar = modexp(valid_public, private_key, kPrime);

    std::array<std::uint8_t, 4> material{};
    for (std::size_t i = 0; i < material.size(); ++i) {
        const auto shift = static_cast<std::uint32_t>((material.size() - 1 - i) * 8);
        material[i] = static_cast<std::uint8_t>((shared_scalar >> shift) & 0xFFu);
    }

    const auto digest = crypto::Sha256::digest(material);
    crypto::Key key{};
    key.bytes = digest;
    return key;
}

}  // namespace ephemeralnet::network
