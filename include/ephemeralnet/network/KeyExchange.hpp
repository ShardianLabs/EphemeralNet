#pragma once

#include "ephemeralnet/crypto/ChaCha20.hpp"

#include <cstdint>

namespace ephemeralnet::network {

struct KeyPair {
    std::uint32_t private_key{0};
    std::uint32_t public_key{0};
};

class KeyExchange {
public:
    static constexpr std::uint32_t kPrime = 2147483647u;  // 2^31 - 1
    static constexpr std::uint32_t kGenerator = 5u;

    static std::uint32_t compute_public(std::uint32_t private_key);
    static KeyPair make_keypair(std::uint32_t private_key);
    static bool validate_public(std::uint32_t candidate);
    static crypto::Key derive_shared_secret(std::uint32_t private_key, std::uint32_t remote_public);

private:
    static std::uint32_t modexp(std::uint64_t base, std::uint32_t exponent, std::uint32_t modulus);
};

}  // namespace ephemeralnet::network
