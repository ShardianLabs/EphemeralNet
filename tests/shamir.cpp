#include "ephemeralnet/crypto/Shamir.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

using ephemeralnet::crypto::Shamir;
using ephemeralnet::crypto::ShamirShare;

namespace {

std::array<std::uint8_t, 32> make_secret(std::uint8_t seed) {
    std::array<std::uint8_t, 32> secret{};
    for (auto& byte : secret) {
        byte = seed++;
    }
    return secret;
}

}  // namespace

int main() {
    const auto secret = make_secret(0x10);
    const auto shares = Shamir::split(secret, 5, 8);
    assert(shares.size() == 8);

    std::vector<ShamirShare> subset{shares.begin(), shares.begin() + 5};
    const auto reconstructed = Shamir::combine(subset, 5);
    assert(reconstructed == secret);

    // Try a different subset order
    std::vector<ShamirShare> mixed{subset.rbegin(), subset.rend()};
    const auto reconstructed2 = Shamir::combine(mixed, 5);
    assert(reconstructed2 == secret);

    return 0;
}
