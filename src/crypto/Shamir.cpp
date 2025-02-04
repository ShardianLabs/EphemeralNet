#include "ephemeralnet/crypto/Shamir.hpp"

#include <algorithm>
#include <array>
#include <random>

namespace ephemeralnet::crypto {

namespace {
constexpr std::uint16_t kFieldPolynomial = 0x11Du;

std::array<std::uint8_t, 512> build_exp_table() {
    std::array<std::uint8_t, 512> exp{};
    std::uint16_t x = 1;
    for (std::size_t i = 0; i < 255; ++i) {
        exp[i] = static_cast<std::uint8_t>(x & 0xFFu);
        x <<= 1U;
        if (x & 0x100U) {
            x ^= kFieldPolynomial;
        }
    }
    for (std::size_t i = 255; i < exp.size(); ++i) {
        exp[i] = exp[i - 255];
    }
    return exp;
}

std::array<std::uint8_t, 256> build_log_table(const std::array<std::uint8_t, 512>& exp) {
    std::array<std::uint8_t, 256> log{};
    log[0] = 0;
    for (std::size_t i = 0; i < 255; ++i) {
        log[exp[i]] = static_cast<std::uint8_t>(i);
    }
    return log;
}

std::uint8_t gf_add(std::uint8_t a, std::uint8_t b) {
    return static_cast<std::uint8_t>(a ^ b);
}

std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b,
                    const std::array<std::uint8_t, 512>& exp,
                    const std::array<std::uint8_t, 256>& log) {
    if (a == 0 || b == 0) {
        return 0;
    }
    const auto sum = static_cast<std::uint16_t>(log[a]) + static_cast<std::uint16_t>(log[b]);
    return exp[sum % 255];
}

std::uint8_t gf_div(std::uint8_t a, std::uint8_t b,
                    const std::array<std::uint8_t, 512>& exp,
                    const std::array<std::uint8_t, 256>& log) {
    if (b == 0) {
        throw std::invalid_argument("division by zero in GF(256)");
    }
    if (a == 0) {
        return 0;
    }
    const auto diff = static_cast<std::int16_t>(log[a]) - static_cast<std::int16_t>(log[b]);
    auto index = diff % 255;
    if (index < 0) {
        index += 255;
    }
    return exp[index];
}

std::uint8_t evaluate_polynomial(std::uint8_t x,
                                  std::uint8_t constant,
                                  const std::vector<std::uint8_t>& coefficients,
                                  const std::array<std::uint8_t, 512>& exp,
                                  const std::array<std::uint8_t, 256>& log) {
    std::uint8_t result = constant;
    std::uint8_t power = 1;
    for (const auto coeff : coefficients) {
        power = gf_mul(power, x, exp, log);
        result = gf_add(result, gf_mul(coeff, power, exp, log));
    }
    return result;
}

std::array<std::uint8_t, 32> interpolate(const std::vector<ShamirShare>& shares,
                                         const std::array<std::uint8_t, 512>& exp,
                                         const std::array<std::uint8_t, 256>& log) {
    std::array<std::uint8_t, 32> secret{};

    for (std::size_t byte = 0; byte < secret.size(); ++byte) {
        std::uint8_t value = 0;
        for (std::size_t i = 0; i < shares.size(); ++i) {
            if (shares[i].value[byte] == 0) {
                continue;
            }
            std::uint8_t numerator = 1;
            std::uint8_t denominator = 1;
            for (std::size_t j = 0; j < shares.size(); ++j) {
                if (i == j) {
                    continue;
                }
                numerator = gf_mul(numerator, shares[j].index, exp, log);
                const auto diff = gf_add(shares[j].index, shares[i].index);
                denominator = gf_mul(denominator, diff, exp, log);
            }
            const auto factor = gf_div(numerator, denominator, exp, log);
            value = gf_add(value, gf_mul(shares[i].value[byte], factor, exp, log));
        }
        secret[byte] = value;
    }

    return secret;
}

}  // namespace

std::vector<ShamirShare> Shamir::split(const std::array<std::uint8_t, 32>& secret,
                                       std::uint8_t threshold,
                                       std::uint8_t share_count) {
    if (threshold == 0 || share_count == 0) {
        throw std::invalid_argument("threshold and share_count must be positive");
    }
    if (threshold > share_count) {
        throw std::invalid_argument("threshold cannot exceed share count");
    }

    static const auto exp_table = build_exp_table();
    static const auto log_table = build_log_table(exp_table);

    std::random_device rd;
    std::vector<ShamirShare> shares;
    shares.reserve(share_count);

    for (std::uint8_t share_index = 1; share_index <= share_count; ++share_index) {
        ShamirShare share{};
        share.index = share_index;
        shares.push_back(share);
    }

    for (std::size_t byte = 0; byte < secret.size(); ++byte) {
        std::vector<std::uint8_t> coefficients;
        coefficients.reserve(threshold - 1);
        for (std::uint8_t degree = 1; degree < threshold; ++degree) {
            coefficients.push_back(static_cast<std::uint8_t>(rd()));
        }

        for (auto& share : shares) {
            share.value[byte] = evaluate_polynomial(share.index, secret[byte], coefficients, exp_table, log_table);
        }
    }

    return shares;
}

std::array<std::uint8_t, 32> Shamir::combine(const std::vector<ShamirShare>& shares,
                                             std::uint8_t threshold) {
    if (shares.size() < threshold) {
        throw std::invalid_argument("insufficient shares to reconstruct secret");
    }

    static const auto exp_table = build_exp_table();
    static const auto log_table = build_log_table(exp_table);

    std::vector<ShamirShare> subset(shares.begin(), shares.begin() + threshold);
    return interpolate(subset, exp_table, log_table);
}

}  // namespace ephemeralnet::crypto
