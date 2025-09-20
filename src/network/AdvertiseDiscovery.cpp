#include "ephemeralnet/network/AdvertiseDiscovery.hpp"

#include "ephemeralnet/network/NatTraversal.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ephemeralnet::network {
namespace {

std::string fallback_echo_address(const Config& config) {
    const auto seed = static_cast<std::mt19937::result_type>(config.identity_seed.value_or(0u) ^ 0xA5A5A5A5u);
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> octet(20, 220);
    return "198.51.100." + std::to_string(octet(rng));
}

bool is_valid_host(const std::string& host) {
    return !host.empty() && host != "0.0.0.0";
}

bool parse_ipv4(const std::string& host, std::array<std::uint8_t, 4>& octets) {
    std::size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        if (start >= host.size()) {
            return false;
        }
        const std::size_t end = (i == 3) ? host.size() : host.find('.', start);
        if (end == std::string::npos) {
            return false;
        }
        if (end == start) {
            return false;
        }
        std::uint32_t value = 0;
        for (std::size_t pos = start; pos < end; ++pos) {
            unsigned char ch = static_cast<unsigned char>(host[pos]);
            if (!std::isdigit(ch)) {
                return false;
            }
            value = value * 10 + static_cast<std::uint32_t>(ch - '0');
            if (value > 255) {
                return false;
            }
        }
        octets[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value);
        start = end + 1;
    }
    return start == host.size() + 1;
}

bool is_private_or_reserved_ipv4(const std::array<std::uint8_t, 4>& ip) {
    if (ip[0] == 10) return true;
    if (ip[0] == 127) return true;
    if (ip[0] == 0) return true;
    if (ip[0] == 169 && ip[1] == 254) return true;
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return true;
    if (ip[0] == 192 && ip[1] == 168) return true;
    if (ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) return true;  // RFC6598 CGNAT
    if (ip[0] == 192 && ip[1] == 0 && ip[2] == 2) return true;     // TEST-NET-1
    if (ip[0] == 198 && ip[1] == 51 && ip[2] == 100) return true;  // TEST-NET-2
    if (ip[0] == 203 && ip[1] == 0 && ip[2] == 113) return true;   // TEST-NET-3
    if (ip[0] == 198 && ip[1] == 18) return true;                  // Benchmarking
    if (ip[0] >= 224) return true;                                 // Multicast/reserved
    return false;
}

std::string normalize_ipv6(std::string host) {
    if (!host.empty() && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    const auto percent = host.find('%');
    if (percent != std::string::npos) {
        host = host.substr(0, percent);
    }
    std::string lowered;
    lowered.reserve(host.size());
    for (char ch : host) {
        lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return lowered;
}

bool is_private_or_reserved_ipv6(const std::string& host) {
    const auto normalized = normalize_ipv6(host);
    if (normalized.empty()) {
        return true;
    }
    if (normalized == "::" || normalized == "::1") {
        return true;
    }
    if (normalized.rfind("fc", 0) == 0 || normalized.rfind("fd", 0) == 0) {
        return true;  // Unique local addresses
    }
    if (normalized.rfind("fe8", 0) == 0 || normalized.rfind("fe9", 0) == 0 ||
        normalized.rfind("fea", 0) == 0 || normalized.rfind("feb", 0) == 0) {
        return true;  // Link-local
    }
    if (normalized.rfind("2001:db8", 0) == 0) {
        return true;  // Documentation
    }
    if (normalized.rfind("ff", 0) == 0) {
        return true;  // Multicast
    }
    return false;
}

bool is_private_or_reserved_host(const std::string& host) {
    if (host.empty()) {
        return true;
    }
    std::array<std::uint8_t, 4> ipv4{};
    if (parse_ipv4(host, ipv4)) {
        return is_private_or_reserved_ipv4(ipv4);
    }
    std::string lowered;
    lowered.reserve(host.size());
    for (char ch : host) {
        lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    if (lowered == "localhost") {
        return true;
    }
    if (lowered == "0.0.0.0") {
        return true;
    }
    if (host.find(':') != std::string::npos || lowered.find(':') != std::string::npos) {
        return is_private_or_reserved_ipv6(host);
    }
    return false;
}

}  // namespace

AdvertiseDiscoveryResult discover_control_advertise_candidates(const Config& config) {
    AdvertiseDiscoveryResult result;
    const std::string local_address = config.control_host.empty() ? std::string{"0.0.0.0"} : config.control_host;

    NatTraversalManager nat_manager{config};
    const auto traversal = nat_manager.coordinate(local_address, config.control_port);
    const std::uint16_t discovered_port = traversal.external_port != 0 ? traversal.external_port : config.control_port;

    std::unordered_set<std::string> seen;
    const bool allow_private = config.advertise_allow_private;
    auto append_candidate = [&](const std::string& host, std::uint16_t port, const std::string& method) {
        if (!is_valid_host(host) || port == 0) {
            return;
        }
        if (!allow_private && is_private_or_reserved_host(host)) {
            return;
        }
        const std::string key = method + "|" + host + ':' + std::to_string(port);
        if (!seen.insert(key).second) {
            return;
        }
        Config::AdvertiseCandidate candidate{};
        candidate.host = host;
        candidate.port = port;
        candidate.via = method;
        candidate.diagnostics = traversal.diagnostics;
        candidate.diagnostics.push_back("Auto-advertise candidate discovered via " + method);
        result.candidates.push_back(std::move(candidate));
    };

    if (traversal.upnp_available && is_valid_host(traversal.external_address)) {
        append_candidate(traversal.external_address, discovered_port, "upnp");
    }

    if (traversal.stun_succeeded && is_valid_host(traversal.external_address)) {
        append_candidate(traversal.external_address, discovered_port, "stun");
    } else {
        auto echo_address = traversal.external_address;
        if (!is_valid_host(echo_address)) {
            echo_address = fallback_echo_address(config);
        }
        append_candidate(echo_address, discovered_port, "https-echo");
    }

    if (allow_private && is_valid_host(local_address)) {
        append_candidate(local_address, config.control_port, "local-fallback");
    } else if (result.candidates.empty() && is_valid_host(local_address)) {
        append_candidate(local_address, config.control_port, "local-fallback");
    }

    std::unordered_map<std::string, std::vector<std::string>> endpoint_methods;
    for (const auto& candidate : result.candidates) {
        const std::string endpoint = candidate.host + ':' + std::to_string(candidate.port);
        endpoint_methods[endpoint].push_back(candidate.via);
    }
    if (endpoint_methods.size() > 1) {
        result.conflict = true;
        std::vector<std::string> formatted;
        formatted.reserve(endpoint_methods.size());
        for (const auto& [endpoint, methods] : endpoint_methods) {
            std::string entry = endpoint + " [";
            for (std::size_t i = 0; i < methods.size(); ++i) {
                entry += methods[i];
                if (i + 1 < methods.size()) {
                    entry += ',';
                }
            }
            entry += ']';
            formatted.push_back(entry);
        }
        std::string warning = "Auto-advertise detected multiple candidate endpoints: ";
        for (std::size_t i = 0; i < formatted.size(); ++i) {
            warning += formatted[i];
            if (i + 1 < formatted.size()) {
                warning += ", ";
            }
        }
        warning += ". Pin a host with --advertise-control to avoid inconsistent manifests.";
        result.warnings.push_back(std::move(warning));
    }

    return result;
}

std::optional<Config::AdvertiseCandidate> select_public_advertise_candidate(const AdvertiseDiscoveryResult& result) {
    constexpr std::array<std::string_view, 2> kPreferredMethods{"upnp", "stun"};
    for (const auto& method : kPreferredMethods) {
        const auto it = std::find_if(result.candidates.begin(), result.candidates.end(), [&](const Config::AdvertiseCandidate& candidate) {
            return candidate.via == method;
        });
        if (it != result.candidates.end()) {
            return *it;
        }
    }
    return std::nullopt;
}

}  // namespace ephemeralnet::network
