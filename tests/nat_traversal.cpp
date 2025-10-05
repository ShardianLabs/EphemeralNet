#include "ephemeralnet/network/NatTraversal.hpp"

#include "ephemeralnet/Config.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>

using ephemeralnet::Config;
using ephemeralnet::network::NatTraversalManager;
using ephemeralnet::network::NatTraversalResult;

int main() {
    NatTraversalManager::TestHooks hooks{};

    const auto stun_success = []() -> std::optional<NatTraversalManager::StunQueryResult> {
        NatTraversalManager::StunQueryResult result{};
        result.address = "45.64.61.85";
        result.reported_port = 46000;
        result.server = "test-stun";
        return result;
    };

    const auto stun_failure = []() -> std::optional<NatTraversalManager::StunQueryResult> {
        return std::nullopt;
    };

    {
        Config config{};
        config.identity_seed = 0x1234ABCDu;
        config.nat_stun_enabled = true;

        hooks.stun_override = stun_success;
        NatTraversalManager::set_test_hooks(&hooks);

        NatTraversalManager manager{config};
        const NatTraversalResult result = manager.coordinate("10.0.0.5", 45000);

        assert(result.stun_succeeded);
        assert(result.external_address == "45.64.61.85");
        assert(result.external_port == 46000);
        const auto success_message = std::find_if(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("STUN discovery succeeded") != std::string::npos;
        });
        assert(success_message != result.diagnostics.end());
        assert(std::none_of(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("Relay fallback required") != std::string::npos;
        }));
    }

    {
        Config config{};
        config.identity_seed = 0xCAFEBABEu;
        config.nat_stun_enabled = true;

        hooks.stun_override = stun_failure;
        NatTraversalManager::set_test_hooks(&hooks);

        NatTraversalManager manager{config};
        const NatTraversalResult result = manager.coordinate("172.16.0.20", 35000);

        assert(!result.stun_succeeded);
        assert(result.external_address == "172.16.0.20");
        assert(result.external_port == 35000);
        const auto failure_message = std::find_if(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("STUN discovery failed") != std::string::npos;
        });
        assert(failure_message != result.diagnostics.end());
        const auto relay_message = std::find_if(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("Relay fallback required") != std::string::npos;
        });
        assert(relay_message != result.diagnostics.end());
    }

    {
        Config config{};
        config.identity_seed = 0xF00DF00Du;
        config.nat_stun_enabled = false;

        NatTraversalManager::set_test_hooks(nullptr);

        NatTraversalManager manager{config};
        const NatTraversalResult result = manager.coordinate("192.168.50.10", 42000);

        assert(!result.stun_succeeded);
        assert(result.external_address == "192.168.50.10");
        assert(result.external_port == 42000);
        const auto skipped_message = std::find_if(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("STUN discovery skipped") != std::string::npos;
        });
        assert(skipped_message != result.diagnostics.end());
        const auto relay_message = std::find_if(result.diagnostics.begin(), result.diagnostics.end(), [](const std::string& message) {
            return message.find("Relay fallback required") != std::string::npos;
        });
        assert(relay_message != result.diagnostics.end());
    }

    NatTraversalManager::set_test_hooks(nullptr);
    return 0;
}

