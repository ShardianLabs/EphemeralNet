#include "ephemeralnet/core/Node.hpp"

#include <cassert>
#include <chrono>

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

}  // namespace

int main() {
    const auto bootstrap_id = make_peer_id(0xA0);
    const auto client_id = make_peer_id(0x10);

    ephemeralnet::Config bootstrap_config{};
    bootstrap_config.identity_seed = 0x55;
    ephemeralnet::Node bootstrap{bootstrap_id, bootstrap_config};

    ephemeralnet::Config client_config{};
    client_config.bootstrap_contact_ttl = std::chrono::minutes(30);
    ephemeralnet::Config::BootstrapNode node_entry{};
    node_entry.id = bootstrap_id;
    node_entry.host = "bootstrap.local";
    node_entry.port = 4040;
    node_entry.public_identity = bootstrap.public_identity();
    client_config.bootstrap_nodes.push_back(node_entry);

    ephemeralnet::Node client{client_id, client_config};

    const auto key = client.session_key(bootstrap_id);
    assert(key.has_value());

    return 0;
}
