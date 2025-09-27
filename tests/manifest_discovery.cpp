#include "ephemeralnet/core/Node.hpp"

#include <cassert>
#include <chrono>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = seed++;
    }
    return id;
}

ephemeralnet::ChunkData make_payload(std::uint8_t seed) {
    ephemeralnet::ChunkData data(32);
    for (auto& byte : data) {
        byte = seed++;
    }
    return data;
}

}  // namespace

int main() {
    // Advertised host+port should be preferred over bind host (even if bound to 0.0.0.0)
    ephemeralnet::Config advertise_config{};
    advertise_config.control_host = "0.0.0.0";
    advertise_config.control_port = 47777;
    advertise_config.advertise_control_host = "relay.example";
    advertise_config.advertise_control_port = 61000;

    ephemeralnet::Node advertise_node(make_peer_id(0x10), advertise_config);
    auto manifest = advertise_node.store_chunk(make_peer_id(0x20), make_payload(0x30), 120s);

    assert(!manifest.discovery_hints.empty());
    assert(manifest.discovery_hints.front().scheme == "control");
    assert(manifest.discovery_hints.front().transport == "control");
    assert(manifest.discovery_hints.front().endpoint == "relay.example:61000");
    assert(manifest.discovery_hints.front().priority == 0);
    assert(!manifest.fallback_hints.empty());
    assert(manifest.fallback_hints.front().uri == "control://relay.example:61000");

    // When only the host is advertised, the control port should be reused.
    ephemeralnet::Config default_port_config{};
    default_port_config.control_host = "0.0.0.0";
    default_port_config.control_port = 52000;
    default_port_config.advertise_control_host = "public.example";

    ephemeralnet::Node default_port_node(make_peer_id(0x40), default_port_config);
    auto default_port_manifest = default_port_node.store_chunk(make_peer_id(0x50), make_payload(0x60), 60s);

    assert(!default_port_manifest.discovery_hints.empty());
    assert(default_port_manifest.discovery_hints.front().scheme == "control");
    assert(default_port_manifest.discovery_hints.front().transport == "control");
    assert(default_port_manifest.discovery_hints.front().endpoint == "public.example:52000");

    // When no advertised host is configured, the bound control host should be used if routable.
    ephemeralnet::Config fallback_config{};
    fallback_config.control_host = "198.51.100.5";
    fallback_config.control_port = 48080;

    ephemeralnet::Node fallback_node(make_peer_id(0x70), fallback_config);
    auto fallback_manifest = fallback_node.store_chunk(make_peer_id(0x80), make_payload(0x90), 90s);

    assert(!fallback_manifest.discovery_hints.empty());
    assert(fallback_manifest.discovery_hints.front().scheme == "control");
    assert(fallback_manifest.discovery_hints.front().transport == "control");
    assert(fallback_manifest.discovery_hints.front().endpoint == "198.51.100.5:48080");

    // Explicit advertised endpoint list should preserve insertion order.
    ephemeralnet::Config multi_endpoint_config{};
    multi_endpoint_config.control_host = "0.0.0.0";
    multi_endpoint_config.control_port = 50500;
    {
        ephemeralnet::Config::AdvertisedEndpoint manual_endpoint;
        manual_endpoint.host = "manual.example";
        manual_endpoint.port = 60500;
        manual_endpoint.manual = true;
        manual_endpoint.source = "manual";
        multi_endpoint_config.advertised_endpoints.push_back(manual_endpoint);
    }
    {
        ephemeralnet::Config::AdvertisedEndpoint auto_endpoint;
        auto_endpoint.host = "auto.example";
        auto_endpoint.port = 61500;
        auto_endpoint.manual = false;
        auto_endpoint.source = "stun";
        multi_endpoint_config.advertised_endpoints.push_back(auto_endpoint);
    }

    ephemeralnet::Node multi_endpoint_node(make_peer_id(0x90), multi_endpoint_config);
    auto multi_manifest = multi_endpoint_node.store_chunk(make_peer_id(0xA0), make_payload(0xB0), 45s);

    assert(multi_manifest.discovery_hints.size() >= 2);
    assert(multi_manifest.discovery_hints[0].scheme == "control");
    assert(multi_manifest.discovery_hints[0].transport == "control");
    assert(multi_manifest.discovery_hints[0].endpoint == "manual.example:60500");
    assert(multi_manifest.discovery_hints[0].priority == 0);
    assert(multi_manifest.discovery_hints[1].scheme == "transport");
    assert(multi_manifest.discovery_hints[1].transport == "tcp");
    assert(multi_manifest.discovery_hints[1].endpoint == "auto.example:61500");
    assert(multi_manifest.discovery_hints[1].priority == 1);

    return 0;
}
