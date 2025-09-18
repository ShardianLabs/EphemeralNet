#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

ephemeralnet::PeerId make_peer_id(std::uint8_t seed) {
	ephemeralnet::PeerId id{};
	for (auto& byte : id) {
		byte = seed++;
	}
	return id;
}

ephemeralnet::ChunkId make_chunk_id(std::uint8_t seed) {
	ephemeralnet::ChunkId id{};
	for (auto& byte : id) {
		byte = seed++;
	}
	return id;
}

void ensure_peer_delivery(ephemeralnet::Node& seeder,
						  const ephemeralnet::ChunkId& chunk_id,
						  const std::string& peer_key,
						  const std::vector<std::string>& expected_endpoints,
						  ephemeralnet::Node& leecher) {
	const auto deadline = std::chrono::steady_clock::now() + 5s;
	while (std::chrono::steady_clock::now() < deadline) {
		if (const auto plan = ephemeralnet::test::NodeTestAccess::swarm_plan(seeder, chunk_id)) {
			const auto delivered_it = plan->delivered_endpoints.find(peer_key);
			if (delivered_it != plan->delivered_endpoints.end()) {
				const auto& recorded = delivered_it->second;
				bool all_present = true;
				for (const auto& endpoint : expected_endpoints) {
					if (std::find(recorded.begin(), recorded.end(), endpoint) == recorded.end()) {
						all_present = false;
						break;
					}
				}
				if (all_present) {
					return;
				}
			}
		}

		ephemeralnet::test::NodeTestAccess::rebroadcast_manifest(seeder, chunk_id);
		seeder.tick();
		leecher.tick();
		std::this_thread::sleep_for(50ms);
	}
}

}  // namespace

int main() {
	const auto seeder_id = make_peer_id(0x90);
	const auto leecher_id = make_peer_id(0xA0);
	const auto chunk_id = make_chunk_id(0x55);

	ephemeralnet::Config seeder_config{};
	seeder_config.identity_seed = 0x21u;
	ephemeralnet::Config::AdvertisedEndpoint manual_endpoint{};
	manual_endpoint.host = "control-a.ephemeral";
	manual_endpoint.port = 45555;
	manual_endpoint.manual = true;
	manual_endpoint.source = "manual";
	seeder_config.advertised_endpoints.push_back(manual_endpoint);
	ephemeralnet::Config::AdvertisedEndpoint auto_endpoint{};
	auto_endpoint.host = "control-b.ephemeral";
	auto_endpoint.port = 46666;
	auto_endpoint.manual = false;
	auto_endpoint.source = "auto";
	seeder_config.advertised_endpoints.push_back(auto_endpoint);

	ephemeralnet::Config leecher_config{};
	leecher_config.identity_seed = 0x34u;

	ephemeralnet::Node seeder(seeder_id, seeder_config);
	ephemeralnet::Node leecher(leecher_id, leecher_config);

	seeder.start_transport(0);
	leecher.start_transport(0);

	const auto pow_leecher = ephemeralnet::test::NodeTestAccess::handshake_work(leecher, seeder_id);
	const auto pow_seeder = ephemeralnet::test::NodeTestAccess::handshake_work(seeder, leecher_id);
	assert(pow_leecher.has_value());
	assert(pow_seeder.has_value());
	const bool handshake_ab = seeder.perform_handshake(leecher_id, leecher.public_identity(), *pow_leecher);
	const bool handshake_ba = leecher.perform_handshake(seeder_id, seeder.public_identity(), *pow_seeder);
	assert(handshake_ab);
	assert(handshake_ba);

	ephemeralnet::PeerContact contact{};
	contact.id = leecher_id;
	contact.address = "127.0.0.1:" + std::to_string(leecher.transport_port());
	contact.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(10);
	seeder.register_peer_contact(contact);

	ephemeralnet::ChunkData payload(64, 0x5Au);
	seeder.store_chunk(chunk_id, payload, 600s);

	const auto peer_key = ephemeralnet::peer_id_to_string(leecher_id);
	const std::vector<std::string> expected_endpoints{
		"control-a.ephemeral:45555",
		"control-b.ephemeral:46666"
	};

	ensure_peer_delivery(seeder, chunk_id, peer_key, expected_endpoints, leecher);

	const auto plan = ephemeralnet::test::NodeTestAccess::swarm_plan(seeder, chunk_id);
	assert(plan.has_value());
	const auto delivered_it = plan->delivered_endpoints.find(peer_key);
	assert(delivered_it != plan->delivered_endpoints.end());
	for (const auto& endpoint : expected_endpoints) {
		assert(std::find(delivered_it->second.begin(), delivered_it->second.end(), endpoint) != delivered_it->second.end());
	}
	assert(plan->delivered_peers.contains(peer_key));

	seeder.stop_transport();
	leecher.stop_transport();

	return 0;
}
