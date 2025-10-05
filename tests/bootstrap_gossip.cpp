#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/dht/KademliaTable.hpp"
#include "ephemeralnet/network/NatTraversal.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <optional>
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
	ephemeralnet::network::NatTraversalManager::TestHooks hooks{};
	hooks.stun_override = []() -> std::optional<ephemeralnet::network::NatTraversalManager::StunQueryResult> {
		ephemeralnet::network::NatTraversalManager::StunQueryResult result{};
		result.address = "45.64.61.85";
		result.reported_port = 45000;
		result.server = "test-stun";
		return result;
	};
	ephemeralnet::network::NatTraversalManager::set_test_hooks(&hooks);

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

	ephemeralnet::Config leecher_config{};
	leecher_config.identity_seed = 0x34u;

	ephemeralnet::Node seeder(seeder_id, seeder_config);
	ephemeralnet::Node leecher(leecher_id, leecher_config);

	seeder.start_transport(0);
	leecher.start_transport(0);

	const auto aggregated_endpoints = ephemeralnet::test::NodeTestAccess::advertised_endpoints(seeder);
	std::vector<std::string> expected_endpoints;
	expected_endpoints.reserve(aggregated_endpoints.size());
	std::size_t auto_entries = 0;
	for (const auto& endpoint : aggregated_endpoints) {
		if (endpoint.host.empty() || endpoint.port == 0) {
			continue;
		}
		if (!endpoint.manual) {
			++auto_entries;
		}
		expected_endpoints.push_back(endpoint.host + ":" + std::to_string(endpoint.port));
	}
	assert(!expected_endpoints.empty());
	assert(std::find(expected_endpoints.begin(), expected_endpoints.end(), "control-a.ephemeral:45555") != expected_endpoints.end());
	assert(auto_entries > 0);

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
	ephemeralnet::network::NatTraversalManager::set_test_hooks(nullptr);

	return 0;
}
