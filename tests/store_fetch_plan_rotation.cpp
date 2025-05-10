#include "ephemeralnet/core/Node.hpp"
#include "test_access.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <utility>
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

ephemeralnet::Config make_config(std::uint32_t seed) {
	ephemeralnet::Config config{};
	config.identity_seed = seed;
	config.handshake_cooldown = 1s;
	config.fetch_retry_initial_backoff = 1s;
	config.fetch_retry_max_backoff = 2s;
	config.fetch_retry_success_interval = 1s;
	config.fetch_retry_attempt_limit = 6;
	config.fetch_availability_refresh = 1s;
	config.upload_reconsider_interval = 1s;
	config.upload_transfer_timeout = 20s;
	config.swarm_rebalance_interval = 2s;
	config.swarm_target_replicas = 2;
	config.swarm_min_providers = 2;
	config.shard_threshold = 2;
	config.shard_total = 4;
	config.default_chunk_ttl = 180s;
	config.min_manifest_ttl = 5s;
	config.max_manifest_ttl = 600s;
	config.key_rotation_interval = 30s;
	config.control_host = "127.0.0.1";
	return config;
}

void register_contact(ephemeralnet::Node& node,
					  const ephemeralnet::PeerId& peer_id,
					  std::uint16_t port,
					  std::chrono::seconds ttl = 180s) {
	ephemeralnet::PeerContact contact{};
	contact.id = peer_id;
	contact.address = "127.0.0.1:" + std::to_string(port);
	contact.expires_at = std::chrono::steady_clock::now() + ttl;
	node.register_peer_contact(std::move(contact));
}

bool plan_contains_peer(const ephemeralnet::SwarmDistributionPlan& plan,
						const ephemeralnet::PeerId& peer_id) {
	return std::any_of(plan.assignments.begin(), plan.assignments.end(), [&](const ephemeralnet::SwarmAssignment& assignment) {
		return assignment.peer.id == peer_id;
	});
}

}  // namespace

int main() {
	const auto seeder_id = make_peer_id(0x10);
	const auto leecher_a_id = make_peer_id(0x40);
	const auto leecher_b_id = make_peer_id(0x70);
	const auto leecher_c_id = make_peer_id(0xA0);

	auto seeder_config = make_config(0xABCDE101u);
	auto leecher_a_config = make_config(0xABCDE202u);
	auto leecher_b_config = make_config(0xABCDE303u);
	auto leecher_c_config = make_config(0xABCDE404u);

	ephemeralnet::Node seeder(seeder_id, seeder_config);
	ephemeralnet::Node leecher_a(leecher_a_id, leecher_a_config);
	ephemeralnet::Node leecher_b(leecher_b_id, leecher_b_config);
	ephemeralnet::Node leecher_c(leecher_c_id, leecher_c_config);

	seeder.start_transport(0);
	leecher_a.start_transport(0);
	leecher_b.start_transport(0);
	leecher_c.start_transport(0);

	std::this_thread::sleep_for(50ms);

	const auto seeder_port = seeder.transport_port();
	const auto leecher_a_port = leecher_a.transport_port();
	const auto leecher_b_port = leecher_b.transport_port();
	const auto leecher_c_port = leecher_c.transport_port();

	assert(seeder_port != 0);
	assert(leecher_a_port != 0);
	assert(leecher_b_port != 0);
	assert(leecher_c_port != 0);

	const bool handshake_sa = seeder.perform_handshake(leecher_a.id(), leecher_a.public_identity());
	const bool handshake_as = leecher_a.perform_handshake(seeder.id(), seeder.public_identity());
	const bool handshake_bs = leecher_b.perform_handshake(seeder.id(), seeder.public_identity());
	const bool handshake_sc = seeder.perform_handshake(leecher_c.id(), leecher_c.public_identity());
	const bool handshake_cs = leecher_c.perform_handshake(seeder.id(), seeder.public_identity());

	assert(handshake_sa);
	assert(handshake_as);
	assert(handshake_bs);
	assert(handshake_sc);
	assert(handshake_cs);

	register_contact(seeder, leecher_a_id, leecher_a_port);
	register_contact(seeder, leecher_b_id, leecher_b_port);

	ephemeralnet::ChunkId chunk_id{};
	chunk_id.fill(0x3Cu);

	ephemeralnet::ChunkData chunk_payload(512, 0x7Du);
	const auto manifest = seeder.store_chunk(chunk_id, chunk_payload, 180s);

	auto plan_deadline = std::chrono::steady_clock::now() + 2s;
	std::optional<ephemeralnet::SwarmDistributionPlan> initial_plan;
	while (std::chrono::steady_clock::now() < plan_deadline && !initial_plan.has_value()) {
		if (auto plan = ephemeralnet::test::NodeTestAccess::swarm_plan(seeder, chunk_id)) {
			initial_plan = plan;
			break;
		}
		seeder.tick();
		std::this_thread::sleep_for(20ms);
	}

	assert(initial_plan.has_value());
	assert(initial_plan->assignments.size() == 2);
	assert(plan_contains_peer(*initial_plan, leecher_a_id));
	assert(plan_contains_peer(*initial_plan, leecher_b_id));
	assert(!plan_contains_peer(*initial_plan, leecher_c_id));

	std::optional<ephemeralnet::ChunkData> leecher_a_data;
	std::optional<ephemeralnet::ChunkData> leecher_b_data;

	auto fetch_window = std::chrono::steady_clock::now() + 6s;
	while (std::chrono::steady_clock::now() < fetch_window) {
		seeder.tick();
		leecher_a.tick();
		leecher_b.tick();

		if (!leecher_a_data) {
			auto data = leecher_a.fetch_chunk(chunk_id);
			if (data.has_value()) {
				leecher_a_data = std::move(data);
			}
		}

		if (!leecher_b_data) {
			auto data = leecher_b.fetch_chunk(chunk_id);
			if (data.has_value()) {
				leecher_b_data = std::move(data);
			}
		}

		if (leecher_a_data) {
			break;
		}

		std::this_thread::sleep_for(50ms);
	}

	assert(leecher_a_data.has_value());
	assert(!leecher_b_data.has_value());
	assert(*leecher_a_data == chunk_payload);

	register_contact(seeder, leecher_c_id, leecher_c_port);

	ephemeralnet::test::NodeTestAccess::inject_active_upload(seeder,
															 leecher_b_id,
															 chunk_id,
															 std::chrono::steady_clock::now());

	auto rotation_deadline = std::chrono::steady_clock::now() + 8s;
	std::optional<ephemeralnet::SwarmDistributionPlan> rotated_plan;
	while (std::chrono::steady_clock::now() < rotation_deadline) {
		seeder.tick();
		leecher_a.tick();
		leecher_b.tick();
		leecher_c.tick();

		if (auto plan = ephemeralnet::test::NodeTestAccess::swarm_plan(seeder, chunk_id)) {
			const bool has_b = plan_contains_peer(*plan, leecher_b_id);
			const bool has_c = plan_contains_peer(*plan, leecher_c_id);
			if (plan->assignments.size() == 2 && has_c && !has_b) {
				rotated_plan = plan;
				break;
			}
		}

		std::this_thread::sleep_for(50ms);
	}

	assert(rotated_plan.has_value());

	ephemeralnet::test::NodeTestAccess::rebroadcast_manifest(seeder, chunk_id);

	std::optional<ephemeralnet::ChunkData> leecher_c_data;
	auto completion_deadline = std::chrono::steady_clock::now() + 8s;
	while (std::chrono::steady_clock::now() < completion_deadline) {
		seeder.tick();
		leecher_a.tick();
		leecher_b.tick();
		leecher_c.tick();

		if (!leecher_c_data) {
			auto data = leecher_c.fetch_chunk(chunk_id);
			if (data.has_value()) {
				leecher_c_data = std::move(data);
			}
		}

		if (leecher_c_data.has_value()) {
			break;
		}

		std::this_thread::sleep_for(50ms);
	}

	assert(leecher_c_data.has_value());
	assert(*leecher_c_data == chunk_payload);
	assert(!leecher_b_data.has_value());

	seeder.stop_transport();
	leecher_a.stop_transport();
	leecher_b.stop_transport();
	leecher_c.stop_transport();

	return 0;
}
