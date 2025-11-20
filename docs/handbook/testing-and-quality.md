# Testing and quality

EphemeralNet ships with an extensive `ctest` suite covering CLI behaviour, storage guarantees, networking, proof-of-work enforcement, and security boundaries. Use this chapter as a map when adding or triaging tests.

## Running the suite

```powershell
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

You can target specific areas with `ctest -R <pattern>`—for example, `ctest -R cli_control_flow` (the last command executed in this workspace) exercises the CLI start/stop logic.

## Test categories

| Path | Focus |
|------|-------|
| `tests/advertise_discovery.cpp` | Validates that manifest discovery hints mirror manual and auto-advertised endpoints, including conflict handling and diagnostics. |
| `tests/announce_abuse.cpp` / `announce_distribution.cpp` | Ensures ANNOUNCE PoW thresholds, throttling, and shard assignments behave under load. |
| `tests/bootstrap.cpp`, `tests/bootstrap_gossip.cpp`, `tests/cli_bootstrap_flow.cpp` | Cover the bootstrap process, DHT seeding, and CLI orchestration when connecting to shardian bootstrap nodes. |
| `tests/cli_*` (config, control_flow, error_cases, fetch_dir, interleaved_args) | Exercise CLI argument parsing, config layering, direct fetch flows, and error surfacing. |
| `tests/crypto_hardening.cpp`, `tests/key_schedule.cpp`, `tests/key_schedule.cpp` | Verify ChaCha20/HMAC primitives, key rotation, and Shamir shard reconstruction. |
| `tests/dht_buckets.cpp` | Guarantee Kademlia bucket operations (insert, eviction, TTL pruning) work as expected. |
| `tests/fetch_priority.cpp`, `tests/fetch_retry.cpp`, `tests/store_fetch_plan_rotation.cpp` | Ensure fetch retry logic, priority ordering, and plan rotation happen deterministically. |
| `tests/handshake.cpp`, `tests/transport_handshake.cpp` | Validate transport handshake PoW, protocol version negotiation, and session adoption. |
| `tests/nat_node.cpp`, `tests/nat_traversal.cpp` | Simulate STUN successes/failures, diagnostics, and relay fallback recommendations. |
| `tests/persistent_storage.cpp`, `tests/ttl_audit.cpp` | Confirm persisted chunks respect TTL expiration and secure wipe policies. |
| `tests/pow_monitoring.cpp` | Checks metrics accounting for handshake/store/announce PoW attempts/successes. |
| `tests/protocol_*.cpp` | Cover manifest encoding/decoding (fuzz tests), message serialization, and auth flows. |
| `tests/relay_client_integration.cpp` | Exercises REGISTER/CONNECT flows against the relay client/server. |
| `tests/secure_exchange.cpp`, `tests/secure_transport.cpp` | Ensure encryption, MAC verification, and session resumption stay correct. |
| `tests/shamir.cpp` | Validates the Shamir implementation used for chunk key sharding. |
| `tests/swarm_*.cpp` (distribution, fairness, node, roles) | Prove the `SwarmCoordinator` respects fairness, choking, and load metrics when assigning shards. |
| `tests/upload_choking*.cpp`, `tests/store_pow.cpp`, `tests/ttl_audit.cpp` | Stress upload scheduler, PoW locking, and TTL reporting paths.

## Quality gates

- **ctest** is integrated into the recommended workflow; failures must be fixed before merging.
- **Smoke tests** (`tests/smoke.cpp`) ensure the basic store/fetch/expiry loop works.
- **Fuzz targets** (e.g., `tests/manifest_fuzz.cpp`, `tests/protocol_fuzz.cpp`) guard against malformed manifests or gossip payloads crashing the daemon.
- **Metrics + observability**: `docs/observability/` contains Grafana dashboards and alerting rules so operators can watch PoW failures, control-plane errors, and swarm health in production.
