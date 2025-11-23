# Validation & Test Guide

EphemeralNet ships with an extensive `ctest` suite spanning CLI flows, storage guarantees, networking, proof-of-work, and security boundaries. Use this guide to plan test coverage, run targeted suites, and understand what each file in `tests/` exercises.

## Running the suite

```powershell
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Filter by regex with `ctest -R <pattern>` to narrow focus (e.g., `ctest -R cli_control_flow`).

## Test categories

| Path | Focus |
|------|-------|
| `tests/advertise_discovery.cpp` | Manifest discovery hints, manual vs. auto-advertised endpoints, conflict diagnostics. |
| `tests/announce_abuse.cpp`, `tests/announce_distribution.cpp` | ANNOUNCE PoW thresholds, throttling, shard assignment under load. |
| `tests/bootstrap.cpp`, `tests/bootstrap_gossip.cpp`, `tests/cli_bootstrap_flow.cpp` | Bootstrap process, DHT seeding, CLI orchestration against shardian bootstrap nodes. |
| `tests/cli_*` | Argument parsing, config layering, fetch directory behaviour, interleaved args, error surfaces. |
| `tests/crypto_hardening.cpp`, `tests/key_schedule.cpp`, `tests/shamir.cpp` | Cryptographic primitives, key rotation, secret sharing. |
| `tests/dht_buckets.cpp` | Kademlia bucket insert/evict/TTL sweeps. |
| `tests/fetch_priority.cpp`, `tests/fetch_retry.cpp`, `tests/store_fetch_plan_rotation.cpp` | Fetch retry logic, prioritisation, plan rotation. |
| `tests/handshake.cpp`, `tests/transport_handshake.cpp` | Transport handshake PoW, protocol negotiation, session adoption. |
| `tests/nat_node.cpp`, `tests/nat_traversal.cpp` | STUN diagnostics, relay fallback recommendations. |
| `tests/persistent_storage.cpp`, `tests/ttl_audit.cpp` | Persistence mode, secure wipe, TTL enforcement. |
| `tests/pow_monitoring.cpp` | Metrics accounting for handshake/store/announce PoW. |
| `tests/protocol_*.cpp`, `tests/manifest_fuzz.cpp` | Protocol and manifest encoding/decoding plus fuzz coverage. |
| `tests/relay_client_integration.cpp` | Relay REGISTER/CONNECT flows. |
| `tests/secure_exchange.cpp`, `tests/secure_transport.cpp` | Encryption/MAC verification and session resumption. |
| `tests/swarm_*.cpp`, `tests/upload_choking*.cpp` | Swarm fairness, choking scheduler, peer role enforcement. |
| `tests/smoke.cpp` | End-to-end store/fetch/expiry sanity check. |

## Quality gates

- `ctest` must pass before merging; treat failures as release blockers.
- Fuzzers (`manifest_fuzz`, `protocol_fuzz`) guard against malformed inputs; run them on release candidates.
- Observability: integrate `docs/observability` dashboards and alerts so PoW counters and announce throttles raise incidents before customers notice.
- Governance: record results of `ttl-audit` and `pow_monitoring` in compliance reports to prove TTL and PoW controls hold.

Use this validation chapter alongside the deployment and performance guides to maintain confidence that every change preserves EphemeralNet’s guarantees.
