# Feature catalog

This catalog enumerates EphemeralNet capabilities so future documentation (and eph.shardian.com) can describe them with consistent terminology. Each entry lists the source files that implement the feature plus the primary tests that keep it working.

## CLI and daemon management

| Feature | Description | Implementation | Tests |
|---------|-------------|----------------|-------|
| CLI config layering | Merge defaults, config file, profile, env, and CLI flags before running commands. | `src/main.cpp`, `include/ephemeralnet/Config.hpp` | `tests/cli_config.cpp`, `tests/cli_interleaved_args.cpp` |
| Foreground daemon (`serve`) | Run control + transport loops within the current terminal. | `src/main.cpp`, `src/daemon/ControlServer.cpp`, `src/network/SessionManager.cpp` | `tests/cli_control_flow.cpp`, `tests/cli_bootstrap_flow.cpp` |
| Background daemon (`start`) | Re-exec `eph` detached from the console and reuse the same options. | `src/main.cpp` | `tests/cli_control_flow.cpp` |
| Graceful shutdown (`stop`) | Sends `STOP`, waits for acknowledgement, and confirms resources were released. | `src/daemon/ControlServer.cpp` | `tests/cli_control_flow.cpp` |
| Status commands (`status`, `defaults`, `list`, `metrics`, `diagnostics`) | Query runtime metadata, TTL reports, advertised endpoints, PoW counters. | `src/daemon/ControlServer.cpp`, `src/core/Node.cpp` | `tests/cli_control_flow.cpp`, `tests/ttl_audit.cpp`, `tests/pow_monitoring.cpp` |
| Inline manual (`man`) | Prints consolidated CLI help for air-gapped environments. | `src/main.cpp` | `tests/cli_error_cases.cpp` |

## Storage, TTL, and manifests

| Feature | Description | Implementation | Tests |
|---------|-------------|----------------|-------|
| Chunk ingestion | Stream `STORE` payloads into `ChunkStore`, encrypt with ChaCha20, assign TTL. | `src/core/Node.cpp`, `src/storage/ChunkStore.cpp`, `src/security/StoreProof.cpp` | `tests/store_pow.cpp`, `tests/persistent_storage.cpp` |
| TTL enforcement | Expire in-memory cache, wipe persisted files, withdraw DHT entries. | `src/storage/ChunkStore.cpp`, `src/core/Node.cpp`, `src/dht/KademliaTable.cpp` | `tests/ttl_audit.cpp`, `tests/smoke.cpp` |
| Shamir shard publication | Split encryption keys into `threshold/total` shares stored in manifests and Kademlia. | `src/core/Node.cpp`, `src/protocol/Manifest.cpp`, `src/dht/KademliaTable.cpp`, `src/crypto/Shamir.cpp` | `tests/shamir.cpp`, `tests/manifest.cpp`, `tests/manifest_flow.cpp` |
| Manifest encoding (`eph://`) | Versioned payload containing metadata, discovery hints, fallback URIs, security advisory. | `src/protocol/Manifest.cpp` | `tests/manifest.cpp`, `tests/manifest_fuzz.cpp` |
| Manifest decoding on CLI | Validate URIs before fetch, display metadata and TTL. | `src/main.cpp`, `src/protocol/Manifest.cpp` | `tests/cli_fetch_dir.cpp`, `tests/cli_error_cases.cpp` |

## Networking, DHT, and swarm

| Feature | Description | Implementation | Tests |
|---------|-------------|----------------|-------|
| Transport sessions | Encrypted TCP sessions with handshake PoW and HMAC verification. | `src/network/SessionManager.cpp`, `src/network/KeyExchange.cpp`, `src/protocol/Message.cpp` | `tests/transport_handshake.cpp`, `tests/secure_transport.cpp`, `tests/handshake.cpp` |
| Swarm coordinator | Score peers, assign shards, and rebalance based on load/fairness. | `src/core/SwarmCoordinator.cpp`, `src/core/Node.cpp` | `tests/swarm_distribution.cpp`, `tests/swarm_roles.cpp`, `tests/swarm_fairness.cpp` |
| Kademlia DHT with TTL | Maintain buckets keyed by XOR distance, expire contacts, store shard metadata. | `src/dht/KademliaTable.cpp` | `tests/dht_buckets.cpp`, `tests/bootstrap_gossip.cpp` |
| Bootstrap nodes | Seed DHT with `bootstrap1.shardian.com`/`bootstrap2.shardian.com` and manual entries. | `src/core/Node.cpp`, `include/ephemeralnet/Config.hpp` | `tests/bootstrap.cpp`, `tests/bootstrap_gossip.cpp` |
| NAT traversal diagnostics | STUN probes + relay hints for operators, surfaced via `STATUS`. | `src/network/NatTraversal.cpp`, `src/core/Node.cpp` | `tests/nat_traversal.cpp`, `tests/nat_node.cpp` |
| Relay client/server | TURN-like tunnels for symmetric NAT peers. | `src/network/RelayClient.cpp`, `src/relay/*`, `README.md` instructions | `tests/relay_client_integration.cpp` |
| Fetch planner | Prioritize transport hints, fallbacks, and local daemon retries. | `src/main.cpp`, `src/core/Node.cpp`, `src/network/AdvertiseDiscovery.cpp` | `tests/fetch_priority.cpp`, `tests/fetch_retry.cpp`, `tests/cli_fetch_dir.cpp` |

## Security and abuse prevention

| Feature | Description | Implementation | Tests |
|---------|-------------|----------------|-------|
| Store PoW | Require nonce per upload above configured difficulty. | `src/security/StoreProof.cpp`, `src/core/Node.cpp`, `src/daemon/ControlServer.cpp` | `tests/store_pow.cpp`, `tests/pow_monitoring.cpp` |
| Handshake PoW | Block unauthenticated transport sessions until a valid nonce is provided. | `src/core/Node.cpp`, `src/network/SessionManager.cpp` | `tests/handshake.cpp`, `tests/secure_exchange.cpp` |
| Announce PoW | Ensure gossip messages carry work proof to prevent spam. | `src/core/Node.cpp`, `src/protocol/Message.cpp` | `tests/announce_abuse.cpp`, `tests/announce_distribution.cpp` |
| Control-plane tokens | Optional shared secret for remote management, constant-time comparison. | `src/daemon/ControlServer.cpp` | `tests/cli_error_cases.cpp` |
| Secure wiping | Overwrite persisted chunks before deletion. | `src/storage/ChunkStore.cpp` | `tests/persistent_storage.cpp` |
| Structured metrics + logging | Prometheus-compatible counters, JSON logs for control events. | `src/daemon/ControlServer.cpp`, `docs/observability/` | `tests/pow_monitoring.cpp`, `tests/announce_abuse.cpp` |

## CLI diagnostics and UX

| Feature | Description | Implementation | Tests |
|---------|-------------|----------------|-------|
| Discovery hint surfacing | Show auto/manual endpoints and explain conflicts in CLI output. | `src/network/AdvertiseDiscovery.cpp`, `src/core/Node.cpp` | `tests/advertise_discovery.cpp`, `tests/bootstrap_gossip.cpp` |
| Detailed error codes | Control-plane responses include `CODE`, `MESSAGE`, `HINT` for automation. | `src/daemon/ControlServer.cpp`, `docs/protocol.md` | `tests/cli_error_cases.cpp`, `tests/cli_control_flow.cpp` |
| TTL auditing command | `eph ttl-audit` (invoked via `list`/`defaults`) summaries upcoming expirations. | `src/daemon/ControlServer.cpp`, `src/core/Node.cpp` | `tests/ttl_audit.cpp` |
