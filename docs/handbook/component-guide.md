# Component guide

This chapter maps EphemeralNet's directory structure to the responsibility of each component. Use it alongside the codebase to jump directly to the file that enforces a rule or implements a feature.

## Top-level directories

| Path | Description |
|------|-------------|
| `src/main.cpp` | Entry point for the `eph` CLI. Parses global options, loads layered config, and dispatches commands (`serve`, `start`, `stop`, `status`, `store`, `fetch`, `defaults`, `list`, `man`). |
| `src/daemon/` | Control plane implementation (`ControlServer`, `ControlClient`, `ControlPlane`, `StructuredLogger`). Owns the TCP listener, request parsing, auth/PoW enforcement, metrics export, and interaction with `ephemeralnet::Node`. |
| `src/core/` | Node kernel: `Node.cpp` orchestrates storage, transport, TTL policy, gossip, PoW stats, and manifest construction. `ChunkStore.cpp` handles persistence/wiping; `SwarmCoordinator.cpp` creates replication plans; `Types.cpp` provides helpers for IDs. |
| `src/network/` | Transport primitives: `SessionManager` (encrypted TCP sessions), `KeyExchange` (Diffie-Hellman), `NatTraversalManager`, `RelayClient`, `AdvertiseDiscovery`, `ReputationManager`, and `SessionManager` test hooks. |
| `src/dht/` | `KademliaTable.cpp` implements TTL-aware buckets, shard records, provider lookup, and contact sweeping. |
| `src/protocol/` | Serialization for manifests (`Manifest.cpp`) and gossip messages (`Message.cpp`), including proof-of-work fields, Shamir shard encoding, discovery hints, and HMAC signatures. |
| `src/bootstrap/` | Token challenge helpers used to verify manifest bootstrap hints and store PoW submissions (`TokenChallenge.cpp`). |
| `src/relay/` | Minimal relay server/client support for TURN-like tunnels (e.g., `RelayClient.cpp`, `relay_server` target referenced in README). |
| `src/security/` | Proof helpers such as `StoreProof` plus future hardening hooks referenced by the daemon. |
| `src/storage/` | Currently only `ChunkStore`; persists encrypted payloads, enforces expiration, wipes files, and reports snapshots. |
| `include/ephemeralnet/` | Public headers exposing the API surface (config struct, types, subsystem interfaces). |
| `tests/` | Unit and integration tests grouped by concern (advertise discovery, bootstrap gossip, CLI flows, crypto, DHT, manifest, NAT, relay, security, TTL audits, etc.). |
| `docs/` | Human documentation (architecture, protocol, deployment, troubleshooting, governance, observability, handbook). |
| `ops/` | Operational tooling (Bootstrap scripts, metrics recipes). |
| `scripts/` | Utility scripts such as `pow_metrics_proxy.py`. |

## Key classes

### CLI (`src/main.cpp`)
- Builds `Config` by layering defaults, config files, profiles, environments, and CLI overrides.
- Opens the control socket via `ephemeralnet::daemon::ControlClient` and writes newline-delimited commands.
- Handles background daemon management for `start`, secure prompts, PoW solving, and streaming fetch output.

### Daemon (`src/daemon`)
- `ControlServer`: accepts clients, parses headers/payloads, rate limits `STORE`/`FETCH`, calculates secure wipe hints, logs events, serves metrics, streams chunk data, and translates responses to CLI-friendly fields.
- `ControlPlane`: central place for `PAYLOAD-LENGTH` limits (default 32 MiB; set via `--max-store-bytes`).
- `StructuredLogger`: JSON-like log emitter used by operators when tailing the daemon.

### Node (`src/core/Node.cpp`)
- Sanitizes config (`sanitize_config`) so TTL/key rotation/PoW bounds stay within safe limits.
- Owns PoW helpers for ANNOUNCE, handshake, and STORE plus the per-command attempt caps.
- Drives storage ingestion (`ChunkStore::put`), manifest encoding, Shamir shard distribution, Kademlia updates, swarm round-robining, TTL sweeps, relay/NAT diagnostics, and metrics snapshots.

### Storage (`src/storage/ChunkStore.cpp`)
- Keeps active chunks in-memory maps keyed by chunk ID.
- Optionally persists each chunk under `<storage_dir>/<chunk>.chunk` and overwrites/wipes them on expiration.
- Returns `SnapshotEntry` objects for `LIST`/`TTL audit` commands and cooperates with the daemon to calculate remaining TTL seconds.

### DHT (`src/dht/KademliaTable.cpp`)
- Adds providers with explicit TTL and prunes them deterministically.
- Stores separate shard records (threshold/total/count) so the node can rehydrate encryption keys.
- Provides `closest_peers`, `find_providers`, `withdraw_contact`, and `snapshot_locators` for gossip and fetch flows.

### Network (`src/network`)
- `SessionManager`: list/accept/dial TCP sockets, wrap payloads with ChaCha20 encryption + random nonces, and deliver decrypted messages to handlers. Also handles transport handshake payloads with PoW.
- `KeyExchange`: fixed prime (32-bit), generator, modular exponentiation, and SHA-256 derivation of 256-bit shared keys.
- `NatTraversalManager`: best-effort STUN queries against `stun.shardian.com` / `turn.shardian.com`, logging diagnostics and falling back to relay when blocked.
- `RelayClient`: attaches to relay providers (9750/tcp by default) when NAT traversal fails.
- `AdvertiseDiscovery`: curates the list of control/transport endpoints to embed in manifests/discovery hints.

### Protocol (`src/protocol`)
- `Manifest`: encodes version 4 manifests (`eph://` URIs) with chunk metadata, TTL, shards, discovery hints, security advisory text, PoW requirements, fallback URIs, and optional attestation digests. Also decodes legacy versions 1–3 for backward compatibility.
- `Message`: encodes ANNOUNCE/REQUEST/CHUNK/Acknowledge plus transport handshakes; appends HMAC-SHA256 signatures via `crypto::HmacSha256`; enforces version checks during decoding.

### Crypto (`src/crypto`)
- `ChaCha20`: symmetric cipher used by `SessionManager`.
- `HmacSha256`: MAC for protocol messages and token hashing.
- `Sha256`: general hashing utility for PoW digests, manifest digests, and metrics.
- `Shamir`: secret-sharing library generating `KeyShard` values stored in manifests/DHT.

### Bootstrap & security (`src/bootstrap`, `src/security`)
- `TokenChallenge`: deterministic PoW puzzles for bootstrap/discovery hints; ensures CLI-provided tokens meet the configured difficulty.
- `StoreProof`: verifies the PoW nonce that accompanies `STORE` uploads when the daemon advertises a non-zero `store_pow_difficulty`.

