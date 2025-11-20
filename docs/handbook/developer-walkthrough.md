# Developer walkthrough

This guide narrates how EphemeralNet processes real requests so contributors can follow the code without jumping between files. Use it alongside the feature catalog and scenario playbook when reviewing pull requests or preparing conference demos.

## Store command pipeline

1. **CLI parsing** – `src/main.cpp` loads layered configuration, validates `--ttl`, `--max-store-bytes`, and resolves the file path. It sets `ControlFields` (COMMAND, PATH, TTL, PAYLOAD-LENGTH) and streams bytes after a blank line.
2. **Control server ingress** – `ControlServer::accept_loop` (inside `src/daemon/ControlServer.cpp`) accepts the TCP socket, parses headers via `parse_request`, enforces payload caps using `daemon::max_control_stream_bytes()`, and runs auth/PoW guards:
   - `security::StoreProof::validate` checks the nonce when `Config::store_pow_difficulty > 0`.
   - Rate limits use `kStoreRateWindow`/`kStoreRateBurstLimit` to emit `ERR_STORE_RATE_LIMITED` codes.
3. **Node interaction** – `ControlServer::handle_store` calls `Node::store_chunk`, which:
   - Computes `chunk_id` via `crypto::Sha256` (see `Node::ChunkComputationContext`).
   - Encrypts payloads with `crypto::ChaCha20` if `Config::storage_persistent_enabled` or transport encryption is requested.
   - Persists data through `ChunkStore::put` and records `expires_at`.
   - Builds a manifest using `protocol::encode_manifest`, which includes Shamir shards, discovery/fallback hints, and the security advisory text.
4. **Swarm dissemination** – `SwarmCoordinator::compute_plan` picks peers from `KademliaTable`, respecting TTL, load, and reputation metrics captured by `network::ReputationManager`. ANNOUNCE messages are emitted via `protocol::MessageType::Announce` and signed with HMAC-SHA256.
5. **Response** – The daemon returns `STATUS:OK`, `CODE:OK_STORE`, `MANIFEST`, `SIZE`, `TTL`, plus diagnostics (advertised endpoints, PoW stats). Tests: `tests/store_pow.cpp`, `tests/swarm_distribution.cpp`.

## Fetch command pipeline

1. **Manifest decoding** – `src/main.cpp` calls `protocol::decode_manifest`, caches discovery hints, and decides whether to attempt direct transports (`--direct-only`, `--transport-only`) or the control plane.
2. **Direct transport attempt** – `network::SessionManager` dials peers listed in the manifest, performs handshake PoW (`Node::compute_handshake_pow`), negotiates message versions, then streams CHUNK payloads encrypted with ChaCha20. Timeout/backoff policy is enforced by `Config::fetch_retry_initial_backoff` and `fetch_retry_max_backoff`.
3. **Control fallback** – If direct attempts fail, CLI sends `COMMAND:FETCH` to the daemon. `ControlServer::handle_fetch` registers the manifest with `Node::fetch_manifest`, which either serves local chunks immediately or requests them from the swarm (ANNOUNCE/REQUEST loop) before streaming bytes back through the control socket.
4. **File reconstruction** – CLI writes the stream to `--out`, prompting before overwriting unless `--yes` is set, and optionally uses the manifest’s `filename` metadata. Tests: `tests/fetch_retry.cpp`, `tests/cli_fetch_dir.cpp`.

## Diagnostics & observability

- `ControlServer::handle_status/defaults/list/diagnostics` gather snapshots by calling `Node::status_snapshot`, `ChunkStore::snapshot`, `NatTraversalManager::coordinate`, and `StructuredLogger`. Responses are deliberately line-oriented so grep/sed/PowerShell can parse them.
- Metrics endpoint uses `Metrics::render_prometheus` in `ControlServer.cpp` to expose counters/gauges. `docs/observability/` contains Grafana dashboards and alert rules that consume the same metrics (e.g., PoW success/failure rates).

## Code-reading tips

| Area | Entry point | Notes |
|------|-------------|-------|
| CLI flag handling | `parse_arguments` inside `src/main.cpp` | Uses a manual state machine to support `--flag command` ordering. |
| Config sanitization | `sanitize_config` (`src/core/Node.cpp`) | Clamps TTL, PoW, announce intervals, and rotation cadences to safe ranges. |
| Network stack | `SessionManager::start/connect/adopt_inbound_socket` (`src/network/SessionManager.cpp`) | Abstracts platform-specific socket handling and ensures encryption is applied consistently. |
| DHT/storage integration | `KademliaTable::add_contact` and `ChunkStore::sweep_expired` | Unit tests simulate expiry to guarantee both structures stay consistent. |
| Proof-of-work | `compute_announce_pow`, `compute_handshake_pow`, `security::StoreProof` | All use SHA-256 digests with leading-zero difficulty, capped at 24 bits. |

## Extending the system

- **New CLI command**: add the handler in `src/main.cpp`, expose a control command in `ControlServer`, and decide whether it needs node access, storage access, or both.
- **Additional manifest metadata**: extend `protocol::Manifest` struct, adjust `encode_manifest`/`decode_manifest`, and add coverage to `tests/manifest.cpp` plus at least one CLI scenario.
- **Alternate storage backend**: implement a new class alongside `ChunkStore`, gate it behind a config flag, and update `Node` to select it. Tests should live under `tests/persistent_storage.cpp` or a new suite.
- **Relay innovations**: extend `src/network/RelayClient.cpp` and document the feature in `docs/handbook/networking-and-bootstrap.md` + `usage-scenarios.md`.
