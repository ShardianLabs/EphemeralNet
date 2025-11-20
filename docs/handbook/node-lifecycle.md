# Node lifecycle

This chapter describes what happens during each major operation exposed by the `eph` CLI. Reference `docs/protocol.md` for control-plane framing and `docs/cli-command-reference.md` for option syntax.

## Boot (`serve` / `start`)

1. `eph serve` parses global options, loads config files/profiles, and forks/execs the daemon when `start` is requested (`src/main.cpp`).
2. The daemon constructs `ephemeralnet::Config`, sanitizes TTL/PoW/key rotation fields (`Node::sanitize_config`), generates or loads the peer identity scalar, and instantiates `ephemeralnet::Node`.
3. `ControlServer` binds to `control_host:control_port` (default `127.0.0.1:47777`). `SessionManager` binds to `transport_listen_port` (default `45000`) and starts its accept loop.
4. `Node::start_transport()` builds the DHT (`KademliaTable`), registers bootstrap peers (`Config::bootstrap_nodes`), prepares NAT traversal plus relay connections, and warms up the `SwarmCoordinator`.
5. The daemon advertises control/transport endpoints by combining operator-supplied values (`--advertise-control`) and auto-discovered candidates (`Config::auto_advertise_candidates`). Diagnostics are stored for `DEFAULTS`/`STATUS` output.

## Store flow (`eph store <file> [--ttl N]`)

1. CLI validates the file, enforces `--max-store-bytes`, and, if necessary, auto-solves the store PoW target reported by `DEFAULTS`.
2. CLI streams a request to the daemon with `COMMAND:STORE`, `PATH`, `TTL`, and `PAYLOAD-LENGTH`. Binary payload bytes follow the blank line.
3. `ControlServer` authenticates (if `control_token` is configured), enforces rate limits and PoW via `security::StoreProof`, reads the payload, and hands it to `Node::store_chunk()`.
4. `Node` calls `ChunkStore::put()` to persist the encrypted chunk (nonce + ChaCha20 ciphertext). TTL defaults to `Config::default_chunk_ttl` but is clamped between `min_manifest_ttl` and `max_manifest_ttl`.
5. The node constructs a manifest (`protocol::encode_manifest`):
   - Computes `chunk_id` (SHA-256), `chunk_hash`, and Shamir shards.
   - Embeds TTL-derived `expires_at`, metadata (original filename), discovery hints (control/transport endpoints), fallback URIs, PoW advisory text, and attestation digest.
6. `SwarmCoordinator` samples peers from the DHT, scores them based on TTL, load, fairness, and choking state, and distributes shards accordingly.
7. The daemon returns `STATUS:OK` with `MANIFEST`, `SIZE`, `TTL`, and diagnostics. The CLI prints the manifest URI for future fetches.

## Fetch flow (`eph fetch eph://...`)

1. CLI decodes the manifest (`protocol::decode_manifest`), inspects discovery hints, and (unless `--direct-only`) attempts transport endpoints before falling back to the local daemon.
2. When transport hints succeed, the CLI performs a transport handshake with PoW (`MessageType::TransportHandshake`) and streams the chunk directly from a peer via `SessionManager`.
3. When falling back to the local daemon, the CLI sends `COMMAND:FETCH` with `MANIFEST`, optional `OUT`, and `STREAM:client` for on-the-wire delivery.
4. `ControlServer` validates TTL bounds, registers the manifest with the node, and either:
   - Serves the chunk immediately if `ChunkStore` already contains it.
   - Triggers a swarm fetch (ANNOUNCE/REQUEST handshake) and streams the result to the CLI once peers respond or the TTL expires.
5. CLI writes the bytes to disk, prompting before overwrite unless `--yes` is set. Manifest metadata (`filename`) is used unless `--fetch-ignore-manifest-name` is active.

## Periodic maintenance (`tick`)

`ControlServer` drives `Node::tick()` on the cadence defined by `Config::cleanup_interval`. Each invocation:

- Sweeps expired chunks from `ChunkStore`, triggering secure wipe passes when persistence is enabled.
- Withdraws announcements and DHT records for expired chunks, ensuring peers stop requesting them.
- Rotates session keys according to `key_rotation_interval` and flushes stale transport sessions in `SessionManager`.
- Recomputes NAT diagnostics, refreshes relay bindings if STUN failed, and updates `Config::auto_advertise_candidates` for future manifests.
- Runs TTL audits (see `tests/ttl_audit.cpp`) and republishes manifests when the `swarm_rebalance_interval` elapses.

## Shutdown (`stop`)

1. CLI sends `COMMAND:STOP` over the control socket.
2. `ControlServer` acknowledges, stops accepting new clients, and asks `Node` to halt gossip/transport workers.
3. `SessionManager` closes sockets, `ChunkStore` flushes outstanding disk writes, and relay/NAT helpers release resources.
4. CLI waits for confirmation (up to five seconds) and informs the user. Because all state lives in the daemon, the CLI can exit immediately after the acknowledgement.
