# Data Lifecycle, Storage, and TTL Enforcement

EphemeralNet’s value proposition hinges on deterministic expiry. This guide describes how chunks move through the system, how manifests encode TTL metadata, and how secure wiping + shard management guarantee data disappears on schedule.

## Chunk ingestion pipeline

1. `ControlServer` accepts a `STORE` request, authenticates it (token + PoW), enforces `PAYLOAD-LENGTH`, and streams bytes to the node.
2. `Node::store_chunk()` computes `chunk_id` via SHA-256, derives the ChaCha20 key/nonce, encrypts the payload when enabled, and wraps it in `ChunkData` with metadata.
3. `ChunkStore::put()` writes the chunk into memory (and to disk when persistence is enabled) keyed by `chunk_id`. Each record tracks `expires_at = now + sanitized_ttl`.
4. Secure persistence: existing files are overwritten before updates; metadata retains filename hints for later fetches.

## Manifest generation

`protocol::Manifest` objects returned to the CLI include:

- `chunk_id` + `chunk_hash` for integrity verification.
- ChaCha20 `nonce` and Shamir shard metadata (`threshold`, `total_shares`).
- TTL-derived `expires_at` encoded as Unix seconds.
- Metadata map (e.g., original filename) for ergonomic fetch defaults.
- Discovery hints: prioritized `(scheme, transport, endpoint, priority)` tuples from manual advertise entries and auto-discovered endpoints (NAT/relay diagnostics feed this list).
- Security advisory: handshake/store PoW expectations, attestation digest mirroring the chunk hash, and textual guidance for offline solvers.
- Fallback URIs: optional `control://` or `https://` entries attempted after discovery hints fail.

Manifests are base64-encoded and prefixed with `eph://`, forming the shareable URI. Recipients can reconstruct encryption keys once they collect enough shards.

## TTL enforcement

- `ChunkStore::sweep_expired()` runs during `Node::tick()` and deletes in-memory records whose `expires_at` passed. When persistence is enabled, files are securely wiped (see below) before removal.
- `KademliaTable::sweep_expired()` prunes provider entries and shard metadata so the DHT never advertises stale nodes.
- `Node::withdraw_manifest()` retracts ANNOUNCE state for expired chunks, preventing peers from chasing dead replicas.
- CLI commands (`list`, `ttl-audit`) compute TTL remaining by subtracting `now` from snapshot metadata so auditors can validate compliance.

## Secure wiping

- Controlled by `storage_wipe_on_expiry` and `storage_wipe_passes` (default one pass).
- `ChunkStore::secure_wipe_file()` overwrites persisted files `n` times, flushing after each pass before deletion.
- Failures emit structured diagnostics so operators notice disks that cannot honor rewrite policies.

## Persistent vs. in-memory mode

- In-memory storage is always active; it guarantees data disappears as soon as TTL expires or the daemon restarts.
- Persistent mode mirrors encrypted bytes onto disk under `<storage_dir>/<chunk>.chunk`. Upon restart, the daemon sweeps expired entries immediately using the stored TTL metadata.
- Operators toggle persistence per profile or CLI flag (`--persistent`).

## Shard management

- `Node` emits `Config::shard_total` Shamir shares per chunk and publishes them both inside manifests and to the DHT.
- Fetchers reconstruct the ChaCha20 key after collecting `threshold` shares.
- Shard records share the same TTL as the underlying chunk; once expired, `KademliaTable::shard_record()` returns `nullopt` and ANNOUNCE messages withdraw the share.

## Fetch lifecycle recap

1. CLI decodes the manifest and orders discovery hints by `priority`.
2. Transport hints (e.g., `scheme="transport"`, `transport="tcp"`) are attempted first; each may require solving bootstrap PoW.
3. If transport attempts fail, control hints/fallback URIs take over. When all hints fail (or `--direct-only` is absent) the CLI falls back to the local daemon, which launches a swarm fetch using the same manifest metadata.
4. Chunk bytes are decrypted using the stored nonce + reconstructed ChaCha20 key and delivered to disk, honoring CLI flags such as `--fetch-use-manifest-name`.

By centralizing TTL logic inside the node and manifest pipeline, EphemeralNet guarantees that data, metadata, and discovery hints all expire coherently—even if peers try to replay stale manifests or a node restarts mid-sweep.
