# Storage and TTL

EphemeralNet treats TTL enforcement as a first-class concern. This chapter explains how chunks move through the storage subsystem, how manifests encode TTL metadata, and how the daemon ensures expired payloads vanish on schedule.

## Chunk ingestion pipeline

1. `ControlServer` accepts a `STORE` request and streams bytes into memory while enforcing the configured payload cap.
2. `Node::store_chunk()` computes `chunk_id` (`crypto::Sha256` over payload bytes) and derives the symmetric key/nonce used by `crypto::ChaCha20`.
3. The payload is encrypted (unless the operator explicitly disabled it) and wrapped in `ChunkData` (vector of bytes plus metadata).
4. `ChunkStore::put()` stores the chunk:
   - Hash map key is `chunk_id` serialized via `chunk_id_to_string` (`Types.cpp`).
   - `record.expires_at` is `now + sanitized_ttl`, where `sanitized_ttl` is at least one second.
   - If persistence is enabled, the bytes are flushed to `<storage_dir>/<chunk>.chunk`. Existing files are securely wiped before overwriting.
   - `record.nonce` tracks the ChaCha20 nonce so fetches can reconstruct plaintext.

## Manifest generation

`Node` builds a `protocol::Manifest` with:

- `chunk_id` and `chunk_hash` (SHA-256 digests), proving chunk integrity.
- `nonce` (12 bytes) required to decrypt the payload during fetch.
- `expires_at` derived from TTL, encoded as Unix seconds.
- Shamir shares (`manifest.shards`) computed via `crypto::Shamir`; `threshold` and `total_shares` mirror `Config::shard_threshold` and `shard_total`.
- Metadata map containing at least `filename` (when CLI uploads from a regular file).
- `discovery_hints`: ordered `(scheme, transport, endpoint, priority)` tuples taken from advertised endpoints (control plane) and auto-discovered transport candidates. Manifest version 4 uses both scheme and transport for clarity.
- `security` section with `token_challenge_bits`, advisory text describing PoW expectations, and optionally a 32-byte attestation digest (mirrors `chunk_hash`).
- `fallback_hints`: URIs (such as `control://host:port` or `https://mirror/...`) attempted after discovery hints fail.

The manifest is base64-encoded, prefixed with `eph://`, and returned to the CLI for later sharing.

## TTL enforcement

- `ChunkStore::sweep_expired()` runs inside `Node::tick()` and removes in-memory records whose `expires_at` has passed. When persistence is enabled and `storage_wipe_on_expiry` is true, the file is overwritten `storage_wipe_passes` times before deletion.
- `KademliaTable::sweep_expired()` prunes provider contacts and shard records with expired TTLs so the DHT never advertises stale locations.
- `Node::withdraw_manifest()` retracts ANNOUNCE state for expired chunks, ensuring gossip no longer points to the old provider list.
- `ControlServer::make_list_response()` computes `TTL` columns by subtracting `now` from `ChunkStore::SnapshotEntry::expires_at` so operators can audit upcoming deletions (`eph list`, `eph ttl-audit`).
- Tests in `tests/ttl_audit.cpp` and `tests/persistent_storage.cpp` assert that expired chunks are removed, wiped, and no longer listed or fetchable.

## Secure wiping

`ChunkStore::secure_wipe_file()` overwrites each persisted file with zeros (or future patterns) `storage_wipe_passes` times, flushing after each pass, before deleting the file. If wiping fails, the code leaves diagnostics in the logs so operators can investigate.

## Persistent vs. in-memory mode

- In-memory mode is always active: chunk bytes live in the process heap and are erased when `sweep_expired()` runs.
- Persistent mode mirrors those bytes to disk, letting nodes survive restarts as long as TTL has not elapsed. Because TTL is stored in the record, expired chunks are still deleted on the first sweep after restart.
- Operators can toggle persistence per profile (`--persistent` at CLI) without recompiling.

## Shard management

- For each chunk, the node builds `Config::shard_total` shares via `crypto::Shamir`, storing them in both the manifest and the DHT (`KademliaTable::publish_shards`).
- Fetchers reconstruct the ChaCha20 key once they gather `threshold` shares.
- Shard records share the same TTL as the chunk; once `expires_at` passes, `KademliaTable::shard_record()` begins returning `nullopt`.

The combined effect is a storage layer that guarantees automatic expiry—even if the daemon restarts or peers attempt to keep requesting the data beyond its TTL.
