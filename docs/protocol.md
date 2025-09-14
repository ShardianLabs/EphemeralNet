# Control & Data Protocol

EphemeralNet exposes a local TCP control plane (`127.0.0.1:47777` by default) and a gossip-based data plane for chunk replication. This document summarizes the line-oriented control protocol and the semantics that the daemon enforces for TTL-aware storage.

## Control Plane

### Request Format

Requests are newline-delimited key/value pairs with the form `KEY:VALUE`. Commands end with a blank line. Keys are case-insensitive (the daemon normalizes them to upper case).

```
COMMAND:STORE
PATH:C:\\data\\payload.bin
TTL:3600

```

### Response Format

Responses follow the same framing. The daemon always emits a `STATUS` line indicating `OK` or `ERROR`. When `STATUS:ERROR` is returned, a `CODE` plus optional `MESSAGE` and `HINT` clarify the failure.

```
STATUS:OK
CODE:OK_STORE
MANIFEST:eph://...
SIZE:4096
TTL:3587

```

### Supported Commands

| Command | Required Fields | Optional Fields | Description |
|---------|-----------------|-----------------|-------------|
| `PING`  | `COMMAND`       | none            | Health-check used by CLI startup logic. |
| `STATUS`| `COMMAND`       | none            | Returns connected peers, local chunk count, and transport port. |
| `STOP`  | `COMMAND`       | none            | Stops the daemon after acknowledging the request. |
| `LIST`  | `COMMAND`       | none            | Streams stored chunk metadata (id, size, state, TTL). |
| `DEFAULTS` | `COMMAND`   | none            | Reports daemon defaults such as TTL bounds, control endpoint, and concurrency caps. |
| `STORE` | `COMMAND`, `PATH` | `TTL`, `STORE-POW` | Stores a local file, returning manifest URI and effective TTL. `STORE-POW` is mandatory when the daemon advertises a non-zero store PoW difficulty. |
| `FETCH` | `COMMAND`, `MANIFEST` | `OUT`, `STREAM` | Retrieves a chunk described by the manifest. When `STREAM:client` is provided the daemon streams bytes back instead of writing to disk. |

### Error Semantics

- Every error uses a stable `CODE` prefix so automation can map to remediation steps.
- `MESSAGE` is human-readable and now localized in English.
- `HINT` provides actionable guidance (e.g., *"Use a positive integer value in seconds"*).

### Proof-of-Work

- The daemon enforces proof-of-work on sensitive control operations. Handshakes and `STORE` uploads require solving a configurable number of leading-zero bits.
- The `DEFAULTS` response advertises the active bits via `HANDSHAKE_POW` and `STORE_POW`. A value of `0` disables enforcement for that path.
- Clients must include a `STORE-POW` header when `STORE_POW > 0`. The value is a 64-bit nonce that satisfies the advertised difficulty over the chunk id, payload size, and sanitized filename hint.
- Failures surface as `ERR_STORE_POW_REQUIRED`, `ERR_STORE_POW_INVALID`, or `ERR_STORE_POW_LOCKED` (the latter after repeated invalid submissions). Hints instruct operators to regenerate work or wait for the temporary back-off window.
- Operators can audit live enforcement via `METRICS`: the gauges `ephemeralnet_handshake_pow_difficulty_bits`, `ephemeralnet_store_pow_difficulty_bits`, and `ephemeralnet_announce_pow_difficulty_bits` mirror the configured targets, while success/failure counters highlight drift that warrants retuning.

## Data Plane Overview

### Manifest

Manifests encode chunk metadata and rendezvous instructions:

- `chunk_id`: 256-bit identifier derived from SHA-256 of the payload.
- `expires_at`: Absolute expiry instant derived from TTL.
- `replica_hint`: Desired replication factor for swarm propagation.
- `metadata`: Key/value annotations. The daemon currently records the original filename (key `filename`) when available so clients can recreate the source name when downloading.
- `discovery_hints`: Ordered list of `(transport, endpoint, priority)` tuples that the CLI can consult when it must bootstrap a manifest-only fetch. EphemeralNet currently emits `transport="control"` hints that point at public control-plane hosts (`host:port`), but the schema allows future HTTP(S) or QUIC transports as well. Lower `priority` numbers are attempted first.
- `security`: Advisory text describing remote discovery requirements, the number of leading zero bits expected for the token challenge, and (when available) a 32-byte attestation digest that mirrors the chunk hash for integrity pinning.
- `fallback_hints`: Optional URIs (`control://host:port`, `https://mirror/...`, etc.) that clients can pivot to after discovery hints fail. These are treated as mirrors/caches rather than first-class discovery mechanisms. (Current CLI builds attempt `control://` hints automatically and log an informative warning for unsupported schemes.)

Manifests are serialized and base64-encoded in the `eph://` URI returned to clients. Version 3 manifests carry the discovery, security, and fallback sections described above. Older readers understand versions 1 and 2 (which omitted these appendices); attempting to load a truncated or tampered version 3 manifest now raises an error because the bootstrap metadata is required for modern clients.

### Storage Lifecycle

1. **Ingestion**: `STORE` reads the file, computes a `chunk_id`, and writes chunk data to the storage directory (persistent or temp) according to configuration.
2. **Replication**: Once stored, the node announces the manifest to peers and accepts fetch requests routed through the transport layer.
3. **Expiration**: During `tick()`, the node checks chunk expirations. Expired chunks trigger secure wipe passes (`storage_wipe_passes`) before removal when wiping is enabled.

### Fetch Semantics

- The CLI requests `STREAM:client` by default, saving the payload locally. If no explicit `--out` is given, the CLI will place the file in the current directory, using the original filename if metadata is present.
- If the chunk is already local, the daemon writes it immediately. Otherwise it registers the manifest and waits for the chunk to arrive from peers.
- If TTL expires before completion, the daemon reports `ERR_FETCH_CHUNK_MISSING`.

## Future Directions

- **Protocol Versioning**: Future revisions will include `PROTO_VERSION` in both requests and responses to negotiate breaking changes.
- **Authentication**: The control socket currently trusts localhost. Mutual authentication and command signing are planned to secure remote management.
- **Streaming Fetch**: For large chunk support, the fetch command may expose chunk streaming with resumable offsets.

This control protocol keeps user tooling simple while giving the daemon room to evolve. The data plane enforces TTL guarantees and paves the way for richer replication strategies.
