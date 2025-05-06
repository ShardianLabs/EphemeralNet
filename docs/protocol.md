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
| `STORE` | `COMMAND`, `PATH` | `TTL`        | Stores a local file, returning manifest URI and effective TTL. |
| `FETCH` | `COMMAND`, `MANIFEST` | `OUT`, `STREAM` | Retrieves a chunk described by the manifest. When `STREAM:client` is provided the daemon streams bytes back instead of writing to disk. |

### Error Semantics

- Every error uses a stable `CODE` prefix so automation can map to remediation steps.
- `MESSAGE` is human-readable and now localized in English.
- `HINT` provides actionable guidance (e.g., *"Use a positive integer value in seconds"*).

## Data Plane Overview

### Manifest

Manifests encode chunk metadata such as:

- `chunk_id`: 256-bit identifier derived from SHA-256 of the payload.
- `expires_at`: Absolute expiry instant derived from TTL.
- `replica_hint`: Desired replication factor for swarm propagation.
- `metadata`: Key/value annotations. The daemon currently records the original filename (key `filename`) when available so clients can recreate the source name when downloading.

Manifests are serialized and base64-encoded in the `eph://` URI returned to clients.

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
