# Networking, Bootstrap, and Relay Strategy

EphemeralNet operates two tightly coupled planes: a newline-delimited control protocol that the CLI speaks over TCP 47777 (by default) and an encrypted gossip-based data plane that replicates shards over TCP 45000. This guide consolidates the networking, DHT, and relay details needed to reason about connectivity end to end.

## Control-plane protocol

### Framing

- Requests and responses are newline-delimited `KEY:VALUE` pairs terminated with a blank line.
- Keys are case-insensitive; the daemon normalizes them before routing.
- `STATUS` is always present in responses (`OK` or `ERROR`). Errors include a stable `CODE` plus optional `MESSAGE` and `HINT` for automation.

Example `STORE` request:

```
COMMAND:STORE
PATH:C:\\data\\payload.bin
TTL:3600
STORE-POW:2489940991873529775
PAYLOAD-LENGTH:4096

<binary payload bytes>
```

Matching success response:

```
STATUS:OK
CODE:OK_STORE
MANIFEST:eph://...
SIZE:4096
TTL:3587
POW-ATTEMPTS:132
```

### Supported commands

| Command | Description |
|---------|-------------|
| `PING` | CLI startup health check. |
| `STATUS` | Returns peer count, chunk inventory, advertised endpoints, transport port, and diagnostics. |
| `DEFAULTS` | Displays effective TTL bounds, PoW bits, rate limits, relay/NAT diagnostics, and advertised endpoints. |
| `LIST` | Streams local chunk metadata (id, size, TTL remaining, persistence state). |
| `STORE` | Accepts payload bytes (gated by PoW + payload cap) and returns a manifest URI. |
| `FETCH` | Streams chunk bytes for a provided manifest or triggers a swarm fetch if missing. |
| `METRICS` | Emits Prometheus-formatted counters/gauges for observability pipelines. |
| `STOP`, `DIAGNOSTICS`, hidden helpers | Administrative commands surfaced through CLI subcommands. |

### Proof-of-work on the control plane

- `HANDSHAKE_POW`, `ANNOUNCE_POW`, and `STORE_POW` bits are advertised via `DEFAULTS` and mirrored in Prometheus metrics.
- Missing or invalid `STORE-POW` headers trigger `ERR_STORE_POW_REQUIRED` / `ERR_STORE_POW_INVALID`; repeated failures yield `ERR_STORE_POW_LOCKED`.
- Payload limits (`control_stream_max_bytes`, default 32 MiB) prevent unbounded uploads.
- Optional `CONTROL-TOKEN` headers enforce shared-secret authentication.

## Transport stack

- `SessionManager` binds a TCP listener (default 45000) and spawns encrypted sessions for inbound peers. Every session begins with a Transport Handshake message containing the initiator’s public scalar + PoW nonce.
- Once PoW is validated (`handshake_pow_difficulty`), both peers derive a ChaCha20 key using Diffie-Hellman and wrap subsequent ANNOUNCE/REQUEST/CHUNK/ACK payloads with HMAC-SHA256 signatures.
- Message handlers registered by the node receive decrypted `protocol::Message` objects, enabling deterministic routing of fetch, announce, and gossip flows.

## Gossip, DHT, and manifests

- `KademliaTable` maintains XOR-distance buckets with TTL-aware entries. It stores provider contacts, shard metadata, and relay preferences.
- ANNOUNCE messages include TTL, manifest URI, endpoint list, assigned shard indices, and the ANNOUNCE PoW nonce. Receiving peers verify the nonce before accepting the update.
- REQUEST/CHUNK exchanges move payload bytes directly between peers. If a provider lacks the chunk, it withdraws the manifest to keep the DHT accurate.
- Manifests (version 4) embed:
  - `chunk_id`, `chunk_hash`, and ChaCha20 nonce.
  - TTL-derived `expires_at` timestamp.
  - Shamir shard metadata (`threshold`, `total_shares`).
  - Discovery hints: ordered `(scheme, transport, endpoint, priority)` tuples sourced from manual advertise flags and auto-discovered endpoints.
  - Security advisory: PoW expectations + optional attestation digest.
  - Fallback URIs: `control://`, `https://`, or other schemes attempted once hints fail.
- The CLI attempts transport hints first, then control hints, then fallback URIs, and finally the local daemon/DHT unless `--direct-only` short-circuits the process.

## Bootstrap and discovery paths

1. **Hardcoded peers** – `Config::bootstrap_nodes` ship with `bootstrap1.shardian.com` and `bootstrap2.shardian.com`. The node contacts them during `start_transport()` to seed the DHT.
2. **Manifest hints** – Every stored chunk advertises prioritized transport + control entries so recipients can reach providers directly before falling back.
3. **Manual overrides** – `--advertise-control host:port` and static `advertised_endpoints` guarantee branded hostnames or relay addresses remain first in manifests.
4. **Fallback URIs** – Provide deterministic final resorts (e.g., HTTPS mirrors) for manifest-only workflows.

## NAT traversal & relay operations

- `NatTraversalManager` probes `stun.shardian.com` / `turn.shardian.com` when enabled, records external IP/port pairs, and reports diagnostics via `DEFAULTS` and `status`.
- When STUN fails or the node sits behind symmetric NAT, `RelayClient` registers with TURN-like relays (default `relay.shardian.com:9750`). Relay endpoints become discovery hints so remote peers can tunnel through the relay.
- Operators can disable or warn on auto-advertise: `on` publishes all candidates, `warn` logs conflicts but withholds ambiguous endpoints, `off` suppresses auto-discovered transport hints entirely.

## Relay-aware troubleshooting checklist

- Transport handshake failures usually indicate PoW misconfiguration or blocked TCP 45000; confirm with `tests/transport_handshake.cpp` and `eph defaults`.
- If `status` shows only `127.0.0.1` under advertised endpoints on a VPS, NAT/STUN likely failed; configure `--advertise-control` with the public hostname or rely on relay hints.
- Relay fairness is enforced by `ReputationManager` + upload choking logic; inspect `tests/upload_choking*.cpp` when tuning quotas.

## Diagnostics & tooling

- `eph diagnostics` returns JSON snapshots (NAT attempts, relay bindings, auto-advertise conflicts) that map directly to structured log events.
- Prometheus metrics expose announce/fetch/PoW counters that correlate with networking incidents; see `docs/03-operations/02-observability.md` for ready-made alert rules.

