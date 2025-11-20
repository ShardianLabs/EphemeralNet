# System overview

EphemeralNet is a C++20 peer-to-peer filesystem that refuses to keep data longer than its declared TTL. The implementation is split into a thin command-line client (`src/main.cpp`), a daemonized control plane (`src/daemon`), and reusable libraries (`src/core`, `src/network`, `src/dht`, `src/storage`, `src/protocol`). Existing high-level diagrams live in `docs/architecture.md`; this chapter summarises how those pieces interact in practice.

## Design goals

- **Ephemerality first** – every chunk, DHT record, and manifest carries an expiration instant enforced inside `ephemeralnet::ChunkStore` and `ephemeralnet::KademliaTable`.
- **Deterministic CLI** – the `eph` CLI stays stateless and shells out to the daemon via the line-oriented control socket on `127.0.0.1:47777` unless the operator overrides it.
- **Composable node kernel** – the `ephemeralnet::Node` orchestrates storage, gossip, NAT discovery, relay failover, DHT maintenance, and PoW without exposing those details to the CLI.
- **Security-in-depth** – ChaCha20 protects transport payloads, HMAC-SHA256 signs protocol messages, handshake/store/announce PoW deter abuse, and secure wiping protects persisted chunks.
- **Operator visibility** – structured logs plus the `METRICS` control command expose counters and gauges that can be scraped into Grafana dashboards (`docs/observability/`).

## Control plane vs. data plane

| Plane | Implementation | Purpose |
|-------|----------------|---------|
| Control | `src/daemon/ControlServer.cpp`, `src/daemon/ControlPlane.cpp` | Line protocol that accepts `PING`, `STATUS`, `DEFAULTS`, `STORE`, `FETCH`, `LIST`, `METRICS`, and `STOP`. Handles auth tokens, payload caps, PoW validation, file ingestion, and streaming fetch responses. |
| Data | `src/network/SessionManager.cpp`, `src/protocol/Message.cpp`, `src/core/SwarmCoordinator.cpp` | Encrypted TCP sessions that replicate shards, fulfill fetch requests, exchange ANNOUNCE/REQUEST/CHUNK messages, and enforce TTL-aware gossip. |

The CLI only speaks to the control plane. The daemon proxies data-plane work to the node, which in turn maintains transport sessions and DHT state.

## Major subsystems

- **CLI (`src/main.cpp`)** parses global flags (see `docs/cli-command-reference.md`), connects to the control socket, marshals payloads, and renders human-friendly output.
- **Daemon control server** accepts TCP clients, parses newline-delimited headers, streams chunk bytes when `PAYLOAD-LENGTH` is set, enforces per-command rate limits, and drives the node via `ephemeralnet::Node` methods.
- **Core node (`src/core/Node.cpp`)** owns the peer identity, proof-of-work parameters, manifest TTL checks, swarm scheduling, shard publication, and cleanup (`tick()`). It embeds `ChunkStore`, `KademliaTable`, `SwarmCoordinator`, and helper managers.
- **Storage subsystem (`src/storage/ChunkStore.cpp`)** stores chunk bytes in-memory, optionally persists them, tracks expiration monotically, and wipes files with configurable passes.
- **Transport subsystem (`src/network`)** provides `SessionManager` (TCP listener and outbound dialer), `KeyExchange` (Diffie-Hellman over a 32-bit prime), `NatTraversalManager` (STUN + diagnostics), `RelayClient` (TURN-like tunnels), and `ReputationManager` for fairness decisions.
- **Protocol layer (`src/protocol`)** defines ANNOUNCE/REQUEST/CHUNK/Acknowledge frames with versioned encodings, HMAC-SHA256 signatures, transport handshake payloads, and manifest serialization.
- **Security helpers (`src/security`)** contain proof-of-work verifiers (`StoreProof`, `TokenChallenge`) and policy glue used by the daemon.

## Runtime timeline

1. `eph serve` (or `start`) loads layered configuration, validates CLI overrides, and spawns the daemon.
2. `ControlServer` binds to `control_host:control_port`, `SessionManager` binds to the transport/data-plane port, and `Node::start_transport()` launches gossip.
3. The daemon registers bootstrap peers from `Config::bootstrap_nodes`, seeds the DHT, advertises control/transport endpoints, and prepares NAT/relay diagnostics.
4. Operators use `eph store`, `eph fetch`, `eph status`, etc. The CLI forwards each request over the control socket; the daemon funnels it into node operations and streams structured responses back.
5. `Node::tick()` runs periodically (driven by the daemon) to rotate keys, enforce TTLs, reannounce manifests, and withdraw expired entries.
6. `eph stop` (or daemon shutdown) drains outstanding uploads/downloads, closes control sessions, stops the transport listener, and persists metrics for operators.

## Extensibility seams

- **Advertised endpoints** – auto-discovered transport endpoints (from NAT traversal or relay binding) are stored in `Config::auto_advertise_candidates` and surfaced via manifests.
- **Manifest extras** – version 4 manifests include discovery hints (scheme, transport, endpoint, priority), a security advisory + attestation digest, and ordered fallback URIs so clients can pick the best path.
- **Proof-of-work knobs** – handshake/store/announce difficulty bits come from `Config` and are exposed through `DEFAULTS` so tooling can auto-tune.
- **Relay providers** – `Config::relay_endpoints` and `RelayClient` make it easy to add additional TURN-style servers without touching control-plane logic.
- **Chunk sharding** – `Config::shard_threshold` and `Config::shard_total` govern how many Shamir shares the node emits per chunk, enabling future durability policies.

Refer back to `docs/architecture.md` whenever an ASCII diagram helps; this chapter is the narrative that the diagrams summarise.
