# EphemeralNet

EphemeralNet is an ephemeral P2P filesystem written in C++ that focuses on sharing data with a limited lifetime. Instead of replicating files indefinitely, as BitTorrent or IPFS typically do, each node enforces a TTL (time to live) that requires chunks to be deleted automatically once they expire.

## Core capabilities

- **Modular node kernel**: clearly separated storage, networking, and DHT table components.
- **Configurable TTL**: default and per-chunk expiration windows.
- **Expiring Kademlia table**: announcements carry explicit expiration metadata.
- **Ephemeral in-memory storage**: chunks are removed as soon as they expire.
- **Symmetric encryption**: chunks are encrypted at rest with ChaCha20 and ephemeral keys.
- **Kademlia buckets**: XOR distance, LRU management, and nearest-neighbour queries.
- **Message integrity**: protocol messages are signed with HMAC-SHA256.
- **Session key rotation**: a session manager refreshes derived keys via HMAC-SHA256.
- **Handshake and reputation**: simplified Diffie-Hellman handshake with per-peer reputation tracking.
- **Control-plane proof-of-work**: handshake and store operations enforce configurable PoW to discourage spam and Sybil abuse.
- **Bootstrap gossip hints**: manifest broadcasts share the ordered set of advertised control endpoints so hint-only (`--direct-only`) peers immediately learn multiple routable contacts.
- **Auto-inferred public endpoints**: binding the control plane to `0.0.0.0` automatically promotes STUN/relay discoveries so peers learn a routable control endpoint without extra flags.
- **Shardian bootstrap defaults**: `eph start` pins the transport listener to TCP 45000, seeds the DHT with `bootstrap1.shardian.com`/`bootstrap2.shardian.com`, and reuses the shared STUN/TURN relays so zero-config peers join the public mesh while the control plane stays on loopback.
- **TTL auditing**: consistent reports that surface expirations pending in local storage and the DHT.
- **Cleanup coordination**: synchronises local expirations with automatic announcement withdrawal and emits notifications.
- **Secure transport**: ChaCha20-encrypted TCP sessions replace the simulated manager and unlock peer-to-peer messaging.
- **Smoke test**: baseline verification of post-TTL deletion.
- **Swarm coordination**: manifest/shard replication across multiple simulated providers.
- **Optional persistent layer**: disk backend with secure wiping when the TTL elapses.
- **Node CLI**: `serve`, `store`, `fetch`, and `list` commands to operate a node with no additional code.

## Requirements

- CMake ≥ 3.20
- C++20-capable compiler (MSVC 19.3+, Clang 13+, GCC 11+)
- Windows with MinGW-w64 or an equivalent toolchain (current prototype)

## Build

```powershell
cmake -S . -B build
cmake --build build
```

Run smoke tests:

```powershell
ctest --test-dir build
```

> **Note:** The first `cmake` configure step generates the project files and the `build/` directory. Add `-DEPHEMERALNET_BUILD_TESTS=OFF` if you want to skip test targets.

## Continuous Integration

GitHub Actions runs the same configure/build/test stack on every push and pull request targeting `master`. The workflow lives in `.github/workflows/ci.yml` and mirrors the local steps:

1. Configure with `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo`.
2. Build via `cmake --build build --parallel`.
3. Execute `ctest --test-dir build --output-on-failure`.

The workflow relies only on the built-in `GITHUB_TOKEN`, so no external secrets are required until deployment artifacts are introduced. Use the local commands above before pushing to keep CI green.

## CLI

The `eph` binary acts as a lightweight client for the daemon and exposes the most common control commands. Typical usage:

```powershell
# Display global help
eph --help

# Show the CLI version
eph --version

# Run the daemon in the foreground until Ctrl+C
eph --storage-dir .\data serve

# Launch the daemon in the background (detached)
eph --storage-dir .\data start

# Query the status of the running daemon
eph status

# Store a file with a 3600-second TTL (computes PoW automatically when required)
eph store secrets.bin --ttl 3600

# Retrieve a file using an eph:// manifest (auto-names when targeting a directory)
eph fetch eph://<manifest> ./downloads/

# Force manifest-only mode (skip daemon/DHT fallback) when you have routable discovery hints
eph fetch eph://<manifest> --direct-only --out ./downloads/

# List locally stored chunks and remaining TTL
eph list

# Display daemon defaults (TTL window, control host, announce throttling, etc.)
eph defaults

# Read the integrated manual
eph man

# Shut the daemon down gracefully
eph stop
```

Global switches control persistence (`--no-persistent`), storage path (`--storage-dir`), secure wipe passes (`--wipe-passes`), deterministic identity (`--identity-seed`), control-plane endpoints (`--control-host`, `--control-port`), the transport/data-plane listener (`--transport-port`, default 45000), TTL bounds (`--min-ttl`, `--max-ttl`), session key rotation cadence (`--key-rotation`), announce throttling (`--announce-interval`, `--announce-burst`, `--announce-window`, `--announce-pow`), concurrency (`--fetch-parallel`, `--upload-parallel`), fetch defaults (`--fetch-default-dir`, `--fetch-ignore-manifest-name`), and version/manual discovery (`--version`, `eph man`).
Fetch now attempts manifest discovery hints first and automatically falls back to the local daemon/DHT—use `--direct-only` when you want to skip that fallback or when operating entirely over routable advertised endpoints.

> The `start` command reuses the same options as `serve` to configure the daemon before backgrounding it.

## Relay Server

`eph-relay-server` is a minimal relay daemon that implements the REGISTER/CONNECT flow expected by `RelayClient`. It ships with a tiny epoll/kqueue-driven event loop so it can multiplex thousands of long-lived relay sockets without depending on libuv or Boost.Asio.

Build it along with the rest of the workspace:

```bash
cmake --build build --target eph-relay-server
```

Start the daemon (binds to `0.0.0.0:9750` by default):

```bash
./build/eph-relay-server --listen 0.0.0.0:9750
```

Attach EphemeralNet nodes by enabling relay endpoints in their config; the server keeps track of `REGISTER`ed peers and forwards `CONNECT` requests by piping the sockets together as soon as the caller streams its identity bytes.

## Documentation

- [Architecture](docs/architecture.md): component map and concurrency model.
- [Control & Data Protocol](docs/protocol.md): control socket semantics and TTL lifecycle.
- [Deployment Guide](docs/deployment-guide.md): build, configuration, and runtime operations.
- [Troubleshooting](docs/troubleshooting.md): common failures and remediation steps.
- [Performance Tuning Runbook](ops/performance-tuning.md): sizing guidance and announce throttling playbooks for operators.
- [Governance & AUP](docs/governance-and-aaup.md): policies for operating public bootstrap/STUN infrastructure and handling abuse reports.
- [Handbook](docs/handbook/README.md): aggregated chapters covering the CLI reference, usage scenarios, feature catalog, and developer walkthrough for eph.shardian.com.
