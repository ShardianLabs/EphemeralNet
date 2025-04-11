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

## Suggested next steps

1. Implement a full networking layer for chunk exchange (UDP/TCP or QUIC).
2. Replace `SessionManager` with a production-grade transport and end-to-end encryption.
3. Add distributed TTL audits and coordinated cleanup.
4. Expose a gRPC/REST API for node orchestration.
5. Introduce a daemon mode with key management and remote CLI control.

## CLI

The `eph` binary acts as a lightweight client for the daemon and exposes the most common control commands. Typical usage:

```powershell
# Display global help
eph --help

# Run the daemon in the foreground until Ctrl+C
eph --storage-dir .\data serve

# Launch the daemon in the background (detached)
eph --storage-dir .\data start

# Query the status of the running daemon
eph status

# Store a file with a 3600-second TTL
eph store secrets.bin --ttl 3600

# Retrieve a file using an eph:// manifest
eph fetch eph://<manifest> --out recovered.bin

# List locally stored chunks and remaining TTL
eph list

# Shut the daemon down gracefully
eph stop
```

Global switches control persistence (`--no-persistent`), storage path (`--storage-dir`), secure wipe passes (`--wipe-passes`), deterministic identity (`--identity-seed`), and control-plane endpoint (`--control-host`, `--control-port`).

> The `start` command reuses the same options as `serve` to configure the daemon before backgrounding it.

## Documentation

- [Architecture](docs/architecture.md): component map and concurrency model.
- [Control & Data Protocol](docs/protocol.md): control socket semantics and TTL lifecycle.
- [Deployment Guide](docs/deployment-guide.md): build, configuration, and runtime operations.
- [Troubleshooting](docs/troubleshooting.md): common failures and remediation steps.
