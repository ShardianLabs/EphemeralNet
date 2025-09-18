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
- **Bootstrap gossip hints**: manifest broadcasts share the ordered set of advertised control endpoints so bootstrap-only peers immediately learn multiple routable contacts.
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

# List locally stored chunks and remaining TTL
eph list

# Display daemon defaults (TTL window, control host, announce throttling, etc.)
eph defaults

# Read the integrated manual
eph man

# Shut the daemon down gracefully
eph stop
```

Global switches control persistence (`--no-persistent`), storage path (`--storage-dir`), secure wipe passes (`--wipe-passes`), deterministic identity (`--identity-seed`), control-plane endpoints (`--control-host`, `--control-port`), TTL bounds (`--min-ttl`, `--max-ttl`), session key rotation cadence (`--key-rotation`), announce throttling (`--announce-interval`, `--announce-burst`, `--announce-window`, `--announce-pow`), concurrency (`--fetch-parallel`, `--upload-parallel`), fetch defaults (`--fetch-default-dir`, `--fetch-ignore-manifest-name`), and version/manual discovery (`--version`, `eph man`).

> The `start` command reuses the same options as `serve` to configure the daemon before backgrounding it.

## Documentation

- [Architecture](docs/architecture.md): component map and concurrency model.
- [Control & Data Protocol](docs/protocol.md): control socket semantics and TTL lifecycle.
- [Deployment Guide](docs/deployment-guide.md): build, configuration, and runtime operations.
- [Troubleshooting](docs/troubleshooting.md): common failures and remediation steps.
- [Performance Tuning Runbook](ops/performance-tuning.md): sizing guidance and announce throttling playbooks for operators.
- [Governance & AUP](docs/governance-and-aaup.md): policies for operating public bootstrap/STUN infrastructure and handling abuse reports.
