# EphemeralNet Architecture

EphemeralNet is composed of a lightweight CLI, a daemonized node runtime, and reusable libraries that implement peer-to-peer storage with TTL-based expiry. The system is organized around a clear separation of responsibilities so the CLI can remain stateless while the daemon owns long-running resources.

## High-Level Overview

```
+-----------------+      control socket      +-----------------------+
| eph CLI         | <----------------------> | Daemon Control Server |
| - argument parsing                           - command routing     |
| - orchestration                              - status monitoring   |
+-----------------+                            - lifecycle hooks     |
        |                                          |
        | spawn/serve                              |
        v                                          v
+-----------------+      chunk ops API      +-----------------------+
| Core Node       | <----------------------> | Storage & Transport   |
| - peer ID mgmt                              - chunk store          |
| - TTL policies                              - UDP/TCP transport    |
| - manifest flow                             - gossip replication   |
+-----------------+                            - secure wipe service |
```

### Components

- **CLI (`eph`)**: Provides user-facing commands. It marshals options, forwards requests to the daemon through the control socket, confirms destructive operations, and renders human-friendly status messages.
- **Daemon Control Server**: Exposes a line-oriented protocol over TCP (default `127.0.0.1:47777`). It handles commands such as `PING`, `STATUS`, `STORE`, and `FETCH`, translating them into node operations.
- **Core Node**: Maintains peer identity, default TTL policies, and orchestrates chunk replication. It interacts with the transport subsystem to join the swarm and with storage to persist ephemeral data.
- **Storage Subsystem**: Stores encrypted or plain chunks depending on configuration, enforces TTL expiration, and performs secure wipe passes when configured.
- **Transport Layer**: Handles peer discovery, manifest dissemination, and chunk exchange. It exposes the externally reachable transport port reported via the control plane.

### Data Flow

1. The user executes a CLI command (e.g., `eph store file.bin`).
2. The CLI sends a structured request over the control socket.
3. The daemon validates the request, possibly mutating configuration (e.g., TTL overrides), and passes it to the core node under a mutex to ensure thread safety.
4. The node either stores or retrieves chunk data, engaging the storage and transport subsystems.
5. The daemon responds with manifest URIs, status codes, and hints. The CLI renders the response for the user.

### Concurrency Model

- The daemon runs an accept loop that spawns lightweight handlers while reusing the shared node instance.
- The node exposes `start_transport`, `tick`, and `stop_transport` methods that the daemon drives from the CLI `serve` command.
- TTL enforcement and secure wiping occur during `tick()` invocations, ensuring deterministic cleanup without separate scheduler threads.

### Extensibility Points

- **Protocol Versioning**: The control server includes a `CODE` field in responses to guide future version negotiation.
- **Security Hooks**: The transport and storage layers expose insertion points for future authentication, encryption, and fuzzing harnesses.
- **Automation**: The CLI supports `--yes` to skip confirmations, easing integration with scripts and CI pipelines.

This architecture keeps the CLI thin, centralizes long-lived state inside the daemon, and leaves clear seams for future enhancements such as distributed consensus or pluggable storage backends.
