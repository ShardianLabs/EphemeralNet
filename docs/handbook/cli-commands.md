# CLI commands

This chapter expands on `docs/cli-command-reference.md` with a structured description of every command, the global options they honor, the control-plane fields exchanged, and the source files that implement each path. Use it when documenting eph.shardian.com or onboarding operators.

## Global options

All commands inherit the following switches. They can appear before or after the command name.

| Option | Purpose | Notes |
|--------|---------|-------|
| `--help`, `-h` | Print global help and exit. | Does not execute a command. |
| `--version` | Print CLI version. | No daemon contact required. |
| `--yes`, `-y` | Accept prompts automatically. | Required for unattended scripts. |
| `--config <file>` | Load YAML/JSON config. | Missing files raise `E_CONFIG_NOT_FOUND`. |
| `--profile <name>` / `--env <name>` | Select profile + environment overlays. | Profiles defined inside config file. |
| `--storage-dir <path>` | Override storage root. | Must not contain whitespace; sanitized via `std::filesystem`. |
| `--persistent` / `--no-persistent` | Toggle disk persistence. | Overrides profile/default. |
| `--no-wipe` / `--wipe-passes <1-255>` | Control secure wipe behavior. | Applies only when persistence is enabled. |
| `--identity-seed <uint32>` / `--peer-id <hex>` | Force deterministic peer identity. | Useful for reproducible tests. |
| `--default-ttl <seconds>`, `--min-ttl`, `--max-ttl` | Configure TTL bounds. | See `configuration-reference.md`. |
| `--key-rotation <seconds>` | Change session key cadence. | Clamped between 5s and 1h. |
| `--announce-interval`, `--announce-burst`, `--announce-window`, `--announce-pow <bits>` | Tune gossip throttling and PoW. | For advanced operators only. |
| `--control-host`, `--control-port`, `--control-expose`, `--control-loopback`, `--control-token` | Control-plane endpoint and auth. | `--control-expose` prompts unless `--yes` supplied. |
| `--transport-port` | Data-plane listener. | Default `45000`. |
| `--advertise-auto <on|warn|off>`, `--advertise-control <host:port>` | Influence manifest discovery hints. | Diagnostics shown in `status/defaults`. |
| `--max-store-bytes <bytes>` | Cap `PAYLOAD-LENGTH`. | `0` = unlimited (still limited by memory). |
| `--fetch-parallel`, `--upload-parallel` | Set concurrency. | `0` = unlimited. |
| `--fetch-default-dir <path>`, `--fetch-use-manifest-name`, `--fetch-ignore-manifest-name` | Tweak fetch destinations. | Directory created lazily. |

Implementation references: `src/main.cpp` (argument parsing) and `include/ephemeralnet/Config.hpp` (fields).

## Command summary

### `serve`
- **Purpose**: Run the daemon in the foreground using the provided configuration.
- **Flow**: CLI constructs `Config`, then directly calls `daemon::ControlServer::serve()` inside the same process.
- **Key options**: Inherits all globals; no command-specific flags.
- **Outputs**: Logs to stdout/stderr until interrupted. Exits with the daemon status code.
- **Source**: `src/main.cpp`, `src/daemon/ControlServer.cpp`.

### `start`
- **Purpose**: Launch the daemon in the background and detach from the console.
- **Flow**: CLI re-execs itself with accumulated options; Windows uses `CreateProcess`, POSIX performs a double-fork.
- **Outputs**: Prints the spawned PID and returns immediately. Subsequent commands reuse the same global flags to talk to that daemon.
- **Tests**: `tests/cli_control_flow.cpp`.

### `stop`
- **Purpose**: Request a graceful shutdown of the foreground/background daemon.
- **Flow**: Sends `COMMAND:STOP` over the control socket, waits up to five seconds for `STATUS:OK`.
- **Responses**: On success returns `CODE:OK_STOP`. Failures surface hints (`ERR_STOP_REFUSED` when auth/token mismatch).
- **Source**: `src/daemon/ControlServer.cpp` handles the command, `src/main.cpp` renders the response.

### `status`
- **Purpose**: Report current peer count, chunk count, transport port, last NAT diagnostics, advertised endpoints, and TTL summaries.
- **Fields returned**: `PEERS`, `CHUNKS`, `TRANSPORT-PORT`, `ADVERTISED-ENDPOINTS`, `AUTO-ADVERTISE-WARNINGS`, `CONTROL-HOST`, `METRICS-URL` (when enabled).
- **Usage**: `eph status [global options]`
- **Source**: `ControlServer::handle_status`, `Node::status_snapshot`.

### `defaults`
- **Purpose**: Display effective configuration (min/max TTL, wipe policy, concurrency limits, PoW bits, NAT/relay diagnostics).
- **Notes**: Useful for documenting a live node’s advertised endpoints before sharing manifests.
- **Source**: `ControlServer::handle_defaults`.

### `list`
- **Purpose**: Enumerate locally stored chunks with size, manifest TTL, and encryption status.
- **Fields**: `CHUNK-ID`, `SIZE`, `TTL-REMAINING`, `ENCRYPTED`, `FILENAME` (from metadata), `PERSISTED`.
- **Implementation**: `ControlServer::handle_list` pulls from `ChunkStore::snapshot()`.

### `man`
- **Purpose**: Print inline manual containing the same text as `docs/cli-command-reference.md`.
- **Implementation**: `src/main.cpp` bundles the manual string at compile time.

### `help`
- **Purpose**: Alias for `--help` that keeps scripts ergonomic.

### `store`
- **Purpose**: Upload a file to the daemon with an optional TTL override.
- **Syntax**: `eph [global options] store <path> [--ttl <seconds>]`
- **Flow**:
  1. CLI validates the path, resolves it to an absolute file, and reads metadata for manifest hints.
  2. If `Config::store_pow_difficulty > 0`, CLI auto-solves the nonce and adds `STORE-POW` header.
  3. CLI reads the file in chunks, streaming bytes after a blank line following `COMMAND`, `PATH`, `TTL`, `PAYLOAD-LENGTH` headers.
  4. Daemon authenticates, enforces payload cap, verifies PoW via `security::StoreProof`, and asks `Node` to persist + announce the chunk.
- **Response fields**: `STATUS`, `CODE`, `MANIFEST`, `SIZE`, `TTL`, `POW-ATTEMPTS`, `HINT`.
- **Example**:
  ```powershell
  eph --storage-dir .\data store secrets.bin --ttl 3600
  ```

### `fetch`
- **Purpose**: Retrieve a chunk by manifest URI.
- **Syntax**: `eph [global options] fetch eph://... [--out <path>|dir] [--direct-only] [--transport-only] [--control-fallback] [--bootstrap-token <nonce>] [--bootstrap-max-attempts N] [--no-bootstrap-auto-token]`
- **Flow**:
  1. Parse/validate manifest (version, TTL, discovery hints, fallback URIs).
  2. Attempt transport hints first unless `--control-fallback` is set.
  3. If direct downloads fail and `--direct-only` is not set, contact the local daemon with `COMMAND:FETCH` and stream into the CLI.
  4. CLI writes the file to `--out` or the default directory, optionally using manifest metadata for the filename.
- **Response fields (daemon)**: `STATUS`, `CODE`, `BYTES`, `SOURCE` (`LOCAL`, `REMOTE`, `DIRECT`), `HINT`.
- **Errors**: `ERR_FETCH_CHUNK_MISSING`, `ERR_FETCH_TTL_EXPIRED`, `ERR_FETCH_OUTPUT_EXISTS`.

### `list-manifests` (implicit via `list`)
- Although not a standalone CLI name, the daemon surfaces manifest metadata through `LIST`. Documented here for web completeness.

### `metrics`
- **Purpose**: Stream Prometheus-formatted counters/gauges for control-plane and PoW stats.
- **Status**: Accessible via `COMMAND:METRICS` over the control socket. CLI exposes it via `eph metrics` (hidden command used in CI scripts).
- **Output**: Gauge/counter pairs such as `ephemeralnet_command_store_requests_total`, `ephemeralnet_store_pow_difficulty_bits`.

### `diagnostics`
- **Purpose**: Provide verbose JSON snapshots for support scenarios (NAT attempts, relay state, auto-advertise conflicts).
- **Usage**: `eph diagnostics` (hidden command). Response includes structured text that matches `StructuredLogger` events.

## Response codes and hints

The daemon always includes a `CODE` field. Common successes/failures:

| Code | Meaning | Typical resolution |
|------|---------|--------------------|
| `OK`, `OK_STORE`, `OK_FETCH` | Command succeeded. | None. |
| `ERR_AUTH_REQUIRED`, `ERR_AUTH_FAILED` | Missing or incorrect `CONTROL-TOKEN`. | Supply the correct token via `--control-token`. |
| `ERR_STORE_POW_REQUIRED`, `ERR_STORE_POW_INVALID`, `ERR_STORE_POW_LOCKED` | Store PoW missing/bad/locked after repeated failures. | Re-run CLI so it auto-solves, or wait for lock to expire. |
| `ERR_TTL_BELOW_MIN`, `ERR_TTL_ABOVE_MAX` | TTL violates daemon bounds. | Adjust `--ttl` or daemon config. |
| `ERR_FETCH_CHUNK_MISSING` | Chunk not present and TTL expired before fetch completed. | Re-upload or re-fetch while TTL is valid. |
| `ERR_CONTROL_PAYLOAD_TOO_LARGE` | `PAYLOAD-LENGTH` exceeded `--max-store-bytes`. | Increase limit or upload smaller file. |
| `ERR_CONTROL_HEADER` | Malformed key-value pair; usually indicates a non-CLI client. | Use the official CLI.

Hints (`HINT`) give remediation steps and are meant to be displayed verbatim on the website.

## Mapping commands to code

| Command | Key functions |
|---------|---------------|
| `serve`, `start` | `main()` (option parsing), `daemon::ControlServer::serve`, `Node::start_transport` |
| `stop` | `ControlServer::handle_stop`, `Node::stop_transport` |
| `status`, `defaults` | `ControlServer::handle_status/defaults`, `Node::status_snapshot`, `network::AdvertiseDiscovery` |
| `store` | `ControlServer::handle_store`, `security::StoreProof::verify`, `Node::store_chunk`, `ChunkStore::put` |
| `fetch` | `ControlServer::handle_fetch`, `Node::fetch_manifest`, `SwarmCoordinator`, CLI manifest parser |
| `list` | `ControlServer::handle_list`, `ChunkStore::snapshot` |
| `metrics` | `ControlServer::handle_metrics`, `Node::pow_statistics` |
| `diagnostics` | `ControlServer::handle_diagnostics`, `NatTraversalManager` |
