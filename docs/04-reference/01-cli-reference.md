# CLI Reference

Run commands as `eph [global options] &lt;command&gt; [args]`. Global options may appear before or after the command; command-specific flags (such as `--ttl` for `store`) must follow the command token. This reference mirrors `src/main.cpp` behaviour as of November 2025.

## Global options

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Print top-level usage and exit. |
| `--version` | Print CLI version without contacting the daemon. |
| `--yes`, `-y` | Assume “yes” for prompts (overwrites, control exposure). |
| `--config &lt;file&gt;` | Load YAML/JSON config. Missing files raise `E_CONFIG_NOT_FOUND`. |
| `--profile &lt;name&gt;` / `--env &lt;name&gt;` | Select profile + environment overlays from the config file. |
| `--storage-dir &lt;path&gt;` | Override storage root passed to the daemon. |
| `--persistent` / `--no-persistent` | Toggle disk persistence. |
| `--no-wipe` / `--wipe-passes &lt;1-255&gt;` | Control secure wipe behaviour. |
| `--identity-seed &lt;uint32&gt;` / `--peer-id &lt;hex&gt;` | Deterministic peer identity for reproducible deployments. |
| `--default-ttl`, `--min-ttl`, `--max-ttl` | Configure TTL bounds surfaced via `DEFAULTS`. |
| `--key-rotation &lt;seconds&gt;` | Session key rotation cadence. |
| `--announce-interval`, `--announce-burst`, `--announce-window`, `--announce-pow &lt;bits&gt;` | Tune gossip throttling + PoW. |
| `--control-host`, `--control-port` | Control-plane endpoint (defaults to `127.0.0.1:47777`). |
| `--control-expose` / `--control-loopback` | Force control socket to `0.0.0.0` (with prompt) or back to loopback. |
| `--control-token &lt;secret&gt;` | Shared secret required by the daemon. |
| `--transport-port &lt;port&gt;` | Transport listener (default 45000) announced to peers. |
| `--advertise-control &lt;host:port&gt;` / `--advertise-auto &lt;on|warn|off&gt;` | Influence manifest discovery hints. |
| `--max-store-bytes &lt;bytes&gt;` | Cap `PAYLOAD-LENGTH` for uploads. `0` = unlimited. |
| `--fetch-parallel`, `--upload-parallel` | Concurrency caps (`0` = unlimited). |
| `--fetch-default-dir &lt;path&gt;` | Default destination when `fetch` omits `--out`. |
| `--fetch-use-manifest-name` / `--fetch-ignore-manifest-name` | Control whether downloads reuse manifest filename metadata. |

Global options are parsed in order; unknown flags before the command throw errors while unknown flags after the command are delegated to that command’s parser. Profiles and environments populate the same fields but are always overridden by CLI flags.

## Command reference

Each command surfaces `STATUS`, `CODE`, and optional `HINT` fields. Success codes typically start with `OK_*`; failure codes are stable for automation.

### `serve`
- Runs the daemon in the foreground using accumulated global options.
- Streams structured logs to stdout/stderr until interrupted.
- Ideal for local debugging because CLI and daemon share the same process.

### `start`
- Re-execs the current binary with the same global options plus `serve`, then detaches (CreateProcess on Windows, double-fork on POSIX).
- Prints the spawned PID and returns immediately once the daemon responds to `PING`.
- Use `stop` with identical global options to shut it down cleanly.

### `stop`
- Sends `COMMAND:STOP` to the daemon and waits up to five seconds for `STATUS:OK`.
- Returns `CODE:OK_STOP` on success or propagates authentication/connection failures.

### `status`
- Reports peer count, chunk count, transport port, advertised endpoints, NAT diagnostics, and metrics URL (when enabled).
- Great for monitoring scripts; parse the machine-friendly `CODE` or raw control response.

### `defaults`
- Dumps effective configuration: TTL bounds, proof-of-work bits, payload caps, advertise mode, relay diagnostics, storage policy, etc.
- Use it before sharing manifests to confirm discovery hints and PoW expectations.

### `list`
- Streams local chunk metadata: `CHUNK-ID`, `SIZE`, `TTL-REMAINING`, `ENCRYPTED`, `PERSISTED`, `FILENAME`.
- Pair with `ttl-audit` scripts to prove compliance.

### `store &lt;path&gt;`
- Uploads a file to the daemon with optional `--ttl &lt;seconds&gt;` override.
- CLI validates the path, enforces `--max-store-bytes`, solves store PoW when required, and streams bytes after headers.
- Response includes `MANIFEST`, `SIZE`, `TTL`, `POW-ATTEMPTS`, and optional hints.

### `fetch &lt;manifest&gt;`
- Retrieves chunk bytes described by `eph://…` URIs.
- Options:
  - `--out &lt;file|dir&gt;`: Destination (directory auto-created).
  - `--direct-only`: Attempt discovery hints only; skip daemon/DHT fallback.
  - `--transport-only`: Attempt only transport hints (skips control/daemon paths).
  - `--control-fallback`: Skip transport hints entirely and pivot straight to control endpoints.
  - `--bootstrap-token &lt;nonce&gt;` / `--bootstrap-max-attempts &lt;n&gt;` / `--no-bootstrap-auto-token`: Control PoW token solving for discovery hints.
- CLI attempts transport hints first, then control hints, then fallback URIs, finally the local daemon (unless suppressed). Responses note `SOURCE` (`DIRECT`, `REMOTE`, `LOCAL`).

### `diagnostics`
- Hidden command returning verbose JSON (NAT attempts, relay bindings, advertise conflicts). Useful for support bundles.

### `metrics`
- Streams Prometheus-formatted metrics. Usually accessed via control protocol automation.

### `man` / `help`
- `man` prints the built-in manual (short narrative). `help` is an alias for `--help`.

## Response codes & hints

Common success/failure codes:

| Code | Meaning |
|------|---------|
| `OK`, `OK_STORE`, `OK_FETCH`, `OK_STOP` | Command succeeded. |
| `ERR_AUTH_REQUIRED`, `ERR_AUTH_FAILED` | Missing/invalid control token. |
| `ERR_STORE_POW_REQUIRED`, `ERR_STORE_POW_INVALID`, `ERR_STORE_POW_LOCKED` | Store PoW missing/bad/locked after repeated failures. |
| `ERR_TTL_BELOW_MIN`, `ERR_TTL_ABOVE_MAX` | TTL outside daemon bounds. |
| `ERR_CONTROL_PAYLOAD_TOO_LARGE` | `PAYLOAD-LENGTH` exceeded `--max-store-bytes`. |
| `ERR_FETCH_CHUNK_MISSING`, `ERR_FETCH_TTL_EXPIRED` | Chunk absent or expired before fetch completion. |
| `ERR_FETCH_OUTPUT_EXISTS` | Destination file exists and `--yes` not supplied. |

`HINT` strings provide remediation steps (increase TTL, supply token, etc.). Preserve them in UX or runbooks so operators see actionable advice.

## Automation patterns

- **Remote management**:
  ```bash
  eph --control-host 198.51.100.10 \
      --control-port 47777 \
      --control-token $(cat ~/.config/eph/token) \
      status
  ```
- **Deterministic uploads**: Supply `--identity-seed`, `--default-ttl`, and `--max-store-bytes` for reproducible CI pipelines.
- **Unattended scripts**: Use `--yes` to bypass prompts, but still monitor `STATUS/CODE` pairs to catch failures.
- **Local manual page**: `eph man` bundles the same content as this file for offline environments.