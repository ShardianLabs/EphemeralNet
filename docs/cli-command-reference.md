# EphemeralNet CLI command reference

Run the client as `eph [global options] <command> [command options]`. Global options always come first; anything after the command name is interpreted as command-specific. This reference mirrors the logic in `src/main.cpp` for EphemeralNet master as of November 2025.

## Global options

| Option | Description | Notes |
|--------|-------------|-------|
| `--help`, `-h` | Print the top-level usage message and exit. | Does not run a command. |
| `--version` | Print the EphemeralNet CLI version string and exit. | No daemon contact required. |
| `--yes`, `-y` | Assume "yes" for interactive prompts (e.g. overwriting files). | Overrides profile/CLI defaults. |
| `--config <file>` | Load layered YAML/JSON configuration. | Parsed before other options; missing file raises `E_CONFIG_NOT_FOUND`. |
| `--profile <name>` | Select a profile from the configuration file. | Defaults to `default`. |
| `--env <name>` | Apply environment overrides defined in the config file. | Can override the selected profile. |
| `--storage-dir <path>` | Directory for chunk persistence. | Converted to absolute path; must not contain whitespace. |
| `--persistent` / `--no-persistent` | Enable/disable persistent storage. | Overrides profile settings. |
| `--no-wipe` | Disable secure wipe on expiry. | To re-enable, use profiles or omit the flag. |
| `--wipe-passes <1-255>` | Number of secure wipe passes. | Validates bounds. |
| `--identity-seed <uint32>` | Deterministic seed for peer identity. | Generates a repeatable peer ID. |
| `--peer-id <64 hex>` | Explicit peer ID. | Must be exactly 64 hexadecimal characters. |
| `--default-ttl <seconds>` | Default TTL for newly stored chunks. | Must be positive. |
| `--min-ttl <seconds>` / `--max-ttl <seconds>` | Enforce manifest TTL bounds. | `min` ≤ `max` and both positive. |
| `--key-rotation <seconds>` | Session key rotation cadence. | Must be positive. |
| `--announce-interval <seconds>` | Minimum spacing between ANNOUNCE messages. | Positive integer. |
| `--announce-burst <count>` | Burst limit for ANNOUNCE messages. | Positive integer. |
| `--announce-window <seconds>` | Rolling window for ANNOUNCE burst. | Positive integer. |
| `--announce-pow <0-24>` | Proof-of-work difficulty for ANNOUNCE. | Validates upper bound of 24 bits. |
| `--control-host <host>` | TCP host for the control plane. | Defaults to `127.0.0.1`. |
| `--control-expose` | Bind the control plane on `0.0.0.0` for remote management. | Prompts for confirmation unless `--yes`; prints a warning when no `--control-token` is present. Transport auto-advertise now runs independently, so exposing control is only required when you need remote CLI/API access. |
| `--control-loopback` | Force the control plane to stay on `127.0.0.1`. | Overrides any profile/default that points at a non-loopback host. |
| `--control-port <port>` | TCP port for the control plane. | 1–65535; default `47777`. |
| `--control-token <secret>` | Shared secret for control auth. | Whitespace not allowed. |
| `--advertise-auto <on|off|warn>` | Controls how auto-discovered transport endpoints are published. | `on` publishes every candidate, `warn` logs conflicts and publishes only when a single candidate is detected, `off` disables transport auto-advertise entirely (manual `--advertise-control` entries are still honored). |
| `--max-store-bytes <bytes>` | Control-plane upload cap. | `0` disables the cap; default `33554432`. |
| `--fetch-parallel <0-65535>` | Concurrent fetch operations. | `0` = unlimited. |
| `--upload-parallel <0-65535>` | Concurrent upload operations. | `0` = unlimited. |
| `--fetch-default-dir <path>` | Default destination when `fetch` omits `--out`. | Created lazily if missing. |
| `--fetch-use-manifest-name` / `--fetch-ignore-manifest-name` | Toggle use of manifest filename hints during fetch. | Overrides profile values. |

### Global option behaviour

- Options are parsed in order. The first non-option token is treated as the command. Any unknown `--flag` triggers `E_UNKNOWN_OPTION`.
- Configuration profiles can populate the same fields; CLI flags always win.
- Validation errors surface as CLI exceptions with a hint describing the fix.

## Commands

### `fetch`
Retrieve a manifest payload to a local file or directory. When the local daemon cannot reach the swarm directly, the command can fall back to the manifest's discovery metadata.

- Required argument: `eph://…` manifest URI.
- Command options:
  - `--out <path>`: Destination file or directory. Defaults to `--fetch-default-dir` or the current directory.
  - `--direct-only`: Use discovery hints/fallbacks exclusively. Skips the local daemon/DHT fallback.
  - `--transport-only`: Attempt only transport/tcp hints. If none succeed the command fails without contacting control endpoints or the local daemon.
  - `--control-fallback`: Skip transport hints entirely and jump straight to control-plane hints/fallback URIs (legacy behaviour).
  - `--bootstrap-token <value>`: Provide a precomputed PoW token when discovery endpoints demand one. Useful for air-gapped token solvers.
  - `--bootstrap-max-attempts <n>`: Cap the number of nonce attempts when auto-solving PoW tokens (default `250000`).
  - `--no-bootstrap-auto-token`: Disable automatic PoW solving. Use with `--bootstrap-token` when you want to supply your own nonce.

Behavioural notes:

- Without `--out`, the CLI picks a filename from manifest metadata (`filename` key) or falls back to `chunk_<timestamp>`.
- Discovery hints are sorted by priority, but transport hints (`scheme="transport"` or `transport="tcp"`) are now attempted before any control-plane hints. If every transport/control hint fails, the CLI still falls back to the local daemon, which can query the swarm/DHT.
- Discovery hints advertise both a `scheme` and a lower-level `transport`. Auto-advertised data-plane endpoints surface as `scheme="transport"`/`transport="tcp"` and require the manifest to embed the publisher peer/public scalar so the CLI can satisfy the transport handshake PoW. Manually pinned control endpoints continue to use `scheme="control"`. Use `--transport-only` to insist on transport hints (great for air-gapped restores) or `--control-fallback` to disable the transport handshake entirely for legacy nodes.
- Fallback hints that reference `control://host:port` are attempted after discovery hints fail; other URI schemes currently log an informative error.
- `--direct-only` skips the swarm fallback entirely—handy for air-gapped restores or when you intentionally avoid the public DHT.
- Progress is displayed per attempt ("Direct download", "Fallback download", or "Downloading" when the daemon streams the result).
- Remote responses surface daemon-provided hints/codes to aid troubleshooting.

Example forcing direct-only mode into a downloads directory (auto PoW solving is enabled by default):

```powershell
eph fetch eph://AAAA... --direct-only --out "$env:USERPROFILE\Downloads"
```

## Derived usage patterns

- Combine global options with any command. For example, to run automated smoke tests against a remote daemon:
  ```bash
  eph --control-host 198.51.100.10 \
      --control-port 47777 \
      --control-token $(cat token.txt) \
      status
  ```
- Apply configuration layering:
  ```bash
  eph --config ./profiles.yaml --profile staging --env eu-west serve
  ```
- Launch a daemon that is reachable from an external VPS while still enforcing authentication:
  ```bash
  eph --control-expose --control-token $(cat ~/.config/eph/token) start
  ```
  The CLI prints a warning and requires confirmation unless `--yes` is supplied.
- Toggle fetch naming policy per command:
  ```bash
  eph --fetch-ignore-manifest-name fetch eph://... --out ./tmp
  ```
- Command options: none.
- Re-executes the current `eph` binary with the accumulated global options and `serve`.
- Standard streams are detached to `/dev/null` (POSIX) or a detached console (Windows).
- Sample usage (works on PowerShell, bash, etc.):
  ```bash
  eph --config /etc/ephemeralnet.yaml start
  ```
- After the background daemon boots, reuse the same global options for management commands (`status`, `stop`, etc.).

### `stop`
Request a graceful shutdown of the foreground/background daemon.

- Command options: none.
- Contacts the control plane to send `STOP`. Waits up to five seconds for shutdown.

### `status`
Query runtime state (peer count, chunk count, transport port).

- Command options: none.
- Example:
  ```bash
  eph --control-host 10.0.0.5 --control-port 47777 status
- Behavioural notes:
  - When auto-advertise reports filtered or conflicting endpoints the CLI prints them under the summary so operators can pin an explicit `--advertise-control-host/--advertise-control-port` pair.
  - `eph defaults` surfaces the current `--advertise-auto` mode and the manifest endpoint list so you can verify what will be published downstream.
- Required argument: path to a regular file.
- Command options:
  - `--ttl <seconds>`: Override the daemon default TTL for this upload.
  - `--help` / `-h`: Show usage and exit.
- Behavioural notes:
  - Files larger than the configured control-plane cap (`--max-store-bytes`, default 32 MiB) are rejected.
  - When PoW is enabled the client pre-computes an acceptable nonce.
  - Confirmation prompt can be auto-accepted via `--yes`.
- Example:
  ```bash
  eph --control-token secret store ./payload.bin --ttl 7200
  ```
- Command options: none.
- Useful for confirming profile/global overrides (TTL, PoW, concurrency, control endpoint, storage path, fetch naming policy).

### `store`
- Re-executes the current `eph` binary with the accumulated global options and `serve`.
- Detaches from the current terminal (Windows uses `CreateProcess`; POSIX does a double-fork and redirects to `/dev/null`).
- Command options: none.
- Typical usage (same flags as `serve`):
  ```bash
  eph --config /etc/ephemeralnet.yaml start
  ```
- After the background daemon boots, reuse the same global options for management commands (`status`, `stop`, etc.).

### `store`
- `--help` / `-h`: Show usage and exit.
Retrieve a manifest payload to a local file or directory.

- Required argument: `eph://…` manifest URI.
- Command options:
  - `--out <path>`: Explicit destination file or directory.
  - `--help` / `-h`: Show usage and exit.
- Behavioural notes:
  - Without `--out` the CLI uses `--fetch-default-dir` (if set) or the current directory.
  - A bare path argument after the manifest also acts as the destination.
  - Overwrites prompt for confirmation unless `--yes` is provided.
- Example storing in a custom directory:
  ```bash
  eph --control-token secret fetch eph://abcd1234 --out ./downloads/
  ```

### `man`
Print the built-in manual page.

- Command options: none (besides optional `--help`).

### `help`
Alias for `--help` that prints the global usage summary.

## Derived usage patterns

- Combine global options with any command. For example, to run automated smoke tests against a remote daemon:
  ```bash
  eph --control-host 198.51.100.10 \
      --control-port 47777 \
### `fetch`
      --control-token $(cat token.txt) \
      status
  ```
- Apply configuration layering:
  ```bash
  eph --config ./profiles.yaml --profile staging --env eu-west serve
  ```
- Toggle fetch naming policy per command:
  ```bash
  eph --fetch-ignore-manifest-name fetch eph://... --out ./tmp
  ```

## Verification checklist

1. Print help: `eph --help`
2. Display version: `eph --version`
3. Launch foreground daemon with config: `eph --config /etc/ephemeralnet.yaml serve`
4. Query defaults/health while daemon runs:
   - `eph defaults`
   - `eph status`
   - `eph list`
5. Upload and fetch a test file:
   ```bash
   eph store ./sample.txt --ttl 60
   eph fetch <manifest-from-previous-command> --out ./roundtrip.txt
   ```
6. Stop the daemon: `eph stop`
7. Exercise optional flags:
   - `eph --yes store ./payload.bin`
   - `eph --fetch-default-dir ./downloads defaults`
   - `eph --announce-pow 5 serve`

Check each command returns exit code 0 (failures now indicate configuration or environment issues that need attention).
