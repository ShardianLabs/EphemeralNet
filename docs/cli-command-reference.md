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
| `--control-port <port>` | TCP port for the control plane. | 1–65535; default `47777`. |
| `--control-token <secret>` | Shared secret for control auth. | Whitespace not allowed. |
| `--fetch-parallel <0-65535>` | Concurrent fetch operations. | `0` = unlimited. |
| `--upload-parallel <0-65535>` | Concurrent upload operations. | `0` = unlimited. |
| `--fetch-default-dir <path>` | Default destination when `fetch` omits `--out`. | Created lazily if missing. |
| `--fetch-use-manifest-name` / `--fetch-ignore-manifest-name` | Toggle use of manifest filename hints during fetch. | Overrides profile values. |

### Global option behaviour

- Options are parsed in order. The first non-option token is treated as the command. Any unknown `--flag` triggers `E_UNKNOWN_OPTION`.
- Configuration profiles can populate the same fields; CLI flags always win.
- Validation errors surface as CLI exceptions with a hint describing the fix.

## Commands

### `serve`
Run the daemon in the foreground until interrupted.

- Command options: none (any extra token raises `E_SERVE_UNKNOWN_OPTION`).
- Typical usage (foreground daemon using config file):
  ```bash
  eph --config /etc/ephemeralnet.yaml serve
  ```
- Output includes control endpoint coordinates and the transport port. Stop with `Ctrl+C` or `eph stop` from another terminal.

### `start`
Launch the daemon in the background, regardless of platform.

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
  ```

### `list`
List local storage entries with size, state, and remaining TTL.

- Command options: none.
- Output mirrors the `LIST` control response and includes the total count.

### `defaults`
Display daemon defaults plus local CLI fetch defaults.

- Command options: none.
- Useful for confirming profile/global overrides (TTL, PoW, concurrency, control endpoint, storage path, fetch naming policy).

### `store`
Upload a file to the daemon and receive an `eph://` manifest URI.

- Required argument: path to a regular file.
- Command options:
  - `--ttl <seconds>`: Override the daemon default TTL for this upload.
  - `--help` / `-h`: Show usage and exit.
- Behavioural notes:
  - Files larger than 32 MiB (control-plane upload cap) are rejected.
  - When PoW is enabled the client pre-computes an acceptable nonce.
  - Confirmation prompt can be auto-accepted via `--yes`.
- Example:
  ```bash
  eph --control-token secret store ./payload.bin --ttl 7200
  ```

### `fetch`
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
