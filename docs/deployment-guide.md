# Deployment Guide

Use this guide to build, configure, and operate EphemeralNet in development or lightweight production environments.

## Prerequisites

- **Compiler**: C++20 toolchain (tested with MSVC 19.38 and MinGW-w64 11). On Linux, use Clang 15+ or GCC 11+.
- **CMake**: Version 3.26 or newer.
- **Windows specifics**: PowerShell 5.1+ and the Visual C++ runtime when using MSVC builds.
- **Linux specifics**: `libssl` and `libpthread` development headers.

## Building the Project

```
> cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
> cmake --build build --config Release
> ctest --test-dir build --output-on-failure
```

On Windows with multi-config generators, pass `--config Debug` or `Release` to select the desired profile.

## Configuration

Runtime options are specified via CLI flags or the control daemon configuration fields:

- `--storage-dir <path>`: Persistent chunk directory.
- `--persistent/--no-persistent`: Toggle on-disk retention.
- `--no-wipe` / `--wipe-passes <n>`: Secure wipe control (default one pass).
- `--default-ttl <seconds>`: Override default chunk TTL.
- `--min-ttl <seconds>` / `--max-ttl <seconds>`: Bound manifest TTLs accepted and advertised.
- `--control-host` / `--control-port`: Customize the control socket endpoint.
- `--identity-seed <n>`: Deterministic peer identity for reproducible deployments.
- `--fetch-parallel <n>` / `--upload-parallel <n>`: Tune control-plane fetch/upload concurrency (0 = unlimited).
- `--fetch-default-dir <path>`: Set the default download location when `--out` is omitted.
- `--fetch-ignore-manifest-name`: Disable reusing stored filenames during fetches (pair with `--fetch-use-manifest-name`).

These flags propagate to the daemon when using `eph start` and `eph serve`.

## Running the Daemon

### Foreground Mode

```
> eph serve --storage-dir C:\\EphemeralNet\\storage --persistent --default-ttl 7200
```

This keeps the daemon attached to the current console. Use `Ctrl+C` to stop; the CLI performs a graceful shutdown.

### Background Mode (Windows)

```
> eph start --storage-dir C:\\EphemeralNet\\storage --persistent
```

The CLI spawns a detached process and waits until the daemon responds to `PING`. Stop it with:

```
> eph stop --storage-dir C:\\EphemeralNet\\storage
```

(Ensure the same storage and control options are supplied so the CLI connects to the correct daemon instance.)

## Verifying Health

- `eph status`: prints connected peer count, local chunk inventory, and transport port.
- `eph list`: dumps chunk metadata including TTL remaining.
- `eph defaults`: shows effective TTL bounds, control endpoint, and concurrency limits.
- `eph --version`: reports the CLI build version.
- `eph man`: displays the integrated manual with command and option reference.
- `eph fetch` / `store`: round-trip validations for storage and replication.

## Environment Hardening Tips

- Run the daemon under a dedicated user account with restricted filesystem permissions.
- Place the control socket on `127.0.0.1` or a private interface; never expose it unprotected.
- Enable secure wiping (`--wipe-passes`) when storing sensitive material on persistent volumes.
- Monitor the storage directory disk usage and configure OS-level quotas if required.

## Upgrade Workflow

1. Pull the latest sources and rebuild with CMake.
2. Run the test suite (`ctest`).
3. Drain the daemon (`eph stop`) and verify it is offline.
4. Deploy the new binaries and restart (`eph start` or `eph serve`).
5. Confirm status and list outputs to validate the upgrade.

## Automation Hooks

- The CLI respects `--yes` for non-interactive runs.
- Integrate the `status` command into monitoring scripts; parse the machine-friendly `CODE` field when using the raw control socket.
- For CI environments, use the deterministic `--identity-seed` to ensure stable peer IDs across runs.

This guide should get you from source checkout to a running, observable EphemeralNet node with minimal friction.
