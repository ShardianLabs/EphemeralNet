# Deployment Guide

Follow this checklist to build EphemeralNet, configure runtime options, and operate daemons safely in development or production environments.

## Prerequisites

- **Compiler**: C++20 toolchain (MSVC 19.38, MinGW-w64 11, Clang 15+, or GCC 11+).
- **Build tooling**: CMake ≥ 3.26 and Ninja/Make/MSBuild depending on platform.
- **Windows**: PowerShell 5.1+, Visual C++ runtime.
- **Linux**: `libssl` + `libpthread` development headers.

## Build & test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

On multi-config generators (Visual Studio, Xcode) pass `--config Debug|Release` to `cmake --build` and `ctest`.

## Running the daemon

### Foreground

```
eph serve --storage-dir C:\EphemeralNet\storage --persistent --default-ttl 7200
```

The CLI stays attached; press `Ctrl+C` to stop. Structured logs stream to stdout/stderr for easy troubleshooting.

### Background

```
eph start --storage-dir C:\EphemeralNet\storage --persistent
```

The CLI re-execs itself, detaches, and waits for a healthy `PING`. Stop the daemon with:

```
eph stop --storage-dir C:\EphemeralNet\storage
```

Always reuse the same global options (`--control-host`, `--control-port`, etc.) so management commands reach the correct daemon instance.

## Configuration essentials

- `--storage-dir <path>` + `--persistent`: Choose where encrypted chunks live. Default TTL (6h) can be overridden per command (`--ttl`) or globally (`--default-ttl`).
- Secure wipe knobs: `--wipe-passes <n>` and `--no-wipe` for non-sensitive workloads.
- Control endpoint: `--control-host`, `--control-port`, `--control-loopback`, `--control-expose`, and `--control-token`. Expose the control plane only when necessary and always pair it with a token.
- Transport tuning: `--transport-port`, `--advertise-control`, `--advertise-auto`, relay toggles, and NAT diagnostics from `eph defaults`.
- Concurrency caps: `--fetch-parallel`, `--upload-parallel`, `--max-store-bytes`.
- Fetch UX: `--fetch-default-dir`, `--fetch-use-manifest-name`, `--fetch-ignore-manifest-name`.

Refer to `03-operations/01-configuration.md` for the full option matrix.

## Health verification

- `eph status`: Peer count, chunk count, transport port, advertised endpoints.
- `eph defaults`: TTL bounds, PoW bits, rate limits, NAT/relay diagnostics.
- `eph list`: Current chunk inventory with TTL remaining.
- `eph store` + `eph fetch`: Round-trip smoke test (use small sample payloads).
- `eph metrics`: Prometheus scrape point for automation.

## Network exposure & privacy

- Forward TCP 47777 (control) and 45000 (transport) when you expect inbound peers. Validate from outside the LAN using `nc -vz <ip> <port>` or `Test-NetConnection`.
- When stuck behind CGNAT, rely on relay hints by enabling relays and advertising their hostnames via `--advertise-control`.
- Use `--advertise-auto warn` or `off` to avoid leaking WAN IPs when privacy is paramount; publish relay endpoints instead.
- Document NAT diagnostics and relay usage so governance teams know what metadata is exposed.

## Environment hardening tips

- Run the daemon under a dedicated OS account with restricted filesystem permissions.
- Keep the control plane on loopback unless absolutely required; if you must expose it, enforce tokens and monitor `ERR_AUTH_*` metrics.
- Enable secure wiping when storing sensitive data and verify disk throughput can handle the extra writes.
- Limit announce pressure by tuning interval/burst/window/PoW as described in the performance guide.
- Monitor disk usage and set OS-level quotas to prevent unbounded storage growth.

## Upgrade workflow

1. Pull latest sources and rebuild with CMake.
2. Run `ctest`.
3. Drain the daemon (`eph stop`) and confirm it exited cleanly.
4. Deploy new binaries, restart (`eph start` or `serve`), and re-run `status` + `list`.
5. Execute the golden-path scenarios from `01-getting-started/01-introduction.md` to validate real workflows.

## Automation hooks

- Use `--yes` for unattended scripts.
- Capture control-plane responses (especially `CODE` and `HINT`) for machine parsing.
- Example remote health check:

```bash
eph --control-host 198.51.100.10 \
    --control-port 47777 \
    --control-token $(cat token.txt) \
    status
```

Combine this deployment guide with the observability and governance chapters to keep nodes secure, observable, and compliant.
