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
- `--control-host` / `--control-port`: Customize the control socket endpoint.
- `--control-expose`: Bind the control socket on `0.0.0.0` (the CLI warns and requires confirmation unless `--yes`).
- `--control-loopback`: Force the control socket back to `127.0.0.1` even if a profile overrides it.
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
- `eph defaults`: shows effective TTL bounds, control endpoint, announce throttling (interval, burst, window, PoW), and concurrency limits.
- `eph --version`: reports the CLI build version.
- `eph man`: displays the integrated manual with command and option reference.
- `eph fetch` / `store`: round-trip validations for storage and replication.

When you invoke `eph fetch`, the CLI now attempts any discovery hints embedded in the manifest first (ordered by their priority). Successful hints short-circuit the flow, while failures automatically fall back to the local daemon which then leverages the swarm/DHT. Supply `--direct-only` when you explicitly want to skip the daemon/DHT path—useful for air-gapped restores or when you already have routable advertised endpoints for the provider. Discovery hints that require proof-of-work can be satisfied automatically unless you disable it via `--no-bootstrap-auto-token`; alternatively, pre-compute a token with `--bootstrap-token` for long-lived manifests.

## Environment Hardening Tips

- Run the daemon under a dedicated user account with restricted filesystem permissions.
- Place the control socket on `127.0.0.1` or a private interface; never expose it unprotected.
- Use `--control-loopback` to override profiles that accidentally expose the control plane, or `--control-expose --control-token <secret>` when you intentionally need remote management on a VPS.
- Enable secure wiping (`--wipe-passes`) when storing sensitive material on persistent volumes.
- Keep the key rotation interval short for volatile clusters. Use `--key-rotation 300` (5 minutes) together with tight TTL bounds (e.g., `--min-ttl 30`, `--max-ttl 900`) when handling highly sensitive data.
- Limit announce pressure against the DHT by tuning rate limits: `--announce-interval 30 --announce-burst 3 --announce-window 120 --announce-pow 8` is a hardened baseline for untrusted peers.
- Monitor the storage directory disk usage and configure OS-level quotas if required.

## Network exposure & privacy

- **Port forwarding**: If peers must reach your control plane directly, forward TCP 47777 (and any custom control port) from the router or cloud firewall to the daemon host. Verify externally via `nc -vz <ip> 47777` or `Test-NetConnection -ComputerName <ip> -Port 47777`. When forwarding fails due to carrier-grade NAT, relocate the daemon to a VPS or push traffic through a TURN/STUN relay as described in `ops/bootstrap/README.md`.
- **Advertised endpoints**: Binding with `--control-expose` now auto-promotes the first UPnP/STUN discovery so basic VPS/home setups become reachable without extra flags. Still set `advertise_control_host`/`port` (or add explicit `advertised_endpoints`) whenever you need a branded hostname, a relay address, or deterministic ordering. Run `eph defaults` after changes to confirm the advertised list (manual entries first, auto discoveries next) matches what you intend to publish.
- **Privacy trade-offs**: Home/office deployments that should stay obscured can keep `--advertise-auto warn` (logs candidates without publishing) or `off`, relying on a relay entry in `advertised_endpoints`. VPS-based bootstrap nodes can safely leave auto-advertise on but should still enforce `--control-token` and monitor for abuse.
- **Relays**: Deploy coturn or a TCP reverse proxy when you cannot open inbound ports. Point `advertised_endpoints` at the relay hostname so new peers only see the hardened edge, not the origin IP. Document the relay credentials and retention policy so operators can reason about the metadata exposure.

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
