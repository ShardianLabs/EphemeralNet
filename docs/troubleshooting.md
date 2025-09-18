# Troubleshooting

Common operational issues and their recommended fixes.

| Symptom | Possible Cause | Resolution |
|---------|----------------|------------|
| `Failed to contact the daemon.` | Daemon is not running or control port mismatch. | Start the daemon (`eph serve` or `eph start`) and ensure the CLI uses the same `--control-host` and `--control-port`. |
| CLI stalls on `fetch`. | Chunk not yet replicated locally. | Wait for swarm propagation or verify peers via `eph status`; check network reachability. |
| `ERR_FETCH_MANIFEST_REGISTRATION` hint about TTL expiry. | Manifest expired before ingestion. | Re-store the payload with a larger TTL or ensure peers remain online during replication. |
| Secure wipe takes a long time. | High `--wipe-passes` value or large data sets. | Lower the pass count or disable wiping (`--no-wipe`) for non-sensitive data. |
| `ERR_STORE_UNAUTHENTICATED`. | Missing or invalid control token. | Pass `--control-token` matching the daemon's `control_token` setting or update the configuration. |
| `ERR_STORE_PAYLOAD_REQUIRED`. | CLI sending legacy path-only requests. | Upgrade the CLI to the streaming release or run the command on the daemon host. |
| `ERR_FETCH_UNAUTHENTICATED`. | Token missing when streaming to the caller. | Supply `--control-token` so the daemon accepts the streamed download. |
| `ERR_FETCH_RATE_LIMITED`. | Too many streamed downloads in a short period. | Wait briefly before retrying or adjust the daemon's rate limits. |
| Control socket creation failure. | Another daemon bound to the port or insufficient privileges. | Stop existing instances or choose a different `--control-port`. |
| Mismatched peer IDs between restarts. | Random identity due to missing seed. | Supply `--identity-seed` or `--peer-id` for deterministic identity during automation. |
| `Failed to register manifest` errors in daemon logs. | TTL expired or manifest invalid. | Regenerate the `eph://` manifest and ensure system clocks are synchronized. |
| Remote peers time out immediately. | Port forwarding/firewall missing for TCP 47777. | Validate from outside the LAN (`nc -vz <ip> 47777`), open the port in the router or security group, or migrate to a relay/VPS. |
| `defaults` shows `127.0.0.1:47777` as the first advertised endpoint even on a VPS. | `advertise_control_host` unset, auto-advertise unable to detect the public address. | Set `advertise_control_host`/`port` explicitly or add a manual entry to `advertised_endpoints`. |
| Operators want to hide the origin IP. | Auto-advertise exposes the host's WAN address. | Disable auto-advertise (`off`/`warn`) and publish a TURN/STUN relay hostname instead; update runbooks with the privacy rationale. |

## Diagnostic Tips

- Increase verbosity by tailing the daemon log output (run `eph serve` in foreground during investigation).
- Enable Windows Event Viewer or Linux `journalctl` to capture crashes.
- Use `netstat -ano` (Windows) or `ss -ltnp` (Linux) to confirm the control port is listening.
- Record control protocol sessions with `nc 127.0.0.1 47777` to isolate automation issues.

## Support Scripts

- `scripts/clean-storage.ps1`: Removes storage directory contents; run only when the daemon is stopped.
- `scripts/check-peer.ps1`: Sample script to query `eph status` and emit metrics for monitoring systems.

Keep this guide handy when operating EphemeralNet nodes to reduce turnaround during incident response.
