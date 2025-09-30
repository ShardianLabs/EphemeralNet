# Troubleshooting

Common operational issues and their recommended fixes.

| Symptom | Possible Cause | Resolution |
|---------|----------------|------------|
| `Failed to contact the daemon.` | Daemon is not running or control port mismatch. | Start the daemon (`eph serve` or `eph start`) and ensure the CLI uses the same `--control-host` and `--control-port`. |
| CLI stalls on `fetch`. | Chunk not yet replicated locally. | Wait for swarm propagation or verify peers via `eph status`; check network reachability. |
| `ERR_FETCH_MANIFEST_REGISTRATION` hint about TTL expiry. | Manifest expired before ingestion. | Re-store the payload with a larger TTL or ensure peers remain online during replication. |
| `direct-only fetch cannot proceed`. | The manifest lacks discovery hints or decoding failed before the daemon fallback kicked in. | Retry without `--direct-only` so the CLI can hand the request to the local daemon/DHT, or re-store the payload so it advertises at least one routable control endpoint. |
| `Transport handshake failed` / `Unable to satisfy transport proof-of-work target`. | Manifest discovery hints advertise data-plane (`transport/tcp`) entries but the payload is missing publisher metadata or the PoW difficulty is too aggressive for the CLI to solve on the fly. | Re-store the payload so manifests include `publisher_peer`/`publisher_public` metadata, keep the transport PoW threshold near the daemon default, switch to `--control-fallback` to skip the transport handshake entirely, or omit `--direct-only` so the control-plane fallback can stream the chunk even when control ports stay private. |
| Secure wipe takes a long time. | High `--wipe-passes` value or large data sets. | Lower the pass count or disable wiping (`--no-wipe`) for non-sensitive data. |
| `ERR_STORE_UNAUTHENTICATED`. | Missing or invalid control token. | Pass `--control-token` matching the daemon's `control_token` setting or update the configuration. |
| `ERR_STORE_PAYLOAD_REQUIRED`. | CLI sending legacy path-only requests. | Upgrade the CLI to the streaming release or run the command on the daemon host. |
| `ERR_FETCH_UNAUTHENTICATED`. | Token missing when streaming to the caller. | Supply `--control-token` so the daemon accepts the streamed download. |
| `ERR_FETCH_RATE_LIMITED`. | Too many streamed downloads in a short period. | Wait briefly before retrying or adjust the daemon's rate limits. |
| Control socket creation failure. | Another daemon bound to the port or insufficient privileges. | Stop existing instances or choose a different `--control-port`. |
| Mismatched peer IDs between restarts. | Random identity due to missing seed. | Supply `--identity-seed` or `--peer-id` for deterministic identity during automation. |
| `Failed to register manifest` errors in daemon logs. | TTL expired or manifest invalid. | Regenerate the `eph://` manifest and ensure system clocks are synchronized. |
| Remote peers time out immediately. | Port forwarding/firewall missing for TCP 47777. | Validate from outside the LAN (`nc -vz <ip> 47777`), open the port in the router or security group, or migrate to a relay/VPS. |
| Transport handshakes keep failing. | TCP 45000 (default transport port) blocked or hairpin NAT disabled. | Forward/allow TCP 45000 alongside the control port, or switch the swarm to relays (Shardian defaults use `stun.shardian.com` and `turn.shardian.com`). |
| `defaults` shows `127.0.0.1:<port>` as the first advertised endpoint even on a VPS. | NAT/STUN failed to discover a routable transport endpoint, so auto-advertise fell back to the loopback bind. | Check port-forwarding for the transport port printed at startup, re-run `eph status` for warnings, or pin `--advertise-control host[:port]` to the public hostname. Control can stay on loopback; only the transport endpoint must be reachable. |
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
