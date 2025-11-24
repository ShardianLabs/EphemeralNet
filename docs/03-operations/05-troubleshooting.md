# Troubleshooting & FAQ

Use this matrix to triage common issues before escalating. Pair it with `eph diagnostics`, structured logs, and the observability dashboard for deeper dives.

## Quick symptom matrix

| Symptom | Likely cause | Resolution |
|---------|--------------|------------|
| `Failed to contact the daemon.` | Daemon not running or CLI pointed at wrong control host/port. | Start the daemon (`eph serve`/`start`) and reuse identical global flags for management commands. |
| CLI stalls on `fetch`. | Chunk not yet replicated locally. | Wait for swarm propagation, verify peers via `eph status`, or ensure transport hints are reachable. |
| `direct-only fetch cannot proceed`. | Manifest lacks transport hints or discovery parsing failed. | Retry without `--direct-only`, or re-store with valid advertised endpoints. |
| `Transport handshake failed` / PoW errors. | Discovery hints advertise transport endpoints but PoW difficulty is too high or metadata is incomplete. | Re-store manifest with publisher metadata, lower handshake difficulty, or use `--control-fallback` to avoid transport handshake. |
| `ERR_STORE_UNAUTHENTICATED` / `ERR_FETCH_UNAUTHENTICATED`. | Missing or invalid control token. | Supply `--control-token` matching daemon config. |
| `ERR_STORE_POW_REQUIRED` / `_INVALID` / `_LOCKED`. | Missing PoW header or repeated bad submissions. | Let the CLI auto-solve or wait for lockout to clear; confirm difficulty via `eph defaults`. |
| `ERR_CONTROL_PAYLOAD_TOO_LARGE`. | Payload exceeds `--max-store-bytes`. | Raise the limit or upload a smaller file. |
| `ERR_FETCH_CHUNK_MISSING` or TTL expiry hints. | Manifest expired before replica arrived. | Re-upload with longer TTL or ensure providers stay online. |
| Secure wipe takes too long. | High `--wipe-passes` value or large payloads. | Lower pass count or disable wiping for non-sensitive data. |
| Control socket bind failure. | Port already in use or insufficient privileges. | Stop existing daemons or choose another `--control-port`. |
| Remote peers time out immediately. | Ports 47777/45000 blocked or hairpin NAT disabled. | Open/forward ports or switch to relay mode. |
| `defaults` shows `127.0.0.1` as advertised endpoint on a VPS. | STUN failed to detect a routable address. | Pin `--advertise-control` to the public hostname or rely on relay hints. |
| High fetch retries / fairness penalties. | Relay congestion or abusive peers. | Inspect relay logs, consult `tests/upload_choking*.cpp`, and tune fairness weights. |

## FAQ

| Question | Answer |
| --- | --- |
| How long do shards live? | TTL defaults to 6h (configurable). `tests/ttl_audit.cpp` verifies expirations; `eph list` exposes remaining TTL per chunk. |
| Can CGNAT peers participate? | Yes. Enable relays and NAT traversal (see `02-networking-and-relay.md`) or deploy a TURN proxy referenced via `--advertise-control`. |
| What hardware do relays need? | Start with 4 vCPU / 8 GB RAM / NVMe storage; see the performance guide for higher tiers. |
| How are abuse reports processed? | Use `eph announce abuse` (when available) plus governance workflows in `06-governance.md`. Structured logs capture outcomes for auditors. |
| PoW solver never finishes. | Check CPU headroom and time sync; inspect `pow_metrics_proxy.py`. Lower difficulty or allocate more CPU. |
| Relay logs show fairness penalties. | Consult upload choking tests and adjust `ReputationManager` weights or block abusive peers. |
| Unsure if a newer CLI exists. | Run `eph update-check` (or set `EPH_UPDATE_URL` for air-gapped mirrors) to compare against `eph.shardian.com/latest.json`. |

## Diagnostic tips

- Run the daemon in the foreground (`eph serve`) to capture verbose logs during investigation.
- Use `netstat -ano` / `ss -ltnp` to confirm ports are listening.
- Record raw control sessions with `nc 127.0.0.1 47777` when debugging automation.
- Archive `eph diagnostics` outputs whenever you open an incident; they capture NAT, relay, and advertise state.