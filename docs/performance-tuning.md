# Performance Tuning & Capacity Planning

This runbook helps operators size EphemeralNet deployments and adjust throttles before the swarm saturates control-plane resources.

## 1. Baseline Node Sizing

| Workload | CPU | Memory | Notes |
|----------|-----|--------|-------|
| Development / Ad-hoc testing | 1 vCPU | 1 GB RAM | Suitable for single-node smoke tests and TTL demos. |
| Bootstrap / Control node | 2 vCPU | 2 GB RAM | Handles control traffic for 100-150 peers with conservative TTL windows. |
| Swarm seeder | 4 vCPU | 4 GB RAM | Supports sustained announce/fetch activity for dense manifest catalogs. |

- Allocate 30 GB of SSD-backed storage for every 10,000 active manifests when using the persistent backend. Increase by 25% if secure wiping (`--wipe-passes > 1`) is enabled to absorb write amplification.
- Reserve at least 25% free disk to avoid fragmentation during chunk rotation and secure wipe operations.

## 2. Announce Throttling Guidance

- `--announce-interval`: Raise to 30-45 seconds on busy swarms. Keep below 60 seconds to prevent manifest visibility gaps.
- `--announce-burst`: Start at 5 (default). Lower to 3 on constrained control nodes; raise to 8 when rollout pipelines push many manifests simultaneously.
- `--announce-window`: 120 seconds pairs well with a burst of 5, ensuring fresh tokens arrive gradually instead of in spikes.
- `--announce-pow`: Set between 6 and 10 for public-facing nodes to discourage Sybil spray. Increase difficulty once CPU telemetry remains <60% utilisation.

Use `eph defaults` after changing knobs to confirm daemon acceptance. Monitor the `MANIFEST_ANNOUNCE_RATE` metric (see below) to keep the average below 60% of total capacity.

## 3. Storage & TTL Strategy

- Align `--min-ttl` and `--max-ttl` with the expected fetch cadence. For archived manifests, tighten the range (e.g., `--min-ttl 600`, `--max-ttl 7200`) to prevent stale shards from occupying storage.
- Set `--key-rotation` to at most half of `--max-ttl` so newly derived session keys propagate before chunks expire.
- For persistent deployments, mount storage on XFS or ext4 with `discard` enabled to accelerate secure wipe operations.

## 4. Network & NAT Considerations

- Leave 30% headroom on uplink bandwidth to absorb bursty uploads triggered by manifest rebalance.
- When deploying behind symmetric NAT, pre-allocate 20 TURN relays (coturn `total-quota`) per expected active peer to avoid throttling.
- Keep STUN reachability tests in CI by invoking `turnutils_uclient` every 15 minutes and alert when latency exceeds 400 ms.

## 5. Observability Checklist

Implement the following minimal dashboards/alerts:

- **Daemon availability**: Poll `eph status --control-token` and alert when the response time exceeds 2 seconds or fails twice.
- **Announce saturation**: Track `ANNOUNCE_RATE_LIMITED` counters from daemon logs. Trigger scaling when more than 5% of announces are rejected in a 10-minute window.
- **Storage churn**: Graph chunk expirations per hour. A spike usually means TTL misconfiguration or abusive uploads.
- **Key rotation drift**: Compare expected rotation cadence versus observed `key_rotation` log entries to catch stalled peers.

## 6. Capacity Planning Playbook

1. Estimate the peak manifest ingest rate (manifests/minute) and multiply by 1.5 to account for retries.
2. Choose announce throttles so that `burst / window` exceeds the projected ingest rate by ~20%.
3. Simulate the peak using the CLI (`eph store` in a loop) while tailing daemon logs to confirm rejections remain below 5%.
4. Scale vertically (CPU/RAM) when announce PoW difficulty needs to rise above 10 bits, or horizontally by adding additional control nodes behind DNS round-robin.
5. Revisit the plan quarterly or after significant workload changes.

Keep this runbook alongside your bootstrap automation so operators have quick access during incident response.
