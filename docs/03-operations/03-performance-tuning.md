# Performance Tuning & Capacity Planning

This runbook merges the baseline tuning guide with the capacity playbook so operators can size clusters, interpret telemetry, and adjust throttles before the swarm hits saturation.

## Baseline node sizing

| Profile | Use case | CPU | RAM | Storage | Notes |
|---------|----------|-----|-----|---------|-------|
| Dev / smoke tests | Single-node demos | 1 vCPU | 1 GB | 10 GB SSD | Great for TTL demos and CI runs. |
| Bootstrap / control | 100–150 peers | 2 vCPU | 2 GB | 50 GB SSD | Keep announce throttles conservative. |
| Swarm seeder | Heavy announce/fetch | 4 vCPU | 4 GB | 120 GB SSD | Allows frequent manifest rotations. |
| Edge relay | Light relay workloads | 4 vCPU | 8 GB | 200 GB NVMe | ~500 shards/min, ~120 Mbps. |
| Regional relay | Mixed workloads | 8 vCPU | 16 GB | 500 GB NVMe | ~1,500 shards/min, ~350 Mbps. |
| Storage shard | Long TTL vault | 16 vCPU | 32 GB | 2 TB NVMe | ~2,200 shards/min, ~400 Mbps. |

Guidance:
- Reserve at least 25% free disk to absorb secure wipe amplification.
- Budget 30 GB per 10,000 active manifests when persistence is enabled.
- Keep TTL windows aligned with workload (e.g., `--min-ttl 600 --max-ttl 7200` for rapid turnover).

## Announce throttling & PoW

- `--announce-interval`: default 15 s. Raise to 25–40 s on busy swarms but keep below 60 s to avoid manifest visibility gaps.
- `--announce-burst`: default 4. Lower to 3 on constrained control nodes; raise to 6 when releasing many manifests simultaneously.
- `--announce-window`: default 120 s; pair with the burst limit to shape traffic.
- `--announce-pow`: default 6 bits. Increase to 8–10 when CPU headroom exists; lower temporarily during promotional events.
- Monitor `ephemeralnet_announce_pow_{success,failure}_total` and log fields such as `ANNOUNCE_RATE_LIMITED` to decide when to scale.

## Storage, TTL, and key rotation strategy

- Align `--key-rotation` with TTL bounds (no more than half of `--max-ttl`) so peers rotate keys before chunks expire.
- Persistent nodes should use XFS or ext4 with `discard` enabled to accelerate secure wipe operations.
- Tighten TTL ranges for audit-heavy environments to reduce stale storage.
- Run `eph list` and `ttl-audit` routinely; spikes in expiration backlog often indicate mis-sized TTLs or stuck `tick()` loops.

## Network & NAT considerations

- Leave 30% headroom on uplink bandwidth for bursty uploads triggered by manifest rebalance.
- Behind symmetric NAT, pre-allocate at least 20 relay slots per active peer (coturn `total-quota`).
- Use `tests/nat_traversal.cpp` and `turnutils_uclient` to monitor STUN latency; alert when latency exceeds 400 ms.
- Document relay credentials and retention policy so governance teams understand metadata exposure.

## Relay & upload fairness

- The upload choking scheduler (`tests/upload_choking.cpp` / `tests/upload_choking_scheduler.cpp`) validates fairness within ±10%. Run it after tweaking relay capacity or QoS rules.
- Track relay penalties via `ReputationManager` counters to detect leechers early.

## Capacity planning playbook

1. Forecast peak manifest ingest rate (manifests/minute) and multiply by 1.5 for retries.
2. Choose announce throttles (`burst / window`) that exceed the projected ingest rate by ~20%.
3. Simulate the peak with looped `eph store` commands while tailing daemon logs; confirm rejects stay <5%.
4. Scale vertically when ANNOUNCE PoW exceeds ~10 bits or CPU >70%; scale horizontally by adding control nodes behind DNS.
5. Revisit sizing quarterly or after major workload shifts.

## Proof-of-work monitoring workflow

1. Scrape `ephemeralnet_*_pow_difficulty_bits` (authoritative values) and corresponding success/failure counters.
2. If failure ratios exceed 5–7% for 10+ minutes, lower the relevant difficulty by one bit or add CPU. If ratios stay below 1%, consider tightening difficulty to deter Sybil attempts.
3. Use `pow_metrics_proxy.py` for ad-hoc solver benchmarking, and integrate alert rules from `docs/observability/pow-alerts.yml`.
4. Document chosen thresholds inside runbooks so teams understand why PoW bits changed.

## Observability tie-in

- Pair Prometheus dashboards with CLI sampling scripts that capture `status`, `defaults`, and `diagnostics` every few minutes; correlate spikes with config changes.
- Alert on `ephemeralnet_command_store_pow_failures_total` and `ephemeralnet_fetch_retry_total` to catch abuse or relay outages quickly.
- Keep `tests/performance_*`, `tests/swarm_distribution.cpp`, and `tests/swarm_fairness.cpp` in your CI gate—they catch regressions before they hit production.

Use this playbook whenever you spin up a new tier, respond to an incident, or revisit governance limits; it encodes the empirical defaults used across Shardian’s reference deployments.
