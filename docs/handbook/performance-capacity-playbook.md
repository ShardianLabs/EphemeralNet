# Performance and Capacity Playbook

EphemeralNet nodes operate under TTL-driven workloads with bursty uploads and constrained relay bandwidth. This playbook provides sizing heuristics and measurement techniques that extend the baseline guidelines from `docs/performance-tuning.md`.

## Sizing Reference Table

| Profile | Use Case | CPU | RAM | Storage | Expected Throughput |
| --- | --- | --- | --- | --- | --- |
| Edge relay | Light upload/fetch | 4 vCPU | 8 GB | NVMe 200 GB | 500 shards/min, ~120 Mbps |
| Regional relay | Mixed workloads | 8 vCPU | 16 GB | NVMe 500 GB | 1,500 shards/min, ~350 Mbps |
| Storage shard | Long-running TTL vault | 16 vCPU | 32 GB | NVMe 2 TB | 2,200 shards/min, ~400 Mbps |
| Bootstrap | Gossip + CLI | 4 vCPU | 8 GB | NVMe 100 GB | 50 sessions/s |

## TTL Expectations

- Default TTL is 24 hours; shorter TTLs reduce storage pressure but increase DHT churn.
- Monitor `tests/ttl_audit.cpp` outputs during load tests to estimate real-world expiration rates.

## DHT Bucket Health

- Buckets should remain 70–90% full under steady load. If they drop below 50% for longer than 10 minutes, either raise parallel fetchers or add nodes.
- `tests/dht_buckets.cpp` provides the benchmark suite used in CI.

## Relay Throughput Benchmarks

- The upload choking scheduler (`tests/upload_choking.cpp`) measures fairness under stress.
- Use `tests/upload_choking_scheduler.cpp` to capture the per-peer bandwidth distribution and confirm fairness within ±10%.

## Scaling Levers

1. **Parallel Fetch Window**: Adjust `config/fetch_window`; doubling the window increases throughput but amplifies congestion risk.
2. **Relay Pools**: Add more relay instances and rebalance shards using `ephemeralnet-cli relay rebalance`.
3. **PoW Difficulty**: Loosen difficulty during planned promotional events to accept more peers, then tighten post-event.
4. **Compression Mode**: Toggle between `lz4` and `zstd` depending on CPU headroom; check `tests/fetch_priority.cpp` for impact.

## Benchmark Procedure

1. Build with `-DENABLE_PROFILING=ON` for deeper flame graphs.
2. Run `ctest -R swarm_distribution` and `ctest -R swarm_fairness`.

## Capacity Planning Checklist

- Forecast monthly shard volume from analytics dashboards.
- Ensure at least 30% headroom in relay bandwidth during peak events.
- Keep TTL backlog below 1.5× average shard size; add storage shards if backlog persists.

## Observability Tie-In

- `docs/observability/` dashboards list Prometheus queries aligned with these metrics.
- Always correlate CLI snapshots with long-term dashboards before enacting config changes.
