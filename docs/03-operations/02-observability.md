# Observability Toolkit

Operators need continuous feedback on proof-of-work drift, announce pressure, relay saturation, and TTL guarantees. This toolkit consolidates the telemetry surfaces shipped with EphemeralNet and explains how to wire them into Prometheus, Grafana, and ad-hoc diagnostics.

## Telemetry surfaces

- **CLI snapshots**: `eph status`, `eph defaults`, `eph list`, `eph diagnostics`, and `eph ttl-audit` provide on-demand JSON or key/value snapshots. Capture them in automation to track advertised endpoints, NAT diagnostics, TTL remaining, and PoW hints.
- **Structured logs**: Running `eph serve` in the foreground prints JSON-like events (command, exit code, latency, PoW attempts). Ship them to your log pipeline to correlate with metrics.
- **Prometheus metrics**: Use `eph metrics` (or call `COMMAND:METRICS` over the control socket) to scrape gauges/counters:
  - `ephemeralnet_*_pow_difficulty_bits` for handshake/announce/store targets.
  - `ephemeralnet_handshake_pow_{success,failure}_total`, `ephemeralnet_announce_pow_{success,failure}_total`, `ephemeralnet_command_store_pow_failures_total` for drift monitoring.
  - `ephemeralnet_command_{store,fetch}_requests_total` and `_duration_seconds` histograms for saturation.
  - Storage/TTL counters such as `ephemeralnet_chunk_expirations_total`.

## Provided assets

This folder replaces the ad-hoc "Observability Toolkit" markdown with concrete assets:

| File | Purpose |
|------|---------|
| `docs/observability/pow-alerts.yml` | Prometheus alert rules that watch PoW failure ratios (warn at 5–7%, critical at 10–12%) and difficulty drift. Validate with `promtool check rules`. |
| `docs/observability/grafana-pow-dashboard.json` | Importable Grafana dashboard plotting PoW counters, difficulty gauges, and ratios. Add more panels for announce throttling or relay usage as needed. |

## Quick start

1. Copy `pow-alerts.yml` into your Prometheus `rule_files` path and reload Prometheus (HUP or HTTP reload).
2. Import the Grafana dashboard, point it at the Prometheus datasource, and adjust the dashboard variables (`job`, `instance`) to match your scrape targets.
3. Expose the daemon’s metrics endpoint securely (SSH tunnel, reverse proxy with auth) if scraping from outside localhost.
4. Combine metrics with CLI snapshots in runbooks; for example, when `ANNOUNCE_RATE_LIMITED` spikes, run `eph diagnostics` to inspect auto-advertise conflicts.

## Operational checklist

- **Alert coverage**: Ensure PoW failure alerts, announce saturation, relay fairness (upload choking counters), and chunk expiration backlog all have thresholds tied to your SLA.
- **Dashboards**: Pair the provided PoW board with storage (chunk count, TTL backlog), networking (active sessions, NAT diagnostics), and governance (abuse reports, token lockouts) panels.
- **Incident capture**: Store recent metrics/logs for at least 30 days so response teams can replay incidents per the governance guide.
- **Regression tests**: Keep `tests/pow_monitoring.cpp`, `tests/ttl_audit.cpp`, and `tests/advertise_discovery.cpp` in your CI signal; their failures often precede observability regressions.

Observability is most useful when it mirrors the architecture: control-plane snapshots explain intent, data-plane metrics quantify work, and governance logs capture policy changes. Leverage all three to keep the swarm healthy.