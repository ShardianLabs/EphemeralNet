# FAQ and Troubleshooting Matrix

A quick-reference companion to `docs/troubleshooting.md`, tailored for operator support and community moderators.

## Frequently Asked Questions

| Question | Answer |
| --- | --- |
| How long do shards live? | TTL defaults to 24 hours but can be set per manifest; TTL compliance is enforced by `tests/ttl_audit.cpp` and daemon logic.
| Can peers behind CGNAT participate? | Yes, via relay mode and NAT traversal helpers; follow `docs/handbook/networking-and-bootstrap.md`.
| What hardware does a basic relay require? | 4 vCPU, 8 GB RAM, NVMe storage (see Performance Playbook for tiers).
| How are abuse reports processed? | Through `ephemeralnet-cli announce abuse`; outcomes are logged in `ops/bootstrap/abuse-report.json`.

## Troubleshooting Matrix

| Symptom | Diagnostic Steps | Resolution |
| --- | --- | --- |
| CLI cannot reach bootstrap | `ping bootstrap1.shardian.com` (already in use) or `ephemeralnet-cli bootstrap verify`; check DNS and firewall rules. | Update hosts file if required; ensure UDP `38081` is open.
| High fetch retries | Run `ctest -R fetch_retry` in staging; inspect relay logs for congestion. | Reduce fetch window or add relay capacity as described in the Performance Playbook.
| Manifest validation fails | `ephemeralnet-cli manifest verify --manifest <file>`; compare schema version with `docs/protocol.md`. | Regenerate manifest using the latest CLI or upgrade nodes per the Upgrade Guide.
| PoW solver never completes | Check system clock sync and CPU availability; tail `pow_metrics_proxy.py`. | Adjust PoW difficulty or allocate more CPU cores.
| Relay logs show fairness penalties | Inspect `tests/upload_choking.cpp` outputs and relay stats. | Tune fairness weights or investigate abusive peers via the Security Hardening guide.
