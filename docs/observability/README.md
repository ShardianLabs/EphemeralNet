# Proof-of-Work Monitoring Toolkit

This folder ships a ready-to-use reference for operators that want automated visibility into EphemeralNet proof-of-work behaviour.

## Contents

- `pow-alerts.yml`: Prometheus alerting rules that watch handshake, announce, and store proof-of-work failure ratios and difficulty drifts. Drop the file into your Prometheus `rule_files` list (or add it to the configuration management template) and reload the server. The rules trigger warnings at 5–7% failure rates and escalate to critical if failures exceed 10–12%.
- `grafana-pow-dashboard.json`: Grafana dashboard definition that plots proof-of-work counters, failure ratios, and the currently advertised difficulty bits. Import it via **Dashboards → Import** and select your Prometheus datasource when prompted.

## Quick Start

1. Copy `pow-alerts.yml` into the directory referenced by the `rule_files` stanza in your Prometheus configuration (for example `/etc/prometheus/rules`).
2. Run `promtool check rules pow-alerts.yml` to validate the syntax, then reload Prometheus (`kill -HUP $(pidof prometheus)` on Linux or use the administrative API).
3. Import `grafana-pow-dashboard.json` into Grafana. Set the `Datasource` variable to the Prometheus instance that scrapes your EphemeralNet daemon's `METRICS` endpoint.
4. Set up Grafana alerting or hook the Prometheus alerts into your paging system (PagerDuty, OpsGenie, Slack, etc.).

## Customisation

- Tweak the failure thresholds in `pow-alerts.yml` to match your SLA. The defaults align with the tuning guidance in `docs/performance-tuning.md`.
- If you run multiple daemons, add a `job` or `instance` label filter to the expressions so the alerts scope to the relevant subset.
- Extend the dashboard with additional panels (for example, plotting CPU load or announce lockout counters) to capture the broader operational picture.
