# Governance & Acceptable Use

EphemeralNet’s bootstrap, TURN/STUN, and shared control-plane infrastructure must remain reliable without becoming an abuse vector. This policy mirrors the guidance applied to the canonical `*.shardian.com` services; adapt it to your jurisdiction and hosting agreements.

## Scope & goals

- **Covered services**: Public bootstrap/control daemons, relay infrastructure, and automation that the community relies upon for discovery.
- **Authoritative hosts**: `bootstrap1.shardian.com`, `bootstrap2.shardian.com`, `stun.shardian.com`, `turn.shardian.com`. Mirrors must meet the same uptime + abuse handling standards.
- **Audience**: Operators, incident responders, and moderators coordinating access to shared infrastructure.
- **Objectives**: Preserve availability, protect user privacy, and minimise illegal use of TTL storage.

## Acceptable use principles

1. **Ephemeral data only** – Participants must honour TTL enforcement; attempts to persist data beyond expiry violate the policy.
2. **Lawful content** – No malware, doxxing, hate speech, or otherwise illegal material.
3. **Respect throttles** – Clients must honour announce windows, PoW gates, and upload quotas.
4. **Identity hygiene** – Rotate session keys (`--key-rotation`), protect control tokens, and avoid sharing secrets publicly.
5. **Telemetry transparency** – Operators may collect aggregate metrics (announce rate, failure counters) solely for capacity planning and abuse mitigation; payload contents remain off-limits.

## Prohibited behaviour

- Flooding control endpoints beyond published quotas.
- Circumventing proof-of-work or replaying manifests to exhaust storage.
- Attempting to deanonymise peers or intercept encrypted traffic.
- Using EphemeralNet infrastructure for spam, phishing, or coordinated abuse.

## Reporting & response workflow

1. **Intake**: Route abuse reports to a dedicated mailbox or ticket queue. Capture timestamps, manifests, peer IDs, and evidence.
2. **Triage**: Within 24 hours, validate the report, replay manifests when safe, and inspect daemon logs/metrics for corroboration.
3. **Containment**: Apply countermeasures such as raising PoW difficulty, tightening announce burst/window, revoking tokens, or blacklisting peer IDs.
4. **Eradication**: Force TTL expiry on offending manifests or issue targeted cleanup commands.
5. **Recovery**: Restore baseline throttles when traffic normalises, rotate relay credentials if required, and notify affected operators.
6. **Post-incident review**: Document root cause, controls applied, and follow-up tasks in the runbook.

## Enforcement toolkit

- **Reputation system**: Use built-in scoring to demote abusive peers automatically.
- **Control tokens**: Issue per-tenant secrets and rotate them when compromised.
- **Announce throttles & PoW**: Adjust interval/burst/window and difficulty bits based on telemetry trends.
- **Blocklists**: Maintain encrypted lists of banned peer IDs/IPs, distribute via secure channels.

## Data retention & privacy

- Retain control-plane logs no longer than 30 days unless required for active investigations.
- Anonymise IPs when exporting metrics outside the immediate ops team.
- Never share raw manifests or chunk data without explicit consent or legal mandate.

## Review cadence

- Revisit this policy quarterly or after major incidents.
- Align updates with changes to performance tuning and security documentation to keep guidance consistent.

Follow this governance chapter when onboarding new infrastructure partners, responding to abuse, or designing runbooks; it ensures the swarm stays open while respecting legal and ethical boundaries.
