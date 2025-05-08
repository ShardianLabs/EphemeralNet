# Governance & Acceptable Use Policy

This document defines the operating guidelines for EphemeralNet bootstrap, STUN/TURN, and control-plane infrastructure when exposed to untrusted peers. Operators should tailor the parameters to their legal jurisdiction and hosting agreement while preserving the security objectives outlined here.

## 1. Scope

- **Covered services**: Public bootstrap/control daemons, TURN/STUN relays, and supporting automation that the community relies upon for discovery and traversal.
- **Audience**: Infrastructure operators, incident responders, and community moderators coordinating access to EphemeralNet resources.
- **Goals**: Maintain availability, protect user privacy, and minimise the risk of abuse or illegal content distribution through shared services.

## 2. Acceptable Use

1. **Ephemeral data only**: Participants must respect TTL enforcement and refrain from attempting to persist content beyond the advertised expiration.
2. **No harmful content**: Distribute only lawful data. Malware, doxxing, hate speech, or other prohibited material violates the AUP.
3. **Rate-limit observance**: Clients must honour announce throttles, proof-of-work challenges, and upload quotas configured by operators.
4. **Identity hygiene**: Nodes should rotate session keys regularly (`--key-rotation`) and avoid sharing control tokens publicly.
5. **Telemetry transparency**: Operators may collect aggregate metrics (announce rate, failure counters) strictly for capacity planning and abuse mitigation. Raw payload data must not be retained.

## 3. Prohibited Behaviour

- Flooding control endpoints (announce, store, fetch) beyond published quotas.
- Circumventing proof-of-work or replaying manifests to exhaust storage.
- Attempting to deanonymise peers or intercept encrypted traffic.
- Using EphemeralNet infrastructure for spam, phishing, or coordinated attacks.

## 4. Reporting & Response Workflow

1. **Intake**: Route abuse reports to a dedicated email (e.g., `abuse@ephemeralnet.example`) or ticket queue. Capture timestamps, peer IDs, manifests, and evidence.
2. **Triage**: Within 24 hours, validate the report, replay manifests where safe, and inspect daemon logs for corroboration.
3. **Containment**: Apply countermeasures such as:
   - Temporarily raising `--announce-pow` or tightening burst/window values.
   - Revoking control tokens or rotating shared TURN secrets.
   - Blacklisting offending peer IDs via reputation penalties and blocklists.
4. **Eradication**: Purge offending manifests by forcing TTL expiry or issuing targeted cleanup commands.
5. **Recovery**: Restore baseline throttles once traffic normalises, and notify affected operators.
6. **Post-incident review**: Document root cause, effectiveness of countermeasures, and follow-up actions in the runbook.

## 5. Enforcement Toolkit

- **Reputation system**: Leverage the node's built-in reputation tracking to demote abusive peers automatically.
- **Control tokens**: Require per-tenant tokens and rotate them when compromised.
- **Announce throttles**: Adjust interval, burst, window, and PoW difficulty based on telemetry trends.
- **Blocklists**: Maintain an encrypted list of offending peer IDs/IPs distributed to operators over secure channels.

## 6. Data Retention & Privacy

- Store control-plane logs for no longer than 30 days unless required for active investigations.
- Anonymise IP addresses when exporting metrics beyond the immediate ops team.
- Do not share raw manifests or chunk data without explicit user consent or legal requirement.

## 7. Review Cadence

- Revisit this policy at least quarterly or after any major incident.
- Align changes with updates to the performance tuning and security runbooks to keep documentation consistent.

By adhering to this governance and AUP framework, operators can strike a balance between openness and accountability while preserving the ephemeral design goals of the network.
