# Security Hardening and Threat Model

EphemeralNet keeps shard data short-lived, yet the supporting infrastructure must withstand abuse, spoofing, and targeted relay exhaustion. This document consolidates controls scattered across `security/`, `protocol_auth`, and daemon modules.

## Threat Landscape

| Vector | Description | Mitigations |
| --- | --- | --- |
| Sybil peers | Attackers announce many fake nodes to bias routing. | PoW attestation, bucket diversity checks, relay fairness throttles.
| Replay of expired manifests | Reinjecting outdated shards past TTL. | Strict timestamp validation, signature binding, TTL audit tests.
| Bootstrap poisoning | Forged gossip to steer clients toward malicious relays. | TLS mutual auth, pinned bootstrap fingerprints, gossip quorum verification.
| Abuse traffic | Flooding announce/abuse channels to exhaust moderators. | Rate limiting on abuse endpoint, structured abuse reports, automation hooks.

## Key Management

- Bootstrap nodes hold long-lived identity keys stored in HSM-backed `security/bootstrap_key.pem`.
- Relay nodes rotate signing keys every 30 days using `scripts/rotate_keys.py`; publish fingerprints via `ephemeralnet-cli announce key`.
- Peel keys for Shamir secret sharing live in `security/shamir/`; enforce restricted permissions (`chmod 600`).

## Proof-of-Work Tuning

- Default target is 120 ms per puzzle on reference hardware; adjust via `config/pow_target_ms`.
- Monitor acceptance rate in `tests/store_pow.cpp` and `pow_metrics_proxy.py`.
- When abuse surges, increase difficulty by 10–20% increments and broadcast the new value over bootstrap gossip.

## Threat Modeling Checklist

- Review new protocol features for authentication, authorization, and accounting impact.
- Update data-flow diagrams when adding relay hops or storage tiers.
- Run fuzzers (`tests/protocol_fuzz.cpp`, `tests/manifest_fuzz.cpp`) on every release candidate.
- Capture findings in `docs/handbook/security-model.md` and link back to this guide.

## Incident Response

- Retain last 30 days of PoW and relay telemetry for forensic analysis.
- Publish advisory notes on eph.shardian.com to inform third-party peers about required mitigation steps.
