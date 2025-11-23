# Security Model and Threat Response

EphemeralNet assumes untrusted peers, intermittent relays, and adversaries willing to brute-force proof-of-work. This chapter consolidates the identity, transport, PoW, and operational hardening controls that keep TTL guarantees intact.

## Identities and key material

- **Peer IDs**: 32-byte values derived from SHA-256 of the deterministic identity scalar. `Node::generate_identity_scalar()` seeds a RNG (optional `--identity-seed`) and computes the Diffie-Hellman public key via `network::KeyExchange::compute_public`.
- **Session keys**: Derived from the shared Diffie-Hellman scalar and hashed with SHA-256 to obtain a 256-bit ChaCha20 key per session.
- **Key rotation**: `Node::tick()` asks `SessionManager` to tear down sessions every `key_rotation_interval` (default 5 minutes) so long-lived peers must re-handshake and refresh entropy.

## Transport confidentiality and authenticity

- All transport payloads (ANNOUNCE/REQUEST/CHUNK/ACK) are encrypted with ChaCha20 using per-message random nonces.
- HMAC-SHA256 signatures appended by `protocol::encode_signed` guarantee tamper detection before decoding.
- Transport handshakes are authenticated by both proof-of-work and knowledge of the shared secret derived from Diffie-Hellman.

## Proof-of-work controls

| Surface | Default bits | Purpose |
|---------|--------------|---------|
| Transport handshake | 4 | Ensure initiators spend CPU before opening a session. |
| ANNOUNCE gossip | 6 | Make routing-table poisoning expensive.
| STORE uploads | 6 | Gate high-volume uploads; CLI auto-solves and sends `STORE-POW`. |

- Bits are configurable via `Config` / CLI flags and exposed through `eph defaults` + Prometheus gauges (`ephemeralnet_*_pow_difficulty_bits`).
- Store failures map to `ERR_STORE_POW_REQUIRED`, `ERR_STORE_POW_INVALID`, or `ERR_STORE_POW_LOCKED`; handshake/announce failures increment telemetry counters for alerting.
- When abuse spikes, raise bits gradually (10–20% CPU impact increments) and broadcast the new difficulty through bootstrap gossip.

## Control-plane protections

- Optional `control_token` requires constant-time secret comparison per connection.
- Rate limiters cap `STORE`/`FETCH` bursts; repeated throttling events surface in structured logs and metrics.
- Payload limits (`--max-store-bytes`) prevent unbounded uploads; the daemon validates size before reading the body.
- Structured logging avoids printing secrets while still surfacing PoW attempts, NAT diagnostics, and governance events.

## Data at rest

- Chunk bytes remain encrypted until delivered to the CLI. Persistent mode mirrors ciphertext to disk and wipes files on expiry.
- Secure wiping overwrites files a configurable number of passes (`--wipe-passes`, default 1). Operators can disable wiping for non-sensitive workloads (`--no-wipe`).
- Manifests only embed filenames when the CLI uploads from disk; automation can toggle filename use via `--fetch-ignore-manifest-name`.

## Threat landscape & hardening checklist

| Vector | Description | Mitigations |
| --- | --- | --- |
| Sybil peers | Attackers flood the DHT with fake identities. | ANNOUNCE PoW, bucket diversity checks, relay fairness throttles. |
| Replay of expired manifests | Attempting to resurrect stale shards past TTL. | Strict timestamp validation, TTL audits, manifest withdrawal. |
| Bootstrap poisoning | Forged gossip to steer clients to malicious relays. | TLS for bootstrap control endpoints, pinned fingerprints, gossip quorum verification. |
| Abuse floods | Exhaust announce or abuse-report channels. | Rate limiting, structured abuse reports, operator automation. |

Hardening actions:

- Keep bootstrap and relay identity keys in HSM-backed storage; rotate relay signing keys every 30 days and publish fingerprints.
- Monitor PoW acceptance via `pow_metrics_proxy.py` and Prometheus counters; adjust difficulty when failure ratios exceed 5–7% for 10+ minutes.
- Run fuzzers (`tests/protocol_fuzz.cpp`, `tests/manifest_fuzz.cpp`) on every release candidate.
- Capture findings in this guide and link from runbooks so operational knowledge stays current.

## Incident response workflow

1. **Intake** abuse reports through a dedicated channel (`abuse@…`) capturing timestamps, manifests, peer IDs, and evidence.
2. **Triage** within 24 hours by replaying manifests (when safe) and correlating with daemon logs.
3. **Contain** by raising PoW difficulty, tightening announce bursts, revoking control tokens, or applying reputation penalties.
4. **Eradicate** by forcing TTL expiry on offending manifests and purging related DHT entries.
5. **Recover** by restoring baseline throttles once traffic normalises and communicating outcomes to stakeholders.
6. **Review**: document root cause, update configuration baselines, and feed lessons learned back into governance + observability docs.

By binding cryptographic identity, transport encryption, PoW, and governance playbooks together, EphemeralNet stays resilient even when peers behave maliciously or infrastructure must operate in hostile environments.
