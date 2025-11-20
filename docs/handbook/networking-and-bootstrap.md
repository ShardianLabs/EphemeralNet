# Networking and bootstrap

EphemeralNet relies on a gossip-based data plane plus a local control plane. This chapter explains the transport stack (`src/network`), DHT operations (`src/dht`), bootstrap mechanisms, NAT handling, and relay support.

## Transport sessions

- `SessionManager` binds a TCP listener (default port `45000`) and accepts inbound peers. Every connection begins with a fixed-size peer ID exchange followed by a transport handshake payload.
- Handshake payloads (`protocol::MessageType::TransportHandshake`) include the initiator's public identity scalar and a PoW nonce. The responder validates the nonce against `Config::handshake_pow_difficulty`, replies with `HandshakeAck`, and, if successful, both sides derive a ChaCha20 key via `network::KeyExchange`.
- All subsequent payloads (ANNOUNCE, REQUEST, CHUNK, ACK) are encrypted with ChaCha20; nonces are random per message. HMAC-SHA256 signatures (`protocol::encode_signed`) defend against tampering.
- `SessionManager::set_message_handler` lets `Node` register callbacks that receive decrypted `protocol::Message` objects for processing.

## Gossip and DHT

- `KademliaTable` stores peer contacts per XOR-distance bucket. Each contact carries an expiration time; sweeps ensure stale peers disappear without manual intervention.
- `Node` publishes chunk providers via ANNOUNCE messages. Each payload includes TTL, manifest URI, endpoint, assigned shard indices, and (in version 3+) the ANNOUNCE PoW nonce that satisfies `Config::announce_pow_difficulty`.
- Peers that need data issue REQUEST messages; providers respond with CHUNK payloads that embed TTL and chunk bytes.
- The DHT also stores Shamir shard records so peers can reassemble encryption keys even if they did not originate the chunk.

## Bootstrap paths

EphemeralNet offers multiple bootstrap strategies to minimise manual configuration:

1. **Hardcoded bootstrap peers** – `Config::bootstrap_nodes` ships with `bootstrap1.shardian.com` and `bootstrap2.shardian.com`. `eph start` contacts them immediately to seed the DHT.
2. **Discovery hints** – Manifests produced by the node include prioritized hints:
   - Transport entries (`scheme="transport"`, `transport="tcp"`) for direct data-plane connectivity.
   - Control entries (`scheme="control"`) for nodes that prefer to fetch through the remote daemon API.
   - Operators can pin manual hints via `--advertise-control` or config files.
3. **Fallback URIs** – After discovery hints fail, clients iterate through fallback URIs (e.g., `control://host:port`, HTTPS mirrors) before giving up.
4. **Relay channels** – When NAT traversal fails, nodes register with relay servers (default `eph-relay-server` on port `9750`). Relay endpoints are advertised so remote peers can connect even if both sides lack public addresses.

## NAT traversal

`NatTraversalManager` performs these steps whenever the node starts or periodically during `tick()`:

1. Assumes the local `transport_listen_port` is reachable (`0.0.0.0:<port>`).
2. If `nat_stun_enabled`, sends STUN binding requests to `stun.shardian.com` and `turn.shardian.com` (UDP/3478).
3. Parses XOR-MAPPED-ADDRESS attributes to discover the external IP/port, noting discrepancies between external and bound ports.
4. Records diagnostics (success/failure, reason) so `DEFAULTS`/`STATUS` can explain what will be advertised.
5. If STUN fails, logs "Relay fallback required" so operators know to enable relay endpoints or configure manual ports.

## Relay support

- `RelayClient` coordinates REGISTER/CONNECT flows with relay servers. Each registration ties the node's peer ID to a relay slot so other peers can request a tunnel through the same relay.
- The standalone relay daemon (`eph-relay-server`) uses a tiny epoll/kqueue loop (see README instructions) and is optional but recommended for symmetric NAT environments.

## Advertised endpoints

- Auto-discovered endpoints are stored in `Config::auto_advertise_candidates`. Each candidate records `host`, `port`, `via` (e.g., `stun`, `relay`, `manual`), and diagnostics.
- Manual entries (CLI `--advertise-control` or config) are marked `manual=true` so operators can tell them apart in diagnostics.
- The daemon exposes the final ordered list through `DEFAULTS`, `STATUS`, and manifest discovery hints. When conflicts exist (multiple viable addresses), `advertise_auto_mode=warn` prevents accidental publication of the wrong one.

## Fetch routing order

When the CLI processes a manifest:

1. Transport hints with the lowest priority value are attempted first. Each attempt may require solving a bootstrap PoW token if the manifest's security advisory advertises a non-zero `token_challenge_bits`.
2. If all transport hints fail and `--direct-only` is not set, control hints/fallback URIs are attempted.
3. Finally, the CLI falls back to the local daemon/DHT, which issues REQUEST messages through its existing transport sessions.

By combining deterministic bootstrap defaults, dynamic discovery hints, plus NAT/relay diagnostics, the network stack ensures nodes can form a mesh even when most participants hide behind consumer routers.
