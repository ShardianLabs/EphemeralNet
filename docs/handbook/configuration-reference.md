# Configuration reference

EphemeralNet loads settings in this order: built-in defaults (`ephemeralnet::Config`), YAML/JSON config file (`--config`), named profile (`--profile`), environment overlay (`--env`), and finally CLI flags. Later layers override earlier ones. This chapter enumerates the most important fields in `include/ephemeralnet/Config.hpp` and how to tune them.

## TTL, storage, and lifecycle

| Config field | Default | CLI flag / key | Notes |
|--------------|---------|----------------|-------|
| `default_chunk_ttl` | `6h` | `--default-ttl` | Applied to new chunks that do not request a TTL. Clamped between `min_manifest_ttl` and `max_manifest_ttl` by `Node::sanitize_config`.
| `min_manifest_ttl` | `30s` | `--min-ttl` | Lower bound for any manifest/STORE request. Requests below this fail with `ERR_TTL_BELOW_MIN`.
| `max_manifest_ttl` | `6h` | `--max-ttl` | Upper bound; requests above it are truncated.
| `cleanup_interval` | `5m` | `--cleanup-interval` (profile only) | Drives `Node::tick()` sweeps and secure wiping cadence.
| `storage_persistent_enabled` | `false` | `--persistent` / `--no-persistent` | Enables disk-backed chunks under `storage_directory`.
| `storage_directory` | `storage` | `--storage-dir <path>` | Base path for persisted chunks.
| `storage_wipe_on_expiry` | `true` | `--no-wipe` (disables) | When enabled, expired persisted chunks are overwritten `storage_wipe_passes` times before deletion.
| `storage_wipe_passes` | `1` | `--wipe-passes <1-255>` | Number of overwrite passes during secure wipe.
| `key_rotation_interval` | `5m` | `--key-rotation` | Governs how often `SessionManager` rotates ChaCha20 keys and drops aged sessions.

## Control plane and CLI interaction

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `control_host` | `127.0.0.1` | `--control-host`, `--control-loopback`, `--control-expose` | Host interface for the daemon. `--control-expose` binds `0.0.0.0` with confirmation.
| `control_port` | `47777` | `--control-port` | TCP port for the control socket.
| `control_token` | `nullopt` | `--control-token <secret>` | Optional shared secret validated per connection (constant-time compare).
| `control_stream_max_bytes` | `32 MiB` | `--max-store-bytes <bytes>` | Maximum `PAYLOAD-LENGTH` accepted for STORE/FETCH streaming.
| `announce_interval` | `15m` | `--announce-interval` | Deprecated by `announce_min_interval` but still populated for backwards compatibility.
| `default_chunk_ttl` | `6h` | `--default-ttl` | Mentioned above; also surfaced via `DEFAULTS`.

## Data plane: transport, NAT, relay

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `transport_listen_port` | `45000` | `--transport-port` | TCP listener used by `SessionManager` for encrypted peer traffic.
| `nat_stun_enabled` | `true` | `--nat-stun` / `--no-nat-stun` (profile) | If true, `NatTraversalManager` probes `stun.shardian.com`/`turn.shardian.com` for external IP hints.
| `advertise_control_host` | unset | `--advertise-control <host:port>` | Manual control endpoint pinned into manifests/discovery hints.
| `advertise_control_port` | unset | `--advertise-control-port` | Optional port override when only the host changes.
| `advertise_allow_private` | `false` | `--advertise-allow-private` | Publish RFC1918 endpoints when true.
| `advertise_auto_mode` | `On` | `--advertise-auto <on|warn|off>` | Governs whether auto-discovered transport endpoints are published, only published when unambiguous (`warn`), or suppressed.
| `advertised_endpoints` | empty | Config only | Static list of endpoints that will always be inserted into manifests (marked `manual=true`).
| `relay_enabled` | `true` | `--relay` / `--no-relay` (profile) | Toggle relay fallback.
| `relay_endpoints` | `[ {host:"relay.shardian.com",port:9750} ]` (from config file) | `--relay-endpoint host:port` | Additional TURN-like relays for `RelayClient`.
| `nat_upnp_start_port` / `nat_upnp_end_port` | `45000-45099` | Config only | Reserved for future UPnP integration.

## Proof-of-work and swarm tuning

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `announce_pow_difficulty` | `6` | `--announce-pow <0-24>` | Bits required for ANNOUNCE messages; validated by peers before accepting gossip.
| `handshake_pow_difficulty` | `4` | Config only | Difficulty enforced when establishing transport sessions.
| `store_pow_difficulty` | `6` | Advertised via `DEFAULTS`; CLI auto-solves and sends `STORE-POW`. Set via config or future flag.
| `swarm_target_replicas` | `3` | Config only | Number of providers `SwarmCoordinator` aims for.
| `swarm_min_providers` | `2` | Config only | Minimum peers before chunk distribution is considered healthy.
| `swarm_candidate_sample` | `8` | Config only | Sample size passed to `KademliaTable::closest_peers` when planning replication.
| `swarm_rebalance_interval` | `30m` | Config only | How often the node reconsider assignments and reannounce manifests.
| `announce_min_interval` | `15s` | `--announce-interval` (new behaviour) | Lower bound between ANNOUNCE transmissions.
| `announce_burst_limit` | `4` | `--announce-burst` | Max announcements within `announce_burst_window`.
| `announce_burst_window` | `120s` | `--announce-window` | Window used alongside the burst limit.

## Chunk sharding and crypto

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `shard_threshold` | `3` | `--shard-threshold` (profile) | Minimum shards required to reconstruct the ChaCha20 key. Node publishes `threshold` in manifests and DHT shard records.
| `shard_total` | `5` | `--shard-total` (profile) | Total number of Shamir shares emitted per chunk.
| `protocol_message_version` | `0` | Internal | Upper bound accepted by the daemon while serializing ANNOUNCE packets.
| `protocol_min_supported_version` | `1` | Internal | Lower bound accepted during decode (`protocol::is_supported_message_version`).

## Fetch/upload concurrency

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `fetch_max_parallel_requests` | `3` | `--fetch-parallel` | Max simultaneous remote fetch attempts issued by the CLI and the daemon when pulling replicas.
| `fetch_retry_attempt_limit` | `5` | Config only | Maximum retries before giving up on a fetch.
| `fetch_retry_initial_backoff` | `3s` | Config only | Base backoff when peers do not respond.
| `fetch_retry_max_backoff` | `60s` | Config only | Cap for exponential backoff.
| `upload_max_parallel_transfers` | `3` | `--upload-parallel` | Concurrent uploads allowed per node.
| `upload_max_transfers_per_peer` | `1` | Config only | Prevents any peer from monopolizing the node.
| `upload_transfer_timeout` | `30s` | Config only | Duration after which stalled uploads are cancelled.

For exhaustive CLI syntax (aliases, validation rules, and behavioural notes), keep `docs/cli-command-reference.md` handy—this chapter simply explains where those knobs land inside the code.
