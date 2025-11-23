# Configuration Reference

EphemeralNet applies settings in this order: built-in defaults (`ephemeralnet::Config`), YAML/JSON config file (`--config`), named profile (`--profile`), environment overlay (`--env`), and finally CLI flags. Later layers override earlier ones. Use this table-driven guide alongside `include/ephemeralnet/Config.hpp` when tuning nodes.

## TTL, storage, and lifecycle

| Field | Default | CLI flag / key | Notes |
|-------|---------|----------------|-------|
| `default_chunk_ttl` | 6h | `--default-ttl` | Applied when uploads omit a TTL. Clamped between `min_manifest_ttl` and `max_manifest_ttl`.
| `min_manifest_ttl` | 30s | `--min-ttl` | Requests below this fail with `ERR_TTL_BELOW_MIN`.
| `max_manifest_ttl` | 6h | `--max-ttl` | Requests above this drop to the max.
| `cleanup_interval` | 5m | profile/env only | Drives `Node::tick()` cadence.
| `storage_persistent_enabled` | false | `--persistent` / `--no-persistent` | Mirrors chunks to disk when true.
| `storage_directory` | `storage` | `--storage-dir <path>` | Base path for persisted chunks.
| `storage_wipe_on_expiry` | true | `--no-wipe` disables | Overwrites expired files `storage_wipe_passes` times.
| `storage_wipe_passes` | 1 | `--wipe-passes <1-255>` | Number of overwrite passes.
| `key_rotation_interval` | 5m | `--key-rotation <seconds>` | Session key refresh cadence.

## Control plane & CLI interaction

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `control_host` | `127.0.0.1` | `--control-host`, `--control-loopback`, `--control-expose` | Bind address for daemon. `--control-expose` binds `0.0.0.0` with a confirmation prompt unless `--yes`.
| `control_port` | 47777 | `--control-port` | TCP port for the control socket.
| `control_token` | unset | `--control-token <secret>` | Shared secret validated per connection.
| `control_stream_max_bytes` | 32 MiB | `--max-store-bytes` | Upper bound for `PAYLOAD-LENGTH`.
| `max_entries_per_list` | impl-defined | config only | Cap the number of rows returned by `LIST` to keep automation snappy.

## Data plane, NAT, and relay

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `transport_listen_port` | 45000 | `--transport-port` | TCP listener for encrypted peer traffic.
| `nat_stun_enabled` | true | profile/env | Enables STUN probes against `stun.shardian.com` / `turn.shardian.com`.
| `advertise_control_host` | unset | `--advertise-control host:port` | Forces manual control endpoint hints in manifests.
| `advertise_allow_private` | false | `--advertise-allow-private` | Publish RFC1918 endpoints when true.
| `advertise_auto_mode` | `on` | `--advertise-auto on|warn|off` | Control transport auto-publishing behaviour.
| `advertised_endpoints` | [] | config only | Static endpoint list always inserted into manifests.
| `relay_enabled` | true | profile/env | Toggles relay fallback.
| `relay_endpoints` | `[relay.shardian.com:9750]` | `--relay-endpoint host:port` (repeatable) | Additional TURN-like relays for stubborn NATs.

## Proof-of-work & swarm tuning

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `announce_pow_difficulty` | 6 | `--announce-pow <0-24>` | Bits required for ANNOUNCE messages.
| `handshake_pow_difficulty` | 4 | config only | Bits required for transport handshakes.
| `store_pow_difficulty` | 6 | config / `DEFAULTS` | Bits required for uploads; CLI auto-solves.
| `swarm_target_replicas` | 3 | config only | Desired replicas per chunk.
| `swarm_min_providers` | 2 | config only | Minimum healthy providers before fetch commands consider the chunk satisfied.
| `swarm_candidate_sample` | 8 | config only | Sample size passed to the DHT when picking replica targets.
| `swarm_rebalance_interval` | 30m | config only | Interval for manifest re-announcement.
| `announce_min_interval` | 15s | `--announce-interval` | Lower bound between ANNOUNCE transmissions.
| `announce_burst_limit` | 4 | `--announce-burst` | Max announcements per rolling window.
| `announce_burst_window` | 120s | `--announce-window` | Window paired with the burst limit.

## Chunk sharding & cryptography

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `shard_threshold` | 3 | profile/env | Shares required to reconstruct the key.
| `shard_total` | 5 | profile/env | Total shares emitted per chunk.
| `protocol_message_version` | 0 | internal | Highest gossip message version the daemon emits.
| `protocol_min_supported_version` | 1 | internal | Lower bound accepted during decoding.

## Fetch/upload concurrency

| Field | Default | CLI flag / key | Description |
|-------|---------|----------------|-------------|
| `fetch_max_parallel_requests` | 3 | `--fetch-parallel` | Maximum concurrent remote fetch attempts (`0` = unlimited).
| `fetch_retry_attempt_limit` | 5 | config only | Cap on retries before marking a fetch failed.
| `fetch_retry_initial_backoff` | 3s | config only | Starting back-off for retries.
| `fetch_retry_max_backoff` | 60s | config only | Back-off ceiling.
| `upload_max_parallel_transfers` | 3 | `--upload-parallel` | Concurrent uploads allowed per node.
| `upload_max_transfers_per_peer` | 1 | config only | Prevents peers from monopolising bandwidth.
| `upload_transfer_timeout` | 30s | config only | Cancels stalled uploads.

