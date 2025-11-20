# Integration Cookbook

A collection of lightweight recipes for embedding EphemeralNet capabilities into external applications, SDKs, or workflows.

## REST/Gateway Integration

- Deploy a thin gateway that invokes `ephemeralnet-cli` commands or links directly against the daemon API.
- Expose endpoints such as `/publish`, `/fetch`, and `/status`, translating HTTP payloads to CLI flags.
- Use asynchronous job IDs to represent long-running fetches; poll or webhooks inform the client when TTL-bound data is ready.

## gRPC Service Wrapper

- Define proto services mirroring CLI flows:
  - `BootstrapService.Verify`
  - `ManifestService.Publish`
  - `RelayService.Stats`
- Stream manifest upload progress and PoW updates through server-side streaming responses.

## SDK Snippets

```cpp
EphemeralClient client("bootstrap1.shardian.com", 38080);
Manifest manifest = client.CreateManifest("./payload", 86400);
client.Publish(manifest);
```

```python
from ephnet import Client
client = Client.from_env()
client.fetch(manifest_id, output_dir="./downloads")
```

## Manifest Schema Embedding

- Import the JSON schema from `docs/protocol.md` into a validation library (AJV, rapidjson schema).
- Validate manifests before publishing to prevent rejections and reduce retries.

## Event-Driven Workflows

- Connect EphemeralNet events (publish success, shard expiration) to message buses like Azure Event Grid or Kafka.
- Use `ephemeralnet-cli control watch --stream` to output JSON events and feed them into automation pipelines.

## Compliance and Auditing Hooks

- Mirror manifest metadata into a compliance database with TTL aligned to organizational policy.
- Leverage `tests/persistent_storage.cpp` patterns for verifying deletion after TTL expiry.

## Testing Integrations

- Embed integration tests alongside existing suites (`tests/cli_control_flow.cpp`) to ensure wrappers stay compatible.
- Mock PoW responses for faster test runs, but always run full end-to-end suites (`tests/multi_node_integration.cpp`) before releases.
