# EphemeralNet Handbook

This handbook aggregates the canonical documentation for EphemeralNet. It complements the architecture, protocol, and deployment guides by stitching together the full story of the TTL-based peer-to-peer filesystem so that contributors, operators, and auditors can navigate the codebase without guesswork. Each chapter below focuses on a different concern and links directly to the relevant source files and existing documents when deeper context already exists.

## Chapters

1. [System overview](system-overview.md) – design goals, roles, and control vs. data plane separation.
2. [Component guide](component-guide.md) – directory-level breakdown of the daemon, storage, transport, and support libraries.
3. [Feature catalog](feature-catalog.md) – exhaustive list of capabilities, where they live in the code, and which tests validate them.
4. [Node lifecycle](node-lifecycle.md) – step-by-step walkthroughs of `serve`, `store`, `fetch`, cleanup, and shutdown flows.
5. [Configuration reference](configuration-reference.md) – how CLI flags, config files, and defaults map to `ephemeralnet::Config`.
6. [CLI commands](cli-commands.md) – detailed help for every command, global option, responses, and diagnostics.
7. [Usage scenarios](usage-scenarios.md) – end-to-end workflows with the exact commands operators run in production.
8. [Storage and TTL](storage-and-ttl.md) – chunk ingestion, manifest creation, secure wiping, and shard management.
9. [Networking and bootstrap](networking-and-bootstrap.md) – transport sessions, DHT behavior, NAT traversal, relay usage, and swarm gossip.
10. [Security model](security-model.md) – encryption, key exchange, proof-of-work enforcement, and trust boundaries.
11. [Developer walkthrough](developer-walkthrough.md) – narrative code tour covering store/fetch pipelines and extension points.
12. [Testing and quality](testing-and-quality.md) – structure of the `tests/` tree and what each suite validates.

Existing guides such as `docs/architecture.md`, `docs/protocol.md`, `docs/deployment-guide.md`, and `docs/troubleshooting.md` remain authoritative; this handbook links back to them whenever it references the same subject.
