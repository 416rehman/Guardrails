# Workspace Crate Design Notes

Every crate under `crates/` declares `[package.metadata.grdr]` (`layer`, `privilege`, `surface`, `renders`) checked continuously by `node scripts/check-architecture.mjs` against `contracts/architecture.toml`.

| Layer | Crates | Architectural Responsibility |
| --- | --- | --- |
| `0` | `grdr-proto`, `grdr-schema` | Generated Protobuf wire messages, Cedar schemas (`v1alpha1`), and embedded operational limits (`contracts/limits.toml`). |
| `1` | `grdr-compat`, `grdr-core`, `grdr-crypto`, `grdr-fastpath`, `grdr-fastpath-ffi`, `grdr-ffi`, `grdr-intel`, `grdr-llm-proto`, `grdr-mcp-proto`, `grdr-model`, `grdr-review`, `grdr-wasm` | Pure policy evaluation, sole Ed25519/SHA-256/ChaCha20-Poly1305 cryptography boundary (`grdr-crypto`), fastpath floor, FFI/WASI bindings, domain models. |
| `2` | `grdr-messages`, `grdr-ports`, `grdr-ports-testkit`, `grdr-strings`, `grdr-wire` | Hexagonal port traits (`TenantCtx`, `BlobPort`, `BusPort`, `EventsPort`), conformance testkit, IPC framing, ICU4X localization tokens. |
| `3` | `grdr-agents`, `grdr-blob`, `grdr-broker`, `grdr-bus-log`, `grdr-bus-nats`, `grdr-comply`, `grdr-export`, `grdr-identity`, `grdr-integrations`, `grdr-ipc-os`, `grdr-jobs`, `grdr-lake`, `grdr-os-clock`, `grdr-os-service`, `grdr-peer-os`, `grdr-rel-postgres`, `grdr-rel-sqlite`, `grdr-saas`, `grdr-sandbox-engine`, `grdr-sensor-linux`, `grdr-sensor-macos`, `grdr-sensor-windows`, `grdr-store-local`, `grdr-ui-model`, `grdr-update` | Storage/bus/blob/relational adapters (`grdr-bus-log`, `grdr-bus-nats`, `grdr-rel-*`), multi-cell SaaS operations (`grdr-saas`), sensors, sandbox engine, UI projection model, TUF updater. |
| `4` | `grdr`, `grdr-acp`, `grdr-approve`, `grdr-daemon`, `grdr-engine`, `grdr-hook`, `grdr-infer`, `grdr-interface-gen`, `grdr-mcp`, `grdr-proxy`, `grdr-run`, `grdr-server`, `grdr-tray`, `grdr-updater`, `grdr-uplink` | Endpoint supervisor, CLI, split Console/Operator server host, hook shim, MCP proxy, approval prompt, tray indicator, and updater binaries. |
| `tool` | `grdr-conformance`, `grdr-policy-ref`, `grdr-schema-lint` | Workspace conformance runner, policy reference generator, and Cedar schema validation tools. |

See [Workspace Crate Layers](../product/reference/_generated/crate-layers.md) for the live contract index generated from `contracts/architecture.toml`.
