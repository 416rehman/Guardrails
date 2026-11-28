---
id: port-contracts
type: reference
personas:
  - extender
shapes:
  - self-hosted
  - embed
covers:
  - grdr-ports
  - grdr-compat
  - grdr-saas
owner_squad: platform
stability: beta
title: Port Contracts and Workspace Layers
---

# Port Contracts and Workspace Layers

All storage, message bus, blob store, relational metadata, job journal, sandbox, and sensor adapters live behind explicit traits in `crates/grdr-ports`.

## Layer Ordering (`contracts/architecture.toml`)

- **Layer 0 (Contracts & Wire):** `grdr-proto`, `grdr-schema`.
- **Layer 1 (Pure Core, Crypto & FFI):** `grdr-compat`, `grdr-core`, `grdr-crypto`, `grdr-fastpath`, `grdr-fastpath-ffi`, `grdr-ffi`, `grdr-intel`, `grdr-llm-proto`, `grdr-mcp-proto`, `grdr-model`, `grdr-review`, `grdr-wasm`.
- **Layer 2 (Ports & Messaging):** `grdr-messages`, `grdr-ports`, `grdr-ports-testkit`, `grdr-strings`, `grdr-wire`.
- **Layer 3 (Adapters & Operations):** `grdr-agents`, `grdr-blob`, `grdr-broker`, `grdr-bus-log`, `grdr-bus-nats`, `grdr-comply`, `grdr-export`, `grdr-identity`, `grdr-integrations`, `grdr-ipc-os`, `grdr-jobs`, `grdr-lake`, `grdr-os-clock`, `grdr-os-service`, `grdr-peer-os`, `grdr-rel-postgres`, `grdr-rel-sqlite`, `grdr-saas`, `grdr-sandbox-engine`, `grdr-sensor-linux`, `grdr-sensor-macos`, `grdr-sensor-windows`, `grdr-store-local`, `grdr-ui-model`, `grdr-update`.
- **Layer 4 (Executables under `programs/`):** `grdr`, `grdr-acp`, `grdr-approve`, `grdr-daemon`, `grdr-engine`, `grdr-hook`, `grdr-infer`, `grdr-interface-gen`, `grdr-mcp`, `grdr-proxy`, `grdr-run`, `grdr-server`, `grdr-tray`, `grdr-updater`, `grdr-uplink`.
- **Tooling (`tools/`):** `grdr-conformance`, `grdr-policy-ref`, `grdr-schema-lint`.

## Sole Cryptography Boundary

`grdr-crypto` is the sole crate permitted to invoke Ed25519, SHA-256, HMAC, or ChaCha20-Poly1305 primitives directly. Higher layers (`grdr-saas`, `grdr-lake`, `grdr-server`) call `grdr-crypto` helpers exclusively.

See [Adding a Port Adapter](../../extending/adding-a-port-adapter.md) for conformance harness requirements (`grdr-ports-testkit`).
