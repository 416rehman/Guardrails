---
id: ref-surfaces-and-support
type: reference
personas:
  - operator
  - extender
shapes:
  - self-hosted
  - hosted
covers:
  - surfaces
  - support-matrix
owner_squad: release
stability: beta
generated: true
title: Public Surfaces and Support Matrix
---

# Public Surfaces and Support Matrix

Generated automatically from `contracts/surfaces.toml` and `contracts/support.toml`.

## Support Policy Bounds

- Release cadence: "monthly"
- Supported minors behind: 2
- Max direct upgrade hop: 2
- Rollback window minors: 1
- Sensor skew tolerance: -2 / +1 minors
- PostgreSQL major tier 1: 18
- Supported Kubernetes versions: ["1.35", "1.36", "1.37"]

## Registered Surfaces (52)

| ID / Kind | Stability | Path |
| --- | --- | --- |
| `grdr-proto` | `experimental` | `Generated protobuf wire and contract messages (contracts/proto/grdr/*).` |
| `grdr-schema` | `experimental` | `Embedded Cedar schemas (v1alpha1), operational limits loader, and validation contracts.` |
| `grdr-model` | `experimental` | `Domain vocabulary, LogSafe data classification, verdicts, and policy signing extensions.` |
| `grdr-core` | `experimental` | `Pure evaluation, session state, fastpath compilation, and audit chain verification; Cedar types tracked.` |
| `grdr-crypto` | `experimental` | `Sole workspace consumer of sha2, ed25519-dalek, chacha20poly1305, and getrandom.` |
| `grdr-fastpath` | `experimental` | `no_std floor evaluator and bounded field scanner.` |
| `grdr-fastpath-ffi` | `experimental` | `C ABI fastpath entrypoints.` |
| `grdr-ffi` | `experimental` | `C ABI JSON engine facade.` |
| `grdr-wasm` | `experimental` | `WebAssembly target binding for pure policy evaluation.` |
| `grdr-compat` | `experimental` | `Protocol and bundle compatibility range resolver.` |
| `grdr-llm-proto` | `experimental` | `Model-provider metadata extraction without raw prompt retention.` |
| `grdr-mcp-proto` | `experimental` | `MCP JSON-RPC 2.0 frame parsing and structural argument inspection.` |
| `grdr-review` | `experimental` | `Sans-IO review queue scoring and bounded judge output schema.` |
| `grdr-intel` | `experimental` | `Threat intelligence restrict-only PackKind::Intel validator, 24-bit fuse index, codecs, and k=5 sightings.` |
| `grdr-ports` | `experimental` | `TenantCtx, clock, blob, bus, events, jobs, and relational port traits.` |
| `grdr-ports-testkit` | `experimental` | `In-memory conformance suite and adapters for port implementers.` |
| `grdr-wire` | `experimental` | `IPC/uplink framing, Ed25519 envelopes, and replay protection.` |
| `grdr-strings` | `experimental` | `ICU4X localization runtime and MessageFormat2 token formatting.` |
| `grdr-messages` | `internal` | `Generated typed language token accessors from contracts/interface/.` |
| `grdr-ui-model` | `experimental` | `Desktop/tray view-models and intents over MessageRef tokens.` |
| `grdr-approve` | `experimental` | `OS-native out-of-band and local step-up approval prompt binary.` |
| `grdr-tray` | `experimental` | `Status indicator tray client binary.` |
| `protocol:wire` | `experimental` | `crates/grdr-wire (1)` |
| `protocol:cedar_schema` | `experimental` | `contracts/cedar/v1alpha1.cedarschema (grdr.cedar.v1alpha1)` |
| `protocol:limits` | `experimental` | `contracts/limits.toml (grdr.limits.v1alpha1)` |
| `proto:common.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:entity.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:event.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:decision.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:finding.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:assurance.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:inventory.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:feed.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:export.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:decide.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:local.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:provider.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:identity.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:ingest.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:fleet.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:bootstrap.v1` | `experimental` | `contracts/proto/grdr` |
| `proto:embed.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:operator.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.activity.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.inventory.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.operator.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.overview.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.policy.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.response.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.surfaces.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.tenancy.v1alpha1` | `experimental` | `contracts/proto/grdr` |
| `proto:api.verdict.v1alpha1` | `experimental` | `contracts/proto/grdr` |
