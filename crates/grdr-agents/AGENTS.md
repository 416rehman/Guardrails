# grdr-agents

layer: 3   privilege: none   renders: none
surface: internal   squad: adapters   trust core: no
stability: not applicable (internal crate)
design: docs/design/03-system-architecture-and-modularity.md section 2; docs/design/07-control-points-and-hook-broker.md section 6; notes: none (internal crate)

## Purpose
Per-agent installers, managed-source probes and structural dialect translators (design/03 section 2). Hook payloads are parsed here and never in `grdr-hook` (ARCH-004).

## Invariants
- Dependency edges: Layers 0 to 2 only (`grdr-core`, `grdr-crypto`, `grdr-model`, `grdr-schema`). Same-layer edges in `architecture.toml`: none (`ARCH-002`).
- No panic path in non-test code: inherits `[lints] workspace = true` (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unsafe_code = "forbid"`).
- No `unsafe`: enforced via `#![forbid(unsafe_code)]`; OS process enumeration is injected via `ProcessSnapshotSource` from Layer 4 callers (`grdr-peer-os`).
- Formats no text a person or an agent reads (`renders = "none"`).
- Event names, tool names, matchers, routes, dialects, and SDKs are manifest data in `packs/catalogue/` and `packs/building-blocks/`, never hardcoded in Rust (`P14`).

## Allowed dependencies
Layers 0 to 2. Same-layer edges in `architecture.toml`: none (`ARCH-002`).

## How to test
- `cargo test --locked -p grdr-agents`

## Data classes
Reads: none yet. Writes: none yet (first content #376). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- Link into a privileged program: its translators parse content, so the engine and the CLI link it (ARCH-004).
