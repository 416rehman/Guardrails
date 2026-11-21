# grdr-agents

layer: 3   privilege: none   renders: none
surface: internal   squad: adapters   trust core: no
stability: not applicable (internal crate)
design: docs/design/03-system-architecture-and-modularity.md section 2; docs/design/07-control-points-and-hook-broker.md section 6; notes: none (internal crate)

## Purpose
Per-agent installers, managed-source probes and structural dialect translators (design/03 section 2). Hook payloads are parsed here and never in `grdr-hook` (ARCH-004).

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Formats no text a person or an agent reads (`renders = "none"`).
- Event names, tool names, matchers and version ranges are manifest data, never code (P14).

## Allowed dependencies
Layers 0 to 2. Same-layer edges in architecture.toml: none (ARCH-002). Its first edges come with #370.

## How to test
- `cargo test --locked -p grdr-agents`
- Oracle: none yet; the crate has no behaviour (first content #376).
- Fuzz and differential targets: none yet: no code reads input (first content #376).

## Data classes
Reads: none yet. Writes: none yet (first content #376). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- Link into a privileged program: its translators parse content, so the engine and the CLI link it (ARCH-004).
