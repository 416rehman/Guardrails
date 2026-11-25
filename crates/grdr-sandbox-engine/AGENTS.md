# grdr-sandbox-engine

layer: 3   privilege: privileged   renders: none
surface: internal   squad: endpoint   trust core: yes
stability: not applicable (internal crate)
design: docs/design/11-endpoint-engineering.md section 2; notes: none (internal crate)

## Purpose
The engine sandbox launcher for all three systems; only the daemon calls it (design/11 section 2).

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- OS adapter crate: keeps `[lints] workspace = true` (unsafe forbidden) until its first `unsafe` item, which moves it to the copy of the root lints with `unsafe_code = "deny"` inside that item's write set.
- Formats no text a person or an agent reads (`renders = "none"`).
- Trust core: `crates/grdr-sandbox-engine/**` in security/trust-core.paths.
- Returns the sandbox report the engine echoes in `Hello`; a missing element sets `engine-sandbox-partial` (design/11 section 2).

## Allowed dependencies
Layers 0 to 2. Same-layer edges in architecture.toml: none (ARCH-002).

## How to test
- `cargo test --locked -p grdr-sandbox-engine`
- Oracle: none yet; the crate has no behaviour (first content #421).
- Fuzz and differential targets: none yet: no code reads input (first content #421).

## Data classes
Reads: none yet. Writes: none yet (first content #421). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- None recorded yet.
