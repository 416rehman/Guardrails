# grdr-store-local

layer: 3   privilege: privileged   renders: none
surface: internal   squad: endpoint   trust core: no
stability: not applicable (internal crate)
design: docs/design/11-endpoint-engineering.md section 4; notes: none (internal crate)

## Purpose
The spool, SQLite local history and flight recorder (design/11 section 4). The spool is daemon-owned; the engine's recorder also links it.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Formats no text a person or an agent reads (`renders = "none"`).
- In the daemon's closure, so ARCH-004 binds it: no content parser.
- A non-ALLOW receipt is fsynced before the reply (design/11 section 4).
- Segment and offset arithmetic is checked.

## Allowed dependencies
Layers 0 to 2. Same-layer edges in architecture.toml: none (ARCH-002).

## How to test
- `cargo test --locked -p grdr-store-local`
- Oracle: none yet; the crate has no behaviour (first content #428).
- Fuzz and differential targets: none yet: no code reads input (first content #428).

## Data classes
Reads: none yet. Writes: none yet (first content #428). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- None recorded yet.
