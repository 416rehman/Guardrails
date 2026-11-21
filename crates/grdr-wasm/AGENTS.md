# grdr-wasm

layer: 1   privilege: none   renders: none
surface: public   squad: core   trust core: no
stability: none yet (surfaces.toml arrives with #1122)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet (first content #378)

## Purpose
`wasm32` bindings over the engine boundary (design/03 section 2). It does no I/O.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No I/O, async runtime, clock or randomness; takes `now` and `entropy` (ARCH-003, ADR-0006).
- Builds for `wasm32-unknown-unknown` (ARCH-003): `cargo check --locked --target wasm32-unknown-unknown -p grdr-wasm`.
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Formats no text a person or an agent reads (`renders = "none"`).

## Allowed dependencies
Layer 0. Same-layer edges in architecture.toml: `grdr-model`, `grdr-core`, `grdr-fastpath`.

## How to test
- `cargo test --locked -p grdr-wasm`
- Oracle: none yet; the crate has no behaviour (first content #378).
- Fuzz and differential targets: none yet: no code reads input (first content #378).

## Data classes
Reads: none yet. Writes: none yet (first content #378). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- None recorded yet.
