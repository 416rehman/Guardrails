# grdr-core

layer: 1   privilege: none   renders: none
surface: public   squad: core   trust core: no
stability: none yet (surfaces.toml arrives with #1122)
design: docs/design/03-system-architecture-and-modularity.md sections 1 to 3; notes: none yet (first content #384)

## Purpose
Normalisation, analysers, session rules, Cedar evaluation, detections, discovery classification, bundle compilation and verdict semantics (design/03 section 1). It never does I/O, reads a clock or randomness, or checks a signature.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No I/O, async runtime, clock or randomness; takes `now` and `entropy` (ARCH-003, ADR-0006).
- Builds for `wasm32-unknown-unknown` (ARCH-003): `cargo check --locked --target wasm32-unknown-unknown -p grdr-core`.
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Modules `analyze`, `session`, `policy`, `detect`, `discover` and `compile`. The first five import only `grdr-model`; `compile` and the crate root's `step` import all five (ARCH-013; review until #1580).
- Module `policy` is trust core (`crates/grdr-core/src/policy.rs` and `policy/**` in security/trust-core.paths), as is `compile/fastpath`.
- Returns `MessageRef`s and formats no text (design/03 section 10).

## Allowed dependencies
Layer 0. Same-layer edges in architecture.toml: `grdr-model`; `grdr-fastpath` (table layout only).

## How to test
- `cargo test --locked -p grdr-core`
- Oracle: none yet; the crate has no behaviour (first content #384).
- Fuzz and differential targets: none yet: no code reads input (first content #384).

## Data classes
Reads: none yet. Writes: none yet (first content #384). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- Link into a privileged program or `grdr-hook`: it is a content parser (ARCH-004).
