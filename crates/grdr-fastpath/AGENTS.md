# grdr-fastpath

layer: 1   privilege: none   renders: none
surface: public   squad: core   trust core: yes
stability: none yet (surfaces.toml arrives with #1122)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet (first content #20)

## Purpose
The `no_std` table evaluator over the compiled floor table and the shim fail-safe table, and the bounded hook-field scanner, over `#[repr(C)]` fixed-layout inputs (design/03 sections 1 and 2). It never parses in general, allocates or starts threads.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No I/O, async runtime, clock or randomness; takes `now` and `entropy` (ARCH-003, ADR-0006).
- Builds for `wasm32-unknown-unknown` (ARCH-003): `cargo check --locked --target wasm32-unknown-unknown -p grdr-fastpath`.
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Formats no text a person or an agent reads (`renders = "none"`).
- `#![no_std]` with no dependencies (`cargo metadata`).
- Trust core: `crates/grdr-fastpath/**` in security/trust-core.paths.

## Allowed dependencies
None: it has no dependencies (design/03 section 2).

## How to test
- `cargo test --locked -p grdr-fastpath`
- Oracle: none yet; the crate has no behaviour (first content #20).
- Fuzz and differential targets: none yet: no code reads input (first content #20).

## Data classes
Reads: none yet. Writes: none yet (first content #20). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- None recorded yet.
