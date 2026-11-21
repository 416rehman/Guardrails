# grdr-crypto

layer: 2   privilege: none   renders: none
surface: public   squad: security   trust core: yes
stability: none yet (surfaces.toml arrives with #1122)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet (first content #334, #336, #337)

## Purpose
The only crate that links cryptography (ARCH-006); it composes vetted libraries only (D-63).

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Formats no text a person or an agent reads (`renders = "none"`).
- Trust core: `crates/grdr-crypto/**` in security/trust-core.paths.
- Cryptography crates appear only under this crate (ARCH-006).

## Allowed dependencies
Layers 0 and 1. Same-layer edges in architecture.toml: none from this crate; `grdr-wire` may depend on it.

## How to test
- `cargo test --locked -p grdr-crypto`
- Oracle: none yet; the crate has no behaviour (first content #334, #336, #337).
- Fuzz and differential targets: none yet: no code reads input (first content #334, #336, #337).

## Data classes
Reads: none yet. Writes: none yet (first content #334, #336, #337). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- None recorded yet.
