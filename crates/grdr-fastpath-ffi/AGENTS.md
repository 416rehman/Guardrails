# grdr-fastpath-ffi

layer: 1   privilege: none   renders: none
surface: public   squad: core   trust core: yes
stability: none yet (surfaces.toml arrives with #1122)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet (first content #418)

## Purpose
The `extern "C"` entry points of the fast path, so `libgrdr_fastpath` carries no engine code (design/03 section 2). It does no I/O.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No I/O, async runtime, clock or randomness; takes `now` and `entropy` (ARCH-003, ADR-0006).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the clippy deny lints of its own `[lints]` table, a copy of the root's.
- `unsafe_code` is `deny` in its own `[lints]` table; each `unsafe` item takes a reasoned `#[allow(unsafe_code)]` and a `// SAFETY:` comment (design/03 section 10). It has none yet.
- Formats no text a person or an agent reads (`renders = "none"`).
- Trust core: `crates/grdr-fastpath-ffi/**` in security/trust-core.paths (`unsafe` in the FFI, D-63).

## Allowed dependencies
Only `grdr-fastpath`, its one same-layer edge in architecture.toml (`scope = "its only dependency"`); no layer 0 crate and no other dependency (design/03 section 2).

## How to test
- `cargo test --locked -p grdr-fastpath-ffi`
- Oracle: none yet; the crate has no behaviour (first content #418).
- Fuzz and differential targets: none yet: no code reads input (first content #418).

## Data classes
Reads: none yet. Writes: none yet (first content #418). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- None recorded yet.
