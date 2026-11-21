# grdr-wire

layer: 2   privilege: none   renders: none
surface: public   squad: core   trust core: no
stability: none yet (surfaces.toml arrives with #1122)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet (first content #374)

## Purpose
IPC and uplink framing, size caps, peer-authentication traits, and the `Dialer` through which every outbound connection is made (design/03 section 2).

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Formats no text a person or an agent reads (`renders = "none"`).
- Module `peer_auth` is trust core and the security squad's (`crates/grdr-wire/src/peer_auth.rs` and `peer_auth/**` in security/trust-core.paths); it arrives with #375.

## Allowed dependencies
Layers 0 and 1. Same-layer edges in architecture.toml: `grdr-crypto`.

## How to test
- `cargo test --locked -p grdr-wire`
- Oracle: none yet; the crate has no behaviour (first content #374).
- Fuzz and differential targets: none yet: no code reads input (first content #374).

## Data classes
Reads: none yet. Writes: none yet (first content #374). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- Open an outbound connection outside the `Dialer` (ARCH-025).
