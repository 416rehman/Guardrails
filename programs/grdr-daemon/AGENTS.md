# grdr-daemon

layer: 4   privilege: privileged   renders: none
surface: internal   squad: endpoint   trust core: yes
stability: not applicable (internal crate)
design: docs/design/03-system-architecture-and-modularity.md sections 1 and 4; docs/design/11-endpoint-engineering.md section 1; notes: none (internal crate)

## Purpose
The minimal core of design/03 section 1: process tree, floor-table evaluation, actuators, peer authentication, spool and key handles. It never interprets payload content or reaches a network.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Trust core: `programs/grdr-daemon/**` in security/trust-core.paths.
- Its closure holds no content parser, only the generated protobuf codec (ARCH-004).
- Binds no TCP listener and reaches no network (design/11 section 14).
- Exposes only `decide`, `local` and `provider`, each peer-checked (design/11 section 1).
- The only writer of every lane (R-08).

## Allowed dependencies
Layers 0 to 3, wiring only, minus every content parser (ARCH-004). Same-layer edges: none (no program depends on another).

## How to test
- `cargo test --locked -p grdr-daemon`
- Oracle: none yet; the crate has no behaviour (first content #1536).
- Fuzz and differential targets: none yet: no code reads input (first content #1536).

## Data classes
Reads: none yet. Writes: none yet (first content #1536). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- Depend on `grdr-core` (ARCH-004).
