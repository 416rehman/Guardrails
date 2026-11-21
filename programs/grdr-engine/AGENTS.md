# grdr-engine

layer: 4   privilege: sandboxed   renders: none
surface: internal   squad: endpoint   trust core: no
stability: not applicable (internal crate)
design: docs/design/03-system-architecture-and-modularity.md sections 1 and 4; docs/design/11-endpoint-engineering.md sections 1 and 2; notes: none (internal crate)

## Purpose
The one session monitor and all parsing (design/03 section 1). It holds no keys, enforces nothing, verifies no signature, writes no lane and reaches no network.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- The daemon starts it over an inherited channel inside `grdr-sandbox-engine`'s profile (design/11 sections 1 and 2).
- Returns `MessageRef`s and formats no text.

## Allowed dependencies
Layers 0 to 3, wiring only. Same-layer edges: none (no program depends on another).

## How to test
- `cargo test --locked -p grdr-engine`
- Oracle: none yet; the crate has no behaviour (first content #1537).
- Fuzz and differential targets: none yet: no code reads input (first content #1537).

## Data classes
Reads: none yet. Writes: none yet (first content #1537). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- None recorded yet.
