# grdr-hook

layer: 4   privilege: untrusted   renders: agent
surface: internal   squad: adapters   trust core: no
stability: not applicable (internal crate)
design: docs/design/07-control-points-and-hook-broker.md section 5; notes: none (internal crate)

## Purpose
The hook shim: it forwards a hook call to the daemon and decides nothing beyond the signed fail-safe table (design/03 section 1). It has `src/main.rs` only; #376 adds `src/lib.rs` for the encoder.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Its closure links no `grdr-core`, `serde_json`, `regex`, `grdr-strings` or `grdr-messages` (ARCH-004, ARCH-024); it writes its output by hand.
- The shim answers within 2 s (D-14).
- On Windows Claude Code calls it for `PowerShell` as well as `Bash` (#1560).

## Allowed dependencies
Layers 0 to 3, wiring only, minus every content parser (ARCH-004). Same-layer edges: none.

## How to test
- `cargo test --locked -p grdr-hook`
- Oracle: none yet; the crate has no behaviour (first content #377).
- Fuzz and differential targets: none yet: no code reads input (first content #377).

## Data classes
Reads: none yet. Writes: none yet (first content #377). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- Parse a hook payload here; `grdr-agents` does (ARCH-004).
