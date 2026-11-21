# grdr

layer: 4   privilege: untrusted   renders: person
surface: internal   squad: endpoint   trust core: no
stability: not applicable (internal crate)
design: docs/design/03-system-architecture-and-modularity.md section 1; docs/design/11-endpoint-engineering.md section 1; notes: none (internal crate)

## Purpose
The CLI: it shows state and proposes changes, and mutates nothing without a grant (D-31).

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- No `unsafe`: the workspace lints forbid it.
- Reaches the daemon only over `local` (design/11 section 1).
- Commands, flags and exit codes come from `interface/cli.toml`, and `main` returns the generated `ExitCode` (ARCH-023).
- `programs/grdr/**` is an interface path, judged by eval-ux and eval-a11y.

## Allowed dependencies
Layers 0 to 3, wiring only. Same-layer edges: none (no program depends on another).

## How to test
- `cargo test --locked -p grdr`
- Oracle: none yet; the crate has no behaviour (first content #1540).
- Fuzz and differential targets: none yet: no code reads input (first content #1540).

## Data classes
Reads: none yet. Writes: none yet (first content #1540). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- Call `std::process::exit` (ARCH-023).
