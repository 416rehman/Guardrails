# grdr-ports

layer: 2   privilege: none
surface: public   squad: core   trust core: yes (`src/tenant.rs` and `src/tenant/**`)
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md sections 2 and 6; notes: none yet

## Purpose
The port traits every external dependency sits behind, and the one retry executor
`retry::run`. It holds traits and shared types, never an adapter.

## Invariants
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Every relational, lake, bus, blob and cache port method takes a `TenantCtx` (ARCH-015).
- No sleep inside a loop outside `retry` (ARCH-018).

## Allowed dependencies
Layers below 2, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-ports`
- Oracle: the conformance suite in `grdr-ports-testkit`, run against the reference adapters.
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
