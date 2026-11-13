# grdr-proto

layer: 0   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet

## Purpose
Generated Rust types for every `grdr.*` protobuf package. Data only: no logic, no I/O.

## Invariants
- No I/O, async runtime, clock or randomness (ARCH-003, WI-0003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Every field carries a `data_class` (WI-0014); generated code is never edited by hand.

## Allowed dependencies
Layers below 0 (none), plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-proto`
- Oracle: the `buf` breaking and lint jobs over `proto/` (WI-0014); none yet.
- Fuzz and differential targets: none yet.

## Data classes
Reads: none. Writes: none. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
