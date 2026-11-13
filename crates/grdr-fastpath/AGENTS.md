# grdr-fastpath

layer: 1   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md sections 1 and 2; notes: none yet

## Purpose
The compiled floor table and the shim fail-safe table over `#[repr(C)]` inputs, and the bounded
hook-field scanner. It never parses generally, allocates or spawns threads.

## Invariants
- `#![no_std]` with no dependencies (design/03 section 2).
- No I/O, clock or randomness (ARCH-003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).

## Allowed dependencies
Layers below 1, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-fastpath`
- Oracle: `grdr-core` on the floor subset, as a differential test (WI-0017).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none. Writes: none. Logs: none; layer 1 returns diagnostics.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
