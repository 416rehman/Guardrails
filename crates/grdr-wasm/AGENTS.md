# grdr-wasm

layer: 1   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (the `wasm32` binding stays experimental until one external embed pilot, D-60)
design: docs/design/03-system-architecture-and-modularity.md sections 2 and 7; notes: none yet

## Purpose
The `wasm32` binding of the core. It adds no behaviour of its own beyond the conversion between
host values and the core's types.

## Invariants
- No I/O, async runtime, clock or randomness; builds for `wasm32-unknown-unknown` (ARCH-003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).

## Allowed dependencies
Layers below 1, plus same-layer edges in architecture.toml: `grdr-model`, `grdr-core`,
`grdr-fastpath`.

## How to test
- `cargo nextest run -p grdr-wasm`
- Oracle: the determinism test, byte-identical on native, C ABI and `wasm32` (WI-0016).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: none; layer 1 returns diagnostics.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
