# grdr-core

layer: 1   privilege: none
surface: public   squad: core   trust core: yes (`src/policy.rs` and `src/policy/**`)
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md sections 2 and 3; notes: none yet

## Purpose
The pure core: normalisation, analysers, session rules, Cedar evaluation, detections, discovery
classification and bundle compilation. It never does I/O, reads a clock or checks a signature.

## Invariants
- No I/O, async runtime, clock or randomness; builds for `wasm32-unknown-unknown` (ARCH-003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Modules `analyze`, `session`, `policy`, `detect` and `discover` import only `grdr-model`;
  `compile` and the crate root import all five (ARCH-013).
- Same bundle, snapshot, inputs, `now` and entropy give byte-identical output (WI-0016).

## Allowed dependencies
Layers below 1, plus same-layer edges in architecture.toml: `grdr-model`, `grdr-fastpath`
(table layout only).

## How to test
- `cargo nextest run -p grdr-core`
- Oracle: `grdr-policy-ref` for `policy` (WI-0018); the shell reference model (WI-0019).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: none; layer 1 returns diagnostics.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
