# grdr-model

layer: 1   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet

## Purpose
Domain types: ids, actions, verdicts, the assurance record and `VerifiedBundle`. The only place
ids are minted, from an injected clock and entropy (ARCH-020). It never does I/O.

## Invariants
- No I/O, async runtime, clock or randomness; builds for `wasm32-unknown-unknown` (ARCH-003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- `VerifiedBundle::assume_verified` is called only where ARCH-012 allows.

## Allowed dependencies
Layers below 1, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-model`
- Oracle: none yet; the envelope and id tests arrive with WI-0015.
- Fuzz and differential targets: none yet.

## Data classes
Reads: none. Writes: none. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
