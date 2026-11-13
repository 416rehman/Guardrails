# grdr-llm-proto

layer: 1   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet

## Purpose
Parsers for model-provider protocols. A content parser, so it never enters the closure of a
privileged program or of `grdr-hook` (ARCH-004).

## Invariants
- No I/O, async runtime, clock or randomness; builds for `wasm32-unknown-unknown` (ARCH-003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Each normaliser returns resolved, unresolved or malformed and has a fuzz target (ADR-0009).

## Allowed dependencies
Layers below 1, plus same-layer edges in architecture.toml: `grdr-model`.

## How to test
- `cargo nextest run -p grdr-llm-proto`
- Oracle: none yet; each parser lands with its reference corpus.
- Fuzz and differential targets: none yet; one per parser once one exists (ADR-0009).

## Data classes
Reads: none yet. Writes: none yet. Logs: none; layer 1 returns diagnostics.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
