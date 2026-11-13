# grdr-ports-testkit

layer: 2   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md sections 2 and 6; notes: none yet

## Purpose
Reference in-memory adapters for every port and the conformance suite each adapter, first-party
or contrib, must pass. It never ships in a program.

## Invariants
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Each reference adapter passes the same suite as the release-gating adapters (design/03 E1).

## Allowed dependencies
Layers below 2, plus same-layer edges in architecture.toml: `grdr-ports`.

## How to test
- `cargo nextest run -p grdr-ports-testkit`
- Oracle: the reference adapters are the oracle the suite holds other adapters to (design/03 E1).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none. Writes: none. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
