# grdr-schema

layer: 0   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet

## Purpose
The Cedar schema, error codes, limits, configuration schema, mappings and pack manifest schema
as data. It never evaluates policy or reads a file at run time.

## Invariants
- No I/O, async runtime, clock or randomness (ARCH-003, WI-0003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Every error code has the form `GRDR-<AREA>-<NNNN>` and is constructed somewhere (ARCH-017).

## Allowed dependencies
Layers below 0 (none), plus same-layer edges in architecture.toml: `grdr-proto`.

## How to test
- `cargo nextest run -p grdr-schema`
- Oracle: none yet; the schema lint `grdr-schema-lint` arrives with WI-0014.
- Fuzz and differential targets: none yet.

## Data classes
Reads: none. Writes: none. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
