# grdr-crypto

layer: 2   privilege: none
surface: public   squad: security   trust core: yes
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet

## Purpose
The only crate that links cryptography. A new primitive is a trust-core change here, never a
dependency elsewhere.

## Invariants
- Cryptography crates appear only under this crate (ARCH-006).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- The `fips` feature links the AWS-LC FIPS module and changes nothing else (design/03 section 8).

## Allowed dependencies
Layers below 2, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-crypto`
- Oracle: published test vectors of each primitive, once one is linked.
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only; never key material.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
