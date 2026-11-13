# grdr-fastpath-ffi

layer: 1   privilege: none
surface: public   squad: core   trust core: no
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md sections 2 and 8; notes: none yet

## Purpose
The `extern "C"` entry points of the fast path, so `libgrdr_fastpath` carries no engine code.
It never links `grdr-core`.

## Invariants
- Its only dependency is `grdr-fastpath` (design/03 section 2, ARCH-001).
- No I/O, clock or randomness (ARCH-003).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- `unsafe` only with a `// SAFETY:` comment; the crate forbids it until its first entry point.

## Allowed dependencies
Layers below 1, plus same-layer edges in architecture.toml: `grdr-fastpath` only.

## How to test
- `cargo nextest run -p grdr-fastpath-ffi`
- Oracle: the closure and symbol scans of the `embedded` build profile (design/03 B3).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none. Writes: none. Logs: none; layer 1 returns diagnostics.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
