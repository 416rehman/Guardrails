# <crate-name>

layer: <0|1|2|3|4|tool>   privilege: <privileged|sandboxed|untrusted|none>
surface: <public|internal>   squad: <owners.toml id>   trust core: <yes|no>
stability: <experimental|beta|stable> (public crates only, from surfaces.toml)
design: docs/design/<NN>-<name>.md section <k>; notes: docs/crates/<crate-name>.md

## Purpose
One or two sentences: what this crate owns and what it never does (design/03 section 1).

## Invariants
- <Each invariant, with the test, lint or type that holds it.>

## Allowed dependencies
Layers below <N>, plus same-layer edges in architecture.toml: <list or "none">.

## How to test
- `cargo nextest run -p <crate-name>`
- Oracle: <reference model, real consumer, golden vectors> at <path>.
- Fuzz and differential targets: <names, or "none: no untrusted input">.

## Data classes
Reads: <classes>. Writes: <classes>. Logs: LogSafe only.

## Limits
Bounds in limits.toml: <keys>.

## Do not
- <Crate-specific pitfalls found by review; each added by the rules gardener with its finding id.>
