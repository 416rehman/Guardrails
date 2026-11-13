# grdr-store-local

layer: 3   privilege: none
surface: internal   squad: endpoint   trust core: no
design: docs/design/03-system-architecture-and-modularity.md sections 1 and 2; notes: none yet

## Purpose
The spool, the SQLite local history and the flight recorder on the endpoint. The daemon is the
only writer of every lane; other programs read.

## Invariants
- No dependency on another layer 3 crate (ARCH-002).
- The SQLite driver appears only in this crate (ARCH-005).
- Every queue and spool size is a named bound, and every drop is counted (design/03 section 10).

## Allowed dependencies
Layers below 3, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-store-local`
- Oracle: the `grdr` CLI golden files over the slice run (WI-0026).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
