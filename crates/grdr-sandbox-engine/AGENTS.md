# grdr-sandbox-engine

layer: 3   privilege: privileged
surface: internal   squad: endpoint   trust core: yes
design: docs/design/11-endpoint-engineering.md; docs/design/03 section 2; notes: none yet

## Purpose
The engine sandbox launcher for Linux, macOS and Windows. Only the daemon calls it; it returns
a sandbox report naming every element it could not apply.

## Invariants
- No dependency on another layer 3 crate (ARCH-002).
- No content parser in its closure, as it links into the privileged daemon (ARCH-004).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- `unsafe` only with a `// SAFETY:` comment; the crate forbids it until its first need.

## Allowed dependencies
Layers below 3, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-sandbox-engine`
- Oracle: the engine under the sandbox cannot open a socket or a file outside its directory
  (design/03 C1, WI-0022), on each system through `matrix-run`.
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
