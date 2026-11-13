# grdr-hook

layer: 4   privilege: untrusted
surface: internal   squad: adapters   trust core: no
design: docs/design/07-control-points-and-hook-broker.md; docs/design/03 section 1; notes: none yet

## Purpose
The hook shim an agent runs: forwards the hook call to the daemon and returns its answer. It
decides nothing beyond the signed fail-safe table, and renders the agent-facing block message.

## Invariants
- No content parser in its closure (ARCH-004); the bounded scanner of `grdr-fastpath` only.
- It links neither `grdr-strings` nor `grdr-messages` (ARCH-024).
- Agent-facing text is plain English, three lines, at most 600 characters (design/28 section 11).
- Wiring only: it depends on no other program (ARCH-001).

## Allowed dependencies
Layers below 4, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-hook`
- Oracle: the slice scenario, shim to engine and back, with the shim binary under 2 MiB (WI-0021).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
