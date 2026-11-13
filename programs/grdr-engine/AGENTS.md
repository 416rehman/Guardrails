# grdr-engine

layer: 4   privilege: sandboxed
surface: internal   squad: endpoint   trust core: no
design: docs/design/03-system-architecture-and-modularity.md sections 1 and 4; notes: none yet

## Purpose
The one session monitor and every parser, run sandboxed: bundle compilation and self-test,
content-dependent policy, and the records it sends to the daemon. It holds no key, enforces
nothing, verifies no signature, writes no lane and reaches no network.

## Invariants
- It reaches the outside only through the daemon's IPC (design/03 section 4).
- Wiring only: it depends on no other program (ARCH-001).
- `grdr-strings` with `pack-text` is allowed here, never in a privileged program (ARCH-024).

## Allowed dependencies
Layers below 4, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-engine`
- Oracle: the sandbox check that the engine cannot open a socket (design/03 C1, WI-0022).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
