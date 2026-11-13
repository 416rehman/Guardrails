# grdr-daemon

layer: 4   privilege: privileged
surface: internal   squad: endpoint   trust core: yes
design: docs/design/03-system-architecture-and-modularity.md sections 1 and 4; docs/design/11; notes: none yet

## Purpose
The minimal privileged core: process tree and session containers, floor-table evaluation, the
label projection, actuators, peer authentication, the spool and supervision. It never
interprets payload content and never reaches a network.

## Invariants
- No content parser in its closure: not `grdr-core`, `grdr-llm-proto`, `serde_json` or `regex`
  (ARCH-004, ADR-0010).
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- It binds no TCP port and no HTTP listener (design/03 section 4).
- Wiring only: it joins adapters and depends on no other program (ARCH-001).

## Allowed dependencies
Layers below 4, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-daemon`
- Oracle: the fault-injection suite: killing the engine yields floor-table answers and Degraded
  (design/03 C1, WI-0022).
- Fuzz and differential targets: none yet; the IPC frame decoder gets one when it lands.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
