# ADR-0006: The core does no I/O and takes time and randomness as inputs

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-05, P5
- Requires: nothing
- RFC: not required: restates D-05 as repository mechanism
- Work items: [WI-0003], [WI-0016]

## Context
Replay, simulation, differential testing and embedding all need the same events and bundle to produce the same verdicts and findings on every host (briefs 27, 37). A core that reads a clock, a file or a socket cannot be replayed.

## Decision
Layers 0 and 1 perform no I/O, start no async runtime and read no clock or randomness. Callers pass `now` and `entropy`. The core builds for native targets, the C ABI and `wasm32`.

## Enforced by
ARCH-003 fails a layer 0 or 1 crate that depends on or calls an I/O, clock, randomness or runtime API listed in `architecture.toml`. Layer 1 builds for `wasm32-unknown-unknown` in `verify`. The determinism test of [WI-0016] requires byte-identical output on native, C ABI and `wasm32`.

## Consequences
Receipts can be replayed exactly. Every host writes its own I/O shell, and anything time-dependent in the core takes a parameter.

## Alternatives rejected
- An async core with pluggable I/O traits: the runtime would leak into embedders and into `wasm32`.
- A clock trait object inside the core: a hidden input that replay could not pin.

## Revisit when
A required core function cannot be expressed without I/O; that case goes to an RFC.
