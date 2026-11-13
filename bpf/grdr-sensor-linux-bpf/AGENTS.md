# grdr-sensor-linux-bpf

layer: 3   privilege: privileged
surface: internal   squad: linux   trust core: yes
design: docs/design/10-sensor-linux-containers-ci.md; docs/design/03 section 2; notes: none yet

## Purpose
The kernel programs of the Linux sensor, licensed `GPL-2.0-only OR BSD-2-Clause` (D-02) and
built to an object that `grdr-sensor-linux` loads. It is never a Cargo dependency.

## Invariants
- Outside the workspace: listed in the root `exclude` and its own workspace root.
- No panic path and checked arithmetic (its own copy of the workspace lints).
- A default build needs no kernel toolchain; signed objects are fetched as artefacts
  (design/03 section 8, ARCH-011).

## Allowed dependencies
Layers below 3, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo build --manifest-path bpf/grdr-sensor-linux-bpf/Cargo.toml`
- Oracle: the kernel verifier on every cell of the design/10 kernel matrix (S-13, WI-0023).
- Fuzz and differential targets: the user-space model over recorded events (WI-0023).

## Data classes
Reads: none yet. Writes: none yet. Logs: none; records go to the back end.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
