# grdr-sensor-linux

layer: 3   privilege: privileged   renders: none
surface: internal   squad: linux   trust core: no
stability: not applicable (internal crate)
design: docs/design/10-sensor-linux-containers-ci.md sections 1 to 3; notes: none (internal crate)

## Purpose
The Linux sensor back end: it implements `SensorBackend` and `Actuator` (design/10 Interfaces) and only collects and enforces (D-20). It runs in the daemon, holds the BPF descriptors and writes the enforcement maps.

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the workspace clippy deny lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and the rest of the root table).
- OS adapter crate: keeps `[lints] workspace = true` (unsafe forbidden) until its first `unsafe` item, which moves it to the copy of the root lints with `unsafe_code = "deny"` inside that item's write set.
- Formats no text a person or an agent reads (`renders = "none"`).
- Decodes fixed-layout ring records only.
- Never sets a provenance grade; the daemon stamps it.
- The probe never branches on distribution name or version (design/10 section 1).
- Kernel enforcement needs S-12 and the D-63 review (D-19).

## Allowed dependencies
Layers 0 to 2. Same-layer edges in architecture.toml: none (layer 3 crates never depend on each other, ARCH-002).

## How to test
- `cargo test --locked -p grdr-sensor-linux`
- Oracle: none yet; the crate has no behaviour (first content #101).
- Fuzz and differential targets: none yet: no code reads input (first content #101).

## Data classes
Reads: none yet. Writes: none yet (first content #101). Logs: LogSafe only.

## Limits
Bounds in contracts/limits.toml: none yet (contracts/limits.toml arrives with #279).

## Do not
- Take a Cargo dependency on `grdr-sensor-linux-bpf`: the object is built separately and loaded (design/10 section 3).
- Depend on `grdr-core` or another content parser: it is in the daemon's closure (ARCH-004).
