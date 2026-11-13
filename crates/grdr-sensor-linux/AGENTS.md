# grdr-sensor-linux

layer: 3   privilege: none
surface: internal   squad: linux   trust core: no (its kernel programs under `bpf/` are)
design: docs/design/10-sensor-linux-containers-ci.md; docs/design/03 section 2; notes: none yet

## Purpose
The Linux sensor back end: probes the host, loads and attaches the kernel programs that
`bpf/grdr-sensor-linux-bpf` builds, and turns their records into fixed-layout events. It never
takes the kernel crate as a Cargo dependency.

## Invariants
- No dependency on another layer 3 crate (ARCH-002).
- Feature decisions come from the runtime probe, never the distribution name (design/10).
- `unsafe` only with a `// SAFETY:` comment; the crate forbids it until its first need.

## Allowed dependencies
Layers below 3, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-sensor-linux`
- Oracle: the user-space model over recorded events (WI-0023); the kernel matrix (`matrix-run`).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
