# grdr-wire

layer: 2   privilege: none
surface: public   squad: core   trust core: yes (`src/peer_auth.rs` and `src/peer_auth/**`, security squad)
stability: experimental (every surface starts experimental until surfaces.toml lists it)
design: docs/design/03-system-architecture-and-modularity.md section 2; notes: none yet

## Purpose
IPC and uplink framing, size caps, peer-authentication traits, and the `Dialer` through which
every outbound connection is made. Peers are authenticated by kernel credentials, never a PID.

## Invariants
- No panic path and checked arithmetic (workspace lints, `clippy::arithmetic_side_effects`).
- Outbound connections open only through `Dialer` (ARCH-025).
- Every frame is size-capped by a named bound in `limits.toml`.

## Allowed dependencies
Layers below 2, plus same-layer edges in architecture.toml: `grdr-crypto`.

## How to test
- `cargo nextest run -p grdr-wire`
- Oracle: none yet; the decide protocol's slice scenario (WI-0021).
- Fuzz and differential targets: none yet; the frame decoder gets one when it lands.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
