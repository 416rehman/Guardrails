# grdr-agents

layer: 3   privilege: none
surface: internal   squad: adapters   trust core: no
design: docs/design/07-control-points-and-hook-broker.md; docs/design/03 section 2; notes: none yet

## Purpose
Per-agent installers, managed-source probes and structural dialect translators. Agent facts
(fingerprints, config locations, match tables) are manifest content, never code here (P14).

## Invariants
- No dependency on another layer 3 crate (ARCH-002).
- No agent or vendor name in code; it comes from the adapter manifest (S7, P14).

## Allowed dependencies
Layers below 3, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr-agents`
- Oracle: payload replay against recorded agent hook calls (design/03 extension points).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
