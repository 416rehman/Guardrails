# grdr

layer: 4   privilege: untrusted
surface: internal   squad: endpoint   trust core: no
design: docs/design/23-api-policy-as-code-and-mcp-server.md section 11; docs/design/28; notes: none yet

## Purpose
The command-line interface: shows state and proposes changes, and mutates nothing without a
grant (D-31). Human output goes through the terminal kit and language tokens.

## Invariants
- Every command, flag, exit code and `--json` type comes from `interface/cli.toml` (ARCH-023).
- `--json` output is a protobuf message in proto3 JSON (ARCH-022).
- Every string a person reads is a language token (D-69; UX1 to UX8).
- Wiring only: it depends on no other program (ARCH-001).

## Allowed dependencies
Layers below 4, plus same-layer edges in architecture.toml: none.

## How to test
- `cargo nextest run -p grdr`
- Oracle: a golden text test and a golden `--json` test per command (ARCH-023, WI-0026).
- Fuzz and differential targets: none yet.

## Data classes
Reads: none yet. Writes: none yet. Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet.

## Do not
- None yet; the rules gardener adds each pitfall with its finding id.
