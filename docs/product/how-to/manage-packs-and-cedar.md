---
id: manage-packs-and-cedar
type: how-to
personas:
  - operator
  - extender
shapes:
  - team
  - self-hosted
covers:
  - cedar
  - packs
  - modes
owner_squad: policy
stability: beta
title: Manage Policy Packs and Cedar Rules
---

# Manage Policy Packs and Cedar Rules

Policy evaluation in Guardrails ADR runs Cedar authorization checks and signed content packs compiled down to the endpoint daemon floor cache.

## Evaluation Modes

Every policy rule produces one of four Guardrails modes and verdicts:

- `Off`: rule disabled in the current assignment.
- `Watch`: record findings and telemetry receipts without blocking execution.
- `Ask`: require bounded step-up `Grant` approval from Console or Desktop before allowing the action.
- `Block`: deny immediately at hook or OS sensor boundary and emit a block notice receipt.

## Signed Floor Compilation

The endpoint daemon (`grdr-daemon`) compiles active policy packs into an Ed25519-verified binary floor cache. If the server uplink disconnects or restarts, local hook evaluation continues offline against the pinned binary floor cache.

## Verifying Pack Conformance

Always run workspace checks after editing packs or Cedar contracts:

```powershell
cargo test --workspace --locked
node scripts/check-architecture.mjs
```

See [Adding a Rule or Pack](../../extending/adding-a-rule-or-pack.md) for pack authoring fixtures and negative test requirements.
