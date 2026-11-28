---
id: RB-10
actor: sre-oncall
rto: 15m
rpo: 5m
---

# RB-10: SLO Error-Budget Burn Rate Incident

## Diagnosis

1. Page triggers on `docs/ops/slo-rules.yaml` multi-window fast-burn rules (`14.4x` over 1h or `6x` over 6h) for Connect RPC ingest, decision fastpath, or fleet sync.
2. Correlate burn spike with recent automated runbook maintenance steps, deploys, or traffic surges.

## Actions

1. Declare a change freeze window blocking non-emergency rollouts (`docs/ops/bounds.toml`).
2. Route around unhealthy cells (`RB-04` / `RB-01`) or roll back recent minor rollout (`RB-02`).
3. Verify offline local `grdr-daemon` / `grdr-hook` binary floor cache continues protecting endpoints with zero disruption.

## Verification

- Error-budget burn falls below `1x` across a clean 30-minute recovery window before lifting change freeze.

## Rollback

Keep change freeze active until post-incident corrective action is tracked.

## Escalation

Page Incident Commander (`RB-08`) if fast-burn spans more than one regional cell simultaneously.
