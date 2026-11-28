---
id: RB-09
actor: billing-ops
rto: 2h
rpo: 0m
---

# RB-09: Billing Reconciliation Halt and Usage Replay

## Diagnosis

1. Triggered when billing reconciliation returns `GRDR-SAAS-0007` (variance > `0%` exact line check, duplicate invoice line identifiers, unit-price mismatch, subtotal mismatch, or > `10 bps` meter drift).
2. Inspect the signed monthly usage statement digest and compare against raw usage ledger records per organisation and billing period.

## Actions

1. Halt automated invoice finalization for the affected billing period and `org_id`.
2. Replay late-arriving samples strictly inside the `35`-day late-usage window (`contracts/limits.toml`) using per-organisation, hour/day-bucketed idempotency keys so retries cannot double-bill.
3. Recompute the signed monthly usage statement and re-run per-metric parity across statement file, Stripe Meter, and Kill Bill adapters.

## Verification

- Confirm strict zero-variance reconciliation passes with `drift_bps == 0` across all billed metrics (`active_endpoints`, `ephemeral_sensor_hours`, `daily_active_endpoint_days`, `over_retention_gb_days`).

## Rollback

Void unissued draft invoices matching stale idempotency keys rather than patching ledger figures manually.

## Escalation

Escalate to Finance Lead and SaaS Engineering Lead if drift stems from clock skew exceeding `35` days (`GRDR-SAAS-0006`).
