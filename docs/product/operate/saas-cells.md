---
id: saas-cells
type: explanation
personas:
  - operator
shapes:
  - hosted
  - msp
covers:
  - grdr-saas
  - cell-router
  - portability
  - billing
owner_squad: saas-ops
stability: alpha
title: Hosted SaaS Cells, Portability, and Billing
---

# Hosted SaaS Cells, Portability, and Billing

Multi-tenant hosted operations are implemented in `crates/grdr-saas`.

## 4096-Bucket Regional Cell Sharding

- Devices hash via SHA-256 into deterministic shard buckets across `[0, 4096)`.
- Each cell owns a contiguous bucket range and capacity vector tracking CPU, active sessions, storage, and write IOPS utilization.
- New tenant placements enforce regional residency pinning (`GRDR-SAAS-0003`) and trigger splits at the 70% utilization soft cap (`docs/ops/bounds.toml` and `contracts/limits.toml`) leaving 20% emergency headroom.
- Splitting a hot cell halves `[start, end)` at the midpoint (`[0, 2048)` and `[2048, 4096)`) and reassigns matching organisations cleanly without gaps or overlapping ownership.

## Lossless Organisation Portability

Organisations can migrate between hosted cells or export cleanly to self-hosted clusters:

- Signed migration bundles carry `lake/` Parquet/blob artifacts, `audit/` hash-chained logs, active revocation IDs, and the current kill-switch epoch under strict single-organisation tenant scoping (`GRDR-SAAS-0004` rejects cross-tenant or delegated exports/imports).
- Every payload blob matches its declared manifest byte length and SHA-256 digest (`GRDR-SAAS-0005` rejects tampering or unmanifested blobs), and imports enforce monotonic watermark checks so old bundles cannot downgrade security state.
- Endpoints receive Ed25519-signed cell redirect receipts checked against minimum supported client SemVer requirements and HTTPS endpoint validation.

## Usage Ledger, Billing, and Dunning Safety

- The usage ledger scopes idempotency keys strictly per organisation and drops stale telemetry older than the 35-day late-usage window (`GRDR-SAAS-0006`).
- Monthly statements are Ed25519-signed and emitted uniformly across statement file, Stripe Meter, and Kill Bill adapters.
- Billing reconciliation blocks invoice issuance (`GRDR-SAAS-0007`) whenever any billed metric deviates beyond policy tolerance (`0%` exact line check or `10 bps` drift tolerance) or fails price/subtotal validation.
- Local endpoint enforcement remains active throughout `14`-day payment retry, past-due, and `60`-day suspended dunning states so endpoints never lose local protection while billing resolves.
