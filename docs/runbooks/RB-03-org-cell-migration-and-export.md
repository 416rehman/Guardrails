---
id: RB-03
actor: saas-ops
rto: 1h
rpo: 0m
---

# RB-03: Organisation Cell Migration and Self-Hosted Export

## Diagnosis

1. Confirm the organisation's target cell or self-hosted export request matches pinned data residency and non-delegated single-tenant context ownership.
2. Verify all endpoints meet the minimum supported agent version specified in the migration manifest.

## Actions

1. Place source placement into drain mode and open the dual-write telemetry catch-up window.
2. Freeze tenant mutations briefly (`Frozen` migration stage) and export an Ed25519-signed organisation migration bundle containing `lake/`, `audit/`, revoked grant IDs, and the active `kill_switch_epoch`.
3. Import the bundle under target tenant verification, checking manifest SHA-256 digests, blob lengths, and monotonic watermark baselines.
4. Commit placement cutover and issue Ed25519-signed device redirect receipts (`https://` endpoint verified) to active endpoints.

## Verification

- Confirm restored file count matches source manifest count and `kill_switch_epoch` / revoked grant IDs match identically.
- Verify cross-tenant or delegated bundle attempts fail cleanly with `GRDR-SAAS-0004`.

## Rollback

Before device redirect receipts expire, revert target drain state and direct endpoints back to the source cell while holding target quarantine data read-only.

## Escalation

Escalate to Security On-Call on any `GRDR-SAAS-0005` signature mismatch or manifest checksum error.
