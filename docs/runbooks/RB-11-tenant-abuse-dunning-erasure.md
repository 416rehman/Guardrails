---
id: RB-11
actor: trust-safety
rto: 4h
rpo: 0m
---

# RB-11: Tenant Dunning, Suspension, and Legal-Hold Erasure

## Diagnosis

1. Triggered by billing invoice delinquency (`PastDue` through `14`-day retry window to `Suspended` through `60`-day grace), abuse report, or contractual offboarding erasure request.
2. Verify active legal hold status before mutating tenant keys or encrypted blobs.

## Actions

1. Under payment delinquency, preserve active local endpoint enforcement so endpoints never silently drop protection while billing resolves.
2. Provide self-hosted migration export (`RB-03`) prior to locking hosted portals.
3. For approved offboarding with no legal hold active, schedule pending erasure (`30`-day cancellation window from `contracts/limits.toml`) and finalize cryptographic key destruction only after the deadline passes.

## Verification

- Confirm held tenants and non-elapsed erasure deadlines reject key purge (`GRDR-SAAS-0008`), and completed erasures verify destroyed session content keys.

## Rollback

While pending erasure inside the `30`-day cancellation window, customer authorization or newly raised legal hold cancels scheduled purge cleanly; billing delinquency transitions cannot override an already pending or completed erasure.

## Escalation

Escalate immediately to Legal Counsel (`docs/legal/counsel-register.yaml`) if conflicting regulatory retention and erasure demands occur.
