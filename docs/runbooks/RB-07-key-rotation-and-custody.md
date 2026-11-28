---
id: RB-07
actor: security-oncall
rto: 1h
rpo: 0m
---

# RB-07: Key Rotation, Custody Ceremony, and Compromise Yank

## Diagnosis

1. Triggered on suspected Ed25519 key exposure, scheduled root/signing rotation, or foreign artefact signature discovery.
2. Identify key scope (`TUF root`, `pack signer`, `route ticket`, or `device identity`) and verify Rekor transparency entries (`RB-12`).

## Actions

1. Add replacement Ed25519 verifying key to pinned trust stores prior to removing the retiring key (overlap window).
2. On active key compromise, revoke affected releases immediately (`TUF` expiry bump), bump `kill_switch_epoch` where required, and invoke the yank advisory template (`docs/ops/security-advisories/vex-csaf-template.json`).
3. Re-sign active floor packs and route tickets exclusively using clean custody keys (`grdr-crypto`).

## Verification

- Confirm `grdr audit verify --json` and bundle signature verification succeed under the rotated public key and fail closed against revoked signatures (`GRDR-SAAS-0005`).

## Rollback

Never un-revoke a compromised key; rotate forward cleanly with fresh generated key material.

## Escalation

Notify Incident Commander and Steward Owner per repository root `SECURITY.md` within 15 minutes of confirmed key compromise.
