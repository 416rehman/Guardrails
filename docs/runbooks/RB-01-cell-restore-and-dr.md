---
id: RB-01
actor: sre-oncall
rto: 4h
rpo: 5m
---

# RB-01: Cell Backup Restore and Disaster Recovery

## Diagnosis

1. Confirm cell outage or unrecoverable storage corruption via health metrics and SLO burn alerts (`docs/ops/slo-rules.yaml`).
2. Verify latest continuous backup snapshot timestamp in the regional object store (`aws-s3`, `gcs`, `azure-blob`, `seaweedfs-4.53`, or `ceph-rgw`) meets `RPO <= 5m`.
3. Confirm standby compute capacity exists in the tenant's pinned region (`required_region`) to preserve data locality.

## Actions

1. Record an incident ticket and runbook operator provenance (`blast_radius_pct <= 25`, `max_concurrent_regions = 1`, `30`-minute regional cooldown).
2. Restore PostgreSQL 18 WAL PITR snapshot into the replacement cell database (`RB-06`).
3. Hydrate immutable `lake/` Parquet batches and `audit/` receipt segments from the regional object store.
4. Run `grdr server preflight --profile ha --strict --json` against the restored cell configuration, verifying distinct `--bind` and `--operator-bind`.
5. Register the restored cell endpoint in the control-plane cell router and clear draining state only after checksum parity passes.

## Verification

- Compare restored `lake_watermark` and `audit_watermark` against pre-incident checkpoints.
- Execute Track 1 and Track 2 of [FLEET-VERIFY.md](FLEET-VERIFY.md) inside the `4h` RTO window.

## Rollback

If restored WAL or lake segments fail digest checks, place the replacement cell into read-only mode, retain primary quarantine evidence, and restore from the prior clean snapshot.

## Escalation

Page Security On-Call (`RB-07`) immediately if checksum mismatches suggest tampering rather than crash recovery.
