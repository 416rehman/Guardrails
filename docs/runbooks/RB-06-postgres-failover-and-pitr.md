---
id: RB-06
actor: sre-oncall
rto: 30m
rpo: 5m
---

# RB-06: PostgreSQL 18 Failover and Point-in-Time Recovery

## Diagnosis

1. Triggered on primary database unavailability, replication slot lag breach, or fenced write failure in `--profile ha` / `distributed`.
2. Verify CloudNativePG (`cnpg`) cluster health, WAL archive continuity, and standby sync state.

## Actions

1. Promote synchronous standby when primary is dead and confirm fencing token epoch increments (`FencingToken`).
2. For logical corruption or accidental DDL, initialize a clean PostgreSQL 18 cluster from WAL archive up to target PITR timestamp immediately prior to fault.
3. Run `grdr server preflight --profile ha --strict --postgres-dsn <DSN> --json` before directing `grdr-server` connection pools to the promoted cluster.

## Verification

- Confirm `grdr server preflight --profile ha --strict` passes and Connect/Protobuf read/write RPCs return healthy latencies.

## Rollback

Retain fenced old primary read-only for forensic diffing; never reattach diverged primaries without pg_rewind validation or fresh basebackup.

## Escalation

Escalate to Security On-Call (`RB-07`) if audit table rows or tenant fencing records show unexpected divergence.
