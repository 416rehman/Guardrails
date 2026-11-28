---
id: RB-05
actor: sre-oncall
rto: 30m
rpo: 0m
---

# RB-05: NATS JetStream Stream and Consumer Recovery

## Diagnosis

1. Triggered when `--profile distributed` event ingest lag breaches SLO thresholds or a JetStream quorum member loses raft consensus.
2. Inspect `grdr-bus-nats` stream state, consumer ACK pending counts, and storage volume free space.

## Actions

1. Verify at least two of three JetStream RAFT peers remain healthy; replace failed PVC/peer node before shrinking replication factor.
2. If backlog spikes due to stalled workers, scale consumer replicas up within `bounds.toml` rate limits rather than purging durable streams.
3. Replay unacknowledged ingest sequences from durable stream checkpoints; idempotency keys deduplicate retried records safely.

## Verification

- Confirm consumer lag drains to nominal baseline and no sequence gaps appear in `lake/` flush checkpoints.

## Rollback

Switch degraded workers off traffic while preserving JetStream storage volumes intact until raft leader quorum stabilizes.

## Escalation

Engage Platform Storage team if quorum loss exceeds two peers (`RPO` assessment against object-store lake backups required).
