---
id: RB-04
actor: saas-ops
rto: 45m
rpo: 0m
---

# RB-04: Cell Shard Split and Capacity Rebalance

## Diagnosis

1. Alert fires when any capacity dimension (CPU, active sessions, storage, write IOPS) hits the 70% cell soft cap configured in `docs/ops/bounds.toml` and `contracts/limits.toml`.
2. Confirm the active target cell owns at least two contiguous shard buckets.

## Actions

1. Provision an empty active cell endpoint in the same region with healthy capacity headroom (`< 70%`).
2. Trigger a regional cell shard split, halving `[start, end)` cleanly at the midpoint with zero bucket gap or overlap and proportional capacity allocation.
3. Drain and migrate reassigned organisations falling into the upper half range (`RB-03`).

## Verification

- Verify source and new cell utilizations both fall well below `70%` leaving `>= 20%` emergency reserve.
- Verify full coverage of `[0, 4096)` across regional cells with zero overlap.

## Rollback

Mark the newly provisioned cell as draining, move reassigned orgs back to the source cell only after reducing tenant load, or provision larger compute backing on both halves.

## Escalation

Escalate to SRE Lead if a single hot organisation drives `> 70%` utilization on a minimal bucket range (`dedicated cell` trigger).
