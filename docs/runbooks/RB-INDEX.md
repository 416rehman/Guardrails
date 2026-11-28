---
id: rb-index
actor: sre-operator
rto: 4h
rpo: 5m
---

# Guardrails ADR Operational Runbook Index

Every operational runbook below declares an accountable actor, diagnosis steps, bounded recovery actions, verification checks, rollback path, and escalation policy.

| Runbook | Scope | Target RTO | Accountable Actor |
| --- | --- | --- | --- |
| [RB-01](RB-01-cell-restore-and-dr.md) | Cell backup restore and regional disaster recovery | 4h | `sre-oncall` |
| [RB-02](RB-02-release-upgrade-rollback.md) | Rolling upgrade and minor rollback across planes | 30m | `release-manager` |
| [RB-03](RB-03-org-cell-migration-and-export.md) | Live org cell move and self-hosted export | 1h | `saas-ops` |
| [RB-04](RB-04-cell-split-and-rebalance.md) | Hot shard bucket split (`[0, 4096)` at 70% cap) | 45m | `saas-ops` |
| [RB-05](RB-05-nats-jetstream-recovery.md) | NATS JetStream stream & consumer recovery (`distributed`) | 30m | `sre-oncall` |
| [RB-06](RB-06-postgres-failover-and-pitr.md) | PostgreSQL 18 / CNPG primary failover & PITR | 30m | `sre-oncall` |
| [RB-07](RB-07-key-rotation-and-custody.md) | Ed25519 root/cell key rotation & compromise yank | 1h | `security-oncall` |
| [RB-08](RB-08-kill-switch-and-emergency-contain.md) | Emergency fleet kill-switch isolation and recovery | 15m | `incident-commander` |
| [RB-09](RB-09-billing-reconciliation-halt.md) | Meter drift halt and invoice ledger reconciliation | 2h | `billing-ops` |
| [RB-10](RB-10-slo-burn-rate-incident.md) | Fast 14.4x / 6x SLO error-budget burn triage | 15m | `sre-oncall` |
| [RB-11](RB-11-tenant-abuse-dunning-erasure.md) | Dunning enforcement preservation & legal-hold erasure block | 4h | `trust-safety` |
| [RB-12](RB-12-sigstore-and-supply-chain-alert.md) | Rekor transparency & crate namespace alert response | 1h | `security-oncall` |

After executing any recovery runbook, log verification results in [FLEET-VERIFY.md](FLEET-VERIFY.md).
