# Hosted Launch Readiness Gate (`OPS-25`, `docs/design/32`)

Every item below must pass before transitioning hosted SaaS cells beyond external precondition `pre-hosted-capacity`. Code-side checks are enforced in `grdr_saas::evaluate_hosted_gate`.

| Gate Check | Required Evidence | Backing Artifact / Module |
| --- | --- | --- |
| `cell_restore_under_4h_rto` | Measured regional cell PITR + lake/audit restore drill under 4 hours (`RPO <= 5m`) | [RB-01](../runbooks/RB-01-cell-restore-and-dr.md), [FLEET-VERIFY](../runbooks/FLEET-VERIFY.md) |
| `backup_restore_verified` | Hash-verified relational & blob snapshot verification across `ha` / `distributed` | [RB-06](../runbooks/RB-06-postgres-failover-and-pitr.md) |
| `slo_burn_alerts_active` | Prometheus multi-window 14.4x / 6x fast-burn alerting live | [slo-rules.yaml](slo-rules.yaml), [RB-10](../runbooks/RB-10-slo-burn-rate-incident.md) |
| `org_export_roundtrip_passed` | Lossless `OrgMigrationBundle` export/import roundtrip (`lake/` + `audit/` + watermarks) | `grdr_saas::portability`, [RB-03](../runbooks/RB-03-org-cell-migration-and-export.md) |
| `runbooks_complete` | Structured RB-01..RB-12 runbooks with bounded `OperationsRunner` caps | [RB-INDEX](../runbooks/RB-INDEX.md), [bounds.toml](bounds.toml) |
