# SOC 2 Type I / II Readiness and Control Ownership Guide

Scope: Guardrails ADR (`grdr`) hosted and self-hosted Trust Services Criteria mapping
(`aicpa-tsc-2017` plus Availability `A1.2`/`A1.3` and Privacy `P4.1` per
`docs/design/29-compliance-and-privacy.md` section 11). External paid SOC 2 examination
remains gated by precondition `pre-external-audit` (`docs/plan/preconditions.toml`);
self-hosters inherit no third-party certification and generate evidence directly from
their deployment via `grdr comply`.

## Control Ownership Matrix (100% Assigned)

Generated directly from `crates/grdr-comply/data/regulatory-pack.yaml` via
`grdr comply export --format soc2`:

| Control | Category | Assigned Owner | Automated Product Evidence |
|---|---|---|---|
| `CC4.1` | Monitoring Activities | Compliance & Oversight Lead | Quarterly `OversightQualityReport`, rule review audits |
| `CC6.1` | Logical Access | Platform Identity & RBAC Lead | Agent inventory, RBAC policy, separation of duties |
| `CC6.2` | Access Approval | Security Operations Lead | Graded STEP_UP approval grants, deny-when-unreachable proofs |
| `CC6.3` | Least Privilege | Identity Broker Lead | Scoped lease records, Just-In-Time `SupportGrant` expiries |
| `CC6.5` | Data Disposal | Data Privacy Officer | Subject erasure cascades, DEK destruction, 35d backup cap |
| `CC6.6` | Boundary Protection | Containment Engineering Lead | OS sandbox execution containment, domain allow-list verdicts |
| `CC6.8` | Malicious Software Prevention | Policy Engine Lead | Deterministic pre-execution Cedar verdict enforcement |
| `CC7.2` | System Monitoring | Audit Chain Lead | Ed25519 signed decision receipts, OCSF export stream |
| `CC7.3` | Anomaly Evaluation | Detection Engineering Lead | Sigma detection rule fixtures and baselines |
| `CC7.4` | Incident Response | Incident Commander (PSIRT) | Scoped kill-switch logs, 24h/72h/14d timeline exports |
| `CC8.1` | Change Management | Release Engineering Lead | Signed policy revisions, risk tiers, dual-model review CI gates |
| `CC9.2` | Vendor & Component Risk | Supply-Chain Lead | MCP/skill digest pinning, `cargo deny`, manifest drift checks |
| `A1.2` | Recovery Objectives | Storage & Availability Lead | Server `RunBackupDrill` restore and PITR verification records |
| `A1.3` | Recovery Testing | Storage & Availability Lead | Lake flush, compaction, and erasure-on-restore replay tests |
| `P4.1` | Privacy Retention | Data Privacy Officer | Floor vs ceiling validator, `HoldsLedger`, Art. 30 RoPA |

## Shared Responsibility Note for Self-Hosters

- **Product layer:** Supplies Cedar 4.x pre-execution enforcement, cryptographic receipts,
  OSCAL 1.2.3 bundles, retention floor/ceiling validation, legal holds, and DSAR erasure tools.
- **Operator layer:** Operates PostgreSQL/SQLite backups, KMS/KEK custody, webhook TLS/SSRF
  egress boundaries, and quarterly restore drills.
- **Customer layer:** Approves legal bases, holds, DSAR identity verification, works-council
  consultation, and GRC target credentials.
