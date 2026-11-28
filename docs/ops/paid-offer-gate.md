# Paid Commercial Offer Gate (`OPS-27`, `LBC-28`, `docs/design/32`, `docs/design/36`)

Billing activation requires passing `HostedGateChecklist` plus every item enforced by `grdr_saas::evaluate_paid_offer_gate`:

| Gate Check | Required Evidence | Backing Artifact / Module |
| --- | --- | --- |
| `hosted_gate_passed` | All 5 items in `hosted-gate.md` verified | [hosted-gate.md](hosted-gate.md) |
| `reconciliation_zero_variance` | `reconcile_usage_vs_invoice` passes with 0% variance across Statement/Stripe/Kill Bill | `grdr_saas::usage`, [RB-09](../runbooks/RB-09-billing-reconciliation-halt.md) |
| `dunning_keeps_enforcement` | `TenantLifecycleRecord::local_enforcement_active()` stays `true` during `PastDue` / `Suspended` | `grdr_saas::ops`, [RB-11](../runbooks/RB-11-tenant-abuse-dunning-erasure.md) |
| `sanctions_screen_wired` | Fail-closed `SanctionsScreen` attached prior to provisioning paid org tenants | `grdr_saas::DeterministicSanctionsScreen` |
| `model_terms_reviewed` | External counsel review on `docs/legal/model-terms.yaml` fresh within 180 days (`LBC-28`) | [counsel-register.yaml](../legal/counsel-register.yaml), [model-terms.yaml](../legal/model-terms.yaml) |
