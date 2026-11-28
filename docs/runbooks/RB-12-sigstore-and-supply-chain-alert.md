---
id: RB-12
actor: security-oncall
rto: 1h
rpo: 0m
---

# RB-12: Sigstore Transparency Log and Supply-Chain Alert

## Diagnosis

1. Triggered within 1 hour when Rekor transparency monitoring or crates/npm namespace checks detect an unexpected signature, OIDC issuer mismatch, or untrusted provenance digest.
2. Inspect `security/trust-core.paths`, release workflows, and Sigstore bundle signatures for the flagged artifact.

## Actions

1. Pause downstream release promotion and TUF metadata publication immediately.
2. Compare suspect binary hash against reproducible builder digest (`verify-artefact` / SLSA provenance).
3. If unauthorized signing is confirmed, execute key revocation and yank (`RB-07`) and populate `docs/ops/security-advisories/vex-csaf-template.json`.

## Verification

- Verify all published release manifests validate strictly against expected repository workflow OIDC claims and clean `cargo deny --config security/deny.toml check` output.

## Rollback

Do not re-enable automated release tags until root cause and signer credential hygiene are independently verified.

## Escalation

Escalate to Steward Owner and external coordinated disclosure list per repository root `SECURITY.md`.
