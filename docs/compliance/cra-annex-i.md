# EU Cyber Resilience Act (CRA) Annex I Conformity Mapping

This document provides the public Regulation (EU) 2024/2847 Annex I essential
cybersecurity requirements mapping for Guardrails ADR (`grdr`), paired with
[`docs/compliance/cra-technical-file.md`](cra-technical-file.md) for release pages
and Article 32(5) open-source conformity documentation.

## Part I: Cybersecurity Properties Relating to Products with Digital Elements

| Requirement | Obligation Summary | Guardrails Capabilities | Repository / Verification Evidence |
|---|---|---|---|
| Annex I Part I (1) | Appropriate cybersecurity level, secure by default | `cap.preexec.enforce`, `cap.containment` | `packs/essentials/rules/essentials.cedar`, `grdr-core`, `grdr-sandbox-engine` |
| Annex I Part I (2)(a) | Delivered without known exploitable vulnerabilities | `cap.supplychain.provenance` | `.github/workflows/scan.yml`, `cargo deny --config security/deny.toml check` |
| Annex I Part I (2)(c) | Protect confidentiality and integrity via standard crypto | `cap.receipts.signed`, `cap.privacy.floor` | `crates/grdr-crypto/src/lib.rs`, `docs/legal/export.md` |
| Annex I Part I (2)(d) | Data minimisation (metadata default, privacy floor) | `cap.privacy.floor`, `cap.retention.policy` | `docs/design/29-compliance-and-privacy.md`, `grdr-comply` retention & floor checks |
| Annex I Part I (2)(f) | Limit attack surfaces and deny unapproved execution | `cap.preexec.enforce`, `cap.containment` | `crates/grdr-fastpath/`, `crates/grdr-broker/` |
| Annex I Part I (2)(k) | Record and monitor security-relevant activity | `cap.receipts.signed`, `cap.export.siem` | Signed Ed25519 receipts, `grdr comply export --format bundle`, `grdr comply verify` |
| Annex I Part I (2)(l) | Support secure deletion / erasure of user data | `cap.retention.policy` | GDPR Art. 17 erasure cascade, session DEK destruction, `crates/grdr-lake/src/erasure.rs` |

## Part II: Vulnerability Handling Requirements

| Requirement | Obligation Summary | Automation & Process | Repository Reference |
|---|---|---|---|
| Annex I Part II (1) | Identify and document components in SBOM | CycloneDX 1.7.2 & SPDX JSON per release | `docs/design/24-deployment-and-packaging.md` |
| Annex I Part II (2)-(3) | Address vulnerabilities without delay and regular testing | Dual-model reviews, fuzzing, `grdr-conformance` | `.github/workflows/fuzz.yml`, `crates/grdr-conformance/` |
| Annex I Part II (4)-(7) | Coordinated disclosure & public advisories (OpenVEX/CSAF) | Embargoed PSIRT intake + automated 24h/72h/14d clocks | `SECURITY.md`, `grdr comply incident-timeline`, `crates/grdr-comply/data/incident-regimes.yaml` |

## Automated CRA Clock & Crypto Allow-List Commands

```text
grdr comply incident-timeline --regime cra-eu-2024-2847 --incident-id INC-001 --summary "Exploited vuln" --detected-at 2026-11-27T00:00:00Z
grdr comply export --format cra-annex-i --out cra-annex-i.json
grdr comply audit-crypto --cargo-lock Cargo.lock --export-doc docs/legal/export.md
```

Note: `audit-crypto` inspects all `[[package]]` entries (direct and transitive) in `Cargo.lock`; any
transitive dependency on unapproved crates (such as `ring` via `quinn-proto`/`rustls-webpki`) is
explicitly flagged until trimmed from transitive feature flags.
