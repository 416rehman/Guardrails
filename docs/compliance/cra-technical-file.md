# EU Cyber Resilience Act (CRA) Technical Documentation Skeleton

This document provides the public Article 32(5) technical documentation file
for Guardrails ADR (`grdr`) under Regulation (EU) 2024/2847 (Cyber Resilience Act),
implementing work item E7.1 of `docs/design/29-compliance-and-privacy.md` and
`docs/design/35-product-security-programme.md`.

## 1. General Product Description and Intended Purpose

- **Product name:** Guardrails ADR (`grdr`)
- **Product kind:** Open-source agent detection and response (ADR) platform
  providing deterministic pre-execution policy enforcement (Cedar 4.x),
  runtime containment, signed audit receipts, and compliance evidence export.
- **Software architecture:** Layered Cargo workspace (`Cargo.toml`, `docs/design/03-system-architecture-and-modularity.md`):
  - Layer 0/1 pure engine, protocol, and verification crates: `grdr-schema`, `grdr-strings`,
    `grdr-model`, `grdr-crypto`, `grdr-core`, `grdr-fastpath`, `grdr-fastpath-ffi`,
    `grdr-ffi`, `grdr-policy-ref`, `grdr-schema-lint`, `grdr-wire`, `grdr-proto`,
    `grdr-messages`, `grdr-llm-proto`, `grdr-mcp-proto`, `grdr-ui-model`
  - Layer 2/3 platform services, containment, storage, and compliance crates:
    `grdr-agents`, `grdr-broker`, `grdr-sandbox-engine`, `grdr-update`, `grdr-comply`,
    `grdr-lake`, `grdr-integrations`, `grdr-export`, `grdr-compat`, `grdr-identity`,
    `grdr-review`, `grdr-jobs`, `grdr-wasm`, `grdr-ports`, `grdr-ports-testkit`,
    `grdr-blob`, `grdr-bus-log`, `grdr-bus-nats`, `grdr-rel-postgres`, `grdr-rel-sqlite`,
    `grdr-store-local`, `grdr-os-clock`, `grdr-os-service`, `grdr-ipc-os`, `grdr-peer-os`,
    `grdr-sensor-linux`, `grdr-sensor-macos`, `grdr-sensor-windows`, `grdr-conformance`,
    `grdr-interface-gen`
  - Layer 4 workspace programs: `grdr` CLI, `grdr-daemon`, `grdr-hook`, `grdr-engine`,
    `grdr-server`, `grdr-approve`, `grdr-tray` (plus excluded targets `grdr-sensor-linux-bpf`
    under `bpf/` and `grdr-desktop` under `desktop/`)
- **Deployment shapes:** `standalone` (single endpoint, metadata-only default capture),
  `embedded` (single-node server), `ha` (multi-zone server with PostgreSQL 18 and S3/SeaweedFS/Ceph RGW),
  and air-gapped isolated operation (`network.mode = "isolated"`, S-31).
- **CRA classification note:** Pre-execution policy enforcement, endpoint detection, and
  tamper-evident security telemetry align with Annex III important product categories
  (Class I / Class II). Final statutory classification and Article 32(5) conformity
  self-assessment vs third-party assessment before any commercial or paid distribution
  are confirmed with legal counsel per `docs/design/29-compliance-and-privacy.md` section 10.

## 2. Design, Development, and Annex I Cybersecurity Properties

- **Secure by default configuration (Annex I Part I):**
  - Default shipping enforcement is `grdr.essentials` (`packs/essentials/`), forbidding
    agent edits to control files, bypass flags, and honeytoken misuse while gating
    credential-store reads and out-of-workspace recursive deletions with step-up approval.
  - Telemetry and network egress default to minimal metadata with zero undeclared outbound
    destinations (`grdr egress --isolated`, `P8`, `P16`).
- **Cryptographic update and rollback protection:**
  - Dual-root TUF chains (project root + deployment root) and DSSE envelopes (`grdr-update`)
    enforce strict monotonic version/generation checks, security-floor invariants, digest
    verification, and explicit operator terms acceptance (`S-31`).
- **Tamper-evident audit and fail-closed defaults:**
  - Hash-chained local receipt logs (`grdr audit verify`), A/B atomic update slots, and
    bounded-time hook fail-closed handover tables (`grdr-conformance`).
- **Data minimisation and workplace privacy (`P8`):**
  - Two-layer keyed pseudonyms, configurable data classes (`metadata` default), local
    pre-preview redaction (`grdr support-bundle --preview`), and works-council profile gates.

## 3. Cybersecurity Risk Assessment Reference

- Canonical threat model and trust boundaries: `docs/design/02-threat-model.md`.
- Trust-core path inventory requiring dual-model independent review and heightened CI checks:
  `security/trust-core.paths` (kernel eBPF/sensor shims, cryptography, policy evaluator,
  updater/TUF, tenant authorization, CI/release gates).
- Automated static, secret, workflow, dependency, and structure gates:
  `cargo clippy` (no panics/indexing/unsafe), `cargo deny`, `CodeQL`, `Semgrep`,
  `osv-scanner`, `gitleaks`, `zizmor`, and `grdr-schema-lint`.

## 4. Vulnerability Handling and CRA Article 14 Reporting Clocks

- **Coordinated vulnerability intake:** Defined in `SECURITY.md` (private embargoed intake,
  reproducer workflow, no public disclosure prior to coordinated fix window).
- **Automated reporting timelines (`docs/design/35-product-security-programme.md` section 4.7):**
  - **24 hours:** Early warning notification upon confirming an actively exploited
    vulnerability or severe security incident.
  - **72 hours:** Initial vulnerability / incident notification with severity, affected
    versions, and initial indicators.
  - **14 days (actively exploited vulnerability) / 1 month (severe incident):** Final
    report with root cause, corrective measures, and mitigation status.
- Customer-facing incident timeline exports follow the closed regime clock registry in `grdr-comply`.

## 5. SBOM, Build Provenance, and VEX Artefacts

- **Software Bill of Materials:** Generated per release artefact in CycloneDX 1.7.2 JSON
  and SPDX formats (`docs/design/24-deployment-and-packaging.md`).
- **Provenance and signing:** SLSA Build Level 3 hermetic build pipeline with keyless Sigstore
  bundles attached as OCI referrers, SHA-256 digests recorded in the release manifest, and
  offline air-gap bundle manifest verification (`grdr airgap verify`).
- **Vulnerability Exploitability Exchange:** OpenVEX and CSAF advisories published alongside
  supported release lines (`docs/design/35-product-security-programme.md`).

## 6. Support Period and Security Updates

- Published release lines, LTS cadence, upgrade hop bounds (at most two minors with required
  LTS stops), and security fix commitments are maintained in `docs/design/34-documentation-support-and-lifecycle.md`
  and `support.toml`.
- Under CRA Article 13(8), any paid/commercial distribution carries at least a five-year
  support period unless shorter expected product use is justified and approved with legal counsel
  before offer (`docs/design/29-compliance-and-privacy.md` section 10).
- Security fixes for supported open-source release lines are provided free of charge.

## 7. Export-Control Hygiene and Cryptography Notice

- Guardrails ADR uses only standard, publicly specified cryptographic primitives vetted in
  `crates/grdr-crypto/` (`ed25519-dalek`, `chacha20poly1305`, `sha2`, `zeroize`, and `rustls` /
  `aws-lc-rs` for transport/FIPS builds).
- No proprietary or non-standard cryptographic algorithms are included; CI dependency and schema
  allow-lists (`deny.toml`, `grdr-crypto`) block unapproved cryptographic primitives.
- Complete source code for every released open-source binary stays publicly available under
  Apache-2.0 (`LICENSE`, `NOTICE`). Private or pre-disclosure OEM/embargoed builds require
  separate legal compliance review before distribution.
