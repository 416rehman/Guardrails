# 29. Compliance and privacy

_Status: draft 3 against spine version 4. Owning squad: Compliance and privacy (crate `grdr-comply`, the `compliance` pack type in the content repository, the privacy-settings schema, the generated documents). Specifies D-46, D-51 (the regimes and the monitored person's view) and D-57 (retention presets, holds, subject requests). Read with: `00-decisions.md`; 04 (data classes, capture filter, integrity, `audit.access`); 16 (capture and redaction mechanics); 18 (approval flow, oversight metrics); 20 (lake retention, holds, crypto-shredding); 21 (roles, ContentGrant, re-identification objects, keys, regions); 22 (pack format); 23 (API); 24 (build, signing, SBOM); 27 and 28 (screens); 32 (hosted operations, drills); 35 (security process, PSIRT, our own reporting clocks); 36 (prices, contract text); `_review/02-owner-answers.md` (zero budget, the buddy as second person); `_review/04-owner-kit-instructions.md` (no human gates, instruction 7; the repository public from the first push, instruction 28) and the air-gap (P16) and language-token (D-69) reviews of 2026-11-11. Prerequisites are those of spine section 7._

## Summary

This document has two halves. Half A is what the product gives a customer who must comply: a control library shipped as signed data, a crosswalk from product capabilities to frameworks, evidence and OSCAL exports, retention presets, legal holds, subject requests, oversight-quality reports and generated privacy documents. Half B is what the project and the hosted service must hold themselves: supply-chain baselines, Cyber Resilience Act duties, SOC 2 and ISO certification, GDPR processor artefacts, accessibility reports and export-control hygiene. The privacy features of D-51 sit between the two halves, because they are both a product feature and the reason the product can be deployed in a European workplace at all.

Key choices:

1. **Compliance content is a pack type** (`compliance`) in the content repository, signed and ringed like any other pack (P7). It holds framework catalogues as identifiers plus our own one-line paraphrase, never licensed control text. Crosswalk entries map a stable *capability* id to control ids.
2. **Evidence is computed, not asserted.** Each capability has a declared, read-only evidence query that is limited to identifier, structural and derived fields. An `EvidenceItem` records the result per organisation and period, is signed, and exports as OSCAL 1.2.3 assessment results. We do not build a GRC product. Adapters push evidence into CISO Assistant, Probo and Openlane.
3. **Retention is policy with floors and ceilings.** Regime presets raise floors only when a legal basis is recorded. Privacy profiles set ceilings. When a floor and a ceiling conflict, the configuration is rejected and both clauses are named; a value below an active floor is rejected the same way. Legal holds pin catalogue entries (D-57) and must be reviewed within 12 months.
4. **The works-council privacy profile** is a locked organisation-layer privacy pack. It does not invent a second Mode. It requires a works-council co-approver for re-identification, capture increases and privacy-relevant pack promotions. It limits activity retention to 90 days and makes drill-down purpose-bound.
5. **Raising the organisation's capture level takes notice.** A raise takes effect 7 days after it is shown on every affected device, or 14 days under the works-council profile. An urgent need for content goes through a session-scoped ContentGrant (21), not a level change.
6. **Re-identification needs purpose, an incident reference and two approvers**, and the subject is told at once. Telling the subject can be deferred only under a recorded legal hold, for at most 90 days at a time. Quarterly counts of content grants and re-identifications are published to every monitored person in the organisation. Because re-identification must be impossible without that quorum, pseudonyms have two layers in server deployments: the sensor's device-side keyed pseudonym, then re-pseudonymisation at ingest by the `identity` target with a key the device never holds (D-51, R-18; section 8).
7. **Erasure is honest.** Deleting the mapping and destroying the content keys leaves pseudonymous security records. These records stay personal data until their retention ends, under a stated legal basis. We never call them anonymous.
8. **Oversight quality is reported per rule and per group of five or more, never per approver.** Brief 34's "outlier approvers" metric is rejected under P8.
9. **Project compliance costs nothing and covers every release.** OSPS Baseline, SLSA Build L3, CycloneDX SBOM and VEX ship with every release. Public CRA technical documentation is an early work item in the repository, which is public from its first push, and keeps the Article 32(5) open-source route available. Paid certifications attach only to the hosted service and require revenue or a sponsor (D-46); the hosted service itself requires revenue, sponsorship or donated cloud credits (D-63).
10. **We say "passes the AARM R1 to R9 test set"** until the AARM label conditions are met. The test runner is part of the efficacy harness (D-45).

## Requirements

| # | Requirement | Source |
|---|---|---|
| R1 | Control library with crosswalks, exported as OSCAL; SOC 2, ISO 27001 and 42001, NIST, EU AI Act deployer duties, NCSC and Five Eyes guidance, Singapore MGF, CSA AARM, AIUC-1, PCI and HIPAA retention | D-46, brief 34, h06 |
| R2 | Mappings keyed on stable document ids, because programme names change | h06 (EO 14434 renaming), brief 19 |
| R3 | A buyer-RFP response generated from live capability status, with the RFP's mandatory items as release gates | D-46, 01 parity checklist T1 to T17 |
| R4 | Monitoring catalogue, impact-assessment pack and worker notice generated from live configuration | D-46, l07 F7 |
| R5 | Retention defaults: content 30 days, structural 184 days, receipts 13 months; presets extend them only with a recorded legal basis | D-51, l07 F5 |
| R6 | Holds are catalogue pins checked by every delete path; erasure deletes the mapping and destroys content keys | D-57, 20 section 5.7 |
| R7 | Subject access, erasure and a record of processing (GDPR Arts. 15, 17, 30) | brief 34 matrix, l07 F5 |
| R8 | Pseudonymous principals; re-identification needs a purpose, an incident reference and two approvers, and is shown to the subject | D-51, SR-49 |
| R9 | No grouping by principal; health metrics reported per rule and per group of five or more | D-51, P8, l07 F3 |
| R10 | No covert mode; the disclosure surface cannot be hidden in any shape; conformance marks require the floor | D-51, l07 F10 |
| R11 | Privacy settings can only be narrowed by provider and operator layers; widening needs the organisation's signature in hosted and provider deployments | D-11, SR-26 |
| R12 | A works-council-ready configuration (BetrVG s.87(1) no.6, s.80(3)) | brief 34, l07 |
| R13 | Oversight-quality reporting: override rate, response time, deny when approvers are unreachable | Singapore MGF v1.5, D-46 |
| R14 | OSPS Baseline, SLSA Build L3, SBOM and VEX for every release, at no cost | D-46, brief 34 |
| R15 | Before any paid offer: counsel's view on CRA class and route, staffed 24-hour, 72-hour and 14-day reporting, an EU contact, public technical documentation, a support statement | D-46, D-63 |
| R16 | SOC 2 Type I, then Type II for the hosted service, requiring revenue or a sponsor; no tenant before the D-63 preconditions | Spine section 7, D-46, D-63 |
| R17 | Accessibility conformance reports for the web console and the desktop app at WCAG 2.2 AA | D-42, brief 33 |
| R18 | Self-hosters inherit no certification, so they need evidence generators and a shared-responsibility statement | brief 34 weak points |

## Design

### 1. Capability registry, control library and crosswalk

Three kinds of record live in the `compliance` pack, under `controls/` in the content repository.

- **Framework catalogue** `controls/frameworks/<doc-id>@<version>.yaml`. The document id is stable and the title is display-only: `nist-sp-800-53r5`, `iso-27001-2022`, `iso-42001-2023`, `aicpa-tsc-2017`, `eu-ai-act-2024-1689-c2026-07-27`, `sg-mgf-agentic-1.5`, `csa-aarm-1.0`, `ncsc-agentic-2026-08`, `fiveeyes-agentic-2026-05`, `pci-dss-4.0.1`, `hipaa-security-45cfr164`, `nist-csf-2.0`, `nist-ai-rmf-1.0`, `nist-ai-600-1`, `aiuc-1-2026q4`, `owasp-asi-2026`, `csa-aicm-1.1`. Each entry holds a control id and a paraphrase written by us, at most 20 words long. ISO and AICPA text is licensed, so the pack never copies it.
- **Capability** `controls/capabilities.yaml`: `{id, statement, decisions[], requires[], assurance_requirement, evidence_query, responsibility}`. `requires[]` names the components and external preconditions of spine section 7 that the capability depends on. Ids look like `cap.inventory.agents` or `cap.receipts.signed` and are never reused. `responsibility` is one of `product` (the software does it in every shape), `operator` (whoever runs the server) or `customer` (configuration or process).
- **Crosswalk** `controls/crosswalk/<doc-id>.yaml`: `{capability, control, relation (satisfies, supports, evidence-for), note}`. A control with no entry is reported as `not-addressed`. We do not hide gaps.

A UI label alias table maps "AI" to "SI" for US federal documents renamed under EO 14434 (h06). Ids never change.

**Initial crosswalk** (the content squad fills exact sub-control ids from the licensed texts). Evidence status by column: the EU AI Act, Singapore and AARM columns were read in the primary texts (brief 34 verification rows 2, 4 and 6). The SOC 2, ISO, NIST, PCI DSS and HIPAA columns rest on background knowledge (brief 34 tags them [K]; the ISO and AICPA texts are licensed and were not read), so every id in them is checked against the licensed text before E4.1 closes.

| Capability (decisions) | SOC 2 | ISO 27001:2022 / 42001 | NIST | EU AI Act (deployer) | Singapore MGF 1.5 | AARM 1.0 | PCI DSS 4.0.1 / HIPAA |
|---|---|---|---|---|---|---|---|
| `cap.inventory.agents`: agents, MCP servers, skills, models, owners (D-24) | CC6.1 | A.5.9; 42001 AI system inventory | 800-53 CM-8; CSF ID.AM | Art. 26(1) use per instructions (supports) | Agents "catalogued and centrally managed" | - | 12.5.1 asset inventory |
| `cap.preexec.enforce`: verdict before completion, session labels (D-07, D-09, D-13) | CC6.8 | A.8.2, A.8.16 | AC-3 | Art. 14 oversight measures | Prefer deterministic system-level controls | R1, R2, R3, R4 | 7.2.5, 8.6 |
| `cap.approval.graded`: STEP_UP, grades, deny when no approver (D-31) | CC6.2 | A.5.15 to A.5.18 | AC-5, AC-6 | Art. 14, Art. 26(2) | Approval checkpoints; deny by default when approval infrastructure fails | R4 | 7.2.5 |
| `cap.receipts.signed`: tamper-evident receipts and chains (D-39) | CC7.2 | A.8.15 | AU-9, AU-10 | Art. 12 logging (provider), Art. 26(6) six months | "Ensure log immutability" | R5 | Req. 10 (10.3 tamper protection) / 164.312(b) |
| `cap.attribution.graded`: agent versus human, evidence grade (D-25, D-26) | CC6.1 | A.5.16 | IA-2 | Art. 26(5) monitoring | Identity tied to a supervising agent, human or department | R6 | 8.6 / 164.312(b) |
| `cap.identity.brokered`: short-lived, scoped credentials (D-27); requires the credential broker and token service | CC6.3 | A.5.17, A.8.2 | AC-6, IA-5 | - | Scoped, time- or session-bound, non-transferable | R6, R9 | 8.6 |
| `cap.policy.change`: signed, staged, replayed changes (D-11, D-37) | CC8.1 | A.8.32 | CM-3 | - | Change-review triggers | - | 6.5 |
| `cap.roles.sod`: separation of duties (D-55) | CC6.1, CC6.3 | A.5.3, A.5.15 | AC-5 | Art. 26(2) authority | - | - | 7.2 |
| `cap.detect.respond`: findings, incidents, kill switch (D-30, D-54) | CC7.3, CC7.4 | A.5.24 to A.5.26 | IR-4; CSF RS.MI | Art. 26(5) suspend use and inform | - | - | 10.4 automated review / 164.308(a)(1)(ii)(D) |
| `cap.export.siem`: export contract (D-54) | CC7.2 | A.8.15 | AU-6 | - | OpenTelemetry logging | R8 | 10.4 |
| `cap.retention.policy`: presets, holds, erasure (D-57) | CC6.5, P4 | A.5.33, A.8.10; 27701 | AU-11 | Art. 26(6) | - | - | 10.5.1 (12 months, 3 immediately available) / 164.316(b)(2) six years |
| `cap.privacy.floor`: pseudonyms, capture levels, disclosure (D-51) | P-series | A.5.34; 27701 | PT family | Art. 26(7) worker information; Art. 5(1)(f) no emotion inference | - | - | 3.4 PAN unreadable (redaction, 16) |
| `cap.containment`: sandbox, egress (D-21, D-16) | CC6.6 | A.8.22 | SC-7 | - | OS-native sandboxes (GovTech case study); MCP allow-lists | R9 | 1.3 |
| `cap.oversight.report`: section 7 metrics | CC4.1 | 42001 performance evaluation | AI RMF MANAGE | Art. 26(2), (5) | Audit override rate and response time | - | - |
| `cap.supplychain.provenance`: digest pinning, drift (D-32) | CC9.2 | A.5.19 to A.5.21 | SR family | - | Whitelist MCP servers | R7 | 6.3 |

The AI Act column binds a customer only where its agent is used as a high-risk system under Annex III, and only from 2 December 2027 (brief 34 verification row 2). Art. 26(6) covers logs "under their control" and yields to data-protection law. Most coding-agent deployments are not Annex III uses, so for them the column is `supports`, not `satisfies`, and the generated reports say so. AARM rows map to the requirement ids R1 to R9 as brief 34 lists them; R7 (drift tracking) is mapped only to provenance drift until the runner (section 7) confirms what its test rows exercise.

The NCSC and Five Eyes crosswalks add one report each (section 7). AIUC-1 and AICM are crosswalked so that customers can use our evidence for their own certification. We do not hold either certificate ourselves (section 11).

### 2. Evidence collection and export

The component definition is built in CI and needs nothing else. Evidence items, assessment results, the evidence API and the GRC adapters require the server (D-46).

An **evidence query** is a named, versioned query over the typed query layer (20), declared in the pack with `reads[]` (field paths), `max_class` (at most `derived`) and `group_by` (never a principal field). The pack validator enforces all three, and also rejects any aggregation keyed by principal. Evaluation runs as a daily job in the `audit` target (D-33). Standalone runs it on demand through `grdr comply evidence`.

`EvidenceItem {id, organisation, capability, control_refs[], period_start, period_end, result (met, partial, not-met, not-evaluable), metrics map<string,int64>, sample_ids[] (receipt, finding or audit ids, at most 20), query_digest, pack_digest, schema_rev, signature}`. Assessments read `not-evaluable` exactly as P9 reads "could not look". For example, an assessment period with pipeline lag above the D-56 objective is `not-evaluable` for detection capabilities. The server signs the item with its audit key (21), and the item is chained into the organisation's checkpoint chain (D-39).

Export formats:

- **OSCAL 1.2.3 component definition**: one per release, built in CI from `capabilities.yaml`, the crosswalk and the D-23 ceiling matrix. It is static and states what the product can do. Self-hosters and agencies import it into their own SSP.
- **OSCAL assessment results**: one per organisation and period, made of evidence items, with `sample_ids` as OSCAL observations. Content is never included.
- **CSV and PDF** for buyers without OSCAL tooling.
- **Evidence package for an offline auditor:** `grdr comply export --format oscal|csv|pdf --period <p> --out <file>` writes the assessment results with the audit key's certificate chain to the deployment root, the checkpoint-chain segment covering every item, and an inclusion proof per item. `grdr comply verify <file> --fingerprint <deployment root>` checks it on any machine with no server and no network. OSCAL validation runs on the schemas vendored in the release (24 section 7). The package holds metadata and sample ids only.
- **Evidence API**: `ListEvidence(organisation, capability, period)` with signed records. This is the seam for FedRAMP 20x machine-readable Key Security Indicators (section 11).
- **GRC adapters**: integration manifests (D-40) that push evidence items. The two first-party members are CISO Assistant and Probo (D-40's two-member rule); Openlane and others arrive through the content lane. Comp AI is AGPL, so it is reached only over its API, never in process.

### 3. RFP response and release gates

`grdr comply rfp` renders a response from three inputs: the capability registry, the `PLAN.md` matrix (D-50) and the published ceiling matrix (D-23). For each item it states its prerequisites (`requires[]`), the assurance reachable per OS and incumbent, and whether the item is unmet in the release being described. 01 lists T6 and the credential halves of T12 and T16 as unmet in any release without the credential broker and token service (D-27). The 17 parity items T1 to T17 from 01 are the mandatory set. Each has an acceptance test in `PLAN.md`, and a release that claims an item whose test is red fails the release gate. A design partner's RFP adds items through the same file; only items marked `mandatory` gate a release.

### 4. Retention presets, ceilings and holds (D-57)

Retention applies to 20's three physical tables (`content`, `activity`, `decision`; `agg_daily` and the archive lanes follow the table they summarise) and to the audit log (21). One `RetentionPolicy {organisation, content_days, activity_days, decision_days, audit_days, hot_days, presets[], legal_basis[], ceilings_from}` is the effective value. Lengthening any value is a privacy widening (D-11, D-31): it needs the privacy officer plus the organisation owner (D-55) at the organisation layer, the co-approver under the works-council profile, a recorded legal basis per extended class, and the organisation's signature in hosted and provider deployments. Shortening applies after staging. A value below an active preset's floor is rejected; to go lower, the privacy officer removes the preset first, with a recorded reason, so the record of processing never claims a regime the configuration does not meet.

| Preset | content | activity | decision | audit | Basis (verified unless marked) |
|---|---|---|---|---|---|
| default | 30 d | 184 d | 13 mo | 13 mo | D-51 |
| `eu-ai-act-deployer` | 30 d | 184 d | 13 mo | 13 mo | Art. 26(6), "at least six months"; applies to Annex III systems from 2 Dec 2027. The 184-day default already covers six calendar months; the preset records the legal basis and locks it as a floor |
| `pci-dss-4` | 30 d | 12 mo, 3 mo hot | 13 mo | 13 mo | Req. 10.5.1: 12 months, three immediately available [K] |
| `hipaa` | 30 d | 12 mo | 6 y | 6 y | Six-year documentation rule, 164.316(b)(2) [K]; the audit-log period is not fixed by the rule, so this is a buyer norm. The Security Rule revision is not final (projected July 2027, h06) |
| `nydfs-500` | 30 d | 3 y | 5 y | 5 y | 23 NYCRR 500.6, three and five years [K] |
| `colorado-adm` | 30 d | 184 d | 3 y | 3 y | Three-year records under SB26-189 (brief 34, verified). Only for customers whose agents take part in consequential decisions the statute covers; the duty attaches to decision records, not security telemetry, so the preset's notes tell the customer to confirm scope with counsel |
| `sox-itgc` | 30 d | 184 d | 7 y | 7 y | Common audit practice [K]; 7 years is the ceiling in 21 |
| `works-council` (ceiling profile) | 30 d (evidence spans and ContentGrant reads only, since the level is `metadata`) | at most 90 d | 13 mo | 13 mo | Typical works-agreement minimisation [K]; counsel confirms (spike SP-29-3) |

Rules:

1. The effective floor is the maximum across active presets. Ceilings come from the privacy profile. A floor above a ceiling is rejected, and the error names both presets and clauses. The privacy officer then removes one of them, with a recorded reason.
2. Absolute ceilings are content 1 year, every other class 7 years, and backups at most 35 days (20). Holds are the only thing that exceeds a ceiling.
3. `hot_days` sets how many days the query layer serves at console latency (20). Older days stay queryable through lake scans.

**Legal hold** `Hold {hold_id, organisation, scope {pseudonyms[], session_ids[], incident_id, classes[], from, to}, matter_ref, reason, created_by, approvers[2] (privacy officer and organisation owner), review_by (at most 12 months; renewal needs two approvers), notify_subject (now | deferred_until, at most 90 days, renewable by two approvers), state}`. A hold pins catalogue entries and content keys. Every delete path calls `Holds::check` (20). A subject erasure that meets a hold is recorded, reported to the subject as "pending, held" (or only "pending" while notice is deferred), and runs when the hold is released. Creating, renewing and releasing a hold are `audit.admin` records. An expired `review_by` raises a finding for the privacy officer. It does not release the hold silently.

### 5. Subject requests and the record of processing

`SubjectRequest {id, organisation, kind (access, erasure, restriction, objection), subject_ref (an IdP subject or OS identity, verified by the privacy officer), pseudonyms[] (resolved through the vault), received, due (received plus one month; GDPR Art. 12(3)), state, output_ref}`.

- **Access**: a bundle of every record keyed to the subject's pseudonyms, at the stored capture level. It includes their `audit.access` and re-identification records and the effective policy that applied to them. The bundle is generated within 24 hours of approval and handed to the subject through the privacy officer. It is the same data that "My activity" shows (section 9), packaged.
- **Erasure**: the `identity` target deletes the mapping; `store` destroys the content keys of the subject's root sessions and reduces their archived events at once (20 section 5.7). Backups age out within 35 days; a restore replays key destructions and reductions from `state-log/` (20), so a restore never revives erased content. The response tells the subject that pseudonymous security records remain until their retention ends, and on which basis: a legal obligation or legal claims (Art. 17(3)(b), (e)), or, where the request rests on an objection, the organisation's compelling legitimate grounds for security logging (Art. 17(1)(c) with Art. 21(1)) [K]. The organisation states which in its record of processing. Pseudonymous records are personal data while the pseudonym key exists. We never call them anonymous.
- **Restriction and objection** add the pseudonym to the organisation's exclusion list (D-51) for future collection. The decision on past data is recorded by the privacy officer.

**Record of processing** (Art. 30): `grdr comply ropa` generates it from configuration. It covers purposes (security monitoring of AI agents), data categories (from the field registry and the capture level), recipients (configured export sinks, integrations, provider delegations, sub-processors in hosted deployments), transfers (organisation region, judge back end region per D-29), retention (the effective policy) and measures (a link to the component definition).

### 6. Generated privacy documents

All four are rendered from the same JSON model (`grdr.comply.v1alpha1`) to HTML and PDF in the console and to Markdown in the CLI. Strings are language tokens (D-69), rendered in the reader's locale. They are regenerated on every configuration change, and versions are kept with diffs.

| Document | Content | Audience |
|---|---|---|
| **Monitoring catalogue** | For each enabled pack and rule: the rule sentence, fields read with data classes (from the pack manifest, P7), outputs (verdict, label, finding), who can read the result (roles), retention; dated diff history; a fixed list of evaluations the product never performs (per-person scores, productivity, keystrokes, screen, clipboard, emotion inference) | Works council, DPO, monitored people |
| **Worker notice** | Plain-language summary: what is collected at the current capture level, what never is, who can read content and on what condition, retention, exclusions, the contact, how to contest a block and how to request access | Every monitored person; shown at enrolment (D-48) and in the Privacy screen |
| **Impact-assessment pack** | GDPR Art. 35(7) structure. The description, data flows, recipients and measures are generated. Necessity and proportionality are prompted questions for the controller. Risks are prefilled from 02's privacy threats (ADV-10). A FRIA appendix (AI Act Art. 27) applies only to deployers the article names [K] | DPO, controller |
| **Works-agreement annex** | German and English. Purposes, the monitoring catalogue by reference, the prohibited evaluations, the re-identification procedure, the co-approver role, retention, the notice periods of section 8, the s.80(3) expert's access to the source and configuration | Works council (BetrVG s.87(1) no.6) |

A pack version that reads a new field or a higher class is *privacy-relevant* (l07 F7). It never auto-promotes past the organisation's current version. It appears as a pending diff in the monitoring catalogue and needs the privacy officer's acknowledgement, or under the works-council profile the co-approver's as well. 22 rings it; this document defines the gate.

National variants: France (CSE consultation), Netherlands (WOR Art. 27), Austria (ArbVG s.96 and 96a), Italy (Workers' Statute Art. 4). Each one is a template in the pack, with no code change. Each template requires review against that country's law, which a design partner in that country or a free legal programme supplies.

### 7. Oversight-quality and posture reports

18 section 12 computes the metrics. This document packages them as compliance evidence. The finest grain is the rule, the group of five or more, or the organisation (P8). Approver-level ranking is not built.

| Report line | Definition | Maps to |
|---|---|---|
| Override rate | (denied + modified) / decided approvals, per rule class | Singapore MGF override rate |
| Response time | Median and p95 approval latency per queue; oldest pending | Singapore MGF; AI Act Art. 14 |
| Deny when unreachable | Share of Ask that became Block because the minimum grade or the approver was unavailable (D-31); timeout share | Singapore deny by default; AARM R4 |
| Grade mix | Approvals per rule class by grade (G0 to G3), and the share of Ask rules whose minimum is G0 or G1, the grades D-31 does not call unforgeable. Approvals below a class minimum cannot occur (Ask becomes Block), so that case is counted under "deny when unreachable". The D-31 time lock stands in for G1 only in a user's own local policy in the user profile, which never reaches these reports | NCSC "guaranteed and gated" approvals |
| Oversight assignment coverage | Share of Ask rules with an assigned approver group holding a competence attestation (`OversightAssignment {rule_class, group, attested_on, attested_by}`) | AI Act Art. 26(2) competence, training, authority |
| Justification coverage | Share of approvals in G2-or-higher classes that carry a written justification (18 stores the field on the grant's audit record) | Singapore written justification |
| Rubber-stamp rules | Rules flagged by 18's over-approval test | Brief 33 |

The **NCSC posture report** (h06) scores each agent type per group on the network ladder (1 unrestricted, 2 domain allow-list, 3 model API only, 4 no external network) and the compute ladder (1 none, 2 container, 3 virtualisation, 4 dedicated hardware). Both scores come from the assurance record and the containment mode (D-21). The report also covers identity class (D-27 `identity_proof`), credential exposure (16), log immutability (D-39) and kill-switch reach (D-30's four actuators). A downgrade on either ladder is a finding. The NCSC text is interim advice phrased as "should" (h06 verification row 1), and the report quotes it that way. The **Five Eyes report** covers per-agent identity, short-lived credentials and approval checkpoints (corroborated, h06 row 6) and the claim-versus-observation cross-check rate (D-13). The cross-check recommendation appears only in one secondary summary, so the report labels that line "single-sourced" until someone reads the primary PDF and records the clause in the catalogue.

The **AARM runner** is a scenario family in the efficacy harness (D-45) that implements the AARM 1.0 conformance table, including "system unavailable, action fails" and offline receipt verification. Its output is the only basis for the sentence "passes the AARM R1 to R9 test set (AARM 1.0, February 2026)". The label itself requires five production customers over three months, SOC 2 Type II, ISO 27001 or FedRAMP (each of which requires revenue or a sponsor), an active community representative and a benchmarking commitment (brief 34 verification row 4). AARM v2.0 is planned, so the runner pins the spec version.

### 8. Privacy settings, profiles and capture-level changes (D-51)

The device side works in every shape, standalone included. Organisation-layer settings, the works-council co-approver and server re-pseudonymisation require the server.

Privacy settings form one typed schema (`grdr.config` privacy section, owned here): `capture_level`, `retention`, `exclusions {principals, paths, repositories}`, `content_roles`, `model_review` (D-29), `git_notes` (D-26), `profile`, `contact`, `co_approver_group`. They live at the organisation layer. Provider and operator layers may only narrow them (D-11), and a device rejects an operator-signed artefact that widens them (SR-26).

**Profiles.**

| Setting | `standard` | `works-council` |
|---|---|---|
| Upload capture level | `metadata`; raising it needs privacy officer plus organisation owner | `metadata`; raising it needs privacy officer, organisation owner and a member of `co_approver_group` |
| Notice before a raise takes effect | 7 days, shown on every affected device | 14 days |
| Re-identification approvers | Two (21) | Two plus a member of `co_approver_group` |
| Activity retention ceiling | None (section 4) | 90 days |
| Privacy-relevant pack promotion | Privacy officer acknowledges | Privacy officer and co-approver |
| Model review tiers (D-29) | Off until chosen | Off until chosen and co-signed |
| Git notes (D-26) | Off by default | Off and locked |
| Drill-down below group level | Any role with `session.metadata.read` | Requires an open incident reference or an assigned finding; every drill-down writes `audit.access` |
| Device display names | MDM asset id if configured | Asset id only; hostnames and serials are vaulted |

Both profiles keep every element of the floor: pseudonyms, `redacted arguments` leaving the device only as evidence or under a ContentGrant, no input hooks and no screen or clipboard capture, the disclosure surface, no grouping by principal, and history from before enrolment staying local unless the user back-fills it (D-48). "Works-council mode" in earlier documents means this profile. It is not a Mode.

**Principal pseudonyms in two layers** (D-51, R-18; answers 21's open item and 04 R2; owner question 9 can move issuance entirely to the server). The organisation-wide HMAC key in 04 section 3 is on every enrolled device and readable by any local administrator, and by the user in the User profile. Human principal ids are HMACs over enumerable inputs (SIDs, uids, IdP subjects, all listable from the directory). Anyone who copies the key from one device and holds metadata access could therefore map every `prn_` in the organisation and bypass the two-approver re-identification without leaving an `audit.access` record. That would defeat D-51's re-identification quorum, so in server deployments:

- The sensor derives the device-side keyed pseudonym (04 section 3), so offline operation needs no server. The device-held key keeps serving the other digests (paths, argv, prompts, agent instances), which need on-device equality.
- At ingest the `identity` target re-pseudonymises every human principal field under a principal key the device never holds, KEK-wrapped (21). Stored, queried and exported records carry only the server pseudonym; the device-side value is kept only in the vault as the join key.
- The batches archived byte-exact for `grdr audit verify` (D-39) still carry device-side values, so they are readable only by the `identity` and `audit` targets.
- A local administrator who copies the device key can therefore link only that device's own records, never the organisation's stored data.
- Standalone keeps the local key generated at install (21). It has one user and nobody else to read.

Hostnames and hardware serials are identifier-class fields that go only to the vault. They are never written into events.

### 9. The monitored person's view

The person sees the same surface in the desktop app's Privacy and My activity screens (D-43), the tray, the local console and `grdr privacy show`. 27 and 28 design the screens. This document fixes the content, which no layer, white-label build or embedding can remove:

1. Status in one line: protected or watched, capture level, pending changes with their effective date.
2. What is collected, per data class, with a live sample of the person's own last records at the uploaded level, plus what never is.
3. Who can read content: the roles, the number of accounts in each role, and the condition (ContentGrant).
4. Who looked: every `audit.access` and re-identification concerning the person's pseudonyms, with the reader's role and display name, the purpose, the scope and the time. Readers act in an official capacity, so names are shown. The server pushes these records to the device over the control plane (22), and they are also visible in the console to an account whose IdP subject maps to the pseudonym (21).
5. Holds that cover the person, unless deferred (section 4), and the date the deferral ends.
6. Retention per class, exclusions in force, and the organisation's privacy contact. The contact is a required field at enrolment.
7. The organisation's quarterly transparency counts: content grants, re-identifications, holds and subject requests. Counts are shown only for organisations with five or more principals.

Standalone shows items 1, 2 and 6 and the local reads by the CLI and console. Nobody else exists to read. Items 3, 4, 5 and 7 require the server and its control plane.

### 10. Compliance of the project

Every duty in this table costs nothing (D-46).

| Duty | What we do | Requires | Owner of the mechanism |
|---|---|---|---|
| OSPS Baseline (v2026.08.28) | Level 3. Level 1 holds once the governance files land | The release pipeline (24) for the Level 2 and 3 controls on released artefacts | 30, 35 |
| SLSA Build L3, signed releases | Provenance for every artefact | The release pipeline (24). Windows user-mode binaries are signed through a free open-source signing programme (for example SignPath Foundation); macOS signing and notarisation require Apple's Developer Program, without which macOS artefacts ship with Sigstore signatures and provenance only, marked not platform-signed | 24 |
| SBOM | CycloneDX 1.7.2 per artefact; SPDX as a second format | The release pipeline | 24 |
| VEX | OpenVEX and CSAF per supported line | The release pipeline | 35 |
| OpenSSF Best Practices badge | Silver, reached through Passing | None | 30 |
| CRA technical documentation | Public in the repository as an early work item: product description, risk assessment (02), SBOM pointer, vulnerability policy, support statement. This keeps the Art. 32(5) route open | None for the skeleton; the complete file is a prerequisite of any paid offer | This document, 35 |
| Export-control hygiene | See below | None; an early work item | 24 |

**Cyber Resilience Act.** These dates are verified in briefs 34 and 28. Chapter IV applies from 11 June 2026, manufacturer reporting under Art. 14 from 11 September 2026, and everything else from 11 December 2027. Steward reporting (Art. 24(3)) starts on 11 December 2027. Annex III Class I names SIEM, anti-malware and identity or privileged-access software. Class II names firewalls and intrusion detection and prevention systems. An agent detection and response (ADR) product could fall in either class, so counsel decides. Article 32(5) lets manufacturers of free and open-source products in Annex III (not Annex IV) self-assess when the technical documentation is public at the time of placing on the market; it does not relax the Annex I requirements.

Two cautions decide the plan. First, point 54 and Example 15 of the Commission's non-binding guidance C(2026) 5252 indicate that a free client that connects to a paid service is itself placed on the market (brief 28 verification row 3). Loonaro should therefore plan as a manufacturer of the free sensor from the first paid offer (hosted service or paid intelligence tier), not as a steward. Second, Art. 13(8) sets a support period of at least five years unless the product's expected use is shorter. This is binding text. It sits above D-58's 24-month public LTS for any paid distribution, and counsel sets it before the offer (open question 1). Loonaro offers nothing paid until counsel has given that view; free legal help for open-source projects (foundation legal programmes) is the first route to it.

No CRA harmonised standard is cited in the Official Journal yet. EN 40000-1-1 and EN 40000-1-2 are scheduled for publication on 17 November 2026 (h06 verification row 8, secondary sources). We track them, and we do not depend on presumption of conformity. Our own reporting clocks (24-hour early warning, 72-hour notification, final report 14 days after a fix for an actively exploited vulnerability or one month after notification for a severe incident) are owned by 35 section 4.7, where agents run the clocks and prepare every report and Loonaro files them as the manufacturer (D-46). This document owns the customer-facing `IncidentTimeline` export, whose per-regime clock definitions are pack data: CRA for embedding manufacturers, NIS2 Art. 23, DORA, SEC 8-K Item 1.05 and NYDFS 500.17 [K].

**Export controls.** Published open source, binaries included, is not subject to the EAR. Since the 2021 change, notification to BIS and the NSA is needed only for non-standard cryptography (Linux Foundation guidance, brief 28). Rules:

1. We use only standard cryptography through vetted libraries (rustls, aws-lc-rs; D-63). A CI check rejects new cryptographic primitives outside `grdr-crypto`'s allow-list.
2. The source of every released binary version stays public.
3. Private artefacts that are not published need counsel's review (free foundation legal programmes first): embargoed fixes in the private fork (D-62), pre-disclosure builds, OEM private conformance builds. The same applies to sanctions screening for the hosted service and paid support, which brief 28 records from memory only.

The optional `fips` build (03) uses AWS-LC FIPS. AWS-LC 3 holds certificate #5314 and AWS-LC 4 is in process (brief 23). As 03 states, "uses a validated module" is claimed only for a bound version and operating environment that the certificate covers; macOS is not on AWS-LC's platform list.

### 11. Compliance of the hosted service

Everything in this section, except the penetration-test and trust-core review rows of the table below, requires the hosted service, which requires the `distributed` profile and its load test, a written incident-reporting process, two people on call (met by the owner and the buddy) and revenue, sponsorship or donated cloud credits (D-63, spine section 7). Self-hosting is the default way to run the platform, and a self-hoster needs nothing from this section.

**SOC 2.** SOC 2 requires revenue or a sponsor (D-46). The scope is the hosted service in the `distributed` profile: cells, router, global content and intelligence, the build and release pipeline that deploys it, and support access (SupportGrant, 21). Type I covers Security, Availability and Confidentiality. Privacy is added after the first Type II report. Most evidence comes from the product itself:

- CC6 from roles and just-in-time elevation (21);
- CC7 from our own findings and the synthetic sensor (D-56);
- CC8 from the merge queue, the evidence template, risk tiers, the evaluators' check runs and each pull request's metadata block (D-61, D-63; owner instructions 7 and 27), where every change names the evaluators that passed it and the model that wrote it;
- A1.2 and A1.3 from 20's restore drills.

We dogfood an open-source GRC tool and do not build one.

**Certifications, audits and assessments.** The budget is zero. Each entry states what triggers it, what it requires and how it is funded. A paid entry requires revenue or a sponsor; where a free route exists it is named and comes first. The penetration-test and trust-core review rows apply to the product and project in every shape, not only to the hosted service.

| Step | Trigger or prerequisite | Funding route | Notes |
|---|---|---|---|
| CSA STAR Level 1: CAIQ and AI-CAIQ self-assessment | The hosted service, before its first beta tenant (it describes a cloud service, so there is nothing to assess without one) | No fee; agent work on the subscription | Generated largely from the capability registry |
| External penetration test, summary published | Before the server's first stable release, then yearly | A free programme for open-source projects or a qualified volunteer; otherwise requires a sponsor | 35 commissions it |
| Privileged-core, updater, shim, approval-helper and transport review | Before each component's first stable-channel release; the transport before the server's first release (D-62; 35 section 5) | The trust-core evaluators (`eval-security` and `eval-adversarial` in clean contexts, two passing evaluators on different models; owner instruction 7), plus a free external audit (OSTIF, OpenSSF Alpha-Omega and similar funds) when one is granted. A kernel component leaves the internal ring only through D-62's review route, run by those evaluators plus any free external audit that has arrived (D-63) | 35 |
| SOC 2 Type I | The hosted service's preconditions (D-63) | Paid; requires revenue or a sponsor (D-46) | Auditor chosen before the hosted service takes a tenant |
| SOC 2 Type II | Type I and its observation window, then a yearly cycle | Paid; requires revenue or a sponsor | Privacy criteria added after the first Type II report |
| CSA STAR for AI Level 2 | Requires SOC 2 (the SOC 2 route yields a STAR for AI Attestation) | Unknown fee (Valid-AI-ted scoring) | Needs a Valid-AI-ted AI-CAIQ already on the STAR Registry; no minimum score published |
| ISO/IEC 27001:2022 | First EU enterprise demand, once SOC 2 Type I is held | Paid; requires revenue or a sponsor | Add 27701:2025 (standalone) on top; 27017 and 27018 on demand |
| ISO/IEC 42001 | Buyer demand, or the hosted service offering a platform-key model tier (D-29; there is no default model) | Paid; requires revenue or a sponsor | Voluntary; not needed for ML use (brief 34 verification) |
| HIPAA BAA template and mapping | First healthcare customer | Legal help: free foundation legal programmes first | No certificate exists |
| DORA Art. 30 addendum | First EU financial customer | Legal help: free foundation legal programmes first | 36 drafts it |
| CRA conformity file | Before the first paid offer, and in any case before the CRA's main obligations apply on 11 December 2027 | Counsel through free foundation legal programmes first; a notified body, if the class needs one, is paid and requires revenue or a sponsor | Depends on the class and on Art. 32(5) |
| VPAT 2.5 INT accessibility reports | The web console report with the server; the desktop report with the Rune app (requires S-19) | Automated scans and U09's screen-reader journeys judged by `eval-a11y` cost nothing; an assessor's audit from a free accessibility programme or a qualified volunteer adds evidence when one is available and never gates (owner instruction 7) | Section 12 |
| FedRAMP 20x Class B (Low), then C (Moderate) | A US federal buyer with funding | Paid; requires the buyer's funding or revenue | Both pipelines open since 31 Aug 2026; new Rev5 certifications end 11 June 2027 (brief 34 verification row 7); FIPS build required [K] |
| AIUC-1 | Only if we host an agent product | n/a | Customers use our evidence |
| Regional (BSI C5, Cyber Essentials Plus, IRAP, ENS, TISAX, HDS) | On demand | Paid; requires revenue or a sponsor | Self-hosting often removes the need |

**GDPR artefacts** (36 writes the contract text; this document fixes the content):

- **Processing agreement** (Art. 28): Loonaro is processor for tenant data and controller for account and billing data. Instructions are limited to running the service (D-51). The agreement covers no training on tenant data, deletion at exit by crypto-shredding within 30 days with a signed receipt (D-57, D-67), audit rights through the SOC 2 report and the generated control file, and a breach notice to the controller without undue delay and within 24 hours of confirmation (Art. 33(2); the figure 36 and 35 section 4.7 use). With an MSP, the provider is processor and Loonaro its sub-processor, with flow-down (36).
- **Sub-processor registry**: a public page plus an RSS and JSON feed generated from 36's `legal/subprocessors.yaml`, 30 days' notice of additions, and an objection right ending in exit with export (D-67). Each entry holds name, purpose, region, data classes and transfer mechanism. A model provider appears only for organisations that choose a platform key (D-29).
- **Transfers**: SCCs (2021/914, modules 2 and 3) and the UK addendum wherever data or support leaves the region [K]. Whether to self-certify under the EU-US Data Privacy Framework is a decision for 36 [K].
- **Residency**: an organisation is pinned to a region at creation (D-35; `eu` and `us` assumed, 21). Content, keys and the vault never leave it. Operator support from outside the region is metadata-only through SupportGrant. Judge back ends obey the region (D-29).
- **Impact-assessment template**: the section 6 pack, prefilled for the hosted service.

## Interfaces and contracts

| Interface | Shape | Counterpart |
|---|---|---|
| `compliance` pack type | `controls/` layout of section 1; evidence queries declare `reads[]`, `max_class`, `group_by`; signed with one verifier | 22 (format, rings), 13 (validator) |
| `grdr.comply.v1alpha1` | `Capability`, `CrosswalkEntry`, `EvidenceItem`, `RetentionPolicy`, `Hold`, `SubjectRequest`, `OversightAssignment`, `PrivacyProfile`, `MonitoringCatalogue`, `DisclosureView` | 04 (imports `grdr.common` only), 23 (API) |
| API services | `ComplianceService` (`ListCapabilities`, `ListEvidence`, `ExportOscal`, `RenderDocument`), `RetentionService` (`Get`, `Propose`, `ListPresets`), `HoldService`, `SubjectRequestService`; widening calls are step-ups (D-31) | 23, 21 (permissions `privacy.settings.write`, `reidentify.approve`, new `hold.manage`, `subject_request.manage`) |
| Retention and holds | `RetentionPolicy` and `Hold` in the relational store; `Holds::check` | 20 |
| Re-identification, ContentGrant | Objects and quorum | 21; this document adds the `co_approver_group` requirement |
| Oversight metrics | Per-rule and per-group aggregates; justification field on grant audit records | 18 |
| Disclosure push | `audit.access` records about a pseudonym delivered to its devices | 22 |
| Pack privacy diff | Manifest `reads[]`, class ceiling, labels written; a privacy-relevant flag computed by the validator | 13, 22 |
| CLI | `grdr comply catalogue`, `evidence`, `export --format` (`oscal`, `csv` or `pdf`), `rfp`, `ropa`; `grdr privacy show`, `notice`, `catalogue`; `grdr retention show` | 03 |
| Incident clocks | `IncidentTimeline` export with clock fields per regime (CRA, NIS2, DORA, SEC, NYDFS); regime clocks are pack data | 18; 35 owns our own clocks |
| Principal pseudonyms (D-51 two layers, R-18) | `identity` target re-pseudonymises human principal fields at ingest; the device-side value stays in the vault as the join key | 04 (id derivation), 21 (key hierarchy), 20 (ingest into `store`) |

## Behaviour by deployment shape

- **Standalone.** The privacy floor and the local disclosure view apply. `grdr comply evidence` runs locally, and `grdr audit verify` covers receipts. No retention presets apply beyond D-52's local defaults, and no GDPR artefacts are produced.
- **Platform, self-hosted.** The customer is controller and operator, so no Loonaro DPA exists. Generated documents name the customer's own recipients. The OSCAL component definition and the shared-responsibility matrix (`responsibility` column) are what the customer inherits. Our certifications do not transfer.
- **Platform, SaaS.** Everything above, plus the processor artefacts, regions and certifications of section 11 (each certification once funded). Provider deployments add the organisation-signature rule for widening (SR-26) and dual audit logs (21). A provider sees transparency counts for its organisations only as aggregates.
- **Embedded.** The partner is the manufacturer and usually the processor. The conformance marks (D-41, D-60) require the section 9 floor and the absence of covert collection at L2 to L6. We supply the CRA documentation pack, SBOM and VEX for our components as an OEM service (D-04). A rebuilt white-label product (L6) must keep the disclosure surface. Its brand manifest may restyle the surface and may not remove it.

## Extension points

- New framework or version: a catalogue file plus a crosswalk file with golden tests. No code change.
- New retention preset, privacy-profile template or national works-agreement template: pack data.
- New evidence query: pack data, validated against the field registry.
- GRC, ticketing or document destinations: integration manifests or WebAssembly components (D-40).
- Translations of the notice, catalogue and annex: language tokens under 34 section 15a; each rendered document states its locale and that the English text governs unless the organisation adopts a translation.

## Security and privacy

- Evidence exports contain metadata and sample ids only. They are signed, and every export is an `audit.admin` record.
- The `compliance` pack can only read. It cannot write labels, verdicts or settings, and it may not read above `derived` (P7).
- Holds are a privacy risk, so they carry a mandatory review date. Deferred subject notice is capped and needs two approvers each time.
- Re-identification abuse (ADV-10) is handled by the quorum, by subject notice and by the transparency counts. A re-identification request from inside an agent session is refused (D-31).
- Retention extension and capture raises are widening operations at the privacy class's minimum grade (D-31) and cannot be proposed by operator or provider layers.
- Generated documents never contain names. They describe classes and roles.

## Test and evaluation strategy

| Property | Test | Oracle |
|---|---|---|
| Crosswalk integrity | Every control id exists in its catalogue version; every capability has a query that compiles against the field registry; no evidence query exceeds `derived` or groups by principal | Schema validator plus the pack validator; mutation test with a planted principal `group_by` |
| OSCAL validity | Component definition and assessment results for three fixture organisations | NIST OSCAL 1.2.3 JSON schemas and a round trip through compliance-trestle, both external |
| Retention presets | Injected clock over a synthetic lake of 400 days with every preset combination | A separate reference model computes the expected surviving objects and keys; an object-store lister compares them |
| Floor-ceiling conflict | `pci-dss-4` with `works-council` | Rejection naming both clauses |
| Holds | Erase a held subject; expire a hold review; restore across a hold | 20's delete-path enumeration plus an object lister; erasure runs only after release |
| Subject access | Seeded subject across 10 devices | Brute-force scan of the lake and relational store for the pseudonyms matches the bundle exactly |
| Erasure | Erase, then try every API, the console and a backup restore | No mapping resolvable; content undecryptable (20 drill) |
| Pseudonym recomputation | With full device key material and the directory's SID and subject list, try to reproduce any stored `prn_` value, and to link another device's records | No match in stored, queried or exported records; only that device's own local records link |
| Group of five | Property test over the query layer and evidence queries | Recount from raw rows; no cell below five with a principal dimension |
| Monitoring catalogue completeness | For every installed pack, compare the catalogue's fields to the effective read set | The validator's computed read set from manifests; golden diff |
| Works-council profile | Every widening without the co-approver, attempted from the CLI, console, API and a deep link | Refused (SR-49 test in 02) |
| Disclosure floor | Attempt to hide the surface from each layer and from a brand manifest | Surface reachable from the CLI and tray (02 TM-15) |
| Notice period | Raise the capture level | No upload above `metadata` before the effective date; canary strings absent (04, 16 canary suite) |
| Oversight report | Metrics on a fixture of 10,000 receipts | Independent recomputation from receipts |
| AARM runner | AARM 1.0 conformance table | The table's own expected outcomes |
| Legal readiness | Works-council review of the default configuration and documents (l07 spike 4) | Written opinion from an employment-law expert in the s.80(3) role |

## Work breakdown

**E1 Privacy floor on the device**
- E1.1 Privacy-settings schema and the two profiles at the local layer. Accept: a provider- or operator-signed artefact that widens any privacy setting is rejected on the device.
- E1.2 Disclosure view items 1, 2 and 6 in the CLI and local console. Accept: a live sample matches the last uploaded record byte for byte at the stored level.
- E1.3 Exclusions with `health.coverage` counts. Accept: excluded paths produce no events, and coverage shows `excluded`.
- E1.4 Vault-only hostnames and serials. Accept: canary hostname absent from every upload batch.

**E2 Retention, holds and subject requests** (requires the server)
- E2.1 `RetentionPolicy`, presets and floor-ceiling resolution. Accept: the reference-model test passes for every preset pair.
- E2.2 `Hold` with review and deferred notice. Accept: erasure of a held subject queues and runs at release; an expired review raises a finding.
- E2.3 `SubjectRequest` access and erasure. Accept: the brute-force oracle matches; erasure responses state what remains and why.
- E2.4 Record-of-processing generator. Accept: every configured sink and sub-processor appears.

**E3 Re-identification and the works-council profile** (requires the server)
- E3.1 `co_approver_group` in 21's quorum. Accept: a two-approver request without the co-approver is refused under the profile.
- E3.2 Notice periods for capture raises. Accept: the notice test passes on three operating systems.
- E3.3 Purpose-bound drill-down. Accept: a drill-down with no incident reference is refused, and each allowed drill-down writes `audit.access`.
- E3.4 Disclosure items 3, 4, 5 and 7 over the control plane. Accept: a read is visible on the subject's device within 60 seconds online.
- E3.5 Server re-pseudonymisation at ingest (D-51, R-18). Accept: the pseudonym-recomputation test finds no match; records uploaded after an offline period carry server pseudonyms; the archived batches still pass `grdr audit verify`.

**E4 Control library and documents**
- E4.1 `compliance` pack type, catalogues and the section 1 crosswalk. Accept: the integrity tests pass, and no licensed text appears (paraphrase length check, at most 20 words).
- E4.2 Monitoring catalogue, worker notice, impact-assessment pack, works-agreement annex. Accept: the completeness oracle passes; German and English render; the pseudo-locale passes.
- E4.3 Privacy-relevant pack gate. Accept: a pack reading a new content-class field stops at the organisation's current version until acknowledged.
- E4.4 RFP generator and T1 to T17 release gates. Accept: a claimed item with a red test fails the release job.

**E5 Evidence and OSCAL**
- E5.1 Component definition in CI. Requires: E4.1. Accept: it validates against the external schemas.
- E5.2 Evidence queries and signed `EvidenceItem`. Requires: the server's `audit` target and E4.1. Accept: `not-evaluable` is produced under injected pipeline lag.
- E5.3 Assessment results, evidence API and GRC adapters for CISO Assistant and Probo. Requires: E5.2. Accept: trestle round trip passes; push is idempotent.
- E5.4 Offline evidence package (`grdr comply export` and `grdr comply verify`). Requires: E5.2. Accept: in the air-gap conformance run (S-31, step 14) a 30-day package carried out by file verifies offline, an altered item fails, and OSCAL validation runs on the vendored schemas.

**E6 Oversight, posture and AARM**
- E6.1 Oversight report from 18's metrics plus `OversightAssignment`. Accept: independent recomputation matches.
- E6.2 NCSC posture report with ladder-downgrade findings. Accept: moving an agent from a container to no containment raises a finding.
- E6.3 AARM runner in the harness. Accept: every row of the AARM 1.0 conformance table maps to an executed scenario with a pass or fail result; the "system unavailable" row ends with the action failed; a receipt verifies offline with no server reachable.

**E7 Project and hosted compliance**
- E7.1 CRA technical-documentation skeleton public. Requires: nothing; it is an early work item in the public repository. Accept: the file exists and is linked from the release page.
- E7.2 Crypto allow-list CI check and the export-control note. Accept: a planted new primitive fails CI.
- E7.3 Incident-timeline export with regime clocks. Accept: a fixture incident yields the 24-hour, 72-hour and 14-day deadlines.
- E7.4 Web console accessibility report, published with the server; desktop report in the release that ships the Rune app. Requires: S-19 passing for the desktop report. Accept: zero WCAG 2.2 AA failures in an automated scan and in U09's screen-reader journeys judged by `eval-a11y`; a VPAT 2.5 INT report published with the release, citing an assessor's audit where one was available.
- E7.5 Sub-processor registry and feed, region pinning checks. Requires: the hosted service. Accept: a cross-region content read is refused.
- E7.6 SOC 2 readiness: evidence mapping for Security, Availability and Confidentiality from product records. Requires: the hosted service; the audit itself requires revenue or a sponsor. Accept: the auditor's readiness review has no unowned control.

## Risks, open questions and spikes

| Item | Risk or question | Settled by |
|---|---|---|
| Open question 1 | CRA class (I or II) and whether Art. 32(5) covers a hosted, monetised distribution; how the five-year support period of Art. 13(8) composes with D-58's 24-month public LTS | Counsel's opinion before any paid offer (D-46) |
| Open question 2 | Where Loonaro (the legal entity, owner answer 1) is established, and the EU contact (authorised representative or establishment) | The owner, with counsel |
| Open question 3 | Whether to self-certify under the EU-US Data Privacy Framework or rely on SCCs only | 36 with counsel |
| SP-29-1 | Would a works council sign the default plus the works-council profile? | l07 spike 4; pass: written opinion with no red-line item |
| SP-29-2 | Can erasure complete inside one month at 10,000 endpoints, including backups? | 20's erasure drill; pass: under 24 hours, backups age out in 35 days |
| SP-29-3 | Is 90 days a defensible activity ceiling for works agreements in Germany? | Same expert review; change the preset value only |
| Risk | Mappings churn: NIST agent overlays unpublished, AARM v2 planned, OCSF and CRA standards moving | Versioned catalogues; quarterly content review; stable ids |
| Risk | Annex III 4(b): the product could become a high-risk AI system if it evaluates workers | P8 floor and the prohibited-evaluation list are tested in CI; counsel's review of the D-29 review stage is a prerequisite of enabling it |
| Risk | Certification cost with a zero budget | Paid certifications are trigger-based and require revenue or a sponsor; project baselines, public documentation and the control library cost nothing; STAR Level 1 costs only agent work and requires the hosted service |
| Open question 4 | Who issues principal pseudonyms (section 8) | Settled by R-18: two layers (spine D-51); owner question 9 may move issuance entirely to the server |
| Risk | Rune accessibility: Rune depends on AccessKit 0.25.2 (brief 33 verification); right-to-left text and input methods are unverified | Desktop accessibility report gated on the S-19 soak |

## Deviations from the spine and objections

1. **Structural retention default of 180 days.** For EU deployers of Annex III systems from 2 December 2027, this is a few days short of Art. 26(6)'s "at least six months". The body keeps D-51's default and fixes the gap in the `eu-ai-act-deployer` preset at 7 months. I recommend that the spine default become six calendar months (184 days).
   Resolved by R-19: spine D-51 now sets 184 days, and the preset uses it.
2. **"Shown to the subject."** D-51 states this without exception. This document allows deferral under a recorded legal hold, capped at 90 days per renewal with two approvers, as l07 F10 proposed. If the owner reads D-51 as admitting no delay, remove `notify_subject: deferred`.
   Open: spine v3 D-51 still states no exception.
3. **Prerequisite split for D-46.** The library, the documents, the component definition and the reports do not depend on evidence collection, because a self-hosted server cannot be deployed in a German workplace without a worker notice. Evidence collectors and assessment results require the server's evidence jobs.
   Resolved by R-33 and spine version 4: D-46 states that project obligations cost nothing and that customer evidence export requires the server, which matches this split; the library and documents carry no evidence.
4. **Who computes principal pseudonyms (D-51, 04 section 3).** D-51 has the sensor emit the keyed pseudonym and 04 derives it on the device from an organisation key delivered at enrolment. Section 8 shows that any local administrator holding that key can recompute every human pseudonym from directory identities and bypass the re-identification quorum. Objection recorded: section 8 proposes server-issued pseudonyms; the owner decides, and 04 and 21 adopt it or keep the current derivation with 21's rotation-on-exposure mitigation.
   Resolved by R-18: two layers, device-side keyed pseudonym then server re-pseudonymisation at ingest (spine D-51); section 8 now specifies it. Owner question 9 can reverse it.

## Sources

Research briefs: `34-compliance.md` (trust its Independent verification: Omnibus Regulation 2026/1744, Art. 26 unchanged, CRA dates and Art. 13(8), AARM conditions, FedRAMP 20x timeline, BetrVG, STAR for AI routes, ISO 42001 not mandatory); `h06-standards-regulation-sweep.md` (EO 14434 renaming, NCSC and Five Eyes texts with modal-verb caveats, CRA standards status corrected, AIUC-1 corrected); `28-oss-sustainability.md` (CRA steward and manufacturer, guidance point 54, Art. 32(5), export controls); `33-ux-personas.md` (transparency, accessibility, Rune AccessKit dependency); `g10-saas-ops-day2-economics.md` (SOC 2 evidence from drills, agent and human split); `23-schemas-transport.md` (FIPS status, audit expectations of regulators); `19-identity-industry.md` (framework requirements, NIST status). Review notes: `l07-privacy-works-council.md`, `l02-enterprise-buyer.md` F8 and F9, `l12-completeness.md` F4.

Primary URLs: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R1689-20260727 ; https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R2847 ; https://www.gesetze-im-internet.de/betrvg/__87.html ; https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf ; https://aarm.dev/conformance ; https://raw.githubusercontent.com/FedRAMP/2026/main/content/timeline.md ; https://cloudsecurityalliance.org/star/about-star-for-ai ; https://www.ncsc.gov.uk/sites/default/files/2026-08/Managing-the-cyber-risk-of-agentic-AI_0.pdf ; https://cyberresilienceact.eu/state-of-play.html ; https://baseline.openssf.org/ ; https://www.linuxfoundation.org/resources/publications/understanding-us-export-controls-with-open-source-projects (via brief 28) ; https://github.com/usnistgov/OSCAL .
