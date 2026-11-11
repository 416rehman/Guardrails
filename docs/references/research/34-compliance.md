# Regulations, standards and certifications for an open-source AIDR platform

_Researched 2026-11-09_

Method note: the session's web-search budget was exhausted before this brief started, so findings come from direct fetches of primary sources (EC, EUR-Lex, NIST, IMDA, CSA, FedRAMP, Microsoft Learn, BeyondTrust docs, Colorado legislature, gesetze-im-internet.de, GitHub via `gh`). Claims are tagged **[V]** = read in the primary source today, **[K]** = from prior knowledge (up to mid-2026) and not re-fetched; treat [K] as possibly stale.

## TL;DR

- **EU AI Act timeline moved.** The Digital Omnibus on AI entered into force 27 July 2026. Annex III high-risk duties now apply **2 Dec 2027**, Annex I **2 Aug 2028**. Article 50 transparency and enforcement started 2 Aug 2026 as planned. [V]
- **Deployer evidence is concrete**: assign competent human oversight, monitor, keep logs **at least six months**, tell workers' representatives before workplace use, reuse provider info in the DPIA (Art. 26). [V] An agent inventory, oversight records and six-month-plus retention are the product's direct answers.
- **Our own product can become high-risk**: Annex III point 4(b) covers AI used to "monitor and evaluate the performance and behaviour" of workers. [K] Detections must score agents and sessions, not people.
- **CRA reporting is already live** (11 Sep 2026); full duties 11 Dec 2027. Annex III Class I names IAM/PAM, anti-malware and SIEM software; Class II names IDS/IPS. Machine-readable SBOM and a five-year support period are required. Non-monetised FOSS is out of scope; stewards get a light regime. [V]
- **No finished US federal agent control set exists.** NIST's SP 800-53 AI overlays project still lists only a concept paper (Aug 2025) and a predictive-AI outline (Jan 2026); single-agent and multi-agent overlays are unpublished. AI RMF 1.0 is under revision. [V]
- **Singapore's Model AI Governance Framework for Agentic AI v1.5 (20 May 2026)** is the most specific government text: unique cryptographic agent identity tied to a human, session-bound least privilege, approval checkpoints with written justification, override-rate and response-time metrics, deny-by-default when approval infrastructure fails, immutable logs. [V]
- **A category conformance spec exists: CSA's AARM** (R1 to R9: pre-execution interception, five decisions, tamper-evident signed receipts, identity binding). Claiming conformance needs five production customers for three months plus SOC 2 Type II, ISO 27001 or FedRAMP. Eleven vendors reviewed. [V]
- **CSA STAR for AI Level 2 is available**: SOC 2 or ISO 27001 or ISO 42001 plus an AI-CAIQ scored by Valid-AI-ted. AICM has 243 control objectives in 18 domains. [V]
- **FedRAMP 20x is the path**: Low and Moderate open, pilots authorised without agency sponsor, **new Rev5 certifications stop 11 June 2027**. [V]
- **Germany**: works council co-determination over any technical device able to monitor behaviour or performance (BetrVG s.87(1) no.6); AI expert deemed necessary (s.80(3)). [V] Product must ship works-agreement-ready privacy modes.
- **Microsoft Virus Initiative requires an antimalware product with annual third-party test certification and Trusted Signing** [V]; a pure AIDR product likely does not qualify, which strengthens the embed-in-EDR strategy.
- **Open-source GRC is healthy**: CISO Assistant (4.6k stars), Comp AI (AGPL), Probo (MIT), Openlane (Apache-2.0), compliance-trestle v5.2.0, OSCAL v1.2.3. [V]

## Findings

### A. What customers must satisfy

**EU AI Act (Reg. 2024/1689 as amended).** EC policy page: Omnibus proposed 19 Nov 2025, political agreement 7 May 2026, in force 27 July 2026; adds a ninth prohibition (nudification/CSAM, from 2 Dec 2026), stronger AI Office powers over GPAI-based systems, SME relief extended to small mid-caps, and an EU-level sandbox [V, digital-strategy.ec.europa.eu]. The AI Act Service Desk confirms: Art. 50 applies 2 Aug 2026; legacy synthetic-content systems have until 2 Dec 2026 for Art. 50(2); Annex III 2 Dec 2027; Annex I 2 Aug 2028 [V]. Art. 26: oversight by persons with competence, training and authority; monitoring; logs kept "at least six months"; workers and representatives informed before workplace deployment; DPIA reuse [V]. Art. 12 (automatic event logging), Art. 14 (human oversight design), Art. 19 (provider log retention), Art. 5(1)(f) (no emotion inference at work) and Annex III 4(b) are unchanged as far as known [K]. Whether Art. 4 AI literacy was softened in the final Omnibus text was not verified.

**GDPR and employee monitoring.** Art. 35 DPIA is effectively mandatory for systematic employee monitoring; Art. 88 lets Member States add employment rules; Art. 5 purpose limitation and minimisation, Art. 25 by-design, Art. 30 records, Arts. 15 to 22 rights [K]. Germany: BetrVG s.87(1) no.6 co-determination on "technical devices designed to monitor the behaviour or performance of the employees"; s.90(1) no.3 information and consultation on AI use; s.80(3) AI expert; s.95(2a) [V]. German case law reads s.87 as "objectively capable of monitoring", so intent is irrelevant [K]. Elsewhere [K]: France CSE consultation plus CNIL proportionality; Italy Art. 4 Workers' Statute (union agreement or labour-inspectorate authorisation; Garante metadata retention guidance); Netherlands WOR Art. 27 consent; Austria ArbVG s.96/96a. UK ICO "Monitoring workers" guidance (2023) requires DPIA, transparency and least-intrusive means [K; ICO site returned 403 today].

**NIS2** [K]: Art. 21 measures (logging, access control, supply chain, incident handling), Art. 23 reporting 24h/72h/one month; managed security service providers and cloud providers are in scope by sector, so MSP users and our SaaS (once medium-sized) are regulated entities. **DORA** [K]: applies since 17 Jan 2025; financial customers will demand Art. 30 contract terms (audit rights, exit, subcontractor chain, data location) and register-of-information fields.

**CRA (Reg. 2024/2847)** [V]: reporting duties from 11 Sep 2026, main duties 11 Dec 2027, Commission implementation guidance 27 July 2026. Annex III Class I: "Identity management systems and privileged access management software", "Software that searches for, removes, or quarantines malicious software", "Security information and event management (SIEM) systems", browsers, password managers. Class II: hypervisors and container runtimes, firewalls and IDS/IPS. Annex I: SBOM "in a commonly used and machine-readable format"; record and monitor "relevant internal activity"; automatic security updates. Recital 60: support period no less than five years. Recital 18: non-monetised FOSS is not commercial activity; recital 19: stewards get a "light-touch" regime. Reporting clock is 24h early warning, 72h notification, final report after fix [K]. FOSS in Annex III classes may self-assess if technical documentation is public (Art. 32(5)) [K].

**UK** [V]: Cyber Security and Resilience Bill introduced 12 Nov 2025, through Commons committee stage, no Royal Assent shown. Data (Use and Access) Act 2025 in force in stages [K].

**US state law.** Colorado **SB26-189** (signed 14 May 2026) repealed and re-enacted SB24-205 as an automated-decision statute: notice, adverse-outcome explanation within 30 days, human review, **three-year record retention**, developer documentation from 1 Jan 2027, AG enforcement with cure period until 2030 [V]. California CCPA regulations on ADMT, risk assessments and cybersecurity audits effective 1 Jan 2026 [V]; ADMT compliance by 1 Jan 2027 [K]. Texas TRAIGA and Illinois HB 3773 effective 1 Jan 2026; federal EO of Dec 2025 targets state AI laws [K].

**Sector rules** [K unless marked]: SEC Form 8-K Item 1.05 (four business days after materiality) and Reg S-K Item 106; HIPAA 164.312(b) audit controls, 164.308(a)(1)(ii)(D) activity review, six-year documentation retention, BAAs (2025 Security Rule NPRM status not verified, HHS returned 403); PCI DSS 4.0.1 Req. 10 (12 months of logs, three immediately available, tamper protection, automated review), 7.2.5 and 8.6 for application and system accounts; SOX ITGC (change management, logical access, segregation of duties: agents committing with a human's credentials break SoD evidence unless attributed); NYDFS 23 NYCRR 500.6 audit trails (three and five years), 500.7, 500.14, 500.17 72h notice, AI letter of Oct 2024; CMMC 2.0 phase 2 (C3PAO Level 2) due 10 Nov 2026 (DoD site 403).

**NIST.** COSAiS page: only the concept paper (14 Aug 2025) and the predictive-AI annotated outline (8 Jan 2026); use cases include "Single Agent" and "Multi-Agent"; no public drafts [V]. The page as fetched carries a 20 Oct 2026 notice renaming the project "Control Overlays for Super Intelligence Systems (COSIS)" and substituting "SI" for "AI"; the CAISI page likewise says "SI Agent Standards Initiative" [V as fetched; anomalous, re-check]. AI RMF 1.0 "is being revised"; critical-infrastructure profile concept note 7 Apr 2026; GenAI Profile AI 600-1 (July 2024) [V]. Cyber AI Profile IR 8596 still a preliminary draft of 16 Dec 2025 [V]. Agent Standards Initiative (Feb 2026): RFI on agent security, NCCoE concept paper on agent identity and authorisation; no published agent outputs [V].

**ISO, SOC 2, CSA, HITRUST, CIS.** ISO/IEC 27001:2022 Annex A 5.9, 5.15 to 5.18, 8.2, 8.15, 8.16, 8.32; 27701:2025 is standalone; 42001:2023 with 42006:2025 for certification bodies [K; iso.org 403]. SOC 2 has no AI-specific trust services criteria as far as known; AI controls ride on CC6, CC7, CC8 and Privacy [K]. CSA AICM: 243 control objectives, 18 domains, mapped to ISO 42001, ISO 27001, NIST AI RMF, AI 600-1, BSI AIC4 and the EU AI Act; first released 9 July 2025, current release dated 22 June 2026 [V]. STAR for AI Level 1 is an AI-CAIQ self-assessment; Level 2 pairs ISO 27001, ISO 27001 plus 42001, ISO 42001 or SOC 2 with a Valid-AI-ted-scored AI-CAIQ [V]. HITRUST AI assessments not reachable (404) [K: add-on to e1/i1/r2]. CIS Controls v8.1 safeguards 1, 2, 5, 6, 8; CIS publishes OSCAL serialisations [V repo].

**Singapore MGF for Agentic AI v1.5** (20 May 2026, updated 5 June 2026; 53 pages; feedback from 60+ companies) [V]. Agent identity should be unique and cryptographically verifiable, tied to a supervising agent, human or department, recorded by capacity (independent versus on behalf of a user), and "catalogued and centrally managed" to prevent sprawl. Authorisation: scoped, time- or session-bound, non-transferable, never exceeding the delegating human. Oversight: checkpoints for high-stakes, irreversible, outlier and user-defined actions; written justification for high-risk approvals; audit **human override rate** and **response time**; deny by default when approvers are unreachable. Controls: prefer deterministic system-level controls over prompt-layer ones; whitelist MCP servers; "MCP as a governance layer". Monitoring: log at user-agent, agent-tool and reasoning layers; OpenTelemetry; "ensure log immutability"; change-review triggers for model, tool and autonomy changes. Case studies describe a runtime policy layer at the AI gateway (MSD) and a managed MCP gateway plus OS-native sandboxes (GovTech).

**CSA AARM** [V, aarm.dev]: R1 pre-execution interception, fail closed; R2 context accumulation; R3 policy evaluation with intent alignment; R4 five decisions ALLOW, DENY, MODIFY, STEP_UP, DEFER with timeout to DENY; R5 tamper-evident receipts for every decision with delegation chain and policy hash, signatures verifiable offline; R6 identity binding; R7 drift tracking, R8 SIEM export, R9 least privilege (SHOULD). Core is R1 to R6, Extended R1 to R9. Listed Extended: Noma, Runlayer, Operant AI, Microsoft Agent Governance Toolkit, QuilrAI, Ultra.

**Incumbent evidence models.** Microsoft Agent 365 (GA 1 May 2026, per user, "works best" with E5): agents are audited "as you would a user"; Purview audit covers agent-to-human, human-to-agent, agent-to-tool and agent-to-agent; DLP, eDiscovery and retention cover fewer interaction types; Compliance Manager ships four premium AI templates (EU AI Act, ISO/IEC 23894, ISO/IEC 42001, NIST AI RMF 1.0) and exports to Excel [V]. BeyondTrust AI Agent Security: endpoint agent on Windows 11 x64 and macOS 14, 15, 26 only; distinguishes agent from human under shared credentials; kernel and network enforcement plus hooks; session records of prompts, commands, files, network and tools; policy replay against history; requires a trusted root certificate and MDM-approved system extensions; no compliance reports documented [V].

### B. What the operating company needs

- **Endpoint programme gates.** MVI: real-time antimalware product, NDA, programme licence, Trusted Signing, and certification within the last 12 months from AV-Comparatives, AV-TEST, SE Labs (AAA), MRG Effitas, VB100, AVLab, SKD Labs or West Coast Labs; applications reviewed monthly [V]. Apple: Endpoint Security client entitlement granted case by case, system extension, Developer ID and notarisation, MDM approval and Full Disk Access profile [K; Apple docs JS-only]. Linux has no gate (eBPF).
- **Supply chain**: SLSA v1.2 with Build and Source tracks; OSPS Baseline v2026.08.28; CycloneDX 1.7.2; OpenVEX 0.2.0 (unchanged since 2023); OSCAL v1.2.3 (7 Aug 2026) [V]. CISA's SSDF attestation form page is marked archived [V]; OMB reportedly rescinded the common-form mandate in Jan 2026 [K].
- **Vulnerability handling** [K]: security.txt, ISO 29147/30111 policy, CNA status, CSAF/VEX advisories; CRA 24h reporting if we supply commercially in the EU.
- **Accessibility** [K]: VPAT 2.5 INT report against WCAG 2.2 AA, Section 508 and EN 301 549; the European Accessibility Act applies since June 2025. The Rust UI toolkit must expose platform accessibility trees or the ACR will fail.
- **Independent tests**: no AV-Comparatives equivalent for agent security was found; AARM commits conformant vendors to "future AARM benchmarking" [V]. MITRE evaluations page unreadable today.
- **Open-source compliance automation** [V via gh, 2026-11-09]: intuitem/ciso-assistant-community 4,612 stars, v4.2.2; trycompai/comp 2,089, AGPL-3.0; getprobo/probo 1,509, MIT; theopenlane/core 337, Apache-2.0; prowler 15,202, Apache-2.0; oscal-compass/compliance-trestle v5.2.0; ComplianceAsCode/content 2,835; defenseunicorns/lula 48; awslabs/mcp-server-for-oscal 52; GRCEngClub/claude-grc-engineering 432; strongdm/comply dormant since 2022. Transparency-log building blocks: sigstore/rekor, google/trillian, transparency-dev/tessera (all Apache-2.0).

**Certification roadmap (durations are estimates from industry norms, not sourced).**

| Step | When | Duration | Notes |
|---|---|---|---|
| Policies, risk register, DPA, subprocessor page, security.txt, CAIQ and AI-CAIQ (STAR Level 1) | M0 to M2 | 6 to 8 weeks | Dogfood an open-source GRC tool |
| External penetration test (app, API, agent, sensor drivers) | M2, then annual | 2 to 3 weeks | Publish summary letter |
| SOC 2 Type I (Security, Availability, Confidentiality) | M3 | 2 to 3 months | Point in time |
| SOC 2 Type II | M6 to M9 | 3-month first window, then 12-month | Add Privacy criteria in year 2 |
| ISO/IEC 27001:2022 | M6 to M12 | Stage 1 plus Stage 2, 4 to 6 months | EU buyers prefer it; add 27701:2025 after |
| HIPAA BAA template and control mapping | M6 | 1 month | No certificate exists; HITRUST e1 optional |
| EU and US data regions; DORA Art. 30 contract addendum | M6 to M9 | Engineering | Region pinning per tenant |
| STAR for AI Level 2; AARM Core then Extended | M9 to M12 | Weeks after SOC 2 | AARM needs 5 customers for 3 months |
| ISO/IEC 42001 | M9 to M15 | 4 to 9 months | Needed if we use ML in detections |
| VPAT/ACR, CNA status, SLSA Build L3, OSPS Baseline L2 to L3 | By GA | Continuous | Cheap for an OSS project; do early |
| CRA conformity file (Class I or II analysis, SBOM, support period) | Before 11 Dec 2027 | 3 to 6 months | Reporting duty already applies |
| FedRAMP 20x Class B then C | M12 to M24 | 6 to 12 months | Rev5 closed to new entrants after 11 June 2027 |
| Regional: BSI C5, Cyber Essentials Plus, IRAP, ENS | On demand | Varies | Self-hosted mode often removes the need |

### C. Evidence-producing features

See matrix; the compliance module list is under Implications.

## Matrix: requirement to architecture

| Requirement (source) | Architecture or feature demanded |
|---|---|
| AI Act Art. 26(6), Art. 19: logs at least 6 months; Colorado 3 years; PCI 12 months; NYDFS 3 and 5 years; HIPAA 6 years | Per-tenant, per-data-class retention policies with floor presets by regime; cold tier; legal hold overriding deletion |
| AI Act Art. 12, 14, 26(2); Singapore 2.2.2; AARM R4 | Approval workflow with STEP_UP and DEFER, named approver, written rationale, timeout to deny, oversight-assignment registry |
| Singapore: audit oversight effectiveness | Metrics: override rate, median approval latency, outlier approvers |
| AARM R5; Singapore "log immutability"; PCI 10.3; 800-53 AU-9, AU-10 | Hash-chained, signed decision receipts; Merkle transparency log with external anchoring; offline verifier CLI |
| AARM R1, R6; Singapore agent identity; SOX SoD | Pre-execution enforcement that fails closed; agent identity distinct from human, with delegation chain on every event |
| ISO 27001 A.5.9; 800-53 CM-8; CIS 1, 2; ISO 42001; AI Act deployer inventory | Continuous agent, MCP-server, model and skill inventory with owner, purpose, risk tier, data classes, first and last seen |
| GDPR Art. 35; AI Act Art. 26(9) | DPIA and FRIA pack generated from live configuration (data categories, capture level, retention, recipients) |
| BetrVG s.87, s.90; Art. 88 GDPR | Works-council mode: pseudonymised by default, four-eyes re-identification, published monitoring catalogue, no per-person scoring |
| GDPR Arts. 15 to 17, 30 | Subject-keyed index, DSAR export and erasure with hold exceptions, processing-record export |
| GDPR Art. 5(1)(b), (c) | Capture levels: metadata only, redacted content, full content; purpose tags enforced by query-time access policy |
| SOC 2 CC8; ISO A.8.32; Singapore change management | Versioned, signed policy bundles; diff, author, approver, simulation result before rollout |
| SOC 2 CC6; 800-53 AC-5, AC-6 | Role separation: policy author, approver, investigator, auditor (read-only), privacy officer; break-glass logged |
| NIS2 Art. 23; DORA; SEC 8-K; NYDFS 500.17; CRA Art. 14 | Incident timeline export with clocks per regime; evidence bundle per incident |
| CRA Annex I; EO 14028 lineage | CycloneDX SBOM and VEX per release, SLSA provenance, signed auto-update, five-year support statement |
| FedRAMP 20x; 800-53 | OSCAL component definition and SSP fragments; machine-readable control evidence API |
| DORA Art. 30; GDPR Ch. V | Regional cells, customer-managed keys, subprocessor registry with change notices, exit export |
| HIPAA; PCI scope | Secret and PHI/PAN redaction at the sensor before upload |
| AARM R8; Singapore OpenTelemetry | OCSF and OTel export to the customer's SIEM |

## Weak points, gaps and risks

- **No authoritative agent control catalogue**: NIST agent overlays are unpublished after 15 months; mappings will churn. Programme names are unstable too.
- **Annex III 4(b) exposure**: behavioural analytics keyed to employees could make the product a high-risk AI system from Dec 2027, with conformity assessment and registration duties.
- **CRA classification is ambiguous** for AIDR (anti-malware, SIEM or IDS/IPS). Class II would force third-party assessment for a commercial distribution; the FOSS self-assessment route depends on public technical documentation.
- **MVI and Apple entitlements are discretionary gates** for kernel-adjacent sensors; a new vendor without AV test certification may be refused.
- **Content capture is the legal fault line**: prompts contain personal and privileged data; full capture by default will fail German works-council review.
- **TLS interception** (BeyondTrust requires a trusted root) is itself a DPIA and secrecy-of-communications issue in several Member States.
- **AARM and STAR for AI are young**; AARM's entry conditions favour funded vendors.
- **Self-hosted users inherit no certification**; they need evidence generators more than our SOC 2 report.

## Implications for our design

1. **Entity model: agent first, human pseudonymous.** Risk scores attach to agents, sessions and devices. Human identity resolves through a separate, audited vault. This addresses Annex III 4(b), BetrVG s.87 and GDPR minimisation at once.
2. **Build the receipt ledger as a core primitive.** Every decision (allow, deny, modify, step-up, defer) emits a signed receipt with principal, delegation chain, policy hash and context digest, chained into a Merkle log (reuse tessera or rekor patterns). Ship an offline verifier. This satisfies AARM R5, PCI 10.3, AU-9/AU-10 and the Singapore immutability clause.
3. **Adopt AARM's five-decision vocabulary and fail-closed semantics** in the policy engine so conformance is a test run, not a redesign.
4. **Compliance module feature list**: agent and AI-system inventory with ownership attestation; control library as data (AICM, ISO 42001, ISO 27001, SOC 2, 800-53, NIS2, DORA, PCI, HIPAA, AI Act, Singapore MGF) with crosswalks; evidence collectors that bind live telemetry to controls; OSCAL 1.2 export (component definition, assessment results) plus CSV and PDF; retention and legal-hold manager; oversight register and metrics; policy change history with approvals; DPIA/FRIA and works-agreement generators; DSAR workflow; incident-clock exporter; auditor read-only role with time-boxed access; AI-CAIQ auto-answer from configuration.
5. **Privacy by design for EU monitoring**: (a) default capture level is metadata only; (b) content capture is opt-in per policy, per purpose, with on-device redaction of secrets and special-category data; (c) pseudonymise user identifiers at the sensor; (d) re-identification needs a security-incident purpose plus two-person approval, optionally including a works-council delegate role; (e) no productivity, performance or emotion analytics, enforced in code and stated in the documentation; (f) employee-facing transparency notice and local "what is collected" viewer in the desktop app; (g) short default retention (30 to 90 days) for content, longer for decision receipts; (h) purpose-bound query access with logged searches; (i) EU-region processing and customer-held keys; (j) exclusion lists for works-council, HR, legal and medical contexts; (k) DPIA template shipped with the product; (l) covert mode absent, not merely disabled.
6. **Publish an OSCAL component definition and a shared-responsibility matrix** so self-hosted agencies and MSPs can inherit control descriptions without our FedRAMP authorisation.
7. **Use the EDR-embed path to sidestep MVI**: partners that already hold MVI and Apple entitlements host the sensor library; our standalone build uses ETW, eBPF, Endpoint Security and agent hooks.
8. **Run the project to OSPS Baseline, SLSA Build L3 and signed releases from day one**; it is cheap now and becomes CRA and FedRAMP evidence.
9. **Dogfood open-source GRC** (Probo or CISO Assistant) for our own SOC 2 and ISO 27001 instead of building a GRC product; integrate by pushing evidence to them.

## Ideas worth stealing and whitespace

- **Policy replay against recorded history** before enforcement (BeyondTrust); pair it with a signed "simulation result" attached to the policy change record.
- **Oversight-quality telemetry** (override rate, approval latency) from Singapore's framework: nobody appears to ship it as a compliance report.
- **Offline-verifiable receipts** as a portable evidence format; propose it as an open schema.
- **Works-council mode as a named product feature**, with a ready German Betriebsvereinbarung annex. No vendor documentation reviewed offers one.
- **A public, reproducible AIDR test harness** (open corpus of agent attacks, scored like AV tests). There is no independent lab programme; an open-source project can define it.
- **OSCAL-native evidence for agent controls** ahead of NIST's overlays, plus an MCP server exposing compliance state to auditors' agents.
- **Compliance Manager exports Excel**; machine-readable, signed evidence is whitespace.

## Could not verify / open questions

- Final Omnibus text: regulation number, Art. 4 literacy changes, Art. 6(3) registration, any change to Art. 26 (EC pages do not detail).
- Whether the NIST "Super Intelligence Systems" renaming is genuine policy or a page anomaly.
- HIPAA Security Rule final rule status; CMMC phase dates; ICO guidance updates; ISO 42001 revision status; HITRUST AI assessment details; AICPA AI-related guidance; MITRE ATT&CK Evaluations 2026 scope (all blocked: 403, 404 or JS-only).
- CRA class for AIDR products and the content of the July 2026 Commission guidance.
- Agent 365 list price and Purview audit retention defaults for agent events.
- AARM specification version, licence and assessor independence.
- Rune UI framework accessibility-tree support.
- UK Cyber Security and Resilience Bill final scope for MSPs.

## Sources

- https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai : EC, AI Act regulatory framework (fetched 2026-11-09)
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/timeline/timeline-implementation-eu-ai-act : AI Act Service Desk timeline (2026-11-09)
- https://artificialintelligenceact.eu/implementation-timeline/ : implementation timeline, updated 31 Aug 2026
- https://artificialintelligenceact.eu/article/26/ : Article 26 text
- https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847 : Cyber Resilience Act, Reg. (EU) 2024/2847
- https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act : EC CRA page, updated 7 Sep 2026
- https://www.gesetze-im-internet.de/englisch_betrvg/englisch_betrvg.html : Works Constitution Act (English)
- https://csrc.nist.gov/projects/cosais : NIST SP 800-53 control overlays project (2026-11-09)
- https://www.nist.gov/itl/ai-risk-management-framework : NIST AI RMF
- https://www.nist.gov/caisi/ai-agent-standards-initiative : NIST agent standards initiative, updated 9 Nov 2026
- https://csrc.nist.gov/pubs/ir/8596/iprd : NIST IR 8596 Cyber AI Profile, 16 Dec 2025
- https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf : Singapore MGF for Agentic AI v1.5, 20 May 2026
- https://cloudsecurityalliance.org/artifacts/ai-controls-matrix : CSA AICM
- https://cloudsecurityalliance.org/star : CSA STAR and STAR for AI
- https://aarm.dev/ and https://aarm.dev/conformance : CSA AARM specification and conformance, 2026
- https://www.fedramp.gov/20x/ : FedRAMP 20x, dated 27 Apr 2026
- https://leg.colorado.gov/bills/sb26-189 : Colorado SB26-189, signed 14 May 2026
- https://cppa.ca.gov/regulations/ccpa_updates.html : CPPA regulations, effective 1 Jan 2026
- https://www.gov.uk/government/collections/cyber-security-and-resilience-bill : UK Bill collection
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview : Agent 365 overview, 19 Aug 2026
- https://learn.microsoft.com/en-us/purview/ai-agent-365 : Purview for Agent 365, 1 May 2026
- https://learn.microsoft.com/en-us/purview/compliance-manager-assessments : Compliance Manager assessments, 1 Jul 2026
- https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria : MVI criteria, updated 6 Oct 2026
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security : BeyondTrust AI Agent Security docs
- https://baseline.openssf.org/ : OSPS Baseline v2026.08.28
- https://slsa.dev/spec/ : SLSA v1.2
- https://www.cisa.gov/secure-software-attestation-form : CISA attestation form (archived)
- GitHub via gh (2026-11-09): usnistgov/OSCAL, oscal-compass/compliance-trestle, intuitem/ciso-assistant-community, getprobo/probo, trycompai/comp, theopenlane/core, prowler-cloud/prowler, ComplianceAsCode/content, CycloneDX/specification, openvex/spec, ossf/security-baseline, sigstore/rekor, transparency-dev/tessera, awslabs/mcp-server-for-oscal

## Independent verification

_Fact-check run 2026-11-09 by a second reviewer. Web search was unavailable (budget exhausted), so every check is a direct fetch of a primary source: EUR-Lex full texts (downloaded and searched locally), the German-language BetrVG, FedRAMP's published rule sources on GitHub, the AARM site source, the IMDA PDF (text extracted locally), CSA and Microsoft Learn pages. Where the law itself is the only primary source, it was re-read through a different URL or copy than the one cited above._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Digital Omnibus on AI in force 27 July 2026; Annex III from 2 Dec 2027, Annex I from 2 Aug 2028; Art. 50 from 2 Aug 2026 | Confirmed | The act is Regulation (EU) 2026/1744, signed 8 July 2026, OJ L 24.7.2026, in force on the third day after publication (27 July 2026). Consolidated Art. 113(c) gives 2 Dec 2027 (Art. 6(2), Annex III) and 2 Aug 2028 (Art. 6(1), Annex I). Art. 50 falls under the general 2 Aug 2026 date; legacy generative systems have until 2 Dec 2026 for Art. 50(2). Resolves two open questions: Art. 4 was softened to "take measures to support the development of AI literacy", with no duty to guarantee a level; Art. 26 is not amended. | https://eur-lex.europa.eu/eli/reg/2026/1744/oj ; https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R1689-20260727 |
| 2 | Art. 26: competent human oversight, monitoring, logs at least six months, inform workers' representatives | Confirmed | Art. 26(2), (5), (6), (7) read as stated in the 27.07.2026 consolidated text. Limits to keep in the design: logs only "to the extent such logs are under their control" and unless other Union or national law (notably data protection) says otherwise; the worker notice binds deployers who are employers and covers affected workers as well as representatives. These duties only bite from 2 Dec 2027 for Annex III systems. | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R1689-20260727 |
| 3 | CRA: reporting from 11 Sep 2026, main duties 11 Dec 2027; Class I and II lists; machine-readable SBOM; non-monetised FOSS not commercial | Confirmed | Art. 71(2): applies 11 Dec 2027, Art. 14 from 11 Sep 2026, Chapter IV from 11 June 2026. Annex III Class I items 1, 4, 7 and Class II item 2 match. Annex I Part II(1): SBOM "in a commonly used and machine-readable format covering at the very least the top-level dependencies" (it sits in the technical documentation; publication is not required). Recital 18 wording matches. The five-year support floor is binding text in Art. 13(8), not only recital 60. EUR-Lex shows no amendment moving the dates. | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R2847 ; https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32024R2847 |
| 4 | CSA AARM R1 to R9; conformance needs 5 production customers for 3 months plus SOC 2 Type II, ISO 27001 or FedRAMP | Confirmed (with nuance) | R1 to R6 MUST, R7 to R9 SHOULD; five decisions; prerequisites as stated, plus an active community representative and a benchmarking commitment. "Fail closed", timeout-to-DENY and offline signature verification come from the conformance test table (for example "Make AARM system unavailable, submit action: action fails (no fail-open bypass)"; "Verify receipt signature offline"), not from the normative R1 and R5 sentences, which only say intercept every action and produce a tamper-evident receipt. Resolves an open question: spec is v1.0, February 2026, CC BY 4.0, single listed author (Herman Errico), arXiv 2602.09433; branded "A Cloud Security Alliance Powered Project"; v2.0 is planned, so requirement text may move. The site source lives in a personal repository (herman-prod/aarm). | https://aarm.dev/conformance ; https://aarm.dev/ ; https://github.com/herman-prod/aarm (src/app/spec/page.tsx, src/app/conformance/page.tsx) |
| 5 | NIST has published no SP 800-53 overlays for AI agents; only a concept paper (14 Aug 2025) and predictive-AI annotated outline (8 Jan 2026) | Confirmed | Raw HTML of the project page lists only those two documents; the January item is a discussion draft, not an initial public draft. Single-agent and multi-agent remain proposed use cases. The projects/cosais/publications sub-page returns 404. | https://csrc.nist.gov/projects/cosais (raw fetch 2026-11-09) |
| 6 | Singapore MGF for Agentic AI v1.5 (20 May 2026): verifiable agent identity tied to a human, session-bound least privilege, approval checkpoints, override-rate auditing, deny by default, immutable logs | Confirmed (with nuance) | Cover reads "Version 1.5, Published 20 May 2026 (Updated 5 June 2026)". Exact wording: identity "tied to a supervising agent, a human user, or an organisational department", so not always a human; authorisations "scoped, time- or session-bound, non-transferable"; deny by default applies "when approval infrastructures fail" or no approval policy exists; "Ensure log immutability" means problematic trajectories and failures cannot be deleted. All of it is voluntary "should" guidance. | https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf (text extracted locally) |
| 7 | FedRAMP 20x Low and Moderate available; Phase 1 authorised without agency sponsor; no new Rev5 certifications after 11 June 2027 | Confirmed | FedRAMP's Consolidated Rules for 2026 timeline: 20x Class A pipeline opened 3 Aug 2026; 20x Class B (Low) and C (Moderate) pipeline opened 31 Aug 2026; "June 11, 2027: End of New Rev5 Certifications". The rules become mandatory for all stakeholders on 1 Jan 2027. FedRAMP now says "Certification", not "authorization". | https://raw.githubusercontent.com/FedRAMP/2026/main/content/timeline.md ; https://www.fedramp.gov/20x/ |
| 8 | BetrVG s.87(1) no.6 co-determination; s.80(3) AI expert deemed necessary | Confirmed | German original s.87(1) no.6 opens "Einführung und Anwendung von technischen Einrichtungen, die dazu bestimmt sind," and covers devices intended to monitor employees' conduct or performance. s.80(3) sentence 2: when the works council must assess the introduction or application of AI, "gilt insoweit die Hinzuziehung eines Sachverständigen als erforderlich". The expert is still engaged by agreement with the employer (sentence 1). | https://www.gesetze-im-internet.de/betrvg/__87.html ; https://www.gesetze-im-internet.de/betrvg/__80.html |
| 9 | MVI requires commercially available real-time antimalware, NDA, Trusted Signing, lab certification within 12 months | Confirmed | Eight requirements, also including a program licence agreement and an industry-reputation test; "Not all applicants are accepted". Labs: AV-Comparatives, AVLab, AV-Test, MRG Effitas, SE Labs (AAA), SKD Labs, VB100, West Coast Labs. Page updated 6 Oct 2026. No independent second source was reachable; the Microsoft page is the authority. | https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria |
| 10 | STAR for AI Level 2 available; SOC 2, ISO 27001 or ISO 42001 plus Valid-AI-ted AI-CAIQ; AICM 243 objectives, 18 domains | Confirmed | Four routes, each needing a Valid-AI-ted AI-CAIQ already on the STAR Registry: ISO 27001; ISO 27001 plus 42001; ISO 42001; SOC 2 (the SOC 2 route yields a STAR for AI Attestation). No minimum score is published. AICM page: "243 control objectives distributed across 18 security domains"; the newest version is AICM v1.1. | https://cloudsecurityalliance.org/star/about-star-for-ai ; https://cloudsecurityalliance.org/artifacts/ai-controls-matrix |

### Further statements checked in the brief

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| BeyondTrust AI Agent Security runs on "Windows 11 x64 and macOS 14, 15, 26 only" | Corrected | Windows support is Windows 11 or Windows Server 2022 or later on x64 (Windows on Arm unsupported); macOS 14, 15, 26 (current major plus two prior). No Linux: "supports Windows and macOS endpoints only". Linux is the full gap; Windows Server is covered. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |
| Roadmap row: ISO/IEC 42001 "Needed if we use ML in detections" | Corrected (overstated) | ISO/IEC 42001 is a voluntary management-system standard; nothing verified here makes it mandatory for using ML. STAR for AI Level 2 can be reached through ISO 27001 or SOC 2 without 42001. Treat it as a buyer-driven option, not a requirement. | https://cloudsecurityalliance.org/star/about-star-for-ai |
| NIST COSAiS renamed "Control Overlays for Super Intelligence Systems (COSIS)", flagged "anomalous, re-check" | Confirmed as served | An independent raw fetch of csrc.nist.gov shows the 20 Oct 2026 notice citing a "September 29, 2026, Executive Order on Inaugurating the Era of Super Intelligence" and stating earlier publications are unaltered; nist.gov's CAISI page is titled "SI Agent Standards Initiative". The executive order text itself was not retrieved. Cite documents by their original titles and treat programme names as unstable identifiers. | https://csrc.nist.gov/projects/cosais ; https://www.nist.gov/caisi/ai-agent-standards-initiative |

Also spot-checked and held: Agent 365 generally available 1 May 2026, per-user licensing, "works best when using Microsoft E5 as a pre-requisite" (learn.microsoft.com/en-us/microsoft-agent-365/overview); Colorado SB26-189 signed 14 May 2026, three-year records, 30-day adverse-outcome explanation, 60-day cure before 1 Jan 2030 (leg.colorado.gov/bills/sb26-189); Annex III point 4(b) wording unchanged in the consolidated AI Act.
