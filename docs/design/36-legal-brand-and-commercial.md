# Legal, brand and commercial

_Status: draft 4 against spine version 4, rulings R-14, R-36, R-39, R-46 and R-47 (`_review/01-document-rulings.md`) and the owner's answers (`_review/02-owner-answers.md`), then the owner's kit instructions (`_review/04-owner-kit-instructions.md`; instructions 7, 20, 25, 26 and 28 bind here) and the language-token review (D-69). Date: 2026-11-11. Owning squad: Direction group (`product-lead`, `team/02` section 3); every item marked **[Counsel]** needs a qualified lawyer and no agent may close it. Read with: `00-decisions.md` (D-02, D-03, D-04, D-46, D-58, D-60, D-63, D-65, D-66, D-67, D-68, P8, P11, section 7); 01 (teardowns, positioning, analyst mapping page CM-10); 03 (`brand/`, `dist.toml`, ARCH-009); 04 (names taken from the brand manifest, 04-4); 07 (block messages); 14 (live intelligence feed and its delay); 21 (tenancy, keys); 22 (trust roots); 24 (build, signing, SBOM); 29 (privacy and AI Act regimes); 30 (governance, covenant); 32 (costs); 33 (prerequisites); 34 (documentation, support, lifecycle); 35 (security response)._

## Summary

This document fixes the names, the business model, and the legal work that must exist before Loonaro sells anything. It specifies D-66 (names), D-04 (revenue without withheld features) and D-65 (positioning), and gives D-02 (licence review) and D-46 (CRA preconditions) their legal and commercial detail.

Key choices:

1. **One brand manifest, three classes of name.** Wire and ABI identifiers (`grdr.*`, `Grdr`, `grdr_`, `GRDR-`) are fixed once D-66's search is recorded, before the first release, and never rebranded. OS identities change only in a rebuilt build. Display strings change through a Provider co-brand profile at runtime. ARCH-009 enforces it.
2. **The product is Guardrails ADR (agent detection and response)**, the owner's answer to D-66's question 4 (owner instruction 25); Loonaro stays the legal entity that publishes it. A recorded, scripted search still runs before the first release, as a work item, not a condition of the repository being public (owner instruction 28): `xtask name-check` over eleven package and organisation namespaces and a knockout trademark search, both recorded. A formal clearance opinion is outside the zero budget and is taken only when free legal help provides one.
3. **The billing unit is the active endpoint-month.** It is device-level, fits P8, and matches the usage ledger (D-68) and MSP practice. It compares with the market's per-user anchors only if developers average about one persistent endpoint each; that is an assumption the conversations in section 14 test.
4. **Two hosted plans are shown by default: Free and Team.** Enterprise, Provider wholesale, self-hosted support, live intelligence and OEM sit behind "View all plans". Plans differ only in quotas, retention, support and contract terms. A lint rejects any feature flag in the plan catalogue (P11).
5. **Proposed prices sit below the public anchors**: Team USD 12 per active endpoint-month billed annually (USD 15 monthly), Provider wholesale USD 6. Team carries a minimum monthly charge that covers support cost, set together with the prices (R-46, 32); Provider wholesale has no minimum. All prices are proposals until spike S-01 and the willingness-to-pay conversations report.
6. **The intelligence delay is 7 days** and applies to enrichment and prevalence only; `malicious` verdicts and withdrawals are public immediately (D-04, R-14, 14).
7. **No paid offer before the D-46 preconditions**: the legal entity (Loonaro), counsel's opinion on CRA class and route, a human-staffed incident response team that meets the 24-hour, 72-hour and 14-day clocks (35), an EU contact, public technical documentation and a support statement. No hosted tenant without the D-63 preconditions, which include the `distributed` load test (R-36, spine section 7) and infrastructure funded by revenue, sponsorship or donated cloud credits.
8. **The server-licence review is held before the first tagged public release** (D-02). It has a fixed evidence list and a recommendation to confirm Apache-2.0 even on a weak result.
9. **The counsel register is data** (`legal/counsel-register.yaml`). Every legal item has an id and lists the work items and offers it blocks.
10. **Zero budget.** Loonaro spends no money. Nothing paid is offered until counsel has reviewed it, and counsel comes first from free legal programmes for open-source projects. The Apple Developer Program's annual fee is the one unavoidable cost, and paying it is an owner decision (spine question 8); without it macOS ships with Sigstore signatures and provenance, marked not platform-signed and not notarised, at tier 1 only (D-18, D-59).

## Requirements

| # | Requirement | Source |
|---|---|---|
| R1 | Product named "Guardrails ADR"; a rename or white-label must be mechanical, and no name, domain, host or address is compiled into code | Owner instructions 25 and 26; spine section 3; D-66 |
| R2 | Final technical namespace fixed by a recorded registry and trademark search before the first release | D-66; l12 F5 |
| R3 | Revenue from hosting, support, LTS maintenance, OEM services and live intelligence, with no withheld feature | D-04, P11; brief 28 section 8 |
| R4 | Multi-tenant SaaS offered by Loonaro, self-hostable by anyone | Owner's request; D-01 |
| R5 | MSPs can quote a client from a published wholesale unit | l05 F10; D-68 |
| R6 | EDR vendors can embed or white-label under a contract that covers warranty, support period and data | Owner's request; D-41, D-60; l08 |
| R7 | Hosted service terms, DPA, SLA and sub-processor list exist before the first hosted tenant | D-63; l12 F4; brief 34 roadmap |
| R8 | Dependency licences and notices are compliant in every artefact, embedded closure permissive only | D-02; c6 F4; brief 27 |
| R9 | Legal questions about agent-written code are answered by counsel before the first public release and before an OEM signs | brief 28 weak points; l08 |
| R10 | Export controls and sanctions handled for the hosted service and paid support | brief 28 section 11; l12 F4 |
| R11 | CRA manufacturer duties and product liability met before any paid offer, against the regulation's application dates | D-46; briefs 28, 34, h06; c6 F8 |
| R12 | Category named in analyst terms; positioning per buyer against bundled and free products | D-65; h04 implication 2 |
| R13 | Pricing and plan pages follow the ui-architect hard constraints | Global UI rule; D-44 |
| R14 | Server-licence go or no-go review before the first public release | D-02; owner question 6 |

## Design

### 1. Naming

**Collision evidence.**

| Name | Holder | Source |
|---|---|---|
| `guardrails` import, CLI and PyPI package | guardrails-ai/guardrails (7,594 stars) | c6 F1, GitHub 2026-11-10 |
| "Guardrails" in AI safety products | NVIDIA-NeMo/Guardrails (7,463 stars); AWS Bedrock Guardrails | c6 F1; h04 verification row 3 |
| `grd` | crates.io 0.13.0 (2026-10-22, a GitHub-release installer); also taken on npm and PyPI | l12 F5 |
| `grdr` | Free on crates.io, npm, PyPI, Homebrew, Docker Hub and Debian on 2026-11-10 | Spine section 3 |
| "ADR" in agent-security products | Uber ADR (Apache-2.0 sensor); SentinelOne Singularity ADR | 01 rival rows |

"Guardrails" is descriptive in this market and crowded in classes 9 and 42, and "ADR" already names other agent-security products, so "Guardrails ADR" is a weak mark on its own. The owner chose it (owner instruction 25, answering D-66's question 4). It carries no house mark, so it can move to a foundation under D-03 without "Loonaro". The recorded search below states how weak it is, and the record is kept whatever it finds.

**What the recorded search checks.**

1. No identical or confusingly similar live mark for "Guardrails ADR" in Nice classes 9 and 42 in the US (USPTO), EU (EUIPO via TMview), UK (UKIPO) and WIPO's Global Brand Database; every near match is recorded with its holder, class and status.
2. The namespace and organisation-level names free in eleven namespaces: crates.io, the npm package name, the npm `@scope`, PyPI, Homebrew core, Homebrew cask, winget, the Debian and Fedora package indexes, Docker Hub and the GitHub organisation name. GHCR follows from the GitHub account and is not checked separately.
3. The CLI name passes the same registry checks and is not a binary in Debian's package contents index.
4. No overlap with a CNCF, OpenSSF, OWASP or Linux Foundation project name.
5. Transferable: the marks and the domain are owned by the entity, free of any personal claim.

**Process.**

1. `xtask name-check <name>...` queries each registry's public API and records query, response code and timestamp in `brand/clearance/<date>.json`. It is never re-run over an old record; reruns append.
2. A knockout trademark search on the four databases is recorded in the same file, with links. An agent does this; it is not legal clearance.
3. **[Counsel] L-01**: a clearance opinion on "Guardrails ADR" in classes 9 and 42 (add 41 if training is sold). It is outside the zero budget, is taken when free legal help provides one, and gates nothing.
4. Reserving the npm scope, PyPI organisation and Docker Hub organisation needs an account in Loonaro's name, which agents never create (owner instruction 23); each is an external precondition of the first publication to that registry, and nothing else waits on it. The repository stays under the owner's GitHub account with no organisation (owner instruction 5). Placeholder packages are not published: crates.io and PyPI discourage squatting. Real packages follow when the first public crate exists.
5. **[Counsel] L-02**: trademark applications for "Guardrails ADR" (US and EU, classes 9 and 42) and, separately, for "Loonaro" as the house mark. Applications carry official filing fees, which are not unavoidable under a zero budget: they are filed when a sponsor, a foundation or a free legal programme covers them. Until then the search record stands and the marks are used unregistered.
6. `brand/brand.toml` carries the name and the rename test (04-4) runs.

**What the name changes.** User-visible text, the conformance marks and the foundation application use the brand manifest's `product_name`, which Loonaro's manifest sets to "Guardrails ADR"; Loonaro's signed builds, hosted service and support use the same name, with Loonaro as publisher. The marks that move under D-03 are "Guardrails ADR" and the conformance marks; Loonaro keeps "Loonaro". Technical namespace: `grdr` stays (D-66). Protobuf packages and the Cedar namespace are wire identifiers, and every external consumer makes them more expensive to change. The namespace need not match the name (`kubectl` is the precedent).

**Trademark policy** (`TRADEMARKS.md`, an early work item, **[Counsel] L-03**):

- Nominative use is free ("works with", "integrates with").
- Factual statements such as "built from <name>" are free. The conformance marks are those of 30 section 8; each is allowed only for a build with a current registry listing, which states the embedding option (D-41, L0 to L6) and the assurance level reached.
- A rebuilt white-label or fork must not use the name in its product name. This is the NATS outcome from brief 28.
- The marks belong to the project and move with it under D-03; Loonaro sells conformance testing, not the mark (c6 F1).

### 2. The brand manifest

`brand/brand.toml` is the only file that contains a user-visible name (ARCH-009). `cargo xtask dist` reads it through the distribution manifest `dist.toml` (03). The schema is in the seed; the co-brand runtime requires the provider tier (D-35).

| Class | Examples | Who may change it | When |
|---|---|---|---|
| A. Wire and ABI | Protobuf packages `grdr.*`, Cedar namespace `Grdr`, C ABI prefix `grdr_`, error codes `GRDR-`, environment prefix `GRDR_`, option numbers | An RFC (D-61) before the first release; nobody after it | Fixed at the first release |
| B. OS identity | CLI and binary names, service and launchd labels, bundle ids, Team ID binding, ETW provider name and GUID, unified-log subsystem, install paths, `HKLM\SOFTWARE\Policies\<brand>`, MDM domain, deb and rpm names, BPF pin prefix, WFP provider GUIDs | A rebuilt build (D-41 L6 rebuilt) with its own signing identities | Build time |
| C. Display | Product name, short name, vendor name, block-message component, logo, DTCG brand tokens, email sender, report template, support and docs links | Rebuilt builds, and the Provider co-brand profile (D-41 L6 co-brand) at runtime | Runtime |

Rules:

- A Class B GUID is generated once per brand and never reused.
- The manifest also holds the project domain and the values derived from it: the docs, hosted-service and update hosts, the mail sending domain, and the security and conduct addresses (owner instruction 25). Loonaro's manifest sets the domain to `guardrailshq.com`; until its DNS exists, the docs and update hosts are GitHub-hosted addresses under the repository owner's account (GitHub Pages and GitHub Releases), so nothing waits on DNS. The DNS records, mail forwarding and SPF, DKIM and DMARC need the registrar or DNS host, which the kit does not reach; the setup step prints the records to add.
- Class C links are display-only. Update, intelligence and enrolment endpoints are configuration (22): `dist.toml` writes the defaults from the manifest's hosts into the default configuration that packages install, no program compiles one in, and a co-brand profile cannot change them, so `grdr egress` never changes with a runtime rebrand; `network.mode = "isolated"` drops them all (24 section 3).
- A self-hosted deployment sets its own domain, hosts and addresses in boot configuration and runtime settings and never contacts or depends on Loonaro's domain; a white-label or partner build swaps the whole manifest (D-41 L6; owner instruction 26). Compiled code holds no domain, host, URL, port, address, product or company name; check S7 blocks one.
- The disclosure surface (D-51) always shows the real software, version and signing publisher, even under co-brand: "Protected by Acme. Software: Guardrails ADR 1.4, signed by Loonaro."
- The `embedded` build profile contains no brand manifest (03).

### 3. Business model

Nothing in this section is offered for money until counsel has reviewed it (D-04, D-46); hosted plans also require the hosted service's preconditions (D-63). The rules below hold from the first push.

**Invariant.** The software is identical in every shape and plan. `plans.toml` may contain only quotas, retention, region choice, support terms and contract terms. The `plans-lint` job fails on any key that enables or disables code paths. SSO, SCIM, roles, audit, customer-managed keys, the provider tier and the full console are in every plan.

**Billing unit.** An active endpoint is a persistent device that sent at least one acknowledged batch that day. The monthly charge is the average of daily distinct counts, not the peak (g10). A WSL2 distribution or a local container served by a counted host's sensor (D-19) is part of that endpoint, not another one. Ephemeral workloads (CI jobs, cluster nodes and sidecars) count as sensor-hours divided by 730. Users and agents are metered (D-68) but not billed: billing per human would need person-level counting, which P8 discourages. Model tiers are off until the Organisation selects a judge back end (D-29); when the payer is a capped platform key, tokens are billed separately, and customer keys and local models are never billed.

**Price anchors** (public list prices as read by the briefs on 2026-11-09 and 2026-11-10; not measured by us).

| Product | Unit | List price | Source |
|---|---|---|---|
| Microsoft Agent 365 | user-month | USD 15; inside E7 at about USD 99 | h04 section 4 (secondary) |
| Knostic Kirin Team | user-month | USD 15; free for 1 to 5 users | h04 verification row 4 |
| Unbound Pro | user-month | USD 20 billed annually, no minimum; Enterprise from USD 28 plus 10% of LLM passthrough | h04 verification row 4 |
| Aembit agentic | agent-month | USD 20 (paid tier 10 to 500 agents); free for 3 agents | h04 verification row 4 |
| Pomerium Zero | user-month | USD 7 annual, USD 9 monthly | h04 verification row 4 |
| CrowdSec intelligence | month | USD 49 a month for 5,000 CTI queries; Platinum USD 1,900 a month | brief 28 verification row 10 |
| Origin | endpoint | Free one seat; Team and Team Pro per endpoint, no figures | brief 01 verification row 9 |
| Falcon Guardian, BeyondTrust, Palo Alto | none published | Quote only | 01 |

**Plans.** All prices are **proposals**, to be set after S-01 and the conversations in section 14.

| Plan | Shown by default | Price (proposal) | Contents |
|---|---|---|---|
| Free | Yes | USD 0 | 1 Organisation, up to 10 active endpoints, structural events kept 30 days, receipts 13 months (audit is never cut), community support, customer key or local model only, no SLA |
| Team | Yes | USD 12 per active endpoint-month annual, USD 15 monthly; a minimum monthly charge covering support cost, set together with the prices (R-46) | D-51 retention defaults; longer retention USD 0.03 per GB-month; platform-key tokens at provider list price plus 10%; standard SLA (section 5); live intelligence; email support within 2 business days |
| Enterprise | Behind toggle | Team price plus a support plan | Region and cell choice, negotiated DPA and DORA Article 30 addendum, the higher SLA (section 5), invoicing, named contact |
| Provider wholesale | Behind toggle | USD 6 per active endpoint-month, no minimum, billed in arrear from the signed usage statement | Free not-for-resale Organisation (25 endpoints), tokens passed through or on the Provider's key, partner support channel, co-brand profile |
| Self-hosted support | Behind toggle | Standard USD 2 per endpoint-month, minimum USD 5,000 a year; Priority USD 4, minimum USD 20,000 | Supported lines only (D-58); response targets, not resolution guarantees; support bundle workflow (34) |
| Live intelligence | Behind toggle | Included in Team, Enterprise and Provider wholesale; self-hosted USD 1 per endpoint-month, minimum USD 1,200 a year | The live feed of 14 section 17. Free and every unsubscribed install get the public feed: mirrored records, `malicious` verdicts and withdrawals at once, enrichment and prevalence after 7 days (R-14) |
| OEM services | Behind toggle | Programme fee plus engineering day rate, quoted | Section 7 |

**What the free tiers cost us (estimates; replace with S-01).**

- Standalone and self-hosted cost Loonaro only the update repository and content operations. Fetches are anonymous and mirrorable (D-48).
- Hosted Free, with no platform model: infrastructure share is USD 0.15 to 0.30 per endpoint-month. That is g10's USD 150 to 300 a month at 1,000 endpoints, an inference from list prices, not a measurement. So a full Free Organisation costs USD 1.50 to 3.00 a month at the margin.
- Each region adds a fixed floor of about USD 1,500 to 3,000 a month (g10, inference). Under a zero budget this floor is why the hosted service requires revenue, sponsorship or donated cloud credits (D-63).
- Each cell has an operator cap on Free Organisations (start: 500, about USD 1,500 a month at the margin). Abuse controls follow g10: email verification for everyone, risk-scored extra checks, never a card for Free.
- Team gross margin target is above 90% before support: COGS of USD 0.15 to 0.30 without platform tokens (g10 modelled range USD 0.28 to 1.00 with them). Token billing at cost plus 10% keeps model spend out of the margin.

**Payments.** Requires the hosted service. Rating and invoicing are adapters over the ledger (D-68). Stripe is the hosted adapter. The adapter sends one meter event per Organisation, meter and hour, with plan and region as the only dimensions (never device or user ids), so it stays inside Stripe's limits of one concurrent call per customer per meter and 100 dimension combinations per customer (g10 verification). Providers are invoiced directly rather than through Stripe Connect, whose connected-account calls get only 100 operations a second (g10 verification). Tax and VAT handling, including whether to use a merchant of record, is **[Counsel/accountant] L-04**.

**Support model.** Community support uses a forum and an answerer grounded in documentation and source. Paid support covers supported lines only (34 section 9: the current minor, the two before it and the live LTS; D-58), for self-hosted installs and, once it exists, the hosted service. Agents draft first answers; a person sends anything contractual (g10 section 8). Priority support needs two people on a rota, the same condition as D-63, which the owner and the buddy meet.

**LTS beyond the public window.** D-58 sets 24 months of public security fixes and leaves longer periods to counsel. The CRA requires a support period of at least five years unless the product's expected use is shorter (Art. 13(8); brief 34 verification row 3). Security updates in that period must be free of charge, except where a manufacturer and a business user agree otherwise for a tailor-made product (Annex I Part II(8); the author's reading of the regulation, not checked in the briefs). So paid "LTS maintenance" may cover only non-security backports and help inside the support period, plus everything after it. **[Counsel] L-05** fixes the support period and says whether OEM contracts fall under the tailor-made exception. Until then engineering plans for up to five lines under commercial support while public fixes stay at two live lines (34 section 9, whose `lifecycle.toml` records `commercial_support_until` per line).

### 4. The legal entity

The legal entity is Loonaro (owner answer 1). It holds the Apple, Microsoft, GitHub and signing accounts, the trademarks and the domains. Its jurisdiction and registration details are confirmed with counsel. These depend on it:

| Dependent | Needs | Blocks |
|---|---|---|
| Apple Developer organisation enrolment, Endpoint Security entitlement request | D-U-N-S number, entity; the Program's annual fee, the one unavoidable cost (owner decision, spine question 8) | Signed and notarised macOS builds; D-18 tiers 2 and 3. Without the Program, macOS ships with Sigstore signatures and provenance, marked not platform-signed and not notarised, at tier 1 only |
| Windows user-mode signing through a free open-source signing programme (for example SignPath Foundation) | Entity; the project's acceptance into the programme, verified at setup | Signed Windows user-mode builds |
| EV certificate and Partner Center with two administrators (the owner and the buddy) | Organisation validation (requirements not verified in the briefs); paid for by a sponsor or partner | D-17 driver |
| Trademark and domain ownership | Applicant entity | D-66, D-03 escrow |
| Contracts (design partners, OEM, MSP, customers), DPA processor role | Entity | Sections 7 to 9 |
| CRA manufacturer, EU declaration of conformity, access to ENISA's single reporting platform | Entity; the EU contact of D-46. If the entity is outside the EU: a GDPR Art. 27 representative, and counsel's view (L-19) on appointing an authorised representative, which CRA Art. 18 makes optional | Any paid offer (D-46) |
| Payments, tax registration, insurance (technology errors and omissions, cyber) | Entity; insurance premiums funded by revenue or a sponsor | Hosted service, beta included |
| Copyright holder of record for steward-written material | Entity | First push |

The covenant assets in D-03 are registered to the entity. **[Counsel] L-06**: a springing assignment of marks, domain and GitHub organisation, held in escrow before the first release and executed on the D-03 trigger. This is how the covenant is made binding before a foundation exists (c6 F2); L-06 also covers the legal wording of `COVENANT.md`, whose content 30 section 13 fixes.

**Counsel under a zero budget.** There is no money for paid counsel. Every **[Counsel]** item goes first to free legal help for open-source projects (foundation legal programmes, pro bono clinics). An item that blocks a paid offer stays open until counsel answers it, and Loonaro offers nothing paid while it is open. Items that block only the free product (L-01, L-03, L-06, L-08, L-14, L-16, L-18, L-21) are worked through the same free routes.

### 5. Terms for the hosted service

Templates live in `legal/terms/` as versioned Markdown. Each change produces a dated diff page. Every document is **[Counsel] L-07**. Drafts can be written at any time; sign-off is required before the first hosted tenant, and the hosted service itself requires the D-63 preconditions.

| Document | Decided content |
|---|---|
| Service terms | Free and beta carry no SLA. Customer data is used only to run the service (D-51). No training on customer data. Suspension for non-payment keeps sensors enforcing cached policy (D-35, l05). Exit export and deletion without operator help (D-67) |
| Acceptable use | No use to monitor people covertly or without the notice the law requires; no attacks on third parties; no load or penetration testing without consent; agent-originated traffic stays attributable |
| Data processing agreement | Customer is controller, Loonaro processor. With an MSP, the Provider is processor and Loonaro its sub-processor, with flow-down. Data categories are listed by D-06 data class; default capture level is `metadata`. Transfers use EU SCCs and the UK addendum. Breach notice to the customer within 24 hours of confirmation (proposal). Audit right is met by the generated control file (D-46) and, once one exists (it requires revenue or a sponsor, D-46), the SOC 2 report; without it, by the control file and a standard questionnaire. Deletion by crypto-shredding (D-57) within 30 days of termination, with a signed receipt |
| Service level agreement | Contract sits below the D-56 objectives (console and API 99.9%, ingest acknowledgement 99.9%), so a missed objective is not yet a credit. Console and API (proposal): 99.5% monthly for Team, 99.8% for Enterprise. Ingest acceptance: 99.5%. Credits of 10, 20 and 50% below 99.5, 99.0 and 98.0% (Grafana's first three bands; Grafana adds 100% below 97.0%; g10 verification row 8). Volume above 300% of the prior 30-day peak is excluded. On-device verdicts are local and outside the SLA, which says so |
| Sub-processor list | Data in `legal/subprocessors.yaml`: name, purpose, data classes, region, transfer basis. It generates the public page and a feed. Changes take effect after 30 days' notice, with a right to object. A model provider appears only for Organisations that choose a platform key (D-29) |
| Security exhibit | Generated from the control library (D-46, 29); never hand-written |
| Regulated customers | HIPAA BAA template and DORA Article 30 addendum, written when a regulated customer requires them |

### 6. Licence and notice compliance

`supply-chain/licences.toml` is enforced by `cargo-deny` for Rust and an equivalent checker for the web console and SDKs, and gated in `verify`. Notices are in every release artefact.

| Closure | Allowed | Denied |
|---|---|---|
| `embedded` build profile (L3) | Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, BSL-1.0, CC0-1.0 (data) | Everything else |
| Sensor, server, console | The above plus MPL-2.0, unmodified, as separate crates or npm packages | GPL, LGPL, AGPL, SSPL, BUSL, ELv2, FSL, DRL, Commons Clause, CC-BY-NC |
| eBPF crate | Our own `GPL-2.0-only OR BSD-2-Clause` (D-02) | Third-party GPL-only kernel code |
| Content packs | Our Apache-2.0 records; mirrored records under their source licence in separate packs (GHSA is CC-BY-4.0 with attribution, 14) | DRL and ELv2 rules (Sage's rules are DRL 1.1; Elastic rules); OWASP MCP Top 10 text (CC BY-NC-SA 4.0, h06), cited by id only |
| Development-only tools | Any licence, installed, never vendored (D-02) | Vendoring share-alike or custom-licence tools |
| Air-gap bundle (24 section 7) | Every component redistributable under its licence: our artefacts, third-party images we build from source on a minimal base, charts, binaries and packages; each copyleft component with its complete corresponding source and our patches in `sources/` (owner instruction 20) | A component whose terms forbid redistribution: it is replaced by a redistributable equivalent or stays optional and `not configured` (30 section 1) |

Changing the allow-list is a protected change (owner instruction 7) through the RFC of 30 section 3, checked by `eval-licence`; **[Counsel] L-08** reviews the policy when free legal help is available and gates no change.

Notices:

- `cargo xtask dist` emits `THIRD-PARTY-NOTICES` per artefact from the SBOM (24) and the Apache-2.0 `NOTICE` chain (section 4(d)), and one for the air-gap bundle beside its CycloneDX SBOM, listing every component, its licence and its source.
- `grdr notices show` prints it. The desktop app and console show it under Settings, About, "Open-source notices".
- A test fails if any SBOM component lacks a notice entry.

Licences still to verify before the dependency is adopted: Astryx and the icon library (the local console subset, D-42), Rune (D-43), and each judge model's weights.

### 7. OEM and embedding agreement outline

Requires an embedding partner. The code is Apache-2.0 for everyone. The agreement sells services and carries risk; it never licenses code. **[Counsel] L-09**.

1. **Deliverables.** Source with a reproducible build and provenance, not our signature (l08 F2). Access to the content relay (D-60). Private conformance runs of the partner's mapping with the three kits. A tailored CRA due-diligence file. Integration engineering at a day rate.
2. **Contractual freshness targets.** An agent-version break is detected within 24 hours, shipped to the early ring within two working days and to stable within five (l08 F7, D-49).
3. **Support period.** Security fixes per engine LTS line long enough to cover the partner's own five-year CRA duty (c6 F4): five years per line, aligned with L-05.
4. **Warranty and indemnity**, capped, only here (Apache-2.0 sections 7 and 8 disclaim both). The agreement discloses agent authorship and the evidence chain (D-61).
5. **Marks.** The conformance mark for the partner's option (30 section 8) once listed, stating the embedding option and assurance level.
6. **Data.** No call to Loonaro, no Loonaro strings, no embedded trust roots (D-60). Contributions are aggregate and digest-keyed. Partner overlays do not disqualify upstream packs (l08 F9).
7. **Channel.** Loonaro does not use partner telemetry to approach partner customers. Public hosting stays open to anyone.
8. **Not sold.** Vulnerability pre-disclosure, which is free to any redistributor meeting the published criteria (D-04, D-62).
9. **Boilerplate.** Confidentiality, export and sanctions compliance, term and termination, governing law.

### 8. MSP (Provider) agreement outline

Requires the provider tier (D-35). **[Counsel] L-10.**

1. **Model.** Resale: the Provider buys wholesale and sets its own price.
2. **Ownership.** For Provider-originated Organisations the Provider is owner of record until the customer claims the Organisation (D-35). The agreement binds the Provider to honour a claim and the exit export (D-67).
3. **Billing.** The signed monthly usage statement from the ledger (D-68) is the billing record. Disputes are settled against the ledger export.
4. **Data chain.** DPA flow-down as in section 5. Content stays metadata-only unless the Organisation grants more (D-40).
5. **Security duties.** Two Provider approvers with step-up for Provider-scope actions (D-30). Technicians sign in through the Provider's IdP.
6. **Branding.** A co-brand profile only. OS-level identity stays Loonaro's and is disclosed (section 2).
7. **Parent Providers** (distributors, OEMs) get provisioning and billing rights only, never data access (spine section 3).

### 9. Copyright and warranty for agent-written code

Counsel answers these before the first public release (30 section 2) and before an OEM signs.

**Facts, from secondary sources (not read at the primary).** The US Court of Appeals for the D.C. Circuit held on 18 March 2025, in Thaler v. Perlmutter, that registration requires human authorship. One source reports that the Supreme Court declined review on 2 March 2026. The Copyright Office's Part 2 report (29 January 2025) separates assistive AI use, which can support protection, from prompting alone.

Questions for counsel, **[Counsel] L-11** to **L-15**:

| Id | Question | Why it matters | Interim practice |
|---|---|---|---|
| L-11 | Which parts of agent-written code are protected by copyright, in the US and EU, given the owner's instructions and the specifications agents write from them? | Enforceability of Apache-2.0 conditions; what we warrant to OEMs | The issue records the specification a change implements and the pull request's metadata block records the harness and model that wrote it (owner instructions 5 and 27) |
| L-12 | With no DCO or sign-off (owner instruction 7), do Apache-2.0 section 5 and the contribution terms in `CONTRIBUTING.md` give the project a sound inbound licence for outside contributions, and what record should each pull request keep? | The whole inbound chain | `CONTRIBUTING.md` states that a contribution is submitted under Apache-2.0 section 5; the pull request records its author and its metadata block |
| L-13 | Do Anthropic's terms for the owner's Claude subscription assign output to us and give indemnities; do they permit headless Claude Code sessions run by the local dispatcher and scheduled routines under the owner's account; and do their data terms give zero retention? The answer is recorded for embargoed fixes and support bundles and gates neither (owner instruction 7) | Ownership, third-party claims, the agent team's runs and the embargo record | `legal/model-terms.yaml` lists the plan, date read and clause for each harness the fleet uses |
| L-14 | Residual risk of verbatim reproduction of copyleft code | Licence contamination of the embedded closure | A snippet-match scan of each merged diff against a licence-indexed corpus; any copyleft match blocks the merge; do-not-read list (D-02) |
| L-15 | Patent exposure of agent-written code, and whether to do freedom-to-operate searches | OEM indemnity scope | No searches before counsel advises; Apache-2.0 patent grant from contributors |

### 10. Export controls and sanctions

- **Published software.** Per the Linux Foundation's guidance (brief 28), published open-source source and binaries are not subject to the EAR. Since 2021 only non-standard cryptography needs a notice to BIS and NSA. We compose standard algorithms only (rustls with aws-lc-rs, Ed25519, hybrid TLS 1.3 key exchange), so we expect no notice. **[Counsel] L-16** confirms this and covers the EU dual-use regulation's public-domain treatment.
- **Export statement.** `docs/legal/export.md` states the cryptography used and links the source.
- **Hosted service, paid support, OEM and MSP contracts.** These are subject to sanctions law (brief 28, unverified there). Sign-up and payment screen the Organisation name, billing country and source-IP country against the OFAC SDN list, the EU consolidated list and the UK OFSI list through a `SanctionsScreen` adapter. The denied-jurisdiction list is data maintained by counsel (**[Counsel] L-17**), never by an agent. Screening results keep only list version, match outcome and date; retention follows L-17. Contract counterparties are screened before signature.
- **Efficacy harness content (D-45).** Payloads are benign stand-ins in the EICAR tradition. **[Counsel] L-18** reviews whether any scenario family could count as intrusion software under Wassenaar-derived controls before the harness is published.

### 11. Cyber Resilience Act and product liability

Technical documentation is public with the first public release; everything else here is a precondition of any paid offer.

**Dates.** These are the regulations' own application dates, not project dates.

| Date | Event | Source |
|---|---|---|
| 2024-12-10 | CRA in force | Reg. 2024/2847, author's reading; brief 28 gives 2024-12-11 via ORC WG. Nothing here depends on it; the Art. 71 dates below bind |
| 2026-06-11 | CRA Chapter IV (notified bodies) applies | brief 34 verification row 3 |
| 2026-09-11 | Manufacturer reporting under Art. 14 applies: 24-hour early warning, 72-hour notification, 14-day final report | briefs 28, 34; D-46 |
| 2026-11-17 | EN 40000-1-1 and 1-2 publication scheduled; no CRA harmonised standard cited in the Official Journal | h06 verification row 8 (secondary) |
| 2026-12-09 | Product Liability Directive (EU) 2024/2853 transposition date. Software is a product. Free and open-source software supplied outside a commercial activity is excluded (Art. 2(2), recital 14); supply for a price or personal data is not | Search summaries of EUR-Lex text (2026-11-10), not read at source |
| 2027-12-02 | AI Act Annex III duties apply (29 owns the analysis) | brief 34 verification row 1 |
| 2027-12-11 | All CRA obligations apply; steward reporting under Art. 24(3) starts | briefs 28, 34 |

**Our status.**

- Once Loonaro monetises anything, Loonaro is a manufacturer of what it monetises (Commission guidance C(2026) 5252 point 76, non-binding). Under point 54 and its Example 15, a free sensor that connects to a paid hosted service is itself likely placed on the market (brief 28 verification row 3). The hosted server counts as remote data processing within the product.
- The candidate categories are Annex III Class I (identity and privileged access management, anti-malware, SIEM) and Class II (intrusion detection and prevention).
- Art. 32(5) lets free and open-source products in those categories self-assess if the technical documentation is public when the product is placed on the market. It covers Annex III only and does not relax the Annex I requirements (brief 28 verification row 4). Self-assessment also avoids a paid notified body, which a zero budget could not cover.
- Art. 14 reporting already applies (since 2026-09-11) to any product Loonaro places on the market, so the first paid offer starts the reporting clocks at once.

**[Counsel] L-19** decides the class, the Art. 32(5) route and the support period (with L-05). Counsel also decides whether the free standalone build distributed by Loonaro inherits manufacturer status.

**Work regardless of the answer.**

1. Technical documentation in `docs/cra/`, public from the first public release. Risk assessment, Annex I mapping, SBOM reference, vulnerability-handling policy (35) and support statement.
2. Access to ENISA's single reporting platform for the entity, set up before the first paid offer; the onboarding procedure is confirmed with L-19.
3. The 24-hour, 72-hour and 14-day clocks met by the security response process of 35 section 4.7, where agents run the clocks and draft every report, plus the human-staffed team D-46 requires before a paid offer, which files them as Loonaro: the owner and the buddy.
4. Security updates free and kept available for the period counsel sets. c6 F8 proposes ten years.
5. EU declaration of conformity and CE marking for the monetised distribution. The law requires them for products placed on the market from 2027-12-11; we produce them with the first paid offer if that comes earlier, so the first customer does not receive a product that changes status a year later.

**Product liability.** **[Counsel] L-20**:

- Exposure under the PLD for the monetised distribution and the hosted service, and whether contractual caps hold. The PLD limits contractual exclusion, but this was not verified here.
- The equivalent US position.
- Insurance cover before the hosted beta, with premiums funded by revenue or a sponsor.

### 12. Pricing and plan surfaces

Built by the interfaces squad with 27 and 28; published with 34.

*Before building, per ui-architect.*

- **Evaluation.** The surfaces are the public pricing page with its quote calculator, plan choice after `grdr join`, the Enterprise and OEM enquiry, the Provider co-brand profile editor, and downgrade or cancel. They must state that nothing is withheld, and they must not gate value.
- **Violations to avoid.** More than two primary tiers shown; empty forms (the enquiry and the calculator are the likely offenders); progress starting at zero; a sign-up wall before value; emoji in cards; mathematically symmetric padding; ad hoc spacing. Opportunities: Chunking on the plan cards, honest Loss Aversion on downgrade, Anchoring on price.

*The fixes and the principle behind each.*

| Surface | Decision | Principle |
|---|---|---|
| Pricing page | Free and Team cards only. A "View all plans" toggle reveals Enterprise, Provider, self-hosted support, live intelligence and OEM | Two-tier hard rule; Chunking |
| Plan cards | The Free card lists the core capabilities once, as at most four lines under "every feature, every plan". The Team card lists only what differs (endpoints, retention, SLA, support), also at most four lines. Each line has a Lucide icon instead of a text chip | Chunking: list core features in the basic tier and only differences above it; Zen of Clarity |
| Price display | The Team card shows the annual rate as a monthly figure per endpoint beside the higher monthly-billing rate (USD 12 against USD 15), so the larger number sets the context. A single line under both cards says the same software self-hosts at no cost, which is true and is the product's promise. "Cancel anytime" under the call to action, which carries a right chevron | Contrast and Anchoring; paywall structure |
| Quote calculator | For Providers and buyers who need a number (R5). Pre-filled with 25 endpoints (the client size in the spine's provider onboarding target, section 6) and the annual Team rate; Providers see wholesale beside it. Changing the count recomputes in place; no account needed | Smart Defaults; Reciprocity |
| Enterprise and OEM enquiry | Never a blank form. A signed-in visitor gets Organisation name, region and the ledger's current active-endpoint count pre-filled; an anonymous visitor gets the calculator's values. Only a contact address is typed | Smart Defaults |
| Primary call to action | "Install free". It runs the standalone first run with no account (D-48). The hosted sign-up appears only at `grdr join`, after local value | No sign-up wall; Reciprocity; Outcomes over features |
| Join flow | The Organisation name is pre-filled from the local organisation alias. Region is pre-filled from the browser locale. The plan is pre-set to Free. The setup checklist is owned by 27 section 6 (R-47); this flow only requires that it opens with completed steps such as "Install" and "First scan" ticked, never at 0% | Smart Defaults; Goal Gradient |
| Co-brand editor | Pre-filled from the Provider's verified domain and sign-in identity. Tokens start from the default DTCG theme. A live preview of the block message and tray | Smart Defaults; IKEA Effect |
| Downgrade and cancel | Shows exactly which data beyond the Free retention will be deleted and on what date, with export (D-67) as the first action. On annual cancel, offers monthly billing instead. Deleting an Organisation needs a typed confirmation and a 24-hour pause | Loss Aversion, stated truthfully; Exit Intent; Ethical Friction |
| Icons, spacing, type | 27 section 10's tokens and presentation registry through the kit's `PlanCards` pattern. Tabular numerals for prices, the smaller raised currency symbol and the chevron-side padding are the tokens `price-currency-scale`, `price-currency-raise` and `optical-chevron-trail`, registered with 27's optical tokens | Exponential Scaling; Optical Corrections |

### 13. Category, analyst mapping and positioning

The wording holds from the first push; the published mapping page is CM-10 in 01.

**Category statement.** Guardrails ADR is an open-source agent detection and response (ADR) platform; the market also calls the category AIDR. In analyst terms:

- Gartner: guardian agents, all three capability areas (AI visibility and traceability; continuous assurance and evaluation; runtime inspection and enforcement), delivered as embedded runtime modules plus gateway, two of Gartner's six delivery approaches. The Market Guide was not read; this rests on a secondary summary (brief 06 verification row 9, g03).
- Forrester: an agentic control plane (secondary, h04).
- Latio: Endpoint Agent Specialists, one of the report's five categories (h04 verification row 9).
- KuppingerCole: AI-VOP (compass March 2027) and ATDR (December 2027) (h04 verification row 8). These are the two questionnaires to prepare.
- CSA: an AARM builder. We say "passes the AARM R1 to R9 test set" until all four conditions for a public conformance claim hold: five production customers for three months, a recognised certification (for example SOC 2 Type II, which requires revenue or a sponsor, D-46), an active community representative and a benchmarking commitment (D-46; h04 verification row 2).

Public pages that name competitors or their prices are comparative claims. **[Counsel] L-23** reviews the positioning table's public form, 01's public comparison page and the price anchors before each is first published: comparison and positioning with LBC-25 (01 CM-5), prices with LBC-15.

The mapping page is CM-10 in 01.

**Positioning against what each buyer already has.**

| Buyer | Bundled or free alternative | Free from us | What they pay Loonaro for |
|---|---|---|---|
| Solo developer | Numbat, Prempti, DefenseClaw (free); Knostic free tier | Everything, standalone | Nothing; hosted Free if they join |
| Team that self-hosts | OpenShell for launched agents only | The full platform (D-65) | Support, LTS, live intelligence |
| Enterprise on Defender | Agent 365 at USD 15 per user, E7 at about USD 99; Defender's agent features need it as the active antivirus | Targeted build beside any EDR | Hosted Team or Enterprise, support. Pitch: Linux, Codex and Cursor enforcement, unregistered agents, local decisions |
| Enterprise on Falcon (Defender passive) | Falcon Guardian, bundled, cloud verdicts | The same | The same, plus L4 import and export (01) |
| MSP or MDR | Arctic Wolf inventory; audit-log MDR for Claude (eSentire, Daylight) | Provider tier in the open build | Wholesale hosting, co-brand, partner support |
| EDR or gateway vendor | Build on Cedar plus open hook contracts | L0 and L1, the engine | OEM services, freshness targets, warranty |

### 14. Design partners and launch steps

Each step can happen once its prerequisites hold; none is scheduled.

| Step | Requires | Content | Exit evidence |
|---|---|---|---|
| Design-partner recruiting | The design-partner letter template (L-21) | One MVI-member EDR or MDR for the L3 sidecar pilot (D-41); 3 to 5 enterprises on Falcon or Defender; 2 to 3 MSPs. Design partners are also the route to incumbent EDR licences for the test lab (D-64) | A signed design-partner letter each. **[Counsel] L-21** templates: free, no data to Loonaro, feedback rights, optional logo |
| Public repository | Nothing: public from its first push (owner instruction 28) | Licence and `SECURITY.md` in the seed; covenant, `GOVERNANCE.md`, `TRADEMARKS.md` and the search record as early work items | Search record filed in `brand/clearance/` |
| Willingness to pay | The mock price page and notes template (LBC-12) | Ten owner-led conversations (five MSP or MDR, five enterprises) with a mock price page and the L0 pack. c6 proposed them as spike 4; the resolution made them input to the owner's D-02 review rather than a team spike. Agents prepare the mock page and the notes template and tally the results; they hold no conversation | Licence review input (section 15) |
| First public release | The server-licence review (section 15); D-66's recorded search; L-03 and L-06 | Standalone, published scorecard (D-45), a plans page that states "every feature, every plan" and lists the hosted plans as "not yet available", with no prices (prices wait for LBC-15) | Licence review passed |
| Enterprise Watch pilots | The targeted build; L0 and L1 feeds; an enterprise design partner | Targeted build, L0 and L1 feeds, coexistence results | One pilot converts to a written self-hosted support intent |
| Self-hosted support offer | The server in `embedded` and `ha`; every D-46 precondition, counsel's review included (key choice 7) | Support plans open | First paid support contract |
| Hosted beta | The `distributed` load test (R-36); the D-63 preconditions, including infrastructure funded by revenue, sponsorship or donated cloud credits | No SLA | D-63 conditions met: two people share on-call (the owner and the buddy), the entity exists, the incident-reporting process is written, funding is in place; section 5 terms signed off |
| Provider programme | The provider tier (D-35); the hosted service | Wholesale price live | One MSP onboarded under the spine's provider onboarding targets |

### 15. The server-licence go or no-go review

**When.** Before the first tagged public release (D-02). It binds future server code. Nothing about the server is relicensable after it.

**Evidence the review needs.**

1. Results of the willingness-to-pay conversations (section 14): conversation notes, the count of written letters of intent for hosting or support, and the count of L0 or L3 pilot commitments.
2. The cost baseline from S-01, and the free-tier cost estimate re-run on measured volumes.
3. Hosting-competition risk: any hyperscaler, EDR or MSP announcing a hosted fork, taken from the 01 re-verification.
4. Any foundation pre-read feedback (D-03) on licence and structure received by then; the pre-read meetings are described in 30 section 10.
5. **[Counsel] L-22**: what AGPL-3.0 for the server would change for MSP self-hosting, OEM embedding and foundation admission.

**Rule.**

- Go (confirm Apache-2.0) when at least three letters of intent and one pilot commitment exist.
- Otherwise the owner decides, with the recommendation still to confirm Apache-2.0 and lead with support and OEM revenue. AGPL closes CNCF, OpenSSF and embedding, and earns nothing without a CLA (D-02, c6).
- No-go means the owner reopens D-02: a spine revision and a public RFC (D-61) before the first tagged release, and that release ships no server code until it closes. Code already public stays Apache-2.0.
- The outcome is a decision record in `docs/decisions/`.

## Interfaces and contracts

| Artefact | Shape | Other side |
|---|---|---|
| `brand/brand.toml` | Schema `grdr.brand.v1alpha1` with tables `identity` (`product_name`, `short_name`, `vendor_name`, `project_name`, `namespace`, `reverse_dns`, `domain`, `category`, `category_short`), `repository` (`forge`, `owner`, `name`, `url`), `hosts` (`docs`, `hosted`, `updates`, `mail_domain`) and `addresses` (`security`, `conduct`), each host and address a `value` and its `on_domain` value, `os_identity` (Class B keys), `display` (Class C keys, `block_component`), `links` (`docs_base_url`, `support_contact_default`), `assets` (`logo_svg`, `icon_set`), `tokens` (path to DTCG file) and `legal` (`copyright_holder`, `trademark_notice`) | 03 (`dist.toml`, ARCH-009), 04 (package, provider and feed names), 07 (block messages), 11 (coexistence pack), 22 (packaged update defaults), 24 (signing identities), 25 (mail sender), 34 (docs links) |
| Co-brand profile | Provider-scoped record of Class C keys only; inherited by Organisations; API in 23 | 21, 23, 27 |
| `brand/clearance/*.json` | Append-only name-check and knockout-search records | Owner, counsel |
| `plans.toml` | Per plan: quotas (endpoints, Organisations, ingest, query), retention by data class, regions, support terms, SLA id, price ids. No feature keys | `router` and quotas (20, D-68), billing adapters, the pricing page |
| Usage statement | Signed monthly statement from the D-68 ledger, with all ancestor ids | Billing adapters; Providers; OEM revenue share |
| Intelligence entitlement | Token claims `org`, `plan`, `expires`, `classes` | 14 (feed), 22 (repository) |
| `SanctionsScreen` port | `screen(org_name, country, ip_country) -> {clear, review, deny, list_version}` | Hosted sign-up and payment |
| `legal/subprocessors.yaml`, `legal/terms/` | Versioned data and documents; generate public pages and change feeds | 34 (publication), customers |
| `legal/counsel-register.yaml` | `{id, question, blocks, status, opinion_ref}`, where `blocks` lists work items and offers | Planner: an open item blocks the work items and offers it lists |
| `supply-chain/licences.toml`, `THIRD-PARTY-NOTICES` | Allow and deny lists per closure; per-artefact notices | 24 (SBOM), `verify` |

## Behaviour by deployment shape

| Concern | Standalone | Platform, self-hosted | Platform, SaaS | Embedded |
|---|---|---|---|---|
| Terms | Apache-2.0 only | Apache-2.0; support contract optional | Section 5 terms | OEM agreement optional |
| Billing | None | Ledger local; signed statements for Provider or OEM revenue share, air-gapped by export | Ledger, Stripe adapter | Partner's own |
| Sanctions screening | None (public download) | None by Loonaro | At sign-up and payment | Counterparty screening only |
| Brand | Default manifest | Default; Provider co-brand | Default; Provider co-brand | Rebuilt manifest or none (03) |
| CRA role | Steward or manufacturer per L-19 | Loonaro manufacturer only for what it monetises | Manufacturer | Partner is manufacturer of its product; Loonaro supplies the due-diligence file |

## Extension points

- **Rebuilt white-label.** A new `brand.toml`, signing identities and content root through `dist.toml`; no core change.
- **Billing.** Adapters implement the rating port over the ledger: Stripe in core; Kill Bill, OpenMeter and PSA posting in contrib (g10). AGPL engines such as Lago are not allowed in the closure.
- **Sanctions screening.** Providers implement `SanctionsScreen`.
- **Plans.** A self-hosting operator who resells writes its own `plans.toml`, subject to the same lint.
- **Translations of legal pages.** Through the docs translation workflow (34 section 15a), labelled as translations. The English text is authoritative unless counsel says otherwise.

## Security and privacy

- The billing unit is device-level. No price, invoice or statement names or counts people (P8); statements carry Organisation and device counts only.
- Billing and screening data sit in the hosted control plane, outside tenant storage, under D-55 operator roles. Card data stays with the processor.
- A co-brand profile cannot change network destinations (section 2); CI asserts that `grdr egress` is identical across co-brand profiles and that a rebuilt build's packaged defaults equal the hosts in its manifest.
- Signed contracts live in a document store outside the repository; templates and the register hold no customer data.
- No agent may send a contract, change a price, approve a credit or edit the denied-jurisdiction list (g10 section 8; D-63).

## Test and evaluation strategy

| Property | Oracle |
|---|---|
| No brand string outside `brand/` | ARCH-009 text scan |
| Rename is mechanical | Build with a test manifest (`project_name = "Acme Sentinel"`, new reverse-DNS) on three operating systems. Every Class B and C name changes, Class A identifiers are unchanged, the coexistence pack regenerates (11), and the 04-4 test passes; a test manifest with another domain changes every docs link, address and packaged default, and no binary contains the old domain, a host or a product name (check S7) |
| Co-brand cannot hide the real software | UI test: with a co-brand profile, the disclosure surface and About still show product, version and signer |
| No withheld feature | `plans-lint` rejects feature keys; a differential test runs the same scenario suite against Free and Team configurations with identical verdicts |
| Licence compliance | `cargo-deny` and the npm checker in `verify`; the embedded closure check; every SBOM component has a notice entry |
| No copyleft regurgitation | Snippet-match scan per merged diff; a seeded GPL fragment in a test branch is caught |
| Usage statements are correct | Statement totals equal a recount from the raw ledger; a tampered statement fails signature verification |
| Pricing and plan surface constraints | Component tests: two plan cards visible by default and the toggle reveals the rest; the primary call to action requires no account; the join form, calculator and enquiry render with every field except contact address pre-filled; the setup checklist never renders at 0%; no emoji code point in any plan string; every padding and margin value is a spacing token |
| Sanctions screening | Adapter conformance against published test entries; a deny result blocks Organisation creation and logs list version |
| Sub-processor notice | A change merged without a 30-day `effective_from` fails the lint |
| Counsel gate | The planner refuses to close a work item, or open an offer, that an open register item lists in `blocks` |

## Work breakdown

**Epic LBC-A: names and brand**

- LBC-1 `xtask name-check` over the eleven namespaces with append-only records. *Accept:* the run for `grdr` reproduces the spine's 2026-11-10 result for the six registries the spine checked; network failures are recorded as `unknown`, never `free`.
- LBC-2 Knockout trademark search and namespace record for "Guardrails ADR" and `grdr`; counsel's clearance (L-01) when free legal help provides it. *Accept:* the search record is filed in `brand/clearance/`; D-66's question 4 is marked answered in the spine.
- LBC-3 `brand.toml` schema and loader; Class A, B and C enforcement; Loonaro's manifest with the product name, short name, domain, hosts and addresses (owner instruction 25). *Accept:* the rename oracle passes.
- LBC-4 `TRADEMARKS.md` (L-03) and escrowed springing assignment (L-06). *Accept:* both published or filed before the first release.
- LBC-5 Co-brand profile runtime with disclosure invariant. *Requires:* the provider tier (D-35). *Accept:* the co-brand UI test passes.

**Epic LBC-B: licence compliance**

- LBC-6 `licences.toml` and checks in `verify`. *Accept:* adding a GPL crate to the embedded closure fails `verify`.
- LBC-7 Per-artefact `THIRD-PARTY-NOTICES`, `grdr notices show`, the About screen entry, and the air-gap bundle's notices with `sources/` for every copyleft component. *Accept:* notice completeness test is green for every release artefact and the air-gap bundle.
- LBC-8 Snippet-match scan in the merge queue (L-14). *Accept:* the seeded-fragment test is caught.
- LBC-9 Astryx, the icon library and Rune: verify their licences before adoption. *Accept:* entries in `licences.toml` with source links.

**Epic LBC-C: entity and accounts**

- LBC-10 Loonaro's registration and D-U-N-S number; acceptance into a free open-source signing programme for Windows user-mode binaries; Apple's Developer Program if the owner decides to pay its fee (spine question 8); EU representative decision. *Accept:* signed Windows test binaries and signed Linux packages; signed and notarised macOS test binaries if the Program is joined, otherwise the macOS tier 1 build, Sigstore-signed and not platform-signed, is recorded as such in the release notes and the ceiling matrix.
- LBC-11 `legal/counsel-register.yaml` seeded with L-01 to L-23 and wired to the planner. *Accept:* the gate oracle refuses to close a test work item listed in an open entry's `blocks`.
- LBC-27 `docs/legal/export.md`, counsel's export opinion (L-16) and the efficacy-harness review (L-18). *Accept:* both register items closed before the harness is published; the export page lists every algorithm the SBOM's crypto crates provide.
- LBC-28 `legal/model-terms.yaml` for every harness and model plan the fleet uses: the owner's Claude subscription, the local dispatcher's headless sessions, any hosted agent runs and scheduled routines (L-13). *Accept:* a CI check fails when the fleet configuration names a provider or plan with no entry, or an entry older than 180 days.

**Epic LBC-D: commercial model**

- LBC-12 Mock price page, notes template and tally for the owner-led willingness-to-pay conversations. *Accept:* ten sets of notes and the counts of section 15 item 1 filed for the licence review.
- LBC-13 Server-licence review (section 15). *Accept:* decision record before the first tagged public release.
- LBC-14 `plans.toml`, `plans-lint`, Free and Team differential test. *Accept:* the lint and the differential test pass.
- LBC-15 Prices fixed from S-01 and the conversations; public pricing page and quote calculator per section 12; comparative claims reviewed (L-23). *Requires:* S-01, LBC-12. *Accept:* the pricing and plan surface tests pass; prices approved by the owner; L-23 cleared for prices.
- LBC-16 Stripe adapter with hourly per-Organisation meter events; Provider invoicing from statements; tax and merchant-of-record decision (L-04). *Requires:* the hosted service. *Accept:* reconciliation between ledger and invoices is exact for one month of synthetic usage; L-04 closed before the first invoice.

**Epic LBC-E: hosted legal**

- LBC-17 Service terms, AUP, DPA, SLA, sub-processor data and page (L-07). *Accept:* counsel sign-off recorded before the first hosted tenant; the sub-processor lint passes.
- LBC-18 `SanctionsScreen` with one provider adapter; denied-jurisdiction list from counsel (L-17). *Requires:* the hosted service or a paid contract. *Accept:* the adapter conformance test passes.

**Epic LBC-F: CRA and product liability**

- LBC-19 `docs/cra/` technical documentation published. *Accept:* every Annex I requirement maps to a control or a stated gap.
- LBC-20 Counsel opinions L-05, L-19, L-20; ENISA reporting-platform access; EU contact named; support statement published; insurance bound, with premiums funded by revenue or a sponsor. *Requires:* nothing; it is itself a precondition of any paid offer. *Accept:* register items closed; a test report submitted through the response team's runbook (35) reaches the platform's acknowledgement step, or counsel records why no test route exists.
- LBC-21 Declaration of conformity and CE marking for the monetised distribution. *Requires:* the first paid offer, or the CRA's 2027-12-11 application date for any product Loonaro places on the market, whichever comes first. *Accept:* published with the release.

**Epic LBC-G: agreements**

- LBC-22 Design-partner letter (L-21). *Accept:* the first partner signs.
- LBC-23 OEM agreement template (L-09). *Requires:* the L3 design partner. *Accept:* reviewed by the L3 design partner's counsel.
- LBC-24 Provider agreement template (L-10). *Requires:* an MSP design partner. *Accept:* reviewed by one MSP design partner.

**Epic LBC-H: category and launch**

- LBC-25 Category statement and buyer positioning in launch documentation (with 34). *Accept:* every claim links to a decision and a test or is worded as a target; L-23 cleared for the positioning and comparison pages.
- LBC-26 KuppingerCole AI-VOP questionnaire draft generated from capability records (01). *Accept:* every answer cites a capability id and its prerequisites.

## Risks, open questions and spikes

| Risk | Trigger and response |
|---|---|
| The free hosted tier becomes the cost driver | Free cost per cell above its funded limit for two consecutive months: lower the per-cell cap; never cut receipts or verdicts |
| Prices set before volumes are known | No price is published before LBC-15, which needs S-01's measured p95 day and the conversations |
| No free counsel is available | A register item that blocks a paid offer stays open: nothing paid is offered, and the free product and self-hosting are unaffected. Items are worked in order of what they block, through foundation legal programmes and pro bono clinics first |
| The owner does not pay Apple's fee | macOS ships with Sigstore signatures and provenance, marked not platform-signed and not notarised, at tier 1 only; the release notes and the ceiling matrix say so; no macOS paid support covers tiers 2 or 3 |
| A competitor hosts our server cheaper | Expected under Apache-2.0. The defence is operational: intelligence freshness, the trademark, being upstream (brief 28) |
| The CRA support period forces five concurrent LTS lines | L-05 is answered before any paid LTS offer; the release squad costs the backport matrix before any paid LTS offer; if the cost is unaffordable, lengthen the gap between LTS lines rather than shorten support |

**Open questions, each with what settles it.**

1. Answered by the owner: the product is Guardrails ADR (owner question 4; owner instruction 25). The recorded search (LBC-2) still runs; if it finds a blocking mark, the brand manifest changes the display name and nothing else, and `grdr` stays.
2. The billing unit, if buyers insist on per-user pricing or average well over one persistent endpoint each. Settled by the willingness-to-pay conversations: if at least six of ten buyers ask for per-user, offer per-user as an alternative quote from the same ledger's `users.active` meter. It is shown only as an aggregate count.
3. Platform-key token markup (10% proposed). Settled by measured platform-key token costs over the hosted beta's first month.
4. The live-intelligence price for self-hosters. Settled by the conversations and the first renewal.
5. The CRA class and support period. Settled by L-19 and L-05.
6. Whether Loonaro pays Apple's annual Developer Program fee (spine question 8). Settled by the owner.

## Deviations from the spine and objections

No deviation. Three objections; the second remains open and is followed in the body:

1. **Resolved by owner instruction 25.** D-03 could not be met as written while the product's name contained the house mark, because Loonaro would have had to transfer or licence "Loonaro" itself. "Guardrails ADR" carries no house mark, so the project's marks move under D-03 without it. What remains is the mark's weakness (section 1), which the recorded search states.
2. **D-04 sells "maintenance of LTS lines beyond the public window".** Under CRA Art. 13(8) and Annex I Part II(8), security fixes inside the support period must be free. If counsel sets that period at five years against D-58's 24 public months, the paid offer shrinks to non-security maintenance inside the period and everything after it.
3. **D-65 lists SaaS connectors as table stakes, while their credential halves require the token service.** Resolved by R-39 and spine section 7: the two read-only connectors (Anthropic Compliance API, OpenAI Compliance Logs) require only the integration host and a customer with access to that API; the credential halves of T12 and T16 require the token service (D-27). Launch documentation states which of them a given build contains.

## Sources

**Research briefs:** `28-oss-sustainability.md` (licences, foundations, CRA status, export controls, business models; verification rows 1 to 10, A to C); `34-compliance.md` (CRA dates and classes, AARM, certification roadmap; verification rows 1 to 10); `g10-saas-ops-day2-economics.md` (cost model, metering, Stripe limits, SLA anchors, support; verification rows 1 to 10); `h04-market-news-sweep.md` (price anchors, analyst framing, AARM gate, MDR gap; verification rows 1 to 10, A to C); `h06-standards-regulation-sweep.md` (CRA standards, EO 14434, NCSC; verification row 8); `27-embed-oem.md` (embedding options, licence and embeddability); `06-market-runtime.md` (acquisition churn, pricing opacity); `07-market-identity.md` (paywalled identity features); `01-origin.md` (pricing tiers, sub-processors; verification rows 8 to 10).

**Review notes:** `c6-product-oss-embed.md` (F1 to F4, F8, spike 4); `l05-msp-operator.md` (F3, F9, F10); `l12-completeness.md` (F4, F5); `l09-oss-maintainer.md` (F4, F10); `l02-enterprise-buyer.md` (F8); `l08-oem-edr-vendor.md` (F2, F7, F9); `_review/00-resolution.md`; `_review/02-owner-answers.md`.

**Primary and secondary URLs added here:**

- https://eur-lex.europa.eu/eli/dir/2024/2853/oj (Product Liability Directive; read through search summaries 2026-11-10, including https://www.ibanet.org/European-Product-Liability-Directive-liability-for-software and https://bivdanewsletter.com/?p=21735)
- https://www.reedsmith.com/our-insights/blogs/viewpoints/102k53m/dc-circuit-affirms-ai-cannot-be-author-under-copyright-act/ and https://foleyhoag.com/news-and-insights/publications/alerts-and-updates/2025/march/dc-circuit-holds-that-ai-generated-artwork-is-ineligible-for-copyright-protection/ (Thaler v. Perlmutter, secondary)
- https://www.jdsupra.com/legalnews/supreme-court-denies-review-in-ai-2865518/ (certiorari denied, secondary)
- https://natlawreview.com/article/usco-releases-part-2-its-report-copyright-and-artificial-intelligence (Copyright Office Part 2 report, secondary)
- https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847 (CRA, via briefs 28 and 34)
- https://www.linuxfoundation.org/resources/publications/understanding-us-export-controls-with-open-source-projects (via brief 28)
