# Review l12: completeness against the owner's request

Lens: auditor checking the spine and document list against the owner's request. 2026-11-10.

## Summary

The spine covers the technical core well. Of the 29 request groups below, 13 are covered, 13 are thin and 3 have no decision. It falls short in four places. It was written from the first research round only: `h01` to `h09` (the search-backed round, with the DEF CON and Black Hat catalogue the owner asked for) are never cited, have no index digest, and contradict at least four decisions. "Cannot be an incomplete product" has no definition: two of the five jobs appear in no milestone and nothing traces request items to documents and tests. Deployment on Kubernetes, AWS and GCP has no decision. A dozen things any shipped product needs have neither a decision nor a document. The change that matters most: reconcile the spine with `h01` to `h09` before any design document is written.

## Coverage of the owner's request

| Request item | Status | Spine | Home |
|---|---|---|---|
| Guardrails and policies on agents | Covered | D-08, D-11, D-12 | 12 |
| Beside CrowdStrike and other EDRs | Covered | P12, D-23, D-41 | 11, 26 |
| RFCs, standards, conference talks | Thin | h01, h02, h06 uncited; no standards register | 02, PLAN appendix |
| Teardown of five products and open source | Thin | No decision; h03 and h04 entrants absent (Cortex AES, SentinelOne ADR, OpenShell) | 01 |
| Open source, cross-platform, WESP, drivers | Covered | D-02, D-17 to D-19; P11 exceptions unstated (acceptance repository, held-out corpus) | 08 to 10, 30 |
| Identity, secrets, keys, data control | Covered | D-27, D-28, D-35 | 15, 16, 21 |
| Sustainable, contributor-friendly, modular | Thin | Section 5 is sound; contribution lanes and governance roles absent | 30, 03 |
| Rules, policies, detections | Covered | D-08, D-09, D-29 | 12, 13 |
| Alerts | Thin | Vocabulary only; routing and deduplication undecided | 18 |
| Events, transport, compression, auth, storage, API | Covered | D-06, D-34, D-36, D-38 | 04, 20, 22, 23 |
| Processing | Thin | Targets listed, no pipeline contract | 20 |
| Heuristics | Thin | "Risk" is written and read but never defined | 13 |
| Safety | Thin | Product failure modes yes; safety of our own LLM features no | 19 |
| Bespoke discovery, attribution | Covered | D-24 to D-26, but attribution is in no milestone | 05, 06 |
| Multi-tenant SaaS and self-hosting | Covered | D-33 to D-35; question 3 reopens what the owner settled | 20, 21 |
| Kubernetes, AWS, GCP | Missing | No decision | 24 |
| Integrations, exports | Covered | D-40, D-06 | 25 |
| Imports, data | Thin | Inventory importers only; no tenant export or exit | 25 |
| Embedding and white-label | Covered | D-41 | 26 |
| Rune desktop, Astryx web; simple versus control; solo, IT, MSP | Covered | D-11, D-42 to D-44 | 27, 28 |
| Threat intelligence; AI and ML | Covered | D-32, D-29 | 14, 19 |
| Third parties | Thin | Integrations yes; dependency health and sub-processors no | 30, 29 |
| Security | Thin | Hardening yes; disclosure and own-service response no | new 35 |
| Agent team, roles, structure | Thin | One decision for six documents | team/01, 02 |
| Hooks, plugins, skills, de-slopping, power prompts | Missing | D-47 names none of them | team/03, 04 |
| SOC 2 and standards | Covered | D-46 | 29 |
| Name "Guardrails, by Loonaro" | Thin | `grd` is taken; no clearance step | new 36 |
| Browser and SaaS agents (Sidekick's ground) | Thin | Extension in M4 only | 17 |
| "Cannot be incomplete" | Missing | No definition or traceability | PLAN.md, 33 |

## Findings

### 1. Blocker, wrong: the spine ignores the second research round (status line, D-03, D-17, D-36, D-40, D-46)

**Problem.** No `h` brief is cited; four decisions contradict them.

**Evidence.** `h05` implications 10 ("Do not plan on donating to AAIF first": AAIF declined Microsoft's toolkit and a governance group; nono withdrew on 9 November), 3 (agentgateway and Agent Router "not the enforcement point of record": 7 and 24 advisories), and section 2 (`tough`: three CVEs, no commits since July; `ferrisetw`: none since August 2025). `h02` TL;DR: Dev Drive detaches non-antivirus minifilters. `h06` section 4: NCSC and Five Eyes guides are absent from brief 34. `h04` TL;DR: the AARM label needs five production customers and a certificate.

**Amendment.** D-03: replace "first choice AAIF sandbox" with "foundation chosen at the trigger; engage OWASP (ACS), OpenSSF and CNCF now". D-40: add "agentgateway and Agent Router are integrations; our decision check sits behind them and an evaluation error denies". D-36: add "TUF client behind our own trait, `tough` pinned with a fork plan". D-17: add "ETW behind our own trait; detect Dev Drive volumes and report the coverage loss". D-46: add the NCSC and Five Eyes texts; say "passes the AARM R1 to R9 test set" until the gate is met. Add `h` digests to the index, and require design/02 to carry a talk-to-requirement table from `h01` and `h02`.

### 2. Major, missing: no definition of complete, and two jobs have no milestone (sections 1, 7)

**Problem.** Section 7 never names attribution (D-25, D-26), the detection engine, findings and incidents, the kill switch (D-30), approvals (D-31), receipts (D-39), the API, Terraform provider or MCP server (D-38).

**Evidence.** Section 7 against section 1 jobs 2 and 5; `h04` "Capability checklist" (14 items buyers treat as mandatory).

**Amendment.** Add section 9: "Every decision names its first milestone. PLAN.md holds a matrix of request item, decision, document, milestone and acceptance test; an empty cell blocks the document. A shape is complete at a milestone when all five jobs work in it at the stated assurance level." Add a non-goals list: no IdP, SIEM, central gateway, model-safety product, mobile or ChromeOS sensor.

### 3. Major, missing: no deployment and packaging decision (D-33, D-34)

**Problem.** The owner named Kubernetes, AWS and GCP. D-34 names NATS as an HA dependency, which neither cloud offers as a first-party managed service.

**Evidence.** Brief 25 design implications (strictest-marketplace Helm rules; AWS rejects attestation layers); `h05` implication 11 (unsigned binaries are the most repeated complaint).

**Amendment.** Add D-48: "Server: one image (amd64, arm64) and one Helm chart written to the strictest marketplace rules (digests, no hooks or `lookup`, node sensor and CRDs in separate charts). Terraform modules for AWS and GCP provision managed Postgres and object storage and run NATS in-cluster; Azure follows. Air-gap is a Zarf bundle with a mirrorable TUF repository. Endpoints: signed, notarised MSI, pkg, deb and rpm from the first public build, with an MDM profile generator."

### 4. Major, missing: product topics with no decision and no document

**Problem.** Not in the spine or the list: user and administrator documentation; support tiers and support bundle; version and LTS lifecycle (the CRA support period); terms, DPA and sub-processor list; trademark policy; export controls and sanctions for the hosted service; PSIRT, disclosure channel and penetration tests; incident response for our own service; pricing; product telemetry; internationalisation and a desktop accessibility target; design partners; community management; uninstall and offboarding.

**Evidence.** Brief 28 sections 9 and 11, verifier row A (curl left GitHub reporting); g10 section 7; brief 33 "Accessibility and internationalisation"; `h04` implications 6 and 10 ("no telemetry by default", public prices); `h03` implication 10.

**Amendment.** Add documents 34 (documentation, support, lifecycle), 35 (product security programme) and 36 (legal, brand, commercial). Add D-49: "The product sends nothing to Loonaro by default in any shape. Update checks are anonymous fetches. Crash reports, reciprocity sharing and shadow backtests are separate opt-ins with a published schema." Add to D-42 and D-43: "Strings live in catalogues from the first commit; a pseudo-locale and right-to-left run are in CI; desktop meets the same WCAG target through AccessKit."

### 5. Major, wrong: `grd` is already someone else's command (section 3)

**Evidence.** crates.io today: `grd` 0.13.0, updated 2026-10-22, "a command-line tool to download and install binaries from GitHub releases". `cargo install grd` installs that tool. `grd` and `guardrails` also exist on npm and PyPI.

**Amendment.** Section 3: "The CLI name and crate prefix are fixed in M0 by a recorded search of crates.io, npm, PyPI, Homebrew, winget, Debian, Docker Hub and GitHub, and reserved the same day. `grd` is unavailable."

### 6. Major, missing: browser and SaaS-hosted agents (section 1, D-13)

**Problem.** Section 1 promises discovery in "browsers and SaaS"; Sidekick is a named teardown target; D-13 says five control points while section 3 lists eight. The extension is an M4 line item.

**Evidence.** Brief 05 design implications (tenant-restriction headers without TLS interception); g09 verifier (WebKit opposes WebMCP).

**Amendment.** D-13: "Eight control points: five on the device, plus `browser`, `gateway` and `connector`." Add D-13a: "One Manifest V3 extension paired with the daemon over native messaging, Chromium only; the first pack is tenant-restriction headers and generated Chrome and Edge policy; M2. SaaS-hosted agents are reached through connectors and never exceed AL1."

### 7. Major, missing: the agent-team decision omits what the owner listed (D-47)

**Evidence.** Brief 32 digest (48 prompts, refuting verifier; desloppify, Trail of Bits skills and Serena carry non-permissive licences); `h09` TL;DR (discover, prove, repair; three-round review cap).

**Amendment.** Add D-47a: "Power prompts are versioned skills in the repository, each with a trigger (every change, or nightly on a rotating crate), one concept, a refuting verifier, and closure only by a type, test or lint. Review is capped at three rounds on the diff. A scheduled gardener removes slop under ratchets. Third-party skills and plugins are pinned, never vendored, and run under Guardrails."

### 8. Major, missing: tenant portability and exit (D-34, D-35)

**Evidence.** `h04` checklist item 13 ("full export and deletion on exit").

**Amendment.** Add D-50: "An organisation owner can export and delete everything without operator help: the Parquet lake, a documented relational dump, policy as git, and the audit log with its verification material. `org export` and `org import` move an organisation between hosted and self-hosted; devices re-enrol by signed redirect; deletion returns a signed receipt."

### 9. Minor, missing: overlapping documents need owners

**Amendment.** State in PLAN.md: updates (11 on-device mechanics, 22 protocol and rings, 24 build, signing, packaging); keys (15 credentials released to agents, 21 tenant and device keys, 16 detection and redaction); MCP (07 verdict interface, 17 broker, 23 our own server); packs (22 format and signing, 13 authoring lifecycle); privacy (29 owns capture levels); lab (31 hardware and corpus, team/05 gates). Rename 32 to "Operations: hosted service, self-hosted day-2, economics".

### 10. Minor, missing: processing, heuristics and alert routing

**Evidence.** g10 implications ("never drop verdicts, detections or audit records"); g06 ("evidence arrays instead of one opaque score").

**Amendment.** D-33: "Pipeline contract: at-least-once, idempotent on device, boot and sequence, ordered per session, with a stated lateness window and quotas that sample raw events only." D-09: "Risk is a bounded per-session integer built from named contributions; policies compare it to pack thresholds." D-30: "Notification routing is policy, deduplicated per incident."

## Spikes

| Question | Method | Pass |
|---|---|---|
| Does the spine survive `h01` to `h09`? | One reader per brief marks each implication agrees, contradicts or absent | No unresolved contradiction; every absent item has a home |
| Is the plan complete? | Build the traceability matrix from finding 2 | No empty cell |
| Which CLI name is free? | Script the eight registry lookups for five candidates | One free everywhere, reserved |
| Does D-48 hold? | Lint the chart against EKS add-on rules; install on kind with in-cluster NATS | Lint clean; first event within 30 minutes, no manual edits |

## Agreed

- D-01: three shapes match the solo, enterprise, MSP and embedding asks.
- D-02: Apache-2.0 with DCO is what "fully open source" and embedding both need.
- D-17: honest about WESP; `h02` confirms it still has no blocking path.
- D-24: bespoke discovery is the first mandatory buyer item (`h04`, `h08`).
- D-41: the ladder answers "package, event provider or otherwise".
- D-42 and D-43: Astryx and Rune are adopted as asked, with exits.
- D-46: the SOC 2 sequence fits the AARM gate.
- Section 3: one vocabulary is the right control for thirty authors.
