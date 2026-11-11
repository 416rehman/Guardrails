# Review L09: open-source maintainer and foundation incubation lens

Scope: the whole spine, read as a maintainer deciding whether to contribute and as a foundation reviewer doing due diligence. Briefs: 28, 31, 32, g06, plus h05 and h09. Checked at source today: the AAIF proposal threads for nono (#61) and the Agent Governance Toolkit (#19), and the CNCF licence-exception register.

## Summary

The licence choice holds. The project around it does not yet exist: the spine has no governance decision, no contribution policy, no security-response decision, and its merge gate depends on a repository outsiders cannot see. As written, a reviewer would describe this as a single-vendor, single-human project whose code lane is closed and whose maintainers are a model bill. I concur with C6 findings 1 to 3 (coined project name, D-02 revisit clause, D-04 selling what the covenant gives away) and C9 F8 (DCO mechanism) and do not repeat them. The one change that matters most: add a governance and contribution decision that binds the steward's agents and outside humans to the same public rules and the same public gate.

## Findings

### 1. No governance decision exists (missing; D-47, D-03). Blocker

**Problem.** D-47 says the project is "governed by the repository". That describes the steward's agents, not decision rights. Nothing says who may merge, who can amend this spine, how a human becomes a maintainer, or whether an agent identity can hold a vote. Brief 28's day-one commitment 6 was dropped.

**Evidence.** Brief 28 "Day-one public commitments" item 6. Brief h05 section 3: the AAIF Technical Committee declined Microsoft's toolkit as "hard to govern" and "vibe coded". Brief 28 section 5: OpenSSF Incubating needs three maintainers from two organisations.

**Amendment.** Add D-48: "`GOVERNANCE.md` and `MAINTAINERS.md` (with affiliations) exist at the first public commit. Agents are tools: no agent identity holds merge rights, a CODEOWNERS entry or a vote. Each layer and platform has a named human maintainer. Changes to this spine, public crates, wire formats and the Cedar schema go through a public RFC with a 14-day comment period. A steering group of five forms at the second external maintainer; the steward holds at most two seats."

### 2. The merge gate is a private repository (wrong; section 5, D-45, P11). Major

**Problem.** "A restricted acceptance repository behind an evaluator service" means an outside pull request can fail a test its author cannot read or run, and a fork cannot reproduce the gate. It is also an unlisted asset in D-03.

**Evidence.** Brief 32 "CI quality-gate specification" ("only pass/fail returned"). P11 "Everything is open".

**Amendment.** Section 5: "The pull-request gate is the public `verify` only. The held-out suite gates releases and agent work items. It is Apache-2.0, readable by every human maintainer regardless of employer, and each set is published two releases after use and replaced. When it fails an external change, a maintainer posts a public reproducer within five working days." Lost: some protection against test fitting at merge time.

### 3. No contribution or AI-assistance policy, and a double standard (missing; D-47, section 5). Major

**Problem.** The spine names "the open contribution lane" once. The steward's agents merge at machine speed; brief 28 would gate outside code behind an accepted specification and a vouch list. Content promotion in brief g06 needs two domain CODEOWNERS and a third for block rules; the project has one human.

**Evidence.** Brief 28 "Contribution model" and section 6. Brief g06 "Contribution workflow" and weak points (poisoned rules and corpus samples).

**Amendment.** Add D-49: "One rule set for everyone. Every code change, agent or human, links an accepted work item, carries `Assisted-by`, the evidence template and a human sign-off under C9 F8. External AI-assisted changes are accepted on the same terms. The vouch list is public with a stated path. Content needs two human approvals from two people; until two exist, no community rule exceeds `action_ceiling: audit`."

### 4. The covenant omits the assets that control users (missing; D-03, D-36, D-17, D-18). Major

**Problem.** D-03 transfers trademark, domain and GitHub organisation. Whoever holds the TUF root, the default update endpoint, the content-signing keys, the Apple Team ID and the Windows signing identity controls every installed sensor. The last two cannot move to a foundation at all.

**Evidence.** D-36 ("offline root keys"), D-18 (entitlement "bound to one Team ID"), D-17. Brief 28 section 4 (NATS: assets, not licence, decided the dispute).

**Amendment.** D-03 adds: "Covenant assets also include the TUF root, content and release signing keys, default update and intelligence endpoints (on the project domain), the conformance registry and held-out corpora. The TUF root is a threshold with at least two non-steward holders by general availability. Releases are reproducible. The steward commits to sign project releases with its Apple and Microsoft identities for as long as it holds them."

### 5. AAIF as first choice is contradicted by the follow-up research (wrong; D-03). Major

**Problem.** D-03 cites only brief 28. Brief h05, dated the same day, says not to plan on AAIF first.

**Evidence.** Brief h05 TL;DR and implication 10. Confirmed today: proposal #19 closed 2026-06-29; on #61 the nono maintainer withdrew on 2026-11-09 citing non-transparent committee and board process. The CNCF Governing Board has a blanket exception (2023-08-31) for dual-licensed in-kernel eBPF, which answers brief 28's open question for CNCF only.

**Amendment.** Replace "(first choice AAIF sandbox)" with: "Foundation chosen by M2 after pre-read meetings. Preference: CNCF Sandbox (Falco, Tetragon and Cedar precedent), then OpenSSF with the AI/ML working group as sponsor; AAIF only once it has accepted a security project and publishes its decisions. Contribute hook-standard conformance evidence to OWASP regardless."

### 6. P6 forbids what section 5 invites, and the layer rule is already broken (wrong; P6, section 5). Major

**Problem.** P6 allows "exactly two supported adapters" per port. Section 5 lists store, bus and sandbox adapters and judge back ends as contributor extension points. A contributor's third adapter has no home, owner or support status. "Adapters do not depend on each other" is violated by the list itself: `grd-proxy` needs `grd-llm-proto` and `grd-mcp`; `grd-wire` and `grd-update` need `grd-crypto`.

**Evidence.** Spine section 2 against section 5.

**Amendment.** P6: "Two core adapters per port gate releases. Community adapters live in `guardrails-contrib` with a named owner, must pass the published port test kit, never gate a release, and are removed after two red releases." Section 5: split layer 3 into 3a shared libraries (`grd-crypto`, `grd-wire`, `grd-llm-proto`, `grd-mcp`) and 3b adapters, which may depend on 3a only. Add `grd-ports-testkit`.

### 7. One repository for forty crates, a driver, a web app and SDKs (risky; section 5). Major

**Problem.** A newcomer's clone needs a driver kit, Xcode, a BPF toolchain, Node and a GPU framework. Embedders at rung L3 pin a commit of everything. Agent exec plans and decision logs will bury human documentation. The strongest alternative is a separate `guardrails-core` (schema, core, C ABI, WASM, conformance vectors), which is also the unit a foundation would take first.

**Evidence.** Brief h05 section 3 ("too much in one repository"; the policy core "worth standing alone"). Brief 27 (YARA-X packaging). Brief 31 section 3 favours one repository for agents.

**Amendment.** Keep one repository but fix the seams now: "Layers 0 to 2 plus `grd-ffi` and `grd-wasm` are the public crates: published, semver-checked, changed by RFC. Everything else is `publish = false`. Workspace default members build and test on stable Rust with no kernel, Swift, Node or GPU toolchain. Agent artefacts live under `docs/agents/`. Split the core out at the first external embedder or foundation application." Spike S1 settles it.

### 8. No security-response decision (missing; D-47, D-04). Major

**Problem.** D-47 lists "disclosure handling" as a human duty and stops. No intake channel, CNA, supported lines or embargo criteria. Reports are untrusted text that must not reach agents holding write access, and embargoed fixes should not be written in shared agent sessions.

**Evidence.** Brief 28 verifier row A (curl left GitHub private reporting in March 2026) and section 9. Brief 31 weak points (injection through issue text). Brief h05: 27 NATS and 38 OpenBao advisories in 2026 flow downstream to us.

**Amendment.** Add D-50: "`SECURITY.md` at first commit: private intake triaged by a human, reproducer required, no bounty. GitHub as CNA at first. Fixes are developed in a private fork by isolated agents with no network tools. Pre-disclosure goes free to any redistributor meeting published criteria. Supported: current and previous minor, plus one LTS a year. Seven-day patch target for bundled dependencies."

### 9. The maintainer base is a model bill (risky; D-47, D-04). Major

**Problem.** One human, agents on paid API time, revenue no earlier than M3. If spending stops, nobody has read the code. Harness parts last months and some are account-bound previews.

**Evidence.** Brief 31 weak points ("We have one"; harness half-life) and section 7 (about $20,000 per 100,000 lines). Brief h09 matrix (scheduled tasks run under the owner's identity). Brief 28 section 8 (donations negligible).

**Amendment.** D-47 adds: "The agent kit is part of the open project and harness-neutral: a second harness lands a canary work item monthly in CI. Public maintenance uses no account-bound feature. Each public crate has a human-reviewed design document. Maintenance cost per release is published. A second human maintainer from another organisation is a precondition for any foundation application."

### 10. Licence details in D-02 (wrong; D-02, D-32). Minor

**Problem and evidence.** (a) Docs under CC-BY-4.0 alone break "OSI licences forever"; brief 28's matrix says `Apache-2.0 OR CC-BY-4.0`. (b) "Embedders owe no attribution" is false under Apache-2.0 section 4; the point is no attribution in match views. (c) D-32 seeds from the GitHub Advisory Database, which is CC-BY-4.0 (brief g06 matrix), so intelligence records cannot all be Apache-2.0. (d) Brief h05 implication 2: vendor only `rsigma-parser` and `rsigma-eval`.

**Amendment.** D-02: "Docs `Apache-2.0 OR CC-BY-4.0`. Content carries no in-product attribution duty. Our own intelligence records are Apache-2.0; imported records stay in a separate mirror under their source licence. One root `LICENSE`; SPDX headers per file. Development-only tools under share-alike or custom licences are installed, never vendored."

## Spikes

| # | Question | Method | Pass criteria |
|---|---|---|---|
| S1 | Can an outsider build and change the core? | A person outside the team clones on clean hosted Windows, macOS and Linux runners, follows `CONTRIBUTING.md`, and lands a small fix in a layer-1 crate. | First green `verify` in under 15 minutes per system with only stable Rust; fix merged without private help. |
| S2 | Can someone else run the agent kit? | An outside engineer with their own model key and a second harness completes one medium work item from the public repository alone. | Merged within one day; cost recorded; no step needs the steward's accounts or the private repository. |
| S3 | Will a foundation take it as designed? | Send a two-page thesis with D-48, D-49, the asset list and the agent-authorship model to CNCF TAG Security, the OpenSSF AI/ML group and one AAIF committee member; add counsel's note on sign-off for agent-written code. | Written feedback from two; no objection that needs a licence or structure change. |
| S4 | Does the rotating held-out suite still catch fitting? | Run ten agent work items against the public gate only, then score against the held-out set. | Gap under five points; otherwise keep the held-out gate on agent items and tighten rotation. |

## Agreed

- Apache-2.0 for code, server and content, with DCO and no CLA (brief 28 sections 2 and 3).
- Kernel programs dual-licensed in their own crate; CNCF's exception covers it.
- No DRL or ELv2 rule content in the default pack (brief g06 verifier row 6).
- A separate, signed content repository with maturity tiers as the open lane.
- P7 and D-37: content validated by the shipping interpreter and released through rings.
- "The repository is the only memory" (D-47): it is what makes a fork viable.
