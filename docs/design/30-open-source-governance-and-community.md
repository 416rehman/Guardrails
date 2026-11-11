# 30. Open-source governance and community

_Status: draft 5 (spine v4, rulings R-43, R-49, R-57, R-58 and `_review/02-owner-answers.md` applied, then the owner's kit instructions in `_review/04-owner-kit-instructions.md`: 3, 5, 6, 7, 20, 22, 23, 25, 27 and 28 change this document, and instruction 7 supersedes R-49's human release manager and R-58's human content approvals). Owning squad: Direction group (`chief-architect`, `team/02` section 3; agents draft and decide, with no human gate). Read with: `00-decisions.md` (spine v4, authoritative; section 7 for prerequisites), 02 (threat model: TB-11, ADV-9, SD-05, SD-06, SD-13), 03 (layers, public crates, repository layout, stability classes), 13 (content maturity, approvals, contribution workflow), 22 (trust roots and ceremonies), 24 (build, signing, reproducibility), 26 (embedding options and host contract), 33 (build order), 34 (release lines and support windows, support statement), 35 (security programme, `SECURITY.md`), 36 (legal, brand, trademark policy, commercial terms), `team/01` (operating model), `team/03` (fleet egress proxy), `team/05` (quality gates and merge queue)._

## Summary

This document turns D-02 (licence), D-03 (neutral ownership) and D-61 (governance and contribution) into files, CI checks and procedures. It also fixes the release and support policy that governance commits to, the conformance-mark programme, community health metrics and the launch of the public project. Key choices:

1. **One root `LICENSE` (Apache-2.0) per repository**, SPDX headers on every file, with the collective notice "The <Project> Authors" (contributors keep their copyright). Other licence texts live only beside the code they cover, so GitHub's licence detection reports `Apache-2.0` for every repository.
2. **A machine-readable do-not-read list** (`supply-chain/do-not-read.toml`) that the fleet's egress and token proxy enforces by host and path, and that binds humans by policy: agents never fetch listed copyleft or source-available sources; humans may read but never copy or paraphrase.
3. **No DCO, no sign-off, no commit trailers** (owner instructions 7 and 27). Every commit is one Conventional Commit line. The pull request carries `Closes #<n>` and a metadata block naming the harness, the model that wrote the change and the attempt. Contributions are received under Apache-2.0 section 5, as `CONTRIBUTING.md` states, and the merge queue lands a pull request on deterministic gates and the evaluators its tier requires.
4. **One rule set for everyone** (`AI_POLICY.md`): accepted work item, the metadata block (harness and model, or `none`), evidence template, the same gates. The merge queue lands every change, so no identity holds a merge right; an evaluator's check run counts only from an agent that did not write the change; agents hold no code-owner entry and no steering vote, and CI rejects any bot in `MAINTAINERS.md` or `CODEOWNERS`.
5. **The covenant is a separate file (`COVENANT.md`) that no governance body can weaken.** It lists every asset that controls installed sensors, the transfer trigger with measurable definitions, and a fallback if no foundation accepts in time.
6. **Two lanes.** Content (content repository) is open to anyone, gated by fixtures, the benign corpus and evaluators: `eval-acceptance`, `eval-adversarial` and `eval-licence` pass every rule, and a community rule needs those passes from two evaluators on different models (13 section 17; owner instruction 7, replacing R-58's human approvals). It enters in Watch; outside content merges once `grdr content test` and the contributor guides exist. Code needs an accepted work item; an unvouched contributor's pull request without one is closed automatically.
7. **The pull-request gate is public `verify` only.** The held-out suite scores every merged change on `main` nightly regardless of origin, and additionally gates the steward's agent work items before merge. A held-out failure attributed to an outside change gets a public reproducer.
8. **Releases** follow 34 section 9: one product bundle version over separately versioned components (owner instructions 3 and 17), `0.x` until the `v1` freeze; from 1.0 the supported lines are the current minor, the two before it and the live LTS (first LTS the first minor at least 90 days after 1.0, then every twelfth, 24 months of public security fixes; D-58, R-43). release-please opens each release pull request, the merge queue lands it and release-please creates the tags; artefacts are signed keylessly through GitHub's OIDC identity, so no person cuts or signs a release (owner instruction 7, replacing R-49's human release manager). Security fixes are never paid.
9. **Conformance marks belong to the project and move with it under D-03.** A listing needs public, reproducible evidence in the conformance registry and the D-51 privacy floor. Loonaro sells test runs, never the mark.
10. **Health metrics are aggregate and public**, and include the two transfer-trigger counters, so anyone can see when D-03 fires.

## Requirements

| # | Requirement | Trace |
|---|---|---|
| R1 | Every component is under an OSI-approved licence: Apache-2.0 code and content, `GPL-2.0-only OR BSD-2-Clause` eBPF programs, `Apache-2.0 OR CC-BY-4.0` docs | D-02, P11; owner: "fully open source"; brief 28 |
| R2 | An embedder's licence scanner detects each repository's licence without manual review | D-02; brief 28 section 1 (mixed repositories report `NOASSERTION`) |
| R3 | No code or content enters the project that carries a copyleft, source-available or attribution-in-UI obligation, except unmodified MPL-2.0 dependencies outside the embeddable closure and imported intelligence kept under its source licence in a separate tree | D-02 do-not-read list; briefs 28, g06 (DRL 1.1, ELv2; malcontent third-party rules); l09 F10 |
| R4 | Every commit on a default branch is one Conventional Commit line with no trailer, and every pull request names its work item and the harness and model that wrote it; there is no DCO check | Owner instructions 7 and 27; D-61; brief 28 section 3 (only humans certify the DCO); c9 F8 |
| R5 | Steward agents and outside contributors follow the same contribution rules and the same public gate | D-61, D-45; l09 F2, F3 |
| R6 | The merge queue lands every change, so no identity holds a merge right; no evaluator judges a change it wrote; no agent holds a code-owner entry or a steering vote | D-61; owner instruction 7; h09 (self-approval never counts) |
| R7 | Changes to the spine, public crates, wire formats and the Cedar schema pass a public RFC, reviewed by the persona council and `eval-architecture` and decided by the chief architect, with no waiting period | D-61; owner instruction 7; 03 section 7 |
| R8 | The covenant names every asset that controls installed sensors and a measurable transfer trigger | D-03; l09 F4; brief 28 section 4 (NATS) |
| R9 | The foundation is chosen after pre-read meetings, before the transfer trigger fires; CNCF first, OpenSSF second, AAIF conditional | D-03; brief h05 sections 1 and 4 |
| R10 | A stranger builds and changes the core with stable Rust only and gets a green `verify` in under 15 minutes (target) | Spine section 5, S-22; l09 F7 |
| R11 | Releases are reproducible, signed, under the source licence, with no usage thresholds | D-03, D-46; brief 28 day-one commitment 4 |
| R12 | Conformance marks require passing published kits and the privacy floor | D-60, D-51; brief 27 (marks are trademark policy) |
| R13 | Public maintenance can continue without any one person's account and never depends on a closed feature: the repository and its issues hold all state and the agent kit is harness-neutral, so people or another harness can carry on if access to the owner's Claude subscription is lost | D-47, D-61 (agent kit harness-neutral); spine section 9 ("Automation is bound to one account"); l09 F9; h09 (scheduled tasks act as the owner) |
| R14 | Contribution text is untrusted input to development agents | 02 ADV-9, SD-06; brief 31 weak points |

## Design

### 1. Licence mechanics (D-02)

**Matrix.**

| Path | Licence (SPDX) | Licence file |
|---|---|---|
| Main repository, all code except below | `Apache-2.0` | Root `LICENSE` |
| `bpf/` (the eBPF crate) | `GPL-2.0-only OR BSD-2-Clause` | `bpf/LICENSE-GPL-2.0`, `bpf/LICENSE-BSD-2-Clause`, `bpf/README.md` explaining the dual licence |
| `docs/`, `rfcs/`, `spec/` prose | `Apache-2.0 OR CC-BY-4.0` | `docs/LICENSE-CC-BY-4.0` (Apache text is the root file) |
| Content repository (packs, fingerprints, corpora we author, mappings) | `Apache-2.0` | Root `LICENSE`; no `NOTICE` file |
| Content repository, imported intelligence (`intel/mirror/<source>/`) | The source's licence, recorded per source at import (GHSA is `CC-BY-4.0`; OpenSSF malicious-packages is `Apache-2.0`; g06) | `intel/mirror/<source>/LICENSE` |
| Contrib repository | `Apache-2.0` | Root `LICENSE` |
| Held-out suite | `Apache-2.0`, private until published two releases after use | Root `LICENSE` |
| Model weights we train (D-29) | `Apache-2.0`, with training code and data description | As code |
| Names, logos, conformance marks | Not licensed; trademark policy (36) | `TRADEMARKS.md` |

Why one root file: GitHub reported `NOASSERTION` for every mixed-licence repository brief 28 checked; single-licence repositories detected cleanly, and embedders' scanners read the same signal. Second-licence texts therefore never sit at a repository root. Imported intelligence stays in a separate mirror tree so that our own records remain Apache-2.0 and the CC-BY-4.0 obligation travels only with GHSA-derived records (l09 F10).

**Headers.** Every source file starts with two lines in its comment syntax:

```
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: The <Project> Authors
```

`<Project>` is the D-66 name, substituted from the brand manifest when the file is generated. Generated files carry the header of their generator's input. Data files that cannot hold comments (JSON fixtures) are covered by a `.license` sidecar or by a path rule in `supply-chain/licences.toml`. `cargo xtask licence-lint` fails on a missing or unlisted identifier, and on any `GPL` identifier outside `bpf/`.

**NOTICE.** The main repository's `NOTICE` holds one copyright line plus the notices that vendored third-party code under `third_party/` requires, nothing else, so redistributors carry the minimum Apache-2.0 section 4(d) burden. The content repository has no `NOTICE`; rule authorship is metadata (`provenance.authors`) and never a display duty, which keeps white-label builds free of attribution-in-UI (brief 27; DRL 1.1 is the counter-example). Apache-2.0 still requires a copy of the licence and retained notices in source form; "no attribution duty" in D-02 means no attribution in the product's interface (l09 F10).

**Third-party policy.** `supply-chain/licences.toml` is the allow-list read by `cargo deny`, the npm and Python licence checks, and the vendoring check:

| Class | Licences | Where allowed |
|---|---|---|
| Permissive | `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`, `CC0-1.0` (data) | Everywhere, including the `embedded` build closure (c6 F4) |
| Weak copyleft | `MPL-2.0` | Unmodified, as a dependency of layer 3 and 4 programs only; never in layers 0 to 2, `grdr-ffi`, `grdr-wasm` or the `embedded` closure |
| Kernel | `GPL-2.0-only` | Only kernel interfaces consumed by `bpf/`; no kernel source copied |
| Data with attribution | `CC-BY-4.0` | Only in `intel/mirror/` and documentation |
| Banned from linking or vendoring | `GPL-*` (outside `bpf/`), `LGPL-*`, `AGPL-*`, `SSPL-1.0`, `BUSL-1.1`, `Elastic-2.0`, `FSL-*`, `DRL-1.0`, `DRL-1.1`, `CC-BY-SA-*`, `CC-BY-NC-*`, no licence | Development tools under these licences may be installed, never vendored, linked or redistributed |
| Aggregated in the air-gap bundle | Any licence that allows redistribution, copyleft included | Only as separate programs, images and packages in the bundle, each copyleft one with its source in `sources/`; never linked into or vendored by our code |

A new licence on the allow-list or a vendored file changes `supply-chain/`, which is gate configuration and a trust-core path (D-63; 03 section 11; `team/05` owns the check). That is a protected change: its own work item, implemented by `lead-agent-kit`, landed after `eval-licence`, `eval-security` and one more evaluator on the other model pass (owner instruction 7). A new dependency inside the policy is high tier (35 section 2.6) and `eval-licence` checks it. Development tools under banned licences, such as the CC-BY-SA-4.0 `trailofbits/skills` that the fleet installs unmodified through its private marketplace (h09), are pinned by commit and never vendored, edited or paraphrased; whether installing them creates any obligation for our repository is an open question for counsel (h09).

**The air-gap bundle.** One bundle carries everything every profile needs, third-party images, charts, binaries and packages included, so nothing is fetched on a connected host (owner instruction 20; 24 section 7). This policy decides what may enter it. A component is bundled only if its licence allows redistribution. Each copyleft component travels with its complete corresponding source and our patches in `sources/`, which meets the GPL's route of accompanying the binary with source and needs no written offer. The third-party images are ones we build from source on a minimal base, reproducible, signed and with SBOM and provenance, so their contents and licences are known; a generated `THIRD-PARTY-NOTICES` file and the CycloneDX SBOM list every component, its licence and its source (36 section 6). A component whose terms forbid redistribution cannot become redistributable by a customer accepting terms: it is replaced by a redistributable equivalent or stays optional, and nothing needed to install, enrol, update, detect, respond or operate depends on it. The FIDO Metadata Service BLOB is the one known case (its current terms to be confirmed); the bundle carries a curated authenticator list built from redistributable sources instead (21). The supply-chain gate checks every bundled component against this rule. The operator accepts the terms at import, on one screen that groups the bundled licences (24 section 7).

**Do-not-read list.** `supply-chain/do-not-read.toml` lists sources whose text must not flow into our code or content, with scope `all` or `content`:

| Entry | Licence | Scope | Reason |
|---|---|---|---|
| `elastic/detection-rules`, `elastic/protections-artifacts` | ELv2 | all | Not open source; hosted use forbidden; re-derive behaviour from incidents instead (g06) |
| `SigmaHQ/sigma` rule trees | DRL 1.1 | content | Attribution in match views; the Sigma specification (public domain) remains readable |
| `chainguard-dev/malcontent/third_party/` | mixed, includes ELv2 and unlicensed | content | g06 verification row 6 |
| `wazuh/wazuh` | GPL-2.0 (4.x releases); `src/engine/` AGPL-3.0-or-later on `main` and the 5.0 release candidates | all | Copyleft engine in our domain (27 verification row 9) |
| ClamAV, Suricata sources | GPL-2.0 | all | Same functional space as our engines (27) |
| `halofyai/halofy` | AGPL-3.0-or-later | all | Agent governance layer (h04, h05) |
| `hardenrun/aif`, `securetron-gh/aifw` | proprietary or none | all | No usable licence (h04, h05) |
| `openai/tart` | FSL-1.1-ALv2 | all | Source-available (31 verification); lab hosts may run its release binaries, agents never fetch its source |

Enforcement differs by actor because the risk differs. Agents can reproduce text verbatim, so the fleet's egress and token proxy (`team/03`), which already terminates every GitHub and registry request, refuses requests whose host and path prefix match an entry (repository, raw, archive and API paths; registry package names) and logs each attempt as a finding against the work item. The proxy cannot remove text a model learned in training; the contribution statement in `AI_POLICY.md`, review and the snippet-match scan (36 L-14) cover that residue. Humans may read listed sources to understand a technique, but must not copy, translate or paraphrase code or rule logic; `CONTRIBUTING.md` says so and the PR template asks. Adding an entry is a normal pull request; removing one is an RFC.

### 2. Commits, landing and provenance (D-61; owner instructions 7 and 27)

Only humans can certify the DCO (brief 28 section 3, verification row 7), and no step of this project needs a person (owner instruction 7), so the project has no DCO and no sign-off. Provenance comes from the record every pull request carries; landing comes from deterministic gates and evaluators that did not write the change.

1. **Workers** commit on `agent/<n>/a<attempt>` branches under the owner's `gh` login, with each role's `gh` calls limited by `guard-command` (owner instructions 5, 6 and 23). Every commit message is one line: a Conventional Commit subject, `type(scope): summary`, with a lower-case type from the allowed list and at most 72 characters, and with no body and no trailer (no `Co-Authored-By` or `Signed-off-by` either). `guard-command` refuses any other message and gate V24 checks every commit on the branch.
2. **The pull request** title is a valid subject. Its body carries `Closes #<issue>`, so GitHub links and closes the work item, and a collapsed metadata block with the harness, the model id that wrote the change and the attempt, which the review pass reads to pick the other model; the `handoff.v1` comment repeats them.
3. **Evaluators** are set by the risk tier and the lane `cargo xtask risk` computes (35 section 2.2; owner instruction 8): deterministic proofs only in the `static` lane, one `eval-diff` pass in `light`, the tier's evaluators in `standard`, and in `full` (high tier and trust core) `eval-security` and `eval-adversarial` in clean contexts plus cross-model review by the model that did not write the change. A trust-core change needs two independent passing evaluators on different models (D-63). An evaluator's check run counts only from an agent that did not write the change.
4. **The merge queue** (`cargo xtask queue`, deterministic software, `team/05`) squash-merges a pull request once verify is green on the rebased head, CI is green where it runs, every evaluator the tier requires has passed, at most three review rounds were used and the branch is current. The squash commit is the pull-request title plus ` (#<pr>)`, the form release-please reads; it copies neither the pull-request body nor the branch's messages. The merge closes the issue.
5. **The record.** The squash commit, the pull request with its metadata block and check runs, and the issue's lease and hand-off comments are the provenance of every change on `main`. The queue refuses a pull request whose title is not a valid subject or whose body lacks `Closes #<n>` for a work item.

Outside contributors follow the same form, and their commits need no sign-off. A contribution is submitted under Apache-2.0 section 5, as `CONTRIBUTING.md` says (36 L-12). The first public release requires counsel's opinion on copyright in agent-written code and on the inbound terms (c9 F8; 36 owns it); with no budget, free legal help for open-source projects (foundation legal programmes) is the first route. The working assumption, to be confirmed by that opinion, is that where agent output carries no copyright the Apache-2.0 grant still covers every copyrightable part and the header stays accurate.

When our people contribute upstream, they follow the upstream's rule, not ours: Kubernetes does not allow `assisted-by`, `co-developed` or similar trailers (brief 28 verification row 7), and the kernel dropped the `Assisted-by` tag on 2026-10-13 (h09 verification row 10). An agent never opens an upstream pull request; a human is the author of record.

### 3. Governance

**Roles and decision rights.**

| Role | Who | Rights | Added by |
|---|---|---|---|
| Steward | Loonaro (the legal entity, D-03) | Holds covenant assets and accounts until transfer; has no budget, so infrastructure is free hosted services for public repositories and the owner's and buddy's own machines (D-64). Its release pipeline signs every artefact keylessly with Sigstore through GitHub's OIDC identity, so no person holds a key; platform signatures are added where a vendor programme exists: Windows user-mode binaries through a free open-source signing programme (for example SignPath Foundation), macOS binaries only with Apple's Developer Program (spine question 8). An artefact without one ships marked "not platform-signed" in the release manifest (D-18; owner instruction 23) | Covenant |
| Owner | One named human from the steward | Sets direction through written instructions (`_review/04-owner-kit-instructions.md`) and answers the spine's open questions; decides the foundation application and the transfer date until the steering group forms (spine question 5). Holds no gate in building, reviewing, landing or releasing (owner instruction 7) | Steward |
| Second maintainer | The owner's buddy | A maintainer for every area; holds the owner's account-level duties (the repository's settings under the owner's account, the covenant assets) if the owner is absent, as the covenant's succession clause states (R-57) | Owner, recorded in `MAINTAINERS.md` |
| Chief architect | The `chief-architect` agent (`team/02`) | Owns the decision spine; accepts, rejects or postpones RFCs after the persona council and `eval-architecture` review them, with written reasons (owner instruction 7) | The roster |
| Release manager | `lead-release`, an agent, per release line | Keeps the release pull request and `release/checklist.toml` green and owns backports and the support statement for the line; release-please creates the tags and the merge queue lands the release pull request (owner instruction 7, replacing R-49's human role) | The roster |
| Maintainer | Human, per area in `MAINTAINERS.md`, affiliation recorded | Code-owner entry for the area, which requests their review and never requires it; vote on maintainer additions; RFC shepherd | Section 4 ladder |
| Trust-core maintainer | Maintainer named for paths in `security/trust-core.paths` | Reviews changes on those paths when available; the review adds evidence and never gates (owner instruction 7) | Steering vote after 10 shadowed trust-core reviews |
| Content reviewer | Human, per content domain; a volunteer or maintainer | Reviews content in the domain when available; the review adds evidence, and the content lane's gates are section 4's | Section 4 ladder |
| Contributor | Anyone who follows `CONTRIBUTING.md` | Open issues, RFCs and pull requests | Nobody: open to anyone |
| Agent | A roster agent (`team/02`), launched by the dispatcher | Files, readies and implements work-item issues, reviews as an evaluator and drafts RFCs (owner instructions 6 and 7); never merges (the queue does), never evaluates its own change, never holds a code-owner entry or a steering vote | The roster |

**Steering group.** Forms when the second external maintainer is added (D-61). Seats: every maintainer up to five; above five, annual election by maintainers, one vote each. The steward holds at most two seats, and fewer than half while the group has fewer than five (with three or four seats, one); steward-affiliated maintainers choose among themselves who sits. It decides maintainer additions that drew an objection, trust-core maintainer additions, code of conduct escalations (members with a conflict recuse), the foundation application and the transfer date under D-03. It gates nothing in building, reviewing, landing or releasing, and it changes the agent gates of D-61 and D-63 only through a spine RFC. Decisions are by lazy consensus over seven days; any member may call a vote, decided by simple majority. Until it forms, the owner decides the foundation application and the transfer date and the chief architect decides the rest; every decision with its reason is written to `docs/decisions/`. `governance-check` enforces the seat cap from the affiliations in `MAINTAINERS.md`.

**What no body can change.** `COVENANT.md` may only be strengthened. An amendment that adds an asset, shortens a period or adds a commitment needs an RFC; nothing removes one.

**The RFC process.** RFCs live in `rfcs/NNNN-title.md` in the main repository.

- **Required for:** `design/00-decisions.md`; public crates (layers 0 to 2, `grdr-ffi`, `grdr-wasm`); protobuf packages, the pack format, the provider protocol and the host contract; the Cedar schema; a new same-layer edge (03); a stability-class change in `surfaces.toml`; `GOVERNANCE.md`, `CONTRIBUTING.md`, `AI_POLICY.md`, `COVENANT.md`, the licence policy, removal from the do-not-read list, and the release and support policy.
- **States:** Draft (pull request open) → Review (the persona council and `eval-architecture` review it, and anyone may comment) → Accepted, Rejected or Postponed (decided by the chief architect, with written reasons) → Implemented (linked work items closed). There is no waiting period (owner instruction 7); a comment that arrives after the decision and shows a defect opens a new RFC.
- **Rules:** every RFC names its author, agent or person, and its metadata block names the harness and model that drafted it. Comment must be possible without an account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; a retroactive RFC opens when the fix is disclosed.
- **CI:** `rfc-required` fails a pull request that touches an RFC-gated path, a `cargo semver-checks` break, a `buf breaking` break or a `surfaces.toml` class change unless its metadata block names an accepted RFC (`RFC: <nnnn>`).

### 4. Contribution lanes and the ladder

**Content lane** (content repository). Declarative files only: rules, session rules, fingerprints and agent adapter manifests, housekeeping profiles, policy packs, mappings, integration manifests, corpus samples. Each pull request carries fixtures; CI loads it in the production interpreter of every supported engine line and replays the public part of the benign corpus (13). A first-party rule lands once `eval-acceptance`, `eval-adversarial` and `eval-licence` pass with their evidence, beside the fixtures and the benign-corpus replay; a community rule needs those passes from two evaluators on different models; a ceiling of `contain` or above also needs `eval-security` (13 section 17; owner instruction 7, replacing R-58's human approvals). A content reviewer's review adds evidence and never gates. Outside content pull requests are accepted from the content repository's first push and merge once `grdr content test` and the guides exist (Requires: 30-15; 13 section 17; 03 G2). Every community rule enters at `experimental` and in Watch; promotion follows 13's data gates, and a community rule without its two evaluator passes stays in Watch (D-61; 13 section 17; Deviations item 2). Corpus samples must be inert and are scanned before merge.

**Code lane** (main and contrib repositories). Work items are GitHub issues in the main repository, `416rehman/Guardrails`, and nowhere else (owner instruction 5, `_review/04-owner-kit-instructions.md`); an accepted work item is an issue that a squad lead, the product lead or the programme manager has readied, with a `ready.v1` comment and `status:ready` (`team/01` section 3). Every change links an accepted work item; the CI check `work-item-linked` fails a pull request without one, whoever opened it. Outside contributors take items labelled `open-to-contributors`, or file an issue, which enters at `status:proposed`, and wait for `status:ready`. A pull request from a person not on the vouch list that links no accepted item is closed automatically with a pointer to the process; the vouch list is public in `governance/vouched.txt`, managed with Ghostty's `vouch` tooling (brief 28). Items labelled `good-first-issue` are reserved for a person's first code contribution, and the steward's fleet never claims them (extending LLVM's rule of no AI on good first issues, brief 28). Contributions that cost more to review than they are worth are labelled `extractive` and closed with a reason (LLVM's label).

**The ladder.** Numbers are entry criteria, not quotas; a maintainer may nominate earlier with reasons.

| Step | Criteria | Decision |
|---|---|---|
| Vouched contributor | One merged content contribution, or one accepted issue with a reproducer, or a maintainer's vouch | Any maintainer |
| Content reviewer (domain) | 10 merged content contributions over at least 3 months; 5 substantive reviews | Nomination issue; lazy consensus of maintainers over 7 days |
| Maintainer (area) | 6 months of activity; 20 merged changes or reviews in the area; read `GOVERNANCE.md`; affiliation declared | Nomination issue; 14 days; majority of maintainers voting; once the steering group exists, an unresolved objection moves the decision to it |
| Trust-core maintainer | Maintainer; 10 shadowed trust-core reviews whose findings matched the evaluators' | Steering vote |
| Steering member | Section 3 | Section 3 |

Inactive for six months: emeritus, rights removed, name kept. Removal for cause: steering vote with the subject recused. Every maintainer and reviewer uses hardware-backed two-factor authentication.

### 5. Public gate and held-out suite (D-45)

| | Public `verify` | Held-out suite |
|---|---|---|
| Who can run it | Anyone, locally and in CI | The evaluator service; every human maintainer can read it |
| Gates | Every pull request in every repository | Every release; every steward agent work item before merge; nightly over `main`, whatever the origin |
| Output | Full logs | Category counts to agents; full results to maintainers |
| Publication | Always public | Each set published two releases after use and replaced |

Why the asymmetry before merge: the steward's fleet produces volume that fits visible tests; in SpecBench the 90th-percentile gap between visible and held-out results grows by about 27 points per tenfold code size, a worst-case trend with a weak fit (R² 0.21; h09 verification row 5). The rule binds by origin of volume, not by kind of author: an outside contributor may ask a maintainer to run the held-out suite on their pull request and receives the same category counts an agent does. When the nightly run attributes a failure to an outside change, a maintainer posts a public reproducer, never the held-out item itself (l09 F2).

### 6. Repository hygiene for outsiders

- **Stable Rust only** for default members (ARCH-011 in 03). The MSRV is the current stable minus two minor releases, declared as `rust-version` in the workspace manifest; CI builds default members with both the MSRV and current stable, and no `rust-toolchain` file pins a newer one. No nightly feature anywhere in the default build; prebuilt signed kernel objects are fetched so no kernel, Swift, Node or GPU toolchain is needed.
- **Public crates** (layers 0 to 2, which include `grdr-ffi` and `grdr-wasm`) are published to crates.io under the `grdr-` prefix with `cargo semver-checks` and `cargo public-api` diffs; everything else is `publish = false` (03).
- **`verify`** is the only gate, the same command for hooks, every harness and CI (D-47). S-22 measures a stranger's time to green: target under 15 minutes on clean hosted Windows, macOS and Linux runners (4 vCPU, `team/05`).
- **Contrib repository.** One directory per adapter with `OWNER` (a named human), the port test kit version it passed and a `dist.toml` snippet. It is Tier 2, never gates a release, and an adapter red for two releases is removed (P6; 03 section 12). `grdr-ports-testkit` is a public crate, so the kit is runnable without the main repository.
- **Agent kit is open and harness-neutral.** `AGENTS.md`, `.agents/` skills and hooks, and the work-item issue form and labels are in the main repository. A second harness lands a canary work item monthly in CI, under a usage cap per run (l09 F9; D-47). It runs on the owner's Claude subscription where the subscription's current terms allow that harness, otherwise on a free local model; it never needs a paid key. Recurring agents run from the local dispatcher on the owner's machine with the owner's logged-in Claude Code (owner instruction 23), so they act under the owner's account; agent runs on GitHub-hosted runners are optional and need a token only the owner can create. The spine accepts that dependency as a risk (section 9, "Automation is bound to one account"); R13 holds because the repository and its issues hold all state and this kit is harness-neutral, not because the automation is account-neutral. Where a workflow uses GitHub Agentic Workflows (bot-neutral identity model, h09), its controls are configurable, so each workflow pins read-only agent jobs and sets threat detection to block (`continue-on-error: false`) instead of the default warn mode (31 verification row 9; h09 verification row 8); `team/05` checks both settings.
- **Untrusted text.** Agents that read issue, pull-request or discussion text from outsiders have no write access and no secrets (SD-06). The subscription token they need is held by the fleet's egress and token proxy (`team/03`) and never enters the job. Triage agents return labels and summaries through buffered outputs only.
- **Per-crate design notes.** Each public crate has a design document in `docs/crates/`, reviewed by `eval-docs` (l09 F9), so the code is readable if access to the owner's subscription is lost or its limits change.

### 7. Release policy and support windows

34 section 9 owns version numbering and the support windows; this section fixes what governance commits to and repeats the windows only so `GOVERNANCE.md` can point at them. Changing any of it is an RFC.

- **One product bundle version over separately versioned components** (owner instructions 3 and 17). Public crates, SDKs, endpoint and server programs, the eBPF object and the optional Windows driver carry their own versions and changelogs, proposed by release-please from the commit subjects; the bundle pins each by version and digest and carries the `compat` block of contract ranges (D-71). Packs, the wire major and the Cedar `schema_version` keep their own carriers (03 section 7). A deployment moves from bundle to bundle (34 section 9). `0.x` until the `v1` freeze, so the first public bundle is `0.1.0`; `1.0.0` comes with the `v1` freeze (03 section 7), labelled beta until D-60's embed pilot, which requires an embedding partner.
- **Cadence.** A minor is cut whenever its release gates pass; patches as needed; content continuously through rings (13, 22). release-please opens the release pull request, the merge queue lands it, and release-please creates the tags and GitHub releases (owner instruction 7). The project's TUF keys live in two GitHub Actions environments, the release signer's and the independent rebuilder's, whose signatures form the threshold, so no person holds a key (owner instruction 23; 35 section 3.3).
- **Support.** Before 1.0, the latest minor only. From 1.0, security and S1 fixes for the current minor, the two before it and the live LTS line (D-58, R-43); upgrades hop at most two minors, with required stops. LTS: designated as 34 section 9 states (the first minor at least 90 days after 1.0 with no open S1 or S2 defect, then every twelfth minor), with public security and S1 fixes for 24 months and at most two live lines (D-58). Packs are published for every supported engine line (03). The server ingests from any sensor of the same wire major.
- **Never paid:** security fixes for any supported line, pre-disclosure to redistributors meeting published criteria (D-04, D-62), signed binaries.
- **Paid only after counsel:** maintenance of an LTS line beyond 24 months and OEM support periods (D-04, D-46, D-58; 36). Loonaro offers nothing paid until counsel's opinion exists; free foundation legal programmes are the first route to it. The CRA sets a five-year support floor for manufacturers in Article 13(8) (brief 34 verification row 3); counsel decides how it applies to Loonaro's distribution, and 34's `lifecycle.toml` records it without changing the public window.
- **Every release** is reproducible, signed, with SBOM, VEX and SLSA Build L3 provenance (D-46; 24), and its notes list public-surface changes by stability class. These cost nothing. Every artefact carries a Sigstore keyless signature through GitHub's OIDC identity with its provenance attestation (owner instruction 23). Platform signatures follow D-17, D-18 and D-59 where a vendor programme exists: Windows user-mode binaries through a free open-source signing programme, macOS signed and notarised only with Apple's Developer Program; an artefact without one is marked "not platform-signed" in the release manifest, and macOS then runs at tier 1 only. deb and rpm repositories are signed with project keys.

### 8. Conformance marks

Marks are trademark use gated on evidence, separate from the code licence (brief 27). They belong to the project, sit in the conformance registry, and transfer under D-03. `TRADEMARKS.md` (36) carries the usage rules; this section fixes the evidence. Each mark requires the conformance registry (30-25) and its kit; the engine mark also requires an L3 embedding partner, the platform mark a rebuilt white-label build (an embedding partner), and the hook-provider mark that D-41 opens L2 to third parties.

| Mark (working text; final words with D-66 and 36) | Kit (D-60) | Evidence |
|---|---|---|
| "Runs <Project> content" | Golden vectors for compiled content (L0, D-41) | Signed vector run against a named build |
| "<Project> hook provider" | Provider kit (L2, D-14; `spec/hook-broker/`, 07) | Kit run; for a provider that speaks ACS, also 07 section 8's signature, replay and skew checks. Offered only if L2 opens to third parties (D-41) |
| "Embeds the <Project> engine" | Golden vectors plus the scripted scenario pack on the partner's sensor (L3) | Vector and scenario logs; "not evaluable" reported per rule |
| "<Project> platform" | Full conformance suite on a rebuilt build (L6 rebuilt); a co-brand profile runs our signed build and needs no listing | Suite run |

Rules: every listing attests the D-51 floor for the listed product (no covert mode; the monitored person can see what is collected and who looked): the scenario pack and suite test it for the engine and platform marks, and the partner attests it in writing for the content and provider marks. A listing states the embedding option and the assurance level reached per OS (26 section 8), needs its evidence published in the registry and reproducible by anyone with the kit; private pre-runs are a paid Loonaro service (D-04) and confer nothing. A listing names the build digest and expires with the kit's major version. Nominative and factual statements ("works with", "built from <Project>") need no listing (36); forks under another name need no permission. Brief 28 commitment 5 would also let unmodified builds say "embeds"; we reserve that word for listed builds so the engine mark stays evidence-based. AARM is a third party's programme: we say "passes the AARM R1 to R9 test set" until its public conditions are met (D-46): five production customers for three months, a recognised certification such as SOC 2 Type II (which requires revenue or a sponsor, D-46), an active community representative and a commitment to future benchmarking (h04 verification row 2).

### 9. Community health metrics

A scheduled deterministic job (`cargo xtask health`, no model) generates `community/health.md` monthly from public code-host API data and opens it as a pull request, so no agent reads outsider text to produce it (SD-06). Metrics are per organisation or per project, never a ranking of individuals (the spirit of P8). Figures are measured; the right column holds targets.

| Metric | Definition | Target |
|---|---|---|
| First response | Median time from issue or pull request to first response, agent and human reported apart, by the author's affiliation | Reported; no gap between affiliations |
| Content decision | Median time from content pull request to merge or close | Reported |
| Outsider build | S-22 time to green `verify` per OS | Under 15 minutes |
| Reproducer promise | Held-out failures on outside changes with a public reproducer | 100% |
| Outside share | Merged changes authored by people outside the steward, code and content separately | Reported |
| Maintainer spread | Maintainers outside the steward; organisations with a maintainer | 2 and 2 (OpenSSF Incubating needs 3 from 2 organisations, brief 28) |
| Review depth | Per public crate, humans who reviewed 3 or more changes in 6 months | 2 |
| Contrib health | Contrib adapters green, red, removed | Reported |
| Trigger (a) | Unaffiliated production adopters; external committing organisations (definitions in `COVENANT.md`) | Reported |
| Trigger (b) | Months since first public release, of 18 | Reported |
| Maintenance cost | Share of the Claude subscription's usage windows, usage-limit pauses and any owner or buddy hours per release (l09 F9; S-20) | Reported |
| Harness neutrality | Monthly second-harness canary | Pass |

### 10. Launch: what each public step requires

1. **The repository is public from its first push** (owner instruction 28). The seed carries the licence, `SECURITY.md` (35) and the commit-form gate V24, and the pre-push public gate runs on it (`team/06` section 11 item 9). Loonaro is the legal entity. Early work items write the rest, none of it a condition of being public: D-66's recorded name and namespace search (36 LBC-2); the covenant, governance files, `CODE_OF_CONDUCT.md`, `TRADEMARKS.md` (36) and empty `ADOPTERS.md`; the springing assignment in escrow (36 L-06); the buddy listed in `MAINTAINERS.md` as second maintainer; `licence-lint`, `rfc-required` and `work-item-linked` green.
2. **Each repository is public from its creation:** the main repository from its first push, the content and contrib repositories when the work that needs each starts; what exists builds green on `verify`; discussions open; content pull requests accepted and queued (merged once `grdr content test` and the guides exist, section 4). The announcement's first line states the licences, that nothing is withheld, and that there is no telemetry by default. This adapts h04 implication 10 ("Apache-2.0, every component, no telemetry by default"), which is inexact because kernel programs and documentation are dual-licensed; h04 verification row B confirms the telemetry point is a real difference (OpenShell ships telemetry on by default). It must not say "nothing sent anywhere": the default anonymous update fetch exists (D-48). OpenSSF Scorecard published.
3. **The first public release requires:** the server-licence go or no-go review (D-02; owner question 6), after which the licence is never revisited; the covenant (step 1) says this review is pending and is the only one. Counsel's opinion on agent-written code, sought first through free foundation legal programmes. OpenSSF Best Practices "passing".
4. **The first public release:** signed as section 7 states (Sigstore on every artefact; platform signatures where a vendor programme exists, otherwise marked "not platform-signed"), with the scorecard (D-45), the support statement (34) and the first health report. The 18-month clock of trigger (b) starts.
5. **Once the contributor guides exist (30-15):** a contributor outside the team lands a Watch detection from the guide alone (03 G2); the first contrib adapter passes the kit; OWASP ACS conformance evidence submitted upstream (D-03; h05 implication 6).
6. **Before the transfer trigger fires:** foundation pre-reads with CNCF TAG Security, the OpenSSF AI/ML working group and one AAIF committee member (l09 S3); choice recorded by RFC.

### 11. Foundation shortlist and transfer

| Foundation | What it requires | Fit |
|---|---|---|
| CNCF Sandbox | Apache-2.0 in and out, DCO, trademark and logo to the Linux Foundation (charter section 11); application reviewed about every two months. Incubation: 5 to 7 adopter interviews, due diligence, two-thirds TOC vote, 5 to 15 months (brief 28). The Governing Board's blanket exception for dual-licensed in-kernel eBPF (2023-08-31) covers `bpf/` (checked at source by l09; reconfirm at pre-read) | First choice. Cedar (Sandbox since 2025-10-08), Falco (Graduated), Tetragon (through Cilium), Agent Substrate and gVisor (Sandbox votes passed 2026-10-20 and 2026-10-28) and OpenShell (Sandbox vote passed 2026-09-26, onboarding open) are there (h05, h04 verification rows) |
| OpenSSF | Apache-2.0 or MIT; a sponsoring working group; repository under OpenSSF's organisation; Best Practices badge mandatory. Incubating: 3 maintainers from 2 or more organisations and the Silver badge. Graduated: 5 from 3 or more, Gold badge, third-party audit (brief 28), which with no budget comes from a free programme such as OSTIF or OpenSSF Alpha-Omega (D-62) | Second choice, through the AI/ML working group |
| AAIF | OSI-approved permissive licence; marks and assets to the LF at Sandbox entry; admission at every stage needs a Technical Committee majority and Governing Board approval; apply for Growth within 12 months or face archival; Growth needs production use at 2 unaffiliated organisations and commits from 2 organisations over six months (brief 28 verification row 2) | Only once it has accepted a security project and publishes its decisions; its committee declined Microsoft's Agent Governance Toolkit (2026-06-29) and nono withdrew citing process (2026-11-09) (h05 verification row 5). Not entered before external commits exist (c6 F2) |
| OWASP | Any OSI licence; 2 to 5 leaders who are OWASP members | Not a home; ACS conformance evidence only |

Preconditions for any application: a second human maintainer from another organisation (l09 F9), the trigger counters published, and the asset register current. Transfer mechanics: marks and domain by assignment (36); the repositories, which live under the owner's GitHub account (owner instruction 5), by repository transfer; project TUF root by a recorded root rotation from the two release environments to foundation-held keys, signed by old and new thresholds (22); default update and intelligence endpoints by DNS on the transferred domain; conformance registry and held-out corpora by repository transfer. The Apple Team ID (which exists only if Loonaro joins Apple's Developer Program) and the Windows signing arrangement with the free signing programme cannot move; the covenant commits the steward to keep signing project releases with them while it holds them, and reproducible builds let the foundation sign its own (l09 F4).

### 12. Signals of bad faith we commit never to send

Each is a covenant item or a tripwire in the health report:

1. Relicensing any project component after the first public release (the single server-licence review of D-02 happens before it and is announced in the covenant), or adding a CLA or copyright assignment.
2. An `ee/` directory, a "community edition", a feature available only in the hosted service, or SSO, multi-tenancy, the provider tier or the console moved behind payment (P11).
3. Binaries under a licence other than the source licence, or with usage, seat or revenue thresholds (Teleport's pattern since v16: free only below 100 employees and USD 10M revenue, brief 28).
4. Delaying source behind binaries, or running product code in the hosted service that is not in the public repositories (the hosted `router` target is public too).
5. Withholding or delaying security fixes for any supported line, or selling vulnerability pre-disclosure.
6. Telemetry, usage pings or crash reports on by default in any shape. The only default outbound traffic is the anonymous, mirrorable update fetch, which can be turned off and is listed by `grdr egress` (D-48).
7. Using the marks against a fork that uses another name, or against an unmodified build saying "built from".
8. Closing, slowing or deprioritising outside pull requests that compete with a paid service; the first-response metric is reported by affiliation.
9. Steward seats above the cap, an agent holding a steering vote, or any identity, agent or person, landing a change outside the merge queue.
10. A private roadmap: the roadmap and decision log are public, except embargoed security work.
11. Archiving the repositories or abandoning a supported line without the transfer having happened.
12. Bought stars, sock-puppet adopters or vouches.

### 13. `COVENANT.md`: required content (D-03)

The full legal wording is 36's; it must contain: (1) all project code, content and documentation stay under OSI-approved licences, forever; (2) binaries are built from the public source by the public pipeline, under the source licence, reproducible, with no usage thresholds; (3) the asset list: marks and logos, project domain, the project's repositories, the project TUF root and release and content signing keys, default update and intelligence endpoints, the conformance registry and the held-out corpora; (4) no person holds a project root key: the threshold is two of two GitHub Actions environments, the release signer's and the independent rebuilder's (owner instruction 23), an independent rebuilder run by a non-steward organisation may hold the second (l09 F4), and the transfer rotates the root to foundation-held keys (section 11); (5) the steward signs project releases with the signing identities it holds (the free Windows signing programme's arrangement, and its Apple identity if it joins Apple's Developer Program) for as long as it holds them; (6) the trigger: transfer on the earlier of (a) two unaffiliated production adopters plus one external committing organisation, or (b) 18 months after the first public release; (7) definitions: an *unaffiliated production adopter* has no ownership, employment, contract or funding relation with the steward, runs the product on at least 25 endpoints or one server installation for at least 90 consecutive days, and confirms in writing in `ADOPTERS.md`; an *external committing organisation* is unaffiliated in the same sense and its people authored at least 10 merged changes, at least 3 of them code, over the trailing six months; with the steward this gives AAIF's Growth bar of commits from two organisations over six months (brief 28), and the 10-change floor is ours, to exclude token commits; (8) the springing assignment in escrow until transfer (c6 F2; 36 L-06); (9) the fallback in "Deviations from the spine and objections", item 1; (10) the bad-faith list of section 12; (11) the server-licence review of D-02 is the only licence review and ends at the first public release; (12) amendments may only strengthen; (13) succession: the owner's buddy, as second maintainer, holds the owner's account-level duties (the repositories' settings under the owner's account and the covenant assets) if the owner is absent, until a new owner is named (D-61, R-57); no landing or release waits on either of them.

### 14. Full text of `GOVERNANCE.md`

```markdown
# Governance

This file says who decides what in <Project>. It changes only through an
RFC. COVENANT.md sits above it: nothing here can weaken the covenant.

## Principles

- The project is open source: Apache-2.0 for code and content, with the
  exceptions stated in CONTRIBUTING.md. Nothing is withheld.
- AI agents plan, build, review and release the project, and no step
  needs a person. The merge queue, which is deterministic software, lands
  every change once its checks and the reviews its risk requires pass. An
  agent never reviews its own change and never holds a code-owner entry or
  a vote in the steering group.
- People may contribute, review and maintain. A person's review adds
  evidence; it is never a required step.
- Decisions and their reasons are public, in docs/decisions/ and rfcs/,
  except security work under embargo (see SECURITY.md).

## Roles

Steward: Loonaro, the company that started the project. It holds the
project's assets (listed in COVENANT.md) until they move to a neutral
foundation and holds the project's accounts. Releases are signed by the
release pipeline without any person holding a key; the steward adds
platform signatures with the signing identities it holds.

Owner: one person from the steward. The owner sets the project's
direction in written instructions and, until the steering group exists,
decides the foundation application and the transfer date. The owner
signs and approves nothing that lands.

Second maintainer: a maintainer named by the owner in MAINTAINERS.md who
holds the owner's account-level duties when the owner is absent.
COVENANT.md states succession.

Chief architect: the agent that owns the decision spine. It accepts,
rejects or postpones RFCs after the review council and the architecture
evaluator have reviewed them, and writes down why.

Release manager: the release agent of each release line. It keeps the
release pull request and checklist green and owns backports; the release
tooling creates the tags, and the merge queue lands the release pull
request.

Maintainers: people listed in MAINTAINERS.md for one or more areas, with
their affiliation. They review changes in their areas, appear in
CODEOWNERS (which requests their review and does not require it),
shepherd RFCs and vote on new maintainers.

Trust-core maintainers: maintainers approved for the paths listed in
security/trust-core.paths (kernel programs, privileged services, updater,
cryptography, policy semantics, tenancy, gate and release configuration).
They review changes on those paths when they can. A trust-core change
lands on two independent passing reviews by agents on different models;
a maintainer's review adds evidence.

Content reviewers: people approved to review content (rules, fingerprints,
packs) in a domain. They may be volunteers or maintainers.

Contributors: anyone who follows CONTRIBUTING.md and AI_POLICY.md.

## Steering group

The steering group forms when the second maintainer from outside the
steward is added. Every maintainer has a seat up to five seats. Above five,
maintainers elect five members each year, one vote per maintainer.

The steward holds at most two seats. While the group has fewer than five
members, the steward holds fewer than half of the seats. When more
steward maintainers are eligible than the cap allows, they choose among
themselves who sits.

The steering group decides:
- adding maintainers when there is an objection, and adding trust-core
  maintainers;
- code of conduct reports escalated to it (members with a conflict recuse);
- the foundation application and the transfer date under COVENANT.md.

It gates nothing in building, reviewing, landing or releasing. The gates
in AI_POLICY.md change only through an RFC to design/00-decisions.md.

It decides by lazy consensus: a proposal posted publicly passes after seven
days without objection. Any member may call a vote instead; a simple
majority decides.

## RFCs

An RFC is required to change:
- design/00-decisions.md (the decision spine);
- the public crates (schema, core, ports and shared libraries, the C ABI
  and the WebAssembly binding);
- wire formats: protobuf packages, the pack format, the provider protocol
  and the host contract;
- the Cedar schema;
- a stability class in surfaces.toml, or a new dependency edge between
  crates in the same layer;
- this file, CONTRIBUTING.md, AI_POLICY.md, COVENANT.md, the licence policy,
  the release and support policy, or removal of an entry from the
  do-not-read list.

How it works:
1. Open a pull request adding rfcs/NNNN-title.md from the template.
2. When the text is ready, the review council and the architecture
   evaluator review it, and anyone may comment in the pull request.
3. The chief architect accepts, rejects or postpones it and writes the
   reasons in the pull request. There is no waiting period; a later
   comment that shows a defect opens a new RFC.
4. Accepted RFCs are implemented through linked work items. CI refuses a
   change to an RFC-gated surface whose pull request does not name an
   accepted RFC.

Every RFC names its author, agent or person.
A fix for an embargoed vulnerability may change a public surface without an
RFC; a retroactive RFC opens when the fix is disclosed.

## Becoming a maintainer

- Vouched contributor: one merged content contribution, an accepted issue
  with a reproducer, or a maintainer's vouch.
- Content reviewer: about ten merged content contributions over at least
  three months and five substantive reviews in the domain. Nominated in a
  public issue; approved if no maintainer objects within seven days.
- Maintainer: about six months of activity and twenty merged changes or
  reviews in the area. Nominated in a public issue; approved after 14 days
  by a majority of the maintainers who vote. Once the steering group
  exists, an objection that is not resolved in the issue moves the
  decision to it.
- Trust-core maintainer: a maintainer whose ten shadowed trust-core reviews
  matched the review agents' findings; approved by the steering group.

Maintainers and reviewers use hardware-backed two-factor authentication
and declare their affiliation.

After six months without activity a maintainer becomes emeritus: rights
end, the name stays in MAINTAINERS.md. The steering group may remove a
maintainer for cause; the person concerned does not vote.

## Releases and support

Release lines and support windows are published in the support statement
and change only by RFC. Security fixes for supported lines are never paid
for.

## Conflicts of interest

Members declare their employer and any paid relationship with the steward.
The first-response and merge-time metrics in community/health.md are
reported by affiliation so that anyone can check that outside
contributions are not handled more slowly.

## Code of conduct

CODE_OF_CONDUCT.md applies in every project space. Reports go to the
address in that file and are handled privately; the project publishes only
counts.
```

### 15. Full text of `CONTRIBUTING.md`

```markdown
# Contributing to <Project>

Thank you for helping. This file covers both ways to contribute: content
(rules, fingerprints, policy packs and other data) and code. AI_POLICY.md
applies to every contribution, whoever or whatever wrote it.

## Before you start

- Licence: code and content are Apache-2.0. Kernel programs in bpf/ are
  GPL-2.0-only OR BSD-2-Clause. Documentation is Apache-2.0 OR CC-BY-4.0.
  There is no CLA and no sign-off. You keep your copyright. By opening a
  pull request you submit your contribution under the project's licence
  (Apache-2.0 section 5); see AI_POLICY.md.
- Commit messages are one line: a Conventional Commit subject such as
  `fix(grdr-core): return unresolved for here-doc bodies`, at most 72
  characters, with no body and no trailers.
- Do not copy, translate or paraphrase code or rule logic from sources
  listed in supply-chain/do-not-read.toml (for example Elastic detection
  rules under the Elastic License, SigmaHQ rules under the DRL, AGPL or GPL
  engines). Reading them to understand a technique is fine; reproducing
  them is not.
- Security problems go to SECURITY.md, never to a public issue.

## Content: the open lane

Repository: the content repository. Anyone may contribute.

1. Pick a template: add-rule, add-agent (fingerprint and adapter manifest),
   add-pack, report-false-positive, report-malicious-artifact.
2. Write the item as a declarative file. A content item can never introduce
   anything to execute, contact or set: a command, an executable path, a
   URL to fetch, an environment variable to set or an MCP server to start;
   the verifier rejects it. Host patterns, environment variable names and
   path templates are allowed as typed match fields.
3. Add fixtures: at least one sample that must match and one that must
   not. Samples must be inert.
4. Run `grdr content test`. It loads your item in every supported engine
   and replays the public benign session corpus. Fix any benign hit or
   record it in known-fps.yaml with a reason.
5. Open a pull request with the evidence template filled in.

Review: the acceptance, adversarial and licence reviews must pass the
item, beside the fixtures and the benign replay, each from two review
agents on different models for a community rule. A rule whose response
ceiling is `contain` or above also needs the security review.
A content reviewer's review adds evidence. While `grdr content test` does
not yet exist, pull requests wait with the label "queued" rather than in
silence.
Every new rule starts as experimental and in Watch mode. It is promoted by
data (time in rings, benign hits, analyst verdicts), never by request, and
no community rule goes beyond Watch without its two passing reviews.

## Code

Repositories: the main repository and the contrib repository (community
adapters).

1. Every code change links an accepted work item: an issue labelled
   "status:ready". Look for issues labelled "open-to-contributors", or open an
   issue describing the problem and wait for the "status:ready" label. Pull
   requests that link no accepted item are
   closed automatically unless you are on the vouch list
   (governance/vouched.txt); if you are, they stay open but cannot merge
   until an accepted item is linked. You get on the list with one merged
   content contribution, an accepted issue with a reproducer, or a
   maintainer's vouch.
2. "good-first-issue" items are kept for people making their first code
   contribution. The project's own agents never take them.
3. Build: install stable Rust (the minimum version is `rust-version` in
   the workspace Cargo.toml and is checked by CI) and run
   `cargo xtask verify`. A clean clone should be green in under 15 minutes
   on Windows, macOS or Linux, with no kernel, Swift, Node or GPU
   toolchain. If it is not, that is a bug; please report it.
4. Keep to the layer rules. `verify` runs the architecture lint; its
   messages say how to fix a violation.
5. Changes to public crates, wire formats, the pack format, the Cedar
   schema or anything else listed in GOVERNANCE.md need an accepted RFC
   first.
6. Changes to trust-core paths (security/trust-core.paths) need the
   security and adversarial reviews, two independent passing reviews on
   different models, and extra evidence (a reference model, differential
   tests, matrix and soak runs); a trust-core maintainer's review adds
   evidence. Talk to a maintainer before starting.
7. New dependencies need a licence on the allow-list in
   supply-chain/licences.toml and pass the licence review. Adding a
   licence to that list changes supply-chain/, a trust-core path, and is a
   change of its own.

### Contrib adapters

A storage, bus, blob, sandbox or sensor adapter outside the two core
adapters per port goes in the contrib repository. It needs a named owner
and must pass grdr-ports-testkit. It never gates a release and is removed
after two releases with a failing kit.

## Every pull request

Fill in the template:

- Work item: `Closes #<n>`.
- Metadata: the tool and model that wrote the change, or `none` (see
  AI_POLICY.md).
- Testing: the commands you ran and their output.
- Risk: what could break, and where.
- How to revert.
- Not verified: what you could not build, run or test.
- Bug fixes: a test that fails before the fix, passes after, and fails
  again if the fix is reverted.
- Removals: a test that fails if the removed code is still there.

Commit messages are one line, for example:

    fix(grdr-core): return unresolved for here-doc bodies

The pull request, not the commit, names the work item and the tools used.

## Tests you cannot see

Pull requests are gated only by the public `verify`. The project also runs
a held-out test suite before releases and every night on the main branch.
Its tests are published two releases after use. If a held-out test fails
because of your change, a maintainer posts a public reproducer. You may ask a maintainer to run the held-out suite on your
pull request before merge; you get the same category counts the project's
own agents get.

## Response times

Every issue and pull request gets a response, from a maintainer or from the
project's triage agent marked as one, and every content pull request a
decision. community/health.md publishes the median times, by
affiliation, so anyone can check that outside contributions are not
handled more slowly.
```

### 16. Full text of `AI_POLICY.md`

```markdown
# AI-assisted contributions

<Project> is built by AI coding agents, which plan, write, review and
release it with no required human step. This policy applies the same rules
to those agents and to everyone else. It is changed only by RFC.

## The rules

1. Every contribution has a responsible author: a person, or the project
   agent named in its pull request. The merge queue lands every change, so
   nobody holds a merge right. A review counts only when it comes from a
   reviewer that did not write the change. Agents hold no code-owner entry
   and no vote in the steering group.

2. Every code change links an accepted work item. Agents do not open
   unsolicited pull requests to this project or to anyone else's.

3. Every pull request says whether AI was used, in its metadata block:
   the tool and model that produced the text (for example
   claude-code:claude-opus-5-5), or none when no AI tool wrote any of it.
   Name the tool and model that produced the text, not every tool you had
   open. Commit messages and pull-request descriptions written by a tool
   count.

4. Every pull request carries the evidence template from CONTRIBUTING.md,
   with command output, not claims. Say what you could not verify.

5. There is no sign-off. Commit messages are one line, and no commit
   carries Signed-off-by, Co-Authored-By or any other trailer.

## What opening a pull request means

By opening a pull request you submit the contribution under the project's
licence (Apache-2.0 section 5) and confirm that you have the right to.
When a tool wrote part of it, you confirm that:

- the tool's terms of use allow you to contribute its output under
  Apache-2.0;
- you did not feed it, and it did not fetch, material from sources on the
  do-not-read list or other code you may not relicense;
- the output does not, to your knowledge, reproduce third-party code or
  rules under an incompatible licence.

This is not a statement that you read every line. Review depth is set by
the change's risk tier and recorded in the pull request.

## How the project's own agents land changes

The steward's agents commit on agent branches with one-line commit
messages. Each pull request names its work item and the model that wrote
it. The merge queue squash-merges it once verify and CI pass on the
rebased branch, every review its risk tier requires has passed, at most
three review rounds were used and the branch is current. Reviews run in a
clean context, and the cross-model review runs on the model that did not
write the change. Every check run and review is recorded on the pull
request.

Risk tiers: a change that deterministic checks can prove (comments,
formatting, prose) lands on those checks alone; a small change gets one
review pass; other changes get their tier's reviews; high-risk changes and
every trust-core change get the security and adversarial reviews, and a
trust-core change needs two independent passing reviews on different
models.

## Quality bar

We close contributions, from anyone, that cost more to review than they
are worth, with the label "extractive" and a reason. Common reasons:
generated changes with no linked work item; tests that cannot fail; code
that wraps what it claims to remove; large diffs with no evidence. Size the
change to what a reviewer can check.

## Same gate for everyone

Pull requests from people and from the project's agents pass the same
public `verify`. The held-out suite scores every change on the main branch
nightly, whoever wrote it. The project's own agent work is also scored
before merge, because it is produced in volume; anyone else may ask for the
same pre-merge run.

## Security reports

AI-found vulnerabilities are welcome through SECURITY.md if they come with
a reproducer and a statement of what you could not test. Reports without a
reproducer are closed.

## Contributing elsewhere

When we contribute to other projects we follow their AI policy, including
their trailer rules, and a person is always the author of record.
```

## Interfaces and contracts

| File or interface | Format | Read by | Owner |
|---|---|---|---|
| `LICENSE`, `NOTICE`, `bpf/LICENSE-*`, `docs/LICENSE-CC-BY-4.0` | Text | Scanners, `licence-lint` | This doc |
| `COVENANT.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `AI_POLICY.md`, `CODE_OF_CONDUCT.md`, `ADOPTERS.md` | Markdown | People, `xtask governance-check` | This doc |
| `MAINTAINERS.md` | Markdown with one TOML block: `name`, `handle`, `affiliation`, `role`, `areas`, `trust_core`, `since` | `xtask codeowners`, `governance-check` | This doc |
| `.github/CODEOWNERS` | Generated from `MAINTAINERS.md` and `security/trust-core.paths`; requests review and is never a required approval; hand edits fail CI; any bot fails CI | Code host | This doc; 02 for the path list |
| `security/trust-core.paths` additions | `MAINTAINERS.md` and `.github/` are gate configuration under D-63 and are listed | Change classifier | 02 owns the file |
| `SECURITY.md` | Markdown | People | 35 |
| `TRADEMARKS.md`, escrow and assignment instruments | Markdown, legal | People | 36 |
| `governance/assets.toml` | One entry per covenant asset: `id`, `kind`, `holder`, `custodian`, `transfer_method`, `verified_on` | Quarterly audit job | This doc; 22 for keys |
| `governance/vouched.txt` | One handle per line | Auto-close job | This doc |
| `supply-chain/licences.toml`, `supply-chain/do-not-read.toml` | TOML | `cargo deny`, vendoring check, agent egress allowlist (`team/03`) | This doc |
| `rfcs/NNNN-*.md` | Markdown template: summary, motivation, design, compatibility, stability class, alternatives, unresolved | `rfc-required` | This doc |
| Commit message and pull-request metadata | Commit: one Conventional Commit line, at most 72 characters, no body or trailer; squash commit: the pull-request title plus ` (#<pr>)`. Pull-request body: `Closes #<n>`, a collapsed metadata block (harness, model id or `none`, attempt, and `RFC: <nnnn>` where an RFC-gated surface changes) and the `release_note` block (34 section 14) | `guard-command`, V24, `rfc-required`, change classifier, merge queue, release-please | This doc; tiers from SD-13 |
| Pull-request evidence template | Sections: Work item; Testing (commands and output); Risk; How to revert; Not verified; three-arm proof for bug fixes; survival tests for removals (D-47) | Evaluators, reviewers | This doc; `team/05` |
| Conformance registry | Repository of listings: mark, build digest, kit version, evidence links, expiry | Public | This doc; kits in 26 |
| `community/health.md` | Generated monthly | Public | This doc |

## Behaviour by deployment shape

- **Standalone:** nothing about the project is reported from a device. Adoption is known only from voluntary `ADOPTERS.md` entries and download counts.
- **Platform, self-hosted:** no phone-home (D-58). Self-hosters appear as adopters only by opting in; production adopters for trigger (a) confirm in writing.
- **Platform, hosted by Loonaro:** requires revenue, sponsorship or donated cloud credits for infrastructure (D-63); self-hosting is the default way to run the platform. When it runs, it runs public releases built by the public pipeline. Hosted-only targets (`router`) are in the public repository. Operating the service gives Loonaro no governance right beyond its capped seats.
- **Embedded:** partners take Apache-2.0 code with the root `NOTICE` only; content carries no display duty. A rebuilt white-label (L6) uses its own brand manifest and signing identities and may use a mark only with a registry listing. Embedded builds make no call to Loonaro (D-60).

## Extension points

Outsiders extend the project without touching the core through: content pull requests (rules, fingerprints, adapter manifests, packs, mappings); contrib adapters passing `grdr-ports-testkit`; verdict providers passing the provider kit; conformance submissions to the registry; translations of language tokens (34 section 15a); RFCs; entries in `threats.yaml` (02); additions to the do-not-read list. Each path is documented under `docs/extending/` with a guide an agent or a person can follow alone.

## Security and privacy

- **Contribution as attack path (ADV-9, TB-11).** Poisoned rules or corpus samples: two independent evaluator passes on different models, Watch entry, inert-sample scan, the benign-corpus gate (13). Injection through issue or pull-request text: readers have no write access or secrets (SD-06). Malicious dependency: allow-list, `cargo vet`, the release-age cooldown (3 days for patch and minor releases, 7 for majors; owner instruction 22), `eval-licence` and `eval-security` (03).
- **Account takeover.** Every agent runs under the owner's `gh` login (owner instruction 23), so `guard-command` limits each role's `gh` calls and a ruleset on `main` requires the verify and evaluator status checks, so nothing reaches `main` except the queue's merge of a green pull request. The owner and every maintainer use hardware-backed two-factor authentication. A GitHub App per role is an optional later hardening.
- **Forged evaluator results.** Each tier's evaluators post required check runs bound to the pull request's head commit, and the queue re-checks them on the rebased head; `guard-command` lets only evaluator sessions post them, and never the writer's. `MAINTAINERS.md`, `.github/` and the gate configuration are trust-core paths, changed only by protected changes (owner instruction 7).
- **Sybil vouching.** Vouching and promotion need human maintainers' decisions recorded in public issues; health metrics flag bursts of new accounts.
- **Contributor privacy.** `MAINTAINERS.md` affiliations are published with consent; health metrics aggregate by organisation; code of conduct reports are handled privately and reported only as counts.
- **Embargoed work** follows D-62 and SD-08 (35); it is the only exception to the public roadmap.

## Test and evaluation strategy

| Property | Oracle |
|---|---|
| Licence detected cleanly | GitHub repository API returns `Apache-2.0` for main, content and contrib repositories |
| Every file has a valid header | `licence-lint` over the tree, plus seeded violations in a fixture |
| No banned licence in any build closure | `cargo deny` per build profile, including `embedded`; seeded GPL dependency fails |
| Agents cannot fetch do-not-read sources | Sandbox test: a scripted fetch to each listed host is denied and logged |
| Every `main` commit is one valid line from a merged pull request | V24 over the history and the queue's title and `Closes #<n>` check; fixtures for a multi-line message, a trailer, a missing `Closes #<n>` and an unlisted type each fail |
| No change lands without its evaluators | Seeded pull requests: a trust-core change with two passes on the same model, a check run posted from the writer's session and a stale check run on a pre-rebase head are each refused by the queue |
| No bot holds rights; steward seats within the cap | `governance-check` parses `MAINTAINERS.md` and `CODEOWNERS` against the code host's App list, and the steering roster against declared affiliations; seeded bot entry and over-cap roster each fail |
| Unlinked code changes cannot merge | `work-item-linked` fails a vouched contributor's pull request with no accepted item; auto-close fires for an unvouched one |
| RFC-gated paths are gated | Seeded semver break, `buf breaking` break and `surfaces.toml` change without `RFC:` each fail |
| Outsider can build | S-22 run by a person outside the team, per OS, repeated for each release |
| Harness neutrality | Monthly canary with a second harness, within its usage cap |
| Reproducer promise | Health report metric against the evaluator's attribution log |
| Asset register is true | Quarterly job checks domain registrar, the repositories' owning account and root metadata against `governance/assets.toml` |
| Marks are earned | Registry listings re-run from published kits by an independent CI job |

## Work breakdown

**E1. Licence and notices**
- 30-01 Root `LICENSE`, `NOTICE`, `bpf/` and `docs/` licence files in all repositories. Accept: GitHub API reports `Apache-2.0` for each repository.
- 30-02 `licence-lint` and header insertion tool. Accept: seeded missing header and stray `GPL` identifier fail `verify`.
- 30-03 `supply-chain/licences.toml` wired into `cargo deny` per build profile. Accept: an MPL-2.0 dependency fails the `embedded` closure and passes a layer 4 program.
- 30-04 `do-not-read.toml` wired into the fleet egress and token proxy (`team/03`). Accept: a scripted fetch of each entry's repository, raw, archive and API paths is refused and logged as a finding; a fetch of an unlisted repository on the same host succeeds.

**E2. Governance files and covenant**
- 30-05 `COVENANT.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `AI_POLICY.md`, `CODE_OF_CONDUCT.md`, `MAINTAINERS.md`, `ADOPTERS.md` from the texts in sections 14 to 16, with `<Project>` substituted. Accept: `governance-check` passes on `main`.
- 30-06 `governance/assets.toml` and the quarterly audit. Accept: a seeded wrong holder fails the job.
- 30-07 Springing assignment of marks, domain and GitHub organisation in escrow (36 drafts; counsel through free foundation legal programmes first). Accept: counsel's signed note in the decision log. The first release requires this item; the repository is public before it (owner instruction 28).

**E3. Commit form and landing**
- 30-08 Commit-form gate V24 and the queue's title and `Closes #<n>` check (with `team/05`). Accept: a multi-line message, a trailer and a pull request without `Closes #<n>` for a work item are each refused.
- 30-09 Merge-queue landing step (with `team/05`). Accept: a pull request lands only with verify green on the rebased head, every evaluator its tier requires passed, at most three review rounds and a current branch; the squash commit is the title plus ` (#<pr>)`; the issue closes.
- 30-10 Required evaluator check runs bound to the head commit. Accept: the seeded pull requests of the evaluator row under "Test and evaluation strategy" are each refused; a clean pull request lands.
- 30-11 `xtask codeowners` generation. Accept: hand edit and bot entry both fail CI.

**E4. Contribution lanes**
- 30-12 Issue and pull-request templates, labels, auto-close for unvouched unlinked pull requests, and the `work-item-linked` check. Accept: a test account's unlinked pull request is closed with the pointer comment; a vouched account's unlinked pull request stays open and cannot merge.
- 30-13 Content landing rules in the content repository (with 13). Accept: a community rule with passes from one evaluator model cannot merge; two passes on the same model count as one; a rule with a ceiling of `contain` or above also needs `eval-security`; a community rule without its two passes stays in Watch.
- 30-14 The owner's buddy listed as second maintainer with the covenant's succession role (D-61, R-57). Accept: listed in `MAINTAINERS.md`, affiliation declared; `governance-check` passes.
- 30-15 `docs/extending/` guides. Accept: 03 G2 passes. Requires: `grdr content test` (13).

**E5. RFC process**
- 30-16 `rfcs/` template, labels, `rfc-required` check. Accept: seeded breaks fail; an accepted RFC named in the pull-request metadata passes.
- 30-17 RFC 0001 adopting the spine as the baseline. Accept: reviewed by the persona council and `eval-architecture`, accepted by the chief architect with written reasons.

**E6. Outsider hygiene**
- 30-18 MSRV policy and check. Accept: a crate using a feature newer than `rust-version` fails; a `rust-toolchain` file pinning a newer toolchain fails.
- 30-19 Publish public crates. Accept: `cargo install` of the CLI from crates.io builds on stable. Requires: the D-66 namespace search; names are reserved before the first crate is published.
- 30-20 Contrib repository skeleton with one sample adapter. Accept: sample passes the kit and a `dist.toml` build. Requires: `grdr-ports-testkit`.
- 30-21 Second-harness canary and GitHub Agentic Workflows settings check. Accept: monthly run green within its usage cap, on the owner's subscription or a free local model with no paid key; a workflow with a writable agent job or threat detection in warn mode fails CI; an agent job that reads outsider text has no subscription token in its environment.
- 30-22 Per-crate design notes for layers 0 to 2. Accept: each public crate has a reviewed note.

**E7. Release and support**
- 30-23 Release policy page generated from 34's `lifecycle.toml` into the support statement. Accept: published with the first public release; the windows on the page match section 7 and 34 section 9.
- 30-24 LTS branch and backport automation; the first designation follows 34 section 9. Accept: on a test LTS branch the backport bot opens a security fix and the release notes list the line's end date. Requires: `1.0.0`, since LTS lines exist only after it.

**E8. Conformance marks**
- 30-25 Conformance registry repository and listing schema. Accept: our own build listed for "Runs <Project> content" from a public run.
- 30-26 Independent re-run job. Accept: a tampered evidence link fails the listing. Requires: 30-25.
- 30-27 Engine mark and platform mark. Accept: the L3 pilot partner's listing reproduces from the published kit; a rebuilt build's listing fails when its disclosure surface is hidden. Requires: 30-25 and 30-26; an L3 embedding partner for the engine mark; a rebuilt white-label build (an embedding partner) for the platform mark.

**E9. Health and launch**
- 30-28 `cargo xtask health`. Accept: the report rebuilds byte-identical from the same API snapshot, uses no model, and reports first response by affiliation.
- 30-29 Launch checklist (section 10) as a tracked issue per step. Accept: each step closed with evidence.
- 30-30 OpenSSF Scorecard, Best Practices passing and silver. Accept: badges live; "passing" is in place before the first public release.

**E10. Foundation and transfer**
- 30-31 Thesis and pre-read meetings. Accept: written feedback from two bodies; choice RFC accepted.
- 30-32 Transfer runbook per asset. Accept: dry run of root rotation on a test repository (22).
- 30-33 Transfer executed. Accept: asset register shows the foundation, or the fallback holding body (Deviations item 1), as holder. Requires: 30-32; the covenant's trigger; a foundation's acceptance or the fallback.

## Risks, open questions and spikes

| Risk or question | Response |
|---|---|
| Evaluator capacity or a usage limit stalls the queue | Items wait in `status:in-review` and nothing lands without its gates; the dispatcher pauses at a usage limit and resumes after the window resets, and the spine trigger (section 9: over 20 items or oldest over 48 hours) cuts writers to three |
| "Guardrails ADR" is a weak mark | 36 section 1: the recorded search states its strength; the name carries no house mark, so the D-03 transfer is not blocked; registration waits for funding (36 L-02) |
| Counsel finds agent-written code unprotectable or the inbound terms weak (36 L-11, L-12) | Adjust `AI_POLICY.md` and `CONTRIBUTING.md` wording before the first public release; licence and gates are unaffected |
| No outside contributors arrive | Trigger (b) still fires at 18 months; health report shows the gap; the second-harness canary and design notes keep the project forkable |
| A foundation declines | Fallback in the covenant (deviations below) |
| CNCF requires the DCO (section 11) while this project has none (owner instruction 7) | Raised at the pre-reads (section 10 step 6); agent commits cannot carry a DCO, so any adoption at transfer is an RFC that covers human contributors only |
| Evaluators disagree on community content | The rule stays in Watch; after the D-47 cap of three rounds the item goes to `lead-content`, then the chief architect, who decides with a written reason (owner instruction 7) |
| No free legal help or free audit is granted | No paid offer is made; kernel components leave the internal ring only through D-62's review route, run by evaluators, and take a free audit when one is granted; governance files, licence and covenant are unaffected |
| Spike: outsider build (S-22) | As in the spine |
| Spike: outside agent kit run (l09 S2) | An outside engineer with their own model access and a second harness completes one medium item from the public repository alone; pass: merged within one day, no steward account needed |
| Spike: foundation readiness (l09 S3) | Section 10 step 6 |

Answered by the owner: the legal entity is Loonaro, the budget is zero with the agent team on the owner's Claude subscription, the owner's buddy is the second person (second maintainer and successor), the product is Guardrails ADR (spine question 4; owner instruction 25), and no step of building, reviewing, landing or releasing needs a person (owner instruction 7). Open questions for the owner: spine questions 5 (foundation preference and the transfer trigger), 6 (the server-licence review), 7 (a licence for the owner's own skills so the open agent kit can carry them; until answered they stay private and optional, outside the harness-neutral kit) and 8 (whether Loonaro pays Apple's annual Developer Program fee, which decides whether project macOS releases are also platform-signed and notarised).

## Deviations from the spine and objections

1. **Open.** **D-03 trigger (b) assumes a foundation will accept on our date.** No foundation's acceptance is in our control (CNCF incubation alone takes 5 to 15 months). The body follows D-03 and adds a fallback in the covenant: if no listed foundation has accepted by the trigger date, the assets move within 90 days to a neutral non-profit holding body whose charter embeds the covenant, chosen by the steering group with counsel (36), and are offered to a foundation later. This adds to D-03 rather than changing it.
2. **Superseded by owner instruction 7.** Content lands on evaluator passes with evidence, and community content needs them from two evaluators on different models (section 4; 13 section 17). Spine v4 D-61 and R-58 required human approvals: two (the owner and the buddy, or any two maintainers) for community content and one plus evaluator evidence for first-party content. Spine version 5 makes the change in D-61 (Deviations item 3). Original text: **D-61 "until two humans exist".** The body read it as 13 did: the two approvals could be the owner plus a contracted external detection reviewer.
3. **Settled by owner instruction 7 and spine version 5.** Batch signing, owner approval of high-tier and trust-core changes and the proposed trust-core stand-in RFC are gone: no person approves a landing, the merge queue lands on gates and evaluators (section 2), and the buddy's role is succession (section 13 item 13). This also removes the objection that D-61 and D-63 could not survive the owner's absence or the D-03 transfer. Spine version 5 removes the owner and the buddy from these duties in D-61 and D-63, and 02's SD-05 now names the evaluator route.
4. **Open.** **D-02's server-licence review against a covenant published earlier.** The covenant is published by an early work item in a repository public from its first push (D-03), but D-02 allows one server-licence review before the first public release. The body makes the covenant name that review as pending and final, and limits bad-faith item 1 to relicensing after the first public release, so the two do not conflict.

## Sources

Research briefs: `research/28-oss-sustainability.md`, `research/31-agentdev-operating-model.md`, `research/g06-threat-intel-content-ops.md`, `research/27-embed-oem.md`, `research/h05-open-source-sweep.md`, `research/h09-agentdev-practice-sweep.md`, `research/h04-market-news-sweep.md`, `research/34-compliance.md` (CRA Article 13(8)); each brief's verification section was preferred over its body. Review notes: `design/_review/l09-oss-maintainer.md`, `c6-product-oss-embed.md`, `c9-delivery-team.md`, `l12-completeness.md`, `00-resolution.md`. Design: 02, 03, 07, 13, 22, 34, 36; `team/03`, `team/05`.

Primary URLs (through the briefs): https://github.com/cncf/foundation/blob/main/charter.md ; https://github.com/cncf/toc/blob/main/process/README.md ; https://github.com/ossf/tac/blob/main/process/project-lifecycle.md ; https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md ; https://github.com/aaif/project-proposals/issues/19 ; https://github.com/aaif/project-proposals/issues/61 ; https://owasp.org/www-policy/operational/projects ; https://www.cncf.io/blog/2025/05/01/protecting-nats-and-the-integrity-of-open-source-cncfs-commitment-to-the-community/ ; https://github.com/torvalds/linux/blob/master/Documentation/process/coding-assistants.rst ; https://llvm.org/docs/AIToolPolicy.html ; https://github.com/kubernetes/community/blob/master/contributors/guide/pull-requests.md ; https://github.com/open-telemetry/community/blob/main/policies/genai.md ; https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md ; https://github.com/mitchellh/vouch ; https://spdx.org/licenses/licenses.json ; https://github.com/SigmaHQ/Detection-Rule-License ; https://github.com/elastic/detection-rules/blob/main/LICENSE.txt ; https://github.com/chainguard-dev/malcontent/blob/main/third_party/README.md ; https://github.com/openai/tart/blob/main/LICENSE ; https://github.com/cncf/sandbox/issues/523 ; https://www.cncf.io/projects/cedar/ ; https://github.com/NVIDIA/OpenShell ; https://aarm.dev/conformance ; https://claude.dev/blog/solving-code-review-at-anthropic/ ; https://arxiv.org/html/2605.21384 ; https://github.com/github/gh-aw ; https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847 . No fact was added from outside the briefs and review notes.
