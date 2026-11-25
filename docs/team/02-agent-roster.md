# Team 02. Agent roster

_Status: draft 6 against the spine, the rulings in `design/_review/01-document-rulings.md`, the owner answers in `design/_review/02-owner-answers.md`, the model rule in `design/_review/03-models-and-orchestration.md` and the owner's kit instructions in [`design/_review/04-owner-kit-instructions.md`](../design/_review/04-owner-kit-instructions.md). Specifies D-47 and D-63, as owner instructions 7, 22 and 27 amend D-61 and D-63; fixes the squad ids design documents defer to `team/`. Read with: [`../design/00-decisions.md`](../design/00-decisions.md) (authoritative); [`01`](01-operating-model.md) (how an issue is worked, tiers, escalation); [`03`](03-skills-hooks-and-plugins.md) (skills and settings); [`04`](04-power-prompts.md) (audit library); [`05`](05-quality-gates-and-ci.md) (gates, CI); [`06`](06-repository-bootstrap.md) (paths and file names); `design/03`, `design/27`, `design/30`, `design/32` section 18, `design/33`; spine D-45 and D-64 for the efficacy harness and test lab._

## Summary

The team is 64 agent definitions in `.claude/agents/`: direction (3), domain leads (18), implementers (6), independent evaluators (13), gardeners (9), the persona council (9) and operations agents (6, `design/32` section 18; R-56). `impl-l10n`, `eval-l10n` and `garden-l10n` join as their files land (TR-14). The intake triager `garden-intake` and the usage gardener `garden-cost` were dropped with the harness that ran them. No agent merges by hand, signs off, holds a code-owner entry or votes, and no step needs a person (D-61, owner instruction 7).

Decisions made here:

1. **One file per agent.** `.claude/agents/<name>.md` holds an agent's front matter and prompt and is edited by hand. A change to one is a `squad:agent-kit` issue, high tier (`.claude/risk-tiers.toml`).
2. **Tools and the write set, no permission limits.** Front-matter tools set what an agent can call, and its issue's write set what it may change, which the evaluators and CI check. Sessions have no permission limits (ADR-0035), and each agent runs in its own worktree.
3. **Verdicts are reports, never approvals.** Evaluators return `pass`, `fail` or `cannot-evaluate` to the orchestrating session, which merges only when every one passed (D-63).
4. **Models may only raise a tier.** Path rules in `.claude/risk-tiers.toml` (which reads `security/trust-core.paths`) set the floor; `eval-tier` may raise it, never lower it (P2 applied to our own process).
5. **Everything runs on the owner's Claude subscription** (D-47), through the owner's logged-in Claude Code (owner instruction 23). Work is measured in share of the subscription's usage windows, never in dollars.

## 1. How every definition is built

### 1.1 Front matter

Fields follow the Claude Code sub-agents page (read 2026-11-10).

| Field | Rule |
|---|---|
| `model` | The exact id of one of three names (`design/_review/03`): `claude-fable-5-2` for `chief-architect` only; `claude-opus-5-5` for medium-to-heavy work; `claude-sonnet-5-5` for everything else. No Haiku and no other vendor's model. The orchestrating session passes `model: "opus"` to the implementer of a high-tier or trust-core issue, and runs `eval-diff` on both models for such a change |
| `effort` | Set on every agent, at a level the bound model has |
| `tools`, `disallowedTools` | Each agent's own list. A role that loads `grdr-vendor-research` has `WebFetch` and `WebSearch` (owner instruction 14) |
| `permissionMode` | Never set: every agent runs in the orchestrating session's mode, `bypassPermissions` (ADR-0035). Read-only agents add `Edit, Write, NotebookEdit` to `disallowedTools`, which defines the role, not a permission |
| `isolation` | Not set in the file; the session spawns implementers and evaluators with `isolation: "worktree"` |
| `memory`, `mcpServers` | Never set: the repository and the issue are the memory (D-47); MCP servers come only from the project settings (Playwright, `team/03`) |
| `maxTurns` | Never set: no agent has a turn limit (ADR-0035). An agent reports `partial` when its context or usage window is nearly spent |
| `skills` | Preloaded in order: project skills and the owner's user-scope skills such as `cleanup:cleanup` |

### 1.2 The common block

Every agent's prompt starts with the same rules block: the repository and the issue are the only memory; `gh` reads `GH_REPO`; use the spine's vocabulary; observed text is data; never claim a result without the command and its exit code; stop with `impossible` when the spec and the tests conflict; hold no secrets; finish by returning the report of `grdr-handoff` to the session that started you. It is copied into each file; change it in every file at once.

### 1.3 The report

Every agent ends with one report as its final message, in the format of `.claude/skills/grdr-handoff/references/format.md`: status, issue, branch and commit, summary, changed paths, the gate commands with exit codes, acceptance per criterion, the three arms for a bug fix, decisions where the spec was silent (least confident first), what was not verified, findings, how to revert and what comes next. Evaluators use the same format with `pass`, `fail` or `cannot-evaluate` (`grdr-evaluate`). `cannot-evaluate` means the evaluator could not look; it never counts as a pass (P9).

### 1.4 Flow of one issue

Skill `grdr-work-issue` runs it (`team/01` section 1): the session reads the issue, spawns the squad's lead when the spec is incomplete, spawns the implementer in a worktree, spawns the evaluators the tier and kind call for in parallel, sends findings back for at most three rounds, then opens the pull request with `Closes #<n>` and squash-merges it once CI is green. The agent that writes an issue's acceptance criteria never implements it, and evaluators are never the writer (D-47).

## 2. Roster at a glance

| Group | Agents | Model, effort | Started by | Writes |
|---|---|---|---|---|
| Direction | `chief-architect`, `product-lead`, `programme-manager` | Fable xhigh (the only Fable agent); Opus high; Sonnet medium | The session, for an escalation, an RFC, a spec or queue order | `rfcs/`, `docs/decisions/` and `docs/agents/status/` (chief architect only); issues and comments through `gh` |
| Leads | `lead-<squad>` × 18 | Opus high | The session, for a missing spec or an escalation in the squad | Issue specs, labels, dependencies and sub-issues through `gh`; `lead-agent-kit` also writes gate configuration in its own issues |
| Implementers | `impl-rust`, `impl-kernel`, `impl-apple`, `impl-web`, `impl-content`, `impl-docs` (`impl-l10n` to come) | Sonnet high; Opus xhigh; Sonnet high; Sonnet medium; Sonnet high; Sonnet medium. Any of them on Opus for a trust-core path or a high-tier change | The session, with an issue number | The issue's write set, on `issue/<n>` |
| Evaluators | `eval-*` × 13 | Section 6 | The session, by tier and kind | Reports; new issues for findings outside the change; `deploy/qa/scenarios/proposed/` for the adversary only |
| Gardeners | `garden-*` × 9 | Section 7 | The owner or a lead, on request | Small fix branches or new issues |
| Persona council | `persona-*` × 9 | Sonnet medium | The session, for an RFC or a UI design item | Seat verdicts |
| Operations | `ops-triage`, `ops-runbook`, `status-drafter`, `capacity-planner`, `usage-reconciler`, `support-first-line` | Sonnet | Alert, schedule or ticket in the hosted deployment (requires the hosted service) | Records, tickets and pull requests named in section 7.1; never production |

## 3. Direction

| Agent | Purpose | Owns | Inputs | Outputs | Done when |
|---|---|---|---|---|---|
| `chief-architect` | Own the codebase: its prompt opens with the owner's sentence "This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it." (owner instruction 1). Keep the spine true and the layers clean, and be the last step of every escalation | `rfcs/`, `docs/decisions/`, spine edit proposals, `architecture.toml` proposals, design 03, 30; the issues it files | Escalations a lead left unresolved, RFCs after the persona council and `eval-architecture` reviewed them, `garden-architecture` audit findings, disputes between leads | RFC drafts and decisions, decision records, layer-rule proposals, answers to escalations, issues | Each RFC has a decision record and either a lint, test or spine edit proposal, and each escalation it took has an answer or a recorded external precondition |
| `product-lead` | Scope, personas, acceptance and the "complete" definition | `PLAN.md` matrix, design 01, 29, 34, 36, acceptance criteria of the issues it specifies, `contracts/support.toml` proposals | Persona council verdicts, scorecards, issues without paths | Product specs and acceptance criteria with named oracles | Every request traces to a decision, document and acceptance test, with its prerequisites named (D-50) |
| `programme-manager` | Order the queue so "work the next issue" takes the right one | design 33, the queue order | Open issues, escalations | `priority:` labels, missing blocker links, a list of issues whose spec is incomplete for their lead | Every open issue has its `priority:` label |

## 4. Domain leads

One lead per squad; each squad activates when its prerequisite exists. A lead is a planner: it decomposes the squad's design documents into issues one writer can finish in one run, each with exact paths, acceptance criteria and a named oracle, and answers blocked reports. It writes no code, except `lead-agent-kit`, which implements gate configuration issues. Ids are `.claude/owners.toml` keys; owned paths and prerequisites are `team/01` section 3's. Every lead preloads `grdr-write-spec`, `grdr-handoff`, `grdr-vendor-research` and the writing skill; `lead-interfaces` also preloads `ui-architect`, and `lead-agent-kit` also preloads `grdr-start-item`, `grdr-verify`, `grdr-structure` and `cleanup:cleanup`.

| Squad (`lead-<id>`, alias) | Design docs | Activates when | Trust-core paths in scope (D-63) |
|---|---|---|---|
| `core` (SQ-01) | 03, 04, 12 | The repository exists | Policy evaluator semantics, `unsafe` in `grdr-ffi` and `grdr-fastpath-ffi`, the TOML gate files |
| `security` (SQ-18) | 02, 35 | The repository exists | Cryptography, approval helper, IPC peer authentication, `security/trust-core.paths`; private triage of security candidates (D-62) |
| `discovery` (SQ-02) | 05, 06 | `grdr-core` exists | None |
| `adapters` (SQ-03) | 07 | `grdr-core` exists | None; managed-settings writers are high tier (D-49) |
| `endpoint` (SQ-07) | 11 | `grdr-core` exists | `grdr-daemon`, `grdr-sandbox-engine` |
| `linux` (SQ-04) | 10 | `grdr-core` exists | `bpf/` |
| `macos` (SQ-05) | 09 | The endpoint daemon exists | Extension shell |
| `windows` (SQ-06) | 08 | The endpoint daemon exists; S-04's outcome sets the sensor design | Optional driver (D-17) |
| `gateway` (SQ-11) | 17 | The proto crates and the endpoint engine exist | None |
| `identity-data` (SQ-10) | 15, 16 | The core `analyze` module exists | None |
| `content` (SQ-08, SQ-09) | 13, 14, 19 | The repository exists (corpus labelling); detections require the `detect` module | None; content enters in Watch (D-61 as amended) |
| `fleet` (SQ-12) | 22 | The endpoint daemon exists | Updater |
| `server` (SQ-13) | 18, 20, 21, 23, 32 | `grdr-wire` and `contracts/proto/` exist; plans the operations agents (section 7.1) | Tenancy |
| `interfaces` (SQ-14) | 27, 28 | The daemon's local API exists; agrees, with `eval-ux`, to each entry of `web/packages/ui/exceptions.toml` (owner instruction 21) | None |
| `ecosystem` (SQ-15) | 25, 26 | The core exists | None |
| `release` (SQ-16, release part) | 24 | The repository exists | Release configuration |
| `lab` (SQ-16, lab part) | Spine D-45 and D-64 | The repository exists | Held-out gating configuration |
| `agent-kit` (SQ-17) | team 01 to 06 | The repository exists | All gate and CI configuration |

Design docs 01, 29, 30, 33, 34 and 36 belong to the direction group.

## 5. Implementers

`impl-kernel` is active only if S-13 passes; `impl-apple` activates with the macOS squad; `impl-l10n` joins with its file (TR-14). Implementers are the only code writers: one per issue, its own worktree, no contact with other writers (brief 31: 20 lock-coordinated peers fell to the throughput of one to three). Trust-core code, such as `bpf/`, may be agent-written and lands only through the trust-core route: `eval-security`, `eval-adversarial` and passing evaluators on two models (owner instruction 7). Every implementer preloads `grdr-start-item`, `grdr-verify`, `grdr-fix-bug`, `grdr-remove-code`, `grdr-handoff`, `grdr-structure`, `cleanup:cleanup`, `grdr-vendor-research` and the writing skill.

| Agent | Writes | Extra tools and skills | Model, effort | Notes |
|---|---|---|---|---|
| `impl-rust` | Layers 0 to 4 Rust in the issue's squad paths; `contracts/proto/`, `contracts/cedar/`, `sdk/`, `deploy/qa/`, `conformance/`, `deploy/` | LSP | Sonnet high | Default writer |
| `impl-kernel` | `bpf/`, kernel-facing parts of `grdr-sensor-linux`; the optional Windows driver | `grdr-matrix-run` | Opus xhigh | Every issue is trust core. Active only if S-13 passes |
| `impl-apple` | `platform/macos/` Swift shell and packaging | LSP; `grdr-matrix-run` | Sonnet high | macOS builds and tests through `grdr-matrix-run`. Extension shell is trust core |
| `impl-web` | `contracts/interface/` (except `strings/tr/`), `web/`, `desktop/` view-models and kit, the `kit` and `ui` packages | LSP, Playwright MCP; skills `ui-architect`, then `frontend-design` for new screens, then `grdr-interface` | Sonnet medium | Composes registered patterns only; every element is an Astryx component through `@grdr/ui` (D-42, P17, owner instruction 21); pnpm only (owner instruction 24) |
| `impl-content` | Content repository: Sigma rules, Cedar packs, agent manifests, mappings | `grdr-author-detection`, `grdr-author-policy`, `grdr-add-agent-adapter` | Sonnet high | Output enters in Watch and leaves it on evaluator evidence (D-61 as amended) |
| `impl-docs` | `docs/` outside `docs/design/` and `docs/decisions/`, crate and program `README.md`, `docs/references/*-llms.txt` | Skills `ui-architect`, then `grdr-interface` for docs components; `skill-creator` | Sonnet medium | Never edits the spine |
| `impl-l10n` (to come) | `contracts/interface/strings/tr/`, `docs/i18n/` and pack `messages/<locale>.mf2.toml`; never a source token | Skills `ui-architect`, then `grdr-interface` | Sonnet medium; Opus high for `safety` tokens | `eval-l10n` judges every change |

Embargoed fixes (D-62, SD-08) use `impl-rust` inside the private fork with the model endpoint as its only network route, no network tools and vendored crates, after `lead-security` triages the finding.

## 6. Independent evaluators

Evaluators read the diff, the built artefact, the issue's acceptance criteria and their own instructions from `main`, never from the branch (brief 32), through the `grdr-evaluate` skill. Each runs in a clean context and its own worktree, and returns its verdict to the session; findings outside the change become new issues. The session picks them from `.claude/risk-tiers.toml` (`team/01` section 4) and this section's change-kind rows. For a high-tier or trust-core change `eval-diff` runs on both Opus and Sonnet, each in a clean context (D-47, `design/_review/03`). Refuting passes run on Opus. Every evaluator preloads `grdr-evaluate`, `grdr-handoff`, `grdr-vendor-research` and the writing skill. The incident eval set in `deploy/qa/reviewer-evals/` (escaped defects, reverted issues) scores every evaluator on each model release (target).

| Agent | Purpose | When | Model, effort | Done when |
|---|---|---|---|---|
| `eval-tier` | Raise the tier above the path rules when warranted | The issue has no tier label or the diff reaches paths outside the write set | Sonnet low | Tier with reasons; never lowered |
| `eval-acceptance` | Prove each criterion against the running artefact | Every code change at medium tier or above | Sonnet high | Every criterion has evidence; three-arm or survival proof re-run |
| `eval-diff` | Clean-context review of the diff with the structure rubric, A01 on state-touching diffs and the per-change prompts of `team/04` section 9 | Every change; twice, on both models, for high tier and trust core | Sonnet high; Opus for the second pass | Findings ranked, each with a failed refutation; no repeat findings across rounds |
| `eval-architecture` | Behaviour or values written into code where a mechanism or data source belongs (P14, S7); RFC review | Every change at medium tier or above; every `kind:rfc` design issue | Opus high | Each behaviour has its mechanism named |
| `eval-security` | Trust-boundary, fail-open, privilege and secret review; threat-model delta | Medium and above; every trust-core path | Opus xhigh | Findings with proofs; fail-mode table updated |
| `eval-adversarial` | Attack the build in the lab: bypasses, approval forgery, tamper, injection | High tier, trust core, policy, control points; release candidates | Opus high | Scenario results in AMTSO vocabulary; new scenarios proposed |
| `eval-ux` | Review screens and flows under ui-architect, then grdr-interface | Every `[interface]` path of `.claude/risk-tiers.toml` | Sonnet high | Each violation cites a principle and a fix |
| `eval-performance` | Measure against spine section 6 targets | Hook path, fast path, engine, proxy, storage | Sonnet medium | `team/05` section 10 gates pass against the `main` baseline |
| `eval-api` | Check wire and API contracts | `contracts/proto/`, `contracts/cedar/`, public crates, `docs/spec/` | Sonnet medium | `buf breaking`, semver-checks and golden vectors green, or an accepted RFC linked |
| `eval-platform` | Run the change on every Tier 1 cell | Endpoint, sensor, adapter, installer and sandbox paths | Sonnet medium | Result per cell; parity gaps listed |
| `eval-a11y` | WCAG 2.2 AA and desktop accessibility | UI paths | Sonnet medium | Automated audit, keyboard and screen-reader script results, and the U09 journeys |
| `eval-l10n` (to come) | Blind back-translation of each changed translation, then an equivalence verdict | Every change to a translation | The model that did not translate it, high | `equivalent` for every `safety` token and `equivalent` or `minor` for the rest |
| `eval-docs` | Documentation matches behaviour | Any user-visible change | Sonnet low | Docs diff present or "no user-visible change" proved |
| `eval-licence` | Licence and provenance hygiene | Dependency, vendored code, content | Sonnet low | `cargo deny`, `cargo vet`, SPDX and do-not-read checks pass |

Evaluators work in a scratch worktree; only `eval-adversarial` and `eval-performance` write, to `target/` and `deploy/qa/scenarios/proposed/`. Until the incident eval set holds 50 cases, low tier is limited to docs and flag-gated additive changes (h09).

## 7. Gardeners

Gardeners are agents the owner or a lead starts on request ("run garden-deslop over grdr-core"). Each finds first, read-only, and either fixes what its duty names on a branch, at most 200 changed lines and judged like any other change, or files what it finds as new issues with evidence for a lead to specify. A gardener whose output is a code change also preloads `grdr-structure` and `cleanup:cleanup`. Find passes run on Sonnet and refuting passes on Opus (`design/_review/03`).

| Agent | Duty | Model, effort | Output |
|---|---|---|---|
| `garden-deslop` | `cleanup` over a crate; narration comments, near-copies, one-implementation traits, speculative fallbacks (E01, E03, E05); the suppression burn-down | Sonnet medium | Removal changes with survival tests |
| `garden-architecture` | Run `team/04`'s audits, among them A01 "find all of the implicit state machines", E08 hard-coded behaviour and B03 layering intent; A01 findings close only by a type change | Sonnet find, Opus refute | An issue per upheld finding |
| `garden-deps` | Review Dependabot pull requests past the cooldown (3 days for patch and minor, 7 for majors; owner instruction 22); a security fix at once, for `eval-security`; read changelogs and `cargo vet` diffs; pins Dependabot does not read | Sonnet medium | A comment per Dependabot pull request; work issues |
| `garden-docs` | Documentation statements the code contradicts, stale `AGENTS.md` and `CLAUDE.md` lines, dead links (H01, H04) | Sonnet medium | Fix changes; issues |
| `garden-tests` | Tests for surviving mutants; tests that cannot fail; flaky tests (G03, G02, D06) | Sonnet high | Test-only changes (never `src/`) |
| `garden-catalogue` | Agent catalogue tiers and hook-contract notes against vendors' published docs and release notes | Sonnet medium | Content changes, issues for adapters |
| `garden-intel` | OpenSSF malicious-packages, GHSA, KEV and incident write-ups into the mirror pack and detection proposals; the horizon sweep of `grdr-vendor-research` (owner instruction 14) | Sonnet medium | Mirror pack changes; rule proposals in Watch; issues |
| `garden-conformance` | Triage failures of the D-49 canary job for a new agent release | Sonnet high | Adapter fix issue for `lead-adapters`; agent dropped to Watch |
| `garden-rules` | Repeated review findings and repeated audit closures become lint, ast-grep, `REVIEW.md` or skill issues (`team/04` section 6) | Sonnet medium | Issues for `lead-agent-kit` |
| `garden-l10n` (to come) | Held, stale and preview locales; glossary drift | Sonnet medium | Translation changes and issues |

### 7.1 Operations agents

`design/32` section 18 defines these roles and their access (R-56). They run in the hosted deployment repository: single writer, no merge rights, no production credentials, read-only access to our own telemetry, which never contains tenant content. Runbook actions go only through the operations runner, which checks each step's actor tag and bounds; the `human` and `two-humans` tags there are the hosted service's own operating classes, not gates on building, reviewing or releasing. They require the hosted service, which requires revenue, sponsorship or donated cloud credits (D-63). `lead-server` plans them. Each runs on Sonnet, and OPS-S1 (`design/32`) is their evaluation.

| Agent | Does | Never | Access |
|---|---|---|---|
| `ops-triage` | Receives every alert and synthetic miss; enriches, classifies severity, opens the incident record, keeps the timeline, drafts postmortems | Lowers or closes a Sev1 or Sev2; holds the pager | Read-only telemetry, alert and change records |
| `ops-runbook` | Submits `agent` and approved `agent-approved` runbook actions to the operations runner; runs restore drills into scratch cells | Submits `human` or `two-humans` actions | Runner request API only |
| `status-drafter` | Drafts status posts and customer incident emails; publishes Sev3 and maintenance posts | Publishes a Sev1 or Sev2 post without the incident lead's approval | Status repository pull requests |
| `capacity-planner` | Weekly forecast per cell; proposes cell provisioning two weeks ahead and `bounds.toml` changes as pull requests | Merges them itself | Read-only telemetry; pull requests |
| `usage-reconciler` | Runs the daily reconciliation job and opens tickets on differences | Finalises or corrects an invoice | Read-only ledger and billing-provider reports |
| `support-first-line` | Drafts first answers; analyses consented support bundles | Sends S1 or S2 replies; requests a SupportGrant | Ticket system; consented bundles only |

## 8. Persona council

The nine-seat council runs from the first design review (R-42); before the provider and embedding surfaces exist, the MSP and OEM seats review their seams. The session spawns it for RFCs and UI design items only. Each seat walks its persona's journeys (brief 33; design 27, 28) on the preview build; the council never reviews code. A seat returns accept, accept with changes, or block, with at most five findings (`team/01` section 10). A block needs a written disposition from `product-lead` before the design is accepted. A broken spine floor (P8, D-51 disclosure, D-31 widening) goes straight to the chief architect. Seats run on Sonnet.

| Agent | Persona and first test | Reviews |
|---|---|---|
| `persona-solo-dev` | One developer, no account: first agent and session within 5 minutes, no elevation, not nagged (median 3 prompts a day) | First run, tray, desktop, CLI, block messages |
| `persona-it-admin` | Enterprise IT beside an incumbent EDR: MDM deploy, rings, health, uninstall restores every file | Installer, `grdr doctor`, deployment health, coexistence pack |
| `persona-soc-analyst` | Triage the review queue, finding to evidence in 1 click, contain a session | Review queue, incidents, hunting, export contract |
| `persona-msp-operator` | Many organisations from one queue, "acting as" banner, onboarding in 10 minutes | Provider views and the tenancy seams |
| `persona-oem-partner` | Embed the engine or content without our network or trust roots | Embedding options, host contract, brand manifest, stability classes |
| `persona-privacy-officer` | Least content by default, no per-person scoring, re-identification needs two approvers | Schemas (`data_class`), capture levels, retention, disclosure screen |
| `persona-contributor` | A stranger builds and changes the core with stable Rust and lands a Watch rule from the guide alone (S-22) | `CONTRIBUTING.md`, `AGENTS.md`, error messages, contribution flow |
| `persona-simplicity` | What can be removed, Simple view uses only the spine's surface terms, control stays reachable in Advanced | Every design change |
| `persona-intl` | An operator who reads Arabic and Japanese: mirrored layout, isolated identifiers, numerals and dates in their own locale, nothing truncated | Console, desktop, tray, CLI, notifications and docs in `ar`, `ja` and the pseudo-locales |

The seats that review screens (`persona-solo-dev`, `persona-it-admin`, `persona-soc-analyst`, `persona-msp-operator`) also load `ui-architect` and `grdr-interface`.

## 9. Responsibility matrix by component

Work on a row starts when its prerequisites exist.

| Component | Lead | Implementer | Required evaluators | Tier or route (D-63) |
|---|---|---|---|---|
| Schemas, `grdr-proto`, `grdr-schema` | core | impl-rust | api, diff, architecture, docs | High; RFC (D-61) |
| `grdr-core` policy evaluator semantics | core | impl-rust | acceptance, diff, security, adversarial, performance, architecture | Trust core |
| Normalisers, `analyze` | core | impl-rust | acceptance, diff, security, adversarial | High |
| `grdr-fastpath`, `grdr-fastpath-ffi`, `grdr-ffi`, `grdr-wasm` | core | impl-rust | api, performance, security | Trust core for `unsafe` |
| `grdr-crypto`, peer authentication, `grdr-approve` | security | impl-rust | security, adversarial, platform | Trust core |
| Discovery, attribution, `session` module | discovery | impl-rust, impl-content | acceptance, adversarial, platform | Medium |
| Hook shim, broker, agent adapters | adapters | impl-rust, impl-content | acceptance, platform, performance, security | High for managed-settings writers |
| Daemon, engine, store, run, sandboxes | endpoint | impl-rust | acceptance, platform, security, performance | Trust core for daemon and `grdr-sandbox-engine` |
| Linux sensor and eBPF (enforcement requires S-12 and the trust-core route, D-19) | linux | impl-kernel, impl-rust | platform, security, adversarial, performance | Trust core |
| macOS sensor, extension shell (D-18) | macos | impl-apple, impl-rust | platform, security | Trust core for shell |
| Windows sensor, optional driver (D-17) | windows | impl-rust, impl-kernel | platform, security, performance | Trust core for driver |
| Proxy, MCP broker, gateway | gateway | impl-rust | security, adversarial, performance | High |
| Redaction, detectors, identity | identity-data | impl-rust | security, adversarial; privacy persona | High |
| Detections, packs, intelligence | content | impl-content | acceptance, adversarial, licence | Leaves Watch on evaluator evidence (first-party); after its fixtures, the benign corpus and two evaluators on different models (community) |
| `JudgeBackend` trait; judge adapters and review stage | core (trait); content (adapters) | impl-rust | api, security, adversarial | High |
| Updates and uplink | fleet | impl-rust | security, platform, adversarial | Trust core for updater |
| Server, storage, tenancy, API | server | impl-rust | api, security, performance, acceptance, architecture | Trust core for tenancy |
| Web console, desktop, tray, browser extension, the interface system | interfaces | impl-web, impl-rust | ux, a11y, acceptance, docs, architecture; council | Medium |
| Translations | interfaces | impl-l10n | l10n, ux | Medium |
| Export, conformance kits, integrations and WebAssembly components | ecosystem | impl-rust, impl-content | api, acceptance, licence; OEM persona | Medium |
| Packaging, deploy, brand, release-please | release | impl-rust, impl-docs | platform, licence, security | Trust core for release configuration |
| Lab, harness, held-out client | lab | impl-rust | adversarial, acceptance | Trust core for gating configuration |
| Agent definitions, skills, `.claude/`, CI | agent-kit | `lead-agent-kit` | security, diff on both models, architecture | Trust core |
| Documentation | product-lead | impl-docs | docs | Low |

## 10. Who reviews which kind of change

`.claude/risk-tiers.toml` encodes this table; it wins where they differ. `eval-architecture` joins every row that changes code or configuration at medium tier or above (owner instruction 9).

| Change kind | Tier floor | Evaluators | Persona | Lands |
|---|---|---|---|---|
| Docs outside the spine | Low | diff, docs | Contributor if `CONTRIBUTING.md` | When they pass |
| Spine or RFC | High | diff, security, architecture; chief architect drafts | Affected personas | The chief architect decides after the council and `eval-architecture`, with no waiting period (owner instruction 7) |
| `architecture.toml` and other gate data | Trust core | diff on both models, security, adversarial, architecture | None | When they pass |
| Bug fix | Medium | diff, acceptance (three-arm re-run), security, architecture | None | When they pass |
| Removal or simplification | Medium | diff, acceptance (survival test), security, architecture | None | When they pass |
| New feature, non-trust-core Rust | Medium | diff, acceptance, security, architecture, platform if endpoint, performance if hot path | By surface | When they pass |
| Wire format, public crate, Cedar schema | High | api, diff on both models, security, adversarial, architecture | Privacy officer, OEM partner | With an RFC |
| Trust-core path | Trust core | diff on both models, security, adversarial, platform, performance, architecture | None | Passing evaluators on two models; leaves the internal ring only through D-62's route |
| New dependency | High | licence, diff on both models, security, adversarial | Contributor | When they pass |
| UI screen, CLI output or the interface system | Medium | ux, a11y, acceptance, docs, security, architecture | Council by surface | When they pass |
| Translation | Medium | l10n, ux | Intl seat by surface | Once every changed `safety` token is `equivalent` |
| Content pack or rule (content repository) | D-61 content rule | acceptance (benign corpus), adversarial, licence | SOC analyst | Enters in Watch (D-61 as amended) |
| Agent adapter manifest (content repository) | D-61 content rule | acceptance (`grdr adapter test`), platform | Solo developer | As content packs |
| Installer, managed-settings writer | High | platform, security, adversarial, acceptance | IT administrator | When they pass |
| Gate, CI, agent definitions, skills | Trust core | diff on both models, security, adversarial, architecture | None | When they pass |
| Dependabot update | By diff | `garden-deps`; `eval-security` reads every security fix | None | Security fixes skip the cooldown (owner instruction 22) |
| Embargoed security fix | Trust core | security, acceptance in the private fork | None | Agents in the private fork with network tools off; `lead-security` triages (D-62, owner instruction 7) |

## 11. Work items

| ID | Item | Acceptance | Requires |
|---|---|---|---|
| TR-05 | Evaluator shadow comparison | Each new evaluator's verdicts compared with the evaluators already in use and with the incident eval set before its findings fail a change | |
| TR-06 | Incident eval set in `deploy/qa/reviewer-evals/`, scored on each model release | 50 cases before low tier widens beyond docs; each evaluator's score published per run | |
| TR-11 | Operations agents of section 7.1 (`design/32` OPS-29) | OPS-S1 passes; the monthly permission test refuses every production write by each agent identity | The hosted service (D-63) |
| TR-14 | Files for `impl-l10n`, `eval-l10n` and `garden-l10n` (D-69, P17); `persona-intl` is done | A translation change gets `eval-l10n` on the model that did not translate it | |

## How this is kept current

Agent changes are `squad:agent-kit` issues. Triggers: each model release, or a change to the models, effort levels or limits the subscription offers (re-run the incident eval set and `team/04`'s Y01, Y02, H04, I05, M05; change a model binding or `effort` only where scores move and within `design/_review/03`'s rule); a squad's prerequisite landing (activate the squad); a falling evaluator score. `garden-docs` checks that this document and `.claude/agents/` agree.

## Risks and open questions

| Item | Risk or question | Settled by |
|---|---|---|
| Evaluator usage | Seven evaluator runs per trust-core issue may exhaust the subscription's usage window | Review in proportion to tier and kind; drop any evaluator whose eval-set score does not beat `eval-diff` alone |
| Same-family review | Every agent runs on a Claude model, so evaluators share a family with the writer | `eval-diff` on both Opus and Sonnet for high tier and trust core |
| No person reads a change | With no human gate, a weakness every evaluator shares can land (owner instruction 7) | The incident eval set, the held-out suite and seeded impossible issues (`team/05` section 18); a miss raises the tier for that area |
| One subscription and one login | The team acts under the owner's account and `gh` login | The repository and its issues hold all state, so the work can continue under another account (spine section 9) |
| Weak acceptance criteria | No person reads acceptance criteria before work starts (owner instruction 6) | The spec writer is never the implementer; evaluators, the held-out suite and seeded impossible issues judge independently; a pattern of weak criteria is a `garden-rules` finding |
| `ui-architect` licence | The skill is the owner's; the open agent kit (D-61) can ship it only under a compatible licence | Spine owner question 7; until answered it loads from the owner's user skills |
| Kernel writers | S-13 may show agents cannot write safe eBPF | `impl-kernel` stays inactive; Linux enforcement code waits for a contributor or partner |

## Deviations from the spine and objections

None raised against the spine. One reading, still open: D-63's "low merges on evaluator evidence" is narrowed until the incident eval set reaches 50 cases (section 6), following h09; this tightens and does not contradict it.

Conflicts settled in earlier passes: browser extension ownership (R-55), operations agents (R-56), council start (R-42), judge timing (R-34), `grdr-fastpath-ffi` and crate timing (R-22), content approvals (spine v3, D-61, amended by owner instruction 7).

## Sources

- Claude Code sub-agents documentation, front-matter table, read 2026-11-10: https://code.claude.com/docs/en/sub-agents
- Claude Code permission modes, read 2026-11-10: https://code.claude.com/docs/en/permission-modes
- Research briefs 31, 32, h09 and 33, read with their Independent verification sections
- Review notes c9, c7, l10
- `design/03` sections 1, 2, 11 and 13 (crates, layers, paths, do-not-use list)
- The consistency, cohesion and language-token review of 2026-11-11 (P17, D-69): the `impl-web`, `eval-ux`, `eval-a11y` and l10n roles and the ninth council seat
