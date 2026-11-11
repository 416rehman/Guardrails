# Owner instructions for the agent kit and what they change

_2026-11-11. The owner gave these instructions while the agent kit was being built, before any agent session started. They bind every document and override the plan where they differ, including [`03-models-and-orchestration.md`](03-models-and-orchestration.md) where its dispatcher row says the dispatcher reads the work graph in the repository: it reads GitHub issues. Sections carry the owner's numbers. Each says what the instruction decides, what the kit builds for it and where, the plan documents that now carry it, and what is not built yet. Later instructions supersede earlier ones where they say so; the numbering rules at the end say which ids the final pass gave. Spine version 5 and `PLAN.md` version 4 carry P14 to P17, D-69 to D-71, spikes S-23 to S-31 and the amendments of D-58, D-59, D-61 to D-63 and D-66._

## 1. The chief architect's ownership sentence

> This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.

- Built: the first line of `.agents/templates/agents/chief-architect.md`, so every rendered definition carries it, and `kit check` fails a rendered definition without it. `session-start` puts it in `additionalContext` whenever `GRDR_AGENT` or `agent_type` is `chief-architect`, on `startup`, `resume`, `clear` and `fork`; `session-restore` does the same after `compact`; the hook self-test covers each source. It is the first line of `.agents/kit/prompts/chief-architect-seed.md`.
- Plan: [`team/03`](../../team/03-skills-hooks-and-plugins.md) section 4.1, [`team/06`](../../team/06-repository-bootstrap.md) section 14, [`team/02`](../../team/02-agent-roster.md) section 3.

## 2. All third-party plugins enabled

> enable all third party plugins, don't keep them disabled

- Built: the marketplace lives in the main repository at `.agents/marketplace/` (one repository, instruction 5), with its catalogue, `PINS.md` and two vendored entries with `PROVENANCE.md`. Its 30 entries are all enabled in `.agents/kit/marketplace.toml` and rendered into `enabledPlugins`; 28 point at their upstream by git subdirectory with a full commit, at the newest stable commit of 2026-11-11 (instruction 22), and `modern-web-guidance` at its v1.0.0 release commit (instruction 18). `PINS.md` records each with its SHA, licence and "enabled by owner instruction, 2026-11-11; not read file by file", except where files were read. CC-BY-SA entries are installed unmodified. `kit install` names the catalogue, enables each git entry and turns off any user-scope plugin that loads under an entry's name in `.claude/settings.local.json`, and prints every installed plugin whose commit differs from its pin. `kit render` folds the `haiku` alias to Sonnet, and `kit check` fails a plugin agent on any other model or on Fable. The old separate marketplace directory is retired.
- Waived for this list only: the file-by-file read and the cooldown. Every other addition and pin move is read in full by `eval-security` (instruction 7) and waits 3 days, 7 for a new major (instruction 22).
- Built since: the tracked settings name the catalogue as the directory source `./.agents/marketplace`, `permissions.toml` gives the managed settings the `strictKnownMarketplaces` path pattern, and `kit check` runs the catalogue check. Not yet confirmed: a live session listing all 30 entries.
- Plan: `team/03` sections 2, 5 and 9, `team/06` sections 2.1 and 2.2. The CC-BY-SA question stays open (`team/06` open question 3).

## 3. Release-please with decoupled versioning

> decoupled component versions ... release-please maintaining release pull requests, versions and changelogs only

- Decided: public crates, SDKs, programs, the eBPF object and the Windows driver version on their own; a coordinated product bundle version carries D-58's upgrade path with LTS and skew policy. release-please maintains the release pull requests, versions and changelogs. Instruction 7 supersedes "the owner or the buddy creating every signed tag": release-please creates the tags and releases once the merge queue lands its pull request (numbering rules).
- Built: `release-please-config.json` (no packages until a component exists), `.release-please-manifest.json`, `.github/workflows/release-please.yml` (pushes to `main`, the workflow token, keyless signing and provenance for released crates, the repository being public from its first push), the `autorelease:` labels no agent sets, and the release files on the protected and trust-core lists. Conventional Commit subjects are enforced as instruction 27 sets them.
- Not built: gate V29 (release diff), the queue's rule that a release pull request lands only on the current tip of `main` (WI-0043), and the package entries, which each public crate adds when it is created.
- Plan: `team/05` sections 3, 5, 14 to 16 and 20; `team/03` section 3 (`grdr-cut-release`, `grdr-scaffold-crate`); `design/24` section 10.

## 4. The structure skill, run through hooks

> implicit state machines are bad; fix the core problem and do it the right way

- Built: project skill `grdr-structure` with the owner's six rules and rule 7 of instruction 9, preloaded for every implementer and code-writing gardener. Structure checks S1 to S5 (with S6 and S7 of instructions 15 and 26) in `xtask/src/gates/structure/`, run by `post-edit` and `stop-gate` and gate V20; `quality/file-size.toml` and `quality/state-machine-exemptions.toml`, protected under `quality/**`. Audit A01 runs inside the `review` workflow when a diff touches a type, field, enum variant or `match`; `garden-architecture` runs it weekly over the whole tree. `session-start` tells every writer, the chief architect included, to load `grdr-structure` and `cleanup`.
- Exemptions follow instruction 7: an entry lands only as a protected change with `eval-architecture` agreeing.
- Naming: S1 to S7 are the owner's names, and Q01 the kit's acceptance digest, so `team/04`'s security prompts are M01 to M05 and its calibration prompts Y01 to Y04. The support severities of `design/34` still use S1 to S4, so the plan writes "structure check S4" and the kit prints `ERROR V20 S4: ...`.
- Plan: `team/03` sections 3, 4.1, 4.2 and 10 (K14); `team/05` sections 3, 7, 8 and 20 (QG-23); `team/02` sections 5 and 7.

## 5. Work items live only in GitHub issues, in one repository under the owner's profile

> heavily use GitHub issues/projects

> The only place for work items should be GitHub issues, not local.. so no need to have any local tooling

> Just use issues, no need for projects or organization. This will be a repo under my own profile. Repo should be called Guardrails

- Decided: one repository, `416rehman/Guardrails`, on the owner's personal account, with no organisation and no GitHub Project; the Cargo namespace stays `grdr` (D-66). A work item is a GitHub issue and nothing else; the issue number is the id, the branch is `agent/<n>/a<attempt>`, and the pull request body's `Closes #<n>` links it (the `Work-Item` trailer is gone, instruction 27). Labels in `.github/labels.toml` are the state machine and the fields; acceptance is held by the `ready.v1` digest; hand-offs, verdicts, escalations and council seats are issue comments. Instruction 23 supersedes "only when the owner starts it": every session posts as the owner's login (numbering rules).
- Built: the repository identity, the branch and snapshot forms and the owner steps in `.agents/harness.toml [github]`, which every kit command reads; `labels.toml` (86 labels, 12 groups, the transitions); the issue form; `kit launch --item <n>` and its snapshot; `kit ready`, `kit handoff`, `kit claim --next` and `cargo xtask dispatch` over the issues; the records `ready.v1`, `lease.v1`, `state.v1`, `handoff.v1`, `meta.v1` and `lane.v1`, trusted only when the repository's owner posted them; gate Q01 in `verify --ci`; `cargo xtask labels sync` and `github check`. The repository exists and is public (instruction 28).
- Readings, recorded so they can be overruled: the chief architect's shell is `.agents/kit/seed-scope.toml`; evidence summaries live in `docs/agents/evidence/<n>/`; Q01 runs outside `verify` because it reads the issue; instruction 5 puts the repository on the owner's account, ahead of owner answer 1's Loonaro accounts, and GitHub can transfer it later.
- Plan: D-47 as instruction 5 words it; `team/01` sections 3, 4, 6, 7 and 8; `team/02` sections 1.4 and 1.5; `team/03` sections 1 to 5; `team/05` section 5; `team/06` sections 1, 2, 2.2, 7, 10, 11, 13 and 14; `design/30` section 4.

## 6. Agents drive the work

> No I don't want this rule... "Only you put an item in the queue" agents should be driving everything finding new issues solving existing ones etc

- Built: the dispatcher's planning pass starts the squad's lead (`.agents/owners.toml`) on every proposed, escalated or blocked issue whose `updatedAt` moved since its last planner ended; an escalation the lead leaves unresolved goes to the chief architect, one Fable session at a time, with its own prompt. The review pass starts the evaluators each in-review issue's lane needs and moves the item on from their verdicts. The recurring agents run on the cadences of `.agents/kit/usage.toml`, on the owner's machine. `guard-command` enforces each role's `gh` calls from the roster's groups. `kit launch`, `kit claim` and `dispatch` refuse to run inside an agent session. A failed GitHub pass retries after full-jitter backoff and polls are jittered (P15).
- Not built: applying an escalation packet's default after 48 hours without a decision.
- Plan: `team/01` sections 3, 5 and 7; `team/02` sections 1.5 and 7; `team/03` sections 6 and 7; `team/06` section 14; `design/30`'s roles table.

## 7. No human gates

> they should be fully self sustained without anything from user/Dev. No human gates

- Decided: every step of building, reviewing, landing and releasing runs without a person; separation of duties stays, between agents and deterministic software. Commit signatures, `Signed-off-by`, `Batch-Approval`, DCO checks, bootstrap mode and the `bootstrap-end` tag are gone, and instruction 27 also removes the trailers. Trust-core changes need `eval-security`, `eval-adversarial`, cross-model review and two passing evaluators on different models. A protected change is its own item for `lead-agent-kit` or the chief architect under `GRDR_SCOPE=protected`, landed after `eval-security` and one more evaluator on the other model; an exemption or ratchet loosening also needs `eval-architecture`. Escalations go to the item's lead, then the chief architect. `garden-rules` items are approved by `lead-agent-kit`; reviewer quality is sampled by `eval-tier`. The chief architect decides spine changes after the persona council and `eval-architecture` review the RFC, with no waiting period. Releases are tagged by release-please and signed keylessly. Embargoed fixes are made by agents in a private fork with network tools off.
- Built: the merge queue (`xtask/src/dispatch/merge.rs`, the dispatcher's landing pass, `cargo xtask queue`): it lands a pull request whose lane's evaluators passed once its title and body are valid, CI is green, the rounds are within the limit and the base-built kit binary's full verify passed on the pull request squashed onto the current `main`, then squash-merges and closes the issue; a refusal goes back to the worker with its reason. The protected-change scope (`harness.toml` `protected_change_agents`, set by `kit launch` only for that lease), `[protected_change]` and `distinct_models` in `risk-tiers.toml`, V05's scopes and the escalation routing. Built since: `cargo xtask kit ci-env`, which gives `verify.yml` the `GRDR_AGENT`, `GRDR_WORK_ITEM` and `GRDR_SCOPE` of a leased branch's lease, so V05 judges an agent's pull request in CI as the queue does (`team/05` section 4). The agent bodies and skills name the agent that now owns each decision; the human steps left in them belong to operating the hosted service (support replies, invoices, on-call), not to building, reviewing, landing or releasing.
- Not built: the queue's matrix cells and other queue jobs (they need `matrix-run`), the release-candidate workflow (K10), and the branch rules on `main`.
- Plan: D-61 and D-63 as amended; `team/01` sections 4 to 7; `team/03` sections 4, 7 and 9; `team/05` sections 5, 11, 14 to 17; `team/06` throughout; `design/24` and `design/30`.

## 8. Spend tokens in proportion to the change

> for simple changes, we shouldn't burn tokens

- Built: `cargo xtask risk` classifies a diff into a tier and a lane (`static`, `light`, `standard`, `full`) from `.agents/risk-tiers.toml [lanes]`; `--raise` posts a `lane.v1` comment and nothing lowers a lane; a failed `light` round raises the item to `standard`; the tree is classified only when clean and at the pull request's head. The review pass, the `review` workflow and the merge queue follow the lane. `usage.toml` gives sizes XS and S low effort and small turn caps. `stop-gate` checks evidence ids and unfiled claims by pattern; the kit's own hooks include no prompt or agent hook. Audits never run in the `static` or `light` lane; the persona council runs only for RFCs and UI design items.
- Built: the `fp-check` entry is rooted at the plugin's `skills` directory, so its `Stop` and `SubagentStop` prompt hooks do not load, and `ENABLE_CODE_SECURITY_REVIEW=0` in the settings `env` turns off `security-guidance`'s model reviews while its pattern warnings run (`.agents/marketplace/PINS.md`).
- Plan: `team/01` section 5, `team/02` section 10, `team/03` sections 4 and 6, `team/05` sections 14 and 15.

## 9. Framework over features

> a core philosophy is modular framework architecture over opinionated/hard-coded features

- Built: rule 7 of `grdr-structure` (find the mechanism first, name the extension point in the hand-off); `eval-architecture` in the roster (an evaluator on Opus at high effort, read-only) with its body, checking every `standard` and `full` lane change for hard-coded behaviour and values, every exemption and ratchet change, and every RFC; audit E08 hard-coded-behaviour in `audits/prompts/E08.md` and `audits/library.toml`, closing by a type change or a decision record, which `garden-architecture` runs weekly.
- Built since: `.agents/risk-tiers.toml` names `eval-architecture` among the medium and high tiers' evaluators, which the review pass starts in the `standard` and `full` lanes. Not built: `eval-architecture` on a low-tier change in the `standard` lane, such as an additive change behind a flag.
- Plan: spine P14; `docs/PLAN.md` section 1; `team/02` (`eval-architecture`); `team/04` (E08); `team/05` section 14.

## 10. A dedicated operator plane, GitLab-style configuration

> the gitlab model for configuration for self deployed installs

- Decided: boot configuration and runtime settings as versioned revisions; an `operator` server target on its own listener, realm and Cedar namespace, with settings, health, diagnostics, upgrades, organisation lifecycle and its own audit chain, and no route to tenant content.
- Plan: spine D-70; `design/20`, `21`, `23` (`grdr.operator.v1alpha1`), `24`, `27` and `32`. Nothing in the kit.

## 11. Identity and email gaps to close

- Decided: a `Mailer` port with SMTP first-party and HTTP-API adapters in contrib; invitations and verification; hosted sign-up with passkeys and OIDC sign-in; passkey step-up, with no passwords, SMS codes or magic links.
- Plan: `design/21` section 6 and `design/25`'s notification section. Nothing in the kit.

## 12. Designed for ten million endpoints

- Decided: principle P15 and the fleet capacity model of the scale review; spikes S-23 to S-30.
- Built in the kit: the dispatcher's jittered polling and full-jitter backoff.
- Plan: spine P15; the capacity model in `design/20`; the scale change set across the design documents; `team/05` section 16's fleet-scale release gate. Section 6 of the review (owner decisions and trust-core reviews) became agent decisions and evaluator reviews (instruction 7).

## 13. Air-gapped deployments must work

- Decided: principle P16, the air-gap change set and the conformance run, numbered S-31 with release gate 24-28.
- Plan: spine P16 and S-31; the design documents the air-gap review names; `team/05` section 16; `grdr-cut-release`'s release gates.

## 14. Check the reference vendors when a feature's requirements are unclear

> when adding a new feature and not sure about requirements/completeness/industry standards, lookup the vendors I had given you

- Built: project skill `grdr-vendor-research` (briefs first, then the vendors' current documentation, then the horizon sweep; one issue comment separating shipping products, converging standards and novel but unproven work), preloaded for the product lead, every lead, the chief architect, implementers, evaluators and `garden-intel` (40 of 66 roles). `.agents/kit/vendors.toml`: 20 vendors with domains and briefs, 18 source classes. `kit render` gives those roles `WebFetch` and `WebSearch`, writes one `WebFetch(domain:)` rule per domain plus `WebSearch`, refuses `WebSearch` for every other role, and puts the domains in the `intel` list of `deploy/fleet/egress.json`; `kit check` fails a missing brief. `garden-intel` runs the sweep daily and files what it finds.
- Plan: `team/03` sections 3, 5, 7, 8 and 10 (K16); `team/02`.

## 15. No panics; recover and stay stable

> no panic or unwraps, self recovery, system stability etc

- Built: `[workspace.lints]` in the root `Cargo.toml` with the deny set of the instruction and `unsafe_code` forbidden, inherited by `xtask`; `clippy.toml` lets tests unwrap, expect, panic and index; the crate-root `arithmetic_side_effects` deny and the unsafe-code copies are documented for the crates that need them. Structure check S6 blocks a new panic path in `post-edit`, `stop-gate` and V20. Every kit handler fails closed instead of panicking.
- Built since: V02 (Clippy with warnings denied) is clean on `xtask`. Supervisors, journalled state, bounds, timeouts, circuit breakers and fault injection are product work.
- Plan: `team/05` section 8; `design/11`; `AGENTS.md`.

## 16. Compatibility between independently versioned components

> how will we ensure compatibility, i.e. component a version x requires component b version x

- Decided: compatibility declared against contract ranges, a `compat` block in the release manifest, one resolver for the updater, preflight, the operator plane and the release job, and a matrix generated from `support.toml`.
- Plan: spine D-71; `design/03` section 7, `design/22` section 8, `design/24`; `team/05` gate V30 and the compatibility-matrix release gate. Not built.

## 17. How a self-hosted deployment upgrades

- Decided: the unit of upgrade is the product bundle and the unit of transfer the changed component; packs, rules, snapshots and the eBPF object within their ranges move on their own channels; the operator plane drives the upgrade.
- Plan: amends D-58; `design/24` section 11 and `design/22` section 6. Nothing in the kit.

## 18. Modern Web Guidance for the web components

- Built: the `modern-web-guidance` plugin and its `chrome-extensions` skill through the marketplace, installed unmodified with attribution in `PINS.md`; `DISABLE_TELEMETRY=1` in the rendered project and managed environments; `.agents/kit/path-skills.toml`, whose `web` entry names `ui-architect`, `frontend-design`, `modern-web-guidance` and `grdr-interface` in that order for `web/**` and `site/**`, with `chrome-extensions` for `web/extension/**`; `guard-path` names an entry's skills on a session's first edit of its paths, `session-start` lists them for the write set, and `stop-gate` records which were loaded; `guard-command` refuses the `modern-web-guidance` CLI through every runner; the preloads for `impl-web`, `eval-ux` and the screen persona seats; `garden-deslop`'s weekly modernisation pass.
- Not built: `kit check` resolving every path-skill name.
- Plan: `team/03` sections 2, 3, 4.1 and 5; `design/27`.

## 19. Consistency and cohesion everywhere; internationalisation

> consistency and cohesion everywhere ... Also what about language tokens? I8n?

- Decided: principle P17 and D-69 (language tokens and internationalisation), the enforcement list of the cohesion review, and translation without a person as a required step.
- Built: project skill `grdr-interface` with `references/checks.md` and `references/strings.md`; the interface checks UX1 to UX8 on the TypeScript, JavaScript and CSS files of the interface paths, in `post-edit`, `stop-gate` and gate V26 (`xtask/src/gates/interface/`), reading `quality/interface.toml`; audit E07 one-way-per-concern; the `eval-ux` cohesion line; the `persona-intl` council seat's body.
- Not built: the Rust and terminal halves of the checks and the registry checks of `cargo xtask interface check` (WI-0041); V27 duplicate code; the `impl-l10n`, `eval-l10n` and `garden-l10n` roles; the rename of `grdr-scaffold-crate` to `grdr-scaffold`.
- Plan: spine P17 and D-69; the cohesion change set across the design documents; `team/03` sections 3 and 10 (K15); `team/05` sections 3, 8, 12 and 16; `team/06` sections 2.1, 2.2 and 10 (WI-0041).

## 20. The air-gap bundle is complete

> this isn't AIRGAPPED if they have to do this: grdr server airgap pull-deps... You must include all, just have them accept a terms/conditions etc

- Decided: overrides rulings 5 and 6 of the air-gap review. One bundle carries every artefact and third-party component every profile needs; licence obligations are met inside it (`sources/` for copyleft components, `THIRD-PARTY-NOTICES`, the SBOM); terms are accepted at import and recorded; a component that may not be redistributed is replaced or optional, never required. `pull-deps` is removed.
- Plan: `design/24` section 7, `design/22`, `design/21`, `design/35` and `design/30`; `team/05` section 16's bundle-contents release gate. Nothing in the kit.

## 21. Astryx first, React Aria only as a registered exception

> we should use existing astryx components no matter what, and only in super extreme rare cases when there's no other option, go with our own through Aria

- Decided: every UI element is an Astryx component behind `@grdr/ui`; `@grdr/kit` composes `@grdr/ui` only; React Aria enters only through `web/packages/ui/exceptions.toml`, whose entries need `eval-ux` and `lead-interfaces`.
- Built: UX2 enforces it: `@astryxdesign/*` only inside `ui`, React Aria only in the files a registry entry lists, `kit` importing only `@grdr/ui`, `@grdr/tokens`, `@grdr/i18n` and React. The registry is a protected path.
- Reading: React is in `kit`'s import list, because a composition needs hooks and the JSX runtime; removing it from `quality/interface.toml` makes the rule strictly the three packages.
- Plan: `design/27`; `team/05` section 8 (ARCH-101 to ARCH-106, UX2); `team/03` section 3.

## 22. Latest versions at bootstrap; proactive vulnerability work; CI time

> Vulnerabilities remediation? Proactive? CI time? Etc. For bootstrapping, we should use the latest version of every dependency

- Built: `cargo update` to the newest compatible releases (toml 1.2.1; no newer major existed); Rust 1.99.1 confirmed as the newest stable; every action pinned to its latest release's SHA; `deny.toml`; `.github/dependabot.yml` with the 3-day and 7-day cooldowns and security updates in their own group; `scan.yml` (gitleaks, zizmor, osv-scanner, Semgrep OSS); `codeql.yml` and `scorecard.yml` for the public repository with the Scorecard floor in `security/scorecard.toml`; `fuzz.yml`, `images.yml` and `dast.yml`, each starting when its input exists; `verify.yml` building the gate from the base, on three systems in a public repository and on Linux only in a private fork or copy; the marketplace pins at their newest. `garden-deps` orders security fixes by KEV and EPSS.
- Reading: Dependabot replaces Renovate, because Renovate needs an app account or a token and instruction 23 allows no new account; Dependabot takes one cooldown for every GitHub Actions update type, so action majors also wait 3 days.
- Plan: `team/05` sections 4 and 9; `team/06` sections 6 and 12; `design/24` section 12.

## 23. Fully hands-off: no step may need the owner

> this is fully hands off and all agentic development environment, you must handle these outside integrations on my behalf

- Decided: no default needs a new third-party account. GitHub Releases and Pages are the update origins, with jsDelivr; Sigstore keyless signing, attestations and Rekor proofs; TUF keys in two GitHub Actions environments with threshold two; ClusterFuzzLite instead of an OSS-Fuzz application; gitleaks locally and in Actions, and CodeQL in Actions from the first push, the repository being public from it (instruction 28); the owner's `gh` login for every agent, with the Apps an optional hardening; the local dispatcher on the owner's logged-in Claude Code, with hosted agent runs optional. Platform signing that needs a vendor programme ships as "not platform-signed" until one accepts Loonaro.
- Reading: CodeQL's terms (the CodeQL CLI licence, read 2026-11-11) allow automated analysis only of an open-source codebase hosted on GitHub.com and bar its use on code in a private repository, so the CodeQL CLI is not a `verify` step; `codeql.yml` runs it in Actions from the first push, the repository being public from it (instruction 28; `team/05` sections 3, 4 and 9).
- Built: the dispatcher and every routine on the owner's machine; `kit launch` passing the owner's user `env` variables to sessions empty; the brand manifest's GitHub-hosted defaults; the release and scan workflows above.
- Remaining one-time owner steps, each optional, a repository setting or the workspace trust dialog the owner accepted on 2026-11-11: `team/06` section 11. Built for the last: the untrusted-workspace preflight, which stops `kit launch` and `dispatch` before any session in a folder Claude Code does not trust (`team/06` section 11 item 14).
- Plan: `team/03` sections 7 and 8, `team/05` sections 4 and 16, `team/06` sections 11 and 13, `design/24` section 10.

## 24. pnpm only, never npm

> We should be using pnpm right? Never npm?

- Built: `guard-command` denies npm, npx, yarn, bun and bunx in every session and names the pnpm replacement; gate V28 (`xtask/src/gates/pnpm.rs`) fails on another manager's lockfile, a `packageManager` other than pnpm and npm or npx in scripts and workflow steps.
- Not built: the root `package.json`, Corepack and `pnpm-workspace.yaml`, which arrive with `web/`.
- Plan: `team/03` section 4.1; `team/05` sections 3 and 9; `CONTRIBUTING.md`.

## 25. Product name and domain

> the product will most likely be just Guardrails ADR. domain is guardrailshq.com

- Decided: the product is Guardrails ADR, agent detection and response; Loonaro stays the legal entity; "AIDR" stays only for other vendors' products and the market's term. The owner's choice answers D-66 question 4, and agents still run and record the registry and trademark search.
- Built: `brand/brand.toml` with the product and entity names, the domain, the repository identity and each address and host, every one with its GitHub-hosted `value` and its `on_domain` value; `AGENTS.md`, `CLAUDE.md`, the seed prompt, the agent bodies and the plan renamed.
- Remaining: DNS for the domain needs its registrar or DNS host (`team/06` section 11 item 5).

## 26. Nothing is hard-coded

> NOTHING SHOULD BE HARD-CODED

- Built: structure check S7 in `post-edit`, `stop-gate` and V20, reading brand and vendor names from `brand/brand.toml` and `.agents/kit/vendors.toml`; `quality/hardcoded-exemptions.toml`, entered only by a protected change; `.agents/kit/limits.toml` with its typed loader in `xtask/src/config/limits.rs`, which rejects a missing or unknown key and reads the base's copy; the repository identity in `harness.toml [github]`, from which the rendered `GH_REPO` comes; the settings schema URL in `permissions.toml`.
- Built since: the hook bounds moved from `hooks.toml [limits]` to `limits.toml [hook.*]`, the workflow scripts' round, finding and issue caps moved to `.agents/kit/usage.toml`, and the repository constant left the code; S7 reports nothing in `xtask/src` or `.agents/kit/workflows`.
- Plan: `AGENTS.md`; `team/03` section 1; `team/05` section 8.

## 27. Commit form: one line, no trailers

Decided with the owner on 2026-11-11, because the owner's `cleanup` plugin denies multi-line commit messages and any AI credit line.

- Decided: every commit message is one Conventional Commit line, `type(scope): summary`, at most 72 characters, with no body, trailer or credit line; Claude Code's `attribution.commit` and `attribution.pr` are empty. The squash commit is the pull request title plus ` (#<pr>)`. The pull request body carries `Closes #<n>` and a collapsed `meta.v1` block with the harness, the model id that wrote the change and the attempt, which the review pass reads to pick the other model; the `handoff.v1` comment repeats it. This replaces the `Work-Item` and `Assisted-by` trailers of instructions 3 and 7.
- Built: `.agents/harness.toml [commit]` and `[pull_request]`; `guard-command` refuses an agent commit that is not one valid line, and `-F`, `--file`, `-t`/`--template`, a second `-m`, `--trailer`, sign-off, fixup and squash commits and a newline; gate V24 checks every commit since the base; `kit handoff` takes the title from the first valid commit subject and writes `Closes #<n>` and `meta.v1`; the merge queue refuses an invalid title or a missing `Closes #<n>`; the skills, bodies, `AGENTS.md`, `CLAUDE.md` and the overlay say the same.
- Not built: V24 judging Dependabot and release-please pull requests by their title, since their own commits carry bodies (WI-0043).
- Plan: `team/01` section 4; `team/03` sections 2, 3 and 4; `team/05` sections 3 and 15; `team/06` sections 1, 2.2 and 13; `design/24` and `design/30`.

## 28. The repository is public from the first push

> No keep the repo public

- Decided: `416rehman/Guardrails` is public before the seed is pushed and stays public. The public gate runs on the seed commit before the first push, by the setup session: a secret scan of the whole tree and history, no `research/_sources/` and no personal data; GitHub's secret scanning and push protection back it on every later push. The covenant, `GOVERNANCE.md` and `MAINTAINERS.md` (WI-0008), the D-66 search and the legal request are work items, not conditions of being public. CI takes its public form from the first commit: hosted runners on Linux, macOS and Windows, the nightly run, CodeQL, Scorecard, secret scanning and release attestations. The repository settings are applied at setup: Actions may create and approve pull requests, the default workflow token is read-only, Dependabot alerts and security updates, private vulnerability reporting, and secret scanning with push protection. This replaces the private period of instructions 22 and 23 and every public flip and first-public-commit gate in the plan.
- Reading: "the first public commit" in the plan means the seed commit. What the plan made a condition of it is a work item, and the namespace that D-66's search fixes is fixed before the first release.
- Built: the CI workflows keep their visibility check as the fallback for a private fork or copy, so this repository runs the full form from its first push; `harness.toml`'s missing-repository step creates the repository public; `cargo xtask github check` reads the repository's settings; `SECURITY.md` names private vulnerability reporting as the first route, with the brand manifest's security address beside it.
- Plan: the spine (D-03, D-61, D-62, D-64, D-66 and section 7); `PLAN.md`; `team/01` section 10; `team/03` section 3; `team/04` section 6; `team/05` sections 4, 9, 16, 19 and 20; `team/06` Summary, sections 1, 9, 10, 11 and 13 and its risks; `design/08`, 22, 24, 26 to 30 and 32 to 36; the `grdr-matrix-run` skill and the `persona-contributor` body.

## Numbering for the final pass

- Principles: P13 enforce below the agent; P14 framework over features (instruction 9); P15 designed for ten million endpoints (the scale review); P16 air-gapped is first-class (the air-gap review); P17 consistency and cohesion (the cohesion review).
- Decisions: D-69 language tokens and internationalisation; D-70 operator plane and two-tier server configuration (instruction 10); D-71 compatibility declared against contract ranges, one resolver, the bundle's `compat` block (instruction 16). Instructions 17 and 20 amend D-58 and D-59; instructions 7, 22 and 27 amend D-61 and D-63; instruction 25 answers D-66 question 4.
- Spikes: the scale review's S-23 to S-30 keep their numbers; the air-gap conformance run, which the air-gap review called S-23, is S-31, with release gate 24-28 unchanged.
- Skill-path data: one file, `.agents/kit/path-skills.toml`; the cohesion review's `.agents/kit/skill-paths.toml` is that file.
- Superseded: instruction 3's "the owner or the buddy creating every signed tag" and instruction 5's "only when the owner starts it", by instructions 6, 7 and 23.
- Gate ids: V18 hook self-test, V20 structure, V21 kit check, V22 model rule, V23 skills lint, V24 commit form, V25 prose and Q01 acceptance digest were in the kit already. The cohesion review's V21 (interface cohesion, checks UX1 to UX8) is V26 and its V22 (duplicate code) is V27. The next free ids went to V28 package manager (instruction 24), V29 release diff (the release research's V22) and V30 contract compatibility (instruction 16); the research's V21 is V24 and its release-freshness gate became a merge-queue landing rule. Supply-chain gates S10 to S12 are Scorecard, Grype and the ZAP baseline (instruction 22).
- New in the final pass: ARCH-025 `one-dialer` (P16) and ARCH-026 `operator-no-content` (D-70), the next free ids after the cohesion review's.
- Names settled in the final pass, one meaning each (P17): the air-gap import is `grdr server airgap import` (instruction 20's name) in every document; the scale review's admission priority classes are AC0 to AC4, because P0 to P4 collided with the spine's principle ids; the writer metadata block is `meta.v1`, the name the kit writes.
- Other ids keep the reviews' numbers: ARCH-017 to ARCH-024 and ARCH-101 to ARCH-106, U08 to U11, F13 and F14, audits E07 and E08 (E08 is instruction 9's audit), kit items K15 (interface checks) and K16 (vendor research), work item WI-0041, and QG-25 to QG-29.
- The scale review's section 2 (fleet capacity model) is a section of `design/20`; its section 6 is agent decisions and evaluator reviews in the spine (instruction 7).
