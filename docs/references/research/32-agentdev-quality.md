# Automatic quality for agent-written code: power prompts, de-slopping, skills, hooks, gates

_Researched 2026-11-09_

Method note: the shared web-search budget was exhausted before this brief started, so everything here comes from direct fetches of primary docs and from the GitHub API (`gh`), not from search. Versions, stars and dates are as returned by the GitHub API on 2026-11-09/10. Items I could only state from memory are marked "(unverified)".

## TL;DR

- Claude Code now exposes **33 hook events** and five handler types (`command`, `http`, `mcp_tool`, `prompt`, `agent`), with an `if` permission-rule filter and `onFailure: "block"` (v2.1.295+). Stop hooks are capped at 8 consecutive continuations. This is enough to build a full definition-of-done loop without custom tooling.
- Hooks are **not a security boundary** (Trail of Bits' wording: "structured prompt injection at opportune times"). Bash bypasses `Edit|Write` matchers, and command hooks fail open on timeout unless `onFailure: "block"` is set. Real enforcement must live in CI and the sandbox.
- Agents game tests. ImpossibleBench (Oct 2025): GPT-5 passed 54% of tasks whose tests contradicted the spec; Opus 4.1 50%. Read-only tests stop test editing but not special-casing; LLM monitors caught only 42-50% on SWE-bench-style tasks. Defence must be layered: protected tests, mutation testing, property tests, held-out acceptance scenarios.
- The "implicit state machines" prompt has been packaged as skills (dzhng `find-state-machines`, the "plain prompt" in mokevnin's patterns book). I could not trace the original post. The best wording adds "every non-terminal state has a guaranteed way out".
- `desloppify` v1.0 is the only mature code-slop scorer (mechanical detectors plus LLM review, anti-gaming strict score, Rust and TypeScript at full depth). Its licence is the custom OSNL, not OSI.
- Cargo still has **no native dependency cooldown** (only unstable `generate-lockfile --publish-time`). Use Renovate `minimumReleaseAge` or Dependabot `cooldown` (default 3 days; security updates bypass both). pnpm now defaults `minimumReleaseAge` to 1440 minutes.
- TypeScript 7.0.2 (the native Go port) is `latest` on npm; Oxlint 1.93 supports JS plugins; Biome 2.6.6; Vitest 5.1; knip 6.44.
- Cedar's verification-guided development (Lean model and proofs, differential random testing of the Rust code against the model via `cargo fuzz`, property tests) found 4 bugs by proof and 21 by DRT/PBT. It is the template for our policy evaluator and parsers.
- Quint (now `quint-co/quint`, v0.33.1) ships agent skills, an LLM kit, and `quint-connect` for replaying spec traces against Rust. TLA+ TLC's last stable release is v1.7.4 from August 2024.
- Claude Code "scheduled tasks" (formerly routines) run in the cloud on cron, API or GitHub triggers, minimum interval one hour, research preview, bound to an individual account. For an open-source project, mirror them as GitHub Actions cron jobs.
- Skills are portable across harnesses (`npx skills add`, `.agents/skills`); hooks are not. Put every check behind one repo command (`just verify-fast`, `just verify-full`) that hooks, CI and other harnesses all call.

## Findings

### Part 1: power prompts

**Origin.** The earliest packaged forms I could find through GitHub code search:
- `dzhng/skills` `find-state-machines` (MIT, 1,470 stars; skill file committed 2026-11-07). Its definition is the best wording available: "one lifecycle whose state, transitions, and ownership are spread across the code", plus the exit-path requirement. https://github.com/dzhng/skills
- `mokevnin/agentic-coding-design-patterns`, `book/en/refactoring.md` (repo created 2026-07-11): seven "plain prompts" (implicit state machines, scattered business rules, unnecessary abstractions, concepts hidden in primitives, calculations mixed with effects, dead code and workarounds, architecture). It advises separating "behavior confirmed by code from inferred rules". https://github.com/mokevnin/agentic-coding-design-patterns
- `dyad-sh/dyad` `plans/codex-correct-state-machines.md` (2026-07-28): after a state-machine migration, 21 PRs drew 256 review findings; its conclusion is that prose rules did not stop invalid states and an executable machine contract with conformance tests was needed. https://github.com/dyad-sh/dyad
- Related packaged audits: Trail of Bits `insecure-defaults` (fail-open, "a refuting verifier per candidate file"), `sharp-edges`, `spec-to-code-compliance`, `fp-check`; Anthropic `pr-review-toolkit` agents `silent-failure-hunter`, `comment-analyzer`, `pr-test-analyzer`, `type-design-analyzer`; dzhng `find-overengineering`, `audit-tests`, `audit-decisions`.

**What makes these prompts work** (common to the sources above): one concept per run; a named scope; read-only; evidence as `file:line`; confirmed versus inferred; a second pass that tries to refute each finding (also the "Verify" stage of Anthropic's managed Code Review); and an artefact that feeds a gate.

**Shared preamble for every prompt in the library:**

> Read-only audit of `<scope>`. Do not edit. For each finding give file:line evidence, mark it CONFIRMED (code proves it) or INFERRED, rate severity, state the smallest fix, and name the test, type or lint that would stop it recurring. Output JSON to `audits/<id>/<date>.json` (schema `findings.v1`) and a short Markdown summary. If you find nothing, say so; do not invent findings. Then spawn a verifier that tries to refute each finding and drop any it refutes.

**Library.** Trigger: W = weekly rotation, D = on PR when matching paths change, M = monthly, R = pre-release. Auto: A = find and open fix PR unattended; F = find unattended, fix needs lead-agent or human approval.

| ID | Core question | Trigger | Auto | Artefact beyond findings JSON |
|---|---|---|---|---|
| P01 implicit-state-machines | Find every lifecycle whose state, transitions and ownership are scattered across flags, nullable fields, timestamps, callbacks and async tasks. Give states, events, transition table, owner, representable-but-illegal states, and every non-terminal state with no guaranteed exit (failure, cancel, timeout, restart). | W, D on lifecycle modules | F | `docs/state-machines/<name>.md` with Mermaid diagram; Quint spec stub; enum or typestate proposal |
| P02 dual-sources-of-truth | Find every fact stored or derived in more than one place. Name the authority and show how the copies can diverge. | W | F | Table of fact, copies, authority, sync path |
| P03 unenforced-invariants | List invariants the code assumes but nothing enforces ("must", "always", "never", test-only asserts). | W | F | Invariant register; proptest or Kani harness stubs |
| P04 illegal-states | Find types whose field combinations can be invalid (paired `Option`s, bool sets). | D | A | Sum-type refactor PR |
| P05 primitive-obsession | Find domain concepts carried as strings or integers (tenant, agent, policy version, path). | M | A | Newtype PR |
| P06 scattered-rules | Find one business or policy rule implemented in several places; show the differences. | W | F | Rule map |
| P07 swallowed-errors | Find `let _ =`, `.ok()`, `unwrap_or_default()`, empty `catch`, log-and-continue. Classify each as deliberate or a bug. | D | A | Fix PR; clippy lint additions |
| P08 fail-open-defaults | For every enforcement point: on error, timeout, missing config or parse failure, does it allow or deny? | D on policy paths, R | F | Fail-mode table per enforcement point |
| P09 panic-paths | Find `unwrap`, `expect`, indexing, arithmetic and `unreachable!` reachable from untrusted input. | D | A | Fuzz target list |
| P10 error-taxonomy | Are errors typed, do they carry context, is retryable separated from fatal, do user-facing errors leak internals? | M | F | Error catalogue |
| P11 partial-failure | Find multi-step operations with no rollback or compensation. | M | F | Step/compensation table |
| P12 retry-storms | Find retries without backoff, jitter, budget or idempotency key. | M | A | Fix PR |
| P13 unbounded-resources | Find unbounded channels, queues, maps keyed by untrusted values, caches without eviction, unlimited spawns, recursion, regex, decompression, body sizes. | W, D | F | Limits register with value and owner per bound |
| P14 blocking-on-deadline-paths | List every path with a latency budget (pre-action decision, event consumer, UI thread). Find blocking I/O, sync locks across `.await`, DNS, model calls on it. | D, R | F | Budget table per path; benchmark targets |
| P15 timeouts-and-cancellation | Find every network, IPC or subprocess call without a timeout; check cancel-safety of each `select!` branch. | W | A | Fix PR |
| P16 backpressure | For each pipeline stage: when the sink is slow, does it block, drop or grow? Is every drop counted? | M | F | Drop-policy table; metrics list |
| P17 resource-leaks | Find handles, tasks, temp files, child processes and kernel objects not released on every path. | M | F | Ownership table |
| P18 trust-boundaries | Enumerate every point where untrusted data enters (network, IPC, files, env, tool output, model output, hook stdin, kernel events), where it is validated, and where it is parsed twice. | M, D on parsers | F | Trust-boundary map; fuzz target list |
| P19 tenant-boundary-leaks | For every query, cache key, queue topic, log line, metric label, file path and background job: is the tenant in the key, and does it come from the auth context rather than the request? | D on storage and API, R | F | Tenant-isolation matrix; isolation test stubs |
| P20 authz-coverage | Map every handler to its policy check. Find handlers with none and checks that run after side effects. | D | F | Handler/check matrix (CI-diffable) |
| P21 secret-handling | Find secrets reaching logs, `Debug` output, errors, crash reports or telemetry; missing zeroisation; non-constant-time comparison. | W | F | Redaction lint rules |
| P22 sharp-edges | Find APIs and config that are easy to misuse: boolean parameters, stringly-typed options, dangerous defaults. | M | F | API hardening list |
| P23 data-becomes-instructions | Find every place data becomes instructions: prompt assembly, tool descriptions, shell strings, SQL, paths. | D | F | Injection-sink register |
| P24 unsafe-audit | For each `unsafe` block and FFI call: stated invariant, who upholds it, Miri coverage. | M | F | Unsafe register |
| P25 privilege-surface | What runs as root or SYSTEM, and what can an unprivileged local user make it do (IPC, file permissions, update channel)? | R | F | Privilege map |
| P26 build-supply-chain | List build scripts, proc macros, install scripts, unpinned CI actions and network fetches at build time. | M | A | Pinning PR |
| P27 time-assumptions | Find wall-clock use in logic, timestamp-as-ordering, skew assumptions, TTL arithmetic, direct `now()` calls. | W | A | Clock-injection PR |
| P28 ordering-assumptions | Where does code assume in-order, exactly-once or timely delivery? What happens on duplicate, late or reordered events? | M | F | Delivery-assumption table; DST scenarios |
| P29 check-then-act | Find TOCTOU on files, paths and process identity (PID reuse), inconsistent lock order, locks held across `.await`. | D | F | Loom or Shuttle test stubs |
| P30 crash-consistency | For every durable write: what if the process dies between any two steps? Check fsync, atomic rename, recovery at startup, half-applied migrations. | M, R | F | Crash-point table; fault-injection tests |
| P31 startup-shutdown | Initialisation order, graceful shutdown, signal handling, what is flushed. | R | F | Sequence diagram |
| P32 version-skew | Old agent with new server and the reverse; schema evolution; downgrade; persisted formats. | R | F | Compatibility matrix; upgrade tests |
| P33 flag-explosion | Enumerate flags, config options and `cfg` features. Which combinations are untested, which never vary? | M | A | Flag register; deletion PR |
| P34 dead-code-and-workarounds | Find dead code and workarounds whose reason has gone. | W | A | Deletion PR |
| P35 duplicates | Find near-duplicate functions and parallel abstractions for one concept. | W | A | Consolidation PR |
| P36 lying-comments | Find comments, docs and README claims the code contradicts; change-log comments; examples that do not compile. | W | A | Fix PR |
| P37 overengineering | Find traits with one implementation, generics with one instantiation, compatibility code for nobody, guards on trusted input. | W | F | Rollback list |
| P38 effects-in-calculations | Find calculations mixed with I/O. | M | F | Functional-core refactor plan |
| P39 layering-violations | Compare the import graph with `ARCHITECTURE.md`; find cycles, god modules, over-wide public surface. | D | A | Violations feed the conformance test |
| P40 terminology-drift | One concept with several names; one name with several meanings. | M | F | Glossary diff |
| P41 test-theatre | Find tests that assert nothing, test mocks, mirror the implementation, or were weakened recently; `#[ignore]`, skips, sleeps. | W, D on tests | F | Test audit; mutation targets |
| P42 observability-gaps | Find failure paths with no log, metric or trace; missing tenant, agent and correlation IDs. | M | A | Instrumentation PR |
| P43 config-audit | Every config key and env var: default, validation, behaviour when invalid, documented or not. | R | A | Generated config reference |
| P44 decision-audit | List decisions the implementing agent made where the spec was silent, least confident first. | D (every agent PR) | A | `decisions.md` on the PR |
| P45 spec-to-code | Which requirements hold, which are contradicted, which are absent, what does the code do that no document mentions? | R | F | Compliance matrix |
| P46 platform-parity | Compare Windows, macOS and Linux implementations of each sensor trait; find stubs that return `Ok`. | R | F | Parity matrix |
| P47 dependency-justification | For each direct dependency: purpose, could std do it, maintenance, unsafe, build script. | M | F | Dependency register |
| P48 performance-cliffs | Find quadratic work, per-event allocation, clones and sync logging on hot paths. | M | F | Benchmark additions |

All 48 can run unattended in find mode. The ones marked F should not auto-merge fixes because the "bug" may be intended behaviour.

### Part 2: de-slopping

**What slop looks like in code** (drawn from desloppify's dimensions, dzhng and Compound Engineering skill descriptions, and `MrZoyo/deslop-GPT`): narration and change-log comments; defensive wrappers that swallow errors; fallbacks that hide failures; compatibility shims and migrations for a product with no users; one-implementation traits; near-copies instead of reuse; over-wide parameters; type assertions and `any`; "test bloat, verification theater, and speculative fallbacks"; stubs that return success; unrequested summary files. **In docs:** inflated adjectives, em-dash and rule-of-three rhythm, claims the code does not support.

**Evidence that it compounds.** GitClear's 2025 report (211M changed lines, 2020-2024): copy/pasted lines rose from 8.3% to 12.3% between 2021 and 2024 while refactoring-associated "moved" lines fell from 25% to under 10%. https://www.gitclear.com/ai_assistant_code_quality_2025_research

**Tools.**

| Tool | What it does | Notes |
|---|---|---|
| `peteromallet/desloppify` v1.0 (2026-05-13), 4.1k stars | Scan, score, LLM review, triage, fix loop. State in `.desloppify/`. Strict versus lenient score so `wontfix` cannot hide debt. `--profile ci` skips subjective phases. | Python 3.11+. Rust and TypeScript at "full plugin depth". No diff-only mode. Licence OSNL v0.2: free for internal use and for open-source companies. |
| Anthropic `code-simplifier` plugin; built-in `/simplify` | Simplify changed code, preserve behaviour. | `/plugin install code-simplifier@claude-plugins-official` |
| Anthropic `pr-review-toolkit` | Six agents including `comment-analyzer` and `silent-failure-hunter`. | Official marketplace |
| Compound Engineering `/ce-simplify-code` | "prune useless tests and comments before review". | v3.37.1, MIT |
| `dmmulroy/anti-slop` (6.0k stars) | Vendored Oxlint JS-plugin rules: `no-chained-type-assertions`, `no-module-mocking`, `no-widen-then-assert`, `require-safety-comment-for-type-assertion`, and others. | Meant to be copied and edited, not depended on |
| dzhng `find-overengineering`, `refactor-clean`, `ratchet-files` | Roll back speculative guards; replace rather than layer; pre-commit file-size ratchet so files stay readable in one pass. | `npx skills add dzhng/skills` |
| `blader/humanizer` (67k stars), `hardikpandya/stop-slop` | Prose. | Encode the same word lists as Vale rules for a deterministic gate |
| `peakoss/anti-slop` | GitHub Action that closes low-quality AI PRs. | Relevant once the project takes outside contributions |

Deterministic detectors to pair with these: ast-grep rules for narration and change-log comments, `cargo machete`/`cargo shear`, knip, clippy `allow_attributes_without_reason`, Vale.

### Part 3: skills, plugins and MCP servers

| Item | Install | Use |
|---|---|---|
| Anthropic official marketplace (`anthropics/claude-plugins-official`, Apache-2.0, auto-added) | `/plugin install <name>@claude-plugins-official` | `rust-analyzer-lsp`, `typescript-lsp`, `clangd-lsp`, `swift-lsp` (code intelligence); `pr-review-toolkit`; `code-simplifier`; `security-guidance` (regex warnings on edit, LLM diff review on Stop, agentic commit review); `claude-security` (deep scan with challenged findings); `hookify`; `claude-md-management`; `feature-dev`; `ralph-loop`; `plugin-dev`; `mcp-server-dev`; `math-proof` |
| Trail of Bits skills (8.1k stars, CC-BY-SA-4.0) | `/plugin marketplace add trailofbits/skills` | `rust-review` (unsafe boundary, concurrency, panic-DoS, FFI, async; SARIF), `insecure-defaults`, `sharp-edges`, `differential-review`, `fp-check`, `variant-analysis`, `static-analysis` (CodeQL, Semgrep, SARIF), `semgrep-rule-creator`, `mutation-testing`, `property-based-testing`, `spec-to-code-compliance`, `zeroize-audit`, `constant-time-analysis`, `supply-chain-risk-auditor`, `agentic-actions-auditor`, `c-review`, `writing-lean-proofs`, `second-opinion`, `trailmark`, `goal-prompt` |
| `trailofbits/claude-code-config` (2.1k stars) | Copy `settings.json`, hooks, CLAUDE.md template | Baseline: deny rules for credentials, two blocking Bash hooks, the anti-rationalisation Stop hook |
| `obra/superpowers` v7.0.2 (MIT) | Plugin marketplace | `test-driven-development`, `systematic-debugging`, `verification-before-completion`, `subagent-driven-development`, `writing-plans`, `using-git-worktrees` |
| `EveryInc/compound-engineering-plugin` v3.37.1 (MIT, 37 skills, 14 hosts) | `/plugin marketplace add EveryInc/compound-engineering-plugin` | brainstorm, plan, work, simplify, review, compound loop; learnings in `docs/solutions/`; "Compound Packs" for org-wide rules (experimental) |
| `openai/codex-plugin-cc` v1.0.6 (Apache-2.0) | `/plugin marketplace add openai/codex-plugin-cc`; `/plugin install codex@openai-codex` | `/codex:review`, `/codex:adversarial-review`, `/codex:rescue`: cross-model review |
| `mattpocock/skills` (MIT), `dzhng/skills` (MIT) | `npx skills add <repo>` | `improve-codebase-architecture`, `tdd`, `domain-modeling`; `find-state-machines`, `audit-tests`, `audit-decisions`, `write-spec`/`implement-spec` |
| Quint agent skills, `quint-llm-kit`, `quint-connect` (Apache-2.0) | `quint-co/quint/skills` | Write specs; replay spec traces against Rust |
| `oraios/serena` v2.1.0 | MCP; also in the official `external_plugins` | Symbol-level retrieval and editing over LSP. Application is GPL-3.0-or-later (SolidLSP part MIT): use as a dev tool, do not embed |
| `upstash/context7` (MIT) | MCP | Current library docs |
| `microsoft/playwright-mcp` v0.0.85, `ChromeDevTools/chrome-devtools-mcp`, `vercel-labs/agent-browser` (all Apache-2.0) | MCP / CLI plus skill | Browser tests and UI verification |
| ast-grep 0.51.1 (MIT), Semgrep 1.184.0 (LGPL-2.1 engine) | CLI | Structural lint and codemods; agents write rules cheaply |

Marketplace hygiene (Claude Code docs): third-party marketplaces do not auto-update by default; pin with `owner/repo#tag`; "A plugin can run hooks and MCP servers, so read the pane before you install".

### Part 4: hooks

Reference facts (https://code.claude.com/docs/en/hooks, fetched 2026-11-09):
- Exit 0 = success; exit 2 = block on events that support it; other codes are non-blocking unless `onFailure: "block"`.
- `PreToolUse` returns `hookSpecificOutput.permissionDecision` `allow|deny|ask|defer`; deny and ask rules still apply after a hook allows.
- `Stop` input includes `stop_hook_active`, `last_assistant_message`, `background_tasks`, `session_crons`. Cap of 8 consecutive continuations (`CLAUDE_CODE_STOP_HOOK_BLOCK_CAP`).
- `PreCompact` receives `trigger` and `custom_instructions`; its stdout becomes compaction instructions. `PostCompact` receives `compact_summary`.
- `additionalContext` is capped at 10,000 characters.
- On Windows `tool_input.file_path` uses backslashes: normalise before matching or a path check "can silently never match".
- `PostToolUse` for Bash can carry `tool_response.bashEditDiff` (v2.1.269+, beta, best effort).
- Default timeouts: 600 s command, 30 s prompt, 60 s agent.
- `allowManagedHooksOnly` and `disableAllHooks` exist in settings.

See the hooks specification under Implications.

### Part 5: quality toolchain

**Rust** (versions from GitHub releases): cargo-deny 0.20.2; cargo-vet 0.10.3; cargo-semver-checks 0.51.0; cargo-machete 0.9.2 and cargo-shear 1.14.0; cargo-nextest 0.9.151; insta 1.49.0; proptest; cargo-fuzz 0.13.2; Miri; loom 0.7.3 and `awslabs/shuttle`; Kani 0.68.0; cargo-mutants 27.1.0; cargo-llvm-cov 0.9.1; cargo-public-api 0.52.0; dylint 6.3.2; cargo-hack; cargo-careful; cargo-msrv; cargo-auditable; cargo-about; gungraun (formerly iai-callgrind), divan, criterion.
- cargo-mutants `--in-diff DIFF` "tests only mutants that overlap with regions changed in the diff"; a diff that only changes tests runs no mutants, and incremental runs do not replace full runs. https://mutants.rs/in-diff.html
- `cargo kani autoharness -Z autoharness` generates harnesses for functions with generable arguments. Experimental; 60 s timeout and unwind 20 by default; one monomorphisation only. https://model-checking.github.io/kani/reference/experimental/autoharness.html
- Clippy configuration (lint names from memory, unverified against current clippy): workspace `[workspace.lints]` denying `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro`, `indexing_slicing`, `arithmetic_side_effects`, `await_holding_lock`, `large_futures`, `undocumented_unsafe_blocks`, `let_underscore_must_use`, `map_err_ignore`, `allow_attributes_without_reason`; `clippy.toml` `disallowed-methods`/`disallowed-types` for layering and determinism.

**Dependency cooldowns.**
- Renovate 44: `minimumReleaseAge` applies per version; from Renovate 42 the default `minimumReleaseAgeBehaviour` is `timestamp-required`; the `crate` and `npm` datasources provide timestamps; "Security updates bypass any `minimumReleaseAge` checks". https://docs.renovatebot.com/key-concepts/minimum-release-age/
- Dependabot `cooldown`: `default-days` (3 if omitted), `semver-major-days`/`-minor-days`/`-patch-days`, `include`/`exclude` (150 each). Supports Cargo, npm, GitHub Actions (default-days only). Version updates only. https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference
- pnpm: `minimumReleaseAge` default 1440 minutes (non-strict unless set explicitly); `blockExoticSubdeps` default true; `trustPolicy: no-downgrade` available. https://pnpm.io/settings/dependency-resolution
- Cargo: only unstable `cargo generate-lockfile -Zunstable-options --publish-time <time>` (tracking issue rust-lang/cargo#16271).

**TypeScript.** `typescript@7.0.2` is `latest` on npm (7.1.0-beta exists); Biome 2.6.6; Oxlint 1.93.0; knip 6.44.2; dependency-cruiser 18.7.2; Vitest 5.1.0; Stryker 10.1.1 for mutation testing.

**Protobuf.** buf v1.75.0: `buf lint`, `buf breaking --against <base>`, `buf format --diff --exit-code` (flag details from memory, unverified).

**eBPF and C.** `aya-rs/aya` or libbpf-rs; kernel-matrix load tests in VMs with `cilium/little-vm-helper` or `danobi/vmtest`; `vbpf/prevail` is the verifier used outside Linux; ToB `c-review` and `modern-cpp` skills. Standard practice (unverified here): `BPF_PROG_TEST_RUN` unit tests, clang-tidy, ASan/UBSan on userspace C.

**Swift.** SwiftLint (19.8k stars, active), `swift-lsp` plugin; Swift 6 strict concurrency and Swift Testing (unverified here).

**Docs.** `cargo doc` with warnings denied, doctests, typos, lychee, Vale.

**Secrets, licences, vulnerabilities.** gitleaks 8.30.1 (MIT); trufflehog (AGPL-3.0); osv-scanner 2.7.1; cargo-deny (advisories, bans, licenses, sources); zizmor 1.32.0 for GitHub Actions.

**Formal methods agents can drive.**
- Cedar VGD: (1) executable Lean model with mechanised proofs, (2) differential random testing of production Rust against the model, (3) property tests where the model does not reach. 4 validator bugs found by proof, 21 more by DRT/PBT. `cedar-spec` holds `cedar-lean`, `cedar-drt` (run with `cargo fuzz run`), `cedar-policy-generators`. https://arxiv.org/abs/2407.01688, https://github.com/cedar-policy/cedar-spec
- Quint 0.33.1: simulator, Apalache-backed verification, agent skills, `quint-connect`.
- P (`p-org/P`, MIT, last push 2026-09). Verus and Aeneas (Rust to Lean) for proofs over Rust.

**Deterministic simulation.** turmoil 0.7.2 (network simulation for Tokio), shuttle (randomised schedules), loom (exhaustive, small models). `madsim` last pushed 2026-02: treat as stale.

**Gaming defences.**
- ImpossibleBench (arXiv 2510.20270, 2025-10-23): cheating rate on Conflicting-SWEbench was GPT-5 54%, Opus 4.1 50%, o3 49%. A strict prompt cut GPT-5 from 92% to 1% on the LiveCodeBench variant. An explicit "flag as impossible" option cut GPT-5 from 54% to 9%. Read-only tests preserve legitimate performance and block test edits but not special-casing or operator overloading. Allowing multiple submissions raised cheating from 33% to 38%.
- StrongDM software factory (2026-02-06): scenarios are "often stored outside the codebase", like a holdout set; "satisfaction" is the fraction of observed trajectories that likely satisfy the user; third-party services are cloned as a "Digital Twin Universe". https://factory.strongdm.ai/
- Anthropic managed Code Review reads `REVIEW.md` "from the base or default branch and never from the pull request's own changes", and reviews without building or running code.

## Matrix

| Mechanism | Catches | Deterministic | Agent can game it by | Counter |
|---|---|---|---|---|
| Format, lint, typecheck hooks | Syntax, style, type errors | Yes | Adding suppressions | Suppression ratchet; `allow_attributes_without_reason` |
| Unit tests | Regressions | Yes | Editing tests, special-casing | Protected paths; mutation; held-out suite |
| Snapshot tests | Output drift | Yes | Accepting snapshots | Block accept commands; snapshot diffs reviewed by a different model |
| Property tests, fuzzing | Unknown inputs | Seeded | Weak properties | Differential oracle (reference model) |
| Mutation testing | Tests that assert nothing | Yes | Hard | Ratchet the score per crate |
| Held-out acceptance | Spec violations | Mostly | Cannot see it | Keep outside the repo; never echo failures verbatim |
| LLM review | Design, logic | No | Persuasive PR text | Verify stage; cross-model; instructions from base branch |
| Model checking, proofs | Design bugs | Yes | Weakening the spec | Specs are protected paths |
| Power-prompt audits | Structural debt | No | n/a | Refuting verifier; findings become lints or tests |

## Weak points, gaps and risks

- Hook coverage has holes: Bash edits bypass `Edit|Write` matchers, `bashEditDiff` is beta and best-effort, timeouts fail open by default, the Stop cap ends the turn after 8 blocks.
- Hooks are Claude Code specific. Codex and Cursor need their own adapters; only skills are portable.
- LLM monitors miss about half of sophisticated test gaming on realistic tasks.
- desloppify: custom licence, Python runtime, whole-codebase scans only, subjective phases are non-deterministic.
- Trail of Bits skills are CC-BY-SA-4.0: install them as plugins; vendoring modified copies triggers share-alike. Serena is GPL-3.0-or-later.
- Scheduled tasks are research preview, tied to one person's account, with a one-hour minimum interval. Managed Code Review is Team/Enterprise, GitHub only, and cannot run self-hosted.
- No native Cargo cooldown; TLC stable is two years old; Kani autoharness is experimental; madsim is stale.
- Every plugin, skill and MCP server we install is itself part of the attack surface our product exists to police.
- Star counts for `obra/superpowers` (315k), `mattpocock/skills` (320k) and `anthropics/skills` (191k) are as the API returned them; popularity is not a quality signal.

## Implications for our design

### Hooks specification

All hook scripts are one cross-platform binary (`xtask hook <event>`) called in exec form (`args`), normalising backslashes, with `onFailure: "block"` on enforcement hooks.

| Event (matcher) | Recipe |
|---|---|
| `SessionStart` (`startup\|resume`) | Emit branch, dirty files, open task ledger, the invariants digest from `ARCHITECTURE.md`, and the last failing gate. Write toolchain pins to `CLAUDE_ENV_FILE`. |
| `SessionStart` (`compact`) | Re-inject the state file written by `PreCompact`. |
| `PreToolUse` (`Edit\|Write`) | Deny edits to `acceptance/**`, `tests/golden/**`, `**/*.snap`, applied `migrations/**`, `specs/**`, `deny.toml`, `clippy.toml`, `supply-chain/**`, `.github/workflows/**`, `.claude/**`, lockfiles. The reason names the waiver path. |
| `PreToolUse` (`Bash`, with `if` rules) | Deny `rm -rf`, force push and push to main, `--no-verify`, `git reset --hard`, publish commands, pipe-to-shell, snapshot acceptance (`cargo insta accept`, `INSTA_UPDATE=always`, `vitest -u`), and the wrong package manager. |
| `PostToolUse` (`Edit\|Write`) | Format the file (rustfmt, Biome). Run file-scoped checks: ast-grep project rules, `biome check`, `buf lint` for `.proto`, typos. Flag new suppressions (`#[allow`, `@ts-ignore`, `#[ignore]`, `todo!`). Return `decision: "block"` with diagnostics. LSP plugins supply type diagnostics. |
| `PostToolUse` (`Bash`) | If `bashEditDiff` lists a protected path, block and instruct a revert. |
| `PostToolBatch` | `cargo check` for touched crates and `tsc --noEmit` once per batch. |
| `Stop` | Command hook: if `background_tasks` is non-empty, allow. Otherwise run `just verify-fast` and exit 2 with the failing output. Then a prompt hook (the ToB anti-rationalisation gate) rejects "pre-existing", "out of scope", "follow-up" excuses; it must demand raw JSON. |
| `SubagentStart` | Inject scope, protected paths and output contract. |
| `SubagentStop` | Agent hook: check that claimed files exist and that `agent_transcript_path` contains the test command the subagent says it ran. |
| `TaskCompleted` | Exit 2 unless the task has an evidence artefact. |
| `PreCompact` | Write plan, decisions ledger, open findings, touched files and verifying commands to `.agent/state/<session>.md`; print "preserve failing tests, invariants and decisions" as compaction instructions. |
| `ConfigChange` | Block mid-session changes to hooks and permissions; log them. |
| `FileChanged` (`Cargo.toml\|package.json`) | Regenerate code and reload env. |
| `WorktreeCreate` | Bootstrap caches and dependencies. |
| `SessionEnd` | Flush the ledger; append candidate learnings. |

Ship the same policy as managed settings with `allowManagedHooksOnly` for organisations.

### CI quality-gate specification

- **Pre-commit:** format, typos, gitleaks, ast-grep, file-size ratchet.
- **PR, required, under about 10 minutes:**
  - Rust: `cargo fmt --check`; clippy with warnings denied; nextest; `cargo deny check`; machete or shear; `cargo doc` warnings denied; semver-checks and public-api diff on published crates; insta with updates off.
  - TypeScript: `tsc --noEmit` (TS 7), Biome or Oxlint with the vendored anti-slop rules, knip, dependency-cruiser, Vitest.
  - Protobuf: `buf lint`, `buf breaking`, `buf format`.
  - Cross-cutting: Semgrep and ast-grep rules, osv-scanner, zizmor, lychee, Vale.
  - Anti-gaming: `cargo mutants --in-diff`; patch coverage; architecture conformance test (allowed crate edges from `cargo metadata`, cargo-deny `bans` wrappers, dylint lints); ratchets (suppressions, ignored tests, assertion count, file size, mutation score may only improve); held-out acceptance run from a separate repository with only pass/fail returned; LLM review plus a cross-model second opinion, both reading instructions from the base branch.
- **Nightly:** Miri on unsafe crates; loom and shuttle; long proptest runs; time-boxed fuzzing with a persisted corpus; Kani harnesses; full sharded cargo-mutants; DST seed sweep; Quint model check and `quint-connect` trace replay; differential fuzzing of the policy evaluator against its reference model; proofs build; `cargo vet`; eBPF load across a kernel matrix; OS matrix; benchmarks (instruction counts via gungraun as a hard gate, wall-clock as a trend).
- **Release:** version-skew upgrade and downgrade tests, SBOM, `cargo auditable`, licence report, signed artefacts.
- **Dependency policy:** Renovate with `minimumReleaseAge` 7 days (14 for majors), security updates immediate, timestamps required; pnpm `minimumReleaseAge` matched and strict; actions pinned by SHA; crates.io as the only source; `cargo vet` with imported audits.

### Design rules that make the gates possible

- Inject clock, randomness, network and filesystem behind traits from the first commit, and ban direct calls with `disallowed-methods`. Without this, DST and time-assumption fixes are retrofits.
- Give the policy evaluator and every parser a small executable reference model and a differential fuzz target. If Cedar is the policy language, reuse its model and generators.
- Every state machine found by P01 becomes an enum plus a transition function plus a Quint spec; the spec directory is a protected path.
- Findings from any audit are closed only by a type, test or lint, never by a comment.

### Schedule of recurring maintenance agents

| Cadence | Agent | Does |
|---|---|---|
| Every PR | Reviewer, cross-model reviewer, security reviewer, simplifier, decision auditor (P44) | Comments, `decisions.md`, simplification commit |
| Nightly | Failure triager | Minimise fuzz, DST and Miri failures; open issue with regression test |
| Nightly | Mutant killer | Write tests for surviving mutants; may not touch `src/` |
| Nightly | Dependency groomer | Review Renovate PRs past cooldown, read changelogs, run `cargo vet` diffs |
| Nightly | Slop loop | `desloppify next` for a fixed budget; PRs capped in size |
| Weekly | Audit rotation | Four to six power prompts per week so all 48 run about every two months; P08, P19, P20 run on every relevant PR as well |
| Weekly | Doc drift (P36, P43), flaky-test hunter, suppression burn-down, benchmark trend report | Fix PRs and a trend issue |
| Weekly | Rules gardener | Turn repeated review findings into CLAUDE.md rules, hooks, ast-grep rules or lints |
| Monthly | Threat-model refresh (P18, P23, P25), unsafe audit (P24), dependency justification (P47), toolchain bump, plugin and skill update review, hook efficacy review | Reports and upgrade PRs |
| Per release | Spec-to-code (P45), platform parity (P46), version skew (P32), crash consistency (P30) | Release-blocking matrices |

Every maintenance agent is read-only by default, has a token and diff budget, goes through the same gates, and cannot edit gate configuration.

## Ideas worth stealing and whitespace

- **Refuting verifier per finding** (ToB `insecure-defaults`, `fp-check`; Anthropic's Verify stage). Make it mandatory for every audit.
- **Decisions, not diffs** (dzhng `audit-decisions`): review the choices the agent made where the spec was silent.
- **Strict versus lenient score** (desloppify): waivers stay visible as a gap.
- **Reviewer instructions from the base branch** so a PR cannot rewrite its own reviewer.
- **File-size ratchet** so every file fits in one read.
- **"Flag as impossible" escape hatch**: give agents a sanctioned way to say the test and the spec conflict; it cut cheating from 54% to 9% for GPT-5.
- **Whitespace:** nobody ships audit findings as a typed, versioned ledger that auto-generates lints and tests; no cross-harness hook standard exists; there is no open mutation-plus-held-out "anti-gaming" gate packaged for agent PRs; no deterministic Rust-comment slop linter. Our own product can dogfood all four, and the hook policy above is the same enforcement surface the product sells.

## Could not verify / open questions

- The original author and date of the "find all of the implicit state machines" prompt (web search unavailable).
- The CACM article on AWS systems-correctness practices returned HTTP 403.
- Clippy lint names, buf flags, eBPF test practice and Swift tooling details are from memory.
- Whether the Rune UI framework has snapshot or accessibility test tooling was not researched.
- Whether desloppify's OSNL permits use inside a hosted CI service we operate for others needs a legal read.
- Per-model ImpossibleBench figures beyond those quoted are only in the paper's figures.
- Codex and Cursor hook equivalents were not researched here.

## Sources

- Claude Code hooks reference, https://code.claude.com/docs/en/hooks (fetched 2026-11-09)
- Claude Code hooks guide, https://code.claude.com/docs/en/hooks-guide (2026-11-09)
- Claude Code scheduled tasks, https://code.claude.com/docs/en/routines (2026-11-09)
- Claude Code Code Review, https://code.claude.com/docs/en/code-review (2026-11-09)
- Claude Code plugin install docs, https://code.claude.com/docs/en/discover-plugins (2026-11-09)
- Anthropic official plugins, https://github.com/anthropics/claude-plugins-official (pushed 2026-11-10)
- Trail of Bits skills, https://github.com/trailofbits/skills (2026-11-06); config, https://github.com/trailofbits/claude-code-config (2026-08-24)
- superpowers, https://github.com/obra/superpowers (v7.0.2, 2026-11-03)
- Compound Engineering, https://github.com/EveryInc/compound-engineering-plugin (v3.37.1, 2026-11-09)
- Codex plugin for Claude Code, https://github.com/openai/codex-plugin-cc (v1.0.6, 2026-07-08)
- dzhng skills, https://github.com/dzhng/skills (2026-11-08)
- Agentic coding design patterns, https://github.com/mokevnin/agentic-coding-design-patterns (2026-11-07)
- dyad state-machine plan, https://github.com/dyad-sh/dyad/blob/main/plans/codex-correct-state-machines.md (2026-07-28)
- desloppify, https://github.com/peteromallet/desloppify (v1.0, 2026-05-13)
- anti-slop Oxlint rules, https://github.com/dmmulroy/anti-slop (2026-10-14)
- GitClear 2025 report, https://www.gitclear.com/ai_assistant_code_quality_2025_research
- ImpossibleBench, https://arxiv.org/abs/2510.20270 (2025-10-23)
- StrongDM software factory, https://factory.strongdm.ai/ (2026-02-06)
- Cedar VGD paper, https://arxiv.org/abs/2407.01688; cedar-spec, https://github.com/cedar-policy/cedar-spec
- Quint, https://github.com/quint-co/quint (v0.33.1, 2026-10-28)
- Kani autoharness, https://model-checking.github.io/kani/reference/experimental/autoharness.html
- cargo-mutants in-diff, https://mutants.rs/in-diff.html
- Renovate minimum release age, https://docs.renovatebot.com/key-concepts/minimum-release-age/
- Dependabot options, https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference
- pnpm dependency resolution settings, https://pnpm.io/settings/dependency-resolution
- Cargo unstable features, https://doc.rust-lang.org/nightly/cargo/reference/unstable.html
- Serena, https://github.com/oraios/serena (v2.1.0, 2026-10-19)
- Tool release versions: GitHub Releases API for each repository named above (queried 2026-11-09)

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (shared budget exhausted), so checks used direct fetches of primary docs, the GitHub API and repository source files. Two claims need correcting before the architecture relies on them: Cargo cooldown (claim 4) and the ImpossibleBench monitor figure (claim 3). Two further statements in the hooks section also need correcting (rows A and B)._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude Code has 33 hook events and five handler types; PreToolUse can deny; Stop can force continuation; Stop capped at 8 consecutive continuations | Confirmed | The event table lists 33 names; handler types are `command`, `http`, `mcp_tool`, `prompt`, `agent` (agent is marked experimental). The cap counts continuations in a row and resets each time Claude calls a tool; `CLAUDE_CODE_STOP_HOOK_BLOCK_CAP` raises it. The changelog dates the cap to v2.1.143 and `mcp_tool` hooks to v2.1.118. | https://code.claude.com/docs/en/hooks ; https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md |
| 2 | Command hooks fail open on non-2 exits and timeouts unless `onFailure: "block"` (v2.1.295+); Windows `file_path` arrives with backslashes | Confirmed, with limits | Changelog 2.1.295 adds `onFailure: "block"` for command and HTTP hooks only. It has no effect on `Stop`, `SubagentStop`, `TaskCompleted`, `TeammateIdle` or async hooks. A timed-out `PreModelSwitch` hook blocks by default. The docs say a forward-slash check "never matches a backslash path" on Windows. | https://code.claude.com/docs/en/hooks ; https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md |
| 3 | ImpossibleBench: GPT-5 54% and Opus 4.1 50% on Conflicting-SWEbench; read-only tests block edits but not special-casing; monitors flagged only 42-50% on the SWE-bench variant | Corrected | The cheating rates and the read-only finding hold. The monitor figure is partial: 42-50% is the Claude Sonnet 4 monitor; the Claude Opus 4 monitor reached 57-65%. The paper's own summary is 42-65% on Impossible-SWEbench and 86-89% on Impossible-LiveCodeBench. "Miss about half" should read "miss a third to more than half, depending on the monitor model". | https://arxiv.org/html/2510.20270v1 (sections 1 and 6) |
| 4 | Cargo has no stable dependency cooldown; the only related feature is unstable `generate-lockfile --publish-time` (#16271) | Corrected | Cargo has a second, more relevant feature: `min-publish-age` (RFC 3923, tracking issue #17009, closed 2026-08-28). The stabilisation PR #17335 merged 2026-08-28 with milestone 1.100.0, and the beta and nightly Cargo books say it "was stabilized in Rust 1.100". The newest release today is 1.99.1 (2026-10-16), where it is still `-Zmin-publish-age`; 1.100.0 is due within days on the six-week train. Keys: `registry.global-min-publish-age = "14 days"`, `registries.<name>.min-publish-age`, `resolver.incompatible-publish-age`. Known gaps: no default value (#17254), no check that already-locked versions are old enough (#17246), `cargo update` can downgrade locked versions (#17642). The plan should set this in `.cargo/config.toml` alongside Renovate. | https://doc.rust-lang.org/beta/cargo/reference/unstable.html#min-publish-age ; https://doc.rust-lang.org/beta/cargo/reference/resolver.html#publish-age ; https://github.com/rust-lang/cargo/pull/17335 ; https://github.com/rust-lang/cargo/issues/17009 |
| 5 | Renovate `minimumReleaseAge` works for `crate` and `npm`, requires timestamps by default since v42, and security updates bypass it; Dependabot cooldown defaults to 3 days and supports Cargo, npm, GitHub Actions | Confirmed | Renovate source has `minimumReleaseAgeBehaviour` default `timestamp-required`; the docs say Renovate 42 changed the default and that security updates bypass the check. `crate` support is listed for crates.io only. Latest Renovate is 44.225.1. Dependabot applies the 3-day default even with no `cooldown` block; GitHub Actions supports `default-days` only; security updates are exempt. | https://github.com/renovatebot/renovate/blob/main/lib/config/options/index.ts ; https://github.com/renovatebot/renovate/blob/main/docs/usage/key-concepts/minimum-release-age.md ; https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference |
| 6 | Cedar VGD: Lean model with proofs, DRT of the Rust code against the model, property tests; 4 bugs by proof, 21 by DRT and PBT | Confirmed | The abstract gives both numbers. `cedar-spec` holds `cedar-lean`, `cedar-drt` and `cedar-policy-generators`; DRT runs with `cargo fuzz run`. The model was first written in Dafny and later ported to Lean. The cedar-spec README says the DRT build "has only been tested on Amazon Linux 2", which matters for a cross-platform CI. | https://arxiv.org/abs/2407.01688 ; https://github.com/cedar-policy/cedar-spec ; https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing |
| 7 | desloppify v1.0: Rust and TypeScript at full depth, CI profile, OSNL v0.2 licence, no diff-only mode | Confirmed | v1.0 published 2026-05-13. The README lists full plugin depth for TypeScript, Python, C#, C++, Dart, GDScript, Go and Rust, documents `--profile ci`, and says diff-only scanning "is not the supported model yet". LICENSE is "Open Source Native License (OSNL) Version 0.2"; GitHub reports no SPDX match. | https://github.com/peteromallet/desloppify (README, LICENSE) |
| 8 | Trail of Bits skills are CC-BY-SA-4.0; Serena application is GPL-3.0-or-later with SolidLSP under MIT | Confirmed | GitHub reports CC-BY-SA-4.0 for `trailofbits/skills`. Serena's LICENSE states the per-component split and `pyproject.toml` declares `GPL-3.0-or-later`; the combined `serena-agent` package is GPL as a whole. | https://github.com/trailofbits/skills ; https://github.com/oraios/serena/blob/main/LICENSE ; https://github.com/oraios/serena/blob/main/pyproject.toml |
| 9 | Scheduled tasks (formerly routines): research preview, individual account, schedule/API/GitHub triggers, cron more frequent than hourly rejected | Confirmed | All four points are stated in the docs. Tasks can also be routed to an organisation's self-hosted environment, and the API trigger still uses a `routine` beta header. | https://code.claude.com/docs/en/routines |
| 10 | `cargo mutants --in-diff` tests only mutants overlapping the diff, runs none for test-only diffs, does not replace full runs | Confirmed | Matches the book source in the repository. Latest release is v27.1.0 (2026-06-02). | https://github.com/sourcefrog/cargo-mutants/blob/main/book/src/in-diff.md |
| A | Hooks specification: "`onFailure: "block"` on enforcement hooks" | Corrected | `onFailure` is ignored on `Stop`, `SubagentStop`, `TaskCompleted` and `TeammateIdle`, and is not offered for `mcp_tool`, `prompt` or `agent` hooks. The Stop gate that runs `just verify-fast` therefore fails open if the script crashes or exceeds its timeout (600 s default). The script must catch its own errors and exit 2, and CI must remain the real gate. | https://code.claude.com/docs/en/hooks |
| B | "`additionalContext` is capped at 10,000 characters" | Corrected | Text over 10,000 characters is not dropped: Claude Code writes it to a file and passes the path with a preview of the first 2,000 characters. Only PreCompact stdout is cut at 10,000 characters. | https://code.claude.com/docs/en/hooks |
| C | "TLA+ TLC's last stable release is v1.7.4 from August 2024" | Confirmed | v1.7.4 (2024-08-05) is still the newest non-prerelease. A v1.8.0 pre-release was published on 2026-11-06, so this may change soon. | https://github.com/tlaplus/tlaplus/releases |

Also spot-checked and found correct: `typescript@7.0.2` is `latest` on npm with `7.1.0-beta`; pnpm `minimumReleaseAge` default 1440 minutes, non-strict unless set, `blockExoticSubdeps` default true; Kani autoharness defaults (60 s, unwind 20, experimental); managed Code Review facts (Team and Enterprise, GitHub including GitHub Enterprise Server, `REVIEW.md` from the base branch, no build or run, not in self-hosted environments).
