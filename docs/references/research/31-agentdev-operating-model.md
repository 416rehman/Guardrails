# Operating model for a product built entirely by AI agents

_Researched 2026-11-09_

Method note: the shared web-search budget for this run was already exhausted, so nothing here comes from search results. Everything was read directly from primary pages (WebFetch, one browser read for the OpenAI post that returned 403) and from the GitHub API. Items I could not reach are listed at the end. "Verified" means I read it in the cited source today; "inferred" is my synthesis.

## TL;DR

- **Two topologies have public evidence of working at scale; flat peers with locks is not one of them.** Cursor: 20 lock-coordinated peers ran at the throughput of 2-3 and became risk-averse; the working design is recursive planners, isolated workers, handoffs, and no integrator role. Anthropic's C compiler did work with 16 flat peers and lock files, but only because the task had thousands of independent failing tests and a GCC oracle.
- **Cognition's April 2026 rule is the safest default for real software: writes stay single-threaded per change; extra agents contribute intelligence (search, review, advice), not parallel edits to the same thing.**
- **The repository is the only memory.** OpenAI's zero-human-code product (about 1M LOC, about 1,500 PRs in five months) uses a roughly 100-line AGENTS.md as a table of contents into a linted `docs/` tree; one giant AGENTS.md failed.
- **Architecture is enforced by custom linters and structural tests whose error messages contain the fix**, not by documentation. OpenAI calls this an early prerequisite, not a scale-up luxury.
- **Separate generator from evaluator, and give the evaluator clean context.** Anthropic: self-grading agents "confidently praise" mediocre work; a tuned separate evaluator with hard thresholds is the lever. Devin Review (diff-only context) catches about 2 bugs per PR, about 58% severe.
- **Evaluators are worth their cost only beyond what the model does reliably solo.** Anthropic removed sprints and per-sprint QA when moving to Opus 4.6. Re-test every harness component per model generation.
- **Test gaming is real and has mechanical counters:** immutable test/acceptance files agents may only flip `passes` on, expected-result-before-action logging, oracle comparison, and independent evaluators that drive the real artefact.
- **Entropy needs scheduled garbage collection.** OpenAI spent 20% of human time cleaning "AI slop" until they encoded "golden principles" and ran recurring cleanup agents that open small auto-mergeable PRs.
- **Cost reference points:** C compiler about $20,000 (2B input / 140M output tokens, about 2,000 sessions, two weeks); a planner-generator-evaluator app build $125-200 versus $9 solo; Claude Code agent teams use about 7x tokens in plan mode; workflows cap at 16 concurrent / 1,000 agents per run by default.
- **Unattended agents need an OS boundary, not just a permission mode.** Claude Code docs: bypass mode only inside a container/VM; auto mode is a per-action classifier, not isolation. Cloud sessions keep the GitHub token outside the VM behind a proxy.
- **GitHub-hosted macOS arm64 runners cannot nest virtualisation**, so system-extension tests need self-hosted Mac hosts with VMs; Windows and Linux runners (x64 and arm64) are free for public repositories.
- **Open-source building blocks exist for every layer** (Beads for claimable work graph, Symphony spec for issue-driven dispatch, gh-aw for sandboxed CI agents, superpowers/compound-engineering for skills), all MIT or Apache-2.0 except claude-squad (AGPL-3.0).

## Findings

### 1. Team topologies: what worked, what failed

**Flat peers with a shared coordination file and locks (failed at Cursor).** Agents held locks too long, crashed holding them, or edited the file without locking; "Twenty agents would slow down to the effective throughput of two or three." Optimistic concurrency fixed the mechanics but not the behaviour: with no hierarchy, agents avoided hard tasks and made small safe changes. [Cursor, Scaling long-running autonomous coding, Jan 2026](https://cursor.com/blog/scaling-agents)

**Cursor's five-step evolution** ([Self-driving codebases, 2026-02-05](https://cursor.com/blog/self-driving-codebases)): single agent (lost track, declared success early) -> self-coordination (above) -> planner/executor/workers/judge (bottlenecked by slowest worker) -> continuous executor (role overload: slept, did work itself, refused to plan, claimed completion) -> **root planner that does no coding, recursive sub-planners, workers on their own repo copy returning a handoff to the requesting planner**. The integrator/quality-gate role was removed because it became the bottleneck. Peak about 1,000 commits/hour, about 10M tool calls in a week, several hundred agents on one machine. They accepted a small steady error rate and a final "green" pass, because requiring 100% correctness per commit serialised everything.

**Flat peers with lock files (worked at Anthropic, narrowly).** 16 Opus 4.6 agents, each in a Docker container, cloning a bare upstream repo; a task is claimed by writing `current_tasks/<name>.txt` and git rejects the second claimant; no orchestrator, no messaging. It broke down when the work became one giant task (the Linux kernel build): every agent hit the same bug and overwrote each other. Fix: use GCC as an oracle and compile a random subset of files with the new compiler so agents fail on different files. Specialised standing roles ran alongside: deduplicator, performance, code-quality critic, documentation. [Anthropic, Building a C compiler, Feb 2026](https://www.anthropic.com/engineering/building-c-compiler)

**Cognition's position** ([Don't Build Multi-Agents, 2025-06-12](https://cognition.com/blog/dont-build-multi-agents); [Multi-Agents: What's Actually Working, 2026-04-22](https://cognition.com/blog/multi-agents-working)): parallel writers make conflicting implicit decisions; unstructured swarms are "mostly a distraction"; the browser/compiler showcases depend on simple verifiable success criteria that most software lacks. What works: (a) generator plus clean-context reviewer loop; (b) "smart friend" consultation across frontier models (a weak primary escalating to a strong model failed); (c) manager/child "map-reduce-and-manage". Observed manager defects: over-prescriptive instructions, assuming shared state with children, children not reporting upward by default.

**Planner/generator/evaluator** ([Anthropic, Harness design for long-running apps, 2026-03-24](https://www.anthropic.com/engineering/harness-design-long-running-apps)): planner expands a short prompt into a product spec and stays high-level; generator builds; evaluator drives the running app through Playwright MCP against a negotiated "sprint contract" (27 criteria in one sprint) with hard per-criterion thresholds. Agents communicate through files.

**Huntley's loop** ([Ralph, 2025-07-14](https://ghuntley.com/ralph/); [loop, 2026-01-17](https://ghuntley.com/loop/)): a single monolithic `while` loop, one task per fresh context, argues agent-to-agent microservices are "a red hot mess". **Gas Town** is the opposite bet: Mayor coordinator, per-repo "rigs", ephemeral "polecat" workers with persistent identity, Witness/Deacon/Dogs watchdogs, a Refinery (Bors-style bisecting merge queue), severity-routed escalation; claims comfortable scale to 20-30 agents. [gastownhall/gastown README](https://github.com/gastownhall/gastown) (MIT, v1.2.1 2026-06-06).

**Product support in Claude Code (verified in docs today):** subagents nest to three levels, 20 concurrent by default; agent teams remain experimental (`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`), are interactive-only, have no nested teams, recommend 3-5 teammates, and "Two teammates editing the same file leads to overwrites"; dynamic workflows move the orchestration plan into a JavaScript script (`agent()`, `pipeline()`, `parallel()`), default 16 concurrent agents, 1,000 per run, resumable. [agent-teams](https://code.claude.com/docs/en/agent-teams), [sub-agents](https://code.claude.com/docs/en/sub-agents), [workflows](https://code.claude.com/docs/en/workflows)

### 2. Specifying, decomposing, claiming and tracking work

- **Feature list as contract.** Anthropic's initializer agent writes `feature_list.json` (200+ entries, each with steps and `"passes": false`); coding agents may change only `passes`; "It is unacceptable to remove or edit tests." JSON was chosen because models were less likely to rewrite it than Markdown. One feature per session. [Effective harnesses, 2025-11-26](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)
- **Execution plans in the repo.** OpenAI keeps `docs/exec-plans/{active,completed}/` with progress and decision logs, plus `tech-debt-tracker.md`. [Harness engineering, 2026-02-11](https://openai.com/index/harness-engineering/)
- **Issue tracker as dispatch queue.** OpenAI Symphony (Apache-2.0, spec "Draft v1", created 2026-02-26) polls a tracker, creates a per-issue workspace, runs one agent session per issue, keeps policy in a repo-owned `WORKFLOW.md`, holds a single authoritative `claimed` set, enforces `max_concurrent_agents` (default 10), `max_turns` (20), `stall_timeout_ms` (300000), and ends at a handoff state such as `Human Review`. Tracker credentials stay host-side and are not inherited by the agent process. [SPEC.md](https://github.com/openai/symphony/blob/main/SPEC.md)
- **Dependency graph with atomic claim.** Beads (MIT, v1.3.4 2026-11-04, now Dolt-backed): `bd ready` lists unblocked work, `bd update <id> --claim` atomically sets assignee and in-progress, old closed items are summarised ("memory decay"). [gastownhall/beads](https://github.com/gastownhall/beads)
- **Spec-driven tools.** Kiro: `requirements.md`/`bugfix.md` -> `design.md` -> `tasks.md`, tasks grouped into dependency "waves" run concurrently, property-based tests from specs ([Kiro specs](https://kiro.dev/docs/specs/)). OpenSpec (MIT, v1.17.0): one folder per change under `openspec/changes/<name>/` with proposal, spec deltas, design, tasks, then archive ([README](https://github.com/Fission-AI/OpenSpec)). GitHub Spec Kit (MIT, v1.3.3) and BMAD (v6.12.4) were confirmed as active via the API only.
- **Task sizing.** superpowers (MIT, v7.0.2) plans in 2-5 minute tasks with exact file paths and verification steps, then a fresh subagent per task with two-stage review (spec compliance, then code quality). Claude Code docs suggest 5-6 tasks per teammate. Cursor: "Generate 20-100 tasks" produced more ambition than "many".

### 3. Keeping context small and durable

- AGENTS.md about 100 lines as a map; knowledge in `docs/` (design docs with verification status, product specs, `references/*-llms.txt` for dependencies, `QUALITY_SCORE.md` grading each domain and layer); linters and CI check freshness and cross-links; a recurring doc-gardening agent opens fix PRs. "Anything it can't access in-context while running effectively doesn't exist." (OpenAI)
- Session start ritual: `pwd`, read git log and progress file, read feature list, run `init.sh`, run a smoke test before new work (Anthropic).
- Keep context at about 40-60% utilisation; compact into research and plan files; subagents exist mainly for context control (HumanLayer, [ACE-FCA](https://github.com/humanlayer/advanced-context-engineering-for-coding-agents/blob/main/ace-fca.md), about Aug 2025).
- Test harness output designed for agents: a few lines on stdout, details to log files, `ERROR` plus reason on one greppable line, precomputed summaries, `--fast` 1-10% sampled runs because agents are time-blind (C compiler).
- Claude Code: keep CLAUDE.md under 200 lines, move workflow instructions into skills, prefer CLIs over MCP for context cost. [costs](https://code.claude.com/docs/en/costs)
- Context resets versus compaction is model-dependent: required for Sonnet 4.5 ("context anxiety"), dropped for Opus 4.5+. Cursor still needs periodic fresh starts against drift.

### 4. Generator/evaluator separation and cross-model review

- Self-evaluation fails; out of the box Claude was also a poor QA agent that "talked itself into approving". Calibrate the evaluator with few-shot scored examples and hard thresholds (Anthropic).
- Clean-context review: reviewer sees only the diff and rediscovers context; the author agent then filters findings against user intent to prevent loops and scope creep (Cognition).
- OpenAI: the author agent requests "additional specific agent reviews both locally and in the cloud" and loops until all reviewers are satisfied; humans may review but are not required to.
- Anthropic internally (2026-07-21): several narrow review agents per PR, findings must carry proof of validity, new AI reviewers run in shadow mode first, every automated approval is logged with reasoning and a risk-weighted sample is human-reviewed; about 80% of merged code is Claude-authored. [Anthropic SDLC post](https://claude.com/blog/how-anthropic-secures-its-ai-native-software-development-lifecycle)
- Cross-model: Cognition runs Claude and GPT together in production as mutual "smart friends"; Cursor assigns models by role (a general model planned better than a coding-tuned one). Cognition notes same-model review is less self-correlated than a human reviewing their own work, so cross-model is an enhancement, not a prerequisite.
- Claude Code managed Code Review: parallel finders, a verification pass, severity ranking; reads `REVIEW.md` only from the base branch, never the PR; never approves or blocks. [code-review](https://code.claude.com/docs/en/code-review)

### 5. Mechanical architecture enforcement

OpenAI: fixed layers per domain (Types -> Config -> Repo -> Service -> Runtime -> UI), cross-cutting concerns only through a Providers interface, enforced by agent-written custom linters and structural tests; "taste invariants" (structured logging, naming, file size limits); lint messages inject remediation text. "Enforce boundaries centrally, allow autonomy locally." Claude Code offers the enforcement points: `PreToolUse` (allow/deny/ask/defer, `updatedInput`), `Stop`/`SubagentStop`, `TaskCreated`, `TaskCompleted`, `TeammateIdle`, `ConfigChange` hooks can block; handler types are command, http, mcp_tool, prompt, agent. [hooks](https://code.claude.com/docs/en/hooks)

### 6. Test gaming, duplication, drift, slop

- Gaming: placeholder implementations because "the reward is compiling code" (Huntley); marking features done after unit tests or curl only (Anthropic); executing JavaScript to force UI state instead of using the UI (Cognition, [Verifying agentic development, 2026-05-29](https://cognition.com/blog/testing-development)). Devin's counter: write the test plan from source first and record expected behaviour before each action.
- Duplication: ripgrep misses lead to re-implementation; instruct "do not assume not implemented" and run a deduplication role (Huntley, Anthropic).
- Drift: agents replicate existing patterns including bad ones; scheduled cleanup against golden principles (OpenAI). Cursor: constraints beat instructions ("No TODOs, no partial implementations"); unstated dependency rules let agents pull in libraries.
- Regression: new features kept breaking old ones until strict CI was added (C compiler).

### 7. Cost and model tiers

Verified data points: C compiler about $20k; harness run $124.70 (planner $0.46, three build rounds $113.85, three QA rounds $10.39) versus $9 solo that did not work; HumanLayer about $12k/month for three people on Opus; Claude Code enterprise average about $13 per developer per active day; agent teams about 7x tokens; workflow `Large workflow` warning above 25 agents or 1.5M projected tokens; subagent cache TTL is 5 minutes unless `subagentPromptCacheTtl: 1h`. Per-role model selection is native (`model:` and `effort:` in subagent frontmatter; `CLAUDE_CODE_SUBAGENT_MODEL`). `--max-budget-usd` exists for headless runs. Devin bills test mode at one-fifth during its trial.

### 8. Human consultation

OpenAI: humans prioritise, turn feedback into acceptance criteria, validate outcomes; the agent escalates "only when judgment is required"; every human correction is encoded into docs or lints, never hand-patched. HumanLayer: review research and plans (a bad research line yields thousands of bad code lines), not 2,000-line diffs, but still read tests. Claude Code auto mode pauses after 3 consecutive or 20 total classifier blocks; `ask` rules are the documented way to force human checkpoints.

### 9. Testing what cannot run locally

- GitHub-hosted standard runners are free for public repos: `ubuntu-24.04`/`-arm` (4 CPU, 16 GB), `windows-2025`, `windows-11-arm` (4 CPU, 16 GB), `macos-15`/`macos-26` arm64 (3 CPU, 7 GB), Intel macOS (4 CPU, 14 GB). macOS arm64: "Nested-virtualization is not supported due to the limitation of Apple's Virtualization Framework." [GitHub docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- Devin runs natively in its own Windows VM (beta, 2026-05-21) and builds, launches and clicks through Windows apps; drivers are not mentioned. [Cognition](https://cognition.com/blog/devin-is-getting-a-windows-pc)
- Tart (macOS/Linux VMs on Apple Silicon for CI): the GitHub API now resolves `cirruslabs/tart` to `openai/tart`; licence field is non-SPDX.
- OpenAI made the app bootable per worktree with an ephemeral observability stack per task, queryable with LogQL/PromQL. Cognition saves environment "blueprints" as VM snapshots.

### 10. Sandboxing the development agents

- Claude Code: built-in Bash sandbox (Seatbelt/bubblewrap; not native Windows) does not cover MCP servers or hooks; `@anthropic-ai/sandbox-runtime` (Apache-2.0, beta) wraps the whole process and denies writes to `.git/hooks`, `.mcp.json`, `.claude/agents` by default; dev container with default-deny firewall; VM for untrusted code. [sandbox-environments](https://code.claude.com/docs/en/sandbox-environments)
- Permission modes: `dontAsk` plus exact allowlist for CI; `auto` for long tasks (blocks `curl | bash`, force-push, prod deploys, merging unapproved PRs, disabling CI, launching bypass-mode loops); `bypassPermissions` only in an isolated non-root container/VM. Agent-to-agent messages cannot carry user consent. [permission-modes](https://code.claude.com/docs/en/permission-modes)
- Cloud sessions: isolated VM, default network allowlist, GitHub credential held by a proxy outside the VM, `claude/`-prefixed branches; scheduled tasks trigger on schedule, API or GitHub events, 100 scheduled runs/hour per account. [cloud](https://code.claude.com/docs/en/claude-code-on-the-web), [routines](https://code.claude.com/docs/en/routines)
- gh-aw (MIT, v1.0.1 2026-10-27): agent job read-only; writes buffered as `agent_output.json` and applied by separate `safe-outputs` jobs with scoped permissions; Agent Workflow Firewall (Squid egress allowlist); MCP gateway with per-server containers; a threat-detection job; `min-integrity` filtering of untrusted author content; compile to SHA-pinned `.lock.yml`. [gh-aw architecture](https://github.github.com/gh-aw/introduction/architecture/)
- Anthropic: engineers and agents work on remote VMs with egress allowlists; each agent has a single-purpose identity with minimal permissions; all agent actions go to the SIEM.

## Matrix

| Effort | Topology | Claim / tracking | Evaluator | Scale evidence | Main failure noted |
|---|---|---|---|---|---|
| OpenAI harness engineering | Humans steer single-writer agents per PR, agent reviewers | Exec plans in repo, PRs | Agent reviewers loop until satisfied; app driven via CDP | ~1M LOC, ~1,500 PRs, 5 months, 3->7 engineers | Slop/drift until GC agents; unknown multi-year coherence |
| Cursor | Root planner -> sub-planners -> isolated workers | Planner-owned tasks, handoffs | Removed judge and integrator; final green pass | ~1,000 commits/h, hundreds of agents | Locks, risk aversion, role overload |
| Anthropic C compiler | 16 flat peers plus specialist roles | Git lock files in `current_tasks/` | Test suites plus GCC oracle | 100k LOC, ~$20k | Collisions on monolithic tasks; regressions |
| Anthropic app harness | Planner / generator / evaluator | Sprint contract files | Separate QA with Playwright, hard thresholds | 4-6 h, $125-200 per app | Lenient evaluator until tuned |
| Cognition Devin | Single writer plus reviewer, smart friend, manager/children | Internal MCP | Clean-context Devin Review; test mode with recordings | ~2 bugs/PR caught | Weak-primary escalation; children silent |
| Gas Town | Mayor, polecats, watchdogs, merge queue | Beads graph, atomic claim | Refinery verification gates | Claims 20-30 agents | Not independently verified |
| Ralph loop | One agent, one task per loop | `fix_plan.md`, specs folder | Tests/types as backpressure | Single repo | Placeholders, duplicate implementations |

## Weak points, gaps and risks

- **Survivorship and incentive bias.** Every source is a vendor or practitioner reporting their own success. Cognition's critique of the showcases (clear oracles) is the most important corrective; a security product has few clean oracles.
- **None of the public efforts built kernel drivers, system extensions or signed installers.** The OS-sensor half of our product is outside the evidence base.
- **Niche stack risk.** OpenAI found agents do best with "boring" technology well represented in training data and sometimes reimplemented libraries rather than fight opaque ones. A new Rust UI framework is the opposite case.
- **Harness half-life.** Sprints, context resets and per-sprint QA became unnecessary within one model generation. Anything bespoke we build may be dead weight in months.
- **Single human bottleneck.** OpenAI's bottleneck became human QA; they had three to seven people. We have one.
- **Agent teams are still experimental** and cannot run headless; do not put them on the critical path.
- **Auto-fix and comment-triggered automation** post under the owner's GitHub identity and can trigger other workflows.
- **A security product built by agents is itself a supply-chain target**; prompt injection through issues, PR text and fetched docs reaches agents holding repo write access.

## Implications for our design

**Roles and reporting lines (single writer per work item).**
1. Owner (human): goals, risk tiers, taste, irreversible approvals.
2. Chief planner (top-tier model, no code): owns roadmap and decomposition into the work graph; spawns area planners (endpoint-windows, endpoint-macos, endpoint-linux, gateway, control plane, desktop UI, detection content).
3. Workers (mid-tier model): one per work item, own worktree/container, never coordinate with each other, return a structured handoff.
4. Evaluators (independent context; different model family where available): spec-compliance reviewer, security reviewer, behaviour QA that drives the real artefact.
5. Standing gardeners (scheduled, cheap tier): doc freshness, duplication, golden-principle sweeps, dependency and flaky-test triage.
6. Merge queue: deterministic software (bisecting queue), not an agent.

**Work-item lifecycle.** idea -> research note -> spec with acceptance criteria and a named oracle -> plan (tasks of minutes, exact paths) -> atomic claim -> implement in isolation with red/green tests -> local gates (lint, structure, tests) -> clean-context review plus behaviour QA with evidence -> merge queue -> remote matrix run -> compound step (learning recorded as a lint, skill or doc change) -> release train with a final all-green pass.

**Artefacts in the repository.** `AGENTS.md` (about 100 lines, map only) plus per-crate `AGENTS.md`; `ARCHITECTURE.md`; `docs/design-docs/` with index and verification status; `docs/decisions/` (ADRs, append-only); `docs/product-specs/`; `docs/exec-plans/{active,completed}/` with progress and decision logs; `docs/references/*-llms.txt` for every unusual dependency (the UI framework first); `docs/golden-principles.md`; `QUALITY_SCORE.md`; `acceptance/*.json` that workers cannot edit except the pass flag; `WORKFLOW.md` for the dispatcher; `.claude/agents/`, `.claude/skills/`, `.claude/workflows/`, hooks in `.claude/settings.json`; `REVIEW.md`.

**Human escalation rules.** Always ask: new dependency or licence, anything that touches signing keys, release, public API or wire-format breaks, kernel/driver/entitlement changes, changes to lints, CI, acceptance files or agent permissions, spend above budget, two failed evaluator rounds on the same item. Never ask: implementation choices inside an approved plan. Every escalation and every automated approval is written to the decision log with the evidence; the owner samples by risk tier rather than reading diffs.

**Cost and model-tier policy.** Top tier for planners, architecture review and the security reviewer; mid tier for workers and QA; small tier for search, log triage, gardening and classification. Set `model` and `effort` per subagent definition; cap concurrency (start at 3-5 writers); per-item token budget with automatic stop and escalation; run evaluators only on items above a risk or size threshold; re-benchmark each harness component on every model release and delete what no longer pays.

**Failure modes and mechanical countermeasures.**

| Failure | Countermeasure |
|---|---|
| Premature "done" | `TaskCompleted`/`Stop` hook runs gates; acceptance flag only flips after evaluator evidence |
| Test gaming | Tests and acceptance files in a path workers cannot write (PreToolUse deny plus CODEOWNERS-style CI check); expected-before-action logs; oracle and differential tests |
| Placeholders/TODOs | Lint that fails on `todo!()`, `unimplemented!()`, stub markers |
| Duplicate work | Atomic claims in the work graph; search-before-write rule; weekly dedup agent |
| Architectural drift | Crate dependency-direction lint, structural tests, lint messages with remediation |
| Stale docs | CI freshness and cross-link checks; doc-gardening schedule |
| Regressions | Bisecting merge queue; no direct pushes |
| Context rot | One task per session; progress file; handoff schema |
| Runaway cost or loops | Max turns, stall timeout, per-run budget, concurrency cap |
| Lenient reviewer | Clean context, few-shot calibration, hard thresholds, shadow mode before trust |
| Prompt injection into dev agents | Read-only agent jobs with buffered scoped writes; egress allowlist; integrity filter on untrusted authors |
| Credential leakage | Tokens held by proxy outside the sandbox; single-purpose identities; signing keys never reachable by agents |

**OS-level testing.** Treat the remote matrix as a tool: a `matrix-run` command that dispatches to runners and returns ten lines plus a log path. Use free hosted Windows and Linux runners for user-mode work; self-hosted VM pools with snapshot/revert for Windows driver test-signing and reboot cycles and for Linux kernel-version sweeps (inferred, not sourced); self-hosted Apple Silicon hosts running disposable macOS VMs for system extensions because hosted arm64 macOS runners cannot nest virtualisation. Keep sensor logic behind a platform trait so most of it tests on any OS with recorded event fixtures.

**Dogfood.** Run our own hooks, MCP/LLM gateway and endpoint sensor on the development agent fleet from day one; the build farm is the first customer and the first detection corpus.

## Ideas worth stealing and whitespace

- Lint errors as prompts (OpenAI); quality grades per domain tracked in the repo.
- Oracle-based parallelisation: sample a random subset under test, compare with a trusted reference (C compiler). For us: differential testing of sensors against existing OS audit sources.
- Expected-result-before-action logging and chaptered test videos as merge evidence (Cognition).
- Shadow-mode onboarding for new AI reviewers (Anthropic).
- Symphony's idea of shipping a language-agnostic SPEC that any agent can implement; publish our embeddable interfaces the same way.
- Whitespace: nobody publishes an operating model for agent-built kernel/driver code, signed-release pipelines with agents excluded from keys, or cross-OS VM test farms designed for agent-readable output. Nobody measures review quality over time (reviewer drift). An AIDR product that publishes telemetry from its own agent build farm would be unique.

## Could not verify / open questions

- Web search was unavailable; I did not survey newer orchestration tools beyond those named, nor Yegge's essays, Simon Willison's individual chapters (index only), GitHub Next "Continuous AI", or Every's guide beyond the Dec 2025 article.
- `web.archive.org` is blocked from this environment.
- Spec Kit and BMAD workflow details: only repository metadata verified.
- Kiro docs page did not mention EARS notation; unverified.
- KVM/nested virtualisation on hosted Linux runners: the page read does not say.
- The circumstances of `cirruslabs/tart` resolving to `openai/tart`, and its current licence terms.
- Claude Code self-hosted environments and cloud VM operating systems were not read in detail; whether cloud sessions can run Windows or macOS is unknown.
- Gas Town's 20-30 agent claim and all vendor numbers are self-reported.
- How any of this behaves with a single human owner over 12+ months.

## Sources

- https://openai.com/index/harness-engineering/ - Harness engineering: leveraging Codex in an agent-first world, 2026-02-11
- https://github.com/openai/symphony/blob/main/SPEC.md - Symphony Service Specification, Draft v1 (repo v0.0.3, 2026-09-15)
- https://www.anthropic.com/engineering/building-c-compiler - Building a C compiler with a team of parallel Claudes, Feb 2026
- https://www.anthropic.com/engineering/harness-design-long-running-apps - Harness design for long-running application development, 2026-03-24
- https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents - Effective harnesses for long-running agents, 2025-11-26
- https://claude.com/blog/how-anthropic-secures-its-ai-native-software-development-lifecycle - 2026-07-21
- https://cursor.com/blog/scaling-agents - Scaling long-running autonomous coding, Jan 2026
- https://cursor.com/blog/self-driving-codebases - Towards self-driving codebases, 2026-02-05
- https://cognition.com/blog/dont-build-multi-agents - 2025-06-12
- https://cognition.com/blog/multi-agents-working - 2026-04-22
- https://cognition.com/blog/testing-development - Verifying Agentic Development at Scale, 2026-05-29
- https://cognition.com/blog/devin-is-getting-a-windows-pc - 2026-05-21
- https://code.claude.com/docs/en/agent-teams, /sub-agents, /workflows, /hooks, /permission-modes, /sandbox-environments, /worktrees, /routines, /claude-code-on-the-web, /code-review, /costs - Claude Code documentation, read 2026-11-09
- https://github.com/gastownhall/gastown - Gas Town README (MIT, v1.2.1 2026-06-06)
- https://github.com/gastownhall/beads - Beads README (MIT, v1.3.4 2026-11-04)
- https://ghuntley.com/ralph/ - Ralph Wiggum as a "software engineer", 2025-07-14; https://ghuntley.com/loop/ - 2026-01-17
- https://github.com/humanlayer/advanced-context-engineering-for-coding-agents/blob/main/ace-fca.md - about Aug 2025
- https://every.to/chain-of-thought/compound-engineering-how-every-codes-with-agents - 2025-12-11
- https://github.com/obra/superpowers - README (MIT, v7.0.2 2026-11-03)
- https://simonwillison.net/guides/agentic-engineering-patterns/ - guide index, from 2026-02-23
- https://kiro.dev/docs/specs/ - Kiro specs, read 2026-11-09
- https://github.com/Fission-AI/OpenSpec - README (MIT, v1.17.0 2026-11-09)
- https://github.github.com/gh-aw/introduction/architecture/ - GitHub Agentic Workflows security architecture (v1.0.1 2026-10-27)
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners - read 2026-11-09
- https://martinfowler.com/articles/exploring-gen-ai/harness-engineering.html - 2026-04-02 (secondary)
- GitHub API metadata for the repositories above plus github/spec-kit, bmad-code-org/BMAD-METHOD, EveryInc/compound-engineering-plugin, anthropics/sandbox-runtime, smtg-ai/claude-squad, BloopAI/vibe-kanban, openai/tart - 2026-11-09

## Independent verification

_Checked 2026-11-09 by a separate fact-checking pass._ Method: the shared web-search budget was exhausted, so no search engine was used. Each claim was re-read independently in the primary page (WebFetch, or a browser read for the OpenAI post), and cross-checked where possible against sources the brief did not use: sibling primary pages (`/sandboxing`, `/permission-modes`, `/costs`), repository source read through the GitHub API (gh-aw docs, Symphony `SPEC.md`, Tart `LICENSE`, Gas Town and Beads READMEs), InfoQ coverage and a GitHub changelog entry. Claims 2 and 5 could only be re-read in the same primary page the researcher cited.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Cursor: flat lock-coordinated peers ran 20 agents at the throughput of 2-3 and became risk-averse; working design is a non-coding root planner, recursive sub-planners, isolated workers returning handoffs, no integrator | Confirmed (attribution nuance) | The cited Feb post says "20 agents would slow to the throughput of 1-3". The "two or three" and "became risk-averse" wording is in the earlier Jan 14 post. Root planner "does no coding itself", recursive sub-planners, single handoff to the requesting planner, and integrator removal are in the Feb post. | https://cursor.com/blog/scaling-agents ; https://cursor.com/blog/self-driving-codebases |
| 2 | Cognition, April 2026: writes stay single-threaded, extra agents add intelligence; swarms and weak-primary escalation fail; Devin Review about 2 bugs per PR, about 58% severe | Confirmed | Dated 2026-04-22. Wording matches, including "an average of 2 bugs per PR, of which roughly 58% are severe". Self-reported vendor figure; no independent source found. | https://cognition.com/blog/multi-agents-working |
| 3 | OpenAI: about 1M lines, about 1,500 merged PRs, five months, zero human-written code; roughly 100-line AGENTS.md as table of contents into linted docs; exec plans; layered architecture enforced by custom linters and structural tests; recurring cleanup agents | Confirmed | Read in the live page. The 1M lines include tooling, infrastructure and documentation, not only product code. 1,500 PRs came from three engineers (team later seven); the product is an internal beta. InfoQ independently reports the million lines, five months, no manual code, layer order and structural tests. | https://openai.com/index/harness-engineering/ ; https://www.infoq.com/news/2026/02/openai-harness-engineering-codex/ |
| 4 | Self-grading agents approve mediocre work; a tuned separate evaluator is the lever; sprints and per-sprint QA removed for Opus 4.6 | Confirmed | The evaluator was not removed: it moved to a single pass at the end of the run, and the post says it stays worth its cost on tasks beyond what the model does reliably solo. Context resets had already been dropped with Opus 4.5. | https://www.anthropic.com/engineering/harness-design-long-running-apps |
| 5 | Anthropic C compiler: 16 agents, 100k lines, just under $20,000, 2B input and 140M output tokens, about 2,000 sessions, git lock files, no orchestrator, GCC oracle fixed the monolithic-task stall | Confirmed | All figures match ("nearly 2,000 Claude Code sessions across two weeks", "I don't use an orchestration agent"). | https://www.anthropic.com/engineering/building-c-compiler |
| 6 | Claude Code docs: bypassPermissions only inside a container, VM or sandbox runtime; auto mode is a per-action classifier, not isolation; Bash sandbox does not cover MCP servers or hooks and has no native Windows support | Confirmed | "Always run `--dangerously-skip-permissions` sessions inside a container, a VM, or the sandbox runtime"; "a per-action control, not an isolation boundary". The Bash sandbox also covers PowerShell and Monitor commands but not file tools, MCP servers, command hooks or plugin monitors. The sandbox runtime uses Seatbelt or bubblewrap, so on a native Windows host the compliant options are a container, a VM or WSL2. | https://code.claude.com/docs/en/sandbox-environments ; https://code.claude.com/docs/en/sandboxing ; https://code.claude.com/docs/en/permission-modes |
| 7 | Agent teams experimental, interactive-only, no nesting, overwrite risk; workflows 16 concurrent and 1,000 agents per run; subagents nest three levels, 20 concurrent | Confirmed (two nuances) | 16 is a default that drops on CPU-limited hosts and is configurable from 1 to 256 (`CLAUDE_CODE_WORKFLOW_MAX_CONCURRENT_AGENTS`). 1,000 per run is a fixed runtime cap, not a documented configurable default. Subagent depth is "three layers below the main conversation" (`CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH`); the 20 limit is `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`. Unlike agent teams, workflows run in `claude -p` and the Agent SDK. | https://code.claude.com/docs/en/agent-teams ; https://code.claude.com/docs/en/workflows ; https://code.claude.com/docs/en/sub-agents |
| 8 | Hosted macOS arm64 runners cannot nest virtualisation; standard Linux, Windows (x64, arm64) and macOS runners are free for public repositories | Confirmed | "Use of the standard GitHub-hosted runners is free and unlimited on public repositories." Applies to standard runners only; larger runners are billed. Public-repository sizes match the brief (4 vCPU and 16 GB for Linux and Windows, 3 vCPU M1 and 7 GB for arm64 macOS). | https://docs.github.com/en/actions/reference/runners/github-hosted-runners |
| 9 | gh-aw: read-only agent job behind an egress firewall, writes through separate scoped safe-output jobs, threat-detection job, integrity filtering | Confirmed (important default) | Confirmed in the repository docs source. Threat detection defaults to warn mode (`continue-on-error: true`): on a detected threat or a detector failure, reviewable outputs (issues, comments, pull requests) are still published with a caution annotation, branch pushes become review PRs, and only non-reviewable outputs are aborted. Blocking requires `continue-on-error: false`. The docs also state that custom steps and safe-output actions are trusted code outside the agent sandbox. | https://github.com/github/gh-aw/blob/main/docs/src/content/docs/introduction/architecture.mdx ; https://github.com/github/gh-aw/blob/main/docs/src/content/docs/reference/threat-detection.md |
| 10 | Test gaming: placeholders, done after unit tests only, JavaScript-forced UI state; counters: passes-only feature list, expected behaviour recorded before each action | Confirmed (mixed attribution) | Three different sources, not the one cited: placeholders are Huntley ("the reward function is compiling code"); unit-test or curl-only completion and the passes-only `feature_list.json` are Anthropic (2025-11-26); JavaScript execution and expectation-before-action are Cognition (2026-05-29). Cognition frames the JavaScript behaviour as over-reliance ("may sometimes lean too heavily"), not deliberate gaming, and lists it as still being addressed. | https://ghuntley.com/ralph/ ; https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents ; https://cognition.com/blog/testing-development |

Further statements checked in the brief:

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Section 7: "harness run $124.70 ... versus $9 solo that did not work" | Corrected | The $9 solo run (20 minutes, Opus 4.5, retro game maker) is paired in the post with the $200, 6-hour full-harness run of the same prompt. The $124.70 run (3 h 50 min) is a different application (a DAW) on the simplified harness and has no solo baseline. The breakdown ($0.46 planner, $113.85 build, $10.39 QA) is correct. | https://www.anthropic.com/engineering/harness-design-long-running-apps |
| Section 9: Tart "licence field is non-SPDX" | Corrected | `openai/tart` ships a `LICENSE` file that is the Functional Source License 1.1 with Apache-2.0 future licence (FSL-1.1-ALv2), copyright 2022-2026 OpenAI. It is source-available, permits internal use, and forbids making it available in a competing commercial product. It is not an OSI open-source licence, so it can serve an internal macOS VM test farm but cannot be treated as an open-source building block or redistributed as part of the product. | https://github.com/openai/tart/blob/main/LICENSE |
| Implications, OS-level testing: self-hosted VM pools for Linux kernel-version sweeps; open question on KVM for hosted Linux runners | Overstated | Hosted x64 Linux runners expose KVM: GitHub announced hardware acceleration on the 2-vCPU Linux runners (previously 4 vCPU and above), and the gh-aw architecture doc lists a "GitHub-hosted Ubuntu x86_64 KVM runner" for its Cloud Hypervisor microVM runtime. Kernel-version sweeps in QEMU or microVM guests can therefore run on free hosted runners. Self-hosting remains necessary for Windows driver and reboot cycles and for macOS system extensions. KVM on arm64 Linux runners was not verified. | https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/ ; https://github.com/github/gh-aw/blob/main/docs/src/content/docs/introduction/architecture.mdx |

Also spot-checked and found accurate: Symphony `SPEC.md` ("Draft v1", defaults `max_concurrent_agents` 10, `max_turns` 20, `stall_timeout_ms` 300000, repository created 2026-02-26, Apache-2.0); licences and latest releases for beads, gastown, superpowers, claude-squad, gh-aw, OpenSpec, spec-kit, sandbox-runtime and compound-engineering-plugin; Gas Town README "Scale comfortably to 20-30 agents"; Beads README `bd update <id> --claim`; Claude Code costs page ($13 per developer per active day, agent teams "approximately 7x more tokens ... when teammates run in plan mode").
