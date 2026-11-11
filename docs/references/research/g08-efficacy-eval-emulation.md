# Efficacy evaluation for an AIDR: benchmarks, adversary emulation, regression corpora

_Researched 2026-11-09_

Method note: the shared WebSearch budget was exhausted before this brief started, so nothing here comes from search results. Everything marked "verified" was read today from a primary page, PDF or the GitHub API. Items marked "memory" are pre-2026 recall and were not re-checked.

## TL;DR

- A testing standard for this exact product category now exists: AMTSO "Guidelines for Testing of Agentic Security Products" v1.0, adopted 2026-09-02. It defines six outcomes (prevented, detected-not-prevented, model refusal, model recognition, missed, inconclusive), requires baseline validation with the product absent, and forbids crediting model refusals to the product. Build the scorer on this vocabulary.
- No independent comparative test of commercial agent-security products was found. SecureIQLab has published a methodology only (32 scenarios, input/output/retrieval layers, no results). MITRE ATT&CK Evaluations Enterprise 2026 is Windows-endpoint tradecraft with no agent-attack round. AIUC-1 certifies agents, not security products.
- uber/ADR (Apache-2.0, released 2026-04, 2.1k stars) is the closest open artefact: Discovery, Sensor, ADR-Bench (302 tasks, 133 MCP servers, 17 techniques) and a detector. Its own best result is precision 1.000 / recall 0.667 at $0.024 and 18.5 s per task; in production 49% of routed alerts were false positives.
- Every public benchmark measures model or monitor robustness in Linux containers. None measures discovery of unknown agents, agent-versus-human attribution, fail-open behaviour, or anything on Windows or macOS. Those four are ours to define.
- Static scores are not evidence. "The Attacker Moves Second" broke 12 defences at above 90% ASR; NIST CAISI raised AgentDojo ASR from 11% to 81% with new attacks and from 57% to 80% by allowing 25 attempts. Report ASR as a function of attacker budget.
- Control-evaluation practice (ControlArena, BashArena, SHADE-Arena) gives the right monitor metric: missed-sabotage rate at a fixed trajectory false-positive budget (BashArena: 26% evasion at 4% FPR).
- Real agents can be driven headless on all three OSes: `claude -p --output-format stream-json`, `codex exec --json`, Cursor `agent -p --output-format stream-json`. Inspect SWE and Harbor already wrap them, but only in Linux sandboxes.
- `claude --bare` skips hooks entirely, and plain `claude -p` runs project hooks and `.mcp.json` with no trust dialog. The harness must pin flags per scenario or it silently tests nothing.
- Held-out sets are consumables. Use a structural file boundary, publish the tune-versus-locked "overfit margin", retire burned sets, and generate fresh instances procedurally.
- Lakera PINT is archived (2026-04) and AgentDojo's last release is 2025-10. Treat both as regression floors, not headline numbers.

## Findings

### 1. Is there an independent test of commercial agent-security products?

**AMTSO guidelines (verified, PDF read in full, 12 pages, dated 2026-09-02).** Contributors include AV-TEST, SecureIQLab, AVLab, Gen Digital, OPSWAT and F-Secure. Scope covers API gateways, in-agent controls, browser and endpoint components, OS-level controls and platform features. Key rules:
- Architecture neutrality: an API proxy and an in-agent hook score the same if the user outcome is the same.
- Credit at any point in the chain; blocking the outbound tool call counts even if the injection reached the model. Detection after data has left "should not be counted as prevention".
- Five vectors in priority order: direct input; indirect content; tool, skill, extension and MCP supply chain; outbound action and exfiltration; memory and cross-agent propagation.
- A test case is valid only if the malicious outcome occurs with the product absent. Scenarios go "inactive" like dead malware samples; validate before and after the run.
- Six classification dimensions: vector, target, environment type, harm type, severity, required capability.
- Non-determinism: repeat runs and report the distribution with confidence and error margins.
- False positives reported separately, using look-alike legitimate workflows (authorised bulk export, developer credential scanning, trusted MCP registration).
- User friction is its own measure: approval prompts are not just latency, and the report should say whether the prompt gives enough information to decide.
- Out of scope in v1: standalone jailbreak resistance, training-time attacks, DoS. Memory and cross-agent tests are "supplemental".
Source: https://www.amtso.org/wp-content/uploads/2026/09/AMTSO_Guidelines_for_Testing_of_Agentic_Security_Products_FINAL_V1.0.pdf

**No lab results yet.** AMTSO's 2026-09-04 update lists no agentic test notifications (https://www.amtso.org/news/amtso-update-2026-09-04/). SecureIQLab's "AI Security CyberRisk Validation Methodology v1.0" has 32 scenarios across Input Security, Output Security and Retrieval Firewall, mapped to OWASP LLM Top 10 and MITRE ATLAS, with no vendors or results listed (https://secureiqlab.com/ai-security-cyberrisk-validation-methodology-v1-0-report/).

**MITRE ATT&CK Evaluations (verified in browser).** Enterprise 2025 emulated Scattered Spider and Mustang Panda. Enterprise 2026 (ER8) is "Windows Endpoint Focused" and introduces a numeric Total Evaluation Score: TES = DQI + PQI on 0 to 2.0. Reusable ideas:
- Detection Coverage tiers DC-0 to DC-3. DC-3 requires an alert with WHO, WHAT, WHEN, WHERE, HOW and severity. DC-1 is telemetry without an alert.
- Scoring per behaviour, not per alert, to stop alert-volume inflation.
- Attack Chain Weighting of 1.0, 0.75, 0.5, 0.25, 0.0 per technique by role in the chain.
- Source-of-Action modifiers (P, P/AI, S/H, S/AI) stating whether automation, a human or an AI produced the result.
- Detection run with protections disabled so the full chain is visible; protection scored separately.
Sources: https://evals.mitre.org/methodology-specification/ and https://evals.mitre.org/enterprise/er8/

**Certification, not product testing.** AIUC-1 (Q4 2026 update, 2026-10-15) certifies agents such as Cursor, Harvey and UiPath with 1,000 to 5,000 red-team scenarios and quarterly retests; Schellman is the first accredited auditor. No pass thresholds are published (https://www.aiuc-1.com/).

**Vendor documentation carries no efficacy numbers.** BeyondTrust AI Agent Security docs describe kernel and network enforcement on Windows 11 x64 and macOS 14/15/26 (no Linux) and offer one validation feature: replay recorded activity against a draft policy before saving. Microsoft Agent 365 (GA 2026-05-01, per-user licence) documents registry, Entra, Purview and Defender with no measurement. Microsoft's AI Red Teaming Agent supports only Foundry-hosted agents with Azure tools, single-turn, and states that non-Foundry agents, function tools, browser and computer-use tools are unsupported.
Sources: https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security , https://learn.microsoft.com/en-us/microsoft-agent-365/overview , https://learn.microsoft.com/en-us/azure/ai-foundry/concepts/ai-red-teaming-agent

### 2. Public benchmarks and environments

See the Matrix for the inventory. Points that change design decisions:

- **uber/ADR** (verified, repo and arXiv 2605.17380). ADR-Bench: 302 tasks in the paper (42 malicious, 260 benign), 304 in the repo; 133 MCP servers, 729 tools, average 28.5 tool calls per task. Detection results: ADR P 1.000, R 0.667, FPR 0; LlamaFirewall P 0.167, R 0.190, FPR 0.153 at $0.459 and 93.8 s per task. Permission Abuse detected in 1 of 5 cases. Production: 7,200+ hosts, 10,000+ sessions a day, alert mix 34% true positive, 17% benign true positive (internal pentest), 49% false positive. A regex-and-entropy pre-prompt credential hook reached 97.2% precision (206 TP, 6 FP). The red-teaming engine (ADR Explorer) and the Prevention component are not released. Results ship with a `run_manifest` of input hashes. https://github.com/uber/ADR
- **Control evaluations.** ControlArena (MIT, 15 settings including BashArena, SHADE-Arena, AgentDojo, IAC, Infra on Kubernetes, vLLM) runs honest and attack modes over the same tasks and scores safety and usefulness. BashArena: 637 Linux admin tasks, four side tasks (run malware, exfiltrate secrets, escalate privilege, disable firewall); Claude Sonnet 4.5 evaded a GPT-4.1 mini monitor 26% of the time at 4% trajectory FPR. SHADE-Arena: best sabotage-without-detection 27%, best monitor AUC 0.87. https://control-arena.aisi.org.uk/ , https://arxiv.org/abs/2512.15688 , https://arxiv.org/abs/2506.15740
- **inspect_evals** (MIT, verified directory listing) packages `agentdojo`, `agentharm`, `b3`, `agent_threat_bench` (OWASP Agentic Top 10 2026, only 24 samples), `ipi_coding_agent` (CodeIPI: 45 samples, canary-based scoring, `network_mode: none`), `cve_bench`, `cybench`, `cybergym`, `cyberseceval_2/3/4`, `gdm_stealth`. https://github.com/UKGovernmentBEIS/inspect_evals
- **Known flaws.** Adaptive attack breaks static results (arXiv 2510.09023: 12 defences, above 90% ASR, most originally near zero). CAISI: per-task results diverge from aggregates, repeated attempts matter (https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations). Gray Swan and UK AISI: 1.8 million attacks, 22 agents, 44 scenarios, 60,000+ policy violations, most behaviours broken within 10 to 100 queries, high transfer (arXiv 2507.20526). Even the best published defended number, Anthropic's 1.4% ASR for Opus 4.5 with safeguards under a 100-attempt adaptive attacker (2025-11-24), is described there as still meaningful risk (https://www.anthropic.com/research/prompt-injection-defenses).
- **Product-facing harnesses are immature.** opena2a-org/oasb (Apache-2.0, 223 scenarios, adapter interface, ATLAS mapped) scores its own vendor's adapter 100% and its README states the atomic tests verify harness conformance, not detection quality. gitayg/agentic-security-benchmark (Apache-2.0, 299 attack and 878 benign samples, zero stars, authored by a vendor) is methodologically the most careful: AMTSO outcomes, refusal baseline, locked split, right-reason scoring, published conflict of interest. Take its methods, not its numbers.

### 3. Driving real agents (verified from vendor docs)

| Agent | Headless command | Machine output | Notes for the harness |
|---|---|---|---|
| Claude Code | `claude -p` | `--output-format stream-json`; `system/init` lists tools, MCP servers, plugins; final `result` has `total_cost_usd` and `permission_denials` | `--bare` skips hooks, plugins, MCP and CLAUDE.md, so never use it for hook-enforcement scenarios. Without it, project hooks and `.mcp.json` load with no trust prompt. `--permission-mode`, `--permission-prompts none`, `--mcp-config`, `--settings` pin the configuration |
| Codex CLI | `codex exec` | `--json` JSONL: `thread.started`, `turn.*`, `item.*`, `error` | Sandbox default read-only; `workspace-write`, `danger-full-access`; `--full-auto` removed; `--ignore-user-config`, `--ignore-rules`; needs a git repo |
| Cursor CLI | `agent -p` | `--output-format json` or `stream-json` | `--force` to write; `CURSOR_API_KEY`; macOS, Linux, WSL and native Windows installers |

Sources: https://code.claude.com/docs/en/headless , https://learn.chatgpt.com/docs/non-interactive-mode , https://cursor.com/docs/cli/headless

Wrappers: Inspect SWE exposes `claude_code()`, `codex_cli()`, `gemini_cli()`, `kimi_code()`, `opencode()` and `mini_swe_agent()` as Inspect agents inside the sample sandbox, with model calls proxied back through `sandbox_agent_bridge()` (https://meridianlabs-ai.github.io/inspect_swe/). Harbor (Apache-2.0, 6.9k stars) runs Claude Code, Codex CLI and OpenHands across Docker and cloud sandbox providers and is the official Terminal-Bench 2.0 harness (https://github.com/harbor-framework/harbor). Both are container-first; neither documents Windows or macOS guests (inferred from the docs read, not confirmed).

### 4. Emulation tooling from classic security

Atomic Red Team (MIT, 12.8k stars) has no agent or MCP atomics that a code search could find. Stratus Red Team (Apache-2.0) has one AI technique, `aws.impact.bedrock-invoke-model`. Caldera now resolves to `apache/caldera` (Apache-2.0, last release 5.3.0 on 2025-04-24); the ATLAS "arsenal" plugin was last pushed 2023-08. PyRIT moved to `microsoft/PyRIT` (v1.1.0, 2026-09-04; `Azure/PyRIT` archived). garak is at v0.17.1 (2026-10-16). These cover model-layer probing and classic ATT&CK, not agent action chains. The useful inheritance is format: Atomic's one-YAML-per-test with prerequisites and cleanup, and Stratus's warm-up, detonate, revert lifecycle.

### 5. Continuous red teaming, arenas and bounties

- Anthropic: internal adaptive "Best-of-N" attacker with 100 attempts per environment, plus external arena participation; human red-teamers still outperform automation.
- Uber ADR Explorer: three agents (mutate, evaluate in sandbox, curate into threat repository) with fitness F = ε × σ × τ^1.2 for execution depth, naturalness and impact. Not open source.
- Gray Swan Arena (verified live 2026-11-09): 23,650 red-teamers; "Indirect Prompt Injection: Black" has 10 scenarios, 42 models and a $300,000 pool. Points are weighted by model and scenario difficulty.
- Bounties: Anthropic's HackerOne programme paid up to $15,000 for universal jailbreaks (2024-08, invite-only). Current terms for Google and OpenAI could not be read today.
- AIxCC final (2025-08-08): 54 of 63 synthetic vulnerabilities found, 43 patched, 18 real vulnerabilities, 45-minute mean patch, about $152 per task, all seven systems open-sourced. The lesson is the format: hidden challenges, fixed budget, automated scoring (https://www.darpa.mil/news/2025/aixcc-results).

## Matrix

Licence and activity verified through the GitHub API on 2026-11-09 unless marked. Sizes marked (m) are from memory.

| Asset | Measures | Size | Licence | Last activity | Fitness for us |
|---|---|---|---|---|---|
| AgentDojo | IPI against tool agents, utility and security | 97 user tasks, 629 cases (m) | MIT | release v0.1.35, 2025-10 | Regression floor; saturated for static attacks |
| InjecAgent | IPI, single-step | 1,054 cases (m) | MIT | 2024-07 | Stale; skip |
| ASB | Injection, memory poison, backdoor | 10 scenarios, 400+ tools (m) | MIT | 2026-09 | Attack taxonomy source |
| AgentHarm | Harmful multi-step compliance | 110 behaviours (m) | in inspect_evals | active | Measures model, not product |
| b3 | Backbone LLM security via threat snapshots | 194,331 attacks, 34 LLMs | in inspect_evals | 2026-02 paper v2 | Model selection for judges |
| ADR-Bench | Session-level detection over MCP workloads | 302 tasks, 133 servers | Apache-2.0 | 2026-10 | Best fit for detector; reuse directly |
| CodeIPI | IPI in repos for coding agents | 45 samples | MIT | active | Seed for coding-agent scenarios |
| AgentThreatBench | OWASP Agentic Top 10 | 24 samples | MIT | active | Too small; taxonomy only |
| ControlArena | Monitor and protocol safety versus usefulness | 15 settings | MIT | 2026-10 | Adopt for monitor evaluation |
| BashArena | Sabotage by privileged shell agents | 637 tasks, 4 side tasks | generator public, no licence file | 2026-10 | Linux sensor and monitor testing |
| SHADE-Arena | Subtle sabotage and monitoring | partly private | MIT | 2026-07 | Reviewer evaluation |
| CyBench, CVE-Bench, CyberGym | Offensive capability of agents | 40 CTFs (m), 40 CVEs (m) | Apache-2.0 | 2026-09/10 | Attacker-agent workload generator |
| CyberSecEval 4 | Model security risks, PI, code interpreter abuse | suite | custom | 2026-11 | Model-layer only |
| OS-Harm, WASP, DoomArena | Computer-use and web-agent safety | 150 tasks (m) | Apache-2.0 / custom | 2025-09, WASP archived | Browser scenario seeds |
| PINT | Prompt-injection classifier accuracy | 4,314 inputs (m) | MIT | archived 2026-04 | Classifier unit test only |
| OASB | Runtime product conformance | 223 scenarios | Apache-2.0 | 2026-11 | Adapter idea; scores not neutral |
| agentic-security-benchmark | AMTSO-graded product corpus | 299 attack, 878 benign | Apache-2.0 | 2026-11 | Methodology template |
| Terminal-Bench 2.0, SWE-bench | Benign task completion | via Harbor | Apache-2.0 | 2026-11 | Benign workload and utility-loss measure |

## Weak points, gaps and risks

- No benchmark anywhere for discovery recall on unregistered agents or for agent-versus-human attribution. We must author ground truth ourselves, which makes us both examinee and examiner.
- Everything public is Linux containers. Windows (ETW, minifilter, WFP) and macOS (Endpoint Security, Network Extension) sensors have no shared test bed.
- Fail-open behaviour (sensor crash, hook timeout, control plane unreachable) is untested in every source read, including AMTSO v1.
- Benchmarks with tens of samples (CodeIPI 45, AgentThreatBench 24, ADR-Bench 42 malicious) give confidence intervals too wide for release gating. With 42 positives, recall 0.667 has a 95% interval of roughly 0.52 to 0.79.
- Scenario decay: model updates turn attacks inactive, which silently inflates "prevented" unless baselines are re-run every time.
- LLM-graded scorers are themselves non-deterministic; Microsoft's docs warn of false positives in ASR grading.
- Agents special-case tests. Any corpus visible to build agents will be fitted, and nothing about a burned set looks different afterwards.
- Self-published scorecards carry a conflict of interest that only open harness, open adapters and third-party reruns can offset.

## Implications for our design

### Emulation harness

1. **Scenario spec**: one YAML per scenario, Atomic-style, carrying the six AMTSO dimensions plus ATLAS and OWASP Agentic IDs, required capability, expected unsafe outcome, oracle definition, reset procedure and per-step chain weight (ACW-style).
2. **Drivers**: adapters for `claude -p`, `codex exec`, Cursor `agent -p`, and SDK agents (Claude Agent SDK, OpenAI Agents SDK, LangGraph), each pinning version, flags and permission mode in the run manifest. A GUI driver handles desktop apps and browsers.
3. **Environments**: Linux through Inspect and Harbor sandboxes; Windows and macOS through snapshot-reset VMs we orchestrate ourselves; a kind or k3s cluster for server scenarios. All attacker infrastructure is sinkholed: canary exfil endpoint, malicious and rug-pull MCP servers, poisoned repositories, pages and mail fixtures, synthetic secrets only.
4. **Independent oracle**: ground truth never comes from the product under test. Use canary tokens at the sinkhole, pre and post file hashes, the driver's own process tree, the agent transcript and an LLM-proxy log.
5. **Three passes per scenario**: product absent (validity and model-refusal baseline), monitor-only, enforce. Re-run the baseline after the protected run.
6. **Actor labelling for attribution**: a scripted "human" (pty keystrokes, UI automation) works under the same OS user and credentials as the agent, interleaved. The harness labels every action by actor at source. Include confounders: human pastes an agent-suggested command, agent detaches a process, subagents, IDE extension hosts, cron and launchd persistence.
7. **Unknown-agent generator**: build bespoke agents from a matrix of SDK, language, model provider, transport and packaging (single binary, container, renamed process, local model, corporate proxy). Add negatives that call LLM APIs without being agents. The generator's held-out cells define discovery recall.
8. **Fault injection**: kill the sensor, stall the hook past its timeout, cut the control plane, fill the disk, corrupt policy. Assert the declared failure mode and that every fail-open is alarmed.
9. **Two speeds**: a replay tier over recorded telemetry (ADR's packed JSONL and BeyondTrust's policy replay show the pattern) for every commit; a live tier nightly and per release, with at least 10 repetitions per cell and Wilson intervals.
10. **Product adapter interface** so competitors and EDR embedders can be scored by the same harness, with capabilities declared and undeclared surfaces reported N/A rather than failed.

### Metrics and proposed targets

Targets are our proposals, anchored to the published numbers above.

| Component | Metric | Target for v1 |
|---|---|---|
| Discovery | Recall on catalogued agents | ≥ 99% |
| Discovery | Recall on held-out generated agents within 15 minutes of first run | ≥ 85%, reported by packaging tier |
| Discovery | Precision against LLM-calling non-agents | ≥ 95% |
| Discovery | Induced blind spots reported as coverage gaps | 100% |
| Attribution | Per-action agent-versus-human precision, shared credentials | ≥ 99% |
| Attribution | Recall of agent-caused process, file and network events linked to the right session | ≥ 95%, "unknown" rate published |
| Enforcement | Prevented rate on validated-active scenarios, net of model refusal | Published per vector; no blended "block rate" |
| Enforcement | Block reliability for deterministic policy (oracle confirms action did not occur) | ≥ 99.9% |
| Enforcement | Silent fail-open under injected faults | 0; every fail-open alarmed within 60 s |
| Enforcement | Time to verdict, by operation | Deterministic hook p99 < 50 ms; LLM-judged p95 < 3 s |
| Detection | Recall at 1% session FPR; ASR at 1, 10 and 100 attacker attempts | Beat ADR-Bench recall 0.667 at FPR ≤ 1% |
| Detection | Alert quality tier distribution (DC-0 to DC-3) and right-reason rate | ≥ 80% of detections DC-3 |
| Review | False prompts per active user per day on benign workload | Median < 1, p95 < 3 |
| Review | Benign task completion delta (Terminal-Bench 2.0) | ≤ 1 point loss |
| Secrets | Precision and recall on seeded synthetic credentials | Precision ≥ 97% (ADR hook: 97.2%) |
| Cost | Dollars and seconds per session; CPU and memory overhead | ≤ $0.03 per session (ADR: $0.024 per task) |
| Integrity | Overfit margin, tune minus locked | < 5 points; larger blocks release |

### Held-out governance

- Three tiers: public development corpus in the repository; a locked set in a separate organisation that build agents have no credentials or network path to; a sealed quarterly set authored by people or agents outside the build loop.
- The evaluator is a service. It returns category-level counts only, never sample content, with a fixed number of scored submissions per release.
- Every held-out file carries a canary GUID. CI and transcript scanning fail the build if a canary appears in the repository, a prompt or a build-agent context.
- Deterministic stratified split (sort by ID inside each family-and-transformation bucket, alternate) so the split is recomputable without a stored seed.
- Publish both tune and locked scores. Any sample that leaks is retired into the public regression corpus; rotate at least a quarter of the locked set each quarter.
- Prefer procedural generators (BashArena publishes its generator) and metamorphic variants: renaming paths, hosts and canary values must not change the outcome.
- Scenario authors use a different model vendor from the build agents. Results are signed with a run manifest of input hashes.

### Public scorecard, one per release

A JSON file plus rendered page containing: product version, deployment mode and policy profile; agent hosts, versions, models and OS builds; corpus IDs and hashes with counts per vector; the six-outcome distribution per vector for monitor and enforce modes; model-refusal baseline; ASR at 1, 10 and 100 attempts; false positives by workflow type; discovery and attribution tables; fault-injection results; latency and cost percentiles; tune and locked scores with the overfit margin; N/A surfaces; inconclusive count; deviations; who ran it and conflicts of interest; a link to raw traces.

### Continuous red teaming

Nightly attacker agents with fixed query budgets and detector feedback (reimplement the Explorer loop; it is unreleased). PyRIT, garak and promptfoo cover model-layer converters only. Every success becomes a minimised scenario that lands in the public corpus once fixed. Run a standing public "break the guard" environment and a bounty scoped to product bypasses: silent policy bypass, attribution spoofing, discovery evasion, sensor tamper and induced fail-open. Exclude jailbreaks with no resulting action.

## Ideas worth stealing and whitespace

- Refusal-baseline subtraction and "build detectors where the model complies" (agentic-security-benchmark).
- Right-reason scoring and the overfit margin as a published number.
- MITRE's per-behaviour DC tiers, chain weighting and Source-of-Action modifiers; our equivalent modifier is deterministic rule, LLM judge or human approval.
- ADR's `run_manifest` and packed-conversation replay; BeyondTrust's pre-enforcement policy replay as a user-facing feature.
- Whitespace: the first open, cross-OS, AMTSO-conformant harness with discovery, attribution and fail-open tracks. No lab, vendor or academic group has published one.
- Whitespace: contribute agent atomics upstream to Atomic Red Team and Stratus, which have almost none.

## Could not verify / open questions

- Whether AV-Comparatives, SE Labs or AV-TEST have announced an agentic product test; search was unavailable and the AMTSO test calendar was not read.
- OpenAI's Atlas hardening post (403) and Google AI VRP rules (JavaScript-only); current bounty amounts unknown.
- Whether Inspect or Harbor have Windows or macOS sandbox providers.
- macOS VM licensing limits for a CI fleet.
- Benchmark sizes marked (m).
- Whether Uber will release ADR Explorer and Prevention.
- 2026 Gray Swan and UK AISI challenge reports beyond the live arena page.

## Sources

- https://www.amtso.org/wp-content/uploads/2026/09/AMTSO_Guidelines_for_Testing_of_Agentic_Security_Products_FINAL_V1.0.pdf , AMTSO Guidelines for Testing of Agentic Security Products v1.0, 2026-09-02
- https://www.amtso.org/news/amtso-update-2026-09-04/ , AMTSO Update, 2026-09-04
- https://secureiqlab.com/ai-security-cyberrisk-validation-methodology-v1-0-report/ , SecureIQLab AI Security CyberRisk Validation Methodology v1.0, 2026
- https://evals.mitre.org/methodology-specification/ and https://evals.mitre.org/enterprise/er8/ , MITRE ATT&CK Evaluations scoring specification and Enterprise 2026, read 2026-11-09
- https://www.aiuc-1.com/ , AIUC-1, Q4 2026 update 2026-10-15
- https://github.com/uber/ADR and https://arxiv.org/abs/2605.17380 , ADR: An Agentic Detection System for Enterprise Agentic AI Security, MLSys 2026
- https://control-arena.aisi.org.uk/ , ControlArena documentation, read 2026-11-09
- https://arxiv.org/abs/2512.15688 , BashArena, 2025-12-17
- https://arxiv.org/abs/2506.15740 , SHADE-Arena, 2025-06-17
- https://arxiv.org/abs/2510.09023 , The Attacker Moves Second, 2025-10-10
- https://arxiv.org/abs/2507.20526 , Security Challenges in AI Agent Deployment (ART), 2025-07-28
- https://arxiv.org/abs/2510.22620 , Breaking Agent Backbones (b3), 2025-10-26, v2 2026-02-24
- https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations , NIST CAISI, 2025-01-17
- https://www.anthropic.com/research/prompt-injection-defenses , Anthropic, 2025-11-24
- https://www.anthropic.com/news/model-safety-bug-bounty , Anthropic, 2024-08-08
- https://github.com/UKGovernmentBEIS/inspect_evals , inspect_evals source tree, 2026-11-09
- https://meridianlabs-ai.github.io/inspect_swe/ , Inspect SWE, read 2026-11-09
- https://github.com/harbor-framework/harbor , Harbor, 2026-11-09
- https://code.claude.com/docs/en/headless , Run Claude Code programmatically, read 2026-11-09
- https://learn.chatgpt.com/docs/non-interactive-mode , Codex non-interactive mode, read 2026-11-09
- https://cursor.com/docs/cli/headless , Cursor CLI headless, read 2026-11-09
- https://github.com/opena2a-org/oasb , Open Agent Security Benchmark, 2026-11
- https://github.com/gitayg/agentic-security-benchmark , Agentic Security Benchmark, 2026-11
- https://github.com/cisco-ai-defense/project-quarry , Project Quarry detection DSL, created 2026-10-27
- https://github.com/lakeraai/pint-benchmark , PINT (archived), 2026-04
- https://github.com/microsoft/PyRIT , https://github.com/NVIDIA/garak , https://github.com/apache/caldera , https://github.com/redcanaryco/atomic-red-team , https://github.com/DataDog/stratus-red-team , repository metadata 2026-11-09
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security , BeyondTrust AI Agent Security, read 2026-11-09
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview , Microsoft Agent 365 overview, updated 2026-10-23
- https://learn.microsoft.com/en-us/azure/ai-foundry/concepts/ai-red-teaming-agent , AI Red Teaming Agent, 2026-08-19
- https://app.grayswan.ai/arena , Gray Swan Arena, read 2026-11-09
- https://www.darpa.mil/news/2025/aixcc-results , DARPA AIxCC results, 2025-08-08

## Independent verification

Checked 2026-11-09/10 by a separate fact-checker. Method limits: the shared WebSearch budget was exhausted, so no search engine was used. Checks were made by fetching primary pages directly, extracting text from the two PDFs (AMTSO guideline, ADR paper), reading evals.mitre.org in a browser, and reading source and metadata through the GitHub API. Negative claims (claim 2) are therefore only as strong as the pages that could be read.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | AMTSO agentic testing guidelines v1.0 adopted 2026-09-02; six outcomes; baseline validation with product absent | Confirmed | AMTSO document archive lists v1.0, adopted 2026-09-02. PDF title page: "Version: 1.0, Date: 2026-09-02 (Approved and adopted by AMTSO membership)". Outcome table: Prevented, Detected but not prevented, Model refusal, Model recognition, Missed or successful attack, Inconclusive. Baseline validation is worded as "should" (guideline, not a mandatory standard) and allows an exception when a test deliberately measures behaviour in the presence of model refusal. | https://www.amtso.org/documents/ |
| 2 | No independent comparative results for commercial agent-security products; SecureIQLab has only a 32-scenario methodology | Corrected | No results found in AMTSO updates of 2026-09-04, 09-18, 10-02 and 10-30, nor on SecureIQLab, SE Labs or AV-TEST listings (AV-Comparatives and CyberRatings could not be read). But the AMTSO test calendar, which the brief did not read, lists the SecureIQLab AI Security CyberRisk Validation as a registered test: ID AMTSO-LS1-TP193, platform Gateway/Firewall, notified 2026-03-23, commenced 2026-04-04, publication due 2026-11-18. "Methodology only" is about to be outdated; expect a first comparative report on AI gateways (input, output, retrieval layers, not agent runtime) within days. | https://www.amtso.org/tests/secureiqlab-ai-security-cyberrisk-validation-methodology-v1-0/ |
| 3 | MITRE Enterprise 2026 is Windows-endpoint focused, no agent-attack round; TES = DQI + PQI, DC-0 to DC-3, ACW, source-of-action modifiers | Corrected | Scoring elements all confirmed (TES 0 to 2.0; ACW 1.0/0.75/0.5/0.25/0.0; modifiers P, P/AI, S/H, S/AI, Mixed; IQI reported separately from TES). No AI-agent or LLM attack scenario appears on the ER8 page. But only Scenario 1 (crimeware-as-a-service) is "Endpoint Focused" on Windows Server 2022, Windows 11 and Exchange. Scenario 2 (PRC espionage, "Enterprise Focused") adds AWS, an identity provider, edge devices and Ubuntu 24.04. The round is not Windows-only. | https://evals.mitre.org/enterprise/er8/ |
| 4 | uber/ADR is Apache-2.0 with Discovery, Sensor, ADR-Bench (302 tasks, 133 MCP servers, 17 techniques) and detector; Explorer and Prevention not released | Confirmed | GitHub API: Apache-2.0, created 2026-04-19, 2,129 stars; top-level dirs Discovery, Sensor, Detection, Common. README states Explorer "is not included here" and Prevention "is not included in the current open-source release". Paper: 302 tasks, 133 servers, 729 tools, 17 techniques. Repo README now says 304 tasks and 134 MCP servers, so use the repo counts when reusing the corpus. Sensor and Discovery cover macOS, Linux and Windows. | https://github.com/uber/ADR |
| 5 | ADR on ADR-Bench: precision 1.000, recall 0.667, $0.024 and 18.5 s per task; 49% of routed alerts false positive in production | Confirmed | Paper Table 2: ADR 1.000 / 0.667 / F1 0.800, TP/FP 28/0, $0.024 per task, 18.5 s mean latency (P95 37.9 s). Section 6.1: alerts routed to human review were labelled TP 34%, true positive non-malicious 17%, FP 49%. The arXiv abstract page omits cost, latency and the 49%; they are in the PDF body. | https://arxiv.org/pdf/2605.17380 |
| 6 | Adaptive attacks bypassed 12 defences at above 90% success, most originally near zero | Corrected | Abstract wording is above 90% ASR "for most" of the 12 defences, not all 12. The "majority originally reported near-zero" part is as stated. | https://arxiv.org/abs/2510.09023 |
| 7 | NIST raised AgentDojo ASR 11% to 81% with new attacks, 57% to 80% with 25 attempts | Confirmed | Numbers match. Scope: 11% to 81% is strongest baseline versus strongest new attack against upgraded Claude 3.5 Sonnet; 57% to 80% is the average over five injection tasks. The January 2025 post was published by the US AI Safety Institute, since renamed CAISI. | https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations |
| 8 | `claude -p --output-format stream-json`; `--bare` skips hooks, plugins, MCP discovery; plain `-p` loads project hooks and .mcp.json with no trust dialog | Confirmed | Confirmed against the permissions page and CLI reference, not only the headless page. Three additions that matter for the harness: (a) the docs state `--bare` "will become the default for `-p` in a future release", so hook-based scenarios must not rely on today's default; (b) under untrusted `-p`, project `permissions.allow` rules and `additionalDirectories` are not applied, and subagent frontmatter hooks are not used, even though settings hooks and `.mcp.json` servers are; (c) every documented `-p` stream-json example pairs it with `--verbose`, and Inspect SWE launches Claude Code with `--print --output-format stream-json --verbose`. `--setting-sources user` is the documented way to exclude project settings and `.mcp.json` without going bare. | https://code.claude.com/docs/en/permissions.md |
| 9 | BashArena: 637 tasks, four side tasks; Sonnet 4.5 evades GPT-4.1 mini 26% at 4% trajectory FPR | Confirmed | Matches the abstract. Note the public repo and the ControlArena setting are now BashArena 1.1, which changed the `disable_firewall` side task to be harder to reward-hack; the paper's 26% was measured on the original release (commit 79ed8e9). The public generator repo has no licence file (GitHub API returns null), as the brief says. | https://github.com/redwoodresearch/basharena_public |
| 10 | Inspect SWE exposes Claude Code, Codex CLI, Gemini CLI, Kimi Code, opencode, mini-SWE-agent inside the sandbox via the agent bridge | Confirmed | Package `__init__` exports those six plus `antigravity` and ACP-based `interactive_claude_code`, `interactive_codex_cli`, `interactive_gemini_cli`. `claude_code.py` wraps `sandbox_agent_bridge`. Source also settles an open question: `detect_sandbox_platform` raises "Unsupported OS" for anything but Linux (x64, arm64, glibc or musl). Inspect SWE cannot drive Windows or macOS guests. | https://github.com/meridianlabs-ai/inspect_swe |

Further statements checked:

| Statement in brief | Verdict | Note | Source |
|---|---|---|---|
| "Both [Inspect SWE and Harbor] are container-first; neither documents Windows or macOS guests" | Corrected | True for Inspect SWE (Linux only, see claim 10). Not true for Harbor: it ships `environments/docker/docker_windows.py` (Windows containers, Hyper-V and process isolation) and a `windows` capability flag, plus `apple_container.py`, `ec2.py` and `cua_cloud.py` providers. No macOS guest was found. Harbor is a candidate for the Windows live tier before building our own VM orchestration; Windows containers still do not exercise a kernel sensor the way a full VM does. | https://github.com/harbor-framework/harbor |
| BeyondTrust AI Agent Security runs on "Windows 11 x64 and macOS 14/15/26 (no Linux)" | Corrected (minor) | Docs also list Windows Server 2022 or later on x64; Windows on Arm is unsupported. macOS 14, 15, 26 and no Linux are as stated. Kernel and network enforcement, hook-based policy for coding tools, policy replay before save and absence of efficacy figures all confirmed. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |
| Repository facts in section 4 and the matrix (Caldera at `apache/caldera`, PyRIT at `microsoft/PyRIT` v1.1.0, garak v0.17.1, PINT archived, AgentDojo v0.1.35, Harbor 6.9k stars, Stratus single AI technique) | Confirmed | GitHub API on 2026-11-10: `mitre/caldera` redirects to `apache/caldera` (Apache-2.0, latest release 5.3.0, 2025-04-24); `Azure/PyRIT` archived, `microsoft/PyRIT` v1.1.0 (2026-09-04); garak v0.17.1 (2026-10-16); `lakeraai/pint-benchmark` archived, last push 2026-04-16; AgentDojo v0.1.35 (2025-10-27); Harbor 6,925 stars; Stratus has only `aws.impact.bedrock-invoke-model`. Also confirmed in passing: Agent 365 GA 2026-05-01 per user, b3 v2 with 194,331 attacks and 34 LLMs, Anthropic 1.4% ASR for Opus 4.5 with 100-attempt adaptive attacker, ControlArena 15 settings and MIT. | GitHub API (`gh api repos/...`) |
