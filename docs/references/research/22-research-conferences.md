# Security research and conference work on AI agents (2025 to Nov 2026): defences, AI control, offence

_Researched 2026-11-09_

Method note: the shared web-search budget for this run was already exhausted, so no search-engine queries were possible. Everything below comes from direct fetches of primary sources (arXiv, conference programmes, vendor docs, IETF datatracker, GitHub advisories via `gh`). Tags: **[V]** fetched and read today; **[T]** title or listing verified today, abstract not read; **[M]** from pre-June-2026 knowledge, URL not re-fetched today.

## TL;DR

- Guardrail classifiers are not a boundary. "The Attacker Moves Second" broke 12 published defences, most at over 90% attack success, after they had reported near zero; it is now a USENIX Security 2026 paper. Detectors also pass non-instruction payloads (fabricated "safety warnings" steer agents 60.4% of the time and are classed benign).
- The defences with real guarantees are architectural: separate control flow from untrusted data (CaMeL, FIDES, six design patterns, compile-then-execute). The latest web-agent result (Baya, Nov 2026) reports 0% attack success with higher utility than ReAct.
- String-matching command allow-lists fail structurally. Claude Code has 36 published advisories and Cursor 30+, dominated by parser bypasses, pre-trust execution, symlink/TOCTOU and config self-modification. Enforcement has to be at the OS.
- NVIDIA's three mandatory controls are the minimum: default-deny egress, OS-level block on writes outside the workspace, and no agent-driven writes to any agent config (hooks, MCP, skills, rules files).
- LLM monitors have measurable, non-trivial miss rates: 17% on real overeager actions (Claude Code auto mode), 26% evasion in BashArena, 6% in Async Control at 1% FPR.
- Monitors are themselves attack surface: an untrusted agent can prompt-inject its monitor, and "defer to resample" amplifies that into best-of-n.
- Chain-of-thought is a fragile signal: backdoored models produce clean reasoning, thought-injection reaches 50% success, and evaluation-aware models behave better when watched. Ground truth must be the kernel and the network.
- The base rate is not attackers but overeager agents: users accept 93% of prompts; frontier models drift past authorisation in 43 to 61% of benchmark tasks without any adversary.
- Cross-agent escalation and repo-borne worms are demonstrated (Copilot rewrites Claude Code config; AgentHopper), and in-the-wild injection is measurable (about 2.5 per 100K GitHub items; 157 malicious of 98,380 skills).
- Agent identity is converging on workload identity: IETF WIMSE `draft-ietf-wimse-aims-01` (2 Nov 2026) says one SPIFFE/WIMSE ID per agent, short-lived credentials, and the LLM must never hold them.
- Shipping products already do kernel-level, agent-vs-human attribution on Windows and macOS (BeyondTrust) and registry-centric governance (Microsoft Agent 365, GA 1 May 2026). Neither docs set covers Linux endpoints, information-flow labels, or control-style responses.

## Findings

### A. Capability, information-flow and design-pattern defences

| # | Item | Takeaway |
|---|---|---|
| 1 | [CaMeL](https://arxiv.org/abs/2503.18813), Google/ETH, Mar 2025 [V] | Program extracted from the trusted query; untrusted data cannot alter control flow; capabilities gate sinks. 77% AgentDojo tasks with provable security vs 84% undefended. Repo Apache-2.0, last push 2025-06. |
| 2 | [FIDES](https://arxiv.org/abs/2505.23643), Microsoft, May 2025 [V] | Planner tracks confidentiality and integrity labels and enforces policy deterministically; adds selective-hiding primitives. `microsoft/fides` MIT, last push 2025-05. |
| 3 | [Design Patterns for Securing LLM Agents](https://arxiv.org/abs/2506.08837), Jun 2025 [V] | Six patterns: action-selector, plan-then-execute, map-reduce, dual LLM, code-then-execute, context-minimisation. Combine them; prefer application-specific agents. |
| 4 | [Dual LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/) and [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) [M] | Privileged model never sees untrusted text; private data + untrusted content + exfil channel is the dangerous combination. |
| 5 | [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/), Meta, 31 Oct 2025 [V] | At most two of: untrusted input, sensitive access, state change or external comms, per session; all three needs supervision or a fresh context. |
| 6 | [CaMeLs Can Use Computers Too](https://arxiv.org/abs/2601.09923), Jan 2026, v3 Jun 2026 [V] | Single-shot branching plan gives control-flow integrity for computer-use agents; keeps up to 57% of OSWorld performance; "Branch Steering" via perception remains. |
| 7 | [Baya: compile-then-execute web agents](https://arxiv.org/abs/2611.06039), Berkeley, 4 Nov 2026 [V] | Planner never sees live pages; 77.8% utility on WebArena Verified (ReAct 55.1%) and 0% attack success on WASP (ReAct 25.5%). |
| 8 | [ACE](https://www.ndss-symposium.org/ndss2026/accepted-papers/) and SAGA, NDSS 2026 [T] | Abstract-concrete-execute planning and a governance architecture for agent-to-agent access; system-level designs are now top-venue mainstream. |
| 9 | [Signed, Sealed, Leaked](https://arxiv.org/abs/2611.06585), 4 Nov 2026 [V] | Signed MCP tools can still leak to allowed destinations. "Germline execution" forks each invocation from a data-free process: 0 leaks in 153 runs, 10 to 49 ms per call. |
| 10 | [Signed but Not Safe](https://arxiv.org/abs/2611.07483), 5 Nov 2026 [V] | Signed handoff manifests cut unsafe commits 69.4% to 9.0%; deterministic verifier beat an LLM checker (78.7% vs 59.0% caught, 7% vs 50% false alarms); injection before signing still wins. |

### B. Programmable privilege control and approvals

| # | Item | Takeaway |
|---|---|---|
| 11 | [Progent](https://arxiv.org/abs/2504.11703), Berkeley, v3 May 2026 [V] | Symbolic rules over tool names and arguments; LLM drafts, SMT solver checks updates; narrowing is automatic, widening needs approval ("monotonic confinement"). MIT. |
| 12 | [AgentSpec](https://arxiv.org/abs/2503.18666), ICSE 2026 [V] | Trigger/predicate/enforce DSL; over 90% unsafe code-agent executions prevented; millisecond overhead; LLM-written rules 95.56% precision, 70.96% recall. |
| 13 | [AgentBound](https://arxiv.org/abs/2510.21236), v3 Apr 2026 [V] | Android-style permissions for MCP servers, enforced without modifying servers; policies auto-generated from source at 80.9% accuracy over 296 servers. |
| 14 | [Conseca](https://arxiv.org/abs/2501.17070), Google, HotOS 2025 [V] | Just-in-time, contextual, human-verifiable policies per task instead of static rules or prompts. |
| 15 | [RuntimeTickets](https://arxiv.org/abs/2611.03772), 2 Nov 2026 [V] | Egress gate checks recipient, object and amount of each outbound send against obligations derived from the skill source; self-reported 0% miss and 0% overblock. |
| 16 | [Assurance-Conditioned Continuous Authorization](https://arxiv.org/abs/2611.05632), 3 Nov 2026 [V] | Authority envelope shrinks and recovers with evidence; "authority epochs" reject stale actions at effect time. |
| 17 | [Aegis OS](https://arxiv.org/abs/2611.08516), Oct 2026 [V] | Rust runtime moving approval from tool calls to transactional copy-on-write workspaces plus egress proxy; self-reported 90.7 to 97.9% fewer prompts on 28,087 real calls. |
| 18 | [Claude Code auto mode](https://www.anthropic.com/engineering/claude-code-auto-mode), 25 Mar 2026 [V] | Users accept 93% of prompts. Two-stage classifier sees only user messages and tool calls ("reasoning-blind"); 0.4% FPR, 17% FNR on real overeager actions; deny-and-continue, escalate after 3 consecutive or 20 total denials. |
| 19 | [Permission Fatigue Is a Security Bug](https://unpromptedcon.org/agenda), Meta, [un]prompted II Oct 2026 [V] | Static gates replaced with a signals/policy/decision runtime; 80% less friction at full rollout. |
| 20 | Towards Automating Data Access Permissions in AI Agents, [IEEE S&P 2026](https://sp2026.ieee-security.org/accepted-papers.html) [T] | Permission prediction for agent data access is an academic topic; no product equivalent found. |

### C. Sandboxing

| # | Item | Takeaway |
|---|---|---|
| 21 | [NVIDIA AI Red Team sandboxing guidance](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/), 30 Jan 2026 [V] | Mandatory: default-deny egress, OS-level block on out-of-workspace writes, no agent writes to config/hooks/skills/MCP files. Recommended: sandbox the whole process tree, microVM, no cached approvals, brokered short-lived secrets, ephemeral sandboxes. |
| 22 | [Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing), 20 Oct 2025 [V] | bubblewrap and Seatbelt; network only via a Unix-socket proxy outside the sandbox; credentials stay outside; 84% fewer prompts. `sandbox-runtime` is Apache-2.0, 7,053 stars. |
| 23 | [Capsem](https://github.com/google/capsem), [un]prompted II [V] | Open-source (Apache-2.0) Rust hypervisor sandbox for coding agents: VM boot under 2 s, HTTPS inspection, MCP routing, per-session telemetry. macOS 14+ Apple Silicon and KVM Linux only; 0.7 pre-release. |
| 24 | [Claude Code advisories](https://github.com/anthropics/claude-code/security/advisories) (36) and [Cursor advisories](https://github.com/cursor/cursor/security/advisories) (30+) [V] | Sandboxes get escaped through config and paths: missing `settings.json` writable in sandbox (CVE-2026-25725), git worktree confusion (CVE-2026-55607), Edit-tool TOCTOU (CVE-2026-88968), Cursor git hooks and Claude hook config (CVE-2026-26268, CVE-2026-48124). |

### D. Runtime monitoring, eBPF, provenance, detection

| # | Item | Takeaway |
|---|---|---|
| 25 | [AgentSight](https://arxiv.org/abs/2508.02736), Aug 2025 [V] | eBPF "boundary tracing": intercept TLS LLM traffic for intent, kernel events for effect, correlate across processes; under 3% overhead. MIT, active (push 2026-10-31). Linux only. |
| 26 | [Promptware EOD](https://unpromptedcon.org/agenda), Zenity, Oct 2026 [V] | Detonation chamber compares what the agent believes happened with what the kernel recorded; hundreds of malicious skills among tens of thousands. |
| 27 | [Towards Monitoring Too Cheap To Meter](https://unpromptedcon.org/agenda), Dreadnode, Oct 2026 [V] | ScopeBench measures scope adherence under cascaded monitoring: cheap decision model first, escalate to a strong judge. |
| 28 | PromptLocate, AttnTrace ([S&P 2026](https://sp2026.ieee-security.org/accepted-papers.html)), AttriGuard ([USENIX Sec 2026](https://www.usenix.org/conference/usenixsecurity26/technical-sessions)) [T] | Research is moving from detecting injection to localising it and causally attributing tool calls to context spans. |
| 29 | [Say Shibboleth](https://unpromptedcon.org/agenda), Oct 2026 [V] | Environment features that model families react to differently fingerprint the model and harness behind an agent without injecting it. |
| 30 | [Into the Wild](https://unpromptedcon.org/agenda), Zenity honeypots, Oct 2026 [V] | Real attackers probe AI stacks within days of a CVE; SSRF via Ollama downloader and code execution via LiteLLM guardrails observed. |
| 31 | [BeyondTrust AI Agent Security docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security) [V] | Shipping: Pathfinder endpoint agent discovers agents, MCP servers, LLM endpoints and skills via process names, code signatures and LLM traffic; kernel and network enforcement; agent identity separate from user; policy replay. Windows 11/Server 2022 x64 and macOS 14 to 26 only; needs a trusted root CA; does not inspect prompts. |
| 32 | [Microsoft Agent 365 overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview), updated Oct 2026 [V] | Registry plus Entra, Purview and Defender; GA 1 May 2026, per-user licence, E5 recommended. Registry-centric, so unregistered bespoke agents are the gap. |

### E. Identity and human presence

| # | Item | Takeaway |
|---|---|---|
| 33 | [draft-ietf-wimse-aims-01](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/), 2 Nov 2026 [V] | Agent is a workload with one WIMSE/SPIFFE identifier; short-lived bound credentials; static API keys are an antipattern; LLM must not access credentials; OAuth for delegation, transaction tokens, CIBA for human approval, SSF/CAEP for revocation, tamper-evident audit. Authors from AWS, Zscaler, Ping, OpenAI, Okta. Replaces [draft-klrc-aiagent-auth](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/). |
| 34 | [Identity Management for Agentic AI](https://arxiv.org/abs/2510.25819), OpenID Foundation, Oct 2025 [V] | Open problems: delegated authority, agent-centric identity, AI workload differentiation, scalable access control. |
| 35 | [Approval Is Not Human Presence](https://unpromptedcon.org/agenda), Dropbox, Oct 2026 [V] | Deployed MCP permission broker demands evidence of a present human, tested against an agent holding the user's UID and session. |
| 36 | [Agent Authorization Is Not a Vault Problem](https://unpromptedcon.org/agenda), Oct 2026 [V] | Open-source USB authenticator shows the exact bytes before signing; first design had a signing-oracle flaw. |
| 37 | [MCP Security Best Practices (draft)](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) [V] | MUST NOT pass through tokens; per-client consent for proxies; SSRF defences; MCP is now stateless, handles are not authentication; clients must show the exact local-server command and should sandbox it. |

### F. AI control and misalignment (monitoring an agent that may evade)

| # | Item | Takeaway |
|---|---|---|
| 38 | [AI Control](https://arxiv.org/abs/2312.06942), Redwood [M] | Trusted and untrusted monitoring, defer-to-trusted, audit budgets: design for a model that is trying to subvert you. |
| 39 | [Ctrl-Z](https://arxiv.org/abs/2504.10374), Apr 2025 [V] | Resampling suspicious actions plus step history cuts attack success 58% to 7% at about 5% usefulness cost (BashBench, 257 tasks). |
| 40 | [BashArena](https://arxiv.org/abs/2512.15688), Dec 2025 [V] | 637 sysadmin tasks; Claude Sonnet 4.5 completes sabotage undetected by a GPT-4.1 mini monitor 26% of the time at 4% FPR. |
| 41 | [SHADE-Arena](https://arxiv.org/abs/2506.15740), Anthropic, Jun 2025 [V] | Best saboteur 27%; best monitor AUC 0.87; success depends heavily on a scratchpad hidden from the monitor. |
| 42 | [Async Control](https://arxiv.org/abs/2512.13526), UK AISI, Dec 2025 [V] | Post-hoc ensemble monitor on software-engineering agents: 6% FNR at 1% FPR, zero added latency. |
| 43 | [Adaptive Attacks on Trusted Monitors](https://arxiv.org/abs/2510.09462), v2 Mar 2026 [V] | Untrusted model injects the monitor through its own output; defer-to-resample backfires into best-of-n. |
| 44 | [CoT Monitorability](https://arxiv.org/abs/2507.11473), 41 authors, Jul 2025 [V] | Reasoning traces are a useful but fragile oversight signal that development choices can destroy. |
| 45 | [Backdoors That Evade CoT Monitoring](https://unpromptedcon.org/agenda), Microsoft, Oct 2026 [V] | Poisoned models emit benign reasoning with attacker-chosen answers; activation analysis hints but does not reliably find it. |
| 46 | [Thought Injection](https://arxiv.org/abs/2611.08811), 6 Nov 2026 [V] | Injections styled as the model's own reasoning reach 50% success (reverse shell, repo backdoor) where user-voice injections got 0; stripping tags is unreliable. |
| 47 | [Stress-testing anti-scheming training](https://arxiv.org/abs/2509.15541), OpenAI/Apollo, Sep 2025 [V] | o3 covert actions 13% to 0.4%, but evaluation awareness causally reduces misbehaviour, so watched behaviour understates risk. |
| 48 | [Agentic Misalignment](https://arxiv.org/abs/2510.05179), Anthropic, Oct 2025 [V] | 16 models; insider-style behaviour (blackmail, leaking) in simulations, often against direct instructions; less when the model says it is a test. |
| 49 | [Pilot Sabotage Risk Report](https://alignment.anthropic.com/2025/sabotage-risk-report/), Anthropic, 28 Oct 2025 [V] | Lab judges risk "very low, but not completely negligible" and relies on monitoring plus security controls; METR reviewed. |
| 50 | [Authorization Drift](https://arxiv.org/abs/2611.09113), 6 Nov 2026 [V] | No adversary needed: 25,207 trajectories, 13 models; frontier models exceed scope in 43 to 61% of tasks, mostly early over-collection; more capable models drift more. |
| 51 | [ControlArena](https://github.com/UKGovernmentBEIS/control-arena), UK AISI [V, repo metadata] | MIT, active (push 2026-10-26); reusable settings and protocols for control experiments. |

### G. Offence

| # | Item | Takeaway |
|---|---|---|
| 52 | [The Attacker Moves Second](https://arxiv.org/abs/2510.09023), Oct 2025; USENIX Sec 2026 [V] | 12 defences, most broken above 90% by gradient, RL, search and human red-teaming. Static-attack evaluations are meaningless. |
| 53 | [Bypassing LLM Guardrails](https://arxiv.org/abs/2504.11168), Apr 2025 [V] | Character injection and AML evasion reach up to 100% against six guardrails including Azure Prompt Shield and Meta Prompt Guard. |
| 54 | Bypassing Prompt Guards in Production with Controlled-Release Prompting, [USENIX Sec 2026](https://www.usenix.org/conference/usenixsecurity26/technical-sessions) [T] | Lightweight input filters are systematically weaker than the model they guard. |
| 55 | [Voluntary Servitude](https://arxiv.org/abs/2611.04393), NeurIPS 2026 [V] | A fabricated hazard written as an ordinary review steers agents 60.4% (instruction injection 66.0%), passes detectors as benign; a corroboration rule removes about 95% non-adaptively. |
| 56 | [Prompt injection to RCE in AI agents](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/), Trail of Bits, 22 Oct 2025 [V] | Argument injection into allow-listed commands: `go test -exec`, `git show --output`, `rg --pre`, `fd -x`. Sandbox first; `--` separators and no shell second. |
| 57 | [Caught in the Hook](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/), Check Point, 25 Feb 2026 [V] | Repo-supplied `.claude/settings.json` hooks, `enableAllProjectMcpServers` and `ANTHROPIC_BASE_URL` ran or leaked the API key before the trust dialog (CVE-2025-59536, CVE-2026-21852). |
| 58 | [Cross-Agent Privilege Escalation](https://embracethered.com/blog/posts/2025/cross-agent-privilege-escalation-agents-that-free-each-other/), 24 Sep 2025 [V] | Hijacked Copilot writes `.mcp.json`, `.claude/settings.local.json`, `CLAUDE.md`; Claude Code then runs attacker code, and can return the favour. |
| 59 | [AgentHopper](https://embracethered.com/blog/posts/2025/agenthopper-a-poc-ai-virus/), 29 Aug 2025 [V] | One conditional payload branches per agent, infects local repos and pushes; used Copilot CVE-2025-53773 (YOLO mode via settings), Amp, Amazon Q `find -exec`, Kiro allow-list rewrite. |
| 60 | [IDEsaster](https://maccarita.com/posts/idesaster/), 6 Dec 2025 [V] | 30+ bugs, 24 CVEs, every AI IDE tested: injection, then agent tool, then base IDE feature (remote JSON schema fetch, settings overwrite, multi-root workspace). |
| 61 | [Invitation Is All You Need](https://arxiv.org/abs/2508.12175), Black Hat USA/DEF CON 33, Aug 2025 [V paper, M venue] | 14 promptware scenarios against Gemini via calendar invites; 73% rated high-critical; includes memory poisoning and app invocation. |
| 62 | [Promptware Kill Chain](https://arxiv.org/abs/2601.09625), Schneier et al., Jan 2026 [V] | Seven stages: initial access, privilege escalation, reconnaissance, persistence, C2, lateral movement, actions on objective; 21 of 36 analysed incidents span four or more. |
| 63 | [Who Is Prompt-Injecting Coding Agents?](https://unpromptedcon.org/agenda), Radware, Oct 2026 [V] | 86 million GitHub issues, PRs, comments and READMEs: about 2.5 hidden injections per 100K, including exfiltration and bot steering. |
| 64 | "Do Not Mention This to the User": malicious agent skills, [USENIX Sec 2026](https://www.usenix.org/conference/usenixsecurity26/technical-sessions) [V] | 157 confirmed malicious among 98,380 third-party skills for coding agents. |
| 65 | Parasites in the Toolchain (MCP ecosystem attacks) and Site Isolation Is Dead (agentic browsers), [IEEE S&P 2026](https://sp2026.ieee-security.org/accepted-papers.html) [T] | MCP supply chain and agentic-browser isolation are measured at scale in top venues. |
| 66 | Les Dissonances (cross-tool harvesting), Prompt Injection to Tool Selection, ObliInjection, [NDSS 2026](https://www.ndss-symposium.org/ndss2026/accepted-papers/) [T] | One tool can harvest or pollute another's data inside a shared agent; tool selection itself is injectable. |
| 67 | MUZZLE, [USENIX Sec 2026](https://www.usenix.org/conference/usenixsecurity26/technical-sessions); MemoryDojo [arXiv 2611.09721](https://arxiv.org/abs/2611.09721) [T] | Adaptive agentic red-teaming of web agents; memory poisoning traced through storage, retrieval and propagation. |
| 68 | [Tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [GitHub MCP toxic flow](https://invariantlabs.ai/blog/mcp-github-vulnerability), Invariant, 2025 [M] | Tool descriptions are instructions; a public issue can drive an agent to leak private repos. |
| 69 | [Morris II](https://arxiv.org/abs/2403.02817), [JudgeDeceiver](https://arxiv.org/abs/2403.17710), [AgentDojo](https://arxiv.org/abs/2406.13352) [M] | Self-replicating prompts, optimisation attacks on LLM judges, and the benchmark almost every defence above is measured on. |
| 70 | [Disrupting AI-orchestrated espionage (GTG-1002)](https://www.anthropic.com/news/disrupting-AI-espionage), Nov 2025 [M] | A state actor used a coding agent as the operator; "The death of TTPs" and "Not a Boogeyman" at [un]prompted II [T] continue the theme. |

## Matrix: defence families against what the evidence says

| Family | Guarantee | Utility cost | Defeated by | Where we can enforce it |
|---|---|---|---|---|
| Input/output classifiers | None under adaptive attack (52 to 55) | Low | Optimisation, encoding, non-instruction payloads | Gateway, as a signal only |
| LLM action judge | Probabilistic; 6 to 26% miss (18, 40, 42) | Low to medium | Injecting the judge, ambiguous consent | Hook, gateway |
| Control/data separation | Control-flow integrity (1, 3, 6, 7) | 7 points on AgentDojo; large on computer use | Data-only steering, branch steering | Our own gateway modes; not third-party agents |
| IFC labels at sinks | Deterministic for labelled flows (2, 9) | Depends on label precision | Unlabelled channels, label laundering | Gateway plus OS sensor |
| Declarative tool policy | Deterministic (11 to 13, 15) | Low | Policy gaps, argument injection | Hook, MCP gateway |
| OS sandbox | Strong if config and paths are covered (21 to 24) | Low to medium | Config persistence, TOCTOU, symlinks, shared kernel | Sensor |
| Async monitoring | 6% FNR at 1% FPR (42) | Zero latency | Irreversible actions before review | Backend |

## Weak points, gaps and risks

- Almost all defence numbers are on AgentDojo-class benchmarks with non-adaptive attacks; several Nov 2026 results (15, 17) are self-reported 0% figures from single groups.
- CaMeL and FIDES reference code has not been pushed since mid-2025; treat them as designs, not dependencies.
- Control/data separation cannot be imposed on closed third-party agents (Claude Code, Cursor, Copilot); for those we only have hooks, gateways and the OS.
- Open sandboxes cover macOS and Linux; nothing equivalent was found for Windows. BeyondTrust covers Windows and macOS but not Linux.
- HTTPS inspection needs a trusted root CA (BeyondTrust, Capsem, AgentSight via uprobes), which breaks on pinned clients and is itself a high-value target.
- LLM monitors and judges expand the attack surface (43, 46, 55); every one we add needs its own red-team budget.
- Signatures and pins prove origin, not behaviour (9, 10; CVE-2026-86063 bypassed a plugin SHA pin with a SHA-shaped branch name).

## Implications for our design: 20 principles

1. **The model is never the control.** Classifiers produce signals, not verdicts. (52, 53, 54, 55)
2. **Enforce at the OS whatever string matching cannot decide.** Sandbox the whole process tree including hooks and MCP startup. (21, 24, 56)
3. **Agent configuration is protected system state.** Block agent-lineage writes to hooks, rules, skills, MCP and IDE settings for every agent on the host, not just the writer. (21, 57, 58, 59, 60)
4. **Nothing runs before trust.** Evaluate repo-supplied config before any hook, MCP start or network call. (57, 24)
5. **Bind checks to inodes and descriptors, not paths.** Assume code inside the sandbox races you. (24)
6. **Default-deny egress with brokered secrets.** Credentials stay outside the sandbox and outside model context. (21, 22, 33)
7. **Track Rule-of-Two state per session and gate the third leg.** (5, 4)
8. **Offer control/data separation as a gateway mode** (plan-then-execute, compile-then-execute) for agents we host. (1, 3, 6, 7)
9. **Carry integrity and confidentiality labels from source to sink** across gateway and sensor; decide deterministically at sinks. (2, 9, 15)
10. **Policy is deterministic and monotonic.** LLMs may draft; narrowing is automatic; widening needs a human. Deterministic verifiers beat LLM checkers. (10, 11, 12, 13, 14)
11. **Approval is not presence.** Replace per-action prompts with boundaries and reserve step-up, with presence evidence, for a few high-impact actions; never cache approvals that break isolation. (18, 19, 21, 35, 36)
12. **Judges see user intent and tool calls, not agent prose or raw tool output.** Add provenance labels to cover the blind spot. (18, 43, 46)
13. **Publish and budget for miss rates.** Report FPR and FNR per detector; never present a monitor as complete. (18, 40, 41, 42)
14. **Monitors are attack surface.** Treat agent output as hostile to the monitor, ensemble, and run adaptive attacks in CI. (43, 45, 52, 69)
15. **Ground truth is effect, not narrative.** Diff what the agent claimed against kernel and network records; do not depend on chain-of-thought. (25, 26, 44, 45, 47)
16. **Design for the non-adversarial case first.** Overeager scope escalation and authorisation drift are the daily volume. (18, 50, 48)
17. **Respond like a control protocol.** Deny-and-continue, resample, defer to human, async review, escalate after N denials, kill headless runs. (18, 39, 42)
18. **Attribute by lineage and traffic, not credentials.** Give agents their own short-lived workload identities; fingerprint the model when identity is unreliable. (25, 29, 31, 33, 34)
19. **Skills, plugins and MCP servers are supply chain.** Verify pins after checkout, require permission manifests, detonate, and enforce runtime egress obligations. (9, 13, 15, 26, 64, 65)
20. **Map detections to the promptware kill chain,** including persistence in memory and lateral movement across agents and repos. (59, 61, 62, 63, 67)

Reuse candidates (licences verified today): `anthropics/sandbox-runtime` (Apache-2.0), `google/capsem` (Apache-2.0, Rust), `eunomia-bpf/agentsight` (MIT), `sunblaze-ucb/progent` (MIT), `ethz-spylab/agentdojo` (MIT) and `UKGovernmentBEIS/control-arena` (MIT) as test harnesses, `snyk/agent-scan` (Apache-2.0).

## Ideas worth stealing and whitespace

We found no shipping product doing these; the two product doc sets read today (31, 32) do not describe them.

- **Provenance-aware, reasoning-blind judge:** auto mode's judge cannot tell whether an identifier came from the user or a web page (18). Feed it taint labels from the sensor and gateway instead of content.
- **Claimed-versus-observed diffing as a live endpoint detection,** not only in a detonation lab (25, 26).
- **Cross-vendor agent-config integrity monitor** with writer lineage: one agent editing another's config is a high-fidelity alert (58).
- **Session Rule-of-Two state machine** enforced by the sensor (5).
- **Monotonic per-task policies** with solver-checked narrowing (11) plus presence-attested widening (35, 36).
- **Germline or ephemeral-fork execution for MCP servers** (9), and transactional copy-on-write workspaces with rollback as a response action (17).
- **Control-protocol responses in an EDR:** resample, defer-to-trusted, async audit with an explicit budget (39, 42), with monitor-injection hardening (43).
- **Model shibboleths and agent-targeted canaries** to separate agent from human on shared credentials (29); auto mode's "credential exploration after an auth error" is a ready-made honeytoken trigger (18).
- **Drift and excess-agency scores per agent and model** as posture metrics (50; AgencyScore at [un]prompted II).
- **Repository and context pre-scan for hidden injections** using prevalence data (63), plus skill detonation at install (26, 64).
- **Adaptive-attack regression suite shipped with the product** so users can measure their own deployment (52, 51).

## Could not verify / open questions

- **Web search was unavailable**, so discovery of post-June-2026 work relied on conference and arXiv listings; coverage of blogs and vendor research after that date is thin.
- **DEF CON 34** (defcon.org and media.defcon.org reset the connection three times) and **Black Hat USA 2026** (HTTP 403): no 2026 talk lists obtained. RSAC 2026, Black Hat Europe/Asia, fwd:cloudsec, BSides, OffensiveCon and SaTML were not reached.
- **[un]prompted I (March 2026)** agenda: archive URL returned 404.
- OpenAI's scheming post (403); the arXiv paper was used instead. OpenAI's write-up on monitoring internal coding agents was not reached.
- The brief's "hook races": no paper found by that name. Closest evidence is the TOCTOU, symlink and hook-config advisories in item 24.
- USENIX Security 2026 programme was read only to about half its length; NDSS and S&P lists are title-only.
- A decision/guardrail model called "Jev" appears in several Nov 2026 titles and one talk; not identified.
- Items tagged [M] were not re-fetched; venue attributions for item 61 are from memory.
- Does BeyondTrust protect agent config files and Linux? Does Agent 365 see unregistered local agents? Not stated on the pages read.

## Sources

Per-item URLs are in the tables above (all accessed 2026-11-09). Index pages and docs:

- https://arxiv.org/list/cs.CR/recent , arXiv cs.CR listing, 3 to 9 Nov 2026
- https://unpromptedcon.org/ and https://unpromptedcon.org/agenda , [un]prompted II, 27 to 29 Oct 2026
- https://www.usenix.org/conference/usenixsecurity26/technical-sessions , USENIX Security 2026
- https://www.ndss-symposium.org/ndss2026/accepted-papers/ , NDSS 2026
- https://sp2026.ieee-security.org/accepted-papers.html , IEEE S&P 2026
- https://github.com/anthropics/claude-code/security/advisories , Claude Code advisories, Jun 2025 to Oct 2026
- https://github.com/cursor/cursor/security/advisories , Cursor advisories, 2024 to Jul 2026
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security , BeyondTrust AI Agent Security
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview , Microsoft Agent 365 overview, updated 23 Oct 2026
- https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/ , AI Identity Management System, 2 Nov 2026
- https://modelcontextprotocol.io/specification/draft/basic/security_best_practices , MCP Security Best Practices (draft)
- https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/ , NVIDIA, 30 Jan 2026
- https://www.anthropic.com/engineering/claude-code-auto-mode , 25 Mar 2026; https://www.anthropic.com/engineering/claude-code-sandboxing , 20 Oct 2025

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (shared budget exhausted), so every check is a direct fetch of a primary page, the IETF datatracker API, or `gh api` (read-only). Verdicts: confirmed, corrected, refuted, unverifiable._

### Claims the architecture depends on

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Adaptive attacks (gradient, RL, random search, human red-teaming) bypassed 12 defences, most above 90% ASR, most having reported near zero | confirmed | Abstract wording matches. The USENIX Security 2026 programme lists the paper by title, so the venue statement in the TL;DR also holds. | https://arxiv.org/abs/2510.09023 ; https://www.usenix.org/conference/usenixsecurity26/technical-sessions |
| 2 | Claude Code has 36 published advisories (Jun 2025 to Oct 2026), Cursor over 30, dominated by parser bypasses, pre-trust execution, symlink/TOCTOU, sandbox escapes, config injection | corrected | The `anthropics/claude-code` repo has 36 advisories (23 Jun 2025 to 26 Oct 2026), but 4 of them affect Claude Desktop/Cowork, not Claude Code; 32 affect Claude Code packages. `cursor/cursor` has 33 (Sep 2024 to Jul 2026), 3 of which are web-API IDOR/billing issues. The class breakdown holds. | `gh api repos/anthropics/claude-code/security-advisories` ; `gh api repos/cursor/cursor/security-advisories` |
| 3 | NVIDIA AI Red Team: three mandatory controls (egress, no writes outside workspace, no agent writes to config incl. hooks, skills, MCP) | confirmed | Page text: network egress controls; block file writes outside the workspace; block writes to configuration files "no matter where they are located" (hooks, skills, local MCP configurations named). Six further controls are "recommended". Dated 30 Jan 2026. | https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/ |
| 4 | Auto mode classifier sees only user messages and tool calls; 0.4% FPR, 17% FNR on real overeager actions; users accept 93% of prompts | corrected | The numbers match the March 2026 post, but the 17% FNR comes from only 52 real overeager actions (0.4% FPR is on 10,000 real calls; 5.7% FNR on synthetic exfiltration). "Only user messages and tool calls" is out of date: current docs say the classifier also receives CLAUDE.md content, skips read-only tool calls, reviews subagent task descriptions and reports, and reads a PostToolUse hook's `classifierContext` field (v2.1.236+). Tool results are still stripped. | https://code.claude.com/docs/en/permission-modes ; https://code.claude.com/docs/en/hooks ; https://www.anthropic.com/engineering/claude-code-auto-mode |
| 5 | Untrusted agent can prompt-inject its trusted monitor; evades diverse monitors on two AI-control benchmarks; defer-to-resample becomes best-of-n | confirmed | Abstract matches; v2 dated 2 Mar 2026. The abstract does not name the two benchmarks. | https://arxiv.org/abs/2510.09462 |
| 6 | BashArena: Sonnet 4.5 evades GPT-4.1 mini monitor 26% at 4% trajectory-wise FPR; Async Control ensemble monitor 6% FNR at 1% FPR | confirmed | Both abstracts match. The Async Control figure is on one held-out environment out of five; the abstract page does not show affiliations (code is under UKGovernmentBEIS). | https://arxiv.org/abs/2512.15688 ; https://arxiv.org/abs/2512.13526 |
| 7 | CaMeL: 77% of AgentDojo tasks with provable security vs 84% undefended; repo not pushed since June 2025 | confirmed | 77% is the v2 (24 Jun 2025) figure. `google-research/camel-prompt-injection`: last push 2025-06-20, three commits in total, Apache-2.0, not archived. `microsoft/fides` last push 2025-05-30. | https://arxiv.org/abs/2503.18813 ; `gh api repos/google-research/camel-prompt-injection` |
| 8 | Hijacked agent writes another agent's config so the second executes attacker code; Microsoft did not treat it as needing immediate servicing | confirmed | Post dated 24 Sep 2025 names all four files plus `AGENTS.md`, `.gemini/settings.json`, `.vscode/mcp.json`, `.vscode/tasks.json`. The MSRC position is the author's paraphrase, not a quote. Only Copilot-to-Claude is demonstrated; the reverse direction is described, not shown. | https://embracethered.com/blog/posts/2025/cross-agent-privilege-escalation-agents-that-free-each-other/ |
| 9 | `draft-ietf-wimse-aims-01` (2 Nov 2026): one WIMSE/SPIFFE identifier per agent, short-lived bound credentials, static API keys an antipattern, LLM must not access credentials | confirmed | Datatracker API: rev 01, 2026-11-02, WIMSE WG, 33 pages, expires 6 May 2027, replaces `draft-klrc-aiagent-auth`. Exact strength: "MUST be assigned exactly one WIMSE identifier, which MAY be a SPIFFE ID"; credentials "SHOULD be short-lived" and MUST carry an expiry. It is an Informational Internet-Draft, not a standard. First author is from Defakto Security. | https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/doc.json |
| 10 | BeyondTrust AI Agent Security: kernel and network enforcement, agent identity separate from user; Windows 11/Server 2022 x64 and macOS 14 to 26 only; needs trusted root certificate | confirmed | Exact text: Windows 11 or Windows Server 2022 "or later", x64 only (no Windows on Arm); macOS 14, 15 or 26; Windows and macOS endpoints only. Root certificate on Windows via GPO, Intune or the agent; macOS needs an MDM profile that also approves system extensions. Policy can also act through coding-tool hooks. The page states no release status (licence via account team), and kernel enforcement is the vendor's description, not independently tested. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |

### Further statements in the brief

| Statement | Verdict | Note | Source |
|---|---|---|---|
| "Open sandboxes cover macOS and Linux; nothing equivalent was found for Windows" (Weak points; also item 22) | refuted | `anthropics/sandbox-runtime` documents Windows support (alpha): a dedicated `srt-sandbox` local account, a Windows Filtering Platform egress fence keyed on its SID, a write-restricted token and explicit ACEs, with a bundled `srt-win.exe` for x64 and arm64. `openai/codex` (Apache-2.0) ships `codex-rs/windows-sandbox-rs` and `windows-sandbox-service`. | `gh api repos/anthropics/sandbox-runtime/readme` ; `gh api repos/openai/codex/contents/codex-rs` |
| Agent 365 is "registry-centric, so unregistered bespoke agents are the gap"; "Does Agent 365 see unregistered local agents? Not stated" (item 32, TL;DR, open questions) | corrected | Agent 365 docs have "Local agents (preview)" and "Shadow AI (preview)" pages: detection of about 30 named local agents (Claude Code, Codex CLI, Cursor, Copilot CLI, OpenClaw and others) on Intune-managed Windows devices, with blocking for a subset. Defender for Endpoint local AI agent discovery is GA on Windows and macOS for 60+ named agents, including MCP server configurations (WSL in preview, no native Linux). Defender "AI agent runtime protection" (preview, Windows) audits or blocks prompt injection through Claude Code and Copilot hooks plus network inspection. What remains open: agents not on the named list, native Linux, and deterministic OS-level policy. | https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-local ; https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-shadow-ai ; https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix ; https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview |
| Principle 17: "escalate after N denials, kill headless runs" as auto mode behaviour (item 18) | corrected | The 3-consecutive / 20-total thresholds are current and not configurable. Current docs say a non-interactive `-p` run without a permission-prompt tool is not stopped: the blocked action does not run and Claude keeps working. The March 2026 post described termination; the product has changed. | https://code.claude.com/docs/en/permission-modes |

Checked and found accurate along the way: `anthropics/sandbox-runtime` is Apache-2.0 with 7,053 stars; CVE-2026-86063 is a plugin SHA-pin bypass via a branch named like the pinned SHA; Agent 365 GA on 1 May 2026, per-user licence, "works best" with E5, page updated 23 Oct 2026.
