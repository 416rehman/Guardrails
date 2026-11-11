# Open-source sweep: agent security, observability and sandbox projects, and dependency health

_Researched 2026-11-10 (search-backed follow-up)_

Method: 16 web searches (2 extended), GitHub REST API through `gh` (repo metadata, releases, 90-day commit counts since 2026-08-12, published security advisories, issue trackers), crates.io API, and direct fetches. Tags: [V] verified on a primary source today, [S] secondary source only, [I] inference. "Authors" means distinct commit authors among the last 100 commits in the 90-day window.

## TL;DR

- **No foundation hosts an agent-security project yet.** AAIF has 10 projects (22 Oct 2026), all protocols, gateways, formats or sandboxes. Its Technical Committee declined Microsoft's Agent Governance Toolkit (29 Jun 2026), declined a governance working group (28 Sep), paused IBM ContextForge, and **nono withdrew its donation on 9 Nov 2026**, citing non-transparent TC and Governing Board process. [V]
- **Sandbox substrate is consolidating in CNCF.** Google announced the donation of Agent Substrate (Apache-2.0, v1.0.0-rc.3) and gVisor to CNCF Sandbox on 5 Nov 2026; `kubernetes-sigs/agent-sandbox` is at v1.0.10; kagent is at v1.0.0-rc4. Cedar has been CNCF Sandbox since 8 Oct 2025. [V]
- **New since June that earlier briefs missed:** `cisco-ai-defense/project-quarry` (multi-turn detection DSL, alpha), `alibaba/loongsuite-pilot` (local telemetry collector for 17 coding agents), `microsoft/nvx` (micro-VM sandbox on OpenVMM), `docker/sandbox-kit-spec` (agent authority as an OCI artifact), `agent-substrate/substrate`, `highflame-ai/zeroid` (agent identity, RFC 8693), `gebruder/wirken`. [V]
- **Three candidate dependencies are effectively single-maintainer or stalled:** `ferrisetw` (last commit 2025-08-20, last crate release 2024-06-27), `tough` (no commits since 2026-07-10, three CVEs in April 2026), `falcosecurity/prempti` (one commit in 90 days, still a release candidate). [V]
- **Bus factor 1 on five more:** rsigma, Rustinel, endpoint-sec, Kingfisher, AccessKit. Each is active; each has one person writing 70 to 95% of recent commits. [V]
- **The gateways we planned to reuse have authorisation-bypass advisories.** agentgateway: 7 advisories in 2026, including MCP sessions crossing routes and overwriting the authorisation policy. Agent Router: 24, including CEL evaluation errors that silently bypass Deny rules. [V]
- **The infrastructure tier needs a patch discipline, not trust.** 2026 published advisories: OpenBao 38 (5 critical), NATS server 27 (12 high, many pre-auth), Santa 15 (1 critical), ToolHive 54, ContextForge 19, nono 15. [V]
- **The OWASP ACS reference Guardian fails its own mandatory baseline on the wire:** it accepts unsigned, replayed and stale envelopes and publishes no chain head (issue #184, 23 Sep 2026, open). [V]
- **Skill scanners were bypassed across the board** (Trail of Bits, 3 Jun 2026, via CSA note 10 Jun): ClawHub/VirusTotal Code Insight, Cisco skill-scanner, Gen, Socket and Snyk. [S]
- **No licence change was found in any selected dependency.** No new permissively licensed small injection classifier appeared since July. [V for the first; search-negative for the second]
- **Rune is 19 days old** (created 2026-10-22, no release, two main authors, 204 open issues). Astryx is pre-1.0 (v0.7.11) with breaking changes inside patch releases. [V]

## Findings

### 1. Projects created or popularised since June 2026

**Detection and observability**

- **Cisco Project Quarry** (`cisco-ai-defense/project-quarry`, Apache-2.0, Python 3.11 to 3.13, created 2026-10-27, v0.1.0, 97 stars). Rules in a YARA-like DSL over messages, tool calls, tool results and event order; each rule compiles to a symbolic finite-state automaton; optional model calls from a rule; explicit input, compile, time and model-call limits. README: alpha, syntax may change before 1.0. Cisco's stated motive: most tools examine single interactions and miss the context. [V] ([repo](https://github.com/cisco-ai-defense/project-quarry), [The Register, 2026-10-28](https://www.theregister.com/security/2026/10/28/cisco-open-sources-tool-for-detecting-ai-agents-on-hacking-sprees/5305867))
- **Alibaba LoongSuite Pilot** (`alibaba/loongsuite-pilot`, Apache-2.0, TypeScript, v1.16.0 2026-11-06, 275 commits in 90 days, 11 authors). Discovers agents on a developer machine, installs hooks or plugins, normalises into a GenAI event schema, exports JSONL, HTTP, OTLP and Alibaba SLS, with per-agent content-capture policy and secret masking. Covers Claude Code, Codex, Copilot CLI, Cursor, Kiro, OpenCode, OpenClaw, Hermes, Pi, Grok Build, Qoder and others. Observe only. This is the nearest open analogue to numbat's collection layer and has broader agent coverage. [V] ([repo](https://github.com/alibaba/loongsuite-pilot))
- **Uber ADR** (Apache-2.0, `sensor-v1.0.0` 2026-07-31, 126 commits in 90 days, 18 authors). README still says Prevention "is not included in the current open-source release" and that the offline Explorer red-team engine is withheld. [V] ([repo](https://github.com/uber/ADR))
- **Perplexity numbat** v0.3.0 (2026-10-19), 93 commits in 90 days, one dominant author. [V]

**Sandboxes**

- **Agent Substrate** (`agent-substrate/substrate`, Apache-2.0, v1.0.0-rc.3 2026-11-05, 6,321 stars, 38 authors). Actor model on Kubernetes: session state snapshotted at turn end, resumed on pre-warmed workers in under 500 ms (Google's claim), gVisor by default, Cloud Hypervisor microVMs under the same API, per-actor network rules. Donated to CNCF Sandbox with gVisor. The blog does not describe a credential broker, identity or audit hooks. [V] ([Google Open Source blog, 2026-11-05](https://opensource.googleblog.com/2026/11/sandboxing-untrusted-ai-agents-at-scale.html))
- **microsoft/nvx** (MIT, Rust, created 2026-08-27, dev pre-releases only, 831 stars, one author). Micro-VM sandbox on OpenVMM with Linux guests; hosts are Linux KVM, Linux MSHV and Windows. Research-grade. [V] ([repo](https://github.com/microsoft/nvx))
- **docker/sandbox-kit-spec** (Apache-2.0, v3.0.0-m.12 pre-release 2026-11-05, marked experimental). A "Kit" packages harness, tools, MCP servers, skills and the authority they request (credentials, network destinations) in one OCI artifact under one digest, so a change in authority shows in a diff. Ships a BuildKit frontend and conformance suites. [V] ([repo](https://github.com/docker/sandbox-kit-spec))
- **perplexityai/SPACE** (Apache-2.0, Rust, created 2026-10-01, no tagged release, 2,095 stars, 8 authors). Firecracker microVM sandbox service with an HTTP API, warm pools, snapshots, operator egress profiles and an E2B compatibility wrapper. Kubernetes-first. [V] ([repo](https://github.com/perplexityai/SPACE))
- **OpenSandbox** moved to `opensandbox-group/OpenSandbox` and is an AAIF project (17,009 stars, 2,445 commits in 90 days). [V]
- Community: `BitMiracle-AI/Dormice` (Apache-2.0, E2B-compatible single machine), `Ephemeral-AI-Lab/layerfs` (MIT). Metadata only.

**Gateways, firewalls, identity**

- **highflame-ai/zeroid** (Apache-2.0, v1.26.0 2026-11-03, 212 stars, 9 authors): agent identity service using RFC 8693 token exchange to carry orchestrator, sub-agent and principal in one credential. [V metadata, S description]
- **Kagenti was renamed rossoctl** (`rossoctl/rossoctl`, Apache-2.0, v0.8.0 2026-10-05). SPIFFE plus token exchange for agents on OpenShift. [V]
- **agentrust-io/agent-manifest** (GitHub reports Apache-2.0; 14 advisories in 2026): attested agent runtime identity, spun out of AGT. [V metadata]
- **gebruder/wirken** (MIT, 207 stars): gateway between messaging apps and agents; Help Net Security notes that MCP child processes and the LLM client still make their own outbound connections. [S] ([Help Net Security, 2026-11-09](https://www.helpnetsecurity.com/2026/11/09/wirken-open-source-ai-agent-gateway/))
- **hardenrun/aif** (1,913 stars, created 2026-08-01): no licence, three commits, installer script only. Not open source in any usable sense. [V]
- Small entrants (metadata only): `solongate/agent-security` (Apache-2.0), `decionis/agent-safe-pipeline` (Apache-2.0), `Bevel-Software/Hexis` (Apache-2.0), `halofyai/halofy` (AGPL-3.0), `securetron-gh/aifw` (no licence), `openguardrails/rontye` (Apache-2.0).

**Scanners, AgBOM, red-team**

- Skill scanners: NVIDIA SkillSpector (Apache-2.0, v2.13.4, 25,125 stars), Cisco skill-scanner (2.3.2), Snyk agent-scan (v0.6.11), Mondoo skillcheck (Apache-2.0, v0.4.0; unknown skills show as clean). [V metadata]
- AgBOM: the OWASP Agent Observability Standard repository has had no commits since 2026-07-08; its CycloneDX mapping is still a working draft. Generators (`agent-bom`, `ai-agentbom`) are small PyPI tools; GitHub search found only repositories with 0 to 2 stars. ACS carries AgBOM events instead. [V for repo state, S for the tools] ([AOS](https://aos.owasp.org/spec/inspect/))
- Red-team: promptfoo (MIT, now part of OpenAI [S]). New benchmarks in October preprints: CarryoverBench (persistent indirect injection), STEER-Bench (computer-use). An NVIDIA "AgentBreaker" reported from Black Hat could not be found on GitHub. [S] ([Adversa, November 2026](https://adversa.ai/blog/top-ai-agent-security-resources-november-2026/))
- Adjacent, not competitors: `openai/codex-security`, `anthropics/oss-scanner`, `cloudflare/security-audit-skill`, `google/mantis`, `capitalone/VulnHunter` are agentic vulnerability finders.

**Large companies with nothing new in this category since June** (GitHub org search, repos over 60 to 80 stars): Meta, AWS (beyond `strands-agents/box`), GitHub, CrowdStrike, Elastic, Datadog, Snyk, Palo Alto, Sysdig, Falco. [V, search-negative]

### 2. Dependency health (GitHub and crates.io, 2026-11-10)

| Dependency | Latest (date) | Commits 90d | Maintainers | 2026 advisories | Home |
|---|---|---|---|---|---|
| cedar | 4.14.1 (11-02) | 92 | 12 authors, all AWS [I] | 2: high memory exhaustion in parser (10-22); low template-link divergence | CNCF Sandbox |
| dogwood | 1.1.1 (11-06) | 16 | 4 | 0 | `dogwood-policy` org, created 2026-07 |
| rsigma | 0.26.0 (11-02) | 604 | 1 (90 of 100), Timescale employee | 5 (3 high), all in daemon, MCP and enricher code | Timescale org |
| yara-x | 1.23.0 (11-05) | 245 | 1 lead (80 of 100) + 8 | 1 low (compiled-rule deserialisation) | VirusTotal |
| aya | 0.16.0 (10-28) | 206 | 2 core | 0 | community org |
| endpoint-sec | 0.6.2 (09-08) | 20 | 1 (HarfangLab) | 0 | vendor |
| ferrisetw | 1.2.0 (2024-06-27) | **0** | none active; last commit 2025-08-20 | 0 | personal |
| windows-drivers-rs | wdk 0.5.0 (10-26) | 19 | 3 to 4 Microsoft | 0 | Microsoft |
| agentgateway | 1.7.0 (10-27) | 842 | 32 | 7 (1 high) | AAIF |
| Agent Router | 1.2.1 (11-06) | 171 | 45 | 24 (5 high) | AAIF |
| OWASP ACS | 0.1.4 (10-16) | 137 | 1 lead (82 of 100) + 10 | 0 | OWASP GenAI Security Project |
| MS agent-control-spec | 0.4.0-beta.2 (11-04) | 97 | 1 lead; 8 stars | 0 | `responsibleai` org |
| MS agent-hooks | no release | 75 | 1 lead; 25 stars | 0 | `responsibleai` org |
| arthur-ai/ai-detection-spec | 0.17.1 (11-06) | 766 | 1 human + agents; 6 stars | 0 | vendor |
| Rustinel | 1.11.0 (11-08) | 380 | 1 | 0 | personal |
| Kingfisher | 2.18.1 (11-09) | 177 | 1 (95 of 100) | 0 | MongoDB |
| tough | 0.24.0 (07-10) | **0** | AWS; quiet since July | 3 medium (04-24): delegated-role threshold bypass, missing delegated-metadata validation, path traversal | awslabs |
| sigstore-rs | 0.15.0 (11-05) | 59 | 2 to 3 | 0 | OpenSSF |
| connect-rust | 0.9.1 and 0.8.2 (09-21) | 55 | 1 lead + ~9 | 1 medium (stalled stream body) | connectrpc (Buf) |
| DataFusion | 55.2.0 (10-07) | 1,269 | 54 | 0 | Apache SF |
| DuckDB | 2.0.0 (10-21) | 10,948 | 17+ | 0 | DuckDB Foundation |
| NATS server | 2.15.3-RC.2 (11-06) | 769 | 13 | 27 (12 high) | CNCF |
| ClickHouse | 26.10.2 (10-24) | 45,237 | 31+ | none in the repo feed | ClickHouse Inc |
| SPIRE | 1.16.0 (11-05) | 143 | 33 | 0 | CNCF Graduated |
| OpenBao | 2.7.2 (10-26) | 378 | 16 | 38 (5 critical, 7 high) | Linux Foundation |
| Santa | 2026.9 (10-27) | 116 | 9 | 15 (1 critical, 4 high) | North Pole Security |
| osquery | 5.24.1 (10-29) | 116 | 30 | 3 (2 high, Windows tables) | Linux Foundation |
| Falco | 0.45.2 (10-29) | 87 | 23, one dominant | 0 | CNCF Graduated |
| Tetragon | 1.8.0 (10-30) | 733 | 13+ | 3 (1 high: unauthenticated gRPC admin API from hostNetwork pods) | CNCF (Cilium) |
| agent-sandbox | 1.0.10 (11-06) | 554 | 32 | 0 | Kubernetes SIG |
| AccessKit | winit adapter 0.34.2 (10-25) | 57 | 1 (49 of 57) | 0 | community |
| Rune | no release | 1,810 | 2 | 0 | Anomaly; created 2026-10-22 |
| Astryx | 0.7.11 (11-07) | 4,227 | 2 leads + 10 | 0 | Meta |

Licences are unchanged from the earlier briefs (Apache-2.0, MIT, BSD-3 or MPL-2.0 throughout; osquery Apache-2.0 or GPL-2.0). [V]

Notes that change design decisions:

- **rsigma's advisories are all outside the evaluator.** They cover the OTLP HTTP endpoint (unbounded gzip), unescaped event fields in enricher and webhook URLs, and `rsigma-mcp` tools reading or mutating arbitrary files and executing commands. The parser and `rsigma-eval` have none. [V] ([advisories](https://github.com/timescale/rsigma/security/advisories))
- **agentgateway and Agent Router show the same failure class twice:** stateful MCP sessions crossing routes and overwriting policy (agentgateway, July and October), invalid tool-call IDs bypassing `mcpAuthorization`, CEL errors failing open and forgeable session resume (Agent Router, October). [V]
- **Santa's 2026 advisories read as a checklist for our sensor:** oversized argv overflowing a telemetry buffer (critical), a local user crashing the daemon to pause enforcement, tamper resistance bypassed by relocating the database directory, and a context-dependent allow cached and reused where the rule denied. [V] ([advisories](https://github.com/northpolesec/santa/security/advisories))
- **OpenBao's criticals** include remote code execution through `sys/storage/raft/snapshot-force` plugin-catalog replacement and token creation through internal operation dispatch. [V]
- **NATS highs cluster in leafnode, MQTT, WebSocket and route handling,** several pre-auth, in two batches (24 Mar, 29 Jun). [V]
- **ferrisetw open issues** include dropped events when reading existing sessions and unsupported MOF providers. `microsoft/one-collect` (MIT, v0.1.34811 2026-07-24, 11 authors) consumes ETW and Linux perf in Rust and is a candidate replacement; fit is untested. [V metadata, I fit]

### 3. What maintainers and users say is weak

- **Hooks.** numbat #21: Cursor `ReadFile` bypasses enforcement because `preToolUse` is not emitted. numbat #27: no `ask` verdict for out-of-band approval. numbat #44 and #45, prempti #53, DefenseClaw #680: release binaries or installers not code-signed. prempti #49: default rules have no coverage for WebFetch, so metadata-service and IOC-domain access is unseen. DefenseClaw #599: hook guardian missed same-window atomic hook replacement. Practitioner posts report subagents not triggering the parent's PreToolUse hooks and agents able to edit their own hook configuration. [V for issues, S for the posts]
- **ACS.** Beyond #184: #435 (the spec does not say what a host does with a decision that arrives after the timeout), #109 (the deny reason is dropped when another hook on the same event exits 2), #375 (a secret can pass on stderr). [V]
- **Sandboxes.** `sandbox-runtime` #419 (Seatbelt profile breaks interactive TUIs), #596 (macOS write paths not canonicalised, so `/tmp` never matches `/private/tmp`), #545 (cannot deny unlink or rename inside a write-allowed path), #560 (IOKit classes hardcoded). MXC #1061 (git-bash cannot initialise in a ProcessContainer), #1468 (about 1 ms per granted path at environment creation). OpenShell #4026 (`dotnet build` fails on EPERM), #1722 (multi-tenant deployments requested). agent-sandbox #1785 (three SDKs diverged), #1045 (credential vault proxy requested, still open). [V]
- **Gateways.** agentgateway #2665: users ask for governance UI and per-team cost analytics parity in Kubernetes mode. [V]
- **Scanners.** Evasion classes: size limits, bytecode, archive indirection, prompt injection against the LLM judge, post-install change. Recommendation from the authors: pin versions, sign, monitor at runtime. [S] ([CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/))
- **AGT.** AAIF TC feedback: too much in one repository, hard to govern, "much of which feels vibe coded", identity specs unlikely to win adoption; the policy core is the part worth standing alone. Last GitHub release is v4.1.0 (2026-06-09) although a v5.0.0 tag exists. [V] ([aaif/project-proposals#19](https://github.com/aaif/project-proposals/issues/19))
- **Monitors.** Per-trajectory monitors flagged 7% of distributed multi-agent attacks against 87% of single-agent ones. [S, Adversa roundup of an October preprint]

### 4. Partners, upstreams and foundations

- **AAIF (Linux Foundation).** Stages are Sandbox, Growth, Impact, Emeritus. Donation requires transferring trademarks and assets to the LF. Growth requires production use at two unaffiliated organisations. Approved: MCP, goose, AGENTS.md, agentgateway, Agent Router, A2A, OpenSandbox, Open Responses, Agent Skills, OpenEnv. TC-approved and awaiting board vote: Agent Client Protocol, Agent Plugins. Under review: Prismor, MCP Gateway Registry, TRACE, AGNTCY. Its CTO said at AGNTCon (22 Oct) that the open problems are identity, attestation, audit and payments. [V] ([lifecycle policy](https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md), [proposals](https://github.com/aaif/project-proposals/issues), [InfoQ](https://www.infoq.com/news/2026/10/agntcon-mcpcon-2026/))
- **CNCF.** Cedar, kagent, Agent Substrate, gVisor (Sandbox); Falco, SPIRE (Graduated); Tetragon through Cilium; NATS.
- **OpenSSF.** sigstore; AI/ML Security WG. AGT withdrew its Sandbox proposal on 21 May 2026 in favour of AAIF, which then declined it. [V] ([ossf/tac#603](https://github.com/ossf/tac/pull/603))
- **OWASP GenAI Security Project.** ACS (has GOVERNANCE.md and a conformance track that accepts outside evidence), AOS/AgBOM (stalled).
- **Natural upstreams:** ACS (implement, and contribute a conformant Guardian), Cedar, agentgateway, agent-sandbox and Agent Substrate (runtime we observe and police), SPIRE, sigstore, aya, yara-x. **Natural peers for schema and rule interop:** numbat, LoongSuite Pilot, Uber ADR, Quarry, Docker Kit descriptors.

## Matrix

Grades: A multi-organisation or foundation, steady releases; B active, one vendor; C one maintainer or under six months old; D stalled; F unusable.

| Project | What it is | Licence | Grade | Use |
|---|---|---|---|---|
| Cedar | Authorisation engine | Apache-2.0 | A- | Depend on |
| Dogwood | Temporal layer over Cedar | Apache-2.0 | C | Learn from; authoring only |
| rsigma (parser, eval) | Sigma evaluator | MIT | C+ | Depend on, vendored; never ship daemon or MCP |
| yara-x | Pattern engine | BSD-3 | B+ | Depend on |
| aya | eBPF in Rust | MIT/Apache | B+ | Depend on |
| endpoint-sec | macOS ES bindings | MIT/Apache | C+ | Depend on behind a trait; be ready to fork |
| ferrisetw | ETW consumer | MIT/Apache | D | Fork now or replace |
| windows-drivers-rs | Rust WDK | MIT/Apache | B- | Prototype only |
| tough | TUF client | MIT/Apache | B- | Depend on, pin 0.24.0 or later, watch |
| sigstore-rs | Signing and verification | Apache-2.0 | B | Depend on |
| connect-rust | RPC | Apache-2.0 | B- | Depend on later; pre-1.0 |
| DataFusion, DuckDB | Query engines | Apache-2.0, MIT | A | Depend on |
| NATS server | Bus | Apache-2.0 | A- | Integrate; minimal listeners |
| ClickHouse | Event store | Apache-2.0 | A | Integrate |
| SPIRE | Workload identity | Apache-2.0 | A | Integrate |
| OpenBao | Secrets | MPL-2.0 | B+ | Integrate; fast patch SLA |
| Kingfisher | Secret scanner crates | Apache-2.0 | B- | Depend on behind a trait |
| Rustinel | Rust EDR sensor | Apache-2.0 | C+ | Learn from |
| Santa | macOS enforcement | Apache-2.0 | B+ | Integrate; learn from advisories |
| osquery, Falco, Tetragon | Host and kernel telemetry | Apache-2.0 | A | Integrate as data sources |
| prempti | Falco rules on agent hooks | Apache-2.0 | D | Learn from |
| agentgateway | MCP and LLM gateway | Apache-2.0 | B+ | Integrate; do not embed as enforcement core |
| Agent Router | AI gateway on Envoy | Apache-2.0 | B | Integrate |
| OWASP ACS | Hook wire standard | Apache-2.0 | C+ | Implement and contribute |
| MS agent-control-spec, agent-hooks | AGT policy core | MIT | C | Learn from; track |
| ai-detection-spec | Detection schema | Apache-2.0 | C- | Learn from |
| Uber ADR | Discovery, sensor, detector | Apache-2.0 | B | Learn from; schema interop |
| numbat | Endpoint agent visibility | Apache-2.0 | B- | Integrate (schema) |
| LoongSuite Pilot | Agent telemetry collector | Apache-2.0 | B | Integrate; learn adapters |
| Project Quarry | Multi-turn detection DSL | Apache-2.0 | C | Learn from; import rules later |
| agent-sandbox | K8s sandbox CRD | Apache-2.0 | A- | Integrate |
| Agent Substrate, gVisor | Actor sandbox runtime | Apache-2.0 | B+, A | Integrate |
| OpenSandbox, SPACE, nvx | Sandbox services | Apache-2.0, MIT | B, C+, C | Integrate; learn |
| Docker Kit spec | Authority descriptor | Apache-2.0 | C | Learn from; ingest as inventory |
| nono, MXC, sandbox-runtime | OS sandboxes | Apache-2.0, MIT | B, B+, B | Integrate; nono as crate with care |
| zeroid, rossoctl | Agent identity | Apache-2.0 | C+ | Learn from |
| SkillSpector, skill-scanner, agent-scan | Skill and MCP scanners | Apache-2.0 | B | Integrate as signal only |
| ToolHive, ContextForge | MCP gateways | Apache-2.0 | B | Integrate; heavy advisory load |
| AccessKit | Accessibility tree | MIT/Apache | C+ | Depend on |
| Rune | UI framework | MIT | C | Depend on only behind an escape hatch |
| Astryx | Design system | MIT | B- | Depend on, pinned |
| hardenrun/aif, aifw | "Agent firewalls" | none | F | Avoid |
| halofy | Agent governance layer | AGPL-3.0 | C | Avoid in embeddable core |

**Gaps no open project fills**

1. A fully open multi-tenant fleet console, with response actions, for agents.
2. Discovery and attribution of agents already running and never registered; every sandbox and hook tool covers only what it launches or is installed into.
3. One cross-OS kernel sensor with a signed distribution.
4. Hook integrity: detecting or preventing an agent rewriting its own hook configuration, and coverage of subagents.
5. A working signed, replay-protected hook transport (the ACS reference does not implement its own MUSTs).
6. Correlation across sessions and across agents; Quarry stops at one conversation.
7. Agent identity bound to endpoint attestation rather than to a cluster workload.
8. Runtime-derived AgBOM; the standard is stalled and the tools are static.
9. Open prevention at fleet scale (Uber withheld it) and open response orchestration.
10. Skill and plugin provenance (signing plus transparency) instead of scanning.
11. Maintained Rust ETW consumer and Rust OpAMP client.
12. A maintained, OSI-licensed, small injection classifier.

## What this changes in the earlier briefs

- **08, matrix row "falcosecurity/prempti: Reuse or interop".** Outdated: one commit in 90 days, v0.3.0-rc5 since 2026-09-21. Treat as learn-only.
- **08, "Microsoft AGT moved its policy engine onto ACS".** Add: AAIF declined AGT (29 Jun) and AGT withdrew from OpenSSF (21 May); AGT has no foundation home.
- **08, "The reference Guardian is unauthenticated and fails open by default".** Newly supported and extended by ACS #184 with wire-level evidence.
- **08, nono "Reuse crate".** Add: 15 advisories in 2026 (4 high); proposed to AAIF 16 Oct, withdrawn 9 Nov. Still independent.
- **08, Kagenti and OpenSandbox.** Kagenti is now `rossoctl/rossoctl`; OpenSandbox is `opensandbox-group/OpenSandbox` under AAIF.
- **08, missing projects.** Agent Substrate, nvx, Docker Kit spec, LoongSuite Pilot, zeroid, Wirken.
- **10, "ferrisetw: Reuse, plan fork".** Stronger: zero commits in 15 months on the default branch; the fork is needed before we depend on it.
- **10, "tough: Reuse".** Add three April 2026 CVEs in delegated-role handling and no commits since July.
- **11, "rsigma bus factor... 186 stars".** Supported (187 stars, 90 of last 100 commits by one person); add the five advisories, confined to daemon and MCP surfaces.
- **11, "Envoy AI Gateway became Agent Router under the Agentic AI Foundation (September 2026)".** The AAIF proposal (#18) was filed 2026-04-24; the approval date was not found, so "September" is unconfirmed.
- **g03, "Dogwood 1.0 exists (13 Oct 2026)".** Now v1.1.1 (6 Nov); still four authors.
- **g03, "No licence change found in any dependency still selected".** Still true after this sweep.
- **09, no clean small classifier.** Still true; search found only small Qwen fine-tunes with unverified licences.

## Implications for our design

1. **Fork `ferrisetw` into our organisation this quarter** or evaluate `one-collect`; keep ETW behind our own trait either way.
2. **Depend only on `rsigma-parser` and `rsigma-eval`,** vendored at a pinned commit; ban the daemon, MCP server and enrichers from our build graph.
3. **Do not use agentgateway or Agent Router as the enforcement point of record.** Run them as integrations; put our own decision check behind them, and make every policy-evaluation error a deny.
4. **Write session and route isolation tests for our own MCP gateway** from the agentgateway and Agent Router advisory list.
5. **Turn Santa's 2026 advisories into sensor test cases:** bounded argv and environment capture, daemon crash means fail-closed or watchdog restart, tamper checks on data-directory relocation, no caching of context-dependent allows.
6. **Ship ACS with signature verification, replay and skew windows, and chain-head publication on from day one,** and submit conformance evidence upstream; that is the fastest route to standing in OWASP.
7. **Set a seven-day patch SLA and automated advisory watch** for OpenBao, NATS, ToolHive and ContextForge; in self-hosted bundles disable NATS leafnode, MQTT and WebSocket listeners unless configured.
8. **Add import adapters, not dependencies, for peer schemas:** numbat findings, LoongSuite Pilot events, Uber ADR telemetry, Quarry rules, Docker Kit descriptors (as declared-authority inventory to diff against observed behaviour).
9. **Treat skill-scanner verdicts as one input to a risk score;** build provenance (digest pinning, sigstore signatures, post-install drift detection) as the control.
10. **Do not plan on donating to AAIF first.** Keep trademarks; engage OWASP (ACS) and OpenSSF AI/ML WG for specifications, CNCF TAG Security for runtime integration, and revisit AAIF once its TC process is public.
11. **Sign every release binary on macOS and Windows from the first public build;** unsigned binaries are the most repeated complaint across numbat, prempti and DefenseClaw.
12. **Rune needs a written exit plan** (AccessKit plus a fallback renderer) before UI work starts; pin Astryx and budget for codemods on each minor.

## Could not verify / open questions

- NVIDIA "AgentBreaker" (Black Hat 2026): no repository found.
- kagent 1.0 GA on 9 Nov is from a secondary source; GitHub shows v1.0.0-rc4 that day.
- Whether CNCF has formally accepted Agent Substrate and gVisor, or only received the proposal; the Google post says "donating".
- AAIF member count (a secondary headline says 190) and the three new governance committees named at AGNTCon.
- OpenSSF SAFE-MCP rebrand to broader agentic security (search summary only).
- `agent-manifest` licence: GitHub reports Apache-2.0, an AAIF comment says MIT.
- Whether RUSTSEC-2026-0173 concerns ferrisetw (search snippet did not name the crate).
- Cedar maintainer affiliations (no MAINTAINERS file at repository root); the "all AWS" reading is from handles.
- `one-collect` suitability for real-time security ETW sessions.
- ClickHouse and DuckDB publish advisories outside the GitHub repository feed; zero there does not mean zero.
- Claude Code issue #45427 (subagent hook bypass) was seen through a search summary, not opened.
- Advisory counts are GitHub-published repository advisories dated 2026; projects that do not use the feature show zero.

## Sources

- https://aaif.io/md/news/agentic-ai-foundation-announces-four-new-projects — AAIF announces four new projects, 2026-10-22
- https://github.com/aaif/project-proposals/issues — AAIF project proposals (#19 AGT, #38 governance WG, #39 ContextForge, #51 Prismor, #61 nono), read 2026-11-10
- https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md — AAIF Project Lifecycle Policy
- https://www.infoq.com/news/2026/10/agntcon-mcpcon-2026/ — AGNTCon + MCPCon recap, October 2026
- https://opensource.googleblog.com/2026/11/sandboxing-untrusted-ai-agents-at-scale.html — Google donates Agent Substrate and gVisor to CNCF, 2026-11-05
- https://github.com/ossf/tac/pull/603 — AGT OpenSSF Sandbox proposal, closed 2026-05-21
- https://www.cncf.io/projects/cedar/ — Cedar CNCF project page (accepted 2025-10-08)
- https://github.com/GenAI-Security-Project/agent-control-standard/issues/184 — ACS-Core conformance report, 2026-09-23
- https://github.com/cisco-ai-defense/project-quarry — Project Quarry README
- https://www.theregister.com/security/2026/10/28/cisco-open-sources-tool-for-detecting-ai-agents-on-hacking-sprees/5305867 — The Register on Quarry, 2026-10-28
- https://github.com/alibaba/loongsuite-pilot — LoongSuite Pilot README
- https://github.com/microsoft/nvx — NVX README
- https://github.com/docker/sandbox-kit-spec — Docker Sandbox Kit Specification v3
- https://github.com/perplexityai/SPACE — SPACE README
- https://github.com/uber/ADR — Uber ADR README
- https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/ — CSA note on skill-scanner bypass, 2026-06-10
- https://adversa.ai/blog/top-ai-agent-security-resources-november-2026/ — Adversa roundup, November 2026
- https://www.helpnetsecurity.com/2026/11/09/wirken-open-source-ai-agent-gateway/ — Wirken, 2026-11-09
- https://aos.owasp.org/spec/inspect/ — OWASP AOS, AgBOM
- https://www.developersdigest.tech/blog/coding-agent-hooks-fail-open-vs-fail-closed-2026 — hook failure posture comparison, 2026
- https://github.com/timescale/rsigma/security/advisories, https://github.com/agentgateway/agentgateway/security/advisories, https://github.com/theagentrouter/agent-router/security/advisories, https://github.com/northpolesec/santa/security/advisories, https://github.com/openbao/openbao/security/advisories, https://github.com/nats-io/nats-server/security/advisories, https://github.com/awslabs/tough/security/advisories, https://github.com/cedar-policy/cedar/security/advisories — advisory feeds, read 2026-11-10
- https://github.com/n4r1b/ferrisetw, https://crates.io/crates/ferrisetw, https://github.com/microsoft/one-collect — ETW consumer status
- GitHub REST API (`repos`, `releases`, `commits?since=2026-08-12`, `security-advisories`, `search`) and crates.io API for every row in the health table, 2026-11-10

## Independent verification

_Checked 2026-11-10 by a separate fact-checker. Method: GitHub REST API through `gh` (commits, releases, `security-advisories`, issues, timelines), crates.io API, direct fetches of aaif.io, the Google Open Source blog, cncf.io and the Trail of Bits blog, and one web search. Advisory counts are published repository advisories with a 2026 `published_at`._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | ferrisetw: no default-branch commit since 2025-08-20, no crate release since 1.2.0 (2024-06-27), zero commits in 90 days | Confirmed | Last `master` commit 22caa099 on 2025-08-20; 0 commits since 2026-08-12; crates.io newest is 1.2.0 (2024-06-27). Repo is not archived; the only later pushes (to 2025-10-20) are unmerged dependabot branches. `next_major_version` branch is from 2022. | https://api.github.com/repos/n4r1b/ferrisetw/commits , https://crates.io/api/v1/crates/ferrisetw |
| 2 | agentgateway 7 advisories in 2026 (1 high: MCP sessions cross routes, overwrite authorisation policy); Agent Router 24 (5 high, incl. CEL errors bypassing Deny) | Confirmed | agentgateway: 7 (1 high GHSA-mvgg-jvj2-4frq 2026-07-27, 6 medium). Agent Router: 24 (5 high, 18 medium, 1 low); CEL fail-open is GHSA-qcwp-vgvh-h3cm. Six of the 24 were published 2026-11-06, so the list is still growing. | https://github.com/agentgateway/agentgateway/security/advisories , https://github.com/theagentrouter/agent-router/security/advisories |
| 3 | OWASP ACS reference Guardian accepts unsigned, bad-signature, replayed and stale envelopes, publishes no chain head (issue #184, 2026-09-23, open) | Confirmed | Issue open, labelled `status:accepted`; D1 covers unsigned and byte-inverted HMAC. Add: fix PR #229 exists but is still open and unmerged; the reporter's 2026-10-24 rerun shows the PR branch passing every MUST probe except replay after restart (D2c), while the integration head still fails all. | https://github.com/GenAI-Security-Project/agent-control-standard/issues/184 , https://github.com/GenAI-Security-Project/agent-control-standard/pull/229 |
| 4 | rsigma: five 2026 advisories (3 high), all in OTLP endpoint, rsigma-mcp and enrichers, none in parser or evaluator; 90 of last 100 commits by one Timescale employee | Confirmed | Affected packages are `rsigma` (CLI/daemon), `rsigma-runtime` and `rsigma-mcp` only. Note `rsigma-runtime` is a library crate and is affected by GHSA-3fh4-8r8j-8xw3, so it belongs on the ban list too. 90 of 100 commits by `mostafa` (profile: Tiger Data, company @timescale, public org member); the last 100 commits span only two weeks. | https://github.com/timescale/rsigma/security/advisories |
| 5 | AAIF hosts 10 projects (2026-10-22), none security or governance; TC declined AGT 2026-06-29; nono withdrew 2026-11-09 citing TC and Governing Board transparency | Confirmed | aaif.io lists 10; the 22 Oct release says "10 hosted projects". #19 closed with label `Declined` 2026-06-29. nono withdrawal comment posted 2026-11-09 19:39 UTC; issue #61 is still open and still carries the `TC Vote` label. Caveat: agentgateway and Agent Router are gateways with authorisation features and agentgateway is described as enabling "secure" connections, so "none is a security project" is a judgement, not a quoted fact. | https://github.com/aaif/project-proposals/issues/61 , https://github.com/aaif/project-proposals/issues/19 , https://aaif.io/projects/ |
| 6 | OpenBao 38 advisories in 2026 (5 critical, 7 high); NATS server 27 (12 high, several pre-auth in leafnode, MQTT, WebSocket) | Confirmed | OpenBao: 38 = 5 critical, 7 high, 10 medium, 16 low. NATS: 27 = 12 high, 15 medium, in batches of 2026-02-23 (1), 03-24 (13) and 06-29 (13). Pre-auth highs include leafnode panics, MQTT partial CONNECT memory exhaustion and WebSocket frame-length overflow. | https://github.com/openbao/openbao/security/advisories , https://github.com/nats-io/nats-server/security/advisories |
| 7 | tough: no commits since 2026-07-10 (0.24.0); three medium CVEs on 2026-04-24 | Confirmed | Last commit on default branch `develop` is 2026-07-10 (release prep, PR #953). CVE-2026-6966 (threshold bypass), CVE-2026-6967 (delegated metadata validation), CVE-2026-6968 (path traversal), all medium, all fixed in tough 0.22.0 and tuftool 0.15.0. Not archived; PRs opened since July (latest 2026-11-03) sit unmerged. | https://github.com/awslabs/tough/security/advisories , https://api.github.com/repos/awslabs/tough/commits |
| 8 | Google announced 2026-11-05 it is donating Agent Substrate (Apache-2.0, v1.0.0-rc.3) and gVisor to CNCF Sandbox; formal acceptance not confirmed | Corrected | Formal acceptance is confirmed. CNCF TOC votes passed: `[Sandbox] Agent Substrate` (cncf/sandbox#523) closed 2026-10-20 and `[Sandbox] gVisor` (#521) closed 2026-10-28, both `gitvote/passed` and `contribution-agreement/signed`; onboarding issues #542 and #546 are open. Version is also stale: Agent Substrate v1.0.0 GA was published 2026-11-05 23:55 UTC, after rc.3. The blog itself states neither licence nor version; Apache-2.0 is from the repository. | https://github.com/cncf/sandbox/issues/523 , https://github.com/cncf/sandbox/issues/521 , https://github.com/agent-substrate/substrate/releases |
| 9 | Santa 15 advisories in 2026, incl. a critical telemetry buffer overflow and highs for crashing santad and bypassing tamper resistance | Confirmed | 15 = 1 critical (GHSA-xcpp-qvv3-r3xf), 4 high, 9 medium, 1 low, published 2026-08-04, 09-16 and 10-27. Two separate highs crash santad and pause enforcement (process chain, malformed Info.plist). | https://github.com/northpolesec/santa/security/advisories |
| 10 | Trail of Bits (3 Jun 2026) bypassed every tested skill scanner; known only through the CSA note | Confirmed, provenance corrected | The primary post is public: "The sorry state of skill distribution", Trail of Bits, 2026-06-03. It reports bypasses of ClawHub (VirusTotal Code Insight and the guard model), Cisco skill-scanner, and Gen Agent Trust Hub, Socket and Snyk on skills.sh. Upgrade the tag from [S] to [V]. NVIDIA SkillSpector was not tested. | https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ |
| A | Brief: "kagent is at v1.0.0-rc4"; "GitHub shows v1.0.0-rc4 that day" | Corrected | `kagent-dev/kagent` v1.0.0 GA was published 2026-11-09 18:43 UTC, 36 minutes after rc4, and is the `latest` release. | https://github.com/kagent-dev/kagent/releases |
| B | Brief section 2: "invalid tool-call IDs bypassing `mcpAuthorization` ... (Agent Router, October)" | Corrected | The `mcpAuthorization` bypass is an agentgateway advisory (GHSA-qm3r-hhvc-62cp, medium, 2026-10-27). Agent Router's tool-call-ID advisory (GHSA-5gx6-2mh3-32v4) is an extproc crash, not an authorisation bypass. Related open question resolved: Agent Router proposal #18 was closed `Approved` on 2026-09-10, so "September 2026" in brief 11 holds. | https://github.com/agentgateway/agentgateway/security/advisories/GHSA-qm3r-hhvc-62cp , https://github.com/aaif/project-proposals/issues/18 |
| C | Brief section 3: scanner authors recommend "pin versions, sign, monitor at runtime"; evasion classes include "post-install change" | Corrected | The Trail of Bits post recommends curated or organisation-managed marketplaces, pinning versions, controlling who can introduce or update skills, and not relying on scanners. It does not recommend signing or runtime monitoring and does not demonstrate post-scan mutation; those items come from the CSA note, not the authors. | https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ |
