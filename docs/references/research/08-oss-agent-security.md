# Open-source landscape: agent security, sandboxes, firewalls and MCP gateways

_Researched 2026-11-09_

Method: GitHub API (`gh api`, `gh search repos`, 35 queries by stars and by creation date), READMEs and architecture docs of about 85 repositories read directly, plus three vendor doc pages. Stars and last-push dates are GitHub values on 2026-11-09 (push dates are UTC, so "11-10" means today). The shared web-search budget was exhausted before my searches ran, so nothing here comes from news or blog coverage; see "Could not verify".

## TL;DR

- The field split into five layers, and no open project spans them: (1) in-agent hook policy engines, (2) OS process sandboxes, (3) egress/MCP/LLM proxies, (4) observe-only telemetry, (5) scanners. Every project that claims "complete" is strong in one or two.
- The closest open analogues to an AIDR are new and incomplete: **uber/ADR** (Apache-2.0, Python, production at Uber, MLSys 2026; ships Discovery, Sensor, Bench, Detector; Prevention explicitly withheld) and **perplexityai/numbat** (Apache-2.0, Go single binary for macOS/Linux/Windows; hooks + OTLP + on-disk transcripts into one CEL rule engine; blocking opt-in). Neither has a console, fleet, identity or kernel sensor.
- Fleet management, multi-agent identity and the team console are where open projects put the paywall: Pipelock (`enterprise/` under ELv2), HOL Guard (Guard Cloud), Obot (device seats counted against a licence), Snyk agent-scan (Evo), AgentWard and Cordum (BSL 1.1), Archestra (dual licence), AgentLens (FSL). A fully open multi-tenant console is unoccupied ground.
- Cross-OS kernel enforcement does not exist in one open project. **agentsh** is nearest (Linux full; macOS ESF+NE alpha; Windows minifilter unsigned, so WSL2 only). **Aten** does eBPF + ETW observation but macOS is unverified because the author lacks Apple entitlements.
- Windows changed in 2026: **microsoft/mxc** (MIT, Rust SDK) exposes a native Windows 11 `processcontainer` backend (24H2 build 26100.9278+) with learning mode; Codex has an `mxc-sandbox` crate; OpenShell uses MXC for native Windows; Anthropic's `srt` now sandboxes on Windows with a dedicated local user, a WFP egress fence keyed on its SID and a write-restricted token.
- A wire standard for hooks now exists: **OWASP Agent Control Standard (ACS) v0.1.x** (JSON-RPC, 44 schemas, hook methods such as `steps/toolCallRequest`, AgBOM events). Microsoft AGT moved its policy engine onto ACS. The reference Guardian is unauthenticated and fails open by default, by its own admission.
- Hook engines are cooperative, and their authors say so (Prempti, Rampart, agentjail, Obot Sentry). Claude Code hooks default to fail-open on error or timeout; `onFailure: "block"` (v2.1.295+) and managed `allowManagedHooksOnly` are the levers.
- Policy language is fragmented: Rego (agentjail, cupcake), Cedar (Leash, Sondera, carapace, Dogwood), CEL (numbat, agentgateway, skill-scanner), Falco YAML (Prempti), Starlark (Codex execpolicy), TOML (Gemini CLI, OpenAPPA), YAML/JSON everywhere else.
- Attribution of agent versus human is solved only inside a sandbox or a run (cgroup, process ancestry). Nobody open stitches it to cloud or SaaS audit logs, and nobody issues an agent identity bound to an endpoint sensor.
- Several seeds are dead or closed: Daytona (archived, development private since June 2026), Invariant, Lasso, Leash (no pushes since April), cupcake (March), mcp-guardian (2025), mcp-context-protector (archived), MCP Defender (acquired by Docker).
- Best Rust building blocks for us: `cedar`, Dogwood, OpenAPPA, `nono`, `mxc-sdk`, Sondera's hook adapters, Prempti, httpjail, agentgateway, Codex's sandbox crates.

## Findings

### 1. In-agent hook policy engines

All sit on the agent's pre-tool hook and return allow/deny/ask. Differences are policy language, adapter breadth and honesty about limits.

- **Sondera coding-agent-hooks** (Rust, MIT, 231 stars, pushed 2026-11-03): hook adapters for Claude Code, Cursor, Copilot, Gemini CLI, Antigravity, Codex, Hermes, OpenCode, OpenHands, VS Code. Adapter forwards over gRPC to `sondera serve`, which runs YARA-X signatures plus Cedar (110 shipped policies), optional LLM classifiers for sensitivity labels (fail open), local Turso/SQLite store. Enforcement hooks fail closed if the harness is unreachable. Publishes a per-agent matrix of block/ask/steer/redact per hook group. Binaries for Linux x86-64 and Apple silicon only. https://github.com/sondera-ai/sondera-coding-agent-hooks
- **agentjail** (Go, Apache-2.0, 102 stars, v1.8.2 2026-09-08): hook binary to warm daemon over Unix socket to OPA/Rego, target under 5 ms; default decision when nothing matches is `ask`. Adds `agentjail-shield` (Seatbelt on macOS, Landlock on Linux), credential broker, MITM tunnel for LLM traffic, monitor mode, signed releases, 100+ ADRs. No Windows. https://github.com/LuD1161/agentjail/blob/main/docs/ARCHITECTURE.md
- **Prempti** (Falco project, Rust, Apache-2.0, v0.3.0-rc5): hook interceptor to Falco running `nodriver` with a plugin; rules are ordinary Falco YAML; Linux, macOS and Windows; guardrails or monitor mode. States plainly that it sees declared commands, not side effects. https://github.com/falcosecurity/prempti
- **numbat** (above): shipped rules are monitor-only; enforce requires copying a rule and setting `enforce: true`; multi-step sequence rules tagged with ATT&CK IDs; versioned NDJSON schema v0.5.0; forensic reconstruction from transcripts without prior instrumentation. https://github.com/perplexityai/numbat/blob/main/docs/enforcement.md
- Others: **gryph** (Go, YAML, SQLite audit, 9 agents), **Rampart** (Go, hash-chained audit, distinguishes "HOST VERIFIED" from "ADAPTER VERIFIED"), **Prismor** (Python, 17 agents, MCP gateway, "shadow AI sweep"), **HOL Guard** (Rust/Python, 16 agents, package-install checks), **failproofai** (TS, MIT, 8,305 stars, 12 harnesses, 40 policies), **cupcake** (Rego to Wasm, stale), **destructive_command_guard** (6,321 stars, MIT with a rider) and **cc-safety-net** (narrow destructive-command guards), **DefenseClaw** (Cisco, Go gateway + Python CLI, hooks fail closed except under Cisco Secure Client).
- Vendor-native controls to drive rather than replace: Claude Code hooks (about 33 events; handler types `command`, `http`, `mcp_tool`, `prompt`, `agent`; `PreToolUse` returns allow/deny/ask/defer and `updatedInput`); Codex `execpolicy` (Starlark `prefix_rule` with allow/prompt/forbidden and inline match tests) and a `hooks` crate; Gemini CLI policy engine (TOML rules, tiers, and a global `deny` removes the tool from the model's view; workspace tier is documented as non-functional). https://code.claude.com/docs/en/hooks , https://github.com/openai/codex/tree/main/codex-rs/execpolicy , https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md

### 2. OS-level sandboxes

- **anthropics/sandbox-runtime (`srt`)** (TS, Apache-2.0, 7,053 stars, v0.0.82): Seatbelt, bubblewrap, and on Windows a dedicated `srt-sandbox` account with WFP filters and ACEs; network through host proxies. JSON settings. Still labelled research preview.
- **Codex** (Rust, Apache-2.0): crates `linux-sandbox`, `bwrap`, `windows-sandbox-rs` (ACLs, restricted tokens, WFP, a setup service), `mxc-sandbox`, `network-proxy` (HTTP 3128 + SOCKS5 8081, MITM in limited mode), `process-hardening`, plus `agent-identity` (Ed25519 keys and JWTs against OpenAI's backend). Not published as stable libraries; `afshinm/zerobox` shows they can be lifted.
- **microsoft/mxc** (Rust, MIT, 3,120 stars, v1.0.1): one JSON containment request, backends ProcessContainer, Windows Sandbox, WSLC, MicroVM, Hyperlight, bubblewrap, LXC, Seatbelt; Rust, .NET and Node SDKs; audit/learning mode that emits a policy. Official builds send required telemetry.
- **nono** (Rust, Apache-2.0, 4,912 stars, v0.81.0, from the Sigstore founders): library crate (`CapabilitySet`, `Sandbox::apply_auto`) on Landlock and Seatbelt, C bindings, proxy with phantom tokens, Sigstore attestation of skills and instruction files, signed audit, rollback snapshots, profile registry. Windows only through WSL2.
- **NVIDIA OpenShell** (Rust, Apache-2.0, 21,332 stars, weekly stable releases): gateway control plane, per-sandbox supervisor on the trusted side, Landlock for files, seccomp user-notification to hold connect and DNS until policy decides, caller identified from `/proc`, credential placeholders, a formal "policy prover" that blocks auto-approval of risky rule changes; drivers for Docker, Podman, Kubernetes, VM. Fleet-shaped, but for sandboxes it launches, not for discovered endpoints.
- **agentsh** (Go, Apache-2.0, 408 stars): FUSE3 + iptables + seccomp on Linux, ESF + Network Extension on macOS (alpha), minifilter + WinFsp + WinDivert on Windows (unsigned). Unique `redirect` and `soft_delete` decisions. https://github.com/canyonroad/agentsh/blob/main/docs/platform-comparison.md
- Lighter wrappers: **fence** and **greywall** (bubblewrap + Landlock + seccomp + proxy, learning mode), **agent-safehouse** (Seatbelt only), **landstrip** (Landlock/Seatbelt/AppContainer, LGPL binary), **Strands Box** (AWS, Rust, Dogwood policies shared across shell, Python, egress gateway and MCP broker; Linux ARM64 and Apple silicon only), **Leash** (containers + Cedar, stale).
- Infrastructure sandboxes (interoperate, do not build): **kubernetes-sigs/agent-sandbox** v1.0.10 (`Sandbox` CRD, delegates isolation to gVisor/Kata), **E2B**, **microsandbox** (Rust, microVMs on all three OSes, secrets never enter the VM), **OpenSandbox** (now an Agentic AI Foundation project), **apple/container**, **container-use**.

### 3. Egress firewalls, MCP and LLM gateways

- **Pipelock** (Go, core Apache-2.0, 988 stars, v3.8.0): forward proxy and MCP wrapper scanning HTTP, WebSocket, MCP, A2A for secrets, injection, SSRF and tool-call chains; mediator-signed receipts verifiable offline, optional Rekor anchoring; states that receipts prove the boundary's decision, not that nothing bypassed it. Per-agent identity, budgets and fleet views are ELv2.
- **agentcage** (Rust, MIT): container whose only route out is an inspecting proxy; decoy tokens swapped on the wire; tmpfs "pivot masks" over `.git/hooks` and `.claude` in the mounted workspace.
- **agentgateway** (Rust, Apache-2.0, Linux Foundation, 6,079 stars, v1.7.0): MCP, A2A and LLM proxy, CEL RBAC, OTel, Kubernetes Gateway API controller. The strongest reusable data plane.
- **ToolHive** (Go, v0.63.0, per-server containers, operator, registry, virtual MCP), **Docker MCP Gateway** (requires Docker Desktop 4.59+ for full features), **IBM ContextForge** (Python, v1.1.0), **Obot** (Go, MIT; MCP and LLM gateways plus **Obot Sentry**, a beta endpoint agent that inventories clients, MCP servers, skills and plugins per device and enforces a tool-call allowlist on Claude Code, Codex, Cursor and Kiro, fail closed, with documented bypasses), **Archestra**, **Bifrost** (MCP gateway and guardrails are enterprise-only), **onecli**, **gh-aw-firewall** (Squid allowlist plus an API-key sidecar).
- **OpenAPPA** (Archestra, Rust, MIT, 1,625 stars): deterministic information-flow control. Tracks sensitivity and trust of everything read, checks each destination before the call, TOML policy, replayable from the event log. Vendor-reported benchmark claims; preview status.

### 4. Telemetry, detection, discovery

- **uber/ADR Discovery**: stdlib-only Python collector; inventories AI binaries, desktop apps, CLI agents, IDE extensions, model runtimes, MCP servers, skills; fingerprint catalog; policy file with `approved`/`forbidden` indicators (`skill_sha256`, `mcp_endpoint`, `package`); reports coverage gaps; never executes what it finds. **Sensor** parses on-disk logs of 11 agents (Claude Code JSONL, Cursor `state.vscdb`, Codex rollouts, Copilot CLI, Claude Desktop agent mode, Gemini, Antigravity, Warp, opencode, Cline). https://github.com/uber/ADR
- **Aten** (Rust, no licence file detected, 63 stars): "Sysmon for agents". Joins transcript intent to kernel action by process ancestry plus timing; eBPF on Linux, ETW on Windows; observe-only.
- **AgentSight** (eBPF + TLS uprobes, MIT), **MCPSpy**, **logira** (cgroup-v2 run-scoped eBPF audit), **AgentLens** (OTel pipeline, FSL).
- Scanners: Cisco **mcp-scanner** and **skill-scanner** (YARA-X, AST, CEL, optional LLM), Snyk **agent-scan** (starts stdio MCP servers to read tool descriptions, so it warns to run in a sandbox), **NVIDIA/SkillSpector** (25,117 stars; metadata only, not read), Tencent AI-Infra-Guard.
- OpenClaw add-ons: **ClawSec** (AGPL, signed advisory feed, drift detection), **ClawVault**, **openclaw-shield** (Knostic says it rots within days of upstream changes), **SecureClaw** (prompt-injected rules).

### 5. Commercial technical docs, for contrast (user-requested)

- **BeyondTrust AI Agent Security** (page updated 2026-10-13): Pathfinder endpoint agent for Windows 11/Server 2022+ x64 and macOS 14/15/26; classifiers use process naming, signatures and LLM API traffic patterns; separates agent from human under the same credentials; enforces at kernel and network level and on hooks where available; allow, audit, hold-for-approval, block; policy replay against recorded activity; needs a tenant root certificate for HTTPS inspection. No cloud or SaaS discovery described. https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- **Microsoft Agent 365** (GA 2026-05-01, per-user licence, E5 recommended): registry in the M365 admin center, Entra for agent access, Purview DLP, Defender detection. Registry-centric; the overview does not describe endpoint discovery of unregistered agents. https://learn.microsoft.com/en-us/microsoft-agent-365/overview

## Matrix

Enforce-at: H hook, P proxy/gateway, K kernel or OS sandbox, C container/VM, O observe only, S static scan.

| Project | Stars | Last push | Licence | Lang | At | Policy | OS | Verdict |
|---|---|---|---|---|---|---|---|---|
| uber/ADR | 2,129 | 10-31 | Apache | Python | O,S | JSON policy, LLM detector | L/M/W | Learn; port catalog and parsers |
| perplexityai/numbat | 1,164 | 11-09 | Apache | Go | H,O | CEL YAML | L/M/W | Interop; learn schema |
| Sondera hooks | 231 | 11-03 | MIT | Rust | H | Cedar + YARA-X | L/M | Reuse |
| falcosecurity/prempti | 232 | 09-21 | Apache | Rust | H | Falco YAML | L/M/W | Reuse or interop |
| agentjail | 102 | 09-24 | Apache | Go | H,K,P | Rego | L/M | Learn |
| safedep/gryph | 182 | 11-06 | Apache | Go | H | YAML | L/M/W | Learn |
| peg/rampart | 92 | 11-09 | Apache | Go | H,P | YAML | L/M/W | Learn |
| PrismorSec/prismor | 481 | 11-10 | Apache | Python | H,P | YAML | L/M | Learn |
| hol-guard | 1,081 | 11-10 | Apache | Rust/Py | H,P | own | L/M/W | Learn |
| failproofai | 8,305 | 11-09 | MIT | TS | H | policy packs | L/M/W | Learn |
| eqtylab/cupcake | 302 | 03-02 | Apache | Rust | H | Rego/Wasm | L/M | Stale |
| DefenseClaw (Cisco) | 912 | 11-10 | Apache | Go/Py | H,P,S | bundles | L/M/W | Interop |
| MS agent-governance-toolkit | 6,546 | 11-09 | MIT | Py + 5 | H (in-app) | ACS, OPA, Cedar | any | Interop |
| OWASP ACS | 250 | 11-09 | Apache | spec | wire | JSON-RPC | n/a | Implement |
| Codex sandbox/execpolicy | 134,524 | 11-10 | Apache | Rust | K,P,H | Starlark, TOML | L/M/W | Reuse crates; drive config |
| Gemini CLI policy engine | 108,748 | 11-10 | Apache | TS | H | TOML | L/M/W | Drive config |
| anthropics/sandbox-runtime | 7,053 | 11-09 | Apache | TS | K,P | JSON | L/M/W | Learn; interop |
| microsoft/mxc | 3,120 | 11-10 | MIT | Rust | K,C | JSON | W/L/M | Reuse |
| nolabs-ai/nono | 4,912 | 11-09 | Apache | Rust | K,P | profiles | L/M | Reuse crate |
| NVIDIA/OpenShell | 21,332 | 11-10 | Apache | Rust | K,P,C | YAML + prover | L/M, W exp. | Interop; learn |
| canyonroad/agentsh | 408 | 11-08 | Apache | Go | K,P | YAML | L; M alpha; W unsigned | Learn |
| fence | 1,016 | 11-03 | Apache | Go | K,P | JSON | L/M | Learn |
| greywall | 316 | 10-17 | Apache | Go | K,P | profiles | L/M | Learn |
| agent-safehouse | 2,146 | 11-10 | Apache | Shell | K | SBPL | M | Learn |
| landstrip | 90 | 11-10 | LGPL/Apache | Rust | K | JSON | L/M/W | Learn |
| strands-agents/box | 512 | 11-10 | Apache | Rust | K,P | Dogwood | L arm64/M | Learn |
| strongdm/leash | 599 | 04-06 | Apache | Go | C,K | Cedar | L/M | Stale |
| pipelock | 988 | 11-10 | Apache + ELv2 | Go | P | YAML | L/M/W | Interop; core only |
| agentcage | 27 | 10-31 | MIT | Rust | C,P | config | L/M | Learn |
| coder/httpjail | 962 | 11-04 | CC0 | Rust | P,K | JS rules | L/M | Reuse |
| gh-aw-firewall | 157 | 11-10 | MIT | TS | C,P | allowlist | L | Learn |
| agentgateway | 6,079 | 11-10 | Apache | Rust | P | CEL | any | Reuse |
| ToolHive | 2,331 | 11-09 | Apache | Go | P,C | authz policy | L/M/W, K8s | Interop |
| Docker MCP Gateway | 1,628 | 10-26 | MIT | Go | P,C | catalog | Docker | Interop |
| IBM ContextForge | 4,782 | 11-09 | Apache | Python | P | plugins | any | Interop |
| Obot (+ Sentry) | 1,176 | 11-09 | MIT | Go | P,H,S | allowlist | L/M/W | Learn; interop |
| Archestra | 4,436 | 11-10 | dual | TS | P | UI + OpenAPPA | K8s | Interop |
| OpenAPPA | 1,625 | 11-10 | MIT | Rust | lib/sidecar | TOML | any | Reuse |
| Dogwood | 515 | 11-06 | Apache | Rust | lib | Cedar + temporal | any | Reuse with care |
| Aten | 63 | 07-28 | none | Rust | O | n/a | L/W | Learn only |
| AgentSight | 780 | 10-31 | MIT | C/Rust | O | n/a | L | Reuse on Linux |
| logira | 76 | 11-03 | Apache | Go | O | YAML | L | Learn |
| Snyk agent-scan | 3,230 | 11-09 | Apache | Python | S | n/a | L/M/W | Invoke |
| Cisco mcp-/skill-scanner | 1,114 / 2,713 | 11-06 | Apache | Python | S | YARA, CEL | any | Invoke |
| k8s-sigs/agent-sandbox | 4,563 | 11-10 | Apache | Go | C | CRD | K8s | Interop |
| microsandbox | 9,015 | 11-10 | Apache | Rust | C | SDK | L/M/W | Interop |
| E2B / OpenSandbox | 14,789 / 16,989 | 11-10 | Apache | Py | C | API | cloud/K8s | Interop |
| Daytona | 71,340 | 07-24 | archived | - | C | - | - | Dead as OSS |
| Invariant, Lasso, mcp-guardian | 476 / 401 / 205 | 01-2026 or older | Apache/MIT | Py/Rust | P | DSL, plugins | - | Stale |
| ClawSec / ClawVault | 1,135 / 1,072 | 11-10 / 08-20 | AGPL / MIT | JS / Py | H,S | skills | OpenClaw | Learn |

## Weak points, gaps and risks

- **Hooks are advisory.** They see the declared tool call, not what `./main` does afterwards; many agents run hooks only in trusted folders (Kiro), load each other's hook configs (Cursor reads Claude's), or skip them in some modes. Default failure posture is open in Claude Code and in the ACS reference Guardian.
- **Kernel sandboxes only cover what they launch.** Every project in section 2 wraps a process it starts. None attaches to an agent that is already running, which is the discovery case.
- **Windows is thin.** Signed kernel components are absent from all open projects; the workable user-mode routes are WFP by SID, restricted tokens and ACLs (srt, Codex) or MXC ProcessContainer, which needs recent Windows 11 builds.
- **macOS needs entitlements.** Endpoint Security and Network Extension require Apple-granted entitlements and notarisation; Aten stalled on this, agentsh is alpha. Seatbelt (`sandbox-exec`) is deprecated-but-working and is what everyone else uses.
- **Licence traps.** Pipelock release binaries contain ELv2 code; AgentWard and Cordum are BSL; landstrip's binary is LGPL; ClawSec is AGPL; Aten has no licence; PurpleLlama carries a Llama licence; MXC official builds phone home.
- **Churn.** Median age of the active projects is under ten months; six seeds died within a year. Depending on a small project as a library is a real risk; prefer vendoring or thin adapters.
- **Self-reported benchmarks.** OpenAPPA's 0% attack success and Adrian's accuracy gains are vendor numbers.

## Implications for our design

1. **Build the sensor/console split nobody has.** One Rust endpoint daemon with three sources (hooks, proxy, OS telemetry) and one open multi-tenant control plane. That combination is the whitespace; each source alone is commoditised.
2. **Adopt ACS as the hook wire format** and ship authenticated, fail-closed Guardian behaviour (HMAC is required by ACS-Core but missing from the reference). Keep per-agent shims thin; study Sondera's adapter matrix and numbat's coverage matrix as the truth table for what each agent can block.
3. **Policy: Cedar core in Rust, compiled outward.** Evaluate Cedar centrally, then generate native configs (Claude managed settings and hooks, Codex `execpolicy` rules, Gemini TOML) so enforcement survives when our hook is not called. Borrow Dogwood's temporal operators and OpenAPPA's taint labels for sequence rules ("secret read, then egress").
4. **Sandbox by delegation.** Use `mxc-sdk` on Windows, `nono` on Linux and macOS, and drive `srt` or Codex's own sandbox where the agent already embeds one. Do not write a fourth Seatbelt profile generator.
5. **Reconcile hook events against OS telemetry.** A process descended from an agent that touched a credential path with no matching tool call is both a detection and a hook-health signal. Aten's ancestry-plus-timing join and logira's cgroup scoping are the starting designs.
6. **Discovery in three passes:** catalog fingerprints and config parsing (port uber/ADR Discovery's catalog and indicator kinds), transcript parsers (ADR Sensor, numbat), then behavioural classification of arbitrary processes by LLM-API traffic shape, which only commercial products claim today.
7. **Evidence format:** signed, hash-chained decision receipts (Pipelock, Rampart) with an honest statement of what the boundary did not see; export OCSF and OTLP.
8. **Embeddability:** publish the hook shims, event schema and policy evaluator as separately versioned crates with a C ABI, as nono does, so an EDR vendor can link the evaluator without our daemon.

## Ideas worth stealing and whitespace

Steal: agentsh `redirect` decisions that steer instead of deny; Gemini's "deny removes the tool from the model"; OpenShell's supervisor on the trusted side plus policy prover; agentcage pivot masks; nono's Sigstore-verified skills and rollback snapshots; MXC and greywall learning modes that emit a least-privilege policy; BeyondTrust-style policy replay over recorded activity; Rampart's verified-versus-configured status; ADR Discovery's exit code for incomplete coverage; openguardrails reporting hosts reached that no tool call named; Codex execpolicy's inline `match`/`not_match` rule tests.

What no open-source project provides today:

1. A free, multi-tenant fleet console with enrolment, policy distribution, RBAC and MSP hierarchy.
2. Kernel-grade enforcement on Windows, macOS and Linux in one signed product.
3. Attachment to already-running, unregistered or in-house agents; all enforcement requires launching or configuring the agent.
4. Agent-versus-human attribution carried beyond the host into cloud, SaaS and Git audit trails.
5. Agent identity issuance tied to the endpoint sensor (SPIFFE or similar) and usable by gateways.
6. Discovery across cloud agent platforms, SaaS and browsers; open discovery is endpoint files only.
7. Response actions across a fleet: kill session, quarantine an MCP server or skill by hash, revoke brokered credentials. Uber withheld Prevention.
8. A shared detection-rule format and corpus for agent behaviour (a Sigma equivalent); rules exist in six incompatible dialects.
9. An embeddable SDK aimed at EDR vendors.
10. Browser-agent and computer-use controls.

## Could not verify / open questions

- Web search was unavailable (shared budget exhausted), so there is no independent reporting on hook-bypass research, incident history, adoption, or announcements. Everything is from repositories and three doc pages.
- ToolHive's authorisation language (Cedar as of 2025) was not re-confirmed in the current README.
- Obot is MIT in the repo, yet its docs count devices against "your license's device limit"; the open/enterprise boundary needs checking.
- NVIDIA/SkillSpector, perplexityai/SPACE, omnigent, solongate's sandbox, and Kagenti were not read beyond metadata.
- The Claude Code hooks page was read to 100k of 291k characters; `ask`/`defer` semantics and later sections were not reviewed.
- MXC ProcessContainer internals ("PSEC") and whether a third-party daemon can apply it to a process it did not create are undocumented in what I read.
- BeyondTrust and Agent 365 pages were summarised by a fetch model; sub-pages (Entra Agent ID, registry APIs, Agent 365 SDK) were not opened.

## Sources

All accessed 2026-11-09.

- https://github.com/uber/ADR (README, Discovery/README.md, Sensor/README.md; sensor-v1.0.0, 2026-07-31)
- https://github.com/perplexityai/numbat (README, docs/agent-coverage.md, docs/enforcement.md; v0.3.0, 2026-10-19)
- https://github.com/sondera-ai/sondera-coding-agent-hooks (README, docs/architecture.md)
- https://github.com/LuD1161/agentjail (README, docs/ARCHITECTURE.md, docs/SANDBOX.md)
- https://github.com/falcosecurity/prempti (README)
- https://github.com/GenAI-Security-Project/agent-control-standard (README, specification/v0.1.0; v0.1.4, 2026-10-16)
- https://github.com/microsoft/agent-governance-toolkit (README; v4.1.0)
- https://github.com/microsoft/mxc (README, docs/backends/process-container/os-version-support.md; v1.0.1, 2026-10-17)
- https://github.com/anthropics/sandbox-runtime (README; v0.0.82)
- https://github.com/openai/codex (codex-rs/execpolicy, mxc-sandbox, network-proxy READMEs; crate listing)
- https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md
- https://code.claude.com/docs/en/hooks
- https://github.com/nolabs-ai/nono (README, crates/nono/README.md; v0.81.0)
- https://github.com/NVIDIA/OpenShell (README, docs/about/architecture.mdx, support-matrix.mdx)
- https://github.com/canyonroad/agentsh (README, docs/platform-comparison.md)
- https://github.com/pipelab-org/pipelock (README, enterprise/ listing; v3.8.0)
- https://github.com/agentcage/agentcage , https://github.com/coder/httpjail , https://github.com/github/gh-aw-firewall
- https://github.com/agentgateway/agentgateway , https://github.com/stacklok/toolhive , https://github.com/docker/mcp-gateway , https://github.com/IBM/mcp-context-forge
- https://github.com/obot-platform/obot (README, docs/docs/device-management/*.md)
- https://github.com/archestra-ai/archestra , https://github.com/archestra-ai/OpenAPPA , https://github.com/dogwood-policy/dogwood , https://github.com/strands-agents/box
- https://github.com/Antonlovesdnb/aten , https://github.com/eunomia-bpf/agentsight , https://github.com/melonattacker/logira , https://github.com/hellnbak/AgentLens
- https://github.com/snyk/agent-scan , https://github.com/cisco-ai-defense/mcp-scanner , https://github.com/cisco-ai-defense/skill-scanner , https://github.com/cisco-ai-defense/defenseclaw
- https://github.com/safedep/gryph , https://github.com/peg/rampart , https://github.com/PrismorSec/prismor , https://github.com/hashgraph-online/hol-guard , https://github.com/FailproofAI/failproofai , https://github.com/eqtylab/cupcake , https://github.com/openguardrails/openguardrails
- https://github.com/fencesandbox/fence , https://github.com/GreyhavenHQ/greywall , https://github.com/eugene1g/agent-safehouse , https://github.com/landstrip/landstrip , https://github.com/strongdm/leash
- https://github.com/kubernetes-sigs/agent-sandbox , https://github.com/superradcompany/microsandbox , https://github.com/e2b-dev/E2B , https://github.com/opensandbox-group/OpenSandbox , https://github.com/daytonaio/daytona
- https://github.com/prompt-security/clawsec , https://github.com/tophant-ai/ClawVault , https://github.com/knostic/openclaw-shield
- https://github.com/bureado/awesome-agent-runtime-security (index of about 120 further projects)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (updated 2026-10-13)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (ms.date 2026-08-19, updated 2026-10-23)

## Independent verification

Checked 2026-11-09 by a second reviewer against primary sources: GitHub API (repo metadata, licence files, READMEs, docs, release assets, source trees) and vendor documentation fetched directly. Web search was unavailable (shared budget exhausted), so no news or blog coverage was used.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | uber/ADR (Apache-2.0, Python) open-sources Discovery, Sensor, ADR-Bench and Detector, is in production at Uber, and withholds Prevention | Confirmed | README states all of this verbatim. The offline ADR Explorer red-teaming engine is also withheld. `Detection/benchmark/agentdojo/` is vendored MIT code. | https://github.com/uber/ADR/blob/main/README.md |
| 2 | Pipelock keeps per-agent identity, budgets and fleet views in `enterprise/` under ELv2 and prebuilt binaries include that code; AgentWard and Cordum are BSL 1.1 | Confirmed | `enterprise/LICENSE` is Elastic License 2.0. README: release artifacts "include paid-tier code that activates with a valid license key"; `make build` yields a Community-only binary. Per-agent profiles are Pro, Conductor and fleet views are Enterprise. Both BSL 1.1 files checked (Cordum change date 2029-01-01, AgentWard 2028-04-24, both to Apache-2.0). "Leading" overstates AgentWard: agentward-ai/agentward has 19 stars, and an unrelated FIND-Lab/AgentWard is Apache-2.0. | https://github.com/pipelab-org/pipelock/blob/main/enterprise/LICENSE , https://github.com/cordum-io/cordum/blob/main/LICENSE , https://github.com/agentward-ai/agentward/blob/main/LICENSE |
| 3 | agentsh is production-ready only on Linux; macOS ESF+NE is alpha; native Windows is pending driver signing, WSL2 is the supported Windows mode | Confirmed | README: macOS ESF+NE "functional but not production-ready"; "only Windows WSL2 mode is fully supported for production use" until the minifilter is signed. Native Windows stack is minifilter + WinFsp + WinDivert + AppContainer. Latest tags are v0.20.6 release candidates. | https://github.com/canyonroad/agentsh/blob/main/docs/platform-comparison.md |
| 4 | microsoft/mxc (MIT): Rust, .NET, Node SDKs; `processcontainer` on Windows 11 24H2 build 26100.9278+, bubblewrap, Seatbelt; audit/learning mode; official builds send required telemetry | Corrected | SDKs, backends, build number and audit/learning mode all hold. Telemetry is overstated: Required diagnostic data applies to the development `1.1.0-alpha` request contract only. The published `0.9.0-alpha` and `1.0.0` contracts keep optional telemetry, off unless the run opts in, the user consents and policy permits. Telemetry is a no-op on Linux and macOS, and a source build with an empty `MXC_TELEMETRY_COMPONENT_PATH` does not route it. `--audit` disables all sandbox security for the run. | https://github.com/microsoft/mxc/blob/main/docs/telemetry.md , https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md |
| 5 | OWASP ACS v0.1.x is a JSON-RPC wire spec with Microsoft AGT as reference implementation; the reference Guardian has no envelope authentication and fails open by default | Corrected | True for `reference-implementations/agt` (HMAC "Not implemented", default posture `proceed`, replay protection and `system/ping` also missing, 2 of 19 hooks live). But the same repo ships a second stack in `adapters/`: `acs-example-guardian` implements HMAC-SHA256 signing, rolling chain, replay and skew rejection, and its Claude Code, Cursor and NAT adapters deny by default when no decision arrives (`ACS_STARTUP_POSTURE` defaults to `refuse`). The reference implementation wraps AGT's policy engine; it is not shipped by Microsoft. | https://github.com/GenAI-Security-Project/agent-control-standard/blob/integration/reference-implementations/agt/README.md , https://github.com/GenAI-Security-Project/agent-control-standard/blob/integration/adapters/README.md |
| 6 | Claude Code hooks fail open by default; `onFailure: "block"` (v2.1.295+); `allowManagedHooksOnly`; handler types command, http, mcp_tool, prompt, agent | Confirmed | All stated in the hooks reference. Limits to design around: `onFailure` works only on `command` and `http` handlers, and has no effect on `Stop`, `SubagentStop`, `TaskCompleted`, `TeammateIdle` or async hooks. Two default-block exceptions exist: Agent SDK callback hooks that time out, and shell-form hooks on Windows without Git Bash. | https://code.claude.com/docs/en/hooks.md |
| 7 | sandbox-runtime supports Windows via a dedicated `srt-sandbox` account, WFP egress fence keyed on its SID, write-restricted token and explicit ACEs | Confirmed | README wording matches. Windows is labelled alpha, needs a one-time elevated `windows-install`, and the WFP filters are machine-wide. Documented gap: filters do not follow a process that puts a different token on a thread before opening a socket, nor traffic a system service carries for it. | https://github.com/anthropics/sandbox-runtime/blob/main/README.md |
| 8 | perplexityai/numbat (Apache-2.0, Go, single binary for macOS, Linux, Windows) normalises hooks, OTLP logs and session artifacts into one CEL-evaluated event model; shipped rules are monitor-only | Confirmed | v0.3.0 assets cover darwin, linux and windows on amd64 and arm64. Blocking needs both `--enforce` at install and a rule with `enforce: true`; the installer refuses enforce mode if no rule sets it. Only observe and deny effects exist. | https://github.com/perplexityai/numbat/blob/main/docs/enforcement.md |
| 9 | Sondera hooks (Rust, MIT): adapters for ten agents over gRPC to a harness with YARA-X and 110 Cedar policies, fail closed; binaries for Linux x86-64 and Apple silicon only | Confirmed | Ten agents listed, tonic gRPC on 127.0.0.1:50051, `yara_x` used in `crates/guardrails/signature`, 110 `.cedar` files in the tree, two release assets (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`). The single release is a rolling `latest` tag, so there are no versioned binaries to pin. | https://github.com/sondera-ai/sondera-coding-agent-hooks |
| 10 | Daytona is archived with development private since June 2026; Invariant, Lasso, Leash, cupcake and mcp-guardian have had no pushes for seven months or more; mcp-context-protector is archived | Confirmed | Daytona `archived: true`, README notice matches. Last pushes: Leash 2026-04-06, cupcake 2026-03-02, Invariant 2026-01-12, Lasso mcp-gateway 2026-01-22, mcp-guardian 2025-08-08. Leash is only three days past the seven-month mark. mcp-context-protector `archived: true`. | GitHub API `repos/{owner}/{repo}` for each, 2026-11-09 |
| A | (TL;DR, matrix) "Microsoft AGT moved its policy engine onto ACS" | Refuted | Two different things share the acronym. AGT's "ACS" is Agent Control Specification, a Rust policy decision runtime at responsibleai/agent-control-spec (MIT) with the `agent-hooks` interception contract. It is not the OWASP Agent Control Standard and has no JSON-RPC wire protocol. The only link is the OWASP repo's own reference implementation, which runs AGT behind the OWASP wire contract. | https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/packages/agent-control-specification.md |
| B | (Section 5) Agent 365 is registry-centric and its overview does not describe endpoint discovery of unregistered agents | Corrected | Literally true of the overview page, misleading as a product summary. Defender for Endpoint discovers local AI agents and their MCP servers on onboarded Windows and macOS devices by process observation, with no extra deployment (needs MDE Plan 2; risk scoring needs Agent 365 or E7). A preview "AI agent runtime protection" on Windows offers agent-native event inspection and network inspection in audit or block mode. The registry also counts "Unmanaged agents". | https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents , https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection |
| C | (Implication 2) "HMAC is required by ACS-Core but missing from the reference" | Corrected | Missing from the AGT reference Guardian only. `adapters/src/acs/core/_signing.py` and the example Guardian implement the HMAC-SHA256 baseline with an independent verifier in the test harness, so there is working code to study before writing our own. | https://github.com/GenAI-Security-Project/agent-control-standard/tree/integration/adapters |
