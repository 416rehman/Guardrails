# Discovering agents (especially bespoke ones) and attributing activity to them

_Researched 2026-11-09_

Evidence labels used below: **[V]** verified today against a primary source; **[S]** seen only in a search summary or secondary source; **[K]** prior knowledge, not re-verified today; **[I]** my inference or design proposal.

## TL;DR

- **Every shipping product discovers known agents from a catalogue; none documents bespoke-agent discovery.** Microsoft states that an unlisted combination "isn't currently documented as supported" [V]. BeyondTrust comes closest: "classifiers using process naming, signatures, and LLM API traffic patterns" [V].
- **Native Linux endpoints are uncovered by the incumbents.** BeyondTrust and Origin are Windows and macOS only [V]; CrowdStrike Falcon Guardian discovers on Windows and macOS [V]; Microsoft has WSL in preview and says that is not native Linux support [V].
- **An open catalogue format already exists:** `arthur-ai/ai-detection-spec` (Apache-2.0, 63 agents, 174 identifiers, each proven on a real install in CI) [V]. It deliberately excludes SDKs, frameworks, gateways and model runners, which are exactly the bespoke-agent signals. Extend it rather than invent one.
- **"LLM client" and "agent" are different findings.** The distinguishing evidence is the loop: model response followed by tool-like effects (child exec, file write, MCP call), repeated. AgentSight correlates these with lineage, a 100 to 500 ms window and argument matching [V].
- **TLS plaintext capture by uprobe is fragile for the agents that matter.** Claude Code (Bun, static BoringSSL) and all Node.js (static OpenSSL) need per-binary resolution [V]. Microsoft's network inspection does not cover certificate pinning or HTTP/3 [V].
- **Hooks give declared intent with stable join keys.** Claude Code hooks carry `session_id`, `prompt_id`, `tool_use_id`, `agent_id`, `agent_type`, `cwd` [V]. With tracing on, Bash and PowerShell subprocesses inherit `TRACEPARENT` for the active tool span [V], which is an in-band tag an OS sensor can read at exec.
- **Self-identifying environment variables are already a de facto convention.** Vercel's `detect-agent` checks `AI_AGENT`, `CLAUDECODE`, `CURSOR_TRACE_ID`, `CODEX_THREAD_ID`, `GEMINI_CLI` and others [V].
- **File-based discovery has a known hole:** agents relocated by `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and similar are invisible to Fleet because fleetd cannot see user environments [V]. A sensor that captures exec-time environment closes it.
- **Off-machine attribution is mostly unsigned convention today** (git trailers, user-agent strings). The durable options are separate identities: Entra agent identities [V], Windows agent accounts (still preview) [V], AWS `SourceIdentity` [K], and an injected `AWS_SDK_UA_APP_ID` (50 characters maximum) [V].
- **Web Bot Auth** is now a working-group draft (`draft-ietf-webbotauth-httpsig-protocol-01`, 2026-10-29) but identifies a key directory URL, not a user or an individual agent session [V].
- **Encrypted-traffic research says LLM streams are classifiable from metadata alone** (97.7% model fingerprinting, 90.7% multi-agent task fingerprinting reported in arXiv 2609.31877) [S]. That is a usable signal for self-hosted or unknown endpoints.

## Findings

### Part 1. How others discover and attribute

**Microsoft Defender for Endpoint** (docs dated 2026-11-02) [V]. Two discovery methods: process-based (seeing the process run is enough; "doesn't prove active use") and periodic collection of installed VS Code extensions. MCP configuration discovery needs antivirus active mode. Agent identity is the tuple user + device + agent type, so 15 project folders count once. Roughly 60 named entries per OS including Claude Code, Cursor, Codex, Gemini CLI, Copilot CLI, OpenClaw, Goose, Kiro, Warp, Windsurf, Ollama, LM Studio. Data lands in `AgentsInfo` (`Platform == "LocalAgents"`), with `RawAgentInfo.localAgentMetadata` holding `vendor`, `relatedProcess`, `trustedProcess`, `autoApprove`, `accountSid`, `localMcps`. Graph edges: `runs on`, `uses` (mcp/server), `used by` (user). Runtime protection (preview, Windows) uses vendor hooks for Claude Code and Copilot, and network inspection for OpenClaw, Ollama and ChatGPT. Minimum versions: Defender platform `4.18.26090.9`, macOS `101.26072.0017`. Licence: Defender for Endpoint P2; risk scoring needs E7 or Agent 365.
Sources: https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents, https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix, https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview

**Microsoft Agent 365 and Entra Agent ID** [V]. Agent 365 went GA 2026-05-01, per user. Cloud agents arrive via "Connected platforms": Amazon Bedrock (Agents Classic, AgentCore), Vertex AI, Salesforce Agentforce, Databricks Genie, Anthropic Claude Managed Agents, Oracle, Snowflake Cortex. Limits: key-based credentials only, manual sync only, deletion reconciliation not guaranteed. Entra agent identities exist to "distinguish operations performed by AI agents"; sign-ins are logged as agents; delegated and autonomous modes both exist.
Sources: https://learn.microsoft.com/en-us/microsoft-agent-365/overview, https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms (2026-11-05), https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities

**BeyondTrust AI Agent Security (Pathfinder agent)** [V]. Endpoint only, Windows 11 / Server 2022+ x64 and macOS 14 to 26, no Linux, no Windows on Arm. Inventories agents, MCP servers, LLM endpoints, skills. Requires a tenant root certificate trusted on each endpoint for HTTPS inspection, plus system extension approval on macOS. Enforces at kernel and network level, and on tool calls where hooks exist; does not inspect prompts. States that agents "run as the signed-in user" and that sensor policy is what separates them. Policy replay against recorded activity.
Source: https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security

**CrowdStrike Falcon Guardian** (announced 2026-09-01) [V for press release; no technical docs reachable]. Sensor discovers "known and shadow" agents on Windows and macOS, inventories "running and dormant" agents and who deployed them, builds a causal chain "from user prompt, identity, tool call, and skill use" to system actions. AI Gateway (including MCP) described in future tense. No mechanism documented publicly.
Source: https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-guardian-ai-agent-security/

**Origin (formerly Prelude)** [V]. macOS and Windows agent. Capture is at the application layer, explicitly "not the network layer": it configures each tool's native OpenTelemetry exporter to a local collector, uses application hooks where no telemetry exists, and reads browser claude.ai, ChatGPT and M365 Copilot from the vendors' compliance APIs. Covered: Claude Code, Claude Cowork, Codex CLI, ChatGPT Desktop, Copilot CLI, Cursor.
Sources: https://docs.originhq.com/getting-started/what-is-origin, https://docs.originhq.com/getting-started/ai-providers.md

**Fleet and osquery** [V]. Fleet's `ai_agent_sessions` table (macOS, Windows, Linux) parses transcripts in every home directory for Claude Code, Copilot CLI, Cursor CLI, Codex CLI, Gemini CLI: `session_id`, `project_path`, `git_repository`, `model`, token counts, `tool_calls`, `user_messages`, `account_identifier`. Caveats: `account_identifier` comes from user-editable files and "isn't an authenticated identity"; env-relocated agents are missed. Community extension `karmine05/agentic-detector` (MIT, 13 stars) adds an `ai_tools` table with a 0 to 100 `confidence` and `evidence` tokens for unknown harnesses, where "name matching alone never creates a row".
Sources: https://fleetdm.com/tables/ai_agent_sessions, https://github.com/karmine05/agentic-detector

**ai-detection-spec** (Arthur AI, Apache-2.0, updated 2026-11-09) [V]. A catalogue, evidence schema, matcher and conformance vectors, with an osquery binding (5.23.1). Routes include `bundle_ids`, `homebrew`, `npm`, `pypi`, `deb/rpm`, `binaries`, `state_dirs`, `process_paths`, `vscode_extensions`, `jetbrains_plugins`, `extension_ids`, `native_messaging_hosts`, `msix_families`, `uninstall_keys`, `launchd_prefixes`, `images`, `image_labels`. Design rules worth copying: identifiers come from real installs, not vendor docs; superseded identifiers are kept; "could not look" never shares a word with "nothing there"; a listening port is not an identifier (measured: OpenClaw's listener resolved to a generic `node` path). Documented blind spots: VMs and dev boxes, Podman, snap, Flatpak, Alpine, AppImage, `/usr/local/bin` installs, npx and bunx caches.
Source: https://github.com/arthur-ai/ai-detection-spec

**Snyk agent-scan** (Apache-2.0, 3,230 stars, active 2026-11-09) [V]. Discovery is purely path existence per OS in `well_known_clients.py`, then MCP config and skills parsing. Also probes WSL home directories from Windows.
Source: https://github.com/snyk/agent-scan

**Cisco** [V]. `cisco-ai-defense/aibom` (Apache-2.0) scans source, container images and cloud for models, agents, tools, MCP servers and clients, prompts, secrets. Seven languages, but structural agent detection (agent instantiation, ReAct loops, MCP and A2A) is Python-only; other languages rely on imports plus an LLM classification tier. Outputs CycloneDX, SPDX, SARIF.
Source: https://github.com/cisco-ai-defense/aibom

**AgentSight** (MIT, 780 stars, arXiv 2508.02736) [V]. eBPF uprobes on `SSL_read`/`SSL_write` plus `sched_process_exec` and kprobes on `openat2`, `connect`, `execve`; in-kernel filtering to the agent's descendants; reported overhead about 2.9% on three Claude Code workflows. No precision or recall figures.
Sources: https://arxiv.org/html/2508.02736v2, https://github.com/eunomia-bpf/agentsight

**Harmonic** [S]: browser extension plus endpoint agent plus local MCP gateway. **Wiz AI-SPM** [S]: agentless cloud API scanning into an AI-BOM in its graph. **Zenity, Noma, Push, Jamf, 1Password Device Trust checks**: not verified (see end).

### Part 2. Fingerprints for known agents

The table is a sample; the full verified set is in `catalog/agents.yaml` of ai-detection-spec [V]. Config paths are from Snyk [V]. Environment markers are from Vercel `detect-agent` [V]. Hostnames and user agents are [K].

| Agent | Install identifiers | State and config | Env marker in children | API host [K] |
|---|---|---|---|---|
| Claude Code | npm `@anthropic-ai/claude-code`; `~/.local/bin/claude(.exe)`; `~/.local/share/claude/versions/`; deb/rpm `claude-code`; VS Code `anthropic.claude-code` | `~/.claude`, `~/.claude.json`, plugin `.mcp.json` | `CLAUDECODE`, `CLAUDE_CODE`; `CLAUDE_CODE_IS_COWORK` | api.anthropic.com, Bedrock, Vertex |
| Claude Desktop | bundle `com.anthropic.claudefordesktop`; MSIX `Claude_pzs8sxrjxfjjc`; native messaging host `com.anthropic.claude_browser_extension.json` | `claude_desktop_config.json` under app support | | api.anthropic.com, claude.ai |
| Claude in Chrome | extension `fcoeoabgfenejglbffodgkkbkcdhcgfn` | | | |
| Codex CLI | npm `@openai/codex`; brew `codex`; VS Code `openai.chatgpt` | `~/.codex` | `CODEX_SANDBOX`, `CODEX_CI`, `CODEX_THREAD_ID` | api.openai.com, chatgpt.com |
| ChatGPT Desktop | bundle `com.openai.codex` (was `com.openai.chat`) | | | |
| Cursor | bundle `com.todesktop.230313mzl4w4u92`; `~/.local/bin/cursor-agent`; `~/AppData/Local/Programs/cursor/` | `~/.cursor/mcp.json` | `CURSOR_TRACE_ID`, `CURSOR_AGENT` | *.cursor.sh |
| Copilot CLI | npm `@github/copilot`; JetBrains `github-copilot-intellij` | `~/.copilot/mcp-config.json` | `COPILOT_MODEL`, `COPILOT_GITHUB_TOKEN` | *.githubcopilot.com |
| Gemini CLI | npm `@google/gemini-cli` | `~/.gemini/settings.json` | `GEMINI_CLI` | generativelanguage.googleapis.com |
| Windsurf | bundle `com.exafunction.windsurf` | `~/.codeium/windsurf/mcp_config.json` | | |
| OpenClaw | npm `openclaw`, `clawdbot`, `moltbot`; bundle `ai.openclaw.mac`; launchd `ai.openclaw.*` | `~/.openclaw` | | any |
| Cline / Roo / Kilo | VS Code `saoudrizwan.claude-dev`, `rooveterinaryinc.roo-cline`, `kilocode.kilo-code` | | | any |
| aider | pypi `aider-chat`; image `paulgauthier/aider` | `~/.aider` | | any |
| opencode | npm `opencode-ai` | `~/.opencode`, `~/.config/opencode` | `OPENCODE=1` | any |
| Kiro, Amazon Q | bundle `dev.kiro.desktop`, `com.amazon.codewhisperer` | `~/.kiro/settings/mcp.json`, `~/.aws/amazonq/mcp.json` | | |
| Devin | npm `devin`; `~/.local/bin/devin` | `/opt/.devin` | | |

Not found in any open source: Apple Team IDs and Authenticode publisher names per agent, TLS fingerprints (JA3 or JA4) per agent, and exact user-agent strings. These need to be measured on real installs.

### Part 3. Bespoke and unknown agents

**Static composition.** [K] Go binaries embed module lists (`go version -m`), so `openai-go`, `anthropic-sdk-go`, `langchaingo`, MCP Go SDK are readable from the file. Rust exposes dependencies only if built with `cargo auditable`, otherwise crate paths in panic strings. Python and Node pure-source modules do not appear in memory maps, so resolve the interpreter's environment from the exec path, working directory, argv and `VIRTUAL_ENV`, then read `site-packages` or `node_modules`. JVM: classpath jars (`langchain4j`, `spring-ai`). aibom's symbol knowledge base is a ready source for the framework list [V].

**API shape on arbitrary hosts** [K, with SDK headers V]. Paths `/v1/messages`, `/v1/chat/completions`, `/v1/responses`, Ollama `/api/chat`, Bedrock `/model/{id}/converse-stream`, Vertex `:streamGenerateContent`, Azure `/openai/deployments/{d}/chat/completions?api-version=`. Headers `anthropic-version`, `x-api-key`, and the Stainless SDK set `X-Stainless-Lang`, `-Package-Version`, `-OS`, `-Arch`, `-Runtime`, `-Runtime-Version` (verified in `anthropic-sdk-python/_base_client.py`). Request JSON with `model` + `messages` + `tools`; response `text/event-stream`. The `tools` array in the request is the cheapest single indicator that a client is an agent rather than a chat app [I].

**Behavioural loop** [V from AgentSight, I for thresholds]. Alternation of model response and tool-like effects, with arguments in the effect appearing in the preceding response.

**MCP** [K]. stdio child exchanging newline-delimited JSON-RPC 2.0 beginning with `initialize` and `protocolVersion`; HTTP with `Mcp-Session-Id` and `MCP-Protocol-Version` headers. OpenTelemetry now defines `mcp.session.id`, `mcp.method.name`, `mcp.protocol.version` [V].

**Servers and Kubernetes.** OpenTelemetry eBPF Instrumentation ships a `gen_ai` schema group [V, depth not checked]. Bedrock runtime calls (`InvokeModel`, `Converse`, streaming variants) are CloudTrail management events; prompt content needs opt-in invocation logging [S, AWS docs]. Mesh sidecars see L7 only when the mesh originates the provider TLS [K].

**Repositories and CI.** aibom [V]; CycloneDX and SPDX AI describe composition, not presence on a machine [V per ai-detection-spec].

**SaaS.** OAuth grants and admin audit logs [K]; vendor compliance APIs as Origin uses [V]; Agent 365 connected platforms [V].

**Traffic and web research.** arXiv 2609.31877, 2510.07176 (AgentPrint), 2606.20910 (web-agent attribution), 2609.28559 [S]. Web Bot Auth: `Signature-Agent` dictionary header, `tag="web-bot-auth"`, key directory at `/.well-known/http-message-signatures-directory`; the draft says the identifier "says nothing about who operates the Agent" and does not authenticate users [V]. Deployed by Cloudflare, AWS WAF, Akamai, Vercel [S].

### Part 4. Attribution

**Hook and telemetry join keys** [V]. Claude Code: 33 hook events including `SessionStart`, `PreToolUse`, `PostToolUse`, `SubagentStart`, `ConfigChange`, `CwdChanged`; `allowManagedHooksOnly` and HTTP hooks with `onFailure: "block"` (v2.1.295+). OTel events `claude_code.tool_result` and `tool_decision` carry `tool_use_id`; `OTEL_LOG_TOOL_DETAILS=1` adds `bash_command`, `mcp_server_name`. `TRACEPARENT` propagation to subprocesses requires tracing (beta).
Sources: https://code.claude.com/docs/en/hooks, https://code.claude.com/docs/en/monitoring-usage

**OS primitives and how lineage breaks** [K]. See the per-OS design below.

**Synthetic input** [K]. Windows low-level hook flags `LLKHF_INJECTED` and `LLMHF_INJECTED`; macOS CGEvent source PID and source state fields, and the TCC Accessibility grant list as the set of processes able to synthesize; Linux uinput virtual devices and XTEST; browsers launched with remote-debugging flags.

**Off-machine.** Git: `Co-Authored-By` trailers; Cursor's Agent Trace RFC 0.1.0 and git-ai's `refs/notes/ai` [S]. AWS: `AWS_SDK_UA_APP_ID` is supported by CLI v2, boto3, JS v3, Go v2, Rust, Java 2.x [V]; `SourceIdentity` persists across role chaining into CloudTrail [K]. Terraform `TF_APPEND_USER_AGENT` [K]. OTel GenAI agent spans (`gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.conversation.id`, `invoke_agent`, `execute_tool`) are still "Development" status [V].

**Provenance research.** Survey arXiv 2606.04990; AuthGraph arXiv 2605.26497 compares an intent-derived authorization graph with an execution provenance graph [S]. No OS-level agent provenance paper found beyond AgentSight.

## Matrix

| Product | Known agents | Bespoke | Method | OS | Attribution basis |
|---|---|---|---|---|---|
| Microsoft Defender | ~60 listed | No | Process, VS Code extension inventory, MCP config | Win, macOS, WSL preview | user + device + agent type |
| BeyondTrust | Yes | Claimed (classifiers) | Kernel, TLS inspection with root cert, hooks | Win, macOS | Per-agent policy, session record |
| CrowdStrike Guardian | Yes | "Shadow" claimed | Falcon sensor | Win, macOS | Causal chain, undocumented |
| Origin | 6 tools | No | Native OTel, hooks, compliance APIs | Win, macOS | Prompt + user + process tree |
| Fleet | 5 CLIs | No | Transcript parsing | Win, macOS, Linux | Session rows, unauthenticated account |
| agentic-detector | Catalogue | Yes, scored | Multi-signal osquery extension | All three | None |
| ai-detection-spec | 63 | No, by scope | Catalogue + osquery | All three | None |
| Snyk agent-scan | 14 | No | Path existence | All three | None |
| Cisco aibom | n/a | Yes, in source | Static analysis + LLM tier | Repos, images | None |
| AgentSight | Any | Yes, if wrapped | eBPF TLS + syscalls | Linux | Lineage + time + arguments |

## Weak points, gaps and risks

- Catalogue identifiers rot: bundle ids and npm scopes change (ChatGPT, Amp, Pi, OpenClaw all renamed) [V]. Unscoped npm names collide [S].
- Process-name and path signals are trivially evaded by renaming; environment markers are set by the agent and can be unset by anything downstream.
- TLS inspection needs a trusted root and breaks on pinning and HTTP/3 [V]; uprobes need per-runtime work [V].
- The loop heuristic's 100 to 500 ms window has no published precision or recall [V].
- Framework presence overcounts: a library is not an agent (the spec removed `mcp-sdk` and `litellm` for this reason) [V].
- Hooks are self-reported. A compromised or misconfigured agent reports nothing; `account_identifier` and git trailers are forgeable [V].
- Inventory counts differ by definition (user + device + type versus per session), which will confuse comparisons with Defender.

## Implications for our design

**Signal taxonomy** (reliability / evasion):

| Class | Signal | Reliability | Evasion |
|---|---|---|---|
| A Identity | Code-signing identity + catalogue path | High for known | Unsigned builds, wrappers |
| B Declared | Hook, OTel, SDK registration | High when present | Disable hooks, relocate config |
| C Composition | LLM SDK or agent framework in the process image | Medium | Vendoring, static builds |
| D Egress | Provider host or API shape on any host | Medium (LLM client only) | Gateway indirection, ECH, HTTP/3 |
| E Loop | Model response then tool-like effect, repeated | High for "agent" | Slow or batched tools, remote tools |
| F MCP | JSON-RPC `initialize` on stdio or HTTP | High | Custom tool protocol |
| G Environment | API keys, base URLs, agent markers | Low alone | Unset |
| H Workspace | Instruction files, skills, MCP configs | Low alone | None needed |
| I Local model | Connection to a model server, GPU use | Low alone | Remote models |

**Score "this process is an agent"** [I]. Take one weight per class, combine as noisy-OR: `P = 1 - Π(1 - w)`. Starting weights: A 0.99, B 0.99, E 0.80, F 0.60, D 0.50, C 0.40 (agent framework) or 0.20 (bare SDK), I 0.30, H 0.20, G 0.15. Emit two tiers: **LLM client** (D without E or F) and **agent** (P at or above 0.8 with at least two classes, one of which is behavioural: D, E or F). Never emit on a single weak class. Always store the evidence tokens, as agentic-detector does. Weights are placeholders until we have labelled data.

**Score "this action belongs to session X"** [I]. Start from the strongest binding and decay:

1. Kernel-tracked container of the session (cgroup, job object, audit-token lineage): 1.0.
2. Inherited tag read at exec (`TRACEPARENT`, our own session variable): 0.95, and it binds to a specific tool call.
3. Hook match: `PreToolUse` with `tool_use_id`, normalised command and `cwd` matched to an exec in the same lineage inside the hook-to-`PostToolUse` interval: 0.95.
4. Brokered hop (Docker socket, SSH, scheduler, WMI, launchd) where the request came from the session's lineage and the effect follows within a short window: 0.6 to 0.8.
5. File-mediated (session wrote a file that another principal later executed): record as "influenced by", never "performed by".

Report two gap detections as first-class events: an OS action inside a session's lineage that no declared tool call covers, and a session lineage with zero hook events while hooks are expected.

**Attribution per OS** [I, built on K]:

- **Linux.** eBPF on fork, exec, exit and LSM hooks; key every process by pid plus start time. Place each agent session in its own cgroup v2 at launch (wrapper or shim), so the cgroup id rides on every event and survives double-fork and `setsid`. Capture exec-time environment. Follow brokers explicitly: connections to the Docker and containerd sockets, `systemd-run`, cron, SSH client execs.
- **macOS.** Endpoint Security: `audit_token`, `parent_audit_token`, `responsible_audit_token`, session id, TTY, signing id and Team ID; exec events carry argv and environment. The responsible token recovers processes that launchd started on the agent's behalf. A Network Extension filter maps flows to the source audit token.
- **Windows.** Kernel process callbacks or ETW, recording the creating process as well as the declared parent to defeat parent spoofing. Put the session in a job object without breakaway. Treat WMI, Task Scheduler, COM and WSL as brokered hops. Adopt agent accounts when Agent Workspace ships; it is preview and off by default today [V].

**Push identity outward** [I]. At session start the sensor (or launcher) injects: a session variable, `AI_AGENT`, `AWS_SDK_UA_APP_ID`, `TF_APPEND_USER_AGENT`, and where a broker exists, short-lived credentials with `SourceIdentity`. Write a sensor-signed git note per commit rather than trusting trailers.

**Catalogue format** [I]. Adopt ai-detection-spec's catalogue and evidence schemas and contribute upstream. Add routes it lacks: `codesign` (Team ID, publisher, signing id), `net` (hosts, path patterns, header and user-agent patterns), `env_markers`, `hooks` (events, config path, managed-settings path), `telemetry` (OTel support), `mcp_config` (paths and parser), `transcripts` (path and parser), `autonomy_flags`. Keep a second catalogue, "building blocks", for SDKs, frameworks, gateways and model runners, feeding classes C and I. Keep the provenance rule: no identifier without a CI run on a real install.

## Ideas worth stealing and whitespace

- "Could not look" as a distinct outcome from "nothing there" (ai-detection-spec).
- Policy replay against recorded history before enforcing (BeyondTrust).
- Configuring the agent's own OTel exporter to a local collector (Origin): cheap, structured, no TLS interception.
- Confidence plus evidence tokens on every unknown-agent row (agentic-detector).
- **Whitespace:** bespoke-agent discovery with stated precision; native Linux endpoints; declared-versus-observed gap detection; sensor-minted session identity carried into cloud, git and SaaS logs; resolving env-relocated agent state; one open catalogue spanning install, network, hooks and telemetry.

## Could not verify / open questions

- The web search budget for this run was exhausted partway. **Not researched from primary sources:** Zenity, Noma, Push Security, Jamf, 1Password Device Trust AI checks, Wiz technical docs, Harmonic docs.
- CrowdStrike technical documentation is behind login; the IR press-release mirror returned 403. Agent Graph internals unknown.
- BeyondTrust's classifier details and how it treats unknown agents: only one overview page reached.
- Whether `AWS_SDK_UA_APP_ID` appears verbatim in CloudTrail `userAgent`: the AWS page does not say.
- Windows Agent Workspace status after December 2025: no newer primary source found.
- Agent Trace repository location: `cursor/agent-trace` returned 404 via the GitHub API.
- Team IDs, publisher names, user agents and TLS fingerprints per agent: must be measured.
- Open problems: remote tool execution (agent in cloud, effects on endpoint or the reverse); agents driving a human's existing browser session; many sessions sharing one long-lived daemon (IDE extension hosts, tmux); sub-agent identity across process boundaries; attribution through shared MCP servers; distinguishing an agent-typed shell command from a human typing in the same terminal.

## Sources

- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (BeyondTrust AI Agent Security, fetched 2026-11-09)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (2026-08-19, updated 2026-10-23)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms (2026-11-05)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview (2026-10-08)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-inventory (2026-11-03)
- https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities (updated 2026-06-15)
- https://support.microsoft.com/en-us/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3 (updated 2025-12-05, may be stale)
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-guardian-ai-agent-security/ (2026-09-01)
- https://docs.originhq.com/getting-started/what-is-origin and /getting-started/ai-providers.md (fetched 2026-11-09)
- https://fleetdm.com/tables/ai_agent_sessions (fetched 2026-11-09)
- https://github.com/karmine05/agentic-detector (pushed 2026-08-10)
- https://github.com/arthur-ai/ai-detection-spec (updated 2026-11-09)
- https://www.arthur.ai/column/detect-ai-coding-agents-osquery (2026-10-29 figures)
- https://github.com/snyk/agent-scan (pushed 2026-11-09)
- https://github.com/cisco-ai-defense/aibom (pushed 2026-11-07)
- https://arxiv.org/html/2508.02736v2 and https://github.com/eunomia-bpf/agentsight (pushed 2026-10-31)
- https://github.com/vercel/vercel/blob/main/packages/detect-agent/src/index.ts (fetched 2026-11-09)
- https://code.claude.com/docs/en/hooks and https://code.claude.com/docs/en/monitoring-usage (fetched 2026-11-09)
- https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol (-01, 2026-10-29)
- https://docs.aws.amazon.com/sdkref/latest/guide/feature-appid.html (fetched 2026-11-09)
- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html (search summary only)
- https://github.com/open-telemetry/semantic-conventions-genai (agent spans, MCP; pushed 2026-11-09)
- https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation (gen_ai schema group)
- https://github.com/anthropics/anthropic-sdk-python/blob/main/src/anthropic/_base_client.py (X-Stainless headers)
- arXiv 2609.31877, 2510.07176, 2606.20910, 2609.28559, 2606.04990, 2605.26497 (search summaries only)
- https://www.harmonic.security/products/command, https://www.wiz.io/academy/ai-security/ai-inventory (marketing, search summaries only)

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: direct fetches of primary documentation and read-only GitHub API reads of source. Web search was not available for this pass (shared budget exhausted), so nothing below rests on search summaries. Three claims need correcting (5, 6, 8) and one statement outside the claim list is outdated (MCP fingerprint)._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Microsoft Defender local agent discovery is catalogue-based (process observation plus VS Code extension inventory) on Windows and macOS, WSL in preview, no native Linux, unlisted agents not documented as supported | confirmed | Matrix lists 62 Windows and 59 macOS entries. WSL preview covers only Claude Code, Codex CLI and Copilot CLI, agent only, no MCP. "WSL support doesn't indicate support for native Linux endpoints." macOS VS Code extension entries are also preview. Commercial cloud only. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix, https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents |
| 2 | BeyondTrust AI Agent Security: Windows 11 / Server 2022+ x64 and macOS 14 to 26 only, tenant root certificate for HTTPS inspection, classifiers on process naming, signatures and LLM API traffic patterns | confirmed | Exact wording matches. macOS means 14, 15 and 26. Windows on Arm excluded. Page metadata dated 2026-10-13. The page says nothing about pinned traffic or how unknown or custom agents are treated, so "bespoke: claimed" in the matrix is an inference from one sentence. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |
| 3 | ai-detection-spec is Apache-2.0, 63 agents, 174 CI-proven identifiers, excludes SDKs, frameworks, gateways, model runners | confirmed | README and SPEC.md section 3 match; also excludes container/language runtimes and completion engines. Removed list: mcp-sdk, litellm, docker, ollama, lm-studio, jan, llama-cpp. Maturity risk: repository created 2026-08-28, 6 stars, 0 forks, 4 contributors, latest release v0.17.1 (2026-11-06). Treat as a young single-vendor project, not an established standard. | https://github.com/arthur-ai/ai-detection-spec (README, SPEC.md, catalog/agents.yaml, repo metadata via GitHub API) |
| 4 | Claude Code hooks deliver session_id, prompt_id, tool_use_id, agent_id, agent_type, cwd; allowManagedHooksOnly enforces managed-only hooks | confirmed | Not all fields are on every event. `session_id`, `cwd` and `prompt_id` are common fields (`prompt_id` absent until first user input). `tool_use_id` is event-specific (tool events). `agent_id` and `agent_type` appear only inside a subagent or with `--agent`. `allowManagedHooksOnly` blocks user, project, local and plugin hooks, except plugins force-enabled in managed `enabledPlugins`. 33 hook events and `onFailure` (v2.1.295+) also confirmed. | https://code.claude.com/docs/en/hooks |
| 5 | With tracing enabled (beta), Bash and PowerShell subprocesses inherit TRACEPARENT for the active tool span | corrected | True only when `ANTHROPIC_BASE_URL` is unset or points at the Anthropic API. Behind a custom proxy or gateway the variable is not set unless `CLAUDE_CODE_PROPAGATE_TRACEPARENT=1` (v2.1.152+). Hook subprocesses get it too. Tracing needs both `CLAUDE_CODE_ENABLE_TELEMETRY=1` and `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`. The brief missed an always-on alternative: `CLAUDE_CODE_SESSION_ID` is set automatically in Bash, PowerShell, hook and stdio MCP subprocesses and matches the hook `session_id`, with no tracing required. Use that as the session tag at exec and TRACEPARENT as the optional per-tool-call tag. | https://code.claude.com/docs/en/monitoring-usage, https://code.claude.com/docs/en/env-vars |
| 6 | Claude Code (Bun, static BoringSSL) and all Node.js (static OpenSSL) do not use system libssl; AgentSight reports about 2.9% overhead, no precision or recall | corrected | "All Node.js" is wrong. Node's default build and the nodejs.org / nvm binaries bundle OpenSSL statically, but distro packages are built with `--shared-openssl` and do use system libssl (verified in Debian `debian/rules` and Alpine `main/nodejs/APKBUILD`). The sensor must detect the linkage per binary, not assume by runtime. The static-linking statement comes from the AgentSight README FAQ; the paper does not mention Bun, BoringSSL or Node. 2.9% is the mean of three tasks (3.4%, 4.9%, 0.4%) on Claude Code 1.0.62, three runs each. No precision, recall or false-positive figures: confirmed. | https://github.com/eunomia-bpf/agentsight (README), https://arxiv.org/html/2508.02736v2, https://salsa.debian.org/js-team/nodejs/-/raw/master/debian/rules, https://github.com/alpinelinux/aports/blob/master/main/nodejs/APKBUILD, https://github.com/nodejs/node/blob/main/configure.py |
| 7 | Fleet ai_agent_sessions cannot find agents relocated by CLAUDE_CONFIG_DIR, CODEX_HOME and similar; account_identifier is not an authenticated identity | confirmed | Listed variables: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`, `GEMINI_CLI_HOME`, `CURSOR_DATA_DIR`. Reason given: fleetd cannot see users' environments. Other limits: default 30-day window, at most 5,000 sessions per agent per home directory, 4 GiB of transcripts per query. | https://fleetdm.com/tables/ai_agent_sessions |
| 8 | Agents set self-identifying env vars in children (AI_AGENT, CLAUDECODE, CURSOR_TRACE_ID, CODEX_THREAD_ID, GEMINI_CLI, OPENCODE), as checked by Vercel detect-agent | corrected | detect-agent does check all six: confirmed in source. Agent-side emission confirmed for `CLAUDECODE=1` (Claude Code docs), `CODEX_THREAD_ID` (openai/codex source) and `GEMINI_CLI=1` (gemini-cli source). `AI_AGENT` is different: it is a convention detect-agent reads first; it is absent from the Claude Code env-var reference and from the openai/codex source, so do not expect the major agents to emit it. `CURSOR_TRACE_ID` (closed source) and `OPENCODE` were not independently verified. Two cautions: `CLAUDECODE` is also set by IDE extensions in integrated terminals, so it does not prove an agent ran the command (`CLAUDE_CODE_CHILD_SESSION` is the narrower marker); and several detect-agent checks (`COPILOT_GITHUB_TOKEN`, `COPILOT_MODEL`, `CODEX_CI`) are user-supplied configuration, not agent-set markers. Better join keys exist: Codex also sets `CODEX_SESSION_ID` and `CODEX_TOOL_CALL_ID` in the child environment. | https://github.com/vercel/vercel/blob/main/packages/detect-agent/src/index.ts, https://code.claude.com/docs/en/env-vars, https://github.com/openai/codex/blob/main/codex-rs/protocol/src/shell_environment.rs, https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/shellExecutionService.ts |
| 9 | Web Bot Auth draft-ietf-webbotauth-httpsig-protocol-01 (2026-10-29): Signature-Agent identifies a key-directory URL; does not authenticate users or say who operates the agent | confirmed | Version and date match. Section 4.1: "says nothing about who operates the Agent"; section 4.6: "does not authenticate human users". `Signature-Agent` is now a Dictionary structured field; earlier individual drafts used a bare String, so a parser should accept both. Still an Internet-Draft. | https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/ |
| 10 | AWS_SDK_UA_APP_ID (max 50 chars) supported by CLI v2, boto3, JS v3, Go v2, Rust, Java 2.x; CloudTrail appearance not confirmed | confirmed | Also supported: .NET 3.x/4.x, PHP 3.x, Ruby 3.x, Kotlin, Swift, C++ (env var only), PowerShell V4/V5. Not supported: Go v1, Java 1.x, JS v2. On CloudTrail: botocore appends `app/<id>` to the User-Agent; CloudTrail `userAgent` stores the string up to 1 KB, and AWS's own Bedrock CloudTrail example shows the full botocore User-Agent verbatim. So it very likely appears, but no AWS page says so explicitly; run one functional test. The value is caller-set and unsigned. | https://docs.aws.amazon.com/sdkref/latest/guide/feature-appid.html, https://github.com/boto/botocore/blob/develop/botocore/useragent.py, https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html, https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html |
| A | (Brief, Part 3 and signal class F) MCP is recognised by `initialize` + `protocolVersion` on stdio and by `Mcp-Session-Id` / `MCP-Protocol-Version` on HTTP | corrected (outdated) | The current MCP revision is 2026-07-28. It removes the `initialize` / `notifications/initialized` handshake and removes protocol-level sessions and the `Mcp-Session-Id` header. Every request now carries `_meta.io.modelcontextprotocol/protocolVersion` and client capabilities; servers must implement `server/discover`; Streamable HTTP POSTs require `Mcp-Method` and `Mcp-Name` headers. stdio is still newline-delimited JSON-RPC. A detector must match both eras: legacy `initialize`, and the new per-request `_meta` keys, `server/discover` and `Mcp-Method`. | https://modelcontextprotocol.io/specification/2026-07-28/changelog, https://modelcontextprotocol.io/specification/2026-07-28/basic/transports |
| B | (Brief, Part 3) Bedrock runtime calls are CloudTrail management events; prompt content needs invocation logging | confirmed | `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream` are management events. Data events (opt-in): `InvokeModelWithBidirectionalStream`, async invoke, `InvokeAgent`, `InvokeInlineAgent`, `InvokeFlow`, `Retrieve`, `ApplyGuardrail`. Two additions: streaming calls emit a second `AwsServiceEvent` with token counts (do not double-count), and the `bedrock-mantle` endpoint has separate CloudTrail logging. | https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html |
| C | (Brief, Part 1) Agent 365 went GA 2026-05-01, licensed per user | confirmed | "As of May 1, 2026, Microsoft Agent 365 is generally available for the Commercial segment on a per user basis." | https://learn.microsoft.com/en-us/microsoft-agent-365/overview |
