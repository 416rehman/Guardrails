# Other agent surfaces: desktop, browser, computer-use, frameworks and cloud agent platforms

_Researched 2026-11-09_

Evidence tags: **[V]** read in a primary source this session; **[S]** secondary source only; **[PK]** prior knowledge, not re-verified (re-check before building on it).

## TL;DR

- **Microsoft has shipped the reference competitor.** Defender for Endpoint "local AI agent discovery" is GA on Windows and macOS (docs dated 2026-11-02) and names about 60 agents, including Claude Desktop, ChatGPT Desktop, Codex Desktop, OpenClaw, Ollama, LM Studio and Perplexity Desktop. Native Linux is absent (WSL preview only). Runtime protection is Windows-only preview. [V]
- **Desktop agents are moving their agent loop to the vendor cloud.** Claude Cowork now defaults to a cloud sandbox; ChatGPT Work uses "Local computer access with Work Cloud". An endpoint sensor sees only the local executor, and host EDR cannot see inside the Cowork VM. Vendor API connectors are therefore mandatory, not optional. [V]
- **Vendors expose real managed policy.** Claude Desktop MDM keys, OpenAI `requirements.toml` (`[browser_use]`, `[computer_use]`, `mcp_servers`), Chrome `GeminiActOnWeb*`, Edge `AllowBrowsingWithCopilot`. Our product should author, deploy and verify these rather than duplicate them. [V]
- **Server-side inline verdict hooks now exist.** Claude Enterprise Inference hooks (`prompt` and `tool_call` events, allow or deny, 5 s default), Copilot Studio `analyze-tool-execution` (1,000 ms, fails open), AgentCore Gateway Policy plus Lambda interceptors, Google Agent Gateway plus Model Armor. One "verdict server" can serve all of them. [V]
- **OpenTelemetry GenAI conventions are still Development status** and moved to a separate repo (`open-telemetry/semantic-conventions-genai`, created 2026-05-05, no release yet). OpenInference has the widest framework coverage; official OTel Python contrib has three packages. We must ingest three dialects. [V]
- **A framework-neutral control contract has appeared:** AGENT-HOOKS-0.1 (`responsibleai/agent-hooks`, MIT, created 2026-06-19, 25 stars), eight interception points, three verdicts, fail-closed. Implemented experimentally in Microsoft Agent Framework for Python only. [V]
- **In-framework guardrails are opt-in and mostly fail open.** Claude Agent SDK callbacks fail open unless `onFailure: "block"`; OpenAI Agents SDK tool guardrails skip hosted tools, handoffs, `ComputerTool` and `ShellTool`. [V]
- **Agent registries are proliferating** (Agent 365, AWS Agent Registry GA August 2026, Google Agent Registry GA 2026-06-18, Workday ASOR, ServiceNow). None is neutral and none covers bespoke endpoint agents well. [V/S]
- **ChatGPT Atlas appears retired (9 August 2026);** its browser-agent function moved into the ChatGPT desktop app, a Chrome extension and Codex. [S, primary page returned 403]
- **Synthetic-input flags are weak evidence.** Windows injected flags carry no process identity, and accessibility-API actions bypass the input stream entirely. Attribute by process lineage, permission grants and agent-native logs. [V/PK]

## Findings

### (a) Desktop and personal agents

**Claude Desktop and Cowork (Anthropic).** [V]
- Execution: cloud sessions run the agent loop and code in a per-session Anthropic sandbox; local files are reached through the desktop app over an Anthropic-brokered connection. Local sessions run the loop natively and code in a Linux VM (Apple Virtualization.framework on macOS, Hyper-V on Windows). For consumer plans, local sessions apply only to tasks started before 2026-10-06. ([architecture overview](https://support.claude.com/en/articles/14479288-claude-cowork-architecture-overview))
- EDR gap, stated by the vendor: a host sensor cannot see inside the VM; an approved vendor sensor can be installed in the VM via `coworkEDRIntegration` and `coworkEDRIntegrationVendor` (beta). Cloud sessions are invisible to endpoint tools.
- Managed policy: macOS domain `com.anthropic.claudefordesktop`; Windows `HKLM:\SOFTWARE\Policies\Claude` (HKCU also read, machine wins). Keys: `allowedWorkspaceFolders`, `forceLoginOrgUUID`, `isDesktopExtensionEnabled`, `isDesktopExtensionDirectoryEnabled`, `isLocalDevMcpEnabled`, `isClaudeCodeForDesktopEnabled`, `secureVmFeaturesEnabled`, `disableAutoUpdates`, `autoUpdaterEnforcementHours`. A machine policy wins even when weaker than the organisation setting. ([enterprise configuration](https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop))
- Telemetry: Cowork OTLP (HTTP/JSON or HTTP/protobuf), endpoint set in Organization settings; content off by default, enabled by device policy `otlpContentCapture`; `prompt.id` correlates events. Team and Enterprise. ([Cowork OTel](https://support.claude.com/en/articles/14477985-monitor-claude-cowork-activity-with-opentelemetry))
- Compliance API: `GET /v1/compliance/activities` plus session-transcript endpoints covering Cowork, Claude Code, Claude in Chrome, Claude for Microsoft 365 and Claude Tag; 600 requests per minute per parent organisation; polling only. API-key (Console), Bedrock and Vertex workloads are excluded. ([Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api))
- Inline block: Inference hooks, Claude Enterprise only. Anthropic POSTs the transcript to your HTTPS server (Standard Webhooks signature); verdict `{"action": "allow"}` or deny with `deny_reason`; failure mode configurable; circuit breaker, shadow mode and rollout percentage. No redaction, no image bytes, not on API platform. ([Inference hooks](https://platform.claude.com/docs/en/manage-claude/inference-hooks))
- Config paths [PK]: `~/Library/Application Support/Claude/claude_desktop_config.json`, `%APPDATA%\Claude\claude_desktop_config.json`; MCP logs under `~/Library/Logs/Claude/`.

**ChatGPT desktop, ChatGPT Work, Codex app (OpenAI).** [V]
- Acts via sandboxed shell and files, Browser Use (in-app browser or Chrome extension) and Computer Use. macOS needs Screen Recording plus Accessibility; Windows drives the visible desktop only. "Locked Use" installs a macOS authorization plugin that can unlock the Mac. ([local security](https://learn.chatgpt.com/docs/enterprise/chatgpt-work-local-security))
- Policy gap worth detecting: when Computer Use drives a browser, Browser Use site policies do not apply.
- Managed config: Admin Console "Agent security"; `requirements.toml` (enforced) and `config.toml` (defaults); macOS MDM keys `requirements_toml_base64` / `config_toml_base64` under `com.openai.codex`. Notable keys: `allowed_sandbox_modes`, `allowed_approval_policies`, `[rules] prefix_rules`, `[mcp_servers.<name>] identity`, `[browser_use] origins`, `[computer_use] macos.bundle_ids / windows.aumids / windows.exes`, `allow_appshots`, `allow_remote_control`, `features.browser_use_full_cdp_access`. MDM outranks the cloud console. ([managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration))
- Audit limits, stated by OpenAI: cloud orchestration events do not reach the customer OTel collector; the Compliance API does not record every local file operation, screenshot or browser action; no complete record of Chrome-extension actions.
- Compliance Logs Platform: immutable time-windowed JSONL, 30-day retention, includes Codex logs. [S]

**Microsoft Copilot on Windows, Copilot Cowork, Agent Workspace.** Copilot Cowork has built-in Agent 365 integration [V]. Windows "agent workspace" reportedly runs each agent under its own standard local account, which would make agent-versus-human attribution an OS primitive; I found only secondary coverage from late 2025. [S]

**OpenClaw and derivatives.** `openclaw/openclaw` is MIT with 394k stars [V]. Defender tracks OpenClaw, ZeroClaw, Nanobot, QClaw, Clawpilot and Hermes Agent as separate named agents [V]. Config `~/.openclaw/openclaw.json` (JSON5) and gateway port 18789 on loopback [S]. Intune can block OpenClaw; that is the only local agent Microsoft blocks by policy [S].

**Local runtimes.** Defender inventories Ollama Desktop, LM Studio and Foundry Local, and network-inspects Ollama [V]. Default listeners [PK]: Ollama 11434, LM Studio 1234, Jan 1337, llama.cpp server 8080.

**Gemini app, Manus, Perplexity desktop, Raycast AI.** No enterprise technical docs retrieved. Perplexity Desktop is in the Defender matrix (discovery only). Treat as discover-by-signature with no vendor control plane.

**Third-party endpoint products.**
- Defender discovery: process observation, periodic VS Code extension inventory, and MCP config parsing (needs AV active mode). Identity is user x device x agent type. Data lands in advanced-hunting table `AgentsInfo` (`Platform == "LocalAgents"`), with `RawAgentInfo.localAgentMetadata` fields `vendor`, `relatedProcess`, `trustedProcess`, `autoApprove`, `localMcps`; graph edges `runs on`, `uses`, `used by`. Requires Defender for Endpoint Plan 2. ([discover](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents), [matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix))
- Defender runtime protection (preview, Windows): "agent-native event inspection" through vendor hooks for Claude Code, Claude Desktop (Code mode) and GitHub Copilot surfaces; "network inspection" for OpenClaw, Ollama Desktop and ChatGPT. Network inspection fails against certificate pinning and HTTP/3. One alert type: "Suspicious AI prompt injection". ([runtime protection](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview))
- BeyondTrust AI Agent Security: Pathfinder agent, kernel and network visibility, Windows 11 / Server 2022+ x64 and macOS 14 to 26 only; classifies by process name, signature and LLM traffic pattern; allow, audit, require-approval, block; different rules for agent and human under the same credentials; replays recorded activity against a draft policy. Needs a trusted tenant root certificate. ([docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security))

### (b) Browser agents

| Surface | Control | Audit |
| --- | --- | --- |
| Gemini in Chrome / auto browse | `GeminiSettings`, `GeminiActOnWebSettings`, `GeminiActOnWebAllowedForURLs`, `GeminiActOnWebBlockedForURLs`, `GeminiSparkSettings`; auto browse off by default for managed users [V via Google help snippet] | Chrome Enterprise reporting |
| Edge Copilot Mode | `AllowBrowsingWithCopilot` (Edge 148+), `CopilotPageContext`, `EdgeEntraCopilotPageContext`, `CopilotCoworkToolActionsEnabled` (Edge 152+) [S citing Learn] | Purview `CopilotInteraction` |
| Claude in Chrome | Org allowlist and blocklist; deploy or block with Chrome extension management; extension id `fcoeoabgfenejglbffodgkkbkcdhcgfn` [S] | Compliance API sessions; Inference hooks [V] |
| ChatGPT (extension, in-app browser) | `[browser_use]` origin policy in `requirements.toml` [V] | OTel site-access, upload and download events; incomplete |
| Perplexity Comet | MDM install; "500+ Chromium-based policies"; Agent Permission Controls [V]; bundle id `ai.perplexity.comet` [S] | Audit logs need 50+ Enterprise Pro seats or one Enterprise Max seat [V] |
| ChatGPT Atlas | Retired 2026-08-09 [S]; bundle id `com.openai.atlas.web` | None |
| Dia, Opera Neon | No enterprise docs found | Unknown |

Automation stacks: Playwright MCP (Apache-2.0, 39k stars), Chrome DevTools MCP (Apache-2.0, 55k), browser-use (MIT, 120k), Stagehand (MIT, 26k) [V]. Since Chrome 136 the `--remote-debugging-port` switch is ignored for the default profile, so automation must pass `--user-data-dir` [S]. Chrome 144+ adds user-enabled remote debugging at `chrome://inspect/#remote-debugging`; DevTools MCP `--autoConnect` attaches to the live profile after a per-session consent dialog. ([Chrome blog](https://developer.chrome.com/blog/chrome-devtools-mcp-debug-your-browser-session)) [V]

### (c) Computer-use agents

- Windows: low-level hooks expose `LLKHF_INJECTED` / `LLMHF_INJECTED` and the lower-integrity variants. The flag says "injected", never "by whom". ([KBDLLHOOKSTRUCT](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-kbdllhookstruct)) [V]
- macOS: events carry a source state id and a source Unix process id; the poster chooses the state, so it is spoofable [S/PK]. Required grants are the strongest signal: Accessibility, Screen Recording, PostEvent and ListenEvent in TCC. Endpoint Security has a TCC-modify notification on recent macOS [PK].
- Linux: uinput virtual devices, XTEST, libei and the RemoteDesktop portal, AT-SPI [PK].
- Structural gap: UI Automation and AX "press" actions never enter the input stream, so no injected flag fires. Vendors document the permissions they need (OpenAI: Screen Recording plus Accessibility, a macOS authorization plugin for Locked Use). [V]

### (d) Frameworks and SDKs

| Framework | Block before tool | Model wrap | Notes |
| --- | --- | --- | --- |
| LangChain 1.x / LangGraph | `wrap_tool_call` (skip handler) | `wrap_model_call`, `before_model`, `after_model` with `jump_to` | [V] ([docs](https://docs.langchain.com/oss/python/langchain/middleware/custom)) |
| OpenAI Agents SDK | `@tool_input_guardrail`, `@tool_output_guardrail` (function tools only) | `@input_guardrail` (`run_in_parallel=False` to block), `@output_guardrail` | Hosted tools, handoffs, `ComputerTool`, `ShellTool` uncovered [V] |
| Claude Agent SDK | `PreToolUse` with `permissionDecision` allow, deny, ask, defer and `updatedInput`; `canUseTool` | `UserPromptSubmit` | Python lacks `SessionStart`/`SessionEnd` callbacks; fail-closed needs `onFailure: "block"` (TS 0.3.317+, Py 0.2.177+) [V] |
| Google ADK | plugin `before_tool_callback` | `before_model_callback`, `on_user_message_callback` | Global on Runner/App; Python, TS, Java, Go, Kotlin; Model Armor and Tool Call Integrity plugins [V] |
| Microsoft Agent Framework | function middleware; Agent Hooks `pre_tool_call` | chat middleware; `pre_model_call` | .NET, Python, Go; Agent Hooks Python-only, experimental [V] |
| Strands | `BeforeToolCallEvent` | model-call events | Repo now `strands-agents/harness-sdk` [V/S] |
| CrewAI, Pydantic AI, Vercel AI SDK, Mastra, LlamaIndex, smolagents, Semantic Kernel, Spring AI, Genkit, Agno | tool hooks, approvals, filters, advisors, processors | model middleware | [PK]; not re-verified |

OTel coverage read from repositories today [V]:
- Official `opentelemetry-python-contrib/instrumentation-genai`: `openai-v2`, `openai-agents-v2`, `vertexai` only.
- OpenLLMetry (Traceloop): 31 packages including `langchain`, `llamaindex`, `crewai`, `openai-agents`, `agno`, `mcp`, `ollama`, `anthropic`, `bedrock`. No Claude Agent SDK, Google ADK, Pydantic AI or Strands.
- OpenInference (Arize): 38 Python packages including `claude-agent-sdk`, `google-adk`, `pydantic-ai`, `strands-agents`, `smolagents`, `agent-framework`, `openai-agents`, `mcp`; JavaScript includes `claude-agent-sdk`, `openai-agents`, `langchain`, `mcp`, `vercel`.
- Microsoft's own Agent 365 observability SDK is deprecated in favour of the Microsoft OpenTelemetry Distro; it adds `microsoft.a365.agent.blueprint.id`, `microsoft.a365.caller.agent.*` and `microsoft.tenant.id` next to `gen_ai.agent.id`. ([choose integration](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/choose-integration-option))

### (e) Cloud and SaaS agent platforms

See the connector matrix. Additional verified detail:
- Agent 365: GA 2026-05-01, per-user licence. Three paths: built-in (Copilot Studio, Foundry, Copilot Cowork), registry sync preview (Vertex AI, Bedrock), SDK. Registry has an "Unmanaged agents" counter; risk signals lag up to an hour. ([overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview), [registry](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview))
- AgentCore: Policy GA March 2026 (Cedar, attached to Gateway); Lambda request and response interceptors (July 2026); Bedrock Guardrails in policy (July 2026); Agent Registry GA August 2026 with auto-detection of Runtimes and Gateways across an AWS Organization; namespace `agent-registry` (September 2026) with `ListDiscoverableRegistryRecords`; Evaluations accept OTel and OpenInference conventions. ([release notes](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/release-notes.html))
- Google: Vertex AI was renamed Gemini Enterprise Agent Platform on 2026-04-22; Agent Engine is now Agent Runtime. Agent Registry (`agentregistry.googleapis.com`), Agent Identity and Agent Gateway with inline Model Armor. [S plus doc snippets]
- Claude Managed Agents: permission policies `always_allow`, `always_ask`, `auto`; SSE at `/v1/sessions/{session_id}/events/stream`; policies cover server-executed tools only. [S from doc snippets]

## Matrix

### Connector matrix

| Platform | Inventory | Activity / audit | Runtime block or approve |
| --- | --- | --- | --- |
| Claude Enterprise | Compliance API users, orgs, settings, sessions | `GET /v1/compliance/activities`, session transcripts, Cowork OTLP | Inference hooks (`prompt`, `tool_call`) |
| Claude Managed Agents | Agents and sessions API | Session event list and SSE stream | `always_ask` confirmations |
| ChatGPT Enterprise / Codex | Workspace admin; `requirements.toml` posture | Compliance Logs Platform JSONL; local OTel | Managed requirements; no documented inline webhook |
| Microsoft Agent 365 | Graph `GET /v1.0/copilot/admin/catalog/packages` (preview, `CopilotPackages.Read.All`) | Purview audit; Defender `AgentsInfo` | Block agent in registry; Defender; Entra |
| Copilot Studio | Power Platform admin, Agent 365 | Purview, Defender | `POST /analyze-tool-execution?api-version=2025-05-01` |
| Azure AI Foundry | Foundry Control Plane fleet view [S] | Tracing GA March 2026 [S]; Purview | AI Gateway, content safety |
| AWS Bedrock AgentCore | Agent Registry; control-plane list calls | CloudTrail; spans in CloudWatch | Gateway Policy (Cedar), Lambda interceptors |
| Google Agent Platform | Agent Registry API | Cloud Audit Logs, Agent Identity trail | Agent Gateway plus Model Armor |
| Salesforce Agentforce | No dedicated inventory API found | Session Trace API (beta, 72-hour window, Data 360) [S] | Platform trust layer |
| ServiceNow | AI Control Tower inventory; connectors for Anthropic, OpenAI, Agent 365 [S] | Platform audit | AI Gateway [S] |
| Workday | ASOR registration API, Agent Definition Registry API [S] | ASOR | Agent Gateway for partner agents |
| GitHub Agent HQ | Enterprise AI controls [S] | Enterprise audit log | Agent and MCP allow policies [S] |
| Databricks, Snowflake, Slack, Notion, Atlassian Rovo, n8n, Zapier | Not researched to primary depth | Use each product's audit-log API | Unknown |

## Weak points, gaps and risks

- **Linux endpoints are unserved** by both Microsoft and BeyondTrust. Kubernetes and server agents are covered only through cloud registries.
- **Named-agent catalogues do not find bespoke agents.** Defender says its inventory "isn't a complete inventory" and keys on known names. BeyondTrust's LLM-traffic classifier is the only behavioural approach seen.
- **Cloud-orchestrated desktop agents break endpoint-only telemetry.** OpenAI states that cloud orchestration events never reach the customer collector.
- **Fail-open is the norm:** Copilot Studio at 1,000 ms, Claude Agent SDK callbacks, any network inspection defeated by pinning or HTTP/3.
- **Verdicts are coarse.** Copilot Studio and Inference hooks are allow or deny only; no redaction.
- **Compliance APIs are polling, lossy and plan-gated** (Enterprise tiers; Comet audit needs 50+ seats).
- **Policy precedence can weaken security:** a Claude machine policy overrides a stricter organisation setting.
- **Standards are unsettled:** GenAI semconv unreleased; AGENT-HOOKS is version 0.1 with 25 stars.
- **Research gaps in this brief:** Gemini app, Manus, Raycast, Dia, Neon, and most SaaS platforms in the last matrix row.

## Implications for our design

1. **Three collection planes, one schema:** endpoint sensor (process, file, network, permissions), vendor connectors (compliance and registry APIs), and in-agent SDK or hooks. Reconcile them on a stable agent identity.
2. **Ship Linux and Kubernetes first-class.** It is the clearest unoccupied ground.
3. **Build a signature catalogue as open data** (process names, bundle ids, AUMIDs, extension ids, config paths, default ports, MCP config locations), seeded from the Defender matrix names, plus a behavioural classifier for unknown agents (LLM endpoint traffic, MCP stdio children, loopback inference ports).
4. **Build one verdict server** with adapters for Claude Inference hooks, Copilot Studio `analyze-tool-execution`, AgentCore Lambda interceptors, Claude Code and Copilot hooks, and AGENT-HOOKS. Budget under 1 s; make fail mode explicit per adapter; offer shadow mode and replay.
5. **Treat vendor managed policy as posture.** Generate and verify Claude Desktop keys, OpenAI `requirements.toml`, Chrome and Edge policies; alert on drift and on precedence conflicts.
6. **Ingest OTLP in three dialects** (OTel GenAI, OpenInference, OpenLLMetry) and normalise to an internal model; emit OTel GenAI outward. Do not invent a fourth convention.
7. **Install inside the Cowork VM** through `coworkEDRIntegration` if we can become an approved vendor; otherwise rely on Cowork OTLP plus Compliance API.
8. **Publish into registries** (Agent 365, AWS, Google) as well as reading from them, so EDR vendors embedding us inherit that reach.

### SDK instrumentation plan

- Phase 1, Python and TypeScript: LangChain/LangGraph middleware, OpenAI Agents SDK guardrails plus trace processor, Claude Agent SDK hooks (with `onFailure: "block"`), Google ADK plugin, MCP client and server wrappers. These cover the frameworks with verified pre-tool block points.
- Phase 2: Microsoft Agent Framework (.NET middleware, Python Agent Hooks), Vercel AI SDK, Mastra, Pydantic AI, CrewAI, Strands, LlamaIndex.
- Phase 3: Java (Spring AI, ADK Java), Go (ADK Go, Agent Framework Go), Semantic Kernel legacy, Genkit, Agno, smolagents.
- Expose one contract shaped like AGENT-HOOKS (eight points, allow, deny, transform) and map each framework to it. Where a framework cannot block (hosted tools), report the gap in the inventory record.

### Normalised agent-inventory record

`agent_id` (stable hash), `instance_id`, `class` (desktop, browser, computer-use, framework, cloud, SaaS, local-runtime), `name`, `vendor`, `version`, `discovery_sources[]` with confidence and first/last seen, `host` (device id, OS, container, cluster, namespace) or `cloud` (provider, account, region, resource id), `human_principal` and `agent_principal` (OS account, Entra Agent ID, service principal, workload identity), `owner` and `sponsor`, `process` (path, signer, hash, parent lineage, trusted flag), `execution_location` (local, VM, vendor cloud), `capabilities` (shell, file scope, browser, computer-use, network egress), `os_permissions` (TCC grants, UIA, debugging), `autonomy` (approval mode, auto-approve), `models[]` and `llm_endpoints[]`, `mcp_servers[]` (name, transport, command or URL, origin), `tools[]`, `skills_plugins_extensions[]`, `config_paths[]`, `managed_policy` (source, keys, drift), `telemetry` (OTel endpoint, content capture), `enforcement_points[]` with fail mode, `registry_refs[]`, `lifecycle_status`, `risk` (score, indicators), `data_sensitivity_reach`.

### Detection signals by class

- **Desktop agents:** signed binary and bundle id or AUMID; config and extension directories; child `node`, `python`, `uvx`, `npx` MCP processes; Hyper-V or Virtualization.framework VM spawned by the app; policy registry keys and plists; outbound to vendor inference hosts.
- **Local runtimes:** loopback listeners 11434, 1234, 1337, 8080; model directories; GPU load.
- **Browser agents:** extension ids; managed-policy values; `--remote-debugging-port` or `--remote-debugging-pipe` with non-default `--user-data-dir`; remote-debugging enabled in the live profile; Playwright or Puppeteer parentage; headless flags; native-messaging host manifests.
- **Computer-use agents:** new Accessibility or Screen Recording grants; screenshot API call cadence; injected-input flags correlated with a foreground agent process; authorization-plugin installs; UIA or AX client attachment.
- **Framework agents:** imported packages in process memory or lockfiles; OTLP exporters; `gen_ai.*` spans; LLM API keys in environment; MCP stdio pipes.
- **Cloud and SaaS agents:** registry records, CloudTrail and audit-log create events, new service principals or agent identities, OAuth grants to agent apps.

## Ideas worth stealing and whitespace

- Steal: BeyondTrust policy replay against recorded history; Anthropic shadow mode, rollout percentage and circuit breaker; Defender exposure-graph edges (`runs on`, `uses`, `used by`) and the `autoApprove` posture flag; AGENT-HOOKS payload-free audit records; OpenAI per-origin browser policy with "block wins".
- Whitespace: native Linux and Kubernetes; bespoke-agent discovery by behaviour; one cross-vendor verdict protocol; unified view of local executor plus cloud orchestration for the same session; computer-use attribution that survives accessibility-API paths; a neutral registry that both reads and writes vendor registries; posture verification of vendor managed policies; self-hosted single-laptop mode (every competitor is SaaS-console-first).

## Could not verify / open questions

- OpenAI help article on Atlas retirement returned 403; retirement date is secondary.
- Windows agent workspace and agent accounts: no primary Microsoft doc retrieved.
- Claude in Chrome extension id and default-on date are from third-party guides.
- Exact Cowork OTel event names, and the tail of OpenAI's managed-configuration page (Windows paths, hooks, OTel keys), not read.
- AgentCore Policy ENFORCE / LOG_ONLY modes and Google `reasoningEngines` paths after the rename.
- Hook details for CrewAI, Pydantic AI, Vercel AI SDK, Mastra, LlamaIndex, smolagents, Spring AI, Genkit, Agno.
- Databricks, Snowflake, Slack, Notion, Rovo, n8n, Zapier, GitHub Agent HQ API specifics; Gemini app, Manus, Raycast, Dia, Neon enterprise controls.
- Whether official OTel GenAI instrumentations beyond the three seen have moved to another repository.

## Sources

- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — BeyondTrust AI Agent Security (fetched 2026-11-09)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Agent 365 overview (2026-08-19, updated 2026-10-23)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/choose-integration-option — integration options (2026-09-30)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview — Agent Registry (2026-09-21)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/archive/observability-sdk — deprecated observability SDK (2026-10-01)
- https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview — local AI agent discovery (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents — discovery how-to and KQL (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix — support matrix (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview — runtime protection preview (2026-10-08)
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers — Copilot Studio threat-detection webhook (updated 2026-10-15)
- https://learn.microsoft.com/en-us/agent-framework/concepts/agents/middleware/ — Agent Framework middleware (2026-10-22)
- https://learn.microsoft.com/en-us/agent-framework/agents/agent-hooks — Agent Hooks (2026-09-15)
- https://github.com/responsibleai/agent-hooks — AGENT-HOOKS-0.1 spec (repo created 2026-06-19)
- https://support.claude.com/en/articles/14479288-claude-cowork-architecture-overview — Cowork architecture
- https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop — Claude Desktop enterprise configuration
- https://support.claude.com/en/articles/14477985-monitor-claude-cowork-activity-with-opentelemetry — Cowork OTel
- https://platform.claude.com/docs/en/manage-claude/compliance-api — Compliance API (API version 2026-10-21)
- https://platform.claude.com/docs/en/manage-claude/inference-hooks — Inference hooks
- https://code.claude.com/docs/en/agent-sdk/hooks — Claude Agent SDK hooks
- https://learn.chatgpt.com/docs/enterprise/managed-configuration — OpenAI managed configuration
- https://learn.chatgpt.com/docs/enterprise/chatgpt-work-local-security — ChatGPT Work local security
- https://openai.github.io/openai-agents-python/guardrails/ — OpenAI Agents SDK guardrails
- https://docs.langchain.com/oss/python/langchain/middleware/custom — LangChain custom middleware
- https://adk.dev/plugins/ — Google ADK plugins
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/release-notes.html — AgentCore release notes (through 2026-11)
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/overview — Gemini Enterprise Agent Platform overview (snippet)
- https://support.google.com/chrome/a/answer/16291696 — Gemini in Chrome admin help (snippet)
- https://developer.chrome.com/blog/chrome-devtools-mcp-debug-your-browser-session — DevTools MCP auto-connect
- https://www.perplexity.ai/help-center/en/articles/12781449-comet-for-enterprise — Comet for Enterprise
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-kbdllhookstruct — KBDLLHOOKSTRUCT
- https://github.com/open-telemetry/semantic-conventions-genai — GenAI conventions repo (created 2026-05-05)
- https://github.com/traceloop/openllmetry and https://github.com/Arize-ai/openinference — package listings read 2026-11-09
- https://accuroai.co/blog/agentic-browsers-enterprise-control-matrix-atlas-comet-edge — secondary browser matrix (Atlas retirement, Edge policies)
- https://developer.salesforce.com/docs/ai/agentforce/guide/otel-api.html — Agentforce session tracing export (snippet)
- https://doc.workday.com/admin-guide/en-us/workday-ai/agents/workday-agent-gateway-for-partner-agents.html — Workday Agent Gateway (snippet)

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: direct fetches of primary documentation and read-only GitHub API queries. Web search was unavailable (session search budget exhausted), so nothing here rests on search snippets, and the ChatGPT Atlas retirement date remains unchecked._

Three claims need correcting before the architecture relies on them: 4, 7 and 8. The rest held.

| # | Claim | Verdict | Note | Source |
| --- | --- | --- | --- | --- |
| 1 | Defender local AI agent discovery covers Windows and macOS only (WSL preview, no native Linux); process, VS Code extension inventory and MCP config; `AgentsInfo` table | Confirmed | GA on Windows and macOS. WSL preview covers only Claude Code, Codex CLI and GitHub Copilot CLI, agent discovery without MCP; the page states WSL support does not imply native Linux. macOS VS Code extension entries are also preview. MCP config is an attribute of a discovered agent, not a way of finding one. Commercial cloud only. | https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview ; https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents |
| 2 | Cowork defaults to an Anthropic cloud sandbox; local sessions run code in a Linux VM host EDR cannot see into; cloud sessions invisible to endpoint tools | Confirmed | Vendor text: sessions "run in the cloud by default"; a host EDR sensor "can't see inside" the VM. The in-VM sensor keys `coworkEDRIntegration` and `coworkEDRIntegrationVendor` exist and are marked beta. | https://support.claude.com/en/articles/14479288-claude-cowork-architecture-overview ; https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop |
| 3 | Inference hooks send each governed prompt, optionally tool calls, to a customer HTTPS server; 5 s default; configurable failure handling; not API platform, Bedrock or Vertex | Confirmed | Timeout range 1 to 10,000 ms, default 5,000 ms. Default failure mode on first save is "Allow the request" (fail open). "Validate tool calls" is on by default in a new configuration, so tool calls are opt-out rather than opt-in. Also covers Claude for Microsoft 365 and Claude Tag. Endpoint must be public HTTPS on port 443. | https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration |
| 4 | Copilot Studio calls `POST /analyze-tool-execution?api-version=2025-05-01` before each tool invocation, 1,000 ms, timeout treated as allow | Corrected | Path, version and 1,000 ms hold. Allow-on-timeout is only the default: the Power Platform admin center "Set error behavior" setting can be switched to "Block the query" for timeouts and errors. The feature is still labelled preview, is configured per environment, and is skipped for classic (non-generative-orchestration) agents. | https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider |
| 5 | OpenAI: with Local computer access with Work Cloud, cloud orchestration events do not reach the customer OTel collector; Compliance API does not capture every local file operation, screenshot or browser action | Confirmed | Both statements appear verbatim in substance; the page adds that changing the collector endpoint does not restore the events and that no complete record of Chrome-extension actions is stored. Only the researcher's own source was available for this one. | https://learn.chatgpt.com/docs/enterprise/chatgpt-work-local-security |
| 6 | OpenAI Agents SDK tool guardrails apply only to function tools | Confirmed | Source code agrees: in `src/agents/tool.py` only `FunctionTool` has `tool_input_guardrails` and `tool_output_guardrails`; `ComputerTool`, `ShellTool`, `ApplyPatchTool`, `LocalShellTool` and the hosted tool classes have neither. Local MCP server tools can carry guardrails (they are function tools); `Agent.as_tool()` does not expose the option. | https://github.com/openai/openai-agents-python/blob/main/src/agents/tool.py |
| 7 | Claude Agent SDK hook callbacks that throw or time out let the action proceed unless `onFailure: "block"` | Corrected | True for a callback that throws, returns nothing or returns invalid output. Not true for timeouts on the events that matter most: a timed-out `PreToolUse` callback blocks the tool call, a timed-out `UserPromptSubmit` blocks the prompt, and a timed-out `PreModelSwitch` blocks the switch, all without `onFailure`. Default timeout is 600 s for most events and 30 s for `UserPromptSubmit`. `onFailure` is ignored by `Stop`, `SubagentStop`, `TaskCompleted` and `TeammateIdle`. Version floors (TS 0.3.317, Python 0.2.177) hold; Python is at 0.2.180. | https://code.claude.com/docs/en/agent-sdk/hooks (sections "Block the action when a callback fails" and "Hook timeout") |
| 8 | GenAI semconv in a separate repo created 2026-05-05 with no release; official Python contrib ships only three GenAI instrumentations; OpenInference ships 38 Python packages | Corrected | Repo date, no release or tag (changelog "Unreleased", schema URL "TODO") and the OpenInference count of 38 all hold. The "only three" inference is wrong: official instrumentations moved to `open-telemetry/opentelemetry-python-genai` (created 2026-05-12), which ships 17 packages including `claude-agent-sdk`, `langchain`, `anthropic`, `bedrock`, `crewai`, `llama-index`, `openai`, `openai-agents`, `google-genai`, `agno`, `dspy`, `ollama` and `smolagents`, released as 1.3b0 on 2026-10-23. The copies left in contrib are security-patch only. | https://github.com/open-telemetry/opentelemetry-python-genai ; https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/instrumentation-genai |
| 9 | AWS Agent Registry GA August 2026 with auto-detection across AWS Organizations; AgentCore Policy (Cedar at the Gateway) GA March 2026 | Confirmed | Registry preview was April 2026. Policy is evaluated at AgentCore Gateway and now accepts Dogwood as a second policy language alongside Cedar. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html |
| 10 | AGENT-HOOKS-0.1 is MIT, framework-neutral, eight interception points, allow, deny and transform; implemented only experimentally in Microsoft Agent Framework for Python | Confirmed | Repo metadata matches (MIT, created 2026-06-19, 25 stars). No other framework host found; GitHub code search shows only `microsoft/agent-framework` plus demos depending on `agent-hooks-sdk`. Beyond the brief: the repo ships SDKs for Rust, Python, TypeScript, .NET and Go, labels itself Beta, carries a moving draft spec next to 0.1, and allows a per-binding `on_error: continue` that turns fail-closed into fail-open. | https://github.com/responsibleai/agent-hooks |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
| --- | --- | --- | --- |
| "Fail-open is the norm: Copilot Studio at 1,000 ms, Claude Agent SDK callbacks" | Corrected (overstated) | Fail-open is the default, not a fixed property. Copilot Studio can be set to block on timeout or error; Claude Agent SDK `PreToolUse` and `UserPromptSubmit` timeouts already block; Inference hooks default to allow but can be set to block. The verdict server should record the configured failure mode per adapter rather than assume one. | Rows 3, 4 and 7 above |
| AgentCore "Lambda request and response interceptors (July 2026); Bedrock Guardrails in policy (July 2026)" | Corrected | Both sit under June 2026 in the release notes ("AgentCore Policy Now Supports Bedrock Guardrails"; interceptor Lambdas are mentioned in "Gateway: AgentCore Runtime targets are now generally available"). July 2026 has no interceptor or policy entry. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/release-notes.html |
| "OpenLLMetry (Traceloop): 31 packages" | Corrected (minor) | The `packages` directory holds 35 entries: 32 instrumentation packages plus `opentelemetry-semantic-conventions-ai`, `traceloop-sdk` and `sample-app`. The absence of Claude Agent SDK, Google ADK, Pydantic AI and Strands holds. | https://github.com/traceloop/openllmetry/tree/main/packages |

Spot checks that held without change: BeyondTrust AI Agent Security supports Windows 11 / Server 2022+ x64 and macOS 14, 15 and 26 only, with policy replay and a tenant root certificate; `openclaw/openclaw` is MIT with 394k stars; `strands-agents/sdk-python` redirects to `strands-agents/harness-sdk`; star counts for Playwright MCP, Chrome DevTools MCP, browser-use and Stagehand.

Design consequence of row 8: official OTel GenAI instrumentation now covers most major Python frameworks, so the "three dialects" ingest plan stands but OTel GenAI deserves more weight relative to OpenInference than the brief gives it.
