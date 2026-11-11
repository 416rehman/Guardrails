# CrowdStrike Falcon Guardian (AIDR) teardown and the Falcon integration surface

_Researched 2026-11-09_

Method note: web search was unavailable for this run (shared search budget exhausted), so everything below comes from the pre-captured pages, direct fetches of CrowdStrike documentation (aidr-docs.crowdstrike.com, developer.crowdstrike.com) and CrowdStrike's public GitHub source. Claims are tagged **[V]** verified in a primary source this session, **[I]** inferred, **[P]** prior knowledge not re-verified.

## TL;DR

- Falcon Guardian (GA 1 Sep 2026) is the Pangea AI Guard service plus Falcon sensor telemetry. The Pangea-era product "AI Detection and Response" reaches **end of support on 30 Nov 2026** and its capabilities continue in Guardian. The API namespace is still `/aidr/*` and the scope is still `AIDR:read`. **[V]**
- Every enforcement decision is a cloud round trip to one endpoint: `POST https://api.crowdstrike.com/aidr/aiguard/v1/guard_chat_completions` (OpenAI chat-completions shaped, 1 MiB cap, may return 202 and require polling). There is no local policy engine in the hook collectors. **[V]**
- Agent hooks are thin and public: Codex and Copilot CLI collectors are MIT Rust binaries, OpenCode is an MIT TypeScript plugin, Claude Code is a native HTTP hook with no binary. All use only `UserPromptSubmit`, `PreToolUse`, `PostToolUse`. Default timeout 30 s. **Codex and Copilot default to fail-open**; OpenCode defaults to fail-closed. **[V]**
- Hook auth is a static collector bearer token in the `CS_AIDR_TOKEN` environment variable, readable by the agent it polices. Tamper resistance is delegated to the agent vendor (Claude Code `managed-settings.json`); nothing else is documented. **[V]**
- Hook events are joined to sensor telemetry by sending the sensor agent ID (AID, read from the Windows registry or `falconctl info`), the hook process ID, and a numeric "process tag" per product. That is the whole "Agent Graph" join key. **[V]**
- Endpoint network inspection is **Windows only, report-only, input only before sensor 8.10**, drops events over 1 MiB, ignores attachments, and works from a per-application allowlist. It needs AIDR for Workforce plus Falcon Insight XDR. How it reads TLS is not documented. **[V]**
- The AI Kill Switch today only tells AI gateways to block model or provider access. Endpoint termination, relaunch blocking, identity, SaaS and browser enforcement are "coming soon". **[V]**
- Linux, Kubernetes, cloud workloads, Bedrock AgentCore, macOS network inspection, behavioural baselines, intent-misalignment detection and agent identity authorization are all pre-beta or Q4 promises. **[V]**
- The public Guardian API is read-only and **cannot attribute tools, skills, models, MCP servers or sessions to a single agent**; host (sensor ID) is the finest grain. **[V]**
- Guardian is SaaS only (US-1, US-2, EU-1), closed, unpriced publicly, and requires the Falcon sensor for its headline features. No self-hosted, no MSP-embeddable form. **[V]**
- Falcon is very open on the integration side: HEC ingest into Next-Gen SIEM, Foundry apps, Fusion SOAR workflows, RTR, Custom IOA, IOC, Event Streams, FDR, correlation rules and an MIT Falcon MCP server (30 modules). An "enhance CrowdStrike" mode is practical without partnership. **[V]**

## Findings

### 1. What Guardian is and how it got here

- Pangea acquisition announced 16 Sep 2025 at Fal.Con 2025, with the stated goal of "complete AI Detection and Response (AIDR)". Price not stated. **[V]** [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-pangea-to-secure-every-layer-of-enterprise-ai/)
- Guardian launched 1 Sep 2026 as "the evolution of Falcon AIDR": AIDR's collectors and policy engine plus sensor-based agent discovery, runtime visibility, agent access controls and Next-Gen SIEM export. **[V]** [blog](https://www.crowdstrike.com/en-us/blog/falcon-guardian-defines-next-generation-of-ai-security/), [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-guardian-ai-agent-security/)
- Fal.Con Europe (3 Nov 2026) added the Kill Switch, AI Gateway GA, SafeMind-powered detection, Falcon Complete for Guardian GA, FDR export of prompt activity, Flight Control (MSSP parent/child) support, and token consumption dashboards. **[V]** [blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-ai-security-and-safety-falcon-guardian/)
- AIDR docs now carry the banner that AIDR reaches end of support on 30 Nov 2026. **[V]** [docs](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint)

### 2. Control point: agent-level hooks

Verified from source and docs:

| Agent | Mechanism | Events | Failure default | Source |
|---|---|---|---|---|
| Claude Code | Native `type: http` hook to `/aidr/aiguard/v1/claude_code_guard`; headers `Authorization: Bearer $CS_AIDR_TOKEN`, `AIDR-User`, `AIDR-Username`; `allowedEnvVars` set; no binary | UserPromptSubmit (block only), PreToolUse (block, transform), PostToolUse (block, transform) | Not documented | [docs](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/agentic/claude-code) |
| OpenAI Codex | Rust binary as `type: command` hook in `hooks.json` | same three | `--failure-mode open` | [repo](https://github.com/CrowdStrike/falcon-guardian-codex-collector) |
| GitHub Copilot CLI | Rust binary, hooks config `version: 1` | same three | open | [repo](https://github.com/CrowdStrike/falcon-guardian-github-copilot-collector) |
| OpenCode | npm plugin `@crowdstrike/falcon-guardian-opencode-collector` in `opencode.json` | prompt, tool execute.before/after | closed | [repo](https://github.com/CrowdStrike/falcon-guardian-opencode-collector) |
| Cursor, Microsoft 365 Copilot | Named in marketing; no public collector found | unknown | unknown | [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-ai-security-safety-for-the-enterprise/) |

Details from the Codex collector source (repos created 19 Oct 2026, version 0.0.0, `publish = false`) **[V]**:

- Request fields beyond the documented API: `session_id`, `conversation_id`, `agent_type: "code-assistant"`, `is_agent: true`, `process_id`, `process_tags: ["213584428666200"]`, and `extra_info.sensor_aid`.
- AID is read from `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim` value `AG` on Windows and `/Applications/Falcon.app/Contents/Resources/falconctl info` on macOS; on Linux it is `None`.
- The token is only sent to HTTPS hosts ending `.crowdstrike.com` or `.collector-crowdstrike.com`; redirects disabled; 202 responses polled with backoff inside the 30 s budget.
- Verdict mapping: PreToolUse blocked returns `permissionDecision: deny`; transformed returns `allow` with `updatedInput`; PostToolUse returns `decision: block` carrying either the reason or the redacted output. Comment in source: Codex cannot rewrite prompts, so a redacted prompt passes through unchanged.
- Fail-open prints a `systemMessage` warning and exits 0; fail-closed exits 2.

Stated limits for the Claude Code hook: it does not see LLM responses, model configuration, token usage, extended thinking, system prompts or subagent context; `model_name` and `provider` are logged as `unknown`; prompts cannot be redacted. **[V]**

How hooks are kept from being disabled: the only documented control is "use managed settings to prevent individual users from disabling the collector" for Claude Code. No tamper detection, no sensor-side integrity check of hook files is documented. **[V]** that nothing is documented; whether the sensor watches these files is unknown.

### 3. Control point: endpoint network inspection

From the Falcon Endpoint collector docs **[V]** ([overview](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint), [network inspection](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint/network-inspection), [deploy](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint/deploy)):

- Built into the sensor, no separate install. Windows 10 x64 and Windows 11 23H2+; sensor 7.40+; sensor 8.10+ adds provider response visibility, more applications and Arm64.
- Report-only: detections are logged, no blocking or transformation. Events over 1 MiB are not sent. File attachments are not processed.
- Requires AIDR for Workforce **and** Falcon Insight XDR.
- Per-application allowlist with sensor version gates: Claude.ai, Claude Desktop, Claude Code CLI, Anthropic Console, Claude Cowork, Claude for Excel and PowerPoint, DeepSeek, Gemini, Microsoft 365 Copilot, Microsoft Copilot, ChatGPT web and desktop at 7.40+; Kiro, GitHub Copilot, ChatGPT Desktop Work tab, Codex CLI at 8.10+. Cursor is absent.
- An internal gateway is covered only if it mimics a supported provider's request structure, and only via a support case to add the FQDN and path.
- Policy toggles: Browser, Network, and "User Input and Response" (disabling it "significantly increases data volume and cost").
- Status conflict: the 3 Nov blog labels network inspection "Pre-beta" with macOS planned; the same-day press release says "Generally available for Windows, with Mac in early access". **[V]** both statements exist.

TLS: the docs say only that it "intercepts network-layer traffic". The per-application, per-version allowlist and the FQDN-plus-path extension mechanism suggest protocol parsers keyed on destination, fed by either local TLS interception or in-process capture before encryption. **[I]** Not verifiable publicly.

The sensor-managed browser extension (Chrome, Edge; sensor 7.39+ Windows, 7.40+ Mac) is the only endpoint path that can block or redact, and only on input. **[V]**

### 4. Control point: OS-level runtime (the sensor)

Reconstructed from the Falcon MCP Guardian module documentation **[V]** ([module docs](https://developer.crowdstrike.com/falcon-mcp/modules/guardian/), [source](https://github.com/CrowdStrike/falcon-mcp)):

- Two stores. An entity store: `AIAgent`, `AIAgentSession`, `AITool`, `AISkillFrontmatter`, `MCPServerName`, `AIAgentInstallation`, `AIModelName`, `AIAgentOSUser` (90-day lookback). LogScale events: `AgenticSessionStart`, `AgenticToolRequest`, `AgenticUserPromptSubmit` (7-day lookback, 2-hour default).
- `AIAgentInstallation` carries `AgentVersion`, `InstallSource`, `AgentDeclarationPath`, `BinaryPath`, `FileSha256`, `LastExecutionTime`. Skills carry `SkillDirectoryHash`.
- `AgenticToolRequest` carries `AgenticToolName`, `AgenticPath`, `AgenticDescription`, `AgenticPattern`, `AgenticQuery`, `AgenticSkill`, `CommandLine`, `Url`. Executions carry `AgenticModel`, input and output token counts, `ContextProcessId`, `ProcessTags`.
- Graph endpoints keyed by `aisess:{aid}:{session_uuid}`: session activity, process tree (depth 1 to 3), network events, file events, and Falcon Data Protection classified file access.
- 22 product tags, including Claude, Claude Code, Claude Cowork, OpenClaw, GitHub Copilot, Kiro, Antigravity, Codex, Cursor, Windsurf, JetBrains, Cline, Continue, ChatGPT Desktop, Microsoft Copilot, plus `GENERIC` and `EXPERIMENTAL`.
- Detections are ordinary Falcon alerts filtered server-side by `HasAgenticProcess == true`, with an "Agentic Threat Score" per agent.
- "Agent access controls" allow or block agent types on managed endpoints. **[V]** from the launch PR; mechanism (likely process-tag based prevention) is **[I]**.

### 5. Gateway, Kill Switch, MCP proxy and other collectors

- Falcon AI Gateway: GA 3 Nov 2026, included with Guardian at no extra cost; centralizes model access, security policy, credential management, usage and cost controls; meant for unmanaged devices and workloads without a sensor. No public technical docs found. **[V]** [blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-introduces-ai-kill-switch/)
- Third-party gateway collectors (guardrail plug-ins calling the same API): Apigee, Azure API Management, Kong, LiteLLM (v1.82.1+, guardrail `crowdstrike_aidr`), Portkey, TrueFoundry, JetStream, MuleSoft. **[V]**
- Kill Switch: activation "directs connected AI gateways to block access to the AI models"; works with Falcon AI Gateway or a third-party gateway. Coming: by agent type, endpoint process termination and relaunch prevention, cloud, identity revocation (Next-Gen Identity Security), SaaS (Falcon Shield), browser sessions (Seraphic), orchestrated by Charlotte Agentic SOAR. The press release wording ("terminate it where it runs") is ahead of the blog. **[V]**
- MCP proxy: `npx -y @crowdstrike/aidr-mcp-proxy -- <original stdio server command>`; Node 22.15+; three checkpoints `tool_listing`, `tool_input`, `tool_output`; remote servers only via `mcp-remote`; does not see prompts or non-MCP traffic. **[V]** [docs](https://pangea.cloud/docs/aidr/collectors/agentic)
- Copilot Studio collector: uses Microsoft's external threat detection webhook; tool name and inputs only; allow or block only; one-second response limit. **[V]**
- OTel collector: OTLP/HTTP logs to `/aidr/aiguard/v1/otel/logs`, `gen_ai.*` events, no compression; log-only. Cloud collector: Bedrock invocation logs; log-only. **[V]**
- SDKs and wrappers (all MIT): `aidr-python`, `aidr-typescript`, `aidr-go`, OpenAI and Google GenAI wrappers, LangChain, Strands, Kiro power, `aidr-mcp-server`, and `aidr-aiguard-lab` for efficacy testing. **[V]** [GitHub org search](https://github.com/CrowdStrike)

### 6. Detection catalogue

Eleven content detectors **[V]** ([prompt rules](https://pangea.cloud/docs/aidr/policies/prompt-rules)):

| Detector | Actions | Notes |
|---|---|---|
| Malicious Prompt | report, block | Analyzer IDs such as `PA4002` with confidence; custom benign and malicious examples |
| MCP Validation | report, block | Injection in tool description, conflicting tool names, similar descriptions (threshold) |
| Malicious Entity | report, defang, block | IP, URL, domain against threat intel |
| Confidential and PII Entity | block, replace, mask, partial mask, hash, FPE, report | Per data type rules |
| Secret and Key Entity | same | API keys and similar |
| Custom Entity | same | Pattern rules |
| Code | report, block | Confidence threshold |
| Language | allow list, block list, report | |
| Topic | report, block | 11 topics including toxicity, self-harm, weapons, roleplay |
| Competitors | report, block | Name list |
| Emoji | report, block | Invisible characters, mixed scripts, stacked modifiers |

Format-preserving encryption (AES-FF1-256) returns an `fpe_context` so values can be restored with `/v1/unredact`. Deterministic mode uses a tenant tweak. **[V]**

Announced beyond content: malicious skill and MCP server discovery (available); SafeMind models built with NVIDIA Nemotron; agentic intent misalignment (upcoming); Agent Insider Threat Detection, Dynamic Risk Scoring 0 to 100, AI Ecosystem Detections for LLM API abuse and stolen keys (all Q4 in Next-Gen SIEM). **[V]** [blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-stops-agent-insider-threats/)

The prompt-injection taxonomy has two dimensions (injection methods, prompting techniques) and four classes: overt, indirect, social/cognitive, evasive. Only the root was captured. **[V]**

### 7. Policy model

**[V]** ([policies](https://pangea.cloud/docs/aidr/policies), [access rules](https://pangea.cloud/docs/aidr/policies/access-rules), [inspection rules](https://aidr-docs.crowdstrike.com/docs/aidr/policies/inspection-rules))

- Policy per collector category, reusable across collectors. Falcon Endpoint policies are assigned to host groups per platform with precedence.
- Inspection rules route events (first match wins) by conditions such as `app.event_type == tool_input`; unmatched events are logged with a "No Inspection" tag.
- Inside each route: access rules (sequential, ABAC) then prompt rules (detectors).
- Access rule operators include RE2 `matches`, `in`, group membership (`custom:`, `entra:`, `ad:` prefixes), `has` a detector finding, `executes` a prompt rule, and references to earlier matched rules. Actions: Continue, Report and Continue, Report and Stop, Block and Stop, Ignore and Stop (no log). Severity and custom tags.
- Event types: `input`, `output`, `tool_input`, `tool_output`, `tool_listing`, plus custom types for the Application collector.
- Report Only Mode per route; a natural-language Assistant drafts access rules; Sandbox and Playground for testing; configuration audit log.

### 8. Response, console, data

- Response today: block or redact at hook, browser input, gateway, MCP proxy; block agent types on endpoints; Kill Switch at gateways; Fusion SOAR workflows; standard Falcon containment. Human-in-the-loop action requests apply to CrowdStrike's own SOC agents, not customer agents. **[V]**
- Console: inside the Falcon console under "AI detection and response": Collectors, Policies, Findings, Visibility (data flows and dashboards), Settings. Roles AIDR Admin and AIDR Viewer. **[V]**
- Next-Gen SIEM: repo `aidr`, event `AIDRPromptDataEvent`; metadata-only repo `aidr_events_metadata`; dashboard template maps findings to MITRE ATLAS. Guardian data is first-party and not billed as ingest. **[V]** [docs](https://aidr-docs.crowdstrike.com/docs/aidr/visibility/next-gen-siem)

### 9. Packaging, price, prerequisites

- No public Guardian price. Pricing page lists Falcon Go $59.99, Pro $99.99, Enterprise $184.99 per device per year; Guardian is not in any bundle; Falcon Flex is the expected vehicle. **[V]** [pricing](https://www.crowdstrike.com/en-us/pricing/)
- AIDR subscriptions were "AIDR for Workforce" and "AIDR for Agents". Hooks, browser, gateway, MCP proxy and SDK collectors work without the sensor; discovery, Agent Graph and network inspection need it. **[V]**
- OverWatch for Guardian requires OverWatch Cross-Domain plus Guardian; Falcon Complete for Guardian is a separate service. **[V]**

### 10. Related products and acquisitions

| Item | Date | Role | Status |
|---|---|---|---|
| Pangea | 16 Sep 2025 | AI Guard engine, collectors, taxonomy | [V] |
| SGNL | 8 Jan 2026 | CAEP-driven runtime access enforcement for Continuous Identity | [V] [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-sgnl-to-transform-identity-security-for-ai-era/) |
| Seraphic | 13 Jan 2026 | In-session browser security in any browser; now Falcon Seraphic Enterprise Browser with an API at `/seraphic-enterprise-browser/*` | [V] [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-seraphic-security/) |
| Onum | Aug 2025 | Real-time telemetry pipeline for Next-Gen SIEM | [P] |
| Agentic Identity Provider | 2 Sep 2026 | Registers discovered agents, verifiable identity, brokered short-lived access | [V] announced; controls "will authorize" |
| Charlotte AI AgentWorks | 2026 | Agent builder; API at `/agentic-studio/*` | [V] API exists |
| Falcon Shield | ongoing | SaaS posture with AI agent inventory (`/saas-security/entities/ai-agents/v3`) | [V] |
| Fiddler, Dreadnode | 3 Nov 2026 | Agent observability; automated AI red teaming | [V] announced, not closed |

### 11. The Falcon integration surface

All paths below are from the FalconPy v1.6.6 endpoint definitions (28 Sep 2026) unless noted. **[V]** [FalconPy](https://github.com/CrowdStrike/falconpy)

Data in:

| Path | How | Notes |
|---|---|---|
| Next-Gen SIEM HEC | Create a data connector, get an ingest URL `https://<id>.ingest.<cloud>.crowdstrike.com` (`/services/collector`) and token; JSON or raw; one parser per connector | FalconPy ships an `HEC` class; ingest hosts exist for us-1, us-2, us-3, eu-1 and two gov clouds; third-party ingest is licensed by payload size ([Cribl docs](https://docs.cribl.io/stream/destinations-crowdstrike-next-gen-siem/)) |
| Falcon LogScale Collector | `type: hec` sink with the same URL and token | Fleet-managed shipper |
| Foundry LogScale ingest | `POST /loggingapi/entities/data-ingestion/ingest/v1` (and `ingest-async`) | Each Foundry app gets its own repository |
| Guardian as a collector target | `POST /aidr/aiguard/v1/guard_chat_completions` with a collector token; custom event types on Application collectors; OTLP logs endpoint | Makes our events first-party Guardian data, but needs the customer's Guardian subscription |
| IOC Management | `POST /iocs/entities/indicators/v1` | Sensor enforces detect or prevent on hashes, domains, IPs |
| Custom IOA | `POST /ioarules/entities/rules/v1`, rule groups per `windows`, `mac`, `linux` | Behavioural rules attached to prevention policies |
| Correlation rules | `/correlation-rules/entities/rules/v1`, import and export | Turns ingested third-party events into Falcon detections; the Alerts API has no create operation |
| Lookup files, parsers, dashboards | `/ngsiem-content/*`, `/humio/api/v1/repositories/{repo}/files` | Ship content as code |

Data out and actions:

| Path | How | Notes |
|---|---|---|
| Guardian read API | `/aidr/{queries,entities,aggregates}/*`, scope AIDR: READ | limit 500, offset cap 1000 |
| Next-Gen SIEM search | `POST /humio/api/v1/repositories/{repo}/queryjobs` | CQL over `aidr` and sensor repos |
| Event Streams | `GET /sensors/entities/datafeed/v2?appId=`, then `dataFeedURL` + `sessionToken`, refresh via `datafeed-actions` | Scope Event streams: READ ([docs](https://developer.crowdstrike.com/api-reference/collections/event-streams/)) |
| Falcon Data Replicator | S3 and SQS feed of raw sensor events; schema API at `/fdr/*` | Guardian prompt activity added Nov 2026 |
| Real Time Response | Sessions, batch commands, custom scripts, put-files | Can kill processes, pull files, and deploy our own components; RTR is not allowed in certified store apps |
| Fusion SOAR | `POST /workflows/entities/execute/v1`, definition import and export, human-input API | Triggers: on demand, scheduled, event-based; no built-in retry |
| Policies, host groups, containment | Prevention, response, firewall policy APIs; containment allowlist rules | |
| Falcon Foundry | CLI-built apps: API integrations, collections, Python or Go functions, workflows, UI extensions and pages, AI agents, knowledge bases | `foundry-skills` v1.7.0 lets coding agents build these; up to 25 instances per workflow template |
| Falcon MCP server | MIT, v0.20.2 (3 Nov 2026), 30 modules including Guardian, NGSIEM, RTR, Custom IOA, IOC, Fusion, Shield, AgentWorks | [repo](https://github.com/CrowdStrike/falcon-mcp) |

## Matrix

Capability map (status as of 9 Nov 2026):

| Capability | Mechanism | Platforms | Enforce? | Status |
|---|---|---|---|---|
| Agent discovery and inventory | Sensor process tags, install records | Windows, macOS | Allow or block agent type | GA |
| Runtime visibility, Agent Graph | Sensor events joined by AID, PID, session ID | Windows, macOS | n/a | GA |
| Agent hooks | Vendor hook APIs calling cloud API | Any OS the agent runs on | Block, redact tool I/O | Available; several default fail-open |
| Browser extension | Sensor-managed or standalone | Chrome, Edge (Firefox standalone) | Input block and redact; output report-only | GA |
| Endpoint network inspection | Sensor | Windows | No | GA or pre-beta (conflicting); macOS early access |
| AI Gateway | Central proxy | Any | Yes | GA 3 Nov 2026 |
| Kill Switch | Gateway model and provider block | Gateway-routed traffic | Yes | GA; endpoint and by agent type coming |
| MCP proxy | stdio wrapper | Node hosts | Block, redact | Available |
| Linux, K8s, cloud agents | Linux sensor, DaemonSet | Linux | Detect only planned | Pre-beta |
| Claude Cowork VM | Linux sensor inside VM | macOS beta, Windows later Nov | Visibility and detection only | Beta |
| Behavioural baselines | Next-Gen SIEM | n/a | n/a | Q4 |
| Agent identity | Agentic IdP, Continuous Identity | n/a | "will authorize" | Announced |

## Weak points, gaps and risks

1. **Cloud-dependent enforcement.** Every hook decision needs `api.crowdstrike.com`. Offline, proxied, or slow means either a 30-second stall or, on Codex and Copilot defaults, silent allow.
2. **Self-defeating secret placement.** The collector token is an environment variable in the agent's own process environment. A compromised agent can read it, forge clean events, or flood the tenant.
3. **Soft hooks.** Three events only. No coverage of model responses, subagents, system prompts or MCP calls made outside the hook path. Prompt redaction is impossible on Claude Code and Codex. No documented integrity monitoring of hook configuration.
4. **Network inspection is observation.** Windows only, allowlisted applications, 1 MiB cap, no attachments, no blocking. Bespoke agents and unlisted tools such as Cursor are invisible at this layer.
5. **Kill Switch reach.** It only affects agents whose model traffic transits a connected gateway. Direct-to-provider and local-model agents are untouched until endpoint enforcement ships.
6. **Attribution stops at the host.** The API states no entity can be scoped to a single agent, sessions are fleet-wide, and hosts run up to 13 agents. Agent versus human attribution on shared credentials rests on process tags.
7. **Two products stitched together.** Pangea events (`AIDRPromptDataEvent`) and sensor events (`Agentic*`) use different stores, retention and product encodings (numeric tag IDs versus names, string versus int). Tool names are case-inconsistent between stores.
8. **Bespoke agents.** Discovery is tag-driven with a `GENERIC` bucket; in-house agent support on LangChain and LangGraph is pre-beta and Linux-only.
9. **No self-hosting, limited regions.** Three commercial clouds, no gov cloud for AIDR, prompts and tool I/O leave the customer boundary.
10. **Supply-chain shape of their own collectors.** `npx -y` fetches the MCP proxy at run time; collector repos are a few weeks old at version 0.0.0.
11. **Marketing ahead of docs.** Three public statements conflict on network inspection status, hook coverage (five versus six agents) and what the Kill Switch does today.

## Implications for our design

1. **Evaluate policy locally.** Ship a local decision engine in the hook binary and endpoint daemon, with signed policy bundles and an offline cache. Target single-digit milliseconds for deterministic rules; call remote models only for semantic detectors and with an explicit budget.
2. **Fail-closed by policy class, not globally.** Let policy say which rule classes block on no-verdict (secrets, destructive commands) and which degrade to allow-and-log.
3. **Keep credentials out of the agent's reach.** The hook should talk to a local daemon over a peer-credential-checked socket or named pipe; the daemon holds device-bound keys. Never place tenant tokens in agent-visible environment variables.
4. **Treat hook configuration as a protected asset.** Install through managed settings where vendors offer them, watch hook files with the OS sensor, auto-repair, and raise a tamper detection. Make "hooks removed while agent running" a first-class detection.
5. **Copy the join key, then go further.** Emit device ID, PID, process start time, session ID and tool-use ID from the hook so OS events correlate deterministically. Add per-agent and per-session identity so tools, skills, MCP servers and models are attributable to one agent instance, which Guardian's API cannot do.
6. **Adopt the same wire shapes.** Use OpenAI chat-completions-shaped guard input, the five event types, and OTel `gen_ai.*`. That makes us a drop-in for the gateway and SDK ecosystems they already seeded, and lets one adapter forward our events into Guardian.
7. **Build a "CrowdStrike enhancer" package:**
   - A Next-Gen SIEM HEC exporter with our parser, dashboards and correlation rules delivered as code via the `ngsiem-content` and `correlation-rules` APIs.
   - A Foundry app: API integration to our control plane, UI extension on detection and host pages, and Fusion SOAR actions (quarantine agent, revoke session, disable MCP server, kill switch).
   - Readers for `/aidr/*` and Event Streams so our graph ingests Guardian inventory and Falcon detections, keyed on AID.
   - Response through Falcon: RTR scripts to kill agent process trees or restore hook config, IOC pushes for malicious skill and MCP server hashes and domains, Custom IOA rules for agent-specific behaviours, host containment as last resort.
   - Optional deployment of our hook and daemon via RTR put-and-run for customers without MDM.
8. **Keep the Foundry app free of RTR** if we want store certification; put RTR paths in the API-side integration instead.
9. **Cover what they defer.** Linux, Kubernetes and in-house agents at launch; real enforcement on network egress per agent process; endpoint-level kill switch by agent instance.
10. **Expose an embeddable engine.** A library plus local API that an EDR vendor can host inside its own sensor and console is something a Falcon-only product cannot offer.

## Ideas worth stealing and whitespace

Worth stealing:

- Inspection-rule routing in front of access rules and detectors, with `executes` and `has` operators so ABAC can conditionally run detectors.
- "Ignore and Stop" (allow without logging) for privacy carve-outs, and a metadata-only log repository.
- Report Only Mode per route that shows would-have-blocked outcomes.
- Format-preserving encryption with a returnable context so agents keep working on realistic values.
- MCP tool-listing validation: description injection, name collisions, near-duplicate descriptions.
- Unicode obfuscation detector (invisible characters, mixed scripts, stacked modifiers).
- Skill directory hashing and install records with declaration path, binary path and SHA-256.
- A public efficacy lab tool for detectors, and an MCP server over the product's own data.
- Running a Linux sensor inside the agent's sandbox VM by vendor arrangement.

Whitespace:

- Offline-capable, local, low-latency enforcement.
- Per-agent-instance attribution and identity across shared human credentials.
- Tamper-evident hooks and agent-inaccessible credentials.
- Enforcing network inspection, on macOS and Linux as well as Windows.
- Endpoint kill switch scoped to one agent, one session or one MCP server.
- Self-hosted and MSP multi-tenant deployment, and an embeddable SDK for other EDRs.
- Coverage of subagents, model responses and agent-to-agent delegation.
- A vendor-neutral open event schema for agent sessions, which nobody has published.

## Could not verify / open questions

- How endpoint network inspection obtains plaintext (local TLS interception versus in-process capture), and whether it handles pinned or bundled TLS stacks.
- Whether the sensor itself installs or integrity-checks agent hooks, and how the Cursor and Microsoft 365 Copilot hooks work (no public collector).
- How the sensor derives `AgenticToolRequest` and `AgenticUserPromptSubmit` events when no hook is installed (transcript parsing versus hooks).
- Falcon AI Gateway internals, supported providers, deployment model, and how third-party gateways receive Kill Switch commands.
- SafeMind model sizes, latency and published efficacy numbers.
- Guardian list price and Falcon Flex credit rates; the free Next-Gen SIEM third-party ingest allowance (commonly cited as 10 GB per day) was not re-verified.
- Onum, CrowdStream and Marketplace partner program terms were not re-verified this session.
- Custom IOA rule types and disposition IDs, Event Streams event type list and offset semantics (pages fetched did not include them).
- Falcon console documentation behind login; the Falcon browser extension page returned 403; the Guardian data sheet PDF and deeper taxonomy nodes were not read.

## Sources

- https://www.crowdstrike.com/en-us/platform/falcon-guardian-aidr/ : Falcon Guardian product page, read 2026-11-09
- https://www.crowdstrike.com/en-us/blog/falcon-guardian-defines-next-generation-of-ai-security/ : launch blog, 2026-09-01
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-guardian-ai-agent-security/ : launch PR, 2026-09-01
- https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-ai-security-and-safety-falcon-guardian/ : Fal.Con Europe blog, 2026-11-03
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-ai-security-safety-for-the-enterprise/ : PR, 2026-11-03
- https://www.crowdstrike.com/en-us/blog/crowdstrike-introduces-ai-kill-switch/ : Kill Switch blog, 2026-11-03
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-ai-kill-switch-for-ai-safety/ : Kill Switch PR, 2026-11-03
- https://www.crowdstrike.com/en-us/blog/crowdstrike-secures-ai-agents-inside-claude-cowork/ : Cowork blog, 2026-11-03
- https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-stops-agent-insider-threats/ : agentic SOC blog, 2026-11-04
- https://www.crowdstrike.com/en-us/blog/crowdstrike-announces-agentic-identity-provider/ : Agentic IdP blog, 2026-09-02
- https://www.crowdstrike.com/en-us/pricing/ : pricing page, read 2026-11-09
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-pangea-to-secure-every-layer-of-enterprise-ai/ : Pangea PR, 2025-09-16
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-sgnl-to-transform-identity-security-for-ai-era/ : SGNL PR, 2026-01-08
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-seraphic-security/ : Seraphic PR, 2026-01-13
- https://aidr-docs.crowdstrike.com/docs/aidr/collectors : collector overview, read 2026-11-09
- https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint : Falcon Endpoint collector, read 2026-11-09
- https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint/network-inspection : network inspection, read 2026-11-09
- https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint/deploy : deployment, read 2026-11-09
- https://aidr-docs.crowdstrike.com/docs/aidr/collectors/agentic/claude-code : Claude Code collector, read 2026-11-09
- https://aidr-docs.crowdstrike.com/docs/aidr/policies/inspection-rules : inspection rules, read 2026-11-09
- https://aidr-docs.crowdstrike.com/docs/aidr/visibility/next-gen-siem : Next-Gen SIEM integration, read 2026-11-09
- https://pangea.cloud/docs/aidr/apis : AIDR API reference (captured)
- https://pangea.cloud/docs/aidr/collectors/agentic : MCP proxy (captured)
- https://pangea.cloud/docs/aidr/policies/prompt-rules , /access-rules , /policies : policy docs (captured)
- https://pangea.cloud/docs/aidr/collectors/agentic/copilot-studio , /gateway/litellm , /otel : collectors (captured)
- https://github.com/CrowdStrike/falcon-guardian-codex-collector : source, updated 2026-10-28
- https://github.com/CrowdStrike/falcon-guardian-github-copilot-collector : source, updated 2026-10-28
- https://github.com/CrowdStrike/falcon-guardian-opencode-collector : source, updated 2026-11-03
- https://github.com/CrowdStrike/falcon-mcp : Falcon MCP server v0.20.2, 2026-11-03 (Guardian module and resources)
- https://developer.crowdstrike.com/falcon-mcp/modules/guardian/ and /modules/overview/ : module docs, read 2026-11-09
- https://github.com/CrowdStrike/falconpy : FalconPy v1.6.6, 2026-09-28 (endpoint definitions, HEC client)
- https://github.com/CrowdStrike/foundry-skills : Foundry skills v1.7.0, 2026-10-30
- https://github.com/CrowdStrike/foundry-sample-logscale : Foundry LogScale ingest sample
- https://github.com/CrowdStrike/logscale-community-content : Falcon LogScale Collector NG-SIEM config sample
- https://developer.crowdstrike.com/api-reference/collections/event-streams/ : Event Streams API, read 2026-11-09
- https://developer.crowdstrike.com/api-reference/collections/custom-ioa/ : Custom IOA API, read 2026-11-09
- https://docs.cribl.io/stream/destinations-crowdstrike-next-gen-siem/ : third-party description of NG-SIEM ingest, read 2026-11-09

## Independent verification

_Checked 2026-11-09 by a second reviewer. Web search was unavailable (shared search budget exhausted), so every verdict rests on direct reads of source code through the GitHub API and direct fetches of vendor documentation. No claim was refuted; two need correction._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Codex and Copilot CLI collectors default to `--failure-mode open`, 30 s timeout, cloud call per UserPromptSubmit / PreToolUse / PostToolUse, no local policy | Confirmed | Both `main.rs` files set `default_value_t = FailureMode::Open` and `timeout = 30`; `run()` always calls `guard_chat_completions`. A missing `CS_AIDR_TOKEN` or malformed stdin also fails open (warning, exit 0). | [codex main.rs](https://github.com/CrowdStrike/falcon-guardian-codex-collector/blob/main/src/main.rs), [copilot main.rs](https://github.com/CrowdStrike/falcon-guardian-github-copilot-collector/blob/main/src/main.rs) |
| 2 | Static bearer token in `CS_AIDR_TOKEN`; correlation by sensor AID (registry or `falconctl`), process ID and numeric process tag | Confirmed | AID from `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim` value `AG` or `falconctl info`; `None` on Linux. Tags: Codex `213584428666200`, Copilot `213584428666189`. The PID sent is the hook process's own PID, not the agent's. | [codex main.rs](https://github.com/CrowdStrike/falcon-guardian-codex-collector/blob/main/src/main.rs), [guardian.rs](https://github.com/CrowdStrike/falcon-guardian-codex-collector/blob/main/src/guardian.rs) |
| 3 | Network inspection: Windows only, sensor 7.40+, responses from 8.10, report-only, 1 MiB cap, no attachments, app allowlist, needs AIDR for Workforce plus Insight XDR | Confirmed | All points are in the docs page. Status is contradictory elsewhere: the 3 Nov press release says GA on Windows with Mac in early access, the 3 Nov blog labels it pre-beta. | [docs](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint/network-inspection), [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-ai-security-safety-for-the-enterprise/) |
| 4 | Claude Code collector is a native HTTP hook to `/aidr/aiguard/v1/claude_code_guard`; no LLM responses, system prompts, subagent context or token usage; no prompt redaction; managed settings is the only anti-disable control | Confirmed, with additions | The published config has no `onFailure` or `timeout` key. Claude Code treats HTTP hook non-2xx, connection failure and timeout as non-blocking unless `onFailure: "block"` is set (v2.1.295+), so this collector is fail-open in practice. The subagent gap is the collector's, not the platform's: Claude Code hook input carries `agent_id` and `agent_type`, and `SubagentStart`/`SubagentStop` events exist. | [docs](https://aidr-docs.crowdstrike.com/docs/aidr/collectors/agentic/claude-code), [Claude Code hooks](https://code.claude.com/docs/en/hooks) |
| 5 | Kill Switch works today only through connected AI gateways (Falcon or third-party) blocking model and provider access; endpoint, agent-type, identity, SaaS, browser are coming soon | Confirmed | Blog: gateway enforcement now, endpoint/cloud/identity/SaaS/browser "coming soon". Product page: "models and providers", and gateway enforcement "by agent type" coming soon. The press release lists relaunch blocking and network cut-off with no "soon" qualifier; treat that as marketing ahead of the blog. | [blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-introduces-ai-kill-switch/), [product page](https://www.crowdstrike.com/en-us/platform/falcon-guardian-aidr/), [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-ai-kill-switch-for-ai-safety/) |
| 6 | Guardian API is read-only, cannot scope tools, skills, models, MCP servers or sessions to one agent; host is the finest grain; 90-day entity and 7-day event lookback | Corrected | Read-only and lookbacks hold: FalconPy's `Aidr` collection has 33 operations, all GET, "Max 90d", limit 1-500, offset 0-1000. But host is the finest grain only for the entity store. The Agentic Graph is session-grained (`aisess:{aid}:{session_uuid}`) and links tools, models, MCP servers, skills, processes and child sub-agent sessions to one session. What is missing is the session-to-AIAgent edge (present but empty). Lookback limits are "observed" and "differ between deployments". | [FalconPy _aidr.py](https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_endpoint/_aidr.py), [falcon-mcp resources](https://github.com/CrowdStrike/falcon-mcp/blob/main/falcon_mcp/resources/guardian.py) |
| 7 | AIDR end of support 30 Nov 2026, continues as Falcon Guardian; AIDR only in US-1, US-2, EU-1 | Confirmed | Banner and region list are both on the AIDR docs root page, with base URLs for the three clouds. The region statement is about AIDR; no separate Guardian region list was found. | [docs root](https://aidr-docs.crowdstrike.com/docs/aidr) |
| 8 | Linux (Claude Code, Codex), Kubernetes DaemonSet, LangChain/LangGraph, Bedrock AgentCore are pre-beta; behavioural baselining and agent insider threat detection are Q4 2026 in Next-Gen SIEM | Corrected | Pre-beta labels confirmed. For insider threat detection the 3 Nov blog says "Pre-beta" and the 4 Nov blog says "(Q4)" with no year. CrowdStrike's fiscal Q4 runs November to January, so do not plan on a calendar-2026 date. | [3 Nov blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-ai-security-and-safety-falcon-guardian/), [4 Nov blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-stops-agent-insider-threats/) |
| 9 | Third-party ingest via HEC connectors (`<key>.ingest.<cloud>.crowdstrike.com`, token, JSON or raw, parser per connector) and Foundry LogScale ingest; rules, parsers, dashboards manageable by API | Confirmed | URL built as `https://{url_key}.{ingest base}/services/collector` (`/raw` for raw); formats json, yaml, xml, csv. Hosts: us-1, us-2, us-3, eu-1, `ingest.laggar.gcw.crowdstrike.com`, and `ingest.us-gov-2.crowdstrike.mil` (not `.com`). Data connections and their tokens are also API-manageable (`/ngsiem/entities/connections/v1`, `.../connections/token/v1`), which the brief did not list. | [_hec.py](https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_ngsiem/_hec.py), [_ingest_base_url.py](https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_enum/_ingest_base_url.py), [_ngsiem.py](https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_endpoint/_ngsiem.py) |
| 10 | Response via RTR (sessions, batch commands, scripts, put-files), IOC Management, Custom IOA for windows/mac/linux, Fusion SOAR execute; RTR scripts not allowed in certified Foundry apps | Confirmed | All routes present in FalconPy. The Foundry restriction is on the RTR-script artifact type ("All Foundry artifact types are supported except RTR scripts"; "RTR workflows work in custom/internal apps only"). | [_real_time_response_admin.py](https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_endpoint/_real_time_response_admin.py), [custom_ioa.py](https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/custom_ioa.py), [publishing-certified-apps.md](https://github.com/CrowdStrike/foundry-skills/blob/main/use-cases/publishing-certified-apps.md) |

Further statements in this brief that were checked:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Section 2 table: Claude Code failure default "Not documented"; TL;DR: "Default timeout 30 s" for all hooks | Corrected | Undocumented by CrowdStrike, but determined by Claude Code: HTTP hook failures are non-blocking by default, so fail-open. Claude Code's default hook timeout is 600 s (30 s on `UserPromptSubmit`); the 30 s figure applies to the Codex, Copilot and OpenCode collectors only. | [Claude Code hooks](https://code.claude.com/docs/en/hooks) |
| Whitespace: "A vendor-neutral open event schema for agent sessions, which nobody has published" | Overstated | OpenTelemetry GenAI semantic conventions define `create_agent` and `invoke_agent` spans, `gen_ai.agent.id`, `gen_ai.conversation.id` and MCP conventions. Status is Development and they are telemetry-oriented, not a security event schema, but they exist and the brief itself recommends `gen_ai.*`. | [gen-ai-agent-spans.md](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md) |
| Weak point 6 and whitespace: "Attribution stops at the host"; "Coverage of subagents" is open | Overstated | See claim 6. Guardian's graph already returns per-session tools, models, MCP servers, skills, process tree, file and network events, and a `ChildSessionAisess` edge for sub-agent sessions (often null). The real gap is binding a session to a stable agent identity, and hook-level subagent coverage. | [falcon-mcp resources](https://github.com/CrowdStrike/falcon-mcp/blob/main/falcon_mcp/resources/guardian.py) |

Minor: falcon-mcp's README lists 28 modules at v0.20.2, not 30. FalconPy v1.6.6 does ship an `Aidr` service collection (added 16 Sep 2026), so the falcon-mcp docstring saying FalconPy has none is stale.
