# Microsoft Agent 365 and the Microsoft agent governance stack: teardown and integration plan

_Researched 2026-11-09_

Method note: almost everything below was read from Microsoft Learn pages (ms.date shown), GitHub Docs and repositories. The shared web-search budget ran out midway, so Edge and parts of GitHub Copilot were covered by direct document fetches only; gaps are listed at the end. "Verified" means read in a primary source; "inferred" is marked.

## TL;DR

- **Agent 365 is GA (1 May 2026), per user, USD 15/user/month standalone or inside Microsoft 365 E7.** It is a licence and a control-plane UI over Entra Agent ID, Defender, Purview and Intune, not a separate enforcement engine. From 1 July 2026 Copilot Studio and Foundry agent security in Defender *requires* it.
- **Endpoint discovery is already broad and GA**: Defender for Endpoint inventories 60+ local agents (Claude Code, Cursor, Codex CLI/Desktop, Copilot CLI, Windsurf, OpenClaw, Gemini CLI, Goose, Ollama) plus their MCP server configs on **Windows and macOS**. Native Linux is not covered (WSL preview for three agents only).
- **Endpoint enforcement is narrow and preview**: runtime protection is Windows-only, detects prompt injection only, and uses the vendors' own hook interfaces (Claude Code hooks, Copilot hooks) for six agent surfaces, with TLS network inspection for four more. Cursor, Codex, Windsurf have no runtime protection. Blocking in Agent 365 "Local agents" works for 7 of 23 listed tools, via Intune and VS Code extension policy.
- **Discovery is signature-based** ("only supported combinations appear"). Bespoke in-house agents are visible only if they adopt the Agent 365 SDK/OTel, get an Entra agent identity, or run on a synced platform.
- **Agent-vs-human attribution on endpoints is not shipped.** Defender defines a local agent as user x device x agent type; Entra separation of agent from user activity on Windows is "coming soon" with MXC.
- **Real extension points exist**: OTLP ingest into Agent 365, Graph package/registry API, Entra Agent ID Graph API, Defender advanced hunting tables (`AgentsInfo`, `CloudAppEvents`, `BehaviorInfo`), the Copilot Studio external threat-detection webhook, Purview `processContent`, Agent 365 Tools Gateway (Azure API Management and **LiteLLM**), BYO MCP registration.
- **The Copilot Studio webhook is fail-open by default**: 1,000 ms budget, then allow. Per-environment config, no tenant-wide API.
- **Registry sync to other clouds is manual and key-based**: Bedrock, Vertex AI, Agentforce, Databricks Genie, Claude Managed Agents, Oracle, Snowflake Cortex. No schedule, no keyless auth, read-only.
- **Microsoft's open source is reusable**: Agent Governance Toolkit (MIT), `agent-hooks` (eight interception points, three verdicts), `agent-control-spec` (Rust policy runtime), and **MXC** (MIT, Rust, cross-platform sandbox, GA 7 Oct 2026).
- **Everything meaningful needs E5 + Agent 365 or E7, commercial cloud, Windows Enterprise/Education.** Much of the interesting surface is Frontier preview with no SLA.

## Findings

### 1. Agent 365 core

**Status and licence.** GA for Commercial on 1 May 2026, per user ([overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview), ms.date 2026-08-19). USD 15/user/month standalone or in E7; a licence covers a person who manages, sponsors or uses agents ([GA blog](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/), 2026-05-01). Add-on to E5/A5/Business Premium ([Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)). Trial: 25 seats, 30 days. FedRAMP High controls assessed 1 Oct 2026, authorisation pending ([service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-agent-365/microsoft-agent-365), 2026-09-30).

**What is free versus paid** (service description): registry inventory, basic actions (publish, block, delete, reassign owner), rules-based lifecycle and external-platform sync are in ordinary Microsoft 365 plans. Policy templates, observability, tenant-wide tool control, Graph API access, Entra CA/ID Protection/access packages for agents, all Purview-for-agents features, all Defender agent features and Intune "block unsanctioned local endpoint agents" need E7 or Agent 365.

**Registry.** Microsoft 365 admin center > Agents > All agents > Registry. Four publisher types; counters for ownerless and "unmanaged" agents; a Risks column aggregating Purview, Entra and Defender signals with up to one hour lag ([registry](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview), 2026-09-21). The Entra Agent Registry was folded into Agent 365; Entra keeps identity ([convergence](https://learn.microsoft.com/en-us/entra/agent-id/agent-registry-convergence), 2026-04-05).

**Graph API.** `GET /copilot/admin/catalog/packages`, `GET .../packages/{id}`; preview `PATCH`, `POST .../block`, `.../unblock`, `.../reassign`. Scope `CopilotPackages.Read.All`; AI Administrator or Global Administrator; requires an Agent 365 licence; not in GCC ([package API](https://learn.microsoft.com/en-us/microsoft-365-copilot/extensibility/api/admin-settings/package/overview), 2026-08-27). It covers catalog packages (Copilot, Teams, Outlook hosts); nothing indicates local agents are exposed here.

**Connected platforms (registry sync, preview).** Amazon Bedrock (Agents Classic, AgentCore), Google Vertex AI, Salesforce Agentforce, Databricks Genie, Anthropic Claude Managed Agents, Oracle Generative AI Agents, Snowflake Cortex. Read-only; manual sync only; deletion reconciliation not guaranteed; key-based credentials only (no federation or role assumption); calls originate from five fixed IPs; observability is read from the platform's own telemetry sink (S3, BigQuery) and is Frontier preview ([connected platforms](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms), 2026-11-05).

**Local agents and Shadow AI (Frontier preview).** Local agents lists 23 developer tools; detection for all, blocking only for Gemini CLI and six VS Code extensions (Claude Code, Cline, Codex, Gemini Code Assist, Copilot, Roo Code). Claude Code CLI, Codex CLI, Cursor, Windsurf, Kiro, Warp: detect only. Blocking generates an Intune policy ("A365 - Block OpenClaw", 15 min to 8 h to apply) or a VS Code allowed-extensions policy; Node.js agents share one run type, so blocking one blocks OpenClaw, QClaw, Nanobot and Gemini CLI together. Usage metadata (users, FQDNs, bytes) appears only with Global Secure Access. Blocking applies only to Intune-managed Windows ([local agents](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-local), 2026-09-04; [shadow AI](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-shadow-ai), 2026-08-25).

**SDK and observability.** The Agent 365 SDK (Python, JavaScript, .NET; MIT at `microsoft/Agent365-python|nodejs|dotnet`) adds identity, governed tooling and notifications to an agent you already run. It does not build, host or orchestrate. Observability moved to the **Microsoft OpenTelemetry Distro**; the Agent 365 Observability SDK is deprecated ([SDK overview](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/agent-365-sdk), 2026-11-05). Notifications and agents with their own user account/mailbox are Frontier only.

**Direct OTLP ingest** ([direct OTel](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/direct-open-telemetry-integration), 2026-10-01):
- `POST https://agent365.svc.cloud.microsoft/observabilityService/tenants/{tenantId}/otlp/agents/{agentId}/traces?api-version=1` (S2S); `/observability/...` for on-behalf-of. OTLP/HTTP+JSON.
- Token audience `9b975845-388f-4429-889e-eab1ef63949c`; permission `Agent365.Observability.OtelWrite`. A standard Entra app registration works; a blueprint is not mandatory.
- Every span needs `gen_ai.operation.name` in {`invoke_agent`, `chat`, `execute_tool`, `output_messages`}; others are dropped. `gen_ai.conversation.id`, `microsoft.channel.name`, `microsoft.session.id` must be set on every span. Agent-to-agent uses `gen_ai.execution.type=Agent2Agent` and `microsoft.a365.caller.agent.*`.
- `200 OK` does not mean ingested: inspect `partialSuccess` and per-span `results`. Unlicensed tenants get 200 with all spans rejected. Eligibility probe: `GET .../observabilityService/tenants/{tenantId}/eligibility?api-version=1`.
- Data lands in Defender advanced hunting `CloudAppEvents` and drives near-real-time detections ([detect](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection), 2026-08-07).

**Tooling and MCP.** Work IQ MCP is GA: one endpoint, 10 generic tools over Microsoft 365 data ([MCP options](https://learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview), 2026-10-08). BYO MCP (preview) routes a remote server through the Agent 365 Tooling Gateway: register with `a365 develop-mcp register-external-mcp-server`, admin approves, Defender hunts on invocations. Requires a public endpoint; auth types include NoAuth, APIKey, ExternalOAuth; supported clients are Copilot Studio, VS Code, **Claude Code** and Copilot CLI; Foundry is not supported ([BYO MCP](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/manage-byo-mcp-server), 2026-11-05). Tools Gateway (preview) connects **Azure AI Gateway (API Management)** or **LiteLLM** by URL plus API key, imports their MCP servers, and "Agent 365 Guardrails" has Defender evaluate LiteLLM MCP tool calls; the APIM policy needs a delegated user token, app-only is unsupported ([Tools Gateway](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/manage-tools-gateway), 2026-11-05).

### 2. Entra Agent ID

GA ([what's new](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id), 2026-05-01); admin-center creation wizards still preview. Free for all Entra customers; Conditional Access, ID Protection and governance for agents need E7, or Agent 365 plus Entra P1/M365 E3 ([CA for agents](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id), 2026-07-31).

- **Constructs** ([key concepts](https://learn.microsoft.com/en-us/entra/agent-id/key-concepts), 2026-04-03): *blueprint* (template that holds the credentials), *blueprint principal*, *agent identity* (no credentials of its own; tokens are issued via the blueprint), *agent's user account* (for agents that need a mailbox or Teams presence). Owners (technical), sponsors (business accountability, mandatory), managers.
- **API**: `POST https://graph.microsoft.com/beta/serviceprincipals/Microsoft.Graph.AgentIdentity` with `agentIdentityBlueprintId` and `sponsors@odata.bind`; still `/beta` ([create](https://learn.microsoft.com/en-us/entra/agent-id/create-delete-agent-identities)).
- **Conditional Access** evaluates at token issuance or refresh, plus CAE where supported. Three separately targeted patterns: delegated (user subject, agent as client), autonomous (agent identity subject), agent user.
- **Logs**: audit entries carry `agentType` (`agenticApp` = blueprint, `agenticAppInstance` = agent identity, plus the agent-user type) on `initiatedBy`, `performedBy`, `targetResources` ([logs](https://learn.microsoft.com/en-us/entra/agent-id/sign-in-audit-logs-agents)).
- **Non-Microsoft agents**: Entra ID Auth SDK sidecar container, or workload identity federation; guides for Bedrock and n8n ([third-party](https://learn.microsoft.com/en-us/entra/agent-id/configure-third-party-agents), 2026-04-29).
- **Network**: Global Secure Access "Secure Web and AI Gateway" forwards Copilot Studio agent traffic (HTTP node, custom connectors, MCP connector) per Power Platform environment for web, threat-intel and file filtering ([GSA](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-secure-web-ai-gateway-agents)). The GA blog extends this to agents on user endpoints, including OpenClaw.

Limit: all of this gates access to *Entra-protected resources at token time*. It says nothing about a local `rm -rf`, a non-Entra API key in `.env`, or an AWS call.

### 3. Defender

**Cloud agents.** Enabled automatically on Agent 365 onboarding ([get started](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai), 2026-10-30). Real-time protection ([RTP](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection), 2026-07-01): a default audit rule plus custom block rules scoped to agents, four detection types (malicious content propagation, secret exfiltration, evasion techniques, unsafe email domain). Coverage: Agent 365 tool invocations through Work IQ MCP and onboarded customer MCP tools; Copilot Studio (preview); Foundry (preview, all four intervention points). Only agents with an Entra agent ID can be scoped. Audit and block events become rows in `BehaviorInfo`. Licence move on 1 July 2026: [transition](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/transition-agent-security-to-agent-365).

**Copilot Studio external threat detection webhook (preview)** ([admin](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider), 2026-06-01; [developer](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers)):
- Provider exposes `POST {base}/validate?api-version=2025-05-01` and `POST {base}/analyze-tool-execution?api-version=2025-05-01`.
- Request carries `plannerContext` (user message, model `thought`, chat history, previous tool outputs), `toolDefinition`, `inputValues`, `conversationMetadata` (agent, user, tenant, environment, trigger, plan step). Response: `blockAction` (bool), optional `reasonCode`, `reason`, `diagnostics`.
- Auth: Entra app with a federated identity credential; the provider validates the bearer token and allow-lists customer app IDs.
- **Under 1,000 ms or the agent proceeds as allow**; admin can flip "Set error behavior" to block. Generative orchestration only. Configured per environment in Power Platform admin center; no API or tenant-wide switch.
- Explicitly "bring your own protection": Defender is one provider, third parties are invited.

**Endpoint discovery (GA on Windows and macOS)** ([overview](https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview), [how-to](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents), [matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix), all 2026-11-02): process observation plus periodic VS Code extension inventory; MCP config discovery (remote endpoints, local start commands) for roughly half the list. Needs MDE P2, Defender AV active mode with real-time protection, Windows platform `4.18.26090.9`+ or macOS `101.26072.0017`+, commercial cloud. Risk levels need E7/Agent 365. Hunting: `AgentsInfo | where Platform == "LocalAgents"`, with `RawAgentInfo.localAgentMetadata` holding `vendor`, `relatedProcess`, `trustedProcess`, `autoApprove`, `localMcps`, account SID; `ExposureGraphNodes/Edges` give `runs on`, `uses` (mcp/server), `used by` edges.

**Endpoint runtime protection (preview, Windows only)** ([overview](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview), 2026-10-08; [config](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection)): 
- *Agent-native event inspection* through vendor hooks: Claude Code, Claude Desktop (Code mode), VS Code Claude Code extension, Copilot CLI, Copilot app, VS Code Copilot extension.
- *Network inspection* of agent-to-LLM flows: OpenClaw, Ollama Desktop, ChatGPT Classic, ChatGPT Desktop. Not for certificate pinning or HTTP/3.
- `Set-MpPreference -AiAgentProtection <Block|Audit|Disabled>` and `-AiAgentNetworkInspection`; Intune profile "Microsoft Defender AI agent runtime protection"; tamper-protected. Alert: "Suspicious AI prompt injection". Preview requires Beta-channel platform updates.
- Scope is prompt injection. No customer-authored tool-call policy.

**Defender for Cloud.** Threat protection for AI services is GA for Azure OpenAI and Azure AI model inference, text tokens only ([doc](https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection), 2026-05-19). Agent-level discovery, posture and detection for Foundry moved under Agent 365.

**Export.** Event Streaming API: `CloudAppEvents` GA; `BehaviorInfo` not available; `AgentsInfo` not listed ([event types](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types)). Inventory and block verdicts therefore need polled hunting queries.

### 4. Purview

Supported for Agent 365: DSPM, audit, classification, sensitivity labels, DLP, Insider Risk, Communication Compliance, eDiscovery, lifecycle, Compliance Manager ([doc](https://learn.microsoft.com/en-us/purview/ai-agent-365), 2026-05-01). An *agent instance* is treated like a user: audit and classification are automatic; DLP and IRM require naming the instance or a group. Agent-created content does not inherit labels; the agent is unaware of a DLP block. For custom apps, Graph `userDataSecurityAndGovernance: processContent` lets an app submit prompts/responses for policy evaluation and audit ([developer](https://learn.microsoft.com/en-us/purview/developer/secure-ai-with-purview)). Endpoint DLP blocks paste to gen-AI sites in browsers on onboarded Windows devices only.

### 5. Intune and Windows

- Intune's role today: device-compliance signal for agent Conditional Access, the generated block policy, and distribution of the Defender runtime-protection profile ([Intune guidance](https://learn.microsoft.com/en-us/microsoft-agent-365/guidance/intune-agent-365), conceptual).
- **Windows On-device Agent Registry (ODR)**, pre-release: MCP servers registered via MSIX run *contained* in a separate Windows session under a separate agent user account; `.mcpb` bundles cannot be contained; `odr.exe` CLI ([MCP on Windows](https://learn.microsoft.com/en-us/windows/ai/mcp/overview), [containment](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment)).
- **WindowsAI Policy CSP**: `AgentConnectorAccessPolicy` (JSON allow-list of MCP server/host pairs), `ConfigureAgentConnectors`, `AgentConsentDuration` (default 720 h), `OnDeviceRegistryLoggingLevel`. Insider Preview only; Enterprise/Education/IoT, **not Pro** ([CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai), 2026-10-14). `SetDataLossPreventionProvider` lets an admin name a third-party DLP DLL, but for Recall only.
- **MXC (Microsoft Execution Containers)**: GA 7 Oct 2026, MIT, Rust, SDK v1.0.1 ([blog](https://blogs.windows.com/windowsdeveloper/2026/10/07/microsoft-execution-containers-policy-driven-containment-for-ai-agents/), [repo](https://github.com/microsoft/mxc)). One JSON policy (process, filesystem, network, UI) mapped to AppContainer (Windows), Seatbelt (macOS), Bubblewrap (Linux); session and WSL containers Windows-only; MicroVM experimental. Enforcement, learning and permissive modes; JSON activity report on Windows process containers only. Adopters: Copilot, Codex, OpenClaw; Claude Code "coming". Intune management, Entra agent-vs-user separation and Agent 365 control of MXC are all "soon". No ETW or security-vendor API is described.

### 6. Foundry Control Plane, GitHub Copilot, Security Copilot, Sentinel

- **Foundry Control Plane**: subscription-wide inventory, observability, guardrail policies and Defender/Purview alerts; advanced governance needs an AI gateway (API Management). Custom/external agents are fronted by an APIM proxy URL, so "block" means refusing inbound requests ([overview](https://learn.microsoft.com/en-us/azure/foundry/control-plane/overview), 2026-05-06; [custom agents](https://learn.microsoft.com/en-us/azure/foundry/control-plane/register-custom-agent), 2026-10-28).
- **GitHub Copilot**: `managed-settings.json` (GA) carries MCP allow/deny lists and tool-approval limits and cannot be overridden; the custom MCP registry is preview and bypassable by editing config ([MCP management](https://docs.github.com/en/copilot/concepts/mcp-management)). Machine-wide **policy hooks** load from `/etc/github-copilot/policy.d/*.json`, `C:\ProgramData\GitHub\Copilot\policy.d\*.json` or `HKLM\Software\Policies\GitHub\Copilot`; `preToolUse` returns `allow|deny|ask`; command hooks fail closed on error, HTTP hooks and all timeouts (30 s default) fail open; the cloud agent has no policy hooks ([hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)). Third-party coding agents are enabled per enterprise then per org ([enterprise management](https://docs.github.com/en/copilot/concepts/agents/enterprise-management)).
- **Security Copilot** is included for E5/E7 (rollout from 18 Nov 2025); agents consume SCUs ([inclusion](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion)).
- **Sentinel MCP server**: hosted, Entra-authenticated, tool collections for data exploration, entity analysis, triage/hunting and agent creation; needs Sentinel data lake onboarding and Security Reader ([overview](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview), 2026-05-07).

### 7. Agent Governance Toolkit (repository read)

`microsoft/agent-governance-toolkit`: MIT, created 2026-03-02, 6.5k stars, latest tagged release v4.1.0 (2026-06-09), active on 2026-11-09, still "Public Preview". Python core plus TypeScript, .NET, Rust, Go SDKs; ready-made plugins for **Claude Code, Codex CLI, Copilot CLI, OpenCode, Antigravity CLI** (the Claude Code plugin ships `pre-tool-use`, `user-prompt-submit`, `session-start` hooks). Policy in YAML, OPA Rego or Cedar; verdicts allow/deny/require_approval; MCP Security Gateway spec (tool poisoning, drift, typosquatting); LF-Projects-format charter.

The decision engine has been externalised: `responsibleai/agent-control-spec` (Rust, MIT, created 2026-07-17) built on `responsibleai/agent-hooks` (MIT, beta, spec 0.1): eight interception points (`agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, `output`, `agent_shutdown`), three verdicts (`allow`, `transform`, `deny` with liftable approval), default-deny on interceptor failure, conformance kit. It states plainly that it is in-process, not a sandbox, and not telemetry. AGT has no fleet discovery, console, tenancy or OS sensor.

## Matrix

| Capability | Microsoft today | Status | Third-party coding agents | macOS | Linux | Other clouds |
|---|---|---|---|---|---|---|
| Inventory of platform agents | Agent 365 registry | GA | n/a | n/a | n/a | Manual sync of 7 platforms (preview) |
| Endpoint agent discovery | MDE `AgentsInfo` | GA | 60+ incl. Claude Code, Cursor, Codex | Yes | No (WSL preview) | n/a |
| MCP config discovery | MDE | GA | About half the list | Yes | No | n/a |
| Endpoint runtime block | MDE hooks + network | Preview | Claude Code, Copilot only; prompt injection only | No | No | n/a |
| Block an agent binary | Intune / VS Code policy | Frontier | 7 of 23 | No | No | n/a |
| Pre-tool approval, cloud | Copilot Studio webhook; Work IQ MCP; Foundry | Preview / GA | n/a | n/a | n/a | No |
| Agent identity | Entra Agent ID | GA | Only if developer adopts | n/a | n/a | Sidecar or federation |
| Agent vs human on device | MXC + Entra | Coming soon | No | No | No | n/a |
| Sandbox | MXC | GA (OSS) | Copilot, Codex now | Process only | Process only | n/a |
| Telemetry ingest | OTLP to Agent 365 | GA | Any, if instrumented | Any | Any | Any |
| Data security | Purview | GA | Agent instances and M365 data only | Partial | No | `processContent` API |

## Weak points, gaps and risks

- **No native Linux, server or Kubernetes sensor coverage** for agents; no macOS enforcement; no blocking of Claude Code CLI, Codex CLI or Cursor.
- **Fixed catalogue.** A bespoke Python agent calling an LLM API from a server is invisible unless its developer instruments it.
- **Identity gap on endpoints.** Local agents inherit the user's token, SID and cloud credentials; nothing shipped distinguishes them.
- **Enforcement is content-classification only.** No deterministic customer policy over tool calls, paths, commands or egress on endpoints. MXC has that model but no central management yet.
- **Fail-open defaults**: Copilot Studio webhook (1 s then allow), Copilot HTTP hooks and all hook timeouts.
- **Observability honesty problem**: OTLP returns 200 while rejecting spans; strict operation-name vocabulary; token counts string-encoded.
- **Operational friction**: manual registry sync, long-lived keys for other clouds, per-environment webhook setup, Global Administrator needed to connect gateways, Intune policy latency up to 8 h, coarse Node.js blocking.
- **Licence and edition wall**: E5 + Agent 365 or E7; Windows Enterprise/Education; commercial cloud only; several Purview/Defender features absent in GCC.
- **Churn**: Observability SDK deprecated within a year, SDK 2.0 migration, `AIAgentsInfo` replaced by `AgentsInfo`, AGT v4 to v5 policy break, block rules silently stopped on 1 July 2026. Integrations need version pinning and contract tests.
- **Risk to us**: Microsoft can extend the Defender catalogue and hook coverage monthly. Durable differentiation is Linux/K8s/macOS enforcement, non-Microsoft identity and clouds, deterministic policy, self-hosting and no E7 dependency.

## Implications for our design

**Read from Microsoft**
1. Graph `/copilot/admin/catalog/packages` for platform-agent inventory (requires customer Agent 365 licence; degrade gracefully).
2. Entra Graph (beta) agent identities, blueprints, sponsors; audit and sign-in logs filtered by `agentType`.
3. Defender advanced hunting via Graph security API for `AgentsInfo`, `BehaviorInfo`, `ExposureGraph*` (poll); Event Streaming API to Event Hubs for `CloudAppEvents` and `Device*`.
4. Windows: `odr.exe` output, WindowsAI CSP state, MXC JSON activity reports.
5. Developer tools: Copilot `policy.d`, `managed-settings.json`, Claude Code managed settings, to detect coexisting controls such as Defender's hooks.

**Write to Microsoft**
1. An **OTLP exporter to Agent 365** using the four-operation vocabulary, so agents we discover on Linux, macOS, K8s or other clouds show up in Defender hunting and Purview. Always parse `results`; call the eligibility endpoint first.
2. A **Copilot Studio threat-detection provider**: implement `/validate` and `/analyze-tool-execution`, FIC-based token validation, p99 well under 1 s with regional deployment, and recommend "Block the query" on error.
3. Optional **Entra Agent ID provisioning** for agents we discover (blueprint plus sponsor), giving unregistered agents a governable identity.
4. **Purview `processContent`** as an optional DLP verdict source inside our gateway.
5. Our MCP gateway should be registrable as BYO MCP and should **mirror LiteLLM's management surface** closely enough to be connected under Tools Gateway (inferred feasibility; test it).

**Build and reuse**
- Implement the `agent-hooks` 0.1 contract as our in-agent interception ABI and accept `agent-control-spec` policies alongside our own; run its conformance kit. This gives day-one compatibility with AGT adapters and plugins.
- Use **MXC** (MIT, Rust) as the sandbox backend from our Rust endpoint agent instead of writing AppContainer, Seatbelt and Bubblewrap glue; add what it lacks: central policy distribution, cross-platform activity reports, signed audit.
- Multiplex vendor hooks: one hook entry point that chains our policy and tolerates Defender's hooks on the same agent.
- Copy the `AgentsInfo` shape (user x device x agent type, `autoApprove`, `trustedProcess`, `localMcps`, `McpServers`, `DeclaredTools`) for our inventory schema so KQL-literate SOCs can map it directly.
- Default **fail-closed with explicit, audited break-glass**, and publish latency budgets.

**Avoid**
- Depending on Frontier features or `/beta` Graph without feature flags.
- Requiring Agent 365 for our core value.

## Ideas worth stealing and whitespace

- **Steal**: "audit by default, block by scoped custom rule"; behaviours as queryable telemetry separate from alerts; sponsor (business owner) distinct from technical owner with lifecycle workflows; exposure-graph edges agent -> device -> identity -> reachable resources; MXC learning mode that emits a least-privilege policy; BYO MCP developer-registers/admin-approves flow; local `a365 develop-mcp evaluate` scoring tool schemas with the developer's own coding agent.
- **Whitespace**: Linux and Kubernetes agent discovery and enforcement; macOS enforcement; deterministic policy for Cursor, Codex and Windsurf; agent-vs-human attribution with shared credentials (process lineage plus hook session IDs plus token binding); keyless, scheduled multi-cloud registry sync; a fail-closed pre-tool decision service with offline cache; one policy across in-agent hooks, MCP gateway, LLM gateway and OS sandbox; self-hosted and MSP multi-tenancy; an embeddable sensor for non-Microsoft EDRs.

## Could not verify / open questions

- **Edge and Copilot agent-mode admin controls**: no primary document located (guessed URLs 404; release notes had no matches). Unknown.
- **Windows Agent Workspace** Learn page (404) and exact build/GA state of ODR and agent accounts; the CSP still says Insider Preview.
- **E7 price** (USD 99 from third-party sites only) and Agent 365 pricing for autonomous agents.
- Whether Graph package APIs are fully v1.0 (the example uses `/v1.0`, the page says preview for some operations).
- Runtime protection overview names Codex CLI as hook-capable, but the support matrix omits it.
- Whether `agent365.svc.cloud.microsoft` enforces rate or size limits (none documented beyond 429 on eligibility).
- Ownership of the `responsibleai` GitHub org (AGT calls it "upstream"; assumed Microsoft-affiliated).
- GitHub's agent control plane audit-log event names and session APIs; Defender AI-SPM specifics; Purview pay-as-you-go pricing for non-Microsoft AI interactions.
- Whether a non-LiteLLM gateway can be connected to Tools Gateway by imitating LiteLLM.

## Sources

- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Agent 365 overview (2026-08-19)
- https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-agent-365/microsoft-agent-365 — Service description (2026-09-30)
- https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/ — GA blog (2026-05-01)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview — Agent registry (2026-09-21)
- https://learn.microsoft.com/en-us/microsoft-365-copilot/extensibility/api/admin-settings/package/overview — Package Management API (2026-08-27)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms — Connected platforms (2026-11-05)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-local — Local agents (2026-09-04)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-shadow-ai — Shadow AI (2026-08-25)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/agent-365-sdk — SDK overview (2026-11-05)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/choose-integration-option — Integration options (2026-09-30)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/direct-open-telemetry-integration — Direct OTel (2026-10-01)
- https://learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview — MCP server options (2026-10-08)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/manage-tools-gateway — Tools Gateway (2026-11-05)
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/manage-byo-mcp-server — BYO MCP (2026-11-05)
- https://learn.microsoft.com/en-us/microsoft-agent-365/guidance/intune-agent-365 — Intune and Agent 365 (2026-07-30)
- https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id — Entra Agent ID (2026-04-14)
- https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id — What's new (2026-05-01)
- https://learn.microsoft.com/en-us/entra/agent-id/key-concepts — Key concepts (2026-04-03)
- https://learn.microsoft.com/en-us/entra/agent-id/configure-third-party-agents — Third-party agents (2026-04-29)
- https://learn.microsoft.com/en-us/entra/agent-id/create-delete-agent-identities — Create agent identities
- https://learn.microsoft.com/en-us/entra/agent-id/sign-in-audit-logs-agents — Agent logs
- https://learn.microsoft.com/en-us/entra/agent-id/agent-registry-convergence — Registry convergence (2026-04-05)
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id — Conditional Access for agents (2026-07-31)
- https://learn.microsoft.com/en-us/entra/global-secure-access/concept-secure-web-ai-gateway-agents — Secure Web and AI Gateway
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai — Enable security for AI agents (2026-10-30)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection — Real-time protection (2026-07-01)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection — Detect and investigate (2026-08-07)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/transition-agent-security-to-agent-365 — Licence transition (2026-06-02)
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table — AgentsInfo schema (2026-06-03)
- https://learn.microsoft.com/en-us/defender-xdr/supported-event-types — Streaming API tables
- https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview — Local agent discovery (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents — Discover local AI agents (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix — Support matrix (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview — Runtime protection (2026-10-08)
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection — Configure runtime protection (2026-09-25)
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider — External threat detection (2026-06-01)
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers — Webhook interface (2025-09-02, updated 2026-10-15)
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection — Defender for Cloud AI threat protection (2026-05-19)
- https://learn.microsoft.com/en-us/purview/ai-agent-365 — Purview for Agent 365 (2026-05-01)
- https://learn.microsoft.com/en-us/purview/developer/secure-ai-with-purview — Purview APIs for AI apps (2025-08-28, updated 2026-06-15)
- https://learn.microsoft.com/en-us/windows/ai/mcp/overview — MCP on Windows (2025-12-06, updated 2026-06-04)
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment — MCP containment (2025-11-11)
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai — WindowsAI CSP (2026-10-14)
- https://blogs.windows.com/windowsdeveloper/2026/10/07/microsoft-execution-containers-policy-driven-containment-for-ai-agents/ — MXC (2026-10-07)
- https://github.com/microsoft/mxc — MXC repository (v1.0.1, 2026-10-17)
- https://learn.microsoft.com/en-us/azure/foundry/control-plane/overview — Foundry Control Plane (2026-05-06)
- https://learn.microsoft.com/en-us/azure/foundry/control-plane/register-custom-agent — Custom agents (2026-10-28)
- https://docs.github.com/en/copilot/concepts/agents/enterprise-management — Copilot enterprise management
- https://docs.github.com/en/copilot/concepts/mcp-management — Copilot MCP management
- https://docs.github.com/en/copilot/reference/hooks-reference — Copilot hooks reference
- https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion — Security Copilot in E5/E7 (2026-06-19)
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview — Sentinel MCP (2026-05-07)
- https://github.com/microsoft/agent-governance-toolkit — AGT (v4.1.0, 2026-06-09; pushed 2026-11-09)
- https://github.com/responsibleai/agent-hooks — agent-hooks spec 0.1
- https://github.com/responsibleai/agent-control-spec — agent-control-spec
- https://github.com/microsoft/Agent365-python — Agent 365 SDK (MIT)

## Independent verification

_Checked 2026-11-09 by a second reviewer. Method: each claim was re-read in the primary document and cross-checked against sibling Microsoft Learn pages, the Microsoft 365 blog and the GitHub API (repository metadata, READMEs, tags, changelogs). Web search was unavailable (shared budget exhausted), so no third-party commentary was consulted; everything below comes from direct fetches of primary sources._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | MDE local agent discovery is GA on Windows and macOS only, WSL preview for three agents, no native Linux, 60+ agents, MCP config discovery for about half | Confirmed | Windows table lists 62 names, macOS 59; MCP discovery 28 of 62 on Windows. WSL preview covers Claude Code, Codex CLI, Copilot CLI (agent only, no MCP). Caveat: discovery of the seven VS Code extensions on macOS is still preview. Licence is MDE P2 only. Docs query a `Name` column while the `AgentsInfo` schema reference lists `AgentName`; check a live tenant before mirroring the schema. | https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents ; https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table |
| 2 | Endpoint runtime protection is preview, Windows-only; hooks for Claude Code, Claude Desktop (Code), Copilot CLI, Copilot app and both VS Code extensions; network inspection for OpenClaw, Ollama Desktop, ChatGPT; prompt injection only | Confirmed | Single alert type, "Suspicious AI prompt injection". Network list is OpenClaw, Ollama Desktop, ChatGPT Classic, ChatGPT Desktop (Chat mode). The Intune/Defender profile configures hook inspection only; network inspection needs a `Set-MpPreference -AiAgentNetworkInspection` script. Licence: MDE P2, E5, Agent 365 or E7. Preview needs Beta-channel updates. | https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection |
| 3 | Agent 365 OTLP/HTTP+JSON ingest URL, `Agent365.Observability.OtelWrite`, four operation names, 200 can reject every span | Confirmed | Details the plan must respect: `{agentId}` must equal the caller's Entra appId and every span's `gen_ai.agent.id`; agents without an Entra registration are described with `microsoft.a365.agent.platform.id` plus `gen_ai.agent.type`, but the sending app still needs an Entra registration. The app role is needed only for unregistered S2S identities and the delegated route. The doc says to "coordinate with the Agent 365 onboarding team to enable the permission", so self-service availability is not guaranteed. Body limit 1 MB (413). | https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-concepts ; https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-attribute-reference |
| 4 | Copilot Studio webhook: `POST /analyze-tool-execution?api-version=2025-05-01` before each tool call, `blockAction` within 1,000 ms, allow on timeout or error by default, per environment, no tenant-wide API | Confirmed | Admin page states there is no PowerShell, API or admin-center setting to propagate the configuration, and new environments must be enabled by hand. Default error behaviour is "Allow the agent to respond"; "Block the query" is selectable. Generative orchestration only. Still preview. | https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider |
| 5 | Agent 365 GA 1 May 2026, per user, USD 15/user/month or in E7; observability, policy templates, Graph API and all Entra, Purview and Defender agent features need E7 or Agent 365 | Corrected | Date, price and per-user model confirmed by Microsoft's own announcement. The licence wall is overstated: MDE local agent discovery, inventory and `AgentsInfo` hunting need only MDE P2, and endpoint runtime protection accepts MDE P2 or E5. Only risk levels, risk indicators and recommendations for local agents need E7 or Agent 365. Core Entra Agent ID is free. The service-description table is accurate for the features it lists. | https://www.microsoft.com/en-us/microsoft-365/blog/2026/03/09/powering-frontier-transformation-with-copilot-and-agents/ ; https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents |
| 6 | Local agents (Frontier): 23 tools detected, only Gemini CLI and six VS Code extensions blockable, Intune-managed Windows only; Claude Code CLI, Codex CLI, Cursor detect-only | Confirmed | 16 detect-only plus 7 blockable. Viewing needs Microsoft 365 E3, Intune enrolment and Frontier opt-in; blocking is listed under Agent 365/E7 in the service description. Blocking Gemini CLI uses the shared Node.js block that also hits OpenClaw, QClaw and Nanobot. | https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-local ; https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-agent-365/microsoft-agent-365 |
| 7 | Streaming API: `CloudAppEvents` GA, `BehaviorInfo` not available, `AgentsInfo` not listed, so inventory and block verdicts must be polled | Confirmed | The Sentinel Defender XDR connector also omits `AgentsInfo` and `BehaviorInfo`. Refinement: endpoint runtime-protection detections are alerts, so they do stream through `AlertInfo`/`AlertEvidence` (GA). Polling is needed for inventory and for cloud real-time-protection verdicts; when a cloud blocking rule covers an agent no alert is raised, so `BehaviorInfo` is the only record of the block. | https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender ; https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection |
| 8 | Connected platforms: Bedrock, Vertex AI, Agentforce, Databricks Genie, Claude Managed Agents, Oracle, Snowflake Cortex; read-only, manual, key-based only | Confirmed | One exception to read-only: an optional delete permission lets an admin remove a synced agent. Observability is "Coming soon" for Oracle and Snowflake. Deletion reconciliation is not guaranteed. | https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms ; https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms-anthropic-claude |
| 9 | MXC GA 7 Oct 2026, MIT, Rust, one JSON policy to AppContainer/Seatbelt/Bubblewrap; Intune, Entra separation and Agent 365 control "coming soon" | Confirmed | GitHub API: MIT, Rust about 75% of the code, v1.0.0 published 2026-10-07 (not prerelease), v1.0.1 on 2026-10-17. README default backends: `processcontainer`, `seatbelt`, `bubblewrap`; Linux also has `lxc` and `hyperlight`. Note for reuse: official Microsoft builds move to Required telemetry (from the 1.1.0-alpha contract) that admin policy cannot block, so build from source if embedding. | https://github.com/microsoft/mxc |
| 10 | AGT (MIT) delegates decisions to upstream `agent-control-spec` built on `agent-hooks` (eight points, allow/transform/deny, default deny on interceptor failure); plugins for Claude Code, Codex CLI, Copilot CLI | Confirmed | README: AGT keeps host APIs and adapters, "not a second decision engine". Default deny holds, but an administrator can mark a binding `on_error: continue`, which substitutes an allow on interceptor failure. Maturity caveat: `agent-hooks` is v0.1.0-beta.3 and `agent-control-spec` v0.4.0-beta.2, with 25 and 8 stars; the `responsibleai` GitHub org is not domain-verified. Plugins also exist for OpenCode and Antigravity CLI. | https://github.com/responsibleai/agent-hooks ; https://github.com/responsibleai/agent-control-spec |

### Further statements checked

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Open question: no rate or size limits documented for `agent365.svc.cloud.microsoft` beyond 429 on eligibility | Refuted | Limits are documented: 1 MB maximum request body (413 above it), separate rate limits per route, and 429 with `Retry-After: 1` on ingestion. | https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-concepts |
| AGT "latest tagged release v4.1.0 (2026-06-09)" | Corrected | v4.1.0 is the latest GitHub Release object, but a `v5.0.0` tag exists, `VERSION` is 5.0.0 and the changelog dates 5.0.0 to 2026-06-25. The ACS-based policy engine is the v5 line; pin against v5, not v4.1.0. | https://github.com/microsoft/agent-governance-toolkit |
| E7 price of USD 99 only found on third-party sites | Corrected | Microsoft's own announcement states E7 at USD 99 per user per month, available from 1 May 2026. | https://www.microsoft.com/en-us/microsoft-365/blog/2026/03/09/powering-frontier-transformation-with-copilot-and-agents/ |
