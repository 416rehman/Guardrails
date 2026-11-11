# Technical-docs teardown: remaining EDR-class, SASE and control-plane agent-security products

_Researched 2026-11-09_

**Method note.** Web search was unavailable for this run (the shared search budget was already spent), so every finding below comes from fetching vendor documentation URLs directly and from reading GitHub with `gh`. That biases coverage toward vendors with public, statically rendered docs or public repositories. Vendors whose docs are gated, JavaScript-only or at URLs I could not guess are listed under "Could not verify" and are marked **NV** (not verified) in the matrix. Nothing marked NV should be treated as a finding.

## TL;DR

- **Agent-native hooks are now the convergent enforcement point.** Microsoft Defender, BeyondTrust, Cisco DefenseClaw, Noma, Zenity, Lasso and 1Password all install into the same Claude Code, Codex, Cursor and Copilot hook surfaces. Coexistence on one machine is undocumented by every vendor.
- **Native Linux endpoints are the largest documented hole.** Microsoft discovery covers Windows and macOS, with WSL in preview and "WSL support doesn't indicate support for native Linux endpoints". BeyondTrust supports Windows 11 or Server 2022 x64 and macOS 14 to 26 only, with no Linux and no Windows on Arm.
- **Microsoft runtime protection is narrow**: preview, Windows only, prompt-injection detection only, one alert type ("Suspicious AI prompt injection"). Hook-based blocking is listed for Claude Code and Copilot surfaces; network inspection covers four apps and fails on certificate pinning and HTTP/3. Cursor has no runtime protection row.
- **Cisco already ships an Apache-2.0 competitor**: DefenseClaw (Go gateway, Python CLI, hook connectors for 12 agents) with version-pinned hook contracts, a documented fail-mode matrix and a published list of bypasses. Project Quarry is an Apache-2.0 detection DSL over agent conversations.
- **Elastic and Sysdig are detection-only on agents.** Elastic ships about 18 GenAI rules (Elastic License v2, not open source) keyed on `process.name`. Sysdig ships about 30 Falco rules for Claude Code, Codex CLI and Gemini CLI in two managed policies. Neither blocks a tool call.
- **Elastic's building-block rule runs over SentinelOne Cloud Funnel, Microsoft Defender XDR and Sysmon telemetry**, which proves agent detection content can ride on another EDR's process events. That is our embed path.
- **First-party controls are strong and file-based.** Claude Code has managed-only keys (`allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `allowManagedPermissionRulesOnly`) and `forceRemoteSettingsRefresh` for fail-closed startup. Codex has `requirements.toml` with cloud-managed requirements. If an admin sets `allowManagedHooksOnly`, our hooks only load when delivered through managed settings.
- **MCP gateways differ sharply in defaults.** Docker MCP Gateway (MIT, v0.44.3) is secure by default (`--block-secrets`, `--log-calls`, signature verification, bearer token on HTTP). Cloudflare MCP portals are remote-HTTP only, cap at 120 servers and 60 seconds per call, and document that blocked users can still reach a server by its direct URL.
- **SaaS agent posture products are connector lists.** Palo Alto SaaS Agent Security lists 10 platforms; Check Point (Lakera) lists 7. Depth "depends on what each platform's APIs expose".
- **Export is frequently paywalled or absent.** Cloudflare portal Logpush is Enterprise-only; BeyondTrust documents no export; GitHub agent streaming is preview and restricted to EMU or data-residency enterprises.

## Findings

### 1. Endpoint sensors with documented agent coverage

**Microsoft Defender for Endpoint + Agent 365** (docs dated 2026-08-19 to 2026-11-02)
- Agent 365 has been GA since 2026-05-01, licensed per user, and "works best when using Microsoft E5 as a pre-requisite". [overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview)
- Local discovery is GA on Windows and macOS for about 60 named agents (Claude Code, Codex CLI, Cursor, Gemini CLI, OpenClaw, Goose, Kiro, Warp, Hermes Agent and others), and MCP configuration discovery for roughly half. Results land in the `AgentsInfo` advanced hunting table, with `RawAgentInfo.localAgentMetadata.localMcps` for local MCP servers. Discovery uses a running agent process or periodically collected VS Code extension inventory. "Only supported combinations appear in the matrix", so bespoke agents are out of scope. [support matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix)
- WSL discovery (preview) covers three agents: Claude Code, Codex CLI, Copilot CLI.
- Runtime protection (preview, Windows only) has two methods, each `Disabled`, `Audit` or `Block`: `Set-MpPreference -AiAgentProtection` (agent-native event inspection through vendor hooks) and `-AiAgentNetworkInspection`. It needs `AntivirusSignatureVersion` 1.451.224.0 or later, Defender Antivirus in active mode, and during preview the Beta update channel. Intune has a profile only for the hook method; network inspection needs a PowerShell platform script. [setup](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection)
- Hook method rows: Claude Code, Copilot CLI, Copilot app, Claude Desktop (Code mode), VS Code Copilot and Claude Code extensions. Network method rows: OpenClaw, Ollama Desktop, ChatGPT Classic, ChatGPT Desktop (Chat mode, minimum tested 26.810.52044). The overview names Codex CLI as exposing event interfaces, but the matrix has no Codex row. [overview](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview)
- Licence: Defender for Endpoint P2, M365 E5, Agent 365 or M365 E7. The setting is covered by tamper protection.
- Cloud side: Copilot Studio real-time protection scans tool invocations through the external security provider webhook; cloud discovery covers Copilot Studio, Foundry, Bedrock and Vertex AI. [get started](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai)

**BeyondTrust AI Agent Security** (doc updated 2026-10-13)
- A "Pathfinder agent" on the endpoint classifies agents by process naming, signatures and LLM API traffic patterns. It names Claude Code and Codex, and inventories MCP servers, LLM endpoints and skills.
- Enforcement is at kernel and network level plus tool-call hooks "for AI coding tools that support hooks". Actions are allow, audit, hold for approval, or block before execution. It does not inspect or block prompts.
- Policies can be replayed against recorded activity before saving.
- Windows needs the tenant root certificate trusted "so HTTPS traffic can be inspected" and EDR allowlisting for the installer; macOS needs MDM-approved system extensions.
- No Linux, no Windows on Arm, no documented event export or API. Licensing is through the account team. [docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security)

**Elastic Defend** (rules updated 2026-09-25 to 2026-10-06)
- Endpoint rules in `elastic/detection-rules`: `GenAI CLI Started with Unsafe Permission Bypass` (matches `--dangerously-skip-permissions`, `--yolo`, `--sandbox danger-full-access`), `GenAI Process Accessing Sensitive Files`, `Unusual Process Modifying GenAI Configuration File`, `GenAI or MCP Server Child Process Execution` (building block), plus rules for unusual domains, suspicious TLDs, compiling executables, encoding before network activity, instruction files in Downloads, and destructive AWS CLI by a GenAI agent. [repo](https://github.com/elastic/detection-rules)
- Rules are tagged with MITRE ATLAS (AML.T0081, AML.T0053, AML.T0085) and carry `license = "Elastic License v2"`.
- The building-block rule indexes `logs-endpoint.events.process-*`, `logs-windows.sysmon_operational-*`, `logs-m365_defender.event-*` and `logs-sentinel_one_cloud_funnel.*`.
- SaaS-side rules consume `logs-anthropic.audit-*` (`event.action: "mcp_server_created"`), ChatGPT Enterprise Codex MCP tool-call logs, and Bedrock guardrail data.
- Documented gaps: "On linux only creation events are available. Access events are not yet implemented"; the config-modification rule is Windows and macOS only; the permission-bypass rule is tagged "Noise: High".

**Sysdig Secure** (Falco rules changelog, 2026-03-17 to 2026-10-27)
- Policies `Sysdig AI Runtime Notable Events` and `Sysdig AI Runtime Activity Logs` were added in rules v0.241.1 (2026-03-17).
- Rule names include `Claude Code Installation Detected`, `Codex CLI Executed with Risky CLI arguments`, `Gemini CLI Accessing Sensitive Files`, `Unauthorized Process Accessed Claude Code Configuration Directory`, `Claude Code Yolo Mode Spawned Suspicious Process`, `Non-Agent Process Connecting to LLM API`, `CLI Agent Loading Kernel Module`, `CLI Agent Spawning SSH Tunnel`, `CLI Agent Impersonation Detected`, `Read Agent CLI Credential File untrusted`, and `Claude Code Removing Own Session Evidence`. [changelog](https://docs.sysdig.com/en/release-notes/falco-rules-changelog/)
- Cloud rules cover Bedrock AgentCore (`Bedrock AgentCore Gateway Created Without Authorization`).
- Sensors are Host Shield for Linux 14.8.3 and Host Shield for Windows 0.21.0 (2026-11-05); no macOS sensor is listed. Per-rule OS is not stated. [release notes](https://docs.sysdig.com/en/release-notes/)
- Only three agents are named. The same rules were tuned for false positives nine times between March and October 2026.

### 2. Open-source and hook-based control layers from security vendors

**Cisco DefenseClaw** (Apache-2.0, 912 stars, pushed 2026-11-10; docs reference v1.0.4)
- A Go gateway plus Python CLI and per-agent hook connectors. Contracts are pinned to agent version ranges, for example Claude Code `>=2.1.219` uses `claudecode-hooks-v2` with 29 events, and Codex `>=0.145.0` uses `codex-hooks-v4` with 11. "Versions with no contract are refused." [compatibility](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/)
- Connectors: Claude Code, Codex, Cursor, Copilot CLI, Kiro, Devin, OpenCode, Amp, Antigravity, Hermes (hooks); OpenClaw and ZeptoClaw (proxy with PATH shims).
- Only Claude Code, Codex, Cursor and Devin can block prompts. Native ask or approval exists only for Claude Code, OpenClaw, Amp and Antigravity. [capability matrix](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/capability-matrix/)
- Fail modes: key `guardrail.hook_fail_mode`. Managed hosts default closed; per-user installs follow the policy pack; Cisco Secure Client deployments default **open**. A gateway that accepts a call but misses the deadline blocks in every mode. Hook input limit is 1 MiB. [fail modes](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/fail-modes/)
- Documented bypasses: a missing or non-executable hook script exits 126 or 127 and the agent runs unguarded "in every mode"; inherited `SHELLOPTS=noexec` or `BASH_ENV` can stop shell-form hooks; Copilot CLI and Antigravity still run the call on hook timeout; Hermes TUI skips hooks on 0.19 to 0.21.0.
- Related repos: `project-quarry` (alpha rule DSL compiled to symbolic finite-state automata over messages, tool calls and event order), `mcp-scanner` (1,114 stars), `skill-scanner` (2,713 stars), `a2a-scanner`, `aibom`, and inspection plugins for Kong, LiteLLM, LangChain and Google ADK. [org](https://github.com/cisco-ai-defense)

**Noma** (`noma-marketplace`, Apache-2.0, pushed 2026-11-09)
- Hook plugins for Claude Code, Codex, Cursor, GitHub Copilot and Kiro. A stdlib-only Python hook streams events to the Noma backend, which returns allow, block or flag. Noma calls its platform "AIDR". Every decision is a cloud round trip; offline behaviour is not stated in the README. [repo](https://github.com/Noma-Security/noma-marketplace)

**Snyk Agent Scan** (Apache-2.0, 3,230 stars, v0.6.11 on 2026-11-06)
- Discovers and scans MCP servers and skills for 12 agents on macOS, Linux and Windows. It requires `SNYK_TOKEN` and calls a hosted analysis API (version `2026-07-10`). It starts stdio MCP servers to read tool descriptions, which its own README flags as code execution. Background and push-key modes feed the Evo platform. CLI output is explicitly unstable. [repo](https://github.com/snyk/agent-scan)

**Lasso** — `claude-hooks` (MIT) is a PostToolUse hook that warns Claude about injected content and does not block. `mcp-gateway` (MIT, 401 stars) was last pushed 2026-01-22 and may be stale. [org](https://github.com/lasso-security)

**Prompt Security (SentinelOne)** — no product docs reachable. Public repos show `clawsec` (AGPL-3.0, 1,135 stars, skills and signed advisories for OpenClaw-family agents) and maintained forks of `mitmproxy` and `mitmproxy_rs`. A local TLS-intercepting proxy on the endpoint is my inference from those forks, not a documented fact. [org](https://github.com/prompt-security)

**1Password** — `agent-hooks` (MIT) installs a hook that validates mounted `.env` files from 1Password Environments for Cursor, Claude Code, Copilot and Windsurf. There are also plugins for Claude Code and Cursor and an Environments MCP server. [dev docs index](https://www.1password.dev/llms.txt)

### 3. Gateways and inline network positions

**Docker MCP Gateway** (MIT, v0.44.3, 2026-10-26)
- Runs each server in a container with `no-new-privileges`, CPU and memory limits, and no host environment.
- Defaults: `--block-secrets` scans tool-call arguments and responses; `--log-calls` records the tool name and argument shape only; signature verification for `mcp/` images; bearer token (`MCP_GATEWAY_AUTH_TOKEN`) on SSE and streaming transports; remote URLs must be public HTTPS.
- Network egress is not denied by default (`--block-network` is opt-in).
- The trust model states that the local OS user and configured interceptors are trusted, so a local agent running as the user is outside its boundary. [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md)
- OpenTelemetry metrics (`mcp.tool.calls`, `mcp.tool.duration`) export every 30 seconds. Enterprise "Docker AI Governance" is invite-only. [docs](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)

**Cloudflare MCP server portals and AI Gateway**
- Portals put many remote MCP servers behind one Access-authenticated endpoint, with per-tool toggles (`default_disabled: true` gives an allowlist), Code Mode in a Dynamic Worker sandbox, and optional Gateway DLP.
- Limits: 120 servers per portal, 60-second tool timeout, tool sync about every two hours, Streamable HTTP only when Gateway routing is on.
- Documented weaknesses: stdio servers unsupported; "DLP AI prompt profiles do not apply"; device posture through WARP identity not supported; admin tokens expire silently; blocked users can still reach a server by its direct URL; Logpush dataset `mcp_portal_logs` is Enterprise-only. [docs](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
- AI Gateway offers guardrails (flag or block), DLP, BYOK key storage, authenticated gateway, Logpush and OpenTelemetry trace export. [index](https://developers.cloudflare.com/ai-gateway/llms.txt)

**Palo Alto Prisma AIRS** (docs updated 2026-11-04)
- Sections: AI Inventory, AI Red Teaming, AI Supply Chain Security, AI Runtime Security (network or code layer), AI Gateway, AI Agent Identity. [docs](https://docs.paloaltonetworks.com/ai-runtime-security)
- SaaS Agent Security supports Atlassian Rovo, Box AI Studio, ChatGPT Enterprise, Cursor Enterprise, Gemini Enterprise, M365 Copilot, Copilot Studio, Agentforce, ServiceNow AI Agent Studio and Zoom AI (page dated 2026-01-15, possibly stale). It needs Strata Cloud Manager and CASB-X, CASB-PA or SSPM, or Prisma AIRS with NGFW software credits. Remediation can pause, deactivate or terminate agents. [supported](https://docs.paloaltonetworks.com/saas-agent-security/getting-started/whats-supported-with-saas-agent-security)
- `pan-mcp-relay` proxies stdio, Streamable HTTP and SSE and scans tool descriptions, parameters and responses through the API Intercept service; last pushed 2026-01-27. [repo](https://github.com/PaloAltoNetworks/pan-mcp-relay)
- Cortex XDR endpoint coverage of local agents: NV.

**Check Point AI Defense Plane (Lakera)**
- `docs.lakera.ai` is now titled "The Check Point AI Defense Plane". Agent discovery connects to Amazon Bedrock, Bedrock AgentCore, Google Cloud, Copilot Studio, Agentforce, n8n and Relevance AI. Device agents arrive through a separate "Workforce AI Security" product in the Infinity Portal. [discovery](https://docs.lakera.ai/docs/agent-security/discovery.md)
- The Guard API has a screen endpoint, a results endpoint, a policy linter and a logs API; self-hosting is documented; an OpenAPI spec is published. [index](https://docs.lakera.ai/llms.txt)

### 4. Agent platform and first-party controls

**GitHub** — Enterprise "AI controls" govern cloud agent sessions, the MCP policy and third-party agents; granular tool and MCP allowlists live in `managed-settings.json`. [docs](https://docs.github.com/en/copilot/concepts/agents/enterprise-management) Audit events carry `actor_is_agent: true` and `agent_session_id`; history is 180 days. Streaming of Copilot API request and response bodies is public preview, limited to EMU or data-residency enterprises, with 1 MB truncation. [audit](https://docs.github.com/en/copilot/reference/agentic-audit-log-events)

**Anthropic Claude Code** — Managed settings load from `/Library/Application Support/ClaudeCode/managed-settings.json`, `/etc/claude-code/managed-settings.json`, MDM (`com.anthropic.claudecode`), registry, or server-managed delivery. Managed-only keys include `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `allowManagedPermissionRulesOnly`, `allowManagedDomainsOnly` and `allowManagedReadPathsOnly`. `forceRemoteSettingsRefresh` "blocks CLI startup until remote managed settings are freshly fetched and exits if the fetch fails". Invalid restrictive keys fail closed from v2.1.282; `requiredMinimumVersion` fails open by design. Embedders can pass policy through the SDK `managedSettings` option. [docs](https://code.claude.com/docs/en/managed-settings.md)

**OpenAI Codex** — `requirements.toml` (local, MDM `config_toml_base64`, or cloud-managed in "Agent security") constrains `allowed_approval_policies`, `allowed_sandbox_modes`, `allowed_permission_profiles` (Codex 0.138.0+), `[rules] prefix_rules`, `[mcp_servers.<name>] identity` and `[network_proxy]` (canonical from 0.166.0). On conflict the client "falls back to a compatible value and notifies the user". [docs](https://learn.chatgpt.com/docs/enterprise/managed-configuration)

**Zenity** — The docs navigation lists Coding Agents, Boundaries and a Boundaries CLI, Inline Prevention, Kill switch, Malicious Package Protection, a Custom Agents evaluate API, and integrations for Cribl, CrowdStrike Falcon Next-Gen SIEM and Cortex XDR, plus an "ACS Schema" page. Page bodies are JavaScript-rendered and unread. [docs](https://docs.zenity.io/)

## Matrix

NV = not verified this run. "Hooks" means the agent's vendor-supported hook interface.

| Vendor | Discovery | Control points | Platforms | Fail behaviour | Policy model | Events and export | Identity and secrets | Licence and prerequisites | Partner or ingest API |
|---|---|---|---|---|---|---|---|---|---|
| Microsoft Defender + Agent 365 | Process and VS Code extension inventory, about 60 named agents; cloud connectors | Hooks; network inspection; Copilot Studio webhook | Discovery: Windows, macOS, WSL preview. Runtime: Windows preview | Not documented | Disabled, Audit or Block per method | `AgentsInfo` table; one alert type | Entra Agent ID, Purview | MDE P2, E5, Agent 365 or E7 | Copilot Studio external security provider; Agent 365 partner agents |
| BeyondTrust | Pathfinder classifiers: process, signature, LLM traffic | Kernel, network (TLS inspection), hooks | Windows 11 or Server 2022 x64; macOS 14 to 26 | Not documented | Allow, audit, hold, block; replay preview | Session records; no export documented | Separates agent from human under one credential | Account team | None documented |
| Elastic Defend | `process.name` lists in rules | None (detect only) | Windows, macOS, Linux (partial file events) | n/a | EQL, KQL, new-terms rules | ECS; ATLAS tags | Rules for credential-file access | Rules ELv2 | Ingests S1 Cloud Funnel, M365 Defender, Sysmon, Anthropic audit, ChatGPT Enterprise |
| Sysdig | Falco rules for 3 CLI agents | None (detect only) | Linux, Windows Host Shield | n/a | Falco rules in 2 managed policies | Sysdig events | Credential-file rules | Commercial; Falco engine Apache-2.0 | Sysdig MCP server |
| Cisco DefenseClaw | Per-connector setup, 12 agents | Hooks, proxy, scanners | macOS, Linux, native Windows | Closed by default; open under Secure Client | Policy packs; Quarry DSL | Audit rows; observability exporters | Scanners for skills and MCP | Apache-2.0 | Kong, LiteLLM, LangChain, ADK plugins |
| Palo Alto Prisma AIRS | SaaS connectors (10 platforms); cloud inventory | Network intercept, API intercept, AI Gateway, MCP relay | Cloud and SaaS; endpoint NV | NV | Security profiles in Strata Cloud Manager | Strata Logging Service | "AI Agent Identity" | CASB-X, CASB-PA, SSPM or AIRS credits | API Intercept |
| Check Point (Lakera) | Connectors (7 platforms); device agents via Workforce AI Security | Guard API; inline guardrails | SaaS or self-hosted | NV | Policies with linter endpoint | Logs API, results API | DLP guardrail | Commercial | OpenAPI spec |
| Noma | Hook plugins, 5 agents | Hooks to cloud verdict | macOS, Linux, Windows | NV | Allow, block, flag | Noma Console | Prompt PII scan | Plugins Apache-2.0; platform commercial | NV |
| Snyk Evo | Agent Scan across 12 agents | Scanner only | macOS, Linux, Windows | n/a | 14 risk types | Evo platform; unstable CLI JSON | Secret detection in skills | CLI Apache-2.0; needs Snyk token | Hosted analysis API |
| Docker MCP Gateway | Catalog and profiles | MCP gateway, containers | Docker Desktop or Engine | Secure defaults; flags opt out | Profiles, tool allowlists | OpenTelemetry metrics | Per-server secret scoping, OAuth | MIT; governance invite-only | Interceptors, OCI catalogs |
| Cloudflare | Portal registration; shadow AI NV | MCP portal, AI Gateway, SWG | Remote HTTP only | Errors on DLP block | Access policies, tool toggles | Portal logs; Logpush Enterprise; OTel | Access OAuth; encrypted upstream secrets | Cloudflare domain and IdP | API, Logpush |
| GitHub | Agent sessions on platform | Policies, `managed-settings.json`, firewall | Cloud agent, Copilot CLI | NV | Enterprise policies | Audit log 180 days; streaming preview | n/a | Copilot Business or Enterprise | Audit log API, streaming |
| Anthropic | n/a (self) | Managed settings, hooks, sandbox | macOS, Linux, Windows | Selectable fail-closed startup | JSON settings, permission rules | Audit logs (Elastic dataset `anthropic.audit`) | n/a | Enterprise plans | SDK `managedSettings`, hooks |
| OpenAI Codex | n/a (self) | `requirements.toml`, sandbox, rules | macOS, Linux, Windows | Falls back to compatible value | TOML requirements | Compliance and analytics (NV detail) | n/a | Enterprise plans | Hooks, MCP identity allowlist |
| SentinelOne + Prompt | NV | NV | NV | NV | NV | Cloud Funnel (seen via Elastic) | NV | NV | NV |
| Zenity | Connectors; coding agents page | Inline prevention, Boundaries, kill switch (titles only) | NV | NV | Boundaries as code | SIEM integrations (titles only) | Okta integration | Commercial | Custom Agents evaluate API |
| Trend, Zscaler, Netskope, Wiz, Tanium, Sophos, Bitdefender, ESET, Kaspersky, Jamf, Iru, Island | NV | NV | NV | NV | NV | NV | NV | NV | NV |

## Weak points, gaps and risks

- **Microsoft**: runtime protection inspects only for prompt injection, not for policy on the action itself; Windows only; preview requires the Beta channel; no Codex or Cursor runtime row; network inspection defeated by pinning and HTTP/3; discovery is an allowlist of named agents, and "installing an agent doesn't by itself guarantee an inventory entry". [matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix)
- **BeyondTrust**: no Linux or Arm Windows; requires a trusted root certificate and EDR allowlisting, which collides with the customer's primary EDR; no documented export; no prompt inspection. [docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security)
- **Elastic and Sysdig**: name-based matching is trivially evaded by renaming a binary or running a bespoke agent under `python` or `node`. Sysdig's own `CLI Agent Impersonation Detected` rule and nine rounds of false-positive tuning show the fragility. Elastic's Linux file-open telemetry is missing.
- **Cisco DefenseClaw**: the Secure Client distribution, which is the enterprise route, defaults to fail-open; hook non-start is a silent bypass; contracts lag agent releases (Cursor Agent CLI is covered only at one exact build).
- **Hook-to-cloud designs (Noma)**: every tool call depends on a remote verdict, and offline behaviour is undocumented.
- **Gateways**: Docker trusts the local user; Cloudflare cannot see stdio servers and allows direct-URL bypass unless each server enforces Access OAuth.
- **SaaS posture tools**: bounded by platform APIs; no coverage of local or bespoke agents.
- **Risk to us**: three or more vendors writing to the same hook configuration files on one machine. Elastic's rule `Unusual Process Modifying GenAI Configuration File` will alert on our own installer unless we are allowlisted.

## Implications for our design

1. **Ship a native Linux sensor first-class** (eBPF), plus Windows on Arm. This is the clearest documented hole in both Microsoft and BeyondTrust.
2. **Deliver hooks through managed settings, not user settings.** Support Claude Code managed-settings and Codex `requirements.toml` as install targets so we survive `allowManagedHooksOnly`, and generate those files for admins.
3. **Build a hook multiplexer.** One registered hook that fans out to our engine and to other vendors' hook commands, with deterministic ordering and deny-wins merging. Nobody documents coexistence.
4. **Copy DefenseClaw's connector contract model**: version-ranged hook contracts, refusal or warning on unknown versions, a published per-connector fail-mode table, and a `doctor` command that detects exit 126 or 127 hook non-start. Add the piece they lack: an OS-level sensor that notices when an agent ran a tool with no matching hook event.
5. **Discover by behaviour, not name.** Combine "process connects to an LLM API", "process spawns shells or MCP servers", and config-file presence. Sysdig's `Non-Agent Process Connecting to LLM API` is the right primitive for bespoke agents.
6. **Make detection content portable across EDR telemetry.** Write rules against a normalised process, file and network schema (ECS or OCSF) with adapters for SentinelOne Cloud Funnel, Defender XDR advanced hunting, Sysmon and Falco. This is the embed story for EDR vendors.
7. **Do not copy Elastic rules** into the codebase: ELv2 is incompatible with an open-source licence. Reimplement from the public behaviours. Falco (Apache-2.0) and Quarry (Apache-2.0, alpha) are reusable.
8. **Ingest rather than rebuild** platform logs: Anthropic audit, ChatGPT Enterprise compliance, GitHub audit (`actor_is_agent`, `agent_session_id`), Cloudflare `mcp_portal_logs`, Docker gateway OpenTelemetry, Defender `AgentsInfo`.
9. **Decide locally, fail closed by default, and document it.** A local policy engine avoids the cloud round trip; publish the outage matrix per connector as Cisco does.
10. **Avoid mandatory TLS interception.** A root certificate plus EDR allowlisting is the main deployment friction in BeyondTrust's guide and breaks on pinning and HTTP/3 in Microsoft's.

## Ideas worth stealing and whitespace

Ranked by value to us.

1. **Linux and Arm endpoint enforcement** (whitespace: no documented vendor).
2. **Hook coexistence and tamper evidence** across vendors (whitespace).
3. **Policy replay before save** (BeyondTrust): evaluate a draft policy against recorded sessions.
4. **Versioned connector contracts and fail-mode matrix** (Cisco).
5. **Action policy rather than prompt classification.** Microsoft detects injection only; BeyondTrust governs actions only. Doing both with one rule language is open ground.
6. **Detection-as-content over foreign EDR data** (Elastic's multi-index building block).
7. **Self-evidence removal and impersonation detections** (Sysdig): agent deleting its own session logs, non-agent process using agent credentials.
8. **Secure-by-default MCP gateway flags** (Docker): secret scanning both directions, argument-shape-only logging, digest-pinned signed servers.
9. **Open export.** Free OTLP and OCSF export where Cloudflare charges and BeyondTrust documents nothing.
10. **Stdio MCP coverage.** Cloudflare cannot see stdio; Snyk must execute servers to scan them. A sensor that observes stdio MCP traffic passively is unclaimed.

## Could not verify / open questions

- **SentinelOne Singularity + Prompt Security**: `docs.prompt.security` does not resolve; one product page returned 404. No discovery, platform or fail-mode facts verified.
- **Palo Alto Cortex XDR**: endpoint agent discovery and enforcement not read. Prisma AIRS runtime, gateway and release-note pages were not opened.
- **Trend Vision One**: docs URL looped on redirects.
- **Zscaler** (`help.zscaler.com/ai-guard`) and **Netskope** (`docs.netskope.com`): pages rendered empty or navigation only.
- **Zenity**: only navigation titles; Coding Agents, Boundaries and ACS Schema bodies unread.
- **Cisco AI Defense commercial docs**: `developer.cisco.com/docs/ai-defense/overview/` returned 404; only the open-source side is verified.
- **Wiz, Island, Tanium, Sophos, Bitdefender, ESET, Kaspersky, Jamf, Iru**: no pages attempted successfully. Without search I could not locate their agent-security docs.
- **Snyk Evo** platform docs, **1Password** agentic autofill and device trust checks, **Sysdig AI Defense** product pages: not found in the indexes I could read.
- **Microsoft**: fail-open or fail-closed behaviour of the Defender hook when the service is unavailable is not stated. Whether Codex runtime protection exists is contradictory between two pages.
- **Matrix columns**: I did not have the five named teardowns, so column parity is my best reconstruction from the brief.

## Sources

- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Microsoft Agent 365 overview, 2026-08-19 (updated 2026-10-23)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix — Defender for Endpoint AI agent support matrix, 2026-11-02
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview — AI agent runtime protection (Preview), 2026-10-08
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection — Set up AI agent runtime protection (Preview), 2026-09-25
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai — Enable security for AI agents, 2026-10-30
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — BeyondTrust AI Agent Security, 2026-10-13
- https://github.com/elastic/detection-rules — Elastic detection rules (GenAI rules updated 2026-09-25 to 2026-10-06)
- https://docs.sysdig.com/en/release-notes/falco-rules-changelog/ — Sysdig Falco rules changelog, through 2026-11-09
- https://docs.sysdig.com/en/release-notes/ — Sysdig release notes index, 2026-11-09
- https://github.com/cisco-ai-defense/defenseclaw — DefenseClaw, pushed 2026-11-10
- https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/ — DefenseClaw connector compatibility
- https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/capability-matrix/ — DefenseClaw capability matrix
- https://cisco-ai-defense.github.io/defenseclaw/docs/reference/fail-modes/ — DefenseClaw fail modes (v1.0.4)
- https://github.com/cisco-ai-defense/project-quarry — Project Quarry, pushed 2026-11-10
- https://github.com/Noma-Security/noma-marketplace — Noma marketplace, pushed 2026-11-09
- https://github.com/snyk/agent-scan — Snyk Agent Scan v0.6.11, 2026-11-06
- https://github.com/lasso-security — Lasso repositories (claude-hooks 2026-01-08, mcp-gateway 2026-01-22)
- https://github.com/prompt-security — Prompt Security repositories, 2026-11
- https://github.com/1Password/agent-hooks — 1Password agent hooks, pushed 2026-11-04
- https://www.1password.dev/llms.txt — 1Password developer docs index
- https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/ — Docker MCP Gateway docs
- https://github.com/docker/mcp-gateway/blob/main/docs/security.md — Docker MCP Gateway security model (v0.44.3, 2026-10-26)
- https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/ — Cloudflare MCP server portals
- https://developers.cloudflare.com/ai-gateway/llms.txt — Cloudflare AI Gateway docs index
- https://docs.paloaltonetworks.com/ai-runtime-security — Prisma AIRS docs, updated 2026-11-04
- https://docs.paloaltonetworks.com/prisma-airs/ai-agent-identity/saas-agent-security-overview — SaaS Agent Security overview
- https://docs.paloaltonetworks.com/saas-agent-security/getting-started/whats-supported-with-saas-agent-security — What's supported, 2026-01-15
- https://github.com/PaloAltoNetworks/pan-mcp-relay — Prisma AIRS MCP relay, pushed 2026-01-27
- https://docs.lakera.ai/llms.txt — Check Point AI Defense Plane (Lakera) docs index
- https://docs.lakera.ai/docs/agent-security/discovery.md — Agent Discovery
- https://docs.zenity.io/ — Zenity docs navigation
- https://docs.github.com/en/copilot/concepts/agents/enterprise-management — GitHub enterprise agent management
- https://docs.github.com/en/copilot/reference/agentic-audit-log-events — GitHub agentic audit log events
- https://code.claude.com/docs/en/managed-settings.md — Claude Code managed settings
- https://code.claude.com/docs/en/permissions — Claude Code permissions
- https://learn.chatgpt.com/docs/enterprise/managed-configuration — Codex managed configuration

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (shared budget spent), so every check is a direct fetch of vendor documentation or a read of source through `gh`. Where possible the check used a page or file the brief did not cite._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Defender local agent discovery is GA on Windows and macOS only; WSL is preview for three agents and does not imply native Linux | Confirmed | The prerequisites page lists only Windows (platform 4.18.26090.9+) and macOS (101.26072.0017+). Two nuances: the seven macOS VS Code extension rows are still preview, and the three WSL rows have no MCP discovery. Sovereign clouds are unsupported. | https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents |
| 2 | Defender runtime protection is preview, Windows only, prompt injection only, hooks for Claude Code and Copilot surfaces, no Cursor or Codex row, network inspection fails on pinning and HTTP/3 | Confirmed | Setup page requires "a supported version of Windows" and the Intune profile is Windows only. The only alert is "Suspicious AI prompt injection". The overview also says Defender scans for "high-risk actions", but no separate detection or alert for them is documented. | https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection |
| 3 | BeyondTrust supports only Windows 11 or Server 2022 x64 and macOS 14 to 26, needs a trusted root certificate on Windows, documents no export | Corrected | Windows is "Windows 11, or Windows Server 2022 **or later**". The root certificate is required on macOS too (pushed by MDM profile), not only Windows. No export holds: the AI agent Events page is console-only, Pathfinder audit logs cover user management only, and webhook streaming exists only for Entitle audit logs. | https://docs.beyondtrust.com/bt-docs/docs/ai-agents-events ; https://docs.beyondtrust.com/bt-docs/docs/pathfinder-audit-logs |
| 4 | Claude Code managed-only keys include `allowManagedHooksOnly` and `allowManagedMcpServersOnly`; `forceRemoteSettingsRefresh` blocks startup if the fetch fails | Confirmed | Server-managed settings page: without the key a failed first fetch continues with a warning; with it "Claude Code exits instead". Under `allowManagedHooksOnly`, hooks still run from managed settings, the Agent SDK, and plugins force-enabled in managed `enabledPlugins`. | https://code.claude.com/docs/en/server-managed-settings.md ; https://code.claude.com/docs/en/settings-reference.md |
| 5 | DefenseClaw is Apache-2.0, 12 agents, fails closed by default except under Secure Client; exit 126 or 127 runs unguarded in every mode | Corrected | Licence, 12 connectors (10 hook, 2 proxy) and the 126/127 bypass hold. The default is not uniformly closed: only managed standalone is `closed`. A per-user install has no saved default, and with the default (balanced) or permissive rule pack a call runs with one warning when the gateway is down; only the strict pack blocks. The repo README repeats the simpler "fail closed by default" line. Latest release is 1.0.8 (2026-11-05); the fail-modes page describes 1.0.4. | https://github.com/cisco-ai-defense/defenseclaw (README, licence, releases) ; https://cisco-ai-defense.github.io/defenseclaw/docs/reference/fail-modes/ |
| 6 | Elastic GenAI rules are ELv2, match on process names, and the building-block rule runs over SentinelOne Cloud Funnel, Defender XDR and Sysmon indices | Confirmed | Read the TOML directly: `license = "Elastic License v2"`, four indices as stated, `integration = ["endpoint", "windows", "sentinel_one_cloud_funnel", "m365_defender"]`. Matching is `process.name` or `process.parent.name` lists, plus `process.args` patterns for CLIs run under `node`. | https://github.com/elastic/detection-rules/blob/main/rules_building_block/execution_mcp_server_child_process.toml |
| 7 | Sysdig coverage is Falco detection rules for Claude Code, Codex CLI and Gemini CLI in two managed policies from 2026-03-17; Linux and Windows sensors, no macOS | Confirmed | Changelog entry 0.241.1 (March 17, 2026) adds both policies; only those three agents are named; release notes list Host Shield for Linux and Windows and no macOS component. Per-rule OS is still not stated. Caveat: the Falco project itself ships enforcement, see row A. | https://docs.sysdig.com/en/release-notes/ |
| 8 | Docker MCP Gateway (MIT) enables secret scanning, call logging, signature verification and bearer-token auth by default; trusts the local OS user; no default egress deny | Confirmed | Source sets `LogCalls`, `BlockSecrets` and `VerifySignatures` to true by default; `--block-network` and `--allow-unauthenticated` are opt-in flags. Bearer auth applies only to the `sse` and `streaming` transports; the default `stdio` transport has none. | https://github.com/docker/mcp-gateway/blob/main/cmd/docker-mcp/commands/gateway.go |
| 9 | Cloudflare MCP portals are remote HTTP only, 120 servers, 60 seconds per call, direct-URL bypass unless Access OAuth, Logpush Enterprise only | Confirmed | All five statements appear verbatim on the page. The Enterprise restriction covers Logpush export only; dashboard portal logs carry no plan restriction. The `mcp_portal_logs` dataset exists with 19 fields. | https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/ |
| 10 | Codex policy is delivered as `requirements.toml` (local, MDM or cloud) and on conflict the client falls back to a compatible value and notifies the user | Confirmed | Sources, lowest to highest: `/etc/codex/requirements.toml` (or `%ProgramData%\OpenAI\Codex\requirements.toml`), cloud Agent Security bundle, legacy `managed_config.toml`, macOS MDM. A failed cloud fetch with no cache returns an error instead of starting unmanaged. See row B for the MDM key. | https://github.com/openai/codex/blob/main/docs/config.md ; https://learn.chatgpt.com/docs/enterprise/managed-configuration |

Further statements checked in the brief body:

| # | Statement in the brief | Verdict | Note | Source |
|---|---|---|---|---|
| A | "Linux and Arm endpoint enforcement (whitespace: no documented vendor)" and "Elastic and Sysdig are detection-only" | Refuted as worded | `falcosecurity/prempti` (Apache-2.0, Falco sandbox project started by Sysdig staff, v0.2.1) intercepts tool calls with allow, deny or ask verdicts from Falco rules on Linux, macOS and Windows, x86_64 and aarch64, including a Windows ARM64 MSI. Claude Code is supported on all three; Codex is experimental on Linux. DefenseClaw also installs on Linux x86_64 and arm64. The real gap is narrower: OS-level (kernel) enforcement on Linux, and Windows on Arm from the commercial EDR vendors. Prempti is a direct open-source rival missing from the brief. | https://github.com/falcosecurity/prempti ; https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install/ |
| B | Codex `requirements.toml` delivered by "MDM `config_toml_base64`" | Corrected | The requirements key is `requirements_toml_base64` in domain `com.openai.codex`. `config_toml_base64` carries managed defaults, which users can override. Codex also has `allow_managed_hooks_only = true`, valid only in `requirements.toml`, which ignores user, project and session hooks; the brief's managed-delivery point applies to Codex as well as Claude Code. | https://learn.chatgpt.com/docs/enterprise/managed-configuration ; https://github.com/openai/codex/blob/main/docs/config.md |
| C | DefenseClaw "docs reference v1.0.4" used as current | Outdated | Latest release is 1.0.8 (2026-11-05). The fail-mode matrix and the contract version ranges should be re-read against 1.0.8 before the design copies them. | https://github.com/cisco-ai-defense/defenseclaw/releases |

