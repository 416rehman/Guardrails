# G09 - OS-native and editor-native agent platforms: Windows agent workspace, ACP, WebMCP, built-in browser agents, synthetic input

_Researched 2026-11-09_

Method note: the shared WebSearch budget for this run was already exhausted, so nothing here comes from search results. Everything was established by fetching primary documents directly (Microsoft Learn, Apple release-note JSON, IETF Datatracker, vendor docs), by reading source through the GitHub API (Chromium policy definitions, WebMCP spec, ACP repo and registry), and by read-only inspection of one Windows 11 Pro 10.0.26300 host. Claims marked "(prior knowledge)" were not re-fetched and should be re-verified.

## TL;DR

- **Windows agent workspace is real but still preview, and still opt-in.** Agents run under separate standard "agent accounts" (names end in `$`) in a separate Windows session with their own desktop. Where it is used, agent-versus-human attribution is a token user/session check. Microsoft's own page was last updated 2025-12-05 and still says private preview for Insiders.
- **The Windows on-device registry (ODR) is a platform MCP registry with enterprise policy.** WindowsAI CSP now has `AgentConnectorAccessPolicy` (JSON allowlist of MCP host to server connections), `ConfigureAgentConnectors`, `AgentConsentDuration` and `OnDeviceRegistryLoggingLevel`. All are Enterprise/Education only and still flagged "Windows Insider Preview" as of 2026-10-14.
- **Windows ships audit plumbing a third party can read today.** On a 26300 (26H2) host: event channels `Microsoft-Windows-AgentConnector-{FilesAgent,FileSearch,Settings}/{Admin,Operational}` and providers `Microsoft-Windows-AI-ModelContextProtocol` (Admin + Operational), `Microsoft-Windows-AgenticPlatform-IsoEnvBroker`, `Windows Mcp Registry`. Event payloads are a single free-text `%1` string, not a structured schema.
- **Third-party agents bypass all of it by default.** Only MSIX-identity binary MCP servers reached through ODR are contained. Claude Code, Cursor, Codex and bespoke agents run in the user session under the user token, so process-lineage attribution is still required for them.
- **ACP (Agent Client Protocol) is the one-shim-many-agents point for editors.** JSON-RPC 2.0 over newline-delimited stdio; schema v1.30.0 and v2.0.0-alpha.14 released 2026-11-09; Apache-2.0. About 50 agents in the registry (Claude via adapter, Codex via adapter, Cursor, Gemini CLI, Copilot, Goose, Junie, Kiro, Cline, OpenCode, Devin, Amp). Clients include Zed, JetBrains, Neovim, Emacs, VS Code extensions and now Xcode 27. Remote transport is still a draft RFD.
- **ACP is a strong observation point but only a partial enforcement point.** `session/request_permission` is agent-initiated; an agent in auto-approve mode never asks. Enforcement is deterministic only for operations the agent delegates to the client (`fs/*`, `terminal/*`).
- **WebMCP is a W3C Community Group draft in origin trial** (Chrome 149, Edge 150). API is `document.modelContext` (`registerTool`, `getTools`, `executeTool`), with a `toolactivated` event and `readOnlyHint` / `untrustedContentHint` / `consequentialHint` annotations. No extension audit API and no dedicated enterprise policy found.
- **Browser built-in agents are governed by per-vendor policies, not a standard.** Chrome: `GeminiSettings`, `GeminiActOnWebSettings`, `GeminiActOnWebAllowedForURLs` / `BlockedForURLs`, `GeminiSparkSettings`. Edge 158: `AgentProfileEnabled`, `CopilotBrowserUseAllowList` / `BlockList`, `CopilotCoworkToolActionsEnabled`. Safari: nothing found.
- **macOS 27 gives no agent identity.** TCC is still attributed to the responsible process. macOS 27 removes direct TCC database access, denies cross-team container access by default, and Xcode 27 adds ACP, agent plug-ins and a filesystem security layer for coding agents.
- **Microsoft and BeyondTrust already ship the discovery half.** Defender for Endpoint discovers local agents and their MCP servers on Windows and macOS (`AgentsInfo` table, `autoApprove`, `trustedProcess`, `localMcps`), with runtime protection in preview via `Set-MpPreference -AiAgentProtection` and `-AiAgentNetworkInspection`.
- **Web Bot Auth is now an IETF WG document** (`draft-ietf-webbotauth-httpsig-protocol-01`, 2026-10-29). AP2 is v0.2 and has been donated to FIDO. Both are egress-side identity signals for a gateway.

## Findings

### 1. Windows: agent workspace, agent accounts, ODR, agent connectors

**Status and dates.** Announced 2025-10-16; support page updated 2025-11-17 (Insider rollout with Copilot Actions) and 2025-12-05 (agent connectors run in agent workspace). No later update on that page; it still says private preview. The toggle is Settings > System > AI Components > Experimental agentic features, off by default, admin-only, device-wide once enabled, and enabling it is what creates the agent accounts and workspace. [Support page](https://support.microsoft.com/en-us/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3), [Windows blog 2025-10-16](https://blogs.windows.com/windowsexperience/2025/10/16/securing-ai-agents-on-windows/).

**Isolation model (verified from docs).**
- Each agent has its own standard account, distinct from the user; the workspace runs in a separate Windows session with its own desktop, described as lighter than Windows Sandbox.
- Agent accounts get read/write to six known folders by consent (Documents, Downloads, Desktop, Music, Pictures, Videos) plus anything Authenticated Users can read. From build 26100.7344: per-agent Files setting with Allow Always / Ask every time / Never allow.
- Stated principles: tamper-evident audit log, agent actions distinguishable from user actions, agents never exceed the initiating user's rights, and "Admin, SYSTEM and other entities should have no special access to an agent beyond its owner". These are goals; no documented API for the audit log was found.
- Known issue: Intune Endpoint Privilege Management profiles for "agent user accounts (names ending in `$`)" are not cleaned up. That confirms the naming pattern.
- Entra and MSA identity for agent accounts was "coming soon" in October 2025; not confirmed shipped.

**ODR and agent connectors.** ODR is "a secure, manageable interface to discover and use agent connectors from local apps and remote servers" ([overview, updated 2026-06-04](https://learn.microsoft.com/en-us/windows/ai/mcp/overview)).
- Registration paths: MSIX `uap3:AppExtension` named `com.microsoft.windows.ai.mcpServer`; MSIX with external location; MCP bundle (`.mcpb`); manual `odr.exe mcp add <manifest>` or `odr.exe mcp add --uri <url>` for remote servers. [Identity registration](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-windows-identity), [manual](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-manual).
- CLI: `odr mcp run | list | add | remove | configure`. [odr tool](https://learn.microsoft.com/en-us/windows/ai/mcp/odr-tool).
- Containment: only binary (`.exe`) servers with package identity and a manifest carrying `_meta["com.microsoft.windows"].static_responses` for `initialize` and `tools/list`. Runtime responses must match the static ones. Contained servers cannot touch user files, settings, registry, credentials, windows, or user-session processes, but **can access the internet**. [Containment](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment).
- Consent is **per host, not per server**: once a host is granted a folder, every MCP server used by that host gets it.
- MCP bundles and unpackaged servers cannot be contained and are hidden from ODR unless the user enables "Reduce protections for agent connectors".
- Built-in connectors: File Explorer and Windows Settings. Agent Launchers register agents themselves in ODR via App Actions (`agentName`, `prompt` entities), but explicitly not "background services or silent automation". [Agent Launchers](https://learn.microsoft.com/en-us/windows/ai/agent-launchers/).
- Minimum build for registration docs: 26220.7262. Test guidance was refreshed 2026-10-28 and still says "preview command surfaces can differ by Windows build". [Test page](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/test-mcp-server).

**Policy (verified, [WindowsAI Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai), ms.date 2026-10-14).**

| Policy | Type | Notes |
|---|---|---|
| `AgentConnectorAccessPolicy` | JSON string | Allowed MCP host to MCP server connections; schema at go.microsoft.com/fwlink/?LinkId=2363700 |
| `ConfigureAgentConnectors` | 0 user / 1 force enable / 2 force disable | |
| `AgentConsentDuration` | 1 to 8760 h, default 720 | How long an "Allow" lasts |
| `OnDeviceRegistryLoggingLevel` | 0 error / 1 info / 2 debug | |
| `DisableSettingsAgent`, `DisableClickToDo` | bool | |

All four agent policies: device scope, Enterprise / Education / IoT Enterprise only (not Pro), "Windows Insider Preview". The same strings appear in the 26H2 ADMX (`CAM_AI.admx`, category "AI Consent") mirrored on 2026-10-01 ([web-admx-tool](https://github.com/pl4nty/web-admx-tool)). A third-party Intune write-up dates 26H2 as build 10.0.26300, released 2026-09-29, and says these are custom OMA-URI only, not yet in the Settings Catalog ([joeloveless.com](https://joeloveless.com/blog/intune-settings-catalog-settings-win11-26h2/), medium confidence).

**Third-party visibility (observed locally, 10.0.26300 Pro, experimental agentic features not enabled).**
- Channels present and enabled: `Microsoft-Windows-AgentConnector-FilesAgent/Operational` and `/Admin`, same for `-FileSearch` and `-Settings`. Readable by Administrators and by interactive users (`IU` has read in the channel SDDL).
- Provider `Microsoft-Windows-AI-ModelContextProtocol`, GUID `cc71be2b-56aa-4756-9116-38bdd0408e43`, channels `/Operational` and `/Admin`; event IDs 1 to 5 with message template `%1` only.
- Provider `Microsoft-Windows-AgenticPlatform-IsoEnvBroker` logging to `Microsoft-Windows-AI-Platform/Operational`.
- Classic provider "Windows Mcp Registry" logging to the Application log.
- `odr.exe` was not on PATH and no `$`-suffixed agent accounts existed. Inference: the plumbing ships inbox in 26H2, the feature is gated.

### 2. Microsoft's own control plane on top (the user-supplied Agent 365 doc and what it links to)

- **Agent 365** GA 2026-05-01, per-user licence, "works best" with E5. Registry in the M365 admin center has an "Unmanaged agents" counter and a Graph API (`GET /v1.0/copilot/admin/catalog/packages`, scope `CopilotPackages.Read.All`, preview). [Overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview), [registry](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview).
- **Defender local agent discovery** ([doc, 2026-11-02](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)): Windows (Defender platform 4.18.26090.9+) and macOS (101.26072.0017+), MDE Plan 2. Process-based plus MCP-config discovery plus periodic VS Code extension inventory. Hunting table `AgentsInfo` with `Platform == "LocalAgents"`; `RawAgentInfo.localAgentMetadata` carries `vendor`, `relatedProcess`, `trustedProcess`, `autoApprove`, `accountSid`, `localMcps`. Exposure graph edges `runs on`, `uses` (mcp/server), `used by`. One inventory row per agent per device per account. Risk scoring needs E7 or Agent 365.
- **Defender runtime protection** ([preview, 2026-09-25](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection)): Windows only. Two methods, each Disabled / Audit / Block: `AiAgentProtection` ("agent-native event inspection" for agents with "vendor-supported agent event interfaces", i.e. hooks) and `AiAgentNetworkInspection` (for agents without). Scope is prompt-injection detection; alert name "Suspicious AI prompt injection"; block message is rendered inside the agent terminal.

### 3. BeyondTrust AI Agent Security (user-supplied doc, updated 2026-10-13)

[Doc](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security). "Pathfinder" endpoint agent. Windows 11 / Server 2022+ x64 only (no Arm); macOS 14, 15, 26. Classifiers use process naming, signatures and LLM API traffic patterns. Enforcement "at the kernel and network levels", plus tool-call policy for agents that support hooks. Requires a tenant root certificate trusted on each endpoint for HTTPS inspection, and system extensions approved by MDM on macOS. Outcomes: allow / audit / require approval / block. Explicitly does not inspect prompts. Policies can be replayed against recorded activity before saving. No Linux.

### 4. macOS 27, App Intents, Apple Intelligence, TCC

Verified from Apple's release-note JSON (beta-era notes, partially read):
- **App Intents (June 2026)**: `OwnershipProvidingEntity` / `EntityOwnership` (system prompts before destructive actions on shared entities), `UndoableIntent`, `CancellableIntent`, `LongRunningIntent`, `allowedExecutionTargets`, `supportedModes`, `SyncableEntity`. Apple Intelligence invokes actions through system app schemas (`app-schema-domains`). [App Intents updates](https://developer.apple.com/documentation/updates/appintents).
- **TCC and data protection**: "Apps can no longer access the local TCC database directly". Cross-team app container and group container access is denied by default with no prompt. XProtect "may now restrict access to app data commonly targeted by malicious software". A process with no bundle ID cannot be granted Files and Folders access to other teams' containers (workaround: Full Disk Access). [macOS 27 release notes](https://developer.apple.com/documentation/macos-release-notes/macos-27-release-notes).
- **Xcode 27**: ACP support; agent plug-ins bundling skills, MCP servers and ACP configurations; standalone MCP server (`sudo xcrun mcp-server enable`, with a `--unsafe-always-allow-all-agents` switch); a "filesystem security layer" that "monitors and controls filesystem access by coding agents and their child processes". [Xcode 27 release notes](https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes).
- **Not found**: any agent account, agent identity in TCC, or third-party audit stream of intents invoked by Apple Intelligence. Inference: on macOS, attribution stays with responsible-process and code-signing identity from Endpoint Security, plus TCC grants (Accessibility, Screen Recording, Automation) as the inventory of computer-use-capable apps.

### 5. Browsers: built-in agents and WebMCP

**WebMCP** ([repo](https://github.com/webmachinelearning/webmcp), spec status `CG-DRAFT`, pushed 2026-11-09):
- `document.modelContext.registerTool(tool, {signal, exposedTo})`, `getTools({fromOrigins})`, `executeTool(tool, args)`, `toolchange` event, `toolactivated` event (`ToolActivatedEvent.toolName`). Earlier drafts used `navigator.modelContext`; code written against that is stale.
- Annotations: `readOnlyHint`, `untrustedContentHint`, `consequentialHint`. The spec itself notes a malicious site can omit or misrepresent them.
- Permissions Policy `tools` (default `self`); cross-origin frames need `allow="tools"`.
- Declarative form API (`toolname`, `tooldescription`, `toolautosubmit`, `SubmitEvent.agentInvoked`, `:tool-form-active`) is an explainer only, "not part of the specification at this time".
- A `toolcall` event for observers was considered and not adopted. There is no audit hook for extensions or for enterprise.
- Implementation: Chrome 149 origin trial, flag `chrome://flags/#enable-webmcp-testing`; Edge 150 origin trial; Brave Leo experimental; ChatGPT Desktop supports it; Firefox and WebKit have open standards-position issues only. [Implementation status](https://github.com/webmachinelearning/webmcp/blob/main/implementation-status.md), [Chrome docs](https://developer.chrome.com/docs/ai/webmcp).
- Chrome docs state "extensions can query and execute tools through content scripts". That makes an extension both a possible agent and a possible monitor.

**Chrome enterprise policies** (read from [Chromium policy definitions](https://github.com/chromium/chromium/tree/main/components/policy/resources/templates/policy_definitions/GenerativeAI)):

| Policy | Since | Effect |
|---|---|---|
| `GeminiSettings` | 137 | Gemini integration on/off |
| `GeminiActOnWebSettings` | 143 | Allow Gemini to act on pages (default allowed) |
| `GeminiActOnWebAllowedForURLs` / `BlockedForURLs` | 146 | Per-URL actuation lists |
| `GeminiSparkSettings` | 150 | External "Gemini Spark" agent may connect to Chrome and use auto browse; default disabled; description warns "Existing management and security controls might not be respected" |
| `EnterprisePublishedSkills` | future | Admin-published skills, URL plus SHA-256, max 10 |
| `GenAiDefaultSettings` | | Default for all GenAI policies |

No WebMCP-specific policy exists in that group (other policy groups were not searched).

**Edge** ([policy list](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies), partially read): new in 158 are `AgentProfileEnabled`, `CopilotBrowserUseAllowList`, `CopilotBrowserUseBlockList`, `CommercialJourneysGetThingsDoneEnabled`; also `CopilotCoworkToolActionsEnabled`, `CopilotOnSensitiveContentEnabled`, `BuiltInAIAPIsEnabled`. `BrowsingWithCopilotAllowList` / `BlockList` are obsolete in 158.

**Safari 27**: nothing on WebMCP, agents or Web Bot Auth in the portion read.

### 6. Agent Client Protocol (ACP)

- **Shape** ([protocol overview](https://agentclientprotocol.com/protocol/overview)): agent methods `initialize`, `authenticate`, `session/new`, `session/prompt`, optional `session/load`, `session/set_mode`, notification `session/cancel`. Client methods `session/request_permission`, optional `fs/read_text_file`, `fs/write_text_file`, `terminal/create|output|release|wait_for_exit|kill`, `elicitation/create`; notification `session/update`.
- **Tool calls** ([tool-calls](https://agentclientprotocol.com/protocol/tool-calls)): `tool_call` and `tool_call_update` carry `toolCallId`, `title`, optional `name`, `kind` (`read`, `edit`, `delete`, `move`, `search`, `execute`, `think`, `fetch`, `switch_mode`, `other`), `status`, `rawInput`, `rawOutput`, `locations`, and `diff` content with `oldText` / `newText`.
- **Permission**: options have `kind` in `allow_once`, `allow_always`, `reject_once`, `reject_always`. These are UI hints; "the Agent stores remembered decisions and decides their scope". "Clients may allow or reject automatically based on user settings".
- **Transport** ([transports](https://agentclientprotocol.com/protocol/transports)): stdio only, newline-delimited UTF-8, client spawns agent as a subprocess. Remote transport is a draft RFD: Streamable HTTP (HTTP/2 required, `Acp-Connection-Id`, `Acp-Session-Id`) plus WebSocket on one `/acp` endpoint.
- **Proxy chains RFD**: a "conductor" that looks like an ordinary agent to the client and routes through proxies using `proxy/successor`. This is the upstream-blessed interception design. A separate RFD defines MCP-over-ACP (`"type": "acp"` MCP servers, targeting MCP 2026-07-28).
- **Ecosystem**: repo 4.6k stars, Apache-2.0; SDKs for Rust, TypeScript, Python, Kotlin, Java; adapters `claude-agent-acp` (2.7k stars) and `codex-acp`. [Registry](https://github.com/agentclientprotocol/registry) at `https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json`, about 50 entries, hourly auto-update from npm / PyPI / GitHub releases, a `quarantine.json`, and JetBrains-specific indexes. Only agents that return `authMethods` are listed.
- **Name collision**: "ACP" also means the OpenAI/Stripe Agentic Commerce Protocol and IBM's former Agent Communication Protocol (prior knowledge). Always spell it out in schemas.

### 7. Synthetic input versus human input

| Platform | Signal | Where readable | Reliability |
|---|---|---|---|
| Windows | Separate agent session and agent-account SID | Process token, session ID | Deterministic when agent workspace is used |
| Windows | `LLKHF_INJECTED` / `LLMHF_INJECTED`, `*_LOWER_IL_INJECTED` | `WH_KEYBOARD_LL` / `WH_MOUSE_LL` hooks | Strong for `SendInput`; set by OS; no source PID (prior knowledge) |
| Windows | `INPUT_MESSAGE_SOURCE.originId` = `IMO_INJECTED` | `GetCurrentInputMessageSource`, in-process only ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-input_message_source)) | Strong but only inside the receiving app |
| Windows | UI Automation pattern calls | No input event is produced | Invisible to input flags; needs process attribution of the UIA client (inference) |
| macOS | `kCGEventSourceUnixProcessID`, `kCGEventSourceStateID` | CGEventTap | Strong; hardware events report PID 0 (prior knowledge) |
| macOS | Accessibility / Screen Recording / Automation TCC grants | MDM PPPC, Endpoint Security TCC events; not the database in macOS 27 | Capability inventory, not per-action |
| Linux | `/dev/uinput` opens, virtual devices with `BUS_VIRTUAL` | eBPF / LSM / audit, `/proc/bus/input/devices` | Strong for uinput; XTEST and portal `RemoteDesktop` + libei are separate paths (prior knowledge) |
| Browser | `--remote-debugging-port` / `--remote-debugging-pipe`, `DevToolsActivePort`, `chrome.debugger` | Process command line, profile dir, extension API | Strong for CDP agents; Chrome 136+ ignores the switch on the default profile (prior knowledge) |
| Browser | `navigator.webdriver`, `SubmitEvent.agentInvoked`, `toolactivated` | Page and content scripts | Weak to medium; CDP input events are `isTrusted` |

### 8. Other protocols

- **Web Bot Auth**: [draft-ietf-webbotauth-httpsig-protocol-01](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) (2026-10-29, Cloudflare and Google authors). RFC 9421 signatures with `Signature-Agent`, `tag="web-bot-auth"`, JWK-thumbprint `keyid`, directory at `/.well-known/http-message-signatures-directory`; Ed25519 or RSA-PSS; no shared secrets. Eleven related individual drafts, including a registry draft and a signed-agent-metadata draft (2026-11-02).
- **AP2** ([ap2-protocol.org](https://ap2-protocol.org/)): v0.2. Mandates are now **Checkout Mandate** and **Payment Mandate**, each with Open and Closed stages (the 2025 Intent/Cart naming is gone). Signed verifiable digital credentials; human-present and human-not-present flows; extension of A2A and MCP; donated to the FIDO Alliance; Apache-2.0.
- **AG-UI** ([events](https://docs.ag-ui.com/concepts/events)): pre-1.0 event stream between agent back ends and front ends: `RunStarted`, `ToolCallStart|Args|End|Result`, `StateSnapshot|Delta`, `SubagentStarted|Finished`, and a draft interrupt outcome on `RunFinished`. Relevant for embedding our approval UI, not for interception.

## Matrix

| Platform | Agent identity | Registry | Permission protocol | Audit a third party can read | Enterprise policy | Status (2026-11) |
|---|---|---|---|---|---|---|
| Windows agent workspace | Per-agent local account (`...$`), own session | ODR (`odr.exe`), AppExtension | Per-host consent, `AgentConsentDuration` | AgentConnector and MCP event channels (free text) | WindowsAI CSP, Enterprise/Edu only | Preview, opt-in |
| macOS 27 | None (responsible process) | None; App Intents schemas | TCC, `OwnershipProvidingEntity` | Endpoint Security only | MDM PPPC; no agent-specific keys found | Shipping |
| Chrome | None (profile user) | None; `chrome://skills` | Vendor UI | None documented | `Gemini*` policies | Shipping; WebMCP in OT |
| Edge | "Agent profile" (policy name only) | None | Vendor UI | None documented | `CopilotBrowserUse*`, `AgentProfileEnabled` | Shipping; WebMCP in OT |
| Safari | None | None | None | None | None found | No agent surface found |
| ACP editors | Agent ID in registry; `authMethods` | ACP registry JSON | `session/request_permission` | Full JSON-RPC stream if you are in the pipe | None | v1 stable, v2 alpha |
| WebMCP | Origin of tool; agent unnamed | Per-document tools | `consequentialHint`, UA dialogs | `toolactivated`, wrappers | Permissions Policy `tools` | CG draft |

## Weak points, gaps and risks

- **Preview drift.** Windows agent docs are 6 to 12 months old with "may be substantially modified" banners. Build anything against ODR and agent accounts behind a capability probe.
- **Enterprise-only policy.** Agent connector policies exclude Windows Pro, which is where single laptops and small MSP customers live.
- **Contained does not mean safe.** Contained MCP servers keep internet access, and folder consent is shared by every server behind one host.
- **Unstructured events.** `%1` payloads will need parsing that can break on any cumulative update.
- **ACP enforcement gap.** Agents that execute their own tools only emit `tool_call` notifications. A shim can cancel the session but cannot veto an action already running.
- **WebMCP has no observer API**, and annotations are author-controlled.
- **Gemini Spark** is an externally connected agent driving a signed-in Chrome profile; Google's own policy text says existing controls might not be respected.
- **macOS 27 breaks sensors that read `TCC.db`.**
- **Synthetic-input flags miss UIA / AX-pattern automation**, which is what better computer-use agents prefer.
- **Defender covers the same discovery ground for E5 customers** at no extra cost; our differentiation must be cross-EDR, Linux, enforcement breadth and openness.

## Implications for our design

Build:
1. **Platform-registry collectors** as first-class discovery sources: ODR (`odr mcp list`, AppExtension `com.microsoft.windows.ai.mcpServer`, agent launcher definitions), the ACP registry JSON as a signed fingerprint feed, editor ACP configuration, Chrome and Edge managed-policy state, Xcode agent plug-ins.
2. **An identity-based attribution tier above lineage heuristics.** Attribution result should carry its basis: `os_agent_account` (Windows agent SID or session), `sandbox_principal` (agent-created local users, restricted tokens), `protocol_asserted` (ACP session, hook payload), `lineage_inferred`, `traffic_inferred`. Policies can then require a minimum basis.
3. **An ACP conductor in Rust** using the official crate (v1.16.0): transparent stdio proxy, logs every `tool_call`, answers or forwards `session/request_permission`, enforces on `fs/*` and `terminal/*`. Ship it as a registry-listed wrapper so one install covers Zed, JetBrains, Neovim and Xcode. Track the proxy-chains RFD so we become a standard proxy rather than a fork.
4. **A Windows event collector** for the AgentConnector and ModelContextProtocol channels, tolerant parsing, raw event retained.
5. **A browser extension sensor** that wraps `document.modelContext.registerTool` in the main world to inventory tools and record `execute` invocations, listens for `toolactivated`, and reports CDP attachment. Pair it with policy templates for the Chrome and Edge keys above.
6. **A synthetic-input sensor per OS**, reported as evidence rather than verdict: LL-hook injected flags on Windows, CGEventTap source PID on macOS, uinput opens on Linux, remote-debugging switches for browsers.
7. **Policy export to native controls**: generate `AgentConnectorAccessPolicy` JSON, Chrome/Edge URL lists and macOS PPPC from our policy model, so the OS enforces where it can and our sensor covers the rest.

Reuse: ACP Rust SDK and schema; ACP registry; MCPB manifest format as the server descriptor; Web Bot Auth for signing our gateway's outbound agent traffic and for verifying inbound agents.

Avoid: depending on agent workspace for third-party agent attribution; reading `TCC.db`; treating WebMCP annotations as trustworthy; assuming ACP permission prompts fire.

**Effect on discovery design (topic 17).** Add a "declared" layer ahead of the "observed" layer: registries and platform policy state give cheap, high-precision inventory; process, file and network heuristics then find what is undeclared. The gap between the two sets is the shadow-agent report. Add local-principal enumeration (agent accounts ending in `$`, agent-created sandbox users) and capability-grant enumeration (TCC, uinput access, debugger ports) as discovery inputs.

## Ideas worth stealing and whitespace

- **Policy replay** against recorded activity before enforcing (BeyondTrust).
- **Static-response pinning**: Windows requires an MCP server's runtime `tools/list` to match its signed manifest. We can do the same as a rug-pull detector for any MCP server.
- **`autoApprove` and `trustedProcess` as posture fields** (Defender).
- **Audit then block rollout modes** per method (Defender).
- **Hash-pinned, admin-published skills** (Chrome `EnterprisePublishedSkills`).
- Whitespace: Linux has no vendor coverage in either Defender's or BeyondTrust's local-agent products. Nobody offers a cross-browser WebMCP audit trail. Nobody normalises agent identity across OS account, ACP session, browser profile and Web Bot Auth key. Nobody enforces on Windows Pro where the native policies are unavailable.

## Could not verify / open questions

- Whether agent workspace or agent connector policies have left Insider Preview in any 26H2 servicing release. Docs say no; no 2026 Insider release notes were reachable without search.
- SID structure, group membership and logon type of Windows agent accounts; whether Security log events (4624, 4688) show them distinctly. Needs a lab host with the feature enabled.
- Schema behind the `AgentConnectorAccessPolicy` fwlink, and how hosts are identified in it.
- "MXC", named in OpenAI's Codex Windows sandbox doc as native process isolation needing builds 26100.9278 / 26200.9278. No Microsoft documentation located.
- Whether Edge `AgentProfileEnabled` yields a distinct profile directory or identity a sensor can key on.
- Whether macOS 27 exposes any log of App Intents invoked by Apple Intelligence; remaining 40 percent of the Xcode 27 and 60 percent of the Safari 27 notes were not read.
- JetBrains and Zed on-disk ACP configuration paths (not fetched).
- Items marked "(prior knowledge)" in section 7; Visa Trusted Agent Protocol and Agentic Commerce Protocol were not researched.

## Sources

- https://support.microsoft.com/en-us/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3 - Experimental agentic features, updated 2025-12-05
- https://blogs.windows.com/windowsexperience/2025/10/16/securing-ai-agents-on-windows/ - Securing AI agents on Windows, 2025-10-16
- https://learn.microsoft.com/en-us/windows/ai/mcp/overview - MCP on Windows overview, updated 2026-06-04
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment - Containing MCP servers, updated 2025-12-04
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-windows-identity - Register with package identity, updated 2025-12-16
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-manual - Manual registration, updated 2025-11-18
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/test-mcp-server - Test MCP servers, 2026-10-28
- https://learn.microsoft.com/en-us/windows/ai/mcp/odr-tool - odr.exe, updated 2025-11-18
- https://learn.microsoft.com/en-us/windows/ai/agent-launchers/ - Agent Launchers, updated 2025-12-12
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai - WindowsAI Policy CSP, 2026-10-14
- https://github.com/pl4nty/web-admx-tool - ADMX mirror, CAM_AI.admx, 2026-10-01
- https://joeloveless.com/blog/intune-settings-catalog-settings-win11-26h2/ - Intune settings in 26H2, 2026-10-04
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Agent 365 overview, updated 2026-10-23
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview - Agent Registry, 2026-09-21
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents - Discover local AI agents, 2026-11-02
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection - Runtime protection (preview), 2026-09-25
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai - Defender security for AI, 2026-10-30
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - BeyondTrust AI Agent Security, 2026-10-13
- https://learn.chatgpt.com/docs/windows/windows-sandbox - Codex Windows sandbox (redirect from developers.openai.com/codex/windows), fetched 2026-11-09
- https://developer.apple.com/documentation/updates/appintents - App Intents updates, June 2026
- https://developer.apple.com/documentation/macos-release-notes/macos-27-release-notes - macOS 27 release notes
- https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes - Xcode 27 release notes
- https://developer.apple.com/documentation/safari-release-notes/safari-27-release-notes - Safari 27 release notes (partial)
- https://github.com/webmachinelearning/webmcp - WebMCP spec, explainer, implementation status, security questionnaire, 2026-11-09
- https://developer.chrome.com/docs/ai/webmcp - Chrome WebMCP docs
- https://developer.chrome.com/blog/webmcp-epp - WebMCP early preview, 2026-02-10
- https://github.com/chromium/chromium/tree/main/components/policy/resources/templates/policy_definitions/GenerativeAI - Chromium GenAI policy definitions, read 2026-11-09
- https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies - Edge policy list (partial)
- https://agentclientprotocol.com/protocol/overview, /protocol/tool-calls, /protocol/transports, /get-started/agents, /get-started/clients - ACP docs
- https://github.com/agentclientprotocol/agent-client-protocol - ACP repo, RFDs (proxy-chains, streamable-http-websocket-transport, mcp-over-acp), releases 2026-11-09
- https://github.com/agentclientprotocol/registry - ACP registry
- https://datatracker.ietf.org/wg/webbotauth/documents/ and https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/ - Web Bot Auth, 2026-10-29
- https://ap2-protocol.org/ - AP2 v0.2
- https://docs.ag-ui.com/concepts/events - AG-UI events
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-input_message_source - INPUT_MESSAGE_SOURCE
- Local read-only inspection of a Windows 11 Pro 10.0.26300 host (`wevtutil el`, `wevtutil gp`, `wevtutil gl`), 2026-11-09

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. The shared WebSearch budget was exhausted, so every verdict rests on direct fetches of primary documents and read-only GitHub API calls (spec source, policy YAML, registry JSON, crates.io, IETF Datatracker). No later Microsoft announcement about agent workspace could be searched for._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Agent workspace: per-agent account, separate Windows session, off by default, admin-enabled device-wide, still private preview for Insiders (page updated 2025-12-05) | confirmed | Page text matches on every point. Two cautions: the page says "private preview for Windows Insiders in a release coming soon", while the Learn MCP docs call the agent connector feature "public preview". The 26H2 "What's new" page (2026-09-29) does not list agent workspace or agent connectors as shipped features, which is consistent with still-preview. No newer statement could be searched. | [support page](https://support.microsoft.com/en-us/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3), [26H2 what is new](https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11-version-26h2) |
| 2 | Only binary MSIX-identity MCP servers in ODR run contained; MCP bundles and unpackaged servers cannot; contained servers keep internet access; folder consent is per host | confirmed | Corroborated by a second page: the MCP bundle doc says bundles "are not supported in the agent session" and are not accessible from ODR by default. "Package identity" includes MSIX with external location, and the servers Windows itself provides are contained too. | [mcp-mcpb](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-mcpb), [mcp-containment](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment) |
| 3 | WindowsAI CSP has `AgentConnectorAccessPolicy`, `ConfigureAgentConnectors`, `AgentConsentDuration`, `OnDeviceRegistryLoggingLevel`; device scope; Enterprise/Education/IoT Enterprise only; Windows Insider Preview as of 2026-10-14 | confirmed | All four: Device only, Pro excluded, "Windows Insider Preview". ms.date 2026-10-14, page updated_at 2026-10-23. Values and defaults in the brief's table match. | [policy-csp-windowsai](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai) |
| 4 | ACP defines only stdio; Streamable HTTP + WebSocket remote transport is still a draft RFD | confirmed | v1 and v2 transports pages both say "currently defines one transport mechanism". One label fix: the RFD sits in the **Active** lifecycle group, not Draft (stages are Draft, Active, Preview, Completed). Active is "a visibility signal, not a stability commitment"; last edited 2026-10-30. | [docs/protocol/v1/transports.mdx, docs/docs.json, docs/rfds/about.mdx](https://github.com/agentclientprotocol/agent-client-protocol/tree/main/docs) |
| 5 | `session/request_permission` is agent to client; kinds `allow_once`, `allow_always`, `reject_once`, `reject_always`; agent stores remembered decisions; an agent that never asks cannot be vetoed this way | confirmed | Spec source: "The Agent MAY request permission", "The Agent owns remembered decisions". v2 keeps the method name but restructures params. | [tool-calls.mdx](https://github.com/agentclientprotocol/agent-client-protocol/blob/main/docs/protocol/v1/tool-calls.mdx) |
| 6 | ACP registry lists about 50 agents at a CDN JSON index updated hourly; latest schema release v1.30.0 on 2026-11-09, Apache-2.0 | corrected | The live index has **45** agents (all twelve named ones present). Hourly cron and CDN URL confirmed. `schema-v1.30.0` (2026-11-09) is a release of the **protocol repo** `agentclientprotocol/agent-client-protocol`, not of the registry; the registry uses date tags (`v2026.11.10-...`) and its JSON carries `"version": "1.0.0"`. Both repos are Apache-2.0. | [registry.json](https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json), [protocol releases](https://github.com/agentclientprotocol/agent-client-protocol/releases) |
| 7 | WebMCP is a CG draft with `document.modelContext` (`registerTool`, `getTools`, `executeTool`, `toolactivated`); origin trials in Chrome 149 and Edge 150; no observer or audit API; Safari and Firefox have only open standards-position issues | corrected | API, CG-DRAFT status and origin trials confirmed (there is also a `toolcancel` event). The last part is wrong: both position requests are **closed with positions**. WebKit: **oppose** (issue 670, closed 2026-06-11; concerns include security, privacy, duplication). Mozilla: **neutral** (issue 1412, closed 2026-08-05). Plan for WebMCP as Chromium-only. | [WebKit #670](https://github.com/WebKit/standards-positions/issues/670), [Mozilla #1412](https://github.com/mozilla/standards-positions/issues/1412), [index.bs](https://github.com/webmachinelearning/webmcp/blob/main/index.bs) |
| 8 | Chrome policies `GeminiSettings` (137+), `GeminiActOnWebSettings` (143+), `GeminiActOnWebAllowedForURLs`/`BlockedForURLs` (146+), `GeminiSparkSettings` (150+, default disabled); no WebMCP policy in the GenerativeAI group | confirmed | Versions are the desktop ones (Android and iOS land later, up to 158; `GeminiSettings` on Linux is still `future_on`). Spark default is 1 = Disabled. Stronger than claimed: a scan of all 1,595 policy definition files in every group finds no WebMCP or modelContext policy. | [policy_definitions](https://github.com/chromium/chromium/tree/main/components/policy/resources/templates/policy_definitions) |
| 9 | Defender for Endpoint discovers local agents and MCP servers on Windows and macOS with Plan 2; `AgentsInfo` with `autoApprove`, `trustedProcess`, `accountSid`, `localMcps`; runtime protection is Windows-only preview | confirmed | Support matrix (2026-11-02) adds: discovery is generally available except macOS VS Code extension entries and WSL (three agents), which are preview; native Linux is not supported. The four fields live under `RawAgentInfo.localAgentMetadata` and the two booleans are reported as strings. | [support matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix), [runtime protection overview](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview) |
| 10 | macOS 27 removes direct access to the local TCC database and denies cross-team container access by default; no agent identity or TCC attribution in the notes | confirmed | Full text of the notes was searched: the TCC item is under "TCC > Deprecations" (90775556), the container item under "System Integrity Protection" (161835690). The only "agent" hit is launchd agents. The notes do not say whether a Full Disk Access holder is also blocked from the database; test before assuming either way. | [macOS 27 release notes](https://developer.apple.com/documentation/macos-release-notes/macos-27-release-notes) |
| A | Brief, design item 3: build an ACP conductor "using the official crate (v1.16.0)" | corrected | 1.16.0 is `agent-client-protocol-schema` (types only). The official Rust SDK crate `agent-client-protocol` is at **5.1.0** in a separate repo, and that repo already ships `agent-client-protocol-conductor` 5.1.0 with Proxy and Conductor roles. Reuse it instead of writing one. | [rust-sdk](https://github.com/agentclientprotocol/rust-sdk), [crates.io](https://crates.io/crates/agent-client-protocol) |
| B | Brief, TL;DR and design item 3: ACP enforcement is deterministic on `fs/*` and `terminal/*` | corrected | True for v1 only. ACP v2 (alpha.14) **removes** `fs/read_text_file`, `fs/write_text_file`, all `terminal/*` client methods, `session/set_mode` and the `tool_call` notification (the first `tool_call_update` creates the call). The RFD says the v1 surface "has not been widely adopted". Do not make it the enforcement backbone; in v2 the remaining levers are `session/request_permission` and client-provided MCP servers. | [v2 migration](https://github.com/agentclientprotocol/agent-client-protocol/blob/main/docs/protocol/v2/migration.mdx), [RFD](https://github.com/agentclientprotocol/agent-client-protocol/blob/main/docs/rfds/v2/client-filesystem-terminal-capabilities.mdx) |
| C | Brief, whitespace: Linux has no coverage in Defender's or BeyondTrust's local-agent products | confirmed | BeyondTrust: "supports Windows and macOS endpoints only". Defender: native Linux absent, but WSL discovery of Claude Code, Codex CLI and Copilot CLI is in preview, so "no Linux" should read "no native Linux". | [BeyondTrust doc](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security), [support matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix) |
