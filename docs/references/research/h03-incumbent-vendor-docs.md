# Incumbent EDR, XDR, SASE and identity vendors: agent-security teardown (search-backed)

_Researched 2026-11-10 (search-backed follow-up)_

**Method.** 18 web searches (5 extended) plus about 50 direct fetches and read-only `gh` calls. Evidence labels: **[P]** primary vendor doc, release note, press release or repository read this session; **[S]** secondary or third-party summary; **[NV]** not verified. `sentinelone.com` returned HTTP 429 on every fetch, so its press release was read through a wire mirror. The GitHub search API hit a shared rate limit part-way through, so the repository sweep covers only six vendor organisations.

## TL;DR

- **Palo Alto now sells the "enhance the EDR you already run" position.** Cortex XDR 6.x (November 2026 release notes) ships a **Cortex Targeted Sensor** that runs Agentic Endpoint Security (AES) "alongside existing third-party EDRs", licensed as XDR ONE, AES or the ITDR add-on. [P]
- **Cortex AES uses agent hooks first and OS interception second.** Hooks capture "every prompt, shell command, file read, tool invocation, and network call"; apps without hooks (Hermes, ChatGPT, OpenClaw, Claude Desktop) need the full XDR sensor, which "intercepts the outgoing prompts". The mechanism and the OS list are not published. [P]
- **SentinelOne launched Singularity Agentic Detection and Response on 2026-10-21, early access only.** It claims inventory of "every agent, tool, skill, connector, and MCP server across endpoints, SaaS, and cloud providers" and per-agent containment. No public technical documentation exists. [P press, mechanism NV]
- **Netskope publishes the most precise endpoint discovery doc of any SASE vendor, and it is narrow**: periodic signature scan, Windows 64-bit and macOS only, Client 138+, eight named agents, default interval 60 minutes, and "only assets listed in Netskope's AI Signature file are detected". No VM, container or Linux coverage. [P]
- **Zscaler has two separate things**: AI Endpoint Security (blog 2026-10-08, "rolling out to customers now", mechanism and OS unstated) and AI Guard "Detection as a Service", whose MIT integration repo ships Python hooks for Claude Code, Codex CLI, Cursor, Cline and Windsurf. [P]
- **Zscaler's own install guide overwrites other vendors' hooks.** The Quick Start copies a whole `settings.json` over `~/.claude/settings.json`; the "merge" one-liner replaces the entire `hooks` key. Default hook timeout is 30 seconds per cloud call. This is the first concrete, documented hook-slot collision. [P]
- **Check Point Workforce AI Security** has four endpoint collectors (browser extension, desktop proxy, IDE integrations, MCP visibility), a script-based "Agentic Endpoint Discovery" with no resident agent, and Agent Policies with Allow, Ask or Block per MCP tool. Windows and macOS only. [S, a training copy of the admin guide; the official page returned 404]
- **Identity vendors do not build endpoint sensors.** Okta for AI Agents discovers "locally running agents and MCP servers" through a **CrowdStrike Falcon** integration and shadow AI through a browser plugin. Jamf pushes vendor-native managed configuration by DDM. 1Password keeps credentials out of the model context. [P]
- **Trend Micro started a hook standard.** `trendmicro/agent-hook-unity` (MIT and CC BY 4.0, created 2026-09-09) is a draft "portable lifecycle-hook protocol" with 18 canonical events and a "minimum cross-handler deny guarantee". Zero stars, not accepted. [P]
- **Datadog is the only incumbent that documents rate limits and overload behaviour**: 14 million tokens and 700 requests per minute per organisation; over the limit, integrations "let the call proceed unevaluated". Coding-agent protection is Preview. [P]
- **Documentation is gated across the category.** Koi, Noma, Knostic and Operant docs redirect to GitBook sign-in; Wiz docs need login; Zenity docs render only navigation; Cisco AI Defense docs were unreachable. Open, ungated docs and a published fail-mode table are themselves a differentiator.
- **No evidence found** of a local-agent discovery or enforcement product from Sophos, Bitdefender, ESET, Tanium, Fortinet, Orca or Iru. One extended search returned nothing; treat as absence of evidence, low confidence.

## Findings

### 1. EDR and XDR incumbents

**Palo Alto Networks: Cortex XDR One and Agentic Endpoint Security (Koi)**

- Release highlights for Cortex XDR 6.x, November 2026 [P] ([release notes](https://cortex-docs.paloaltonetworks.com/cortex-xdr-6.x-rn/release-information/features-introduced-in-2026/november-2026/release-highlights)):
  - *Extend AES with XDR ONE*: single console and sensor; discover the endpoint AI stack, govern supply-chain risk "against risky components or silent updates", apply runtime guardrails. Licence: XDR ONE or AES.
  - *Runtime Protection and AI Detection & Response*: "Captures every action an AI coding agent takes into a session-centric audit trail" and "intercepts policy-violating actions before they execute". Licence: AES.
  - *Cortex Targeted Sensor*: runs AES or AD posture management alongside third-party EDRs, with a later switch to the full sensor. Licence: XDR ONE, AES or ITDR add-on.
  - *AIDR: AI agent context*: using process causality tracking, the analytics engine "flags AI agent involvement in the issue" and can adjust severity.
  - *Native Application Control*: allow, block or alert per executed binary.
  - On-sensor small language models for obfuscated scripts, working offline.
- Launch blog, 2026-10-19 [P] ([blog](https://www.paloaltonetworks.com/blog/security-operations/cortex-xdr-6-0.md/)): AES "discovers every agent, MCP server, plugin, model, and extension and scores the real risk each one introduces" from publisher identity, code composition and runtime behaviour, re-scored continuously. Standalone AES covers coding agents "with built-in hooks". Runtime policy templates are mapped to MITRE ATLAS. App-control policies apply at publisher, application or file level, scoped to device groups, with a test mode.
- `PaloAltoNetworks/AppSecMCP` (MIT, pushed 2026-11-02) [P]: Claude Code and Cursor plugins. Hooks run the `cortexcli` binary on every file write or edit for secrets and SCA scanning; the Cursor hook file uses a `failClosed` field. ([repo](https://github.com/PaloAltoNetworks/AppSecMCP))
- Not published: supported OS list, named-agent matrix, hook contract versions, fail mode, price. Koi product docs redirect to sign-in. The earlier claim (brief 06) that Koi covers macOS, Windows and Linux for Cursor, Claude Code and Antigravity remains secondary. Prisma AIRS, Protect AI and Idira were not re-read this round.

**SentinelOne: Singularity ADR, Prompt Security, Purple AI**

- Singularity Agentic Detection and Response, announced 2026-10-21 at OneCon, "immediately available in early access" [P via mirror] ([release](https://www.stocktitan.net/news/S/sentinel-one-launches-singularity-agentic-detection-and-response-to-77tany7rhvun.html)). Claims: inventory across endpoints, SaaS and cloud; in-line prevention before an action executes; it "goes beyond the MCP gateway"; agent containment that stops one agent without halting a workflow; approval workflows for high-risk tools; intent-drift detection. Named platforms: Salesforce Agentforce, Microsoft Copilot Studio, ChatGPT workspace agents, Claude managed agents. Claude Code, Cowork and Codex are mentioned only as context.
- It builds on Prompt AI Agent Security (March 2026, RSAC), whose status is reported inconsistently as preview or GA [S].
- Prompt Security modules per a third-party review updated 2026-10-07 [S] ([review](https://appsecsanta.com/prompt-security)): AI Usage Control (browser extension), Agentic AI Security (MCP gateway, shadow MCP mapping), AI Application Security (API). Price is not public. Self-hosting predates the acquisition and is unconfirmed now.
- The only mechanism evidence for the endpoint agent is still the single hands-on review cited in brief 06 (local intercepting proxy, tenant root CA, proxy environment variables for CLIs). No source shows SentinelOne using agent hooks.
- `Sentinel-One/purple-mcp` (MIT, 102 stars, pushed 2026-10-28) exposes Purple AI and alerts over MCP [P]. `prompt.security` hosts no documentation; only ClawSec, OneClaw and a fuzzer [P].

**Trend Micro (TrendAI)**

- TrendAI Agentic Governance Gateway was announced 2026-03-24 on top of Vision One, framed around OpenClaw-style agents [S]. No endpoint agent-discovery documentation was found.
- `trendmicro/agent-hook-unity` [P] ([repo](https://github.com/trendmicro/agent-hook-unity)): draft 0.1, wire identifier `agent-hook-unity/0.1`, 18 canonical `hook_event_name` values (session and turn lifecycle, prompts, model requests and responses, tool use, permission outcomes, subagents, network requests, memory writes, configuration changes), a "12 Gate / 6 Observe registry", per-event capability claims of `gate`, `observe`, `partial` or `unavailable`, and a conformance scenario for gate composition. The README states it is "not an active standard until accepted".
- Also MIT: `vision-one-mcp-server` (41 stars).

**Datadog AI Guard** [P] ([docs](https://docs.datadoghq.com/security/ai_guard/))

- Evaluates prompts, responses and tool calls including the system prompt. Text and images only.
- Runs in the Datadog SDK (Python, Node.js, Java, Ruby), automatic integrations (LangChain, OpenAI SDK, Anthropic SDK, AI SDK, RubyLLM), manual ones (Amazon Strands, LiteLLM Proxy), or a plain HTTP API.
- Verdict `ALLOW` or `DENY` with a reason; "monitor only" or "block unsafe" modes.
- Limits: 14 million tokens and 700 requests per minute per organisation. Over the limit the API returns 429; integrations let the call proceed unevaluated, while direct SDK calls raise `AIGuardClientError`.
- Two-pass evaluation: fast classifier, then an LLM if flagged. Text typically under 100 ms. All evaluation is processed in the US; unavailable on the government sites.
- "Coding agent protection, such as Claude Code, is in Preview", by request form.

**Sysdig, Elastic** — nothing new beyond brief g02 and 06; the guessed Sysdig AI Defense doc URL returned 404.

**Sophos, Bitdefender, ESET, Tanium, Fortinet, Orca** — no agent-discovery or agent-enforcement product surfaced [NV].

### 2. SASE and network vendors

**Netskope One AI Security** [P] ([Client AI Discovery](https://docs.netskope.com/en/netskope-client-ai-discovery/))

- "Periodic signature-based scanning"; interval 1 to 1,440 minutes, default 60. Results go to the AI Command Center.
- Platforms: "Windows (64-bit) and macOS endpoints only". Client 138 minimum; AI Agent Network Telemetry needs 140.0.0; Codex detection needs 142.0.0.
- Named agents: Claude Desktop, ChatGPT Desktop, Microsoft Copilot, Claude Code, OpenClaw, Perplexity Comet, Perplexity Desktop, Codex. Local runtimes: Ollama, LM Studio, Jan AI, GPT4All. IDE extensions in VS Code and Cursor; browser extensions in Chrome, Edge and Safari.
- Per asset: process name, PID, PPID, binary and install path, version, and connected MCP servers or LLMs (local connections only). Network telemetry adds source and destination IP and port, destination hostname and byte counts.
- Documented limits: signature-file assets only; on shared machines only the active user's default browser and IDE profile; assets in VMs or containers are not detected unless the Client runs inside; an MSIX app never launched does not appear.
- Discovery is inventory only. Enforcement is in the Agentic Broker (a proxy that decodes MCP sessions, tool requests and responses), AI Guardrails, "AI Guardrails On Demand" (hosted REST API for LiteLLM, Kong, Apigee) and AI Gateway, shipped in R140 and R141 (September 2026) [P] ([monthly update](https://community.netskope.com/monthly-updates-hub-147/monthly-updates-september-2026-8970)).

**Zscaler**

- AI Endpoint Security [P blog, 2026-10-08] ([blog](https://www.zscaler.com/blogs/product-insights/ai-endpoint-security-closes-zero-trust-gap)): inventory below the app level (config files, skill files and prompts, MCP servers, agent definitions, memory stores, model files, persistence mechanisms). Runtime capture of prompts, responses, tool calls, skill files, file access, process and data lineage, and network connections, with reconstruction of an agent run including subagents. Enforcement claims: halt dangerous commands, block unauthorised agents, stop malicious skill files. Named: Claude Code, Cowork, Codex, Gemini, Copilot, OpenClaw, Hermes, Cursor, Windsurf, Comet, Atlas. Mechanism, OS list and relationship to Client Connector are not stated.
- AI Broker with Agent Registry (announced 2026-06-09): inline on MCP and A2A traffic with fine-grained access control [P blog] ([blog](https://www.zscaler.com/blogs/product-insights/how-zscaler-secures-the-agentic-ai-era)).
- AI Guard integrations repo [P] ([repo](https://github.com/zscaler/zguard-ai-integrations), MIT, 6 stars, pushed 2026-10-15): hooks for five coding agents; plugins for Kong, LiteLLM, Portkey, Apigee, Azure APIM, NeMo Guardrails, TrueFoundry, n8n; CI steps for GitHub Actions and Jenkins. Detectors: prompt injection, DLP, toxicity, malicious URLs, gibberish, off-topic, competition. The Claude Code hooks cover `UserPromptSubmit`, `PreToolUse` (URLs and `mcp__.*`) and `PostToolUse`; default `AIGUARD_TIMEOUT=30`. The README documents a silent failure where a wrong policy setting lets policy blocks pass with no error, and that Cursor shows blocks as silent failures.

**Check Point Workforce AI Security and AI Defense Plane** [S for Workforce: a training copy of the admin guide] ([copy](https://wfai-doc.pages.dev/))

- Collectors: browser extension (web chat), desktop proxy (ChatGPT Desktop, coding assistants), IDE integrations, MCP server visibility.
- Editions: Essentials (web apps only, extension) and Enterprise (extension plus desktop agent, IDEs).
- Agentic Endpoint Discovery: "Script-based discovery (no resident agent)", by MDM or manual, Windows and macOS.
- Three policy layers: Access (app), Chats/DLP (prompt, upload, paste), Agent (MCP tools, URL and file reputation, prompt injection, moderation). Agent rules name MCP servers, tools, OS and platform with Allow, Ask or Block. Other actions: Detect, Prevent, Redact.
- Policy refresh about every 10 minutes. Retention 30 days by default. "Prompts not classified as sensitive are not stored." Maximum 100 Data Types. SIEM forwarding exists.
- Integrations: OpenAI Enterprise and Claude Enterprise Compliance APIs, Microsoft 365 Copilot, Devin, Bedrock AgentCore, Copilot Studio, Agentforce, n8n.
- Lakera-branded AI Agent Security is "an early access release" and says "native platform runtime integrations are on the roadmap"; runtime goes through the Guard API [P] ([docs](https://docs.lakera.ai/docs/agent-security)).
- A Check Point community thread titled "Problem when install Workforce AI Security Agent with third..." exists but returned 403; coexistence trouble is indicated, not confirmed.

**Cisco** — commercial AI Defense docs unreachable again. A third-party summary cites three runtime enforcement points (Multicloud Defense egress gateway, AI Defense Gateway, Inspection API), an MCP Security Profile governing in-flight calls when a tool definition changes after a scan, an Agent Runtime SDK and release 2026.8.2 [S, NV].

### 3. Identity, device management and browser

**Okta for AI Agents** [P] ([discover](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-discover.htm))

- Discovery sources, each an ISPM integration: Secure Access Monitor browser plugin (shadow AI), **CrowdStrike Falcon** (locally running agents and MCP servers), Salesforce Agentforce and Microsoft Copilot Studio (builder platforms).
- Registration is manual (custom agents) or imported; agents live in Directory > AI Agents with owners, credentials and a linked OIDC app. Cross App Access is available to all orgs. The "Okta for AI Agents - Core" SKU excludes ISPM and Privileged Access.

**Jamf AI Governance** [P] ([press release, 2026-06-30](https://www.jamf.com/resources/press-releases/jamf-launches-ai-governance-a-first-of-its-kind-native-ai-control-plane-for-mac/))

- GA for Claude Code, Claude Desktop and OpenAI Codex. Controls: model access, tenancy, network permissions, file system controls, MCP server restrictions. Policies "are in place offline and before a user's first login to an AI agent".
- Delivery through Blueprints and DDM as managed configuration, "resistant to local tampering" [P, AWS blog 2026-07-08] ([blog](https://aws.amazon.com/blogs/machine-learning/manage-ai-applications-on-mac-with-jamf-ai-governance-and-amazon-bedrock/)).
- Shadow AI visibility uses the existing telemetry agent: "No new agent is required". macOS only.

**1Password** [P] ([1Password for Claude, published 2026-11-04](https://support.1password.com/1password-claude/))

- Mac only; 1Password for Mac and extension 8.12.28+; Claude desktop (Cowork) with Claude in Chrome. Business admins enable "Allow AI agents to autofill for users".
- The user approves each request; the fill happens "through a secure channel outside the agent's view"; the model learns only which login was used. Exact URL match required; passkeys unsupported. No audit trail is described.
- Agentic Mode disables the extension's inline suggestions while active.
- Device Trust has an MCP server for fleet queries; no posture check that gates agent access was found [S].

**Island** [P product page] ([page](https://www.island.io/product/ai/enterprise-browser-for-agents))

- An MCP server inside the browser, a headless "Enterprise Browser for Agents", and a separate MCP Gateway. Policy can target users, agents or both; per-application read-only mode blocks writes.
- Island says it detects whether a human or an agent drives a session from inside the browser, and logs the person and the agent separately. No OS list, price or limits.

**Iru** — nothing found [NV].

### 4. Specialists and cloud posture vendors

- **Zenity**: docs still render only navigation. It lists integrations for Codex, Cursor AI, GitHub Copilot, Anthropic, Palo Alto Cortex XDR and CrowdStrike Falcon Discover [P nav only].
- **Noma, Koi, Knostic, Operant**: public doc sites redirect to GitBook visitor authentication [P].
- **Lasso** (blog 2026-09-28): "agentless" first, through existing EDR or MDM; intent check on each MCP tool call; admits agentless gives visibility "without device-level configuration detail" [P blog].
- **Harmonic**: browser extension, endpoint agent, MCP gateway; deploys by Intune, Jamf, Kandji or Group Policy [S].
- **HiddenLayer**: runtime ships as container images the customer runs in its own cloud or Kubernetes; no coding-agent specifics [P].
- **Wiz**: AI Studio covers Bedrock AgentCore, Gemini Enterprise Agent Platform, Copilot Studio and Agentforce; pre-commit scanning for Claude Code and Cursor through the Wiz MCP server and WizCLI is GA [S]. No workstation agent discovery found.
- **New endpoint entrants from DLP** [S, vendor-authored comparison 2026-08-11]: Nightfall (hooks for Cursor, Claude Code, VS Code; macOS and Windows; June 2026) and Cyberhaven (endpoint agent on Windows, macOS, Linux).

## Matrix

"n/s" means not stated in any source read. Bold marks facts verified in a primary source this round.

| Vendor | Discovers, and how | Enforces at | OS and agents | Fail mode | TLS interception | Policy and attribution | Export and API | Licence and price |
|---|---|---|---|---|---|---|---|---|
| Palo Alto Cortex AES | **Agents, MCP, plugins, models, extensions; risk score** | **Hooks; OS-level via XDR sensor; app control** | OS n/s; hooks for coding agents, sensor for Hermes, ChatGPT, OpenClaw, Claude Desktop | n/s (`failClosed` in Cursor plugin) | n/s | **ATLAS templates; session audit; process causality** | Cortex console | **XDR ONE or AES**; price n/s |
| SentinelOne ADR + Prompt | Endpoint, SaaS, cloud inventory (method n/s) | "In-line"; MCP gateway; extension; local proxy [S] | n/s; four SaaS platforms named | n/s | Yes on endpoint [S] | Containment per agent; approvals | Singularity | **Early access**; price n/s |
| Netskope | **Signature scan every 1 to 1,440 min** | Agentic Broker, AI Gateway, guardrail API | **Windows x64, macOS; 8 agents** | n/s | Implied by inline proxy | Inline DLP policy; user from Client | AI Command Center; REST guardrails | n/s |
| Zscaler | **Config-level inventory (method n/s)** | Endpoint agent; AI Broker; **hooks via AI Guard DAS** | OS n/s; **5 coding agents by hooks** | n/s; **30 s timeout** | Not for hooks | Detector actions Block or Detect | AI Guard console, local log | Repo MIT; product n/s |
| Check Point | Script (no agent); extension; desktop proxy | Extension, desktop proxy, IDE, Guard API | Windows, macOS | n/s | Implied by desktop proxy | Access, Chats, Agent layers; Allow, Ask, Block | SIEM forwarding; 30-day retention | Essentials or Enterprise |
| Datadog AI Guard | None (instrumented apps) | **SDK, gateway plugin, HTTP API** | 4 languages; Claude Code Preview | **Open on rate limit** | No | ALLOW or DENY; monitor or block | APM spans, 15 days | n/s |
| Okta | **Browser plugin; CrowdStrike Falcon; SaaS connectors** | Identity (XAA, resource connections) | Depends on Falcon | n/a | No | Agent identity with owners | System Log | Core SKU excludes ISPM |
| Jamf | **Existing telemetry agent** | **Managed config by DDM** | **macOS; Claude Code, Claude Desktop, Codex** | **Offline-safe** | No | Vendor-native settings | Jamf reports | Part of Jamf for Mac |
| 1Password | None | **Credential broker; `.env` hook** | **Mac; Claude** | User approval required | No | Human approves each fill | n/s | Business policy |
| Island | In-browser | **Browser MCP server; MCP gateway** | n/s | n/s | No (presentation layer) | **Human versus agent in session** | Audit events | n/s |
| Cisco AI Defense | n/s | Gateway, egress, Inspection API [S] | See DefenseClaw (g02) | See g02 | n/s | MCP Security Profile [S] | n/s | Commercial plus Apache-2.0 |
| Trend | n/s | Gateway [S]; hook spec draft | n/s | Spec defines deny guarantee | n/s | 18 events, gate or observe | Spec schemas MIT | n/s |

## Synthesis

**Shipped by at least three vendors (we must match):**

1. Named-agent, MCP-server and IDE or browser-extension inventory on Windows and macOS through an already deployed agent or MDM (Microsoft, Netskope, Zscaler, Palo Alto, Check Point, Jamf).
2. Hook-based pre-execution verdicts for Claude Code, Cursor and Codex (Microsoft, Palo Alto, Zscaler, Cisco, Noma, Nightfall; Datadog in preview).
3. An MCP broker or gateway with per-tool allow or block (Netskope, Zscaler, SentinelOne, Island, Harmonic, Check Point).
4. Allow, Ask, Block plus a detect-only mode (Check Point, Microsoft, BeyondTrust, Sysdig).
5. A hosted guardrail verdict API with LiteLLM, Kong and Portkey plugins (Zscaler, Netskope, Datadog, Lakera, Cisco).
6. Connectors for Agentforce, Copilot Studio and Bedrock AgentCore (SentinelOne, Okta, Check Point, Palo Alto, Wiz).
7. Session-centric audit with agent-run reconstruction (Palo Alto, Zscaler, SentinelOne, BeyondTrust).
8. Deployment beside a third-party EDR or with no new agent (Palo Alto Targeted Sensor, Okta through CrowdStrike, Jamf, Lasso, Noma).
9. MITRE ATLAS mapping of policy or detection content (Palo Alto, Netskope, Elastic).

**Documented by nobody:**

- Discovery of unlisted or bespoke agents by behaviour. Netskope and Microsoft both state the list is the limit.
- Coverage inside WSL, VMs and containers on a workstation, and native Linux desktops, from any SASE or identity vendor.
- A published fail-mode table from a commercial incumbent. Only Cisco's open-source DefenseClaw and Datadog's rate-limit note exist.
- Hook coexistence: ordering, merging, and what happens when two vendors register on the same event.
- Local, offline policy verdicts for tool calls. Hook integrations call a cloud API per event.
- Passive visibility of stdio MCP traffic.
- One attribution model spanning browser, CLI, IDE and SaaS. Island attributes in the browser, Palo Alto by process causality, Okta by registered identity; none joins them.
- Public prices and ungated technical documentation.

**Conflicts on one endpoint:**

- **Hook slots.** Zscaler's guide replaces the `hooks` key or the whole user settings file. Palo Alto, Noma and 1Password ship hooks as agent plugins; Microsoft and Jamf use managed configuration. With `allowManagedHooksOnly`, user-level installs silently stop running.
- **Latency stacking.** Each cloud-verdict hook adds a round trip; Zscaler's default timeout is 30 seconds.
- **Local proxies and root certificates.** SentinelOne Prompt (local proxy and tenant CA [S]), Check Point (desktop proxy), Netskope and Zscaler clients, BeyondTrust and Microsoft network inspection all want the same traffic. Proxy environment variables and PAC settings are single-valued.
- **Managed configuration ownership.** Jamf, Intune and a security vendor can each write the one managed-settings location; last writer wins.
- **MCP configuration.** Every gateway rewrites client MCP config to point at itself.
- **Browser extensions.** Check Point, Prompt, Harmonic, Okta's plugin and Island's extension inspect the same pages; 1Password's Agentic Mode disables its own inline features during agent control.

## What this changes in the earlier briefs

- **g02, matrix row "SentinelOne + Prompt: NV"**: partly filled. ADR is early access from 2026-10-21 with SaaS-platform coverage named; mechanism still unverified and no public docs exist.
- **g02, "Cortex XDR endpoint coverage of local agents: NV"**: now verified in primary release notes, including the Targeted Sensor and AES licence.
- **g02, final matrix row (Trend, Zscaler, Netskope, Wiz, Jamf, Island all NV)**: Netskope, Jamf and Island are now verified; Zscaler partly; Check Point Workforce added.
- **g02 implication 3 and brief 27 TL;DR ("a neutral hook broker ... is unclaimed", "nobody documents coexistence")**: still true for an implementation, but Trend Micro's `agent-hook-unity` draft now claims the specification layer, including a cross-handler deny guarantee.
- **Brief 27 TL;DR ("Defender active-mode requirement is our clearest opening for 'enhance the EDR you already run'")**: narrower. Palo Alto's Targeted Sensor targets exactly that, and Okta already consumes CrowdStrike for local agents.
- **Brief 06 TL;DR (kernel plus hook correlation "only EDR-class vendors")**: Palo Alto is now confirmed from primary sources ("process causality tracking"). Zscaler claims process and data lineage on the endpoint without stating a mechanism.
- **Brief 06, Netskope "no hook-level control" [S]**: confirmed from primary docs, with added limits. **Zscaler [S]**: outdated; Zscaler does ship hook integrations through AI Guard.
- **Brief 06, Cortex XDR One entry [S]**: upgraded to primary, but the Koi OS and agent list is still unverified.
- **Brief 06, "public pricing is almost non-existent"**: newly supported; no incumbent price was found.

## Implications for our design

1. **Ship a hook broker that preserves foreign entries.** Never replace the `hooks` key. Detect and report other vendors' hooks, and detect when ours were removed. Zscaler's installer shows the failure we must survive.
2. **Track `agent-hook-unity` and map our event model to it.** Publish our per-agent capability claims in its `gate`, `observe`, `partial`, `unavailable` vocabulary. Do not depend on it; it is unaccepted.
3. **Offer a targeted-sensor mode explicitly.** A build that does only agent discovery and enforcement beside any EDR, with documented coexistence for CrowdStrike, SentinelOne, Defender and Cortex.
4. **Expose a Falcon-style inventory feed for identity vendors.** Okta's design proves identity platforms will consume local-agent inventory from an endpoint product. Provide an ISPM-compatible export.
5. **Make discovery list-independent.** Combine signatures with behaviour (LLM API egress, tool-loop process trees, MCP handshakes) and report "unknown agent" as a first-class finding. Cover WSL, containers and VMs, which Netskope excludes.
6. **Decide locally with a hard budget.** Target tens of milliseconds, no cloud call on the hook path, and a published per-connector fail-mode table including behaviour at rate limits.
7. **Write managed configuration through the MDM, not around it.** Emit Jamf Blueprint, Intune and plain-file artefacts, and read back what Jamf already enforces so policies do not fight.
8. **Avoid a local TLS proxy by default.** If network inspection is offered, detect existing Netskope, Zscaler, Prompt and Check Point interceptors and chain or stand down.
9. **Match the Allow, Ask, Block, Detect, Redact vocabulary** and provide per-MCP-tool rules, since buyers will compare against Check Point and Sysdig.
10. **Keep documentation and prices public.** Four specialists gate their docs; an open product should not.

## Could not verify / open questions

- SentinelOne: any official technical doc; whether ADR uses hooks, the Singularity kernel sensor, or the Prompt proxy on endpoints; OS list; GA date.
- Palo Alto: AES supported OS, agent matrix, hook contracts and fail mode. The `cortex-docs` index is 4.9 MB and was not searchable through the fetch tool.
- Zscaler: whether AI Endpoint Security is Client Connector or a new agent; OS; hook behaviour on API error.
- Check Point: the official admin guide (404) and the community thread on third-party conflicts (403). The Workforce details rest on an unofficial copy.
- Cisco AI Defense commercial docs and Secure Access MCP policy pages.
- Trend Vision One endpoint agent discovery; Fortinet, Sophos, Bitdefender, ESET, Tanium, Orca, Iru: no product found, not proven absent.
- Sysdig AI Defense docs; Snyk Evo docs; Wiz docs (login required).
- Okta Agent Gateway and the exact data Okta pulls from Falcon.
- Prices for every vendor in scope.

## Sources

- https://cortex-docs.paloaltonetworks.com/cortex-xdr-6.x-rn/release-information/features-introduced-in-2026/november-2026/release-highlights — Cortex XDR 6.x release highlights, November 2026
- https://www.paloaltonetworks.com/blog/security-operations/cortex-xdr-6-0.md/ — Cortex XDR 6.0 blog, 2026-10-19
- https://www.paloaltonetworks.com/blog/2026/10/reinventing-endpoint-security-with-cortex-xdr-one.md/ — Cortex XDR One blog, 2026-10-19
- https://github.com/PaloAltoNetworks/AppSecMCP — Cortex AppSec plugins, pushed 2026-11-02
- https://www.stocktitan.net/news/S/sentinel-one-launches-singularity-agentic-detection-and-response-to-77tany7rhvun.html — SentinelOne ADR press release (mirror), 2026-10-21
- https://appsecsanta.com/prompt-security — Prompt Security review, updated 2026-10-07 (secondary)
- https://openclawai.io/blog/sentinelone-prompt-ai-agent-security-purple-ai-rsac-2026 — RSAC recap, 2026-03-24 (secondary)
- https://www.prompt.security/ — Prompt Security site, 2026-11
- https://docs.netskope.com/en/netskope-client-ai-discovery/ — Netskope Client AI Discovery
- https://community.netskope.com/monthly-updates-hub-147/monthly-updates-september-2026-8970 — Netskope monthly highlights, September 2026
- https://www.zscaler.com/blogs/product-insights/ai-endpoint-security-closes-zero-trust-gap — Zscaler AI Endpoint Security, 2026-10-08
- https://www.zscaler.com/blogs/product-insights/how-zscaler-secures-the-agentic-ai-era — Zscaler agentic platform, 2026-06-18
- https://github.com/zscaler/zguard-ai-integrations — Zscaler AI Guard integrations, pushed 2026-10-15
- https://wfai-doc.pages.dev/ — Workforce AI Security training copy (unofficial host)
- https://docs.lakera.ai/docs/agent-security — Check Point AI Agent Security overview (early access)
- https://github.com/trendmicro/agent-hook-unity — Agent Hook Unity draft 0.1, pushed 2026-11-04
- https://docs.datadoghq.com/security/ai_guard/ — Datadog AI Guard
- https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agents.htm — Okta for AI Agents
- https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-discover.htm — Okta: discover and assess AI agents
- https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-register.htm — Okta: add and register AI agents
- https://www.jamf.com/resources/press-releases/jamf-launches-ai-governance-a-first-of-its-kind-native-ai-control-plane-for-mac/ — Jamf AI Governance, 2026-06-30
- https://aws.amazon.com/blogs/machine-learning/manage-ai-applications-on-mac-with-jamf-ai-governance-and-amazon-bedrock/ — AWS and Jamf walkthrough, 2026-07-08
- https://support.1password.com/1password-claude/ — 1Password for Claude, 2026-11-04
- https://www.1password.dev/llms.txt — 1Password developer docs index
- https://www.island.io/product/ai/enterprise-browser-for-agents — Island Enterprise Browser for Agents
- https://www.lasso.security/blog/securing-ai-on-endpoints-how-to-govern-ai-tools-coding-agents-and-mcp-connections — Lasso, 2026-09-28
- https://docs.hiddenlayer.ai/docs/products/runtime/overview.md — HiddenLayer AI Runtime Security overview
- https://docs.zenity.io/llms.txt — Zenity docs navigation
- https://www.nightfall.ai/blog/ai-agent-security-platforms-desktop-ai-agents — Nightfall comparison, 2026-08-11 (vendor-authored, secondary)
- https://pisinger.github.io/wiz-release-radar/2026-10/ — Wiz release radar, October 2026 (third-party tracker)
- https://github.com/Sentinel-One/purple-mcp — Purple AI MCP server, pushed 2026-10-28

## Independent verification

_Checked 2026-11-10 by a separate fact-checker. 4 web searches, direct fetches, raw `curl` reads of vendor pages and read-only `gh` calls. Verdicts: confirmed, corrected, refuted, unverifiable._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Cortex XDR 6.x (November 2026) ships a Cortex Targeted Sensor that runs AES alongside third-party EDRs; licence XDR ONE, AES or ITDR add-on | confirmed | Release highlights say it runs "alongside existing third-party EDRs without conflict" and "Requires either the XDR ONE, AES license, or ITDR add-on". The Cortex capabilities page separately lists a "Targeted" agent type that supports AES on Windows, macOS and Linux. | https://cortex-docs.paloaltonetworks.com/cortex-xdr/protect-your-endpoints/endpoint-protection/endpoint-protection-capabilities |
| 2 | Cortex AES uses agent hooks; apps without hooks (Hermes, ChatGPT, OpenClaw, Claude Desktop) need the XDR sensor; supported OS and interception mechanism are not published | corrected | Hooks and sensor pairing hold (blog wording is "built-in hooks" and "native hooks"). The OS list IS published: the Cortex capabilities table marks AES supported on Windows, Mac and Linux, not Android or iOS, with Application Control on Windows and macOS only. Only the prompt-interception mechanism is unpublished. | https://cortex-docs.paloaltonetworks.com/cortex-xdr/protect-your-endpoints/endpoint-protection/endpoint-protection-capabilities |
| 3 | Zscaler's Claude Code guide copies a whole settings.json or replaces the entire hooks key; default 30-second timeout per cloud scan | confirmed | `Anthropic/README.md` Quick Start runs `cp claude-code-aiguard/settings.json ~/.claude/settings.json`. The detailed README warns against that copy, backs the file up, then assigns the whole `hooks` key, which still replaces every existing hook. `AIGUARD_TIMEOUT` defaults to 30 (SDK API timeout). The hooks fail closed, so a timeout blocks the action. | https://github.com/zscaler/zguard-ai-integrations/blob/main/Anthropic/claude-code-aiguard/README.md |
| 4 | Netskope Client AI Discovery: periodic signature scan, default 60 min, Windows 64-bit and macOS only, Client 138+, signature-file assets only, no separate VMs or containers | confirmed | Read the page raw: interval "1 to 1,440 minutes; default: 60 minutes"; "Windows (64-bit) and macOS endpoints only"; minimum Client 138 (140.0.0 for network telemetry); VM and Docker assets not detected unless the Client runs inside; signature file is the limit. No second independent source found. | https://docs.netskope.com/en/netskope-client-ai-discovery/ |
| 5 | SentinelOne Singularity ADR announced 2026-10-21, early access only, SaaS agent platforms named, no endpoint mechanism or OS list | confirmed | Business Wire text (read through a second syndication, not the researcher's mirror) is dated 2026-10-21, says "immediately available in early access", names Agentforce, Copilot Studio, ChatGPT workspace agents and Claude managed agents, and states no mechanism or OS. The companion ADR and ASOC release adds nothing on mechanism. sentinelone.com still returns 429. | https://finviz.com/news/405513/sentinelone-launches-singularity-agentic-detection-and-response-to-stop-rogue-and-malicious-ai-agents-at-machine-speed |
| 6 | Okta for AI Agents has no endpoint sensor of its own; it finds local agents and MCP servers through CrowdStrike Falcon and shadow AI through a browser plugin | corrected | True today, with three limits the plan must carry. (a) Endpoint discovery is Early Access. (b) Okta says "Okta Verify is the next source we are bringing online", with more EDRs after, so Okta will have its own endpoint source. (c) ISPM discovers only REMOTE MCP servers seen in Falcon telemetry; local MCP servers (npx, container, local program), servers behind gateways and devices without Falcon are explicitly not discovered. | https://help.okta.com/ispm/en-us/content/topics/ispm/locally-running-ai-agents-and-mcp.htm and https://www.okta.com/blog/ai/shadow-ai-agent-discovery/ |
| 7 | trendmicro/agent-hook-unity: draft 0.1, 18 events (12 gate, 6 observe), minimum cross-handler deny guarantee, MIT and CC BY 4.0, created 2026-09-09, not accepted, no visible adoption | confirmed | GitHub API: created 2026-09-09T01:31Z, 0 stars, 0 forks, all three contributors are Trend accounts. `spec/0.1/events.md` lists 18 events, 12 classified Gate and 6 Observe. README: "not an active standard until accepted". Code search finds only two outside mentions, both survey notes by one user. | https://github.com/trendmicro/agent-hook-unity/blob/main/spec/0.1/events.md |
| 8 | Datadog AI Guard: 14 million tokens and 700 requests per minute per organisation; over the limit integrations proceed unevaluated; coding-agent protection in Preview | confirmed | Verified in the docs source file: 14 million tokens, 700 requests, 429 on excess, integrations "let the model call or tool call proceed without an evaluation", SDK raises `AIGuardClientError`, "AI Guard for coding agents is in Preview". The page was overhauled 2026-11-05, so the figures are current. | https://github.com/DataDog/documentation/blob/master/hugo/content/en/security/ai_guard/_index.md |
| 9 | Jamf AI Governance GA since 2026-06-30 for Claude Code, Claude Desktop and Codex on macOS; managed configuration through DDM, offline and before first login, no new agent | confirmed | GA date, the three apps and the offline sentence are in the press release. DDM and Blueprints come only from the AWS post of 2026-07-08; Jamf's own pages say "OS-level management plane". "No new agent is required" refers to shadow-AI visibility through the existing telemetry agent. Included in Jamf for Mac and Jamf for Mac Higher Education, not K-12. | https://www.jamf.com/solutions/ai-governance/ |
| 10 | Check Point Workforce AI Security: extension, desktop proxy, IDE integrations, script-based discovery with no resident agent, Windows and macOS, Agent Policies of Allow, Ask or Block per MCP tool; rests on an unofficial copy | corrected | The official admin guide is live at a new path (the old URL returns 404; last revised 2026-11-08). It confirms the four collectors and a "lightweight, volatile scan script" that needs no desktop client, on Windows and macOS (ChromeOS is extension only). Agent rules offer Allow or Block only, set per rule with tools selected inside it; Ask belongs to Access and Chats policies. The Enterprise desktop client also has its own scan interval setting. | https://sc1.checkpoint.com/documents/Workforce_AI_Security/Workforce_AI_Security/manage_interactions_agents/manage_interactions_agents.html |

### Further statements checked in this brief

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Zscaler hook fail mode is "n/s"; the README "documents a silent failure where a wrong policy setting lets policy blocks pass"; "hook behaviour on API error" is an open question | corrected | Outdated. Since commit 6df2e8f1 (2026-09-02) the README has a "Fail-Closed Behavior" table: missing API key, unreachable API, 401 or 403, a 200 with no action and any unrecognised verdict all block. The "Policy not found" soft failure is now treated as a block. Zscaler says that if AI Guard is unreachable, Claude Code stops until it returns. | https://github.com/zscaler/zguard-ai-integrations/blob/main/Anthropic/claude-code-aiguard/README.md |
| "Documented by nobody: a published fail-mode table from a commercial incumbent. Only Cisco's DefenseClaw and Datadog's rate-limit note exist" | refuted | Zscaler publishes the fail-mode table above. Check Point's official guide documents a "Claude Inference Hooks" integration (added 2026-08-06) with a fail-closed or fail-open choice, shadow mode, and a note that enforcement can be suspended after repeated failures. That integration runs server side for Claude Enterprise, covers Claude Code and Cowork with no endpoint component, and is missing from the brief. | https://sc1.checkpoint.com/documents/Workforce_AI_Security/Workforce_AI_Security/integration_claude_inference_hooks/claude_inference_hooks_integration.html |
| "With `allowManagedHooksOnly`, user-level installs silently stop running", while Palo Alto, Noma and 1Password ship hooks as plugins | confirmed, incomplete | Under this setting plugin hooks are blocked too. Only managed hooks, Agent SDK hooks and hooks from plugins force-enabled in managed `enabledPlugins` (matched on the full plugin@marketplace ID) run. A vendor's hooks survive only through managed settings or a force-enabled plugin. | https://code.claude.com/docs/en/settings-reference.md |

**Net effect on the plan.** (1) Do not claim Linux as a gap against Palo Alto: AES and the Targeted agent type list Linux. (2) Okta's Falcon path does not see stdio or local MCP servers, so that gap is real and documented, but Okta Verify is announced as a first-party endpoint source. (3) Check Point per-tool Ask for agents is not documented; only Allow and Block. (4) A published fail-mode table is no longer unique: Zscaler has one and fails closed.
