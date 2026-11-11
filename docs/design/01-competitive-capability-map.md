# Competitive capability map

_Status: draft 4 against spine version 4, rulings R-35, R-39 and R-62 (`design/_review/01-document-rulings.md`) and the owner's answers (`design/_review/02-owner-answers.md`). Date: 2026-11-10. Owning squad: Direction group (`product-lead`, `team/02` section 3); a recurring gardener re-verifies the data (D-47). Read with: `design/00-decisions.md` (D-65, D-01, D-50, section 7), 05 (inventory), 07 (control points and hook broker), 17 (MCP broker), 25 (export destinations), 33 (risk register), 34 (documentation), 36 (prices and legal terms)._

## Summary

This document says what each rival does, how, and at what release status, and fixes where Guardrails ADR leads, matches and stays out. Vendor facts are as read on 2026-11-09 and 2026-11-10; each brief's verification section overrides its body.

Key choices:

1. **Eight leads, six table stakes** (D-65). Each lead has its evidence, shape and prerequisites in section 5; each table stake is a parity item in section 6.
2. **Endpoint parity needs Windows and Cursor.** The Tier 1 cells that need no external precondition (Claude Code and Codex on Linux x64 and macOS arm64, D-50) carry the leads, not parity. Windows inventory and verdicts reach parity when Windows joins Tier 1 (S-04), and Cursor when its adapter passes the conformance suite. Console items require the server; the two read-only SaaS connectors need the integration host and a customer with access to the API, and the other connectors follow their own work items in 25 (R-39).
3. **Hooks are the commodity.** At least twelve vendors write into the same hook slots. Our difference surrounds the hook: a shim that decides alone, owner-aware delivery (D-49), the OS cross-check (D-13) and an honest assurance record (P1).
4. **Complement the incumbent.** Importers for Defender and Falcon Guardian inventory (requires discovery pass 4 and access to the incumbent's API), L0 content and L1 feeds, with a targeted build beside any EDR (D-23).
5. **Interoperate with the open projects.** OpenShell, DefenseClaw, Numbat and Prempti are import dialects and compile targets (export requires D-12's compile-down), never dependencies.
6. **The map is data** in one status vocabulary. Every rival claim carries a source and a date; the matrix is generated; a Guardrails cell cannot claim a capability without a `PLAN.md` row and an acceptance test (D-50).
7. **Re-verify every 90 days**, and review the wedge against adoption data or when an incumbent ships a lead's capability (spine section 9).

## Requirements

|#|Requirement|Source|
|---|---|---|
|R1|Tear down the five named products and the open-source alternatives: capabilities, weak points, improvements|Owner's request|
|R2|Go past the named products|Owner's request; h03, h04|
|R3|State shipping, preview or announced, with dates|Task brief; 04 (marketing ahead of documentation)|
|R4|Fix where we lead, what we must match, what we are not|D-65, spine section 1|
|R5|Give each lead and match a shape, the design document that specifies it and its prerequisites|D-01, D-50, spine section 7|
|R6|Never present a request as a boundary, ours or a rival's|P1, 02|
|R7|Keep the map current without a human author|D-47, spine section 9|
|R8|Turn a buyer's mandatory RFP items into release gates|D-46, h04|

## Design

### 1. Method and status vocabulary

Matrix codes:

- `G` shipping, documented in a primary source.
- `g` shipping but narrow; the limit is in the teardown.
- `P` preview, beta, pre-beta or early access.
- `A` announced, not available.
- `c` vendor claim with no published mechanism or documentation.
- `-` not documented in any source read. This is not proof of absence.

The Guardrails ADR column (GR) names the design document that specifies the capability and, where the capability or part of it depends on an external precondition, says which (spine section 7). It states no status: a Guardrails status comes only from the capability's acceptance test (D-50). Each teardown's "Our answer" gives the improvements its weak points call for, as decisions. Prices and counts are measured values from the cited briefs unless marked target.

### 2. Teardowns of the five named products

#### 2.1 Origin (originhq.com)

Shipping, closed source; sensor v1.12.5 (2026-09-30). Prelude Security until 2026-07-27.

- **Mechanics.** The sensor points each agent's native OpenTelemetry exporter at a loopback collector (port 4318), adds application hooks, reads transcripts (needs Full Disk Access), polls provider compliance APIs (Anthropic, Microsoft 365 Copilot; OpenAI in preview), runs a browser extension for five chat sites, and reads OS telemetry (macOS Endpoint Security client, Windows user-mode ETW). The Light sensor (2026-06-12) intercepts nothing; the Full sensor keeps on-wire capture.
- **Covers.** macOS 13+, Windows 10/11, Server 2022+. No Linux, container or Kubernetes sensor; Claude Code in WSL is the only Linux coverage. Capture is per application (Claude Code, Cowork, Codex, ChatGPT Desktop, Copilot CLI, Cursor); inventory is wider.
- **Discovery and attribution.** Tools, extensions, MCP servers, skills, local runtimes and inference-library loads. A bespoke agent appears only as process or library evidence. Process starts and file activity are tied to an agent session.
- **Enforcement.** None inline is documented. "Enforce" means configuration push plus a finding when its settings are displaced. "Active response" appears only on the pricing page.
- **Detection and response.** Deterministic rules with evidence spans, a model review of every trace, then a triage step that drops findings whose quote is not in the session. Two ratings per finding, a three-bucket queue, alerts to Slack and Teams.
- **Deployment, API, price.** Hosted in the US by default, with EU and Australian regions; regional hosting and self-hosting are Enterprise options. A read-only MCP server; no SIEM export or REST API documented. Eight fixed roles, prompt text behind its own permission. Free one-seat tier, per-endpoint paid tiers, no figures published.
- **Strengths.** Published investigations that double as a detection backlog; evidence-checked review; a one-command free tier.
- **Weak points.** It trusts the watched process: its own research shows 27 executions with no telemetry record in one run (26 were harness housekeeping) and telemetry falsified by patching the binary. A port collision silently stops capture. Full prompts sit in a multi-tenant store with three third-party model sub-processors.
- **Our answer.** Cross-check claims against OS observation (P3, D-13); enforce Essentials from first protection (D-53); Linux as the reference platform (D-19); default upload `metadata` (D-51); an export contract (D-54). We keep its two ratings and three buckets (spine section 3, D-44) and rebuild its published detection ideas as open content.

#### 2.2 BeyondTrust AI Agent Security

Announced 2026-06-30 naming Linux and containers; GA 2026-10-21 for Windows and macOS only. Agent versions 0.40 to 0.41.

- **Mechanics.** Two planes. A Windows kernel driver (exec, file open, connect, TLS redirect) and macOS Endpoint Security plus Network Extension system extensions give mandatory control. Managed hooks for Claude Code, Codex, Cursor and Copilot give tool-call context; some rules run at the hook and again at process launch. HTTPS method, path and content rules need a local proxy and a per-tenant root CA; on Windows a separate traffic redirect is armed per endpoint and must not touch browsers.
- **Covers.** Windows 11 and Server 2022+ on x64 (Arm unsupported); macOS 14, 15, 26.
- **Discovery and attribution.** Agents, MCP servers, LLM endpoints, flagged skills and stored credentials. Any process calling a known or learned LLM host is treated as an agent, with the evidence shown. Events carry "AI agent" and "Acting under" from classifiers plus process ancestry. No agent identity leaves the endpoint.
- **Policy.** Allow by default. Four modes: Off, Audit, Require Approval, Block. Subjects are only "Any AI agent" or "Anyone"; six actions; no file-write action. The 27 managed policies run at Audit or Off and must be forked to block. Drafts replay against recorded activity. Conditions can pin AWS account, Entra tenant or GCP project.
- **Fail mode.** Hooks allow the call when the local service is unreachable and mark the endpoint Degraded. No fail-closed option is documented.
- **Approval.** A grant relaxes the whole matching policy on that endpoint; users can self-approve for up to 24 hours; no central revoke of self-approved grants is documented.
- **MCP.** Per-server and per-tool access; a new server is allowed until someone acts.
- **Detection and response.** Findings on flagged skills and per session; no prompt or response inspection, by design. Response is the deny, an optional process kill (not yet on Windows) and a fleet switch that downgrades blocks to audit.
- **Deployment, API, price.** Only a hosted console is documented; one administrator role; CSV export; no API or SIEM export documented; quote only.
- **Strengths.** Both planes in one product; replay; cloud-tenant conditions; update rings with pause and yank.
- **Weak points.** No Linux; a root CA as the price of HTTP policy; coarse subjects; nothing blocks by default; policy-wide approvals; CSV as the only documented export.
- **Our answer.** The same two-plane check with a published assurance record (D-13, P1); no mandatory interception (D-16); Cedar subjects per agent, session, repository and MCP tool (D-08); exact, single-use grants with a grade (D-31); separation of duties (D-55). We adopt its replay buckets (D-11) and its production-pinning conditions (D-28).

#### 2.3 Microsoft Agent 365 with Defender, Entra Agent ID and Purview

Agent 365 GA 2026-05-01 at USD 15 per user per month, or inside E7 at USD 99. It is a licence and console over four products.

- **Defender for Endpoint.** Local discovery GA on Windows and macOS (October 2026) for about 60 named agents, with MCP configuration for roughly half, in the `AgentsInfo` hunting table. It needs Defender Antivirus in active mode and MDE P2. WSL is preview for three agents; native Linux is not covered; "only supported combinations appear". Runtime protection is preview, Windows only, detects prompt injection only, through vendor hooks on six Claude and Copilot surfaces plus network inspection for four apps. Codex and Cursor have no runtime row.
- **Agent 365.** Registry of platform agents; manual, key-based sync of seven other clouds (preview); local-agent blocking for 7 of 23 tools through Intune or VS Code policy (Frontier preview); OTLP ingest that can return 200 while rejecting every span.
- **Entra Agent ID.** GA. Blueprints, agent identities, mandatory sponsors, Conditional Access at token issuance, for registered agents only. Separating agent from user on a Windows device is "coming soon".
- **Purview.** DLP, audit and labels for agent instances; Edge inline DLP for 19 named unmanaged AI apps on Intune-managed Windows.
- **Other surfaces.** Copilot Studio threat-detection webhook (preview; 1,000 ms; allow on timeout by default). MXC sandbox (MIT, GA 2026-10-07), which confines only what its caller launches. Guardian Agents announced 2026-10-19 with no date or price (secondary source).
- **Export.** `CloudAppEvents` streams; `AgentsInfo` and `BehaviorInfo` must be polled.
- **Strengths.** Reach through licences customers already hold; identity and data classification we will not build; real third-party extension points.
- **Weak points.** A fixed catalogue; no macOS or Linux enforcement; no customer-authored policy over commands, paths or egress; nothing where Defender is passive; fail-open defaults; interface churn.
- **Our answer.** Import `AgentsInfo` as a dialect with a published field mapping (requires access to the customer's Defender API); export to its OTLP ingest and serve its webhook as a verdict provider (requires the server's `decide` target, D-40); recognise MXC as a containment back end (D-21); correlate Entra agent objects to observed processes (requires the token service and registry connectors, D-27). We lead where the bundle is absent: Falcon-primary fleets, Linux, Codex and Cursor, bespoke agents.

#### 2.4 CrowdStrike Falcon Guardian

Unveiled 2026-09-01, GA since September. It is Pangea's AI Guard plus Falcon sensor telemetry; the earlier AIDR product ends support on 2026-11-30.

- **Mechanics.** The sensor inventories agents by process tag and install record (Windows, macOS). Hook collectors for Claude Code (native HTTP hook), Codex and Copilot CLI (MIT Rust binaries, 30-second timeout) and OpenCode send three event types to a cloud API; every verdict is a round trip. Codex and Copilot default to fail open; the Claude Code hook is fail open in practice. The collector token sits in an environment variable the agent can read. Hook events join sensor events by sensor id, hook process id and a product tag.
- **Other control points.** Browser extension (input block and redact). Endpoint network inspection on Windows is report-only with a 1 MiB cap; the 2026-11-03 press release calls it GA and the same day's blog calls it pre-beta. AI Gateway GA 2026-11-03, bundled. An MCP proxy wraps stdio servers.
- **Kill Switch (2026-11-03).** Today it tells connected gateways to block models and providers. Endpoint termination, identity and SaaS reach are "coming soon".
- **Not shipping.** Linux, Kubernetes and in-house agents are pre-beta; behavioural baselines and the Agentic Identity Provider are announced.
- **Policy and detection.** Routing rules, then attribute-based access rules, then eleven content detectors; a report-only mode per route.
- **API and data.** Read-only API; a session graph with sub-agent edges but no edge from a session to a stable agent. Hosted only, three regions, no public price; parent and child tenants for MSSPs since 2026-11-03. Discovery and the graph require the Falcon sensor.
- **Strengths.** Installed base; the widest collector list; a gateway; a managed service; an open integration surface (HEC ingest, Custom IOA, RTR, SOAR).
- **Weak points.** Cloud-dependent verdicts; agent-readable token; observation-only network inspection; a kill switch that misses direct-to-provider and local-model agents; no self-hosting; public statements that conflict.
- **Our answer.** Decide locally (P4, D-14); keep secrets behind a peer-checked socket (D-14, D-20); session-scope kill actuators on the endpoint with no server (D-30); import Guardian inventory (requires access to the customer's Falcon API) and export to Next-Gen SIEM; Falcon is an interference-tested incumbent (D-23), with its licence through a design partner or a free vendor programme (D-64).

#### 2.5 Sidekick Security

A Chrome extension (store version 0.0.531) with a hosted console. Repositioned around 2026-11-10 to "Agentic SaaS under control". No public documentation, price or integration list.

- **Claims.** Per-account answers: which accounts train on company data, where personal identities reach company data, which apps are connected, where SSO or MFA is missing. Guidance at sign-up, sign-in and settings change, generated by hosted model "guardian agents".
- **Inferred limits.** Chrome-family browsers only; nothing for desktop apps, CLIs, coding agents or MCP; guidance, not enforcement; extension permissions unknown.
- **Strength.** Reaches apps with no admin API at the moment a user acts.
- **Our answer.** It is a positioning signal, not a benchmark. The browser control point (17) carries tenant pinning and browser-agent evidence; it requires the engine in WebAssembly and each browser's extension store account. We do not audit SaaS account settings (section 7).

### 3. Other products that set buyer expectations

|Product|Status|How it works|Fail mode|Weak point|Our stance|
|---|---|---|---|---|---|
|Palo Alto Cortex AES (Koi) and Targeted Sensor|Launched 2026-10-19; November 2026 release notes|Hooks first; XDR sensor for hookless apps; risk-scored inventory; session audit; process causality. AES lists Windows, macOS and Linux. The Targeted Sensor runs beside third-party EDRs|Not published|Closed; no price; interception mechanism unpublished|Nearest rival to our targeted build. Compete on openness, local policy and published failure modes|
|SentinelOne Singularity ADR, Prompt Security|Announced 2026-10-21, early access|Claims endpoint, SaaS and cloud inventory and per-agent containment. One hands-on review found a local intercepting proxy with a tenant CA|Not published|No technical documentation|Wait for evidence; publish coexistence results|
|Zenity|Shipping (vendor statement)|SaaS connectors, hooks, Anthropic inference hooks, MCP gateway|Inference hooks allow on timeout by default|Documentation unreadable; SaaS-centred|Complement: two read-only connectors (Anthropic Compliance API, OpenAI Compliance Logs) and the rest of 25's connectors|
|Sysdig AI Defense|Announced 2026-11-04; trial on macOS and Windows|Kernel sensor plus hooks on Falco rules; Alert, Block, Confirm, Kill; no prompt capture by default. About 30 detection rules for three CLI agents since 2026-03-17|Not published|No documentation page; Linux desktop unstated|Closest design to ours; compete on openness and console|
|Prempti (Falco project)|v0.3.0-rc5; one commit in 90 days|Hook to Falco rules; allow, deny, ask; three operating systems including Windows on Arm|Closed by default on Claude Code|Declared commands only; stalled|Import its alerts|
|Cisco DefenseClaw|Apache-2.0, v1.0.8 (2026-11-05)|Local gateway plus hook connectors for 12 agents; version-pinned hook contracts; scanners|Managed closed; Secure Client open; a hook that fails to start runs unguarded|No discovery of running agents, no OS sensor, no fleet console|Copy contract pinning and the fail table (D-49, D-15); interoperate|
|Uber ADR|Apache-2.0, sensor v1.0.0 (2026-07-31)|Catalogue discovery, transcript parsers for 11 agents, benchmark, model detector|Not applicable|Prevention withheld; no console or kernel sensor|Import its catalogue and telemetry (D-24)|
|Perplexity Numbat|Apache-2.0, v0.3.0 (2026-10-19)|One binary; hooks, OTLP and transcripts into CEL rules; rebuilds sessions that predate install|Open; shipped rules monitor only|No console, fleet or OS sensor|Import its schema; our standalone build must beat it on enforcement and reconciliation|
|Nvidia OpenShell|Apache-2.0, v0.1.7 (2026-11-03), CNCF Sandbox|Landlock and seccomp sandbox, egress check, credential placeholders, policy prover|Holds connections until policy decides|Governs only what it launches; telemetry on by default|A containment back end (D-21); export policy to it (D-12)|
|NVIDIA NeMo Guardrails|Apache-2.0 Python toolkit; release not re-read for this draft|Programmable input, output, retrieval and dialogue rails (Colang) around an application's LLM calls; many rails are LLM self-checks|Set by the host application|In-process in one application; model-judged rails; no view of agent tool calls on the OS|Do not compete: application-side model safety is a non-goal (spine section 1)|
|Guardrails AI|Apache-2.0 Python framework with a validator hub; release not re-read for this draft|Validators over LLM inputs and outputs (structure, PII, toxicity), with re-ask or fix on failure|Set by the host application|In-process; output-centred; validators mix deterministic and model checks|Do not compete: output validation inside applications is model safety (spine section 1)|
|Meta LlamaFirewall and Llama Guard|LlamaFirewall open source in PurpleLlama; Llama Guard weights under Meta's Llama licence, not OSI; releases not re-read for this draft|Prompt Guard jailbreak classifier, AlignmentCheck model audit of agent reasoning, CodeShield static checks; Llama Guard classifies prompts and responses against a hazard taxonomy|Set by the host application|Classifiers that adaptive attacks beat (P2 evidence); in-process; licence limits bundling|Integrate: candidate local judge back end behind the D-29 trait, restrict-only (P2); bundle model weights only after licence review (D-02)|
|NVIDIA garak|Apache-2.0 LLM vulnerability scanner; release not re-read for this draft|Probes (injection, jailbreak, leakage) against a model endpoint, scored by detectors|Not applicable|Tests models, not agent actions or OS effects|Test with: a probe source for injection scenarios in the efficacy harness (D-45)|
|Microsoft PyRIT|MIT Python red-teaming framework; release not re-read for this draft|Orchestrated single- and multi-turn attacks with converters and scorers|Not applicable|Targets model and application responses; no endpoint enforcement to test without our harness|Test with: drive adaptive multi-turn attacks in model-driven scenarios (D-45)|
|promptfoo|MIT evaluation and red-team CLI; release not re-read for this draft|Declarative test suites and red-team plugins for LLM applications, agents and MCP tools|Not applicable|Scores application behaviour, not OS-observed effects|Test with: generate adversarial tool-call scenarios for the harness (D-45); red teaming is not a goal (section 7)|

Also seen: Netskope (signature scan, Windows x64 and macOS, eight agents, "only assets listed" are detected); Zscaler (AI Guard hooks fail closed, and its guide replaces the whole `hooks` key); Check Point (extension, desktop proxy, script discovery; Allow or Block per MCP tool); Jamf AI Governance (GA 2026-06-30, macOS, vendor-native settings by DDM); Okta (finds local agents through Falcon, early access); Datadog AI Guard (proceeds unevaluated over its rate limit); 1Password (credential fill outside the agent's view); Elastic (rules under Elastic License v2 that run over SentinelOne, Defender and Sysmon telemetry); Pillar (Vanta agreed to acquire it on 2026-11-09; enforcement deferred to summer 2027). Public prices: Knostic USD 15, Unbound USD 20 and Pomerium USD 7 per user per month; Aembit USD 20 per agent per month.

### 4. Capability matrix

Columns: OR Origin; BT BeyondTrust; MS Microsoft; CS Falcon Guardian; SK Sidekick; PA Palo Alto; S1 SentinelOne; ZN Zenity; SY Sysdig AI Defense; DC DefenseClaw; UB Uber ADR; NB Numbat; PR Prempti; OS OpenShell; GR Guardrails ADR (the design document that specifies the capability, and any external precondition).

|Capability|OR|BT|MS|CS|SK|PA|S1|ZN|SY|DC|UB|NB|PR|OS|GR|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|**Discovery**||||||||||||||||
|Named agents on Windows and macOS|G|G|G|G|-|G|P|c|c|-|G|g|-|-|05; 08, 09|
|Native Linux endpoints|-|-|-|P|-|G|-|-|c|-|G|g|-|-|05; 10|
|MCP servers, configured and observed|G|G|G|G|-|G|P|c|-|g|G|-|-|-|05; 17|
|Skills, plugins, extensions|G|g|g|G|-|G|P|c|-|g|G|-|-|-|05|
|Unregistered or bespoke agents by behaviour|g|g|-|P|-|-|-|-|g|-|-|-|-|-|05; on macOS needs Apple's Developer Program (Network Extension)|
|WSL, containers, Kubernetes, CI|g|-|P|P|-|-|-|-|g|-|-|-|-|g|10|
|SaaS and cloud agent platforms|g|-|G|g|c|G|P|G|g|-|-|-|-|-|25; 05 (AL1); needs a customer with access to each platform's API|
|Browser AI use and browser agents|g|-|G|G|c|-|c|-|-|-|-|-|-|-|17; needs each browser's extension store account|
|Declared versus observed diff|-|g|g|-|-|-|-|-|-|-|g|-|-|-|05; incumbent inventories need access to the incumbent's API|
|**Attribution**||||||||||||||||
|Session timeline with sub-agents|G|G|-|g|-|G|c|c|c|g|G|G|-|-|06|
|Agent versus human under one OS user|g|G|A|g|-|G|c|-|c|-|-|-|-|g|06|
|Tool call joined to its OS effects|g|g|-|g|-|c|-|-|c|-|-|-|-|-|06; 07; on macOS needs the Endpoint Security entitlement|
|Evidence and doubt stated per attribution|-|g|-|-|-|-|-|-|-|-|-|-|-|-|06|
|Agent identity visible in cloud, SaaS, git logs|-|-|g|A|-|c|-|-|-|-|-|-|-|-|06; 15|
|**Enforcement**||||||||||||||||
|Pre-tool verdict, Claude Code|-|G|P|G|-|G|-|c|c|G|-|g|g|-|07|
|Pre-tool verdict, Codex and Cursor|-|G|-|g|-|g|-|c|c|G|-|g|P|-|07|
|Verdict decided on the device, offline|-|G|-|-|-|-|-|-|c|G|-|G|G|G|07; 12|
|Fail mode per rule class, published per agent|-|-|-|g|-|-|-|-|-|g|-|g|g|-|07|
|OS-enforced control, Windows|-|G|g|g|-|g|c|-|c|-|-|-|-|-|08; mandatory needs the optional driver (EV certificate and Microsoft's hardware programme through a sponsor or partner) or an embedding partner|
|OS-enforced control, macOS|-|G|-|g|-|g|-|-|c|-|-|-|-|g|09; mandatory needs Apple's Developer Program and the Endpoint Security entitlement|
|OS-enforced control, Linux|-|-|-|-|-|c|-|-|c|-|-|-|-|g|10; mandatory needs a free external audit or a qualified volunteer reviewer (D-62)|
|Launch sandbox or containment|-|-|g|-|-|-|-|-|-|-|-|-|-|G|08, 09, 10|
|MCP control point, per-tool rules, stdio included|-|g|P|G|-|g|c|c|-|g|-|-|-|g|17|
|Hook silence or unmatched OS effect raises a finding|-|g|-|-|-|-|-|-|c|-|-|-|-|-|07; 06|
|Preserves other vendors' hooks and managed settings|-|-|-|-|-|-|-|-|-|-|-|-|-|-|07|
|**Policy**||||||||||||||||
|Watch, Ask and Block modes|-|G|g|g|-|g|P|c|c|g|-|g|G|g|12|
|Subject by agent, user, repository, MCP tool|-|-|g|g|-|g|-|-|-|-|-|g|g|g|12|
|Open policy language, published schema|-|-|g|-|-|-|-|-|c|g|g|G|G|G|12|
|Replay of a draft against recorded activity|-|G|-|g|-|g|-|-|-|-|-|-|-|g|12; 20|
|Blocking rules active by default|-|-|-|-|-|-|-|-|-|g|-|-|-|g|12; 13|
|Layers with ceilings, provider to user|-|g|-|g|-|-|-|-|-|-|-|-|-|-|12; 21|
|Compiles to agents' native managed settings|-|g|g|-|-|-|-|-|-|-|-|-|-|-|12|
|**Identity**||||||||||||||||
|Agent registry with accountable sponsor|-|-|G|A|-|c|-|c|-|-|-|-|-|-|15|
|Identity for unregistered local agents|-|-|A|-|-|-|-|-|-|-|-|-|-|-|15|
|Credential broker or injection|-|-|g|g|-|c|-|-|-|-|-|-|-|G|15; 16|
|Credential inventory on the endpoint|-|G|-|-|-|-|-|-|-|-|-|-|-|-|15; 05|
|Delegation chains, AuthZEN, CAEP|-|-|g|A|-|-|-|-|-|-|-|-|-|-|15|
|**Data**||||||||||||||||
|Protected paths and secret-read rules|g|G|-|g|-|c|-|-|g|g|-|g|G|G|16|
|Prompt and response DLP or redaction|g|-|G|G|c|G|c|c|-|g|-|-|-|-|16|
|Session labels with sink gating|-|-|-|-|-|-|-|-|-|-|-|-|-|-|16|
|Tenant pinning: AI accounts, cloud accounts|-|G|g|-|c|-|-|-|-|-|-|-|-|-|17; 16|
|Metadata by default, pseudonymous people|-|-|-|g|-|-|-|-|c|-|g|g|g|-|29; 04|
|**Detection**||||||||||||||||
|Deterministic detections on agent behaviour|G|g|g|G|-|G|c|c|G|G|g|G|G|-|13|
|Detection content open and portable|-|-|-|-|-|-|-|-|-|G|G|G|G|-|13; 26|
|Model review with checked evidence|G|-|-|A|-|-|c|c|-|-|g|-|-|-|19; needs the organisation's chosen judge back end and a capture level that permits it|
|Agent-config and hook tamper findings|G|g|g|-|-|-|-|-|g|-|-|-|-|-|11; 13|
|Skill and MCP reputation|g|g|g|G|-|G|c|c|-|G|-|-|-|-|14; own scanning needs data from many organisations|
|Published efficacy results|-|-|-|-|-|-|-|-|-|-|g|-|-|-|Spine D-45 (31 not yet written); a third-party rerun needs an independent party|
|**Response**||||||||||||||||
|Denial reason the agent can act on|-|G|-|g|-|c|-|-|c|G|-|g|G|g|07; 18|
|Human approval of a blocked action|-|G|-|-|-|-|P|-|c|g|-|-|g|-|18|
|Approval bound to the exact action, graded|-|-|-|-|-|-|-|-|-|-|-|-|-|-|18|
|End or freeze one session on the endpoint|-|g|g|A|-|g|P|-|c|-|-|-|-|G|18|
|Fleet kill switch including the inference route|-|-|g|g|-|-|-|c|-|-|-|-|-|-|18; 17|
|Disable an MCP server or skill by digest|g|g|g|g|-|c|-|-|-|-|-|-|-|-|18|
|Incidents with ticketing and SOAR sync|g|-|G|G|-|G|c|c|g|-|-|-|-|-|18; 25|
|**Platform**||||||||||||||||
|Documented API and SIEM export|g|-|G|G|-|g|c|c|g|g|g|G|g|-|23; 25|
|Roles with separation of duties|g|-|G|g|-|-|-|-|-|-|-|-|-|-|21|
|Provider (MSP) multi-tenancy|-|-|-|G|-|-|-|-|-|-|-|-|-|-|21|
|Tamper-evident audit, signed receipts|-|-|-|-|-|-|-|-|-|-|-|-|-|-|04; 21; the witness layer needs an external witness|
|**Deployment**||||||||||||||||
|Works with no server, sends nothing by default|-|-|-|-|-|-|-|-|-|g|G|G|G|g|11; 28|
|Self-hosted server and console|g|-|-|-|-|-|c|-|-|-|-|-|-|-|20; 24; 27|
|Hosted service with regions|G|g|G|G|c|G|P|G|c|-|-|-|-|-|32; needs revenue, sponsorship or donated cloud credits|
|Supported beside a third-party EDR|-|-|-|g|-|G|-|-|-|g|g|g|g|g|11; incumbent licences beyond Defender need design partners or free vendor programmes|
|**Openness**||||||||||||||||
|Open-source licence, nothing withheld|-|-|g|g|-|-|-|-|-|G|g|G|G|g|30; 36|
|Embeddable engine or OEM path|-|-|g|-|-|-|-|-|-|-|-|-|g|-|26; L2 to L6 need an embedding partner|
|Public price|g|-|G|-|-|-|-|-|-|G|G|G|G|G|36; 32; any paid offer needs counsel's opinion first (D-04)|
|Ungated documentation with a fail-mode table|g|g|g|g|-|g|-|-|-|G|g|G|G|g|34|

Reading notes. "Scoped" and "mandatory" are the spine's control grades; Windows mandatory needs the optional driver or an embedding partner (D-17), macOS mandatory needs Apple's Developer Program and the Endpoint Security entitlement (D-18). On macOS the join to OS effects requires Endpoint Security; without it the second source is the transcript and visibility stays `claimed` (D-18). Assurance by platform is in spine section 7. Identity follows R-35 and D-27: observed identifiers and credential inventory need only the sensor; helpers and the broker require the launcher and the protected profile; issued identity requires the token service and the server. Three prerequisites this map states where the spine is silent: tenant pinning requires the explicit proxy; open-project import requires 25's dialect manifests; policy export requires D-12's compile-down and a subset conformance test per target.

### 5. Whitespace: what nobody ships

|#|Gap|Evidence|Ours|
|---|---|---|---|
|W1|Discovery of unregistered agents that tells an agent from an LLM client by loop evidence, on Linux too|Microsoft and Netskope state the list is the limit; BeyondTrust treats any caller of an LLM host as an agent, Windows and macOS only|D-24, 05; on macOS requires Apple's Developer Program (tier 2)|
|W2|Hook-against-OS reconciliation as a product: "hook dark", unmatched effects scored against a housekeeping profile|Origin published the problem and ships no control|D-13, 07; requires an OS sensor and a housekeeping profile per agent version (S-07)|
|W3|Failure mode per rule class; a shim that still denies those classes when its daemon is down|One fail setting per hook or policy in every source read; BeyondTrust allows when its service is down; Falcon Guardian and Zscaler call a cloud API per event|D-14, D-15; 07|
|W4|Hook coexistence: owner-aware delivery, no overwrite, a canary proving the hook fired|Zscaler's guide replaces the `hooks` key; nobody documents merging|D-49; 07|
|W5|Exact-action grants with an approval grade|BeyondTrust relaxes a whole policy; others defer to the agent's own prompt|D-31; 18; G3 requires the server's `approve` target|
|W6|Attribution that states its grade and says "undetermined"|No rival documents a grade or an undetermined outcome; BeyondTrust shows the classifying evidence only|D-25; 06|
|W7|Identity for an unregistered local agent, bound to the sensor|Identity products assume a registered OAuth client|D-27; 15; issued identity requires the token service|
|W8|Session labels gating sinks at OS control points|BeyondTrust concedes no data-flow control|D-28; 16; sinks stay in Watch until replay passes|
|W9|Open, mandatory kernel enforcement on Linux, with WSL2, containers and CI in one graph|Palo Alto lists Linux with no mechanism; Falcon Guardian Linux is pre-beta; OpenShell confines only what it launches|D-19; 10; mandatory enforcement requires S-12 and trust-core review with a free external audit or a qualified volunteer reviewer|
|W10|A fully open multi-tenant console with a provider tier|Open projects paywall fleet, identity and console (08)|D-33, D-35; 20, 21, 27|
|W11|Published efficacy on agent-action scenarios|No lab has tool-call or MCP scenarios|D-45; requires the core and the replay model endpoint|
|W12|Private by schema|No rival documents pseudonymous principals or a ban on per-person scoring|D-51; 29|
|W13|Engine and content an EDR vendor can embed|Elastic proved content over foreign telemetry under a licence nobody can embed|D-41; 26; L2 to L6 require an embedding partner|
|W14|Endpoint-level, cross-vendor agent telemetry an MDR can run|MDR for agents exists only on Claude audit logs (eSentire, Daylight)|D-44; 18; requires the provider tier|
|W15|Signed receipts per decision|AARM R5 asks for it; no endpoint rival documents it|D-39; 04; the local chain needs no server|

Linux is a lead, not an empty field: Palo Alto, DefenseClaw and Prempti run there. Per-policy fail-closed is table stakes: Claude Code, Zscaler, Prempti and Anthropic inference hooks offer it. Central hook-health reporting exists only as BeyondTrust's Degraded state.

The eight leads of D-65, each with its evidence, shape (D-01) and what it requires:

|Lead|Evidence|Shape|Requires|
|---|---|---|---|
|Unregistered and bespoke agents|W1|Standalone, Platform|An OS sensor with network visibility; on macOS, Apple's Developer Program|
|Hook-against-OS reconciliation|W2|Standalone, Platform|Shim, an OS sensor and housekeeping profiles (S-07); on Windows, S-04 for Tier 1|
|Offline local decisions|W3; Falcon Guardian decides in its cloud, Microsoft documents no on-device verdict|All three|Core and shim|
|Codex, Cursor and open harnesses|No Microsoft runtime row; Falcon Guardian's collectors need its cloud|Standalone, Platform|A shim translator per agent; each agent joins Tier 1 when it passes the conformance suite|
|Open kernel enforcement, Linux to CI|W9|Platform; Embedded at L3|S-12; trust-core review plus a free external audit or a qualified volunteer reviewer|
|Self-hosting|Matrix, Deployment rows|Platform|Server in `embedded` and `ha` (S-02, S-03)|
|Open multi-tenant console|W10|Platform|Server; the provider tier also requires the tenancy model (D-35)|
|Published efficacy|W11|All three|Core and replay model endpoint; a third-party rerun needs an independent party|

### 6. Parity checklist

Sources: D-65 table stakes, the capabilities shipped by three or more vendors (h03), and the merged buyer checklist (h04). Endpoint items on Windows require S-04, console items require the server, and connectors require the integration host and a customer with access to each API.

|#|Item a buyer holds us to|Who sets the bar|Specified in and prerequisites|
|---|---|---|---|
|T1|Inventory of named agents, MCP servers and extensions on Windows and macOS, no manual registration|Microsoft, Falcon Guardian, Palo Alto|05; Windows Tier 1 requires S-04|
|T2|Pre-execution hook verdicts for Claude Code, Codex and Cursor|BeyondTrust, DefenseClaw, Palo Alto|07; Cursor requires its adapter to pass the conformance suite|
|T3|MCP control point with per-tool allow and block|Falcon Guardian, Check Point, Netskope|17|
|T4|Allow, Ask, Block plus a detect-only mode|Check Point, BeyondTrust, Sysdig|12|
|T5|Session-centred audit with run reconstruction|Palo Alto, BeyondTrust, Zscaler|06; local with no server, fleet requires the server|
|T6|Connectors for Copilot Studio, Agentforce, Bedrock AgentCore, Claude Enterprise|SentinelOne, Zenity, Check Point|25; Anthropic Compliance API and OpenAI Compliance Logs read-only (R-39), then the rest; each needs a customer with API access|
|T7|Runs beside a third-party EDR|Palo Alto Targeted Sensor|11; D-23 interference test, with incumbent licences through design partners or free vendor programmes|
|T8|MITRE ATLAS mapping of content|Palo Alto, Netskope, Elastic|13|
|T9|A verdict API for gateways (LiteLLM, Kong)|Zscaler, Netskope, Datadog|17; 23; requires the server's `decide` target (D-33, D-40)|
|T10|User and agent in every record; five verdicts|CSA AARM R1, R4|04; 12|
|T11|Recorded human approval for high-impact actions|BeyondTrust, SentinelOne|18|
|T12|Suspend one agent or a group; revoke credentials|Falcon Guardian, SentinelOne|18; session scope on the device, organisation scope requires the server, revoke requires the credential broker (15)|
|T13|SIEM, SOAR and ticketing integration with stable ids|Microsoft, CrowdStrike|25; generic sinks need no server, the lifecycle requires the server|
|T14|Policy versioning, dry run and rollback|BeyondTrust|12; 23|
|T15|Tamper-evident log kept 12 months or more|NHI Mgmt Group RFP|04; 21; local chain on the device, checkpoints require the server; receipts kept 13 months (D-39, D-51)|
|T16|Static-secret findings with age and last use; short-lived tokens|RFP|15; inventory needs only the sensor, short-lived tokens require the broker|
|T17|Assurance: SOC 2 or ISO 27001, penetration-test summary, export and deletion on exit|RFP|29; D-67 export and deletion and the control library cost nothing; paid certifications require revenue or a sponsor; a penetration-test summary requires a free external audit when one is granted (D-62)|

Where only the two read-only connectors exist, T6 is partly met (Copilot Studio, Agentforce and Bedrock AgentCore need their own connectors), and until the credential broker and token service pass their tests the credential halves of T12 and T16 are a known gap (R-39). Without revenue or a sponsor, T17's certification half is unmet. The generated RFP response (D-46) must say so.

### 7. Where we deliberately do not compete

|Not building|Who does|What we do instead|
|---|---|---|
|Identity provider or agent directory|Entra Agent ID, Okta|Broker and correlate (D-27)|
|SIEM or data lake product|Next-Gen SIEM, Sentinel, Elastic|Export contract and L4 (D-54, D-41)|
|Model-routing or key-management gateway|Portkey, LiteLLM, Falcon AI Gateway|An enforcement `gateway` target; adapters for theirs (D-40)|
|Prompt-classifier product as the primary control|Pangea detectors, Purview, Prompt Security|Deterministic tier 0; model tiers off until chosen (P2, D-29)|
|Mandatory TLS interception|BeyondTrust, Prompt Security, Netskope|Tiered visibility; chain or stand down (D-16)|
|SaaS account auditing and session-riding checks|Sidekick, Push, Nudge, Reco|Connectors at AL1; tenant pinning|
|Enterprise browser|Island, Seraphic, Edge|An extension (17)|
|Sandbox runtime for cloud fleets|OpenShell, agent-sandbox, E2B|Recognise as containment back end and export policy (D-21)|
|MCP and skill reputation at catalogue scale|Prompt Security, Pillar, AIR|Mirror, pin by digest, detect drift; own scanning requires the server's `intel` target and data from many organisations (D-32)|
|Managed detection service|Falcon Complete, eSentire|The provider workbench an MDR runs (D-44)|
|AI red teaming, model safety, mobile and ChromeOS sensors|Dreadnode, HiddenLayer|Nothing: not goals (spine section 1)|
|Windows kernel tamper resistance without the driver|CrowdStrike, Microsoft|Report `tamper: admin`; reach it through an embedding partner (D-17, D-22)|

### 8. Positioning by buyer

- **Solo developer (Standalone).** See every agent on your machine and what it did, and block the few actions you would never approve, with no account and nothing sent anywhere. Unlike free hook guards it checks the agent's story against the operating system, with Linux as the reference platform (macOS reports `claimed` without D-18 tier 3).
- **Team that self-hosts (Platform, requires the server).** The whole product under Apache-2.0, including sign-on, roles and audit, on one node or highly available, with your data in Parquet you can take away.
- **Enterprise running CrowdStrike or Defender (targeted build, or Platform with the server).** Keep your EDR. Guardrails adds the agent layer where it is missing, decides on the device, takes no exclusive slot, and tells you per action whether a control is a boundary or a request.
- **MSP or MDR (provider tier, requires the server and the tenancy model).** One queue across organisations, baselines per organisation set, delegated access the customer can revoke, and no licence that withholds the console.
- **EDR or gateway vendor (Embedded: L0 and L1 need only the sensor and content; L3 and L4 require an embedding partner).** Detection content for your query language with no partner work; an engine you can link or run as a sidecar, under your brand and signing keys, with no call home.
- **Privacy officer or works council (every shape).** Metadata by default, pseudonymous people, no per-person scoring, a disclosure surface nobody can hide.

## Interfaces and contracts

**Claim records.** `docs/competitive/claims/<product>.yaml`, one entry per capability:

```yaml
capability: enforcement.hook_verdict.codex_cursor   # id from capabilities.yaml
status: shipping-narrow   # shipping | shipping-narrow | preview | announced | claimed | not-documented
as_of: 2026-11-09         # date the source was read
source_url: https://...
source_kind: primary      # primary | secondary
quote: ""                 # vendor's words; required when the note asserts an absence
note: "Codex collector public; Cursor named, no public collector"
```

**Guardrails records.** `docs/competitive/guardrails.yaml`: capability id, decision ids, design documents, external precondition (if any), support tier (D-50), `plan_row`, `acceptance_test`. The generator fails when a row lacks a `PLAN.md` row or names a test absent from the harness (D-45) or the conformance suites.

**Generated outputs.** `docs/competitive/matrix.md` (section 4), the parity table and the public comparison page (34). None is edited by hand.

**Contracts with other documents.**

|Other document|Exchange|
|---|---|
|Spine and 33|`PLAN.md` rows. This map reads each capability's design document, prerequisites and acceptance test from them; the three prerequisites it adds (section 4 reading notes) take effect only as `PLAN.md` rows|
|05 inventory|Catalogue import dialects: Uber ADR catalogue, Defender `AgentsInfo`, Falcon Guardian entities|
|04 and 25 export|Dialects in: Numbat NDJSON v0.5.0, Falco alert JSON, DefenseClaw audit rows, OpenShell sandbox events. Sinks out: HEC for Next-Gen SIEM, OTLP for Agent 365|
|07 control points and hook broker|Per-agent fail-mode table (D-15) and capability claims in the draft portable hook vocabulary (D-14). The map links to them|
|D-23 coexistence|The interference test and ceiling matrix are the authority, and the test, for "beside a third-party EDR" cells; cells without a licensed incumbent are marked untested|
|29 and D-46|T1 to T17 feed the RFP response and release gates|
|36|Price anchors, and the legal rule for naming rivals in public|

**Interoperation with open projects (D-65).**

|Project|Ingest|Export|Tier in, out (D-50)|
|---|---|---|---|
|OpenShell|Sandbox events; a containment fact per session|Forbids over path and host classes as OpenShell policy|2, 2|
|DefenseClaw|Audit rows as events|Deny sets as a policy pack fragment|2, 3|
|Numbat|NDJSON findings and events|Deny sets as CEL rules|2, 3|
|Prempti|Falco alert JSON|Falco rules, only if upstream releases resume|3, 3|

Exports obey D-12: only unconditional, locked forbids compile down, and each target has a conformance test proving its denials are a subset of what Cedar always denies.

## Behaviour by deployment shape

D-01 makes each shape a product, so each has its own rivals and its own completeness test (D-50: all five jobs work for every Tier 1 cell at the stated assurance with zero silent fail-open).

|Shape|Rivals|What they lack|Complete when|
|---|---|---|---|
|Standalone|Numbat, Prempti, DefenseClaw, the free tiers of Origin and Knostic|Free tiers observe only or need an account; open hook guards have no console, no OS cross-check, and rules that only monitor by default|Discovery passes 1 and 2 (pass 3 on Linux, and on macOS with the Network Extension, D-24), session attribution, AL2 hooks, Essentials, protected paths, tier 0 detections and session response pass in every Tier 1 cell; no server and no external precondition needed on Linux x64 and macOS arm64|
|Platform, self-hosted|None with an open console|Fleet, identity and console are paywalled elsewhere|The server in `embedded` and `ha` passes the same test with the organisation, group and fleet entries|
|Platform, hosted|Every commercial product|Local decisions, Linux, published efficacy, exit by export|Requires the `distributed` profile and its load test and D-63's preconditions (two people on call, met by the owner and the buddy; Loonaro as the legal entity; a written incident-reporting process), and infrastructure funded by revenue, sponsorship or donated cloud credits|
|Embedded|Palo Alto Targeted Sensor (beside, not inside); Okta consuming Falcon|Elastic's content cannot be embedded; Microsoft's MIT policy runtime is in-process, with no sensor content|L0 and L1 need only the sensor and content; complete when one L3 pilot evaluates all five jobs or returns "not evaluable" per rule (D-60), which requires an MVI-member EDR or MDR design partner|

The GR column and the parity table describe Platform. In Standalone, entries needing a server (T6, T9, T17, and the organisation, fleet and provider parts of other entries) do not apply. In Embedded, enforcement and response entries inherit the host's assurance or return "not evaluable" (D-60).

## Extension points

- **A new rival or capability.** Add a claims file or a row in `capabilities.yaml` by pull request; no code changes.
- **A new import dialect.** A declarative mapping manifest (D-40 tier one) plus golden vectors; Tier 2 until first-party.
- **A new compile target.** A code-defined template with its subset conformance test (D-12); Tier 3 until proven for two releases.
- **Vendors may correct their own row** by pull request with a primary source.

## Security and privacy

- Rival products are examined from public documentation, public source and lab installs licensed through design partners or free vendor programmes only. Source-available and copyleft code is on the do-not-read list (D-02): Elastic's rules, Pipelock's `enterprise/` directory and Sage's rule files are behaviour references, never copied.
- Imported events from other tools are claims (P3) with their provenance grade and never raise assurance by themselves.
- Lab installs of rival sensors run only in isolated snapshot-revert guests on tier B machines, or on tier C (D-64), and those guests hold no project secrets.
- Web pages read by the re-verification agent are data, not instructions; it runs read-only and opens a pull request for human review (D-47).
- The public comparison names no person and quotes at most one short phrase per source.

## Test and evaluation strategy

|Property|Oracle|
|---|---|
|Every rival cell is sourced and dated|Schema and link checks; a record older than 120 days renders as stale|
|No negative overclaim|A lint rejects "cannot" or "does not" in generated text unless the record is `primary` and carries a `quote`; otherwise the text reads "not documented"|
|Guardrails cells are true|A Guardrails capability is shown as working only when its acceptance test passes in every Tier 1 cell; otherwise the public page shows the design document and prerequisites, not a status|
|Our standalone build is not a me-too|Spike S-CM1|
|Parity items hold|Each of T1 to T17 maps to a harness or conformance scenario; the RFP gate (D-46) fails the release otherwise|
|Interoperation works|Golden vectors from pinned upstream releases; a nightly run against each upstream's latest release opens an issue on drift|

Head-to-head numbers are published only for Apache-2.0 tools, with configuration, under the three-pass method (D-45). Commercial products are compared on documented behaviour unless counsel clears their terms (36).

## Work breakdown

**Epic CM-A: map as data**

- CM-1 Schemas for capabilities, claims and Guardrails records. *Accept:* an invalid status or missing `as_of` fails `verify`.
- CM-2 Seed files from this document. *Accept:* the generated matrix equals section 4 cell for cell. *Requires:* CM-1.
- CM-3 Generator and lints (staleness, negative overclaim, `PLAN.md` binding). *Accept:* removing a `PLAN.md` row fails the build. *Requires:* CM-1.

**Epic CM-B: baseline against open rivals**

- CM-4 Run Numbat, Prempti and DefenseClaw through the efficacy harness on Linux x64 (spike S-CM1). *Accept:* a scorecard per tool with pinned version and configuration. *Requires:* the efficacy harness (D-45).
- CM-5 Rerun CM-4 on the standalone build with hook-dark and Essentials scenarios; publish the standalone comparison. *Accept:* every row links a scenario id; no rival beats us on block reliability for Essentials rules. *Requires:* CM-4, the Linux sensor, the Essentials pack and one CM-11 pass.

**Epic CM-C: complement incumbents**

- CM-6 to CM-8 Defender and Falcon Guardian importers, the Next-Gen SIEM HEC sink with parser and dashboard, and the four open-project import dialects are 25's IMP-1, IMP-2, ENH-1 and IMP-5; this map's cells read their acceptance results.

**Epic CM-D: parity gates**

- CM-9 Bind T1 to T17 to scenarios and the RFP response. *Accept:* `verify` fails when a T item has no scenario id; the response marks each item met, partly met or unmet with its prerequisites.
- CM-10 Analyst mapping page: Gartner guardian-agent areas, Forrester agentic control plane, Latio categories, KuppingerCole AI-VOP and ATDR. *Accept:* every analyst category maps to a capability id or is listed as not covered; published with 34.

**Epic CM-E: upkeep**

- CM-11 Re-verification every 90 days by a read-only gardener with a usage cap per run (D-47). *Accept:* a pull request listing changed cells with sources; no stale record at a release.
- CM-12 Wedge review, run when adoption data exists or an incumbent ships a lead's capability. *Accept:* a decision record that keeps, reorders or drops each D-65 lead against adoption data.

**Epic CM-F: export targets**

- CM-13 and CM-14 Compile targets for OpenShell, DefenseClaw and Numbat, the Agent 365 OTLP exporter and the Copilot Studio verdict provider are 25's IMP-7, EXP-7 and VPA-3.

## Risks, open questions and spikes

|Risk|Trigger and response|
|---|---|
|The map goes stale: Origin ships every two weeks; 14 acquisitions were announced in 2026|A stale record at release: the release note says so and the cadence drops to 45 days|
|An incumbent closes a lead (Defender adds Codex and Cursor; Falcon Guardian ships Linux)|Re-verification flags the cell; the wedge review reorders leads|
|A public comparison draws a legal complaint|Primary sources, the status vocabulary, counsel review before first publication, through free foundation legal programmes first (36)|

**Spike S-CM1: is the standalone build a me-too?** Run the efficacy harness scenarios against Numbat, Prempti and DefenseClaw at pinned releases and against our core and shim build. Pass: only our build reports the scripted bespoke agent and the unmatched OS effect, with zero silent fail-open under fault injection. Hook-dark and Essentials need the Linux sensor and the Essentials pack; CM-5 reruns with them. Fail: revise which leads the standalone shape is built and positioned on. Decisions at stake: D-65, D-01.

**Open questions, each with the experiment that settles it.**

1. Does SentinelOne ADR use hooks, its kernel sensor or the Prompt proxy on endpoints? A trial tenant on an isolated lab guest (D-64), if a free trial or a design partner provides one.
2. What are Cortex AES's hook fail mode and interception mechanism? The same lab method, plus S-05 with its hooks installed.
3. How does Falcon network inspection obtain plaintext? Observe the sensor beside our explicit proxy in the interference test.
4. Which permissions does Sidekick's extension request? Read its manifest in an isolated profile.
5. Does Sysdig AI Defense support Linux desktops? Re-read at the next re-verification pass.

## Deviations from the spine and objections

No deviation. Two objections:

1. **D-65 lists SaaS connectors as table stakes.** Resolved by R-39: two read-only connectors (Anthropic Compliance API, OpenAI Compliance Logs) need only the integration host and a customer with API access; the credential halves of T12 and T16 require the credential broker and token service and stay a stated gap until those pass their acceptance tests.
2. **Open. D-65 names kernel enforcement on Linux as a lead, but observation and scoped boundaries are what Linux has without it, and Palo Alto already lists Linux.** Kernel enforcement requires S-12 and trust-core review with a free external audit or a qualified volunteer reviewer; until it leaves the internal ring the claim that holds is "open, with OS cross-check", and public wording should say only that.

## Sources

Research briefs 01 to 08, 16, 17, 27, g02, g03, h03, h04 and h05; captures under `research/_sources/` (BeyondTrust, CrowdStrike, Origin). Review notes: `c6-product-oss-embed`, `l02-enterprise-buyer`, `00-resolution`, `02-owner-answers`.

Primary pages behind the load-bearing claims (read dates in the briefs):

- Origin: https://docs.originhq.com/llms-full.txt ; https://www.originhq.com/changelog ; https://www.originhq.com/research/otel-telemetry-asymmetry ; https://www.originhq.com/pricing
- BeyondTrust: https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security ; https://docs.beyondtrust.com/bt-docs/docs/policies ; https://docs.beyondtrust.com/bt-docs/docs/exception-requests-details ; https://www.beyondtrust.com/press/ai-agent-security-general-availability
- Microsoft: https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix ; https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection ; https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-local ; https://github.com/microsoft/mxc
- CrowdStrike: https://aidr-docs.crowdstrike.com/docs/aidr/collectors/falcon-endpoint/network-inspection ; https://github.com/CrowdStrike/falcon-guardian-codex-collector ; https://www.crowdstrike.com/en-us/blog/crowdstrike-introduces-ai-kill-switch/ ; https://github.com/CrowdStrike/falcon-mcp
- Sidekick: https://sidekicksecurity.ai/
- Palo Alto: https://cortex-docs.paloaltonetworks.com/cortex-xdr-6.x-rn/release-information/features-introduced-in-2026/november-2026/release-highlights
- Others: https://github.com/cisco-ai-defense/defenseclaw ; https://github.com/uber/ADR ; https://github.com/perplexityai/numbat ; https://github.com/falcosecurity/prempti ; https://github.com/NVIDIA/OpenShell ; https://github.com/NVIDIA/NeMo-Guardrails ; https://github.com/guardrails-ai/guardrails ; https://github.com/meta-llama/PurpleLlama ; https://github.com/NVIDIA/garak ; https://github.com/Azure/PyRIT ; https://github.com/promptfoo/promptfoo ; https://www.sysdig.com/blog/introducing-sysdig-ai-defense ; https://docs.netskope.com/en/netskope-client-ai-discovery/ ; https://github.com/zscaler/zguard-ai-integrations ; https://nhimg.org/ai-agent-security-platform-rfp-guide ; https://aarm.dev/spec
