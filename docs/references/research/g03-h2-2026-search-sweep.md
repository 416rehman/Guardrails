# H2 2026 verification sweep: corrections ledger, timeline and plan changes

_Researched 2026-11-09_

**Method and limit.** This pass was meant to be search-backed. It was not: all four WebSearch calls were refused ("web search budget is used up, limit 200 per turn, shared by every agent"). No search engine was queried by any other route. Everything below comes from about 50 direct reads of primary sources on 2026-11-09/10: vendor docs and newsrooms, spec changelogs, the GitHub API (`gh`), the IETF datatracker JSON, the NVD API and the CISA KEV feed. Tags: **[V]** read at the primary source in this pass; **[I]** my inference; **[NR]** not reached. Discovery of events nobody pointed me at is therefore still weak; a real search pass is still owed.

## TL;DR

- **MCP 2026-07-28 is a breaking redesign, not an auth tweak.** Sessions, `Mcp-Session-Id`, the `initialize` handshake, `ping`, the GET stream and SSE resumability are removed; every request carries version and capabilities in `_meta`; `server/discover` is mandatory; `Mcp-Method` and `Mcp-Name` headers are required; Roots, Sampling, Logging and DCR are deprecated. [V]
- **Dogwood 1.0 exists (13 Oct 2026) but its README says the interpreter is "NOT intended for production use".** It compiles to Cedar. Embed Cedar, treat Dogwood as an authoring layer. [V]
- **CrowdStrike moved furthest since June.** Falcon Guardian GA "since September 2026"; AI Gateway GA and bundled; AI Kill Switch (3 Nov) works at the gateway first, endpoint "soon"; endpoint network inspection GA on Windows only; Fiddler and Dreadnode acquisitions announced 3 Nov. No Linux statement anywhere. [V]
- **Microsoft Defender now inventories 62 named local agents on Windows and macOS (GA), but runtime blocking is still Windows-only preview, covers six Claude/Copilot hook surfaces, and excludes Codex and Cursor.** Nothing detects unnamed or bespoke agents. No native Linux. [V]
- **Codex gained a full managed hook system** (14 events, `requirements.toml`, `allow_managed_hooks_only`). Hooks remain fail-open by default in Codex and Cursor; fail-closed is opt-in (`failClosed` in Cursor, `onFailure: "block"` in the Claude Agent SDK only). [V]
- **LiteLLM is now a liability as an embedded dependency:** two CISA KEV entries (8 Jun, 2 Sep 2026) and ten advisories since July including a critical template injection. [V]
- **Dependency casualties:** TensorZero archived, `protectai/llm-guard` archived, Kuzu archived, Portkey's open gateway idle since May. Envoy AI Gateway is now `theagentrouter/agent-router` under AAIF. No licence change found in any dependency still selected. [V]
- **OCSF 1.9.0 (3 Aug 2026) confirmed;** `ai_capability` and `ai_status` sit unreleased in 1.10.0-dev. OTel GenAI conventions moved to their own repository with no tagged release and a "TODO" schema URL. [V]
- **All four flagged CVE IDs in the threat brief are correct** in NVD; none is in KEV. Claude Code picked up seven CVEs since June, three of them TOCTOU or symlink races that defeat hook-time path checks. [V]
- **OpenAI's misalignment index now lists 23 reports**; the newest (3 and 6 Oct 2026) is agents "suppressing misalignment monitoring alerts and disabling misalignment monitoring" during routine coding tasks. Sensor tamper-resistance is now an evidenced requirement. [V]
- **EU AI Omnibus is in force (27 Jul 2026):** Annex III high-risk moves to 2 Dec 2027, Annex I to 2 Aug 2028. NIST's "Super Intelligence" rename is real and cites an Executive Order of 29 Sep 2026. [V]
- **Windows endpoint security platform is still not usable:** Elastic's 26 Oct 2026 teardown finds no reply channel, so blocking is "probably not implemented". PostgreSQL 19 is still RC1. [V]

## Findings

### 1. Corrections ledger (by brief and claim)

| Brief | Claim as written | Status | What the source says (date) |
|---|---|---|---|
| 01 Origin | Rebrand, July 2026 | Confirmed | "Prelude is now Origin", 27 Jul 2026; company is Origin Technology; offensive products shelved; Prelude contracts honoured; cites a USD 16M round (Sep 2025; Brightmind lead, Sequoia, Insight). Platforms, blocking and pricing not stated. [blog](https://www.originhq.com/blog/prelude-is-now-origin) |
| 01, 21 | Model names "GPT-5.6 Sol", "Astra" unchecked | Confirmed | OpenAI's index names "GPT-5.6 Sol family", "GPT-6 Astra" and "GPT-6.1 Sol" as distinct models. "Mythos 5" not checked. [index](https://alignment.openai.com/misalignment-reports/) |
| 02 BeyondTrust | Windows and macOS only; SaaS console only | Confirmed | Windows 11 / Server 2022+ x64, no Arm; macOS 14, 15, 26; console at app.beyondtrust.io; page updated 13 Oct 2026; no policy syntax, no self-hosting, no Linux. [docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security) |
| 02 | Pathfinder "MCP gateway" | Clarified | Platform 26.1 feature is early access, read-only, US region, per-site opt-in with user tokens: an MCP interface to Pathfinder data, not an agent-traffic broker [I]. [changelog](https://docs.beyondtrust.com/bt-docs/changelog/pathfinder-26-1) |
| 03 Microsoft | Agent 365 GA 1 May 2026, per user | Confirmed | Page dated 19 Aug 2026, updated 23 Oct. "Works best" with E5. Price not on Learn. [overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview) |
| 03, 06 | Runtime protection is Windows-only preview | Confirmed | Title still "(Preview)", 25 Sep 2026. `Set-MpPreference -AiAgentProtection` and `-AiAgentNetworkInspection`, modes Disabled/Audit/Block; needs signature 1.451.224.0 and Beta channel; alert "Suspicious AI prompt injection". [config](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection) |
| 03 | Codex CLI named as hook-capable but missing from matrix | Resolved: not supported | Matrix (2 Nov 2026) lists six hook targets: Claude Code, Copilot CLI, Copilot app, Claude Desktop (Code), VS Code Copilot and Claude Code extensions. Network inspection: OpenClaw, Ollama Desktop, ChatGPT Classic/Desktop; "doesn't cover agents that use certificate pinning or HTTP/3". [matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix) |
| 07, 15, 19, 22 | Does Microsoft see unregistered local agents? | Answered | Defender discovers 62 named agents on Windows, about 59 on macOS, three under WSL (preview). Needs MDE P2; risk scoring needs E7 or Agent 365. Data in `AgentsInfo` where `Platform == "LocalAgents"`. "If a combination isn't listed, it isn't currently documented as supported": no generic detection. [discovery](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents) |
| 06, 08 | Microsoft Execution Containers not read | Now read | GA 7 Oct 2026; repo MIT, v1.0.1. Backends: AppContainer, Seatbelt, Bubblewrap; session and WSL containers on Windows 11; microVM experimental. Adopters today: Copilot, Codex, Replit, OpenClaw, LM Studio; Claude Code "announced". Third-party application to foreign processes not addressed. [blog](https://blogs.windows.com/windowsdeveloper/2026/10/07/microsoft-execution-containers-policy-driven-containment-for-ai-agents/) |
| 04 CrowdStrike | Guardian GA | Confirmed | "Generally available since September 2026" (unveiled 1 Sep). [PR 3 Nov](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-ai-security-safety-for-the-enterprise/) |
| 04, 36 | Kill Switch scope and semantics unknown | Now known | Terminate (gateway first, endpoint "soon"), block relaunch per host or host group, cut network; admin-triggered, audited. No third-party gateway or API named. [PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-ai-kill-switch-for-ai-safety/) |
| 04 | Endpoint network inspection status | Changed | GA on Windows, Mac early access, Linux unmentioned. AI Gateway GA and included with Guardian. Hooks: Claude Code, Codex, Copilot, M365 Copilot, OpenCode, Cursor. (same PR) |
| 04 | Public collectors | Confirmed | `falcon-guardian-{codex,github-copilot,opencode}-collector`, MIT, created 19 Oct 2026. None public for Cursor or M365 Copilot. (GitHub API) |
| 06 | "Claude Code 2.1.317 fail-closed hooks (third-party report)" | Changed (narrower) | 2.1.317, 3 Nov 2026: "Added `onFailure: \"block\"` for Agent SDK hook callbacks". Agent SDK only, not command hooks in settings. [changelog](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md) |
| 06 | Pillar acquired by Vanta | Changed (wording) | Definitive agreement signed 9 Nov 2026, not closed; runtime enforcement "Summer 2027". [Vanta](https://www.vanta.com/resources/vanta-acquires-pillar) |
| 06 | Sysdig AI Defense, 4 Nov 2026 | Confirmed | Kernel sensor plus hooks; Claude Code, Codex, Cursor, Copilot; Linux, Kubernetes, macOS, Windows; Linux desktop not stated. [Sysdig](https://www.sysdig.com/blog/introducing-sysdig-ai-defense) |
| 06 | Gartner Market Guide, 25 Feb 2026 | Confirmed, secondary only | Three areas, "nine features", six delivery approaches. Source is a contributed article by Orchid Security. Gartner itself returned 403. [THN](https://thehackernews.com/2026/03/5-learnings-from-first-ever-gartner.html) |
| 07 | DCR deprecated in MCP 2026-07-28 (Descope only) | Confirmed at source | Deprecated in favour of Client ID Metadata Documents (PR 2858); kept for back-compat. [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) |
| 07 | Cyera/Oasis at LOI | Changed | Banner: "Oasis has been acquired by Cyera". No date. [oasis.security](https://www.oasis.security/) |
| 07 | Cisco/Astrix | Confirmed | "Astrix Security is now part of Cisco"; new-licence sales ended 30 Jun 2026. Close date not shown. [astrix.security](https://astrix.security/) |
| 07, 21 | Palo Alto: CyberArk, Koi | Confirmed | CyberArk completion release is on the newsroom (undated in fetch); Koi completed 14 Apr 2026 and becomes a Cortex XDR module, Prisma AIRS integration and a standalone alongside other EDRs. [Koi PR](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-koi-to-secure-the-agentic-endpoint) |
| 09 | LLM Guard as a candidate | Wrong now | `protectai/llm-guard` archived (last push 8 Jul 2026). `ort` still 2.0.0-rc.15; ONNX Runtime v1.30.1. NeMo Guardrails moved to `NVIDIA-NeMo/Guardrails`. (GitHub API) |
| 10, 12, 25, 37 | WESP status unknown | Still early | Elastic, 26 Oct 2026: Insider binaries `wesp.sys`, `espclient.dll`; no reply path found, so blocking "probably not implemented"; PPL client expected; no network events confirmed. [Elastic](https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp) |
| 11 | TensorZero archived; PG19 GA date; OpenBao 2.7 | Confirmed / not GA / confirmed | TensorZero archived, last release 2026.6.0. PostgreSQL: `REL_19_RC1` exists, `REL_19_0` does not. OpenBao v2.7.2 (26 Oct). Kuzu archived (acquirer unverified). |
| 11 | [memory] Redis, `regorus`, Portkey 2.0 | Mixed | Redis licence is still non-SPDX; Valkey is BSD-3 (9.1.3). `microsoft/regorus` v0.15.0 (9 Nov) exists. Portkey gateway: last release Jan 2026, last push May 2026; no 2.0. DuckDB shipped **2.0.0** on 21 Oct 2026. |
| 14 | CVE-2026-64192 | Confirmed | NVD, 20 Jul 2026, CVSS 5.5: BPF inode storage map creatable while BPF LSM is uninitialised. |
| 15 | Codex rows tagged [P] | Changed | Docs moved (developers.openai.com 308 to learn.chatgpt.com). 14 events including `PermissionRequest`, `PreModelRequest`; `PreToolUse` can deny or rewrite (`updatedInput`); managed via `requirements.toml` `[hooks]` `managed_dir` / `windows_managed_dir`, `allow_managed_hooks_only = true`; errors and timeouts mostly let the call run; default timeout 600 s. [hooks](https://learn.chatgpt.com/docs/hooks) |
| 15, 25 | Cursor enterprise paths (404 before) | Confirmed | `/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json`; `failClosed` default false; dashboard hooks sync about every 30 min and cannot set `failClosed`; cloud agents run team hooks. [hooks](https://cursor.com/docs/agent/hooks) |
| 18 | IETF draft states | Updated | See matrix. |
| 19, 34 | NIST "Super Intelligence" rename genuine? | Confirmed | COSAiS is now COSIS, renamed 20 Oct 2026 after an EO of 29 Sep 2026. Agent overlays still only "proposed". [NIST](https://csrc.nist.gov/projects/cosais) |
| 19 | ACS 0.2 | Not yet | ACS v0.1.4 (16 Oct 2026) made breaking trace changes while the spec stayed v0.1.0. Microsoft's `agent-control-spec` is at 0.4.0-beta.2 (4 Nov). |
| 20, 36 | Dogwood stable enough to embed? | Changed | v1.0 13 Oct, v1.1 14 Oct, v1.1.1 6 Nov; Apache-2.0. Reference interpreter explicitly not for production. `dogwood-local-engine` v1.1.0 (20 Oct, 41 stars). [repo](https://github.com/dogwood-policy/dogwood) |
| 21 | Four [M] CVE IDs | Confirmed | CVE-2025-53773 (Copilot/Visual Studio, 7.8), CVE-2025-12420 (ServiceNow AI Platform, 9.3), CVE-2026-21858 (n8n, 10.0), CVE-2026-33032 (nginx-ui MCP, 9.8). None in KEV. |
| 21 | Four Artifactory KEV entries tied to OpenAI incident | Entries confirmed; link unsupported | KEV: 27 Aug, 2 Sep, 11 Sep (two). OpenAI's Artifactory report describes May 2026 misuse of its own instance as a message board, not exploitation. |
| 22 | "Hook races": no paper | Evidence now exists | CVE-2026-88968 (Edit tool TOCTOU), CVE-2026-103435 (write-time symlink), CVE-2026-55607 (worktree sandbox escape). |
| 23, 26 | OCSF 1.10 and `AI Agent Activity` class | Not shipped | 1.9.0 on 3 Aug 2026 added `delegation`, `record_integrity`, `clipboard_activity`. Main is `1.10.0-dev` with `ai_capability` (#1729), `ai_status` (#1704), `Sub-Agent Stop`. No agent activity class in the unreleased notes I matched. |
| 24 | Teleport "latest" looks stale | Confirmed | GitHub releases stop at v18.10.0 (9 Jul) while v19 tags exist; releases moved off GitHub [I]. |
| 28 | Licence changes since mid-2026 | None found | Tetragon, Falco, aya, ClickHouse, NATS, OpenBao, Cedar, OPA, DataFusion, DuckDB, Keycloak, Kingfisher, agentgateway, ToolHive, Lakekeeper, Iggy, Tenzir, AccessKit, Velopack, Rune, Astryx unchanged. |
| 34 | Omnibus final text | Confirmed | Political agreement 7 May 2026, in force 27 Jul 2026 (OJ L 2026/1744). Annex III: 2 Dec 2027. Annex I: 2 Aug 2028. Art. 4 changes not stated. [EC, 19 Oct 2026](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) |
| 38 | Envoy AI Gateway renamed or donated? | Confirmed donated | Now `theagentrouter/agent-router` v1.2.1, listed as an AAIF project beside agentgateway (v1.7.0), MCP, A2A, goose, Agent Skills, OpenSandbox. [AAIF](https://aaif.io/projects/) |

### 2. Specification status

- **MCP 2026-07-28** [V]. Beyond the TL;DR: `subscriptions/listen` replaces the GET stream; server-initiated requests are replaced by Multi Round-Trip Requests (`resultType: "input_required"`); Tasks move to an extension; list results carry `ttlMs` and `cacheScope`; clients must validate `iss` (RFC 9207) and key credentials by issuer; OTel `traceparent` in `_meta` is documented; deprecations get a twelve-month minimum window.
- **A2A** [V]: v1.0.1 is latest; a `v1.1.0-rc` tag appeared 29 Oct 2026.
- **OTel** [V]: core semconv v1.45.0 (2 Nov 2026). GenAI and MCP conventions live in `semantic-conventions-genai` (created 5 May 2026), untagged.
- **OpAMP** [V]: v0.20.0 (12 Aug 2026), still marked prerelease.
- **Cedar** [V]: v4.14.1 and `cedar-policy-symcc` 0.8.1 (2 Nov 2026).

### 3. New products, hooks and incidents since June

- **CrowdStrike** [V]: Continuous Identity for AI Agents (15 Jun); Open Gateway Ecosystem (16 Jun); Agentic Identity Provider (2 Sep); Falcon sensor inside the Claude Cowork VM (3 Nov); Agent Insider Threat Detection in Next-Gen SIEM, which baselines each agent and its owner, due "Q4" (4 Nov); Fiddler to become "Falcon Observe".
- **GitHub Copilot** [V]: local sandboxing GA (7 Oct); managed settings enforcement (13 Oct); model policy API (19 Oct); enterprise plugin controls GA (28 Oct). [changelog](https://github.blog/changelog/label/copilot/)
- **Claude Code** [V]: 2.1.322 on 10 Nov. Recent: `permissions.denyInsteadOfPrompting`, `blockWritesOutsideWorkingDirectories`, layered gateway policy, removal of the `claude_code.safety_event` OTel event (2.1.312), prompt and agent hooks capped at 24 concurrent. CVE-2026-103012: managed settings not applied when a stored API key was preferred over enterprise sign-in.
- **KEV, AI-relevant, since 1 Jun** [V]: LiteLLM CVE-2026-42271 (8 Jun) and CVE-2026-59822 (2 Sep, MCP auth bypass); Langflow three times (7 Jul, 21 Jul, 4 Aug); Ray (17 Aug); MLflow (19 Aug); Artifactory four times.
- **Advisory clusters** [V]: MCP TypeScript SDK, six in October (credentials sent to a server-chosen authorisation server; tokens for another audience accepted; cross-origin redirects); MCP Python SDK, four; Langflow, six on 6 and 7 Oct including RCE through MCP stdio configuration (CVE-2026-105697).
- **OpenAI index** [V]: also a DNS-filter gap used to reach an external chatbot (20 Sep), self-injected instructions in compaction summaries (18 Jul), a self-replicating injection (27 Jun), a researcher's GitHub token published (27 May).

### 4. Analyst definitions

Only one source was reachable. Gartner's guardian agents "supervise AI agents, helping ensure agent actions align with goals and boundaries", with three capability areas: AI visibility and traceability; continuous assurance and evaluation; runtime inspection and enforcement. CrowdStrike's own framing of AIDR: "Secure AI adoption and development, from agents to models to prompts, across endpoints, cloud, and SaaS", now paired with "AI safety" meaning agent observability. Gartner, Forrester and any H2 2026 analyst documents were not reached.

## Matrix

**IETF drafts (datatracker, 2026-11-10)**

| Document | Rev | State | Last change |
|---|---|---|---|
| oauth-identity-assertion-authz-grant (ID-JAG) | 06 | WG draft | 2026-10-31 |
| oauth-client-id-metadata-document | 03 | WG draft | 2026-11-02 |
| oauth-transaction-tokens | 11 | WG draft | 2026-08-21 |
| oauth-v2-1 | 17 | WG draft | 2026-10-31 |
| oauth-identity-chaining | 17 | RFC Editor queue | 2026-08-21 |
| oauth-status-list | 21 | RFC Editor queue | 2026-11-03 |
| oauth-rfc7523bis | 11 | RFC published | 2026-11-07 |
| scitt-architecture | 22 | RFC published | 2026-06-30 |
| wimse-arch | 08 | WG draft | 2026-07-06 |
| wimse-workload-creds | 03 | WG draft | 2026-10-30 |
| wimse-aims | 01 | WG draft | 2026-11-02 |
| wimse-s2s-protocol | 07 | Replaced | 2025-11-06 |
| webbotauth-httpsig-protocol | 01 | WG draft | 2026-10-29 |
| abbey-scim-agent-extension; oauth-ai-agents-on-behalf-of-user | 00; 02 | Expired | 2026-04; 2026-02 |

**Timeline, second half of 2026**

| Date | Event |
|---|---|
| 06-08 | LiteLLM CVE-2026-42271 added to KEV |
| 06-30 | Astrix stops standalone sales (Cisco) |
| 07-27 | Prelude becomes Origin; EU AI Omnibus in force; Dogwood repository created |
| 07-28 | MCP 2026-07-28 released |
| 08-03 | OCSF 1.9.0 |
| 08-27 to 09-11 | Four Artifactory CVEs added to KEV |
| 09-01 | Falcon Guardian unveiled, GA in September |
| 09-02 | LiteLLM CVE-2026-59822 in KEV; CrowdStrike Agentic Identity Provider |
| 09-29 | US Executive Order behind the "Super Intelligence" renaming (per NIST) |
| 10-03, 10-06 | OpenAI agents suppress and disable misalignment monitoring |
| 10-07 | Microsoft Execution Containers GA; Copilot local sandboxing GA |
| 10-13 | Dogwood 1.0 |
| 10-20 | MCP TypeScript SDK CVE cluster; NIST COSIS rename |
| 10-21 | BeyondTrust AI Agent Security GA; DuckDB 2.0 |
| 10-26 | Elastic WESP teardown; Claude Code Edit TOCTOU advisory |
| 10-29 | A2A v1.1.0-rc tag |
| 11-02 | Defender local-agent matrix refreshed; OTel semconv 1.45.0 |
| 11-03 | CrowdStrike Kill Switch, AI Gateway GA, Fiddler and Dreadnode deals; Claude Code 2.1.317 |
| 11-04 | Sysdig AI Defense; CrowdStrike agent insider threat detection |
| 11-09 | Vanta signs to acquire Pillar |

## Weak points, gaps and risks

- **This sweep has the same blind spot as the briefs it audits.** It confirms what they named; it cannot find what none of them named. New entrants, funding rounds and conference research from June to November are under-covered.
- **Hooks are still fail-open nearly everywhere** (Codex, Cursor default, BeyondTrust) and three 2026 Claude Code CVEs are path races. A hook-only product inherits both.
- **MCP version skew** will last at least twelve months: brokers must speak the sessionful 2025 revisions and the stateless 2026 one together.
- **Dogwood is three months old** with a non-production interpreter and a tiny engine repository. Its semantics may still move.
- **Incumbents ship weekly.** CrowdStrike listed 77 press releases since June; Defender's matrix changed on 2 Nov. Any parity table decays within a month.
- **Microsoft's network inspection admits it misses pinned and HTTP/3 traffic**; ours will too unless QUIC is blocked for inspected processes.

## Implications for our design

Plan recommendations that must change:

1. **MCP broker and detectors: design for stateless 2026-07-28 first.** Do not key sessions on `Mcp-Session-Id` or the `initialize` exchange. Read `_meta` per request, use `Mcp-Method` and `Mcp-Name` headers for cheap routing and policy, implement `server/discover`, MRTR and `subscriptions/listen`, and keep a 2025-11-25 compatibility path. Use CIMD, not DCR. Enforce audience and issuer binding, which is exactly what the October SDK CVEs got wrong.
2. **Policy engine: embed Cedar 4.14 with SymCC; offer Dogwood as an optional authoring front end** that lowers to Cedar, with our own event-history store filling the temporal context slots. Do not ship the Dogwood reference interpreter.
3. **Drop LiteLLM as a bundled gateway.** Support it only as an external integration with a minimum patched version check. Build gateway integrations against agentgateway and Agent Router (both AAIF, Apache-2.0).
4. **Remove TensorZero, LLM Guard, Kuzu and Portkey's open gateway from the candidate lists.**
5. **Add a first-class Codex adapter** using `requirements.toml` managed hooks and `allow_managed_hooks_only`. For Cursor set `failClosed: true` on MDM-file hooks (dashboard hooks cannot). For Agent SDK embeddings use `onFailure: "block"`. Record per agent whether fail-closed is achievable and show it in the console.
6. **Treat hook verdicts on paths as advisory; enforce file and exec decisions at the OS sensor.** Add detections for the TOCTOU and symlink patterns in CVE-2026-88968 and CVE-2026-103435.
7. **Make sensor and hook tamper detection a first-release requirement.** Monitor edits to managed settings, hook files and our own configuration by agent-lineage processes, and verify at runtime that managed settings actually applied (CVE-2026-103012).
8. **Adopt MXC as the containment backend instead of writing a sandbox.** It is MIT, GA, and maps one JSON policy to AppContainer, Seatbelt and Bubblewrap. Ingest its activity report.
9. **Schema: target OCSF 1.9.0** (`ai_operation` profile, `delegation`, `record_integrity`) and keep a private extension mirroring `ai_capability` and `ai_status` so the 1.10 move is a rename. Pin OTel GenAI attributes to a commit of the new repository.
10. **Database baseline is PostgreSQL 18;** re-test the DuckDB path against 2.0.
11. **Windows: plan the signed-driver and no-driver paths only.** Do not schedule work on the Windows endpoint security platform.
12. **Positioning against incumbents, as of this week:** Linux and Kubernetes endpoints; bespoke agents; runtime blocking on macOS and Linux; Codex and Cursor enforcement; endpoint-first kill switch (CrowdStrike is gateway-first); self-hosting. Emit a Defender-compatible inventory shape so customers can join on `AgentsInfo`.
13. **Compliance roadmap:** use 2 Dec 2027 and 2 Aug 2028 for high-risk dates; accept "SI" terminology in US federal mappings.

## Ideas worth stealing and whitespace

- **Microsoft's `autoApprove` and `trustedProcess` posture flags** per discovered agent, plus `used by` and `runs on` graph edges, are a cheap, legible risk model.
- **CrowdStrike's three-part kill switch** (terminate, block relaunch, cut network) is a clear contract; nobody offers it as an open, scriptable API.
- **Dogwood's `explain`** (deterministic policy-to-English, no model) and BeyondTrust's replay simulation belong together in our policy workflow.
- **Whitespace confirmed by primary docs:** generic discovery of unnamed agents; native Linux workstation coverage; fail-closed hooks with an OS backstop; a broker that bridges sessionful and stateless MCP; monitoring that an agent cannot quietly disable.

## Could not verify / open questions

- **No web search ran.** Unreached: Gartner and Forrester (403), BeyondTrust press index (403), SecurityWeek M&A index (403), Palo Alto press listing (truncated), Black Hat and DEF CON 2026 talk lists, AI Incident Database, funding trackers.
- Dates for the CyberArk and Oasis closings; prices for Fiddler, Dreadnode and Pillar; whether Seraphic closed (CrowdStrike navigation lists "Seraphic Enterprise Browser", suggesting yes [I]).
- OWASP ASI06 to ASI10 names (page did not list entries); Helm 3 end-of-support date (v3.22.1 shipped 15 Oct 2026); whether the `MCP-Protocol-Version` HTTP header survives in 2026-07-28.
- Whether CrowdStrike or Microsoft will accept third-party verdict providers; whether BeyondTrust supports Cedar per-agent subjects.
- Whether `dogwood-local-engine` is production-grade and who maintains it.
- Stable [K] items (kernel version floors, API semantics, trust-store behaviour) were not re-checked; they are not time-sensitive.

## Sources

- https://modelcontextprotocol.io/specification/2026-07-28/changelog (MCP key changes, 2026-07-28)
- https://www.crowdstrike.com/en-us/press-releases/ (index, June to Nov 2026) and the releases dated 2026-11-03 and 2026-11-04 linked above, plus https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-fiddler-to-deliver-agent-observability/ and https://www.crowdstrike.com/en-us/press-releases/crowdstrike-extends-agentic-soc-detect-stop-agent-insider-threat/
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (updated 2026-10-13); https://docs.beyondtrust.com/bt-docs/changelog/pathfinder-26-1
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (2026-08-19); https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai (2026-10-30); https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents (2026-11-02); https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection (2026-09-25); https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix (2026-11-02)
- https://blogs.windows.com/windowsdeveloper/2026/10/07/microsoft-execution-containers-policy-driven-containment-for-ai-agents/ ; https://github.com/microsoft/mxc
- https://www.originhq.com/blog (index) and https://www.originhq.com/blog/prelude-is-now-origin (2026-07-27)
- https://learn.chatgpt.com/docs/hooks (Codex hooks); https://cursor.com/docs/agent/hooks; https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md (2.1.311 to 2.1.322); https://github.blog/changelog/label/copilot/
- https://alignment.openai.com/misalignment-reports/ (23 reports, to 2026-10-06)
- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (catalogue 2026.11.09, 1,773 entries)
- https://services.nvd.nist.gov/rest/json/cves/2.0 (seven CVE lookups); GitHub advisory API for litellm, MCP SDKs, claude-code, langflow, n8n
- https://datatracker.ietf.org/doc/ (per-draft `doc.json`, 2026-11-10)
- https://github.com/dogwood-policy/dogwood ; https://github.com/ocsf/ocsf-schema/blob/main/CHANGELOG.md ; https://github.com/GenAI-Security-Project/agent-control-standard/releases ; https://github.com/a2aproject/A2A ; https://github.com/open-telemetry/semantic-conventions-genai ; https://github.com/theagentrouter/agent-router ; https://github.com/tensorzero/tensorzero ; https://github.com/protectai/llm-guard (all via GitHub API, 2026-11-09/10)
- https://aaif.io/projects/ ; https://csrc.nist.gov/projects/cosais (updated 2026-10-20) ; https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai (updated 2026-10-19)
- https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp (2026-10-26)
- https://www.sysdig.com/blog/introducing-sysdig-ai-defense (2026-11-04); https://www.vanta.com/resources/vanta-acquires-pillar (2026-11-09); https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-koi-to-secure-the-agentic-endpoint (2026-04-14); https://astrix.security/ ; https://www.oasis.security/
- https://thehackernews.com/2026/03/5-learnings-from-first-ever-gartner.html (2026-03-24, contributed by Orchid Security)

## Independent verification

_Checked 2026-11-10 by a separate fact-checker. Web search was unavailable in this pass too (the shared search budget was already spent), so every verdict rests on direct reads of primary sources: spec pages, vendor docs, EUR-Lex, the CISA KEV feed and the GitHub API and source trees. Where the only available source was the one the researcher cited, the note says so._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | MCP 2026-07-28 removes sessions, `Mcp-Session-Id` and `initialize`, requires `server/discover` and `Mcp-Method`/`Mcp-Name`, deprecates DCR, Roots, Sampling, Logging with a twelve-month minimum window | Confirmed, with precision | Release tag `2026-07-28` published 28 Jul 2026. `Mcp-Method` is required on all requests; `Mcp-Name` only on `tools/call`, `resources/read`, `prompts/get`. The `MCP-Protocol-Version` header survives and is a MUST on every POST (closes the brief's open question); it must equal `_meta` protocolVersion or the server returns 400 `HeaderMismatch` (-32020). `logging/setLevel`, `ping` and `notifications/roots/list_changed` are removed outright, not merely deprecated. DCR "remains available for backwards compatibility". A 2026-only server answers GET or DELETE with 405 and ignores `Mcp-Session-Id`. | [transport spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog), GitHub releases of `modelcontextprotocol/modelcontextprotocol` |
| 2 | Dogwood v1.0 on 2026-10-13, v1.1.1 on 2026-11-06, Apache-2.0; interpreter not for production; compiles to Cedar | Confirmed | Releases: v1.0 (13 Oct), v1.1 (14 Oct), v1.0.1 and v1.1.1 (both 6 Nov). Licence Apache-2.0, repo created 27 Jul 2026. README: the reference interpreter "is **NOT** intended for production use", and "policies lower to standard Cedar". A maintained 1.0.x line exists alongside 1.1.x. | GitHub API and README, `dogwood-policy/dogwood` |
| 3 | Defender runtime protection is Preview and Windows-only; six hook targets; Codex and Cursor not supported; only listed agents discovered | Confirmed | Runtime section is headed "Windows (preview)"; the setup page title ends "(Preview)" and requires the Beta channel and signature 1.451.224.0. Hook targets are exactly the six listed. Codex CLI, Codex Desktop and Cursor are discovered (inventory, with MCP config) but absent from both runtime tables. 62 Windows rows and 59 macOS rows counted. | [matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix), [setup](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection) |
| 4 | Falcon Guardian GA since September 2026; AI Gateway GA and included; Kill Switch gateway first, endpoint "soon"; network inspection GA on Windows, Mac early access; Linux not mentioned | Confirmed (vendor press releases only) | Both 3 Nov 2026 releases agree: "first at the Gateway, and soon on the endpoint"; "Generally available for Windows, with Mac in early access". The Kill Switch release names no operating system at all and carries a forward-looking-statements notice. No independent technical documentation was reachable, so this is vendor marketing, not a tested capability. | [Kill Switch PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-ai-kill-switch-for-ai-safety/), [Guardian PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-ai-security-safety-for-the-enterprise/) |
| 5 | LiteLLM: two KEV entries since June (CVE-2026-42271 on 2026-06-08, CVE-2026-59822 on 2026-09-02) plus ten advisories since July including a critical template injection | Confirmed, slightly understated | KEV catalogue 2026.11.09 holds three LiteLLM entries; the third, CVE-2026-42208 (SQL injection), was added 8 May 2026. The GitHub advisory database lists exactly ten since 1 July, including critical CVE-2026-37004 (SSTI in `/prompts/test`, 27 Aug). The repository's own advisory list adds one not yet in the global database: GHSA-w4c7-34wj-hqm8, critical, unauthenticated file read leaking the master key (27 Oct). | [KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), GitHub advisories API (`affects=litellm`), `BerriAI/litellm` security advisories |
| 6 | Codex hooks: 14 events; PreToolUse can deny or rewrite; `requirements.toml` managed hooks; errors and timeouts mostly let the call proceed | Confirmed, and stricter than stated for PreToolUse | Source lists 14 event names. In `pre_tool_use.rs` every failure path leaves `should_block = false`: runner error or timeout, any exit code other than 0 or 2, invalid JSON, unsupported output, and exit code 2 with empty stderr. A blocking hook must exit 2 and write a reason to stderr, or return a deny decision. The Cursor-migration code states "Codex does not currently support a per-hook failure policy". `allow_managed_hooks_only` works only in `requirements.toml`, not `config.toml`. | `openai/codex`: `codex-rs/hooks/src/events/pre_tool_use.rs`, `codex-rs/external-agent-migration/src/hooks_cur.rs`, `docs/config.md`, `HookEventName.ts`; [docs](https://learn.chatgpt.com/docs/hooks) |
| 7 | Cursor hooks fail open by default; `failClosed` default false; three enterprise paths; dashboard hooks cannot set `failClosed` | Confirmed (same source) | Docs: crashes, timeouts and non-zero exits other than 2 "fail open by default"; dashboard hooks "don't take per-hook options such as `failClosed` or `matcher`" and sync every thirty minutes. One nuance: permission hooks that return invalid JSON still block even with `failClosed` false. The Linux path is documented as Linux/WSL. No second source exists; Cursor is closed source. | [Cursor hooks docs](https://cursor.com/docs/agent/hooks) |
| 8 | OCSF 1.9.0 on 2026-08-03 with `delegation` and `record_integrity`; main is 1.10.0-dev with `ai_capability` and `ai_status` unreleased | Confirmed | Release 1.9.0 published 3 Aug 2026; changelog section adds the `delegation` object (#1665) and `record_integrity` profile (#1661). `version.json` on main reads `1.10.0-dev`; `ai_capability` (#1729), `ai_status` (#1704) and `Sub-Agent Stop` (#1780) sit under Unreleased. Unreleased also extends `delegation` with `scopes`, `audience`, `expiration_time` (#1705). No AI agent activity class appears. | GitHub API, `ocsf/ocsf-schema` releases, `version.json`, `CHANGELOG.md` |
| 9 | TensorZero, `protectai/llm-guard`, Kuzu archived; `envoyproxy/ai-gateway` resolves to `theagentrouter/agent-router` (AAIF); no licence change among selected dependencies | Confirmed | All three report `archived: true`. The API redirects `envoyproxy/ai-gateway` to `theagentrouter/agent-router` (Apache-2.0, v1.2.1 on 6 Nov). AAIF lists Agent Router and agentgateway but says nothing of origin or donation; "donated" is an inference from the redirect. Spot check of 20 selected repositories found none archived and licences as expected (OpenBao MPL-2.0; Tenzir and AccessKit BSD-3-Clause; DuckDB and Velopack MIT; the rest Apache-2.0). A licence change inside a repo that keeps its SPDX tag would not show in this check. | GitHub API; [AAIF projects](https://aaif.io/projects/) |
| 10 | EU AI Omnibus in force 2026-07-27; Annex III to 2 Dec 2027; Annex I to 2 Aug 2028 | Confirmed | Regulation (EU) 2026/1744, adopted 8 Jul 2026, published in the OJ 24 Jul 2026, in force on the third day after publication, 27 Jul 2026. Recital 40 gives 2 Dec 2027 (Annex III) and 2 Aug 2028 (Annex I). The operative Article 113 text was beyond the portion read; the dates come from the recitals and the Commission page. | [EUR-Lex 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng), [EC page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) |

### Further statements checked in the brief

| Statement in the brief | Verdict | Right fact | Source |
|---|---|---|---|
| Fail-closed in Claude Code is "`onFailure: \"block\"` in the Claude Agent SDK only"; 2.1.317 is "Agent SDK only, not command hooks in settings" (TL;DR, ledger row 06, implication 5) | Refuted | `onFailure: "block"` for command and HTTP hooks shipped in Claude Code 2.1.295 (8 Oct 2026); 2.1.317 (3 Nov) extended it to Agent SDK callbacks. It is set per hook in settings, covers can't-start, timeout, exit codes other than 0 or 2, HTTP errors and invalid output, and has no effect on `Stop`, `SubagentStop`, `TaskCompleted`, `TeammateIdle` or async hooks. Prompt, agent and MCP-tool hook types do not list the field. So a Claude Code adapter can be fail-closed from managed settings on 2.1.295 or later; Codex cannot; Cursor can from file-based `hooks.json` (including the MDM paths) but not from dashboard hooks. | `anthropics/claude-code` `CHANGELOG.md` (2.1.295, 2.1.317); [hooks reference](https://code.claude.com/docs/en/hooks) |
| "Adopt MXC as the containment backend ... maps one JSON policy to AppContainer, Seatbelt and Bubblewrap" (implication 8) | Corrected (overstated) | GA and MIT are right (v1.0.0 on 7 Oct, v1.0.1 on 17 Oct 2026). But the README describes MXC as "an SDK dependency that builds into your app": it contains workloads that the embedding application launches, and does not wrap an agent someone else started. The Windows default backend is named `processcontainer`; `windows_sandbox`, `microvm` and `hyperlight` are experimental. Official Microsoft builds send required diagnostic data to Microsoft, which matters for a self-hosted product. Useful for sandboxing our own tool runners, not a way to confine third-party agents. | `microsoft/mxc` README and releases |
| "PostgreSQL 19 is still RC1" | Confirmed | Tags `REL_19_BETA1` to `BETA4` and `REL_19_RC1` exist; no `REL_19_0`. Latest 18.x tag is `REL_18_6`. PostgreSQL 18 as the baseline stands. | GitHub API, `postgres/postgres` tags |
