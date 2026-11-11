# BeyondTrust AI Agent Security: vendor teardown

_Researched 2026-11-09_

Evidence base: the 48 vendor docs pages (docs.beyondtrust.com, last updated 2026-10-13/14, read in full from the vendor's own Markdown), the product page, two press releases, the "Hard Boundary or Soft Request" blog, one Phantom Labs post, the datasheet PDF, pricing page and three demo-video pages. Labels: **[V]** = verified in a primary source, **[I]** = my inference. Web search was unavailable in this run (budget exhausted), so there is no third-party coverage; everything is the vendor's own account.

## TL;DR

- **It is two enforcement planes glued together, not "kernel only".** A kernel/network sensor (Windows driver; macOS Endpoint Security + Network Extension) gives mandatory control of process exec, file open and network connect. Coding-agent hooks (Claude Code, Codex, Cursor, Copilot) give tool-call, MCP and session context. Managed policies say explicitly that some rules are enforced at the hook and again at process launch. [V]
- **Windows and macOS only at GA (21 Oct 2026).** Windows 11 / Server 2022+ x64 (no Arm); macOS 14, 15, 26. No Linux, containers or Kubernetes, although the June 2026 announcement named them. Initial focus is user laptops. [V]
- **HTTPS content rules depend on TLS interception** with a per-tenant root CA and a local proxy. On Windows that needs a separately rolled-out "traffic redirect" which breaks browsers and declines on corporate-proxy networks; on macOS it needs an MDM profile. [V]
- **Attribution is process lineage plus classifiers**, not a new identity: process name, install path, code signature, launched-by lineage and observed LLM API traffic. Events carry "AI agent" and "Acting under" fields. [V]
- **Policy is allow-by-default.** Four postures (Off, Audit, Require Approval, Block). The 27 Phantom Labs managed policies ship at Audit or Off and cannot block until forked. [V]
- **The policy subject is only "Any AI agent" or "Anyone".** The builder has no per-agent, per-user, per-repo or per-skill subject; six action types; no file-write action. Cedar exists as a policy type but is undocumented. [V]
- **Hooks fail open.** If the local agent service is unreachable, the tool call proceeds and the endpoint shows "Degraded". [V]
- **Approval is an exception to a policy, not to a call.** Approving relaxes the whole matching policy on that endpoint for the grant window; users can self-approve under Require Approval (up to 24 h); self-approved grants cannot be revoked centrally. [V]
- **Simulation is real and good:** replay recorded activity with Matched / Almost matched / Did not match / Not enough detail, plus live shadow sampling of pending policy changes on hook traffic. [V]
- **EPM is not required** (MSI/pkg can be pushed with Intune, Jamf, GPO), though EPM Package Manager 26.3.1+ is the easy path. Pricing is quote-only. Single role: every console user is a full admin. [V]
- **The gated four-vendor whitepaper could not be read.** Its framing and the vendor list (BeyondTrust, Idira/Palo Alto Networks formerly CyberArk, SailPoint, Zscaler) are verified; the placement below is reconstructed from the companion blog and is inference.

## Findings

### 1. Timeline, packaging, licensing

- 30 Jun 2026: announced as a Pathfinder module in private beta, "initially offered as an add-on to Endpoint Privilege Management", naming Windows, macOS, Linux and containers. [V] ([press, 2026-06-30](https://www.beyondtrust.com/press/ai-agent-security))
- 21 Oct 2026: GA on Pathfinder for Windows and macOS only; co-developed by Phantom Labs and the EPM team. [V] ([press, 2026-10-21](https://www.beyondtrust.com/press/ai-agent-security-general-availability))
- Licensing: contact the account team to add it to a tenant; pricing page is a lead form with no numbers or metric. [V] ([docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security), [pricing](https://www.beyondtrust.com/products/ai-agent-security/pricing))
- EPM is optional: the docs give a full path for customers who do not run EPM. With EPM, a "Deploy AI Agent Security" page in PM Cloud creates the key and the Package Manager (26.3.1+) installs silently; check-in up to about 2 hours. [V] ([Windows install](https://docs.beyondtrust.com/bt-docs/docs/windows-manual-install))
- Agent versions shown in docs are 0.40.x to 0.41.x: a young codebase. [V] ([update strategy](https://docs.beyondtrust.com/bt-docs/docs/update-strategy))

### 2. Supported platforms and installed components

**Windows** ([install guide](https://docs.beyondtrust.com/bt-docs/docs/windows-manual-install), [administration](https://docs.beyondtrust.com/bt-docs/docs/administration)) [V unless marked]
- MSI `pathfinder-agent-<ver>-x86_64.msi`, properties `BACKEND_URL` and `DEPLOYMENT_KEY`; binary `%ProgramFiles%\BeyondTrust\Pathfinder\pathfinder-agent.exe` (`status`, `enroll`, `hook install`); data in `C:\ProgramData\BeyondTrust\Pathfinder\`.
- A kernel driver with six separately excludable features: file-open interception, hook DLL injection, TLS transparent redirect, network connect interception, inline SNI capture, process-exec interception. A docs example shows `sc.exe query PathfinderEnf`, so the driver service is probably `PathfinderEnf` [I]. Event paths appear in `\Device\HarddiskVolumeN\` form, consistent with a minifilter [I].
- Local inspection proxy plus per-tenant "Pathfinder Root CA". The agent can install the root itself (docs warn this is MITRE T1553.004 and EDR will alert) or it is pushed by GPO/Intune. Marker file `tls-intercept-ready`; chain rechecked every minute; a removed root is reinstalled.
- "Windows traffic redirect" is a separate fleet setting that forces agent traffic through the proxy even for tools ignoring proxy variables; required to inspect or block CLIs such as `aws.exe`. The docs' own example shows 2 of 29 endpoints armed. Browsers must not be armed (connections break). Endpoints on corporate-proxy-only networks decline to arm.
- A separate updater component and "modules" (example 2/2 running).

**macOS** ([install guide](https://docs.beyondtrust.com/bt-docs/docs/mac-manual-install), [enrollment plist](https://docs.beyondtrust.com/bt-docs/docs/macos-enrollment-plist)) [V]
- Universal pkg `pathfinder-sysext-<ver>-darwin-universal.pkg` installing `/Applications/PathfinderEnforcement.app`.
- Two system extensions: Endpoint Security ("Pathfinder Enforcement", needs Full Disk Access) and Network Extension ("Pathfinder Network Filter", a transparent proxy). Helpers `com.pathfinder.tls-proxy` and `com.pathfinder.netfilter.signing-oracle` (mints per-host certificates); proxy listens on TCP 8443.
- Config `/etc/pathfinder/agent.toml` (`inspection_enabled`, `[hooks] managed_autoinstall`); credentials `/var/lib/pathfinder/enrollment.json`.
- No zero-touch without MDM: one `.mobileconfig` trusts the CA, approves both extensions and configures the transparent proxy (Jamf signed; Intune, Iru/Kandji plain XML).
- A connection is intercepted only when a TLS inspection policy matches the calling process, so ordinary traffic is untouched.
- Careful enrollment contract: zero-touch plist must be `root:wheel 0600`, not a symlink, https-only; refused rather than repaired; key passed by file, not argv; key redacted in logs; an enrolled Mac is never re-pointed.

**Hooks** ([install and verify](https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-install-and-verify), [MDM payloads](https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-mdm-payloads)) [V]
- Machine-wide managed hook files, written by the installer for every user: Claude Code `managed-settings.json`, Codex `requirements.toml`, Cursor `hooks.json`, Copilot `/etc/github-copilot/policy.d/pathfinder.json` (macOS paths under `/Library/Application Support/...`).
- Every hook runs `pathfinder-agent hook --agent-type <x> <event>`; the verdict comes from the local agent service; 30 s timeout on Cursor and Copilot.
- Claude Code events registered: PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit, UserPromptExpansion, SessionStart, SessionEnd, SubagentStart, SubagentStop, PreCompact, PostCompact, Notification, Stop, StopFailure, PermissionDenied. Codex adds PermissionRequest; Copilot adds permissionRequest, errorOccurred, userPromptTransformed.
- Fail-open: unreachable service means the call is allowed and the endpoint's Health tab shows hook enforcement Degraded.

### 3. Discovery

- Inventories: AI agents, MCP servers, LLM endpoints, agent skills, endpoints; plus process and credential discovery ("credentials stored on each endpoint and the identities they grant"). Scan interval 30 to 86,400 s. [V] ([administration](https://docs.beyondtrust.com/bt-docs/docs/administration))
- Agent identification signals, shown per endpoint with a link to the evidence event: process name, install path, code signature, launched-by lineage, observed LLM connections. Product names are normalised ("Also seen as"). Hosts seen only indirectly appear as NOT ENROLLED. [V] ([agent overview](https://docs.beyondtrust.com/bt-docs/docs/ai-agents-overview))
- Bespoke agents are caught by traffic: any process calling a known LLM host is treated as an AI agent. LLM hosts are Built-in, Learned (from inference traffic), Declared (admin adds private gateways) or Rejected. There is a tenant cap on learned hosts, and a "probe" that samples the first 1 to 64 connections to unknown hosts. An undeclared private gateway leaves its callers unrecognised. [V] ([LLM endpoints](https://docs.beyondtrust.com/bt-docs/docs/visibility-llm-endpoints))
- MCP servers are grouped as Owned (in the agent's config), Called (observed but undeclared), Related (launched by or alongside), and "seen in traffic", the last only on macOS with TLS inspection. Transport, auth required or none, tool list. [V] ([agent MCP tab](https://docs.beyondtrust.com/bt-docs/docs/ai-agents-mcp-servers))
- Skills: only flagged skills are listed. Fields include source (marketplace), provenance (plugin), declared tools, content hash, repo/path/commit, and findings with a technique id (example `spooky-skills#extra`) and file:line evidence. Re-reported at least every 20 h. Usage counts come only from Claude Code's local usage file. [V] ([skill details](https://docs.beyondtrust.com/bt-docs/docs/agent-skills-details))

### 4. Human versus agent attribution

- Mechanism: the sensor tags an "agentic process" by the classifiers above and propagates that through process ancestry. Event detail shows the full chain with PID, parent, user, executable, arguments, "AI agent" and "Acting under". [V] ([event details](https://docs.beyondtrust.com/bt-docs/docs/event-details))
- Hook events carry category `codinghooks`; sensor events `enforcement`. A command typed by a person inside an agent session is recorded with actor `human`. [V] ([agent events](https://docs.beyondtrust.com/bt-docs/docs/ai-agents-events))
- File reads are captured only for AI agents (the "Anyone" subject is unavailable for reads). [V] ([policies](https://docs.beyondtrust.com/bt-docs/docs/policies))
- There is no agent credential or identity token. Separation exists only on the endpoint; cloud and SaaS still see the user. Cloud blast radius is handled separately in Identity Security Insights (Insights > AI Agents). [V] ([workflow](https://docs.beyondtrust.com/bt-docs/docs/map-agent-privileges-to-cloud-resources))

### 5. Policy model

Source: [policies](https://docs.beyondtrust.com/bt-docs/docs/policies), [details](https://docs.beyondtrust.com/bt-docs/docs/policies-details), [managed policies](https://docs.beyondtrust.com/bt-docs/docs/beyondtrust-managed-policies). All [V].

- Rule sentence: mode, when who, action, on target, optional condition. Posture belongs to the whole policy.
- Subjects: Any AI agent, Anyone.
- Actions: uses a coding-agent tool (tool name and input glob such as `*rm -rf*`); calls an MCP tool (marked "limited"); runs a process (binary path); reads a file (path); makes an HTTPS request (host at connect; method, path, content need decryption); opens a network connection (hostname or address:port, pre-TLS).
- Glob patterns with exceptions; reusable managed lists (hosts, AWS account IDs, Azure tenant IDs).
- Cloud-aware conditions: AWS account derived from the request signature; Azure tenant from a JWKS-verified Entra token; GCP user-project header; tenant fields in internal API requests.
- "Kill the process on deny" option; no effect on Windows yet.
- The builder refuses rules that would lock humans out.
- A policy does nothing until attached to endpoints or tags; attachments can override posture with a TTL. Managed policies reach the fleet through a built-in tag.
- 27 managed policies in seven categories: MCP governance 1, anti-forensics and evasion 3, cloud protection 4, credential and secret protection 6, destructive actions 2, supply chain 3, example templates 8 (pin AWS account, Azure tenant or subscription, GCP project, Databricks workspace). Served from a registry with generation and digest. Audit or Off only; fork to block.
- Emergency switches: enforcement master switch and an "audit ceiling" that downgrades every block to audit. Settings inherit built-in, fleet, tag, endpoint, with an audit trail.

### 6. "Steering", approval, simulation

- Steering has no docs page. Evidence: managed policies use one rule per hazard family so the message names the specific hazard, and a demo page says blocked actions are returned to the agent in a form it understands rather than as a user prompt. [V] Conclusion: steering is a hook deny reason fed back into the model loop [I]. By the vendor's own blog taxonomy that is a cooperative control. ([demo](https://www.beyondtrust.com/resources/videos/ai-agent-security-demo-hr-users-and-sensitive-files))
- Approval: a block yields a link to a request form. Block posture goes to an admin queue; Require Approval lets the user approve it themselves. Fields: requester, agent, host, blocked call, repository, session, blocking policies, justification, requested duration or "Session". Approval reaches the endpoint in 15 to 30 s; revoke in about 15 s. [V] ([exception requests](https://docs.beyondtrust.com/bt-docs/docs/exception-requests), [details](https://docs.beyondtrust.com/bt-docs/docs/exception-requests-details))
- Simulation: time-window replay in the builder and per MCP control; "Hook shadow sample bps" (0 to 10,000) evaluates upcoming policy changes against live hook activity. [V]

### 7. MCP controls

- Per-server access: Allow, Monitor, Require approval, Block; all tools or named tools; all endpoints or tags; coverage reporting ("Enforcing on N of M", "Delivery pending", reasons). Servers can be pre-registered before discovery. [V] ([MCP server details](https://docs.beyondtrust.com/bt-docs/docs/mcp-server-details))
- Three enforcement paths: hook (tool call), inline adjudication at the endpoint inspection proxy for HTTPS MCP clients, and raw network-connection rules for remote servers. [V]
- No default-deny: servers are controlled one at a time and a new server is allowed until someone acts. Require approval only works through a coding agent; other connections are recorded, not blocked. [V] ([workflow](https://docs.beyondtrust.com/bt-docs/docs/block-model-providers-and-unapproved-agents))
- Separate product: Pathfinder MCP gateway (`https://mcp.beyondtrust.io/mcp`, bearer `MCP_...` tokens, read-only, US-only early access) exposes BeyondTrust product data to agents. It is not a gateway for governing third-party MCP traffic. [V] ([gateway docs](https://docs.beyondtrust.com/bt-docs/docs/welcome-to-pathfinder-mcp-gateway))

### 8. Audit data model and console

- Event: time, category, actor (process path), host, activity (`process.exec`, `file.open`), object, outcome (Blocked, Audited, Allowed, Observed), optional risk; ancestry; matched policies with decision and mode; raw JSON with credential-shaped values redacted. Volume example: 1.76 M events in one window. Allow events are optional and high volume, with dedup TTL and capacity controls. [V] ([events](https://docs.beyondtrust.com/bt-docs/docs/events))
- Session: developer, machine, tool, repo, branch, directory, start, duration, outcome (for example committed); counts of reads, edits, commands, tool calls; findings with severity; network egress (destination, via process, calls, decision); MCP servers; files changed or viewed with diff stats; transcript including nested tool calls and, if enabled, assistant reasoning. [V] ([session details](https://docs.beyondtrust.com/bt-docs/docs/ai-session-details))
- Console: app.beyondtrust.io; Dashboard, Visibility, Intelligence, Protection, Settings; a built-in chatbot; update rings (Latest, patch N-1/N-2, minor N-1/N-2, pinned), device pins, yank, fleet-wide pause. Export is CSV only in these docs; no SIEM, webhook or API reference appears in the section. [V]

### 9. The enforcement-location framework

Verified from the blog ([Gaehtgens, 2026-10-20](https://www.beyondtrust.com/blog/entry/ai-agent-security-controls)):
- Two axes: mandatory (enforced across a privilege boundary the agent cannot reach) versus cooperative (depends on agent, harness or hook behaving); and agent-scoped (process lineage) versus agent-loop-aware (sees tool calls and reasoning).
- Five approaches: prompt/content inspection; harness hooks (largest cluster); user-space proxy interception; supply-chain gating; OS-level enforcement.
- Named examples: Endor Labs (hooks, praised for documenting fail-open and per-agent differences: Cursor does not pause on reads, Codex cannot pause so denies, Copilot CLI ignores "ask"); Operant AI (provider-side inference hooks: mandatory and loop-aware but channel-bound); Cyberhaven (data lineage); nono (Landlock + seccomp, open source).
- Conceded limits: the kernel cannot see meaning; no coverage where no enforcer can be installed; no published adversarial evaluation of any kernel-level agent control exists.

Verified from the whitepaper landing page: it frames the agent activity lifecycle as distinct control windows, compares BeyondTrust, Idira (Palo Alto Networks, formerly CyberArk), SailPoint and Zscaler from public docs, and walks one coding-agent session through each. ([landing page](https://www.beyondtrust.com/resources/whitepapers/ai-agent-security-comparison-vendor-approaches))

## Matrix

Whitepaper placement, reconstructed. Only the BeyondTrust row is verified; the other three rows are inference from each vendor's general product category, not from the paper.

| Vendor | Control window | Decision point | Mandatory? | Loop-aware? | Sees | Misses |
|---|---|---|---|---|---|---|
| BeyondTrust [V] | Action on the endpoint | Kernel driver / ES + NE extension, local TLS proxy, plus hooks | Yes for exec, file open, connect; hooks cooperative and fail-open | Only via hooks | Process tree, file opens, connections, tool calls, transcripts | Cloud/SaaS agents, Linux, unmanaged devices, meaning of data flows |
| SailPoint [I] | Before the session: identity and entitlement governance | Admin-time catalogue, ownership, certification | Not a runtime control | No | Who owns an agent, what it is entitled to | Anything done with inherited user credentials on a laptop |
| Idira / CyberArk [I] | Credential issuance and privileged access | Vault, secrets broker, access gateway | Mandatory for brokered credentials only | Partly (gateway) | Credential checkout, brokered sessions | Local actions, credentials already on disk |
| Zscaler [I] | Traffic in transit | Inline cloud proxy, prompt/content inspection | Mandatory for routed traffic | Prompt-level | Prompts, responses, destinations | Local file and process actions, unrouted or pinned traffic |

BeyondTrust capability map (all [V]):

| Area | What exists | Stated limit |
|---|---|---|
| OS | Win 11, Server 2022+ x64; macOS 14/15/26 | No Linux, containers, Windows on Arm |
| Process exec | Block by binary path, optional kill | Kill not on Windows |
| File | Read rules by path glob | Reads only; AI agents only |
| Network | Connect rules; HTTPS host/method/path/content | Content needs TLS interception; Windows redirect opt-in |
| Hooks | Claude Code, Codex, Cursor, Copilot | Fail open; four agents only |
| MCP | Per server/tool access, coverage view | No allowlist mode; in-traffic view macOS only |
| Approval | Self or admin, time-boxed | Relaxes whole policy; one admin role |
| Simulation | Replay plus live shadow sampling | Customer policies only |
| Audit | Events, sessions, transcripts | CSV export only in docs |

## Weak points, gaps and risks

1. **No Linux, servers, containers, Kubernetes, cloud agent platforms, SaaS or browsers.** Coverage is a managed Windows or Mac laptop.
2. **TLS interception is the price of HTTP-level policy**: tenant root CA on every device, EDR alerts, broken browsers, pinned clients, corporate-proxy conflicts, MDM dependency. A decryption failure falls back to uninspected pass-through.
3. **Loop-aware control is cooperative and fail-open**, and limited to four agents. Anything else gets process, file-read and connect rules only. A user or skill that alters hook configuration degrades it; the same vendor's research shows hooks themselves are an attack surface.
4. **Coarse subject model**: no per-agent, per-user, per-group, per-repo, per-skill or per-sub-agent subject in the builder. Policies attach to endpoints, so attaching a block for one agent governs every agent on those machines.
5. **No write, delete or rename file action** in the builder; destructive file operations rely on command-string globs at the hook and process-argument matching, which interpreters and renamed binaries evade [I].
6. **Allow-by-default with audit-only managed content**: a fresh deployment blocks nothing. Removing a policy silently re-permits.
7. **Approval granularity**: a grant opens the whole policy on that endpoint; self-approval up to 24 h; no central revoke of self-approved grants; no separation of duties.
8. **MCP**: no default-deny; stdio servers are covered only through hooks or process rules; proxy adjudication only for clients whose HTTPS is inspected.
9. **Attribution is heuristic.** An agent calling an undeclared private gateway, or a renamed or unsigned binary before its first LLM call, is unrecognised [I]. Rejecting a host stops its callers being treated as agents.
10. **No prompt or response inspection by design**; no data-lineage or exfiltration-by-summary control (conceded in the blog).
11. **Operations**: SaaS console only as documented; quote-only pricing; no documented SIEM or API surface; young agent with emergency yank and kill-switch controls prominent.

## Implications for our design

1. **Build both planes and label them honestly.** Every control in our UI and API should carry `boundary` or `request` and the privilege needed to defeat it. Publish a per-agent semantics matrix (which hooks can deny, ask, pause).
2. **Enforce twice by default**: evaluate the same policy at the hook and again at the OS sensor on the resulting exec, open and connect, correlated by lineage. Copy this pattern directly.
3. **Lead with what they lack**: Linux via BPF LSM, containers and Kubernetes, Windows on Arm, and server workloads.
4. **Do not make TLS MITM a prerequisite.** Tier network control: connect and SNI rules with no CA; hook and OpenTelemetry content where the agent offers it; optional per-process selective interception as a separate module. If we ship interception, copy their per-process matching and never touch browsers.
5. **Richer policy subject**: agent product, version, session, sub-agent, skill hash, MCP server and tool, user and group, repo and branch, device tag. Use Cedar as the native language with a published schema and keep a sentence builder on top.
6. **Add what the builder omits**: file write, delete and rename; default-deny MCP allowlist mode; per-call and per-pattern exception grants; central revocation of every grant; role separation.
7. **Make hook failure mode configurable** (open, closed, closed for high-risk tools) with visible degraded state, and monitor integrity of managed hook files as a first-class detection.
8. **Copy the cloud-aware conditions**: AWS account from SigV4, Entra tenant from verified token, GCP project header. This is the cleanest "agent may not touch production" control seen so far.
9. **Copy the fleet plumbing**: four-level setting inheritance with audit trail, update rings with N-1/N-2, yank, device pins, global pause, break-glass audit ceiling, per-feature driver exclusions, and coverage reporting per control.
10. **Copy the enrollment hygiene**: expiring, use-limited deployment keys; key by file not argv; refuse-not-repair on bad permissions; https only; never re-point an enrolled device.
11. **Open the data model**: publish event and session schemas (OCSF and OTel GenAI mapping), streaming export and an embedding API. BeyondTrust documents none; this is our route into EDR vendors.

## Ideas worth stealing and whitespace

Steal:
- "Almost matched" and "Not enough detail" buckets in simulation, and basis-point shadow sampling of pending policies on live traffic.
- Identification evidence tab: show exactly which signals classified a process as an agent.
- LLM endpoint lifecycle (built-in, learned, declared, rejected) and first-connection probing.
- Owned / Called / Related / Seen-in-traffic grouping for MCP servers.
- Skill records with content hash, provenance and commit, plus "flagged and unused" as the first clean-up target.
- One rule per hazard family so the deny message can name the hazard and the safe alternative.
- "Create policy from this event/finding" and "Block agent" one-click flows.

Whitespace:
- A published adversarial evaluation of an OS-level agent control. The vendor says none exists; an open benchmark would be a credibility asset.
- Exact-call, cryptographically bound approvals instead of policy-wide windows.
- Agent identity that survives off the endpoint (token binding or exchange) so cloud and SaaS can also tell agent from human.
- Data-flow awareness joined to OS enforcement.
- Self-hosted and MSP multi-tenancy with real RBAC.
- Coverage for agents with no hook surface: desktop apps, in-house agents, browser agents.

## Could not verify / open questions

- Whitepaper body (gated lead form, not submitted): actual lifecycle windows, per-vendor placement and the session walkthrough. The Idira, SailPoint and Zscaler rows above are inference.
- Phantom Labs "AI worms" research: only an executive quote exists on the product page and datasheet; no standalone publication found.
- Datasheet: text layer read; supported-agent logos are images and were not legible (text shows "Code, Codex, Vibes, and more").
- Pricing metric and whether GA is still sold only to EPM customers.
- Cedar: schema, entity model and whether Cedar policies allow per-agent subjects.
- Exact Windows mechanisms (minifilter, WFP callout, what the "hook DLL injection" feature is used for) and the implementation language.
- Whether the backend can be self-hosted (the enrollment docs mention a backend behind a customer reverse proxy, but only a SaaS console is documented).
- Data retention, residency, transcript privacy controls, SIEM/API integrations, performance overhead.
- Whether the sensor coexists cleanly with CrowdStrike or other EDR drivers and other Endpoint Security clients.
- No independent or third-party validation was reachable (web search unavailable in this run).

## Sources

| URL | Title | Date |
|---|---|---|
| https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security | AI Agent Security (overview, prerequisites, enforcement) | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/windows-manual-install | Windows manual install | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/mac-manual-install | Mac manual install | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/macos-enrollment-plist | macOS enrollment plist | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-install-and-verify | Coding hooks: install and verify | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-mdm-payloads | Coding hooks MDM payloads (macOS) | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/policies | Policies | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/policies-details | Policies details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/beyondtrust-managed-policies | BeyondTrust managed policies | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/exception-requests | Exception requests | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/exception-requests-details | Exception requests details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/administration | Administration (fleet defaults, driver exclusions, trust anchor) | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/update-strategy | Update strategy | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/deployment | Deployment (keys) | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/ai-agents-overview | AI Agents overview (identification signals) | 2026-10-14 |
| https://docs.beyondtrust.com/bt-docs/docs/ai-agents-events | AI Agents events | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/ai-agents-mcp-servers | AI Agents MCP servers | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/ai-agents-policies | AI Agents policies | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/visibility-llm-endpoints | Visibility: LLM endpoints | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/visibility-mcp-servers | Visibility: MCP servers | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/mcp-server-details | MCP server details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/visibility-agent-skills | Visibility: Agent skills | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/agent-skills-details | Agent skills details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/endpoints-details | Endpoints details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/events | Events | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/event-details | Event details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/ai-sessions | AI sessions | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/ai-session-details | AI session details | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/block-model-providers-and-unapproved-agents | Workflow: block providers, agents, MCP | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/block-access-while-retaining-user-privileges | Workflow: block agent, keep user access | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/map-agent-privileges-to-cloud-resources | Workflow: Insights AI Agents | 2026-10-13 |
| https://docs.beyondtrust.com/bt-docs/docs/welcome-to-pathfinder-mcp-gateway | Pathfinder MCP gateway | 2026-10-02 |
| https://docs.beyondtrust.com/bt-docs/changelog/pathfinder-26-1 | Pathfinder 26.1 changelog | 2026-04 |
| https://docs.beyondtrust.com/bt-docs/changelog/pathfinder-workload-credentials | Pathfinder Workload Credentials changelog | 2026-10 |
| https://www.beyondtrust.com/products/ai-agent-security | Product page | read 2026-11-09 |
| https://www.beyondtrust.com/products/ai-agent-security/pricing | Pricing page (quote only) | read 2026-11-09 |
| https://www.beyondtrust.com/press/ai-agent-security | Launch press release | 2026-06-30 |
| https://www.beyondtrust.com/press/ai-agent-security-general-availability | GA press release | 2026-10-21 |
| https://www.beyondtrust.com/blog/entry/ai-agent-security-controls | Agentic AI Security Controls: Hard Boundary or Soft Request | 2026-10-20 |
| https://www.beyondtrust.com/blog/entry/claude-code-hooks-c2-skill-security | Weaponizing Claude Code Hooks | 2026-10-06 |
| https://www.beyondtrust.com/resources/whitepapers/ai-agent-security-comparison-vendor-approaches | Where AI Agent Security Gets Enforced (landing page only) | read 2026-11-09 |
| https://assets.ctfassets.net/ahmdpntb02m6/4LLrN1ye9VBegCHpMNws3I/25db6fbbe7719732e07e1ba1a97d9d98/BT_Datasheet_AI_Agent_Security_for_Endpoints.pdf | Datasheet: AI Agent Security for Endpoints | 2026 |
| https://www.beyondtrust.com/resources/videos/ai-agent-security-demo-build-a-policy | Demo: Build a Policy | 2026-10 |
| https://www.beyondtrust.com/resources/videos/ai-agent-security-demo-discover-and-control-mcp-servers | Demo: Discover and Control MCP Servers | 2026-10 |
| https://www.beyondtrust.com/resources/videos/ai-agent-security-demo-hr-users-and-sensitive-files | Demo: HR Users and Sensitive Files | 2026-10 |
| https://www.beyondtrust.com/blog/entry/phantom-labs-research-index | Phantom Labs Research Index | 2026-08-06 |
| https://www.beyondtrust.com/blog/entry/closing-the-agentic-ai-security-gap | Closing the Agentic AI Security Gap | 2025-09-16 |

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: each docs page re-fetched live and queried for exact wording; the two press releases, the pricing page and the whitepaper landing page read in a browser. Web search was unavailable in this run too (budget exhausted), so there is still no third-party corroboration: every verdict rests on the vendor's own pages. Claims were cross-checked against pages other than the one the brief cited where possible._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | GA supports only Windows 11 / Server 2022+ x64 and macOS 14, 15, 26; no Linux, containers, Windows on Arm | Confirmed | Docs: "Windows 11, or Windows Server 2022 or later, on x64 hardware. Windows on Arm is not supported"; "supports Windows and macOS endpoints only". Linux and containers are excluded by that sentence, not named. macOS support is a rolling "current major and the two before it". No Linux install page exists (404). | [overview](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security), [Windows install](https://docs.beyondtrust.com/bt-docs/docs/windows-manual-install), [GA press](https://www.beyondtrust.com/press/ai-agent-security-general-availability) |
| 2 | Managed hooks for exactly four agents; hook allows the call if the local service is unreachable (Degraded) | Confirmed | "all four supported assistants (Claude Code, Codex, Cursor, and GitHub Copilot)"; "the hook allows the call rather than blocking the developer's work". The docs do not use the term "fail-open" and document no fail-closed option. The MDM payloads page names the same four and no others. | [hooks install](https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-install-and-verify), [MDM payloads](https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-mdm-payloads) |
| 3 | Allow-by-default; subjects only "Any AI agent" or "Anyone"; six actions; no file-write action | Confirmed | "Everything is allowed by default"; two subjects; the six actions as listed; only file action is "reads a file". Caveats: a "Cedar policy" type exists outside the builder (undocumented), and the coding-agent tool action can match a `Write` tool call at the hook, so writes are reachable only cooperatively. | [policies](https://docs.beyondtrust.com/bt-docs/docs/policies) |
| 4 | 27 managed policies run only at Audit or Off; blocking requires a fork | Confirmed | "A managed policy runs at Audit or Off, never at Require Approval or Block"; "To block, fork the policy". The page never states the total; 27 is the sum of the category counts (1+3+4+6+2+8+3). | [managed policies](https://docs.beyondtrust.com/bt-docs/docs/beyondtrust-managed-policies) |
| 5 | HTTPS method/path/content rules need TLS interception with a per-tenant root CA; Windows needs a separate traffic redirect for CLI tools, not for browsers; macOS requires an MDM profile for two system extensions | Corrected | First two parts hold ("rules on the method, path, or content need decrypted traffic"; one tenant root; redirect "Required to inspect or block command-line tools such as aws.exe"; "Do not arm browsers"). The redirect is armed per endpoint and is needed for tools that ignore proxy environment variables. macOS: an MDM profile is required only for zero-touch fleet rollout; a single Mac can be done by hand (approve both extensions in System Settings, grant Full Disk Access). | [administration](https://docs.beyondtrust.com/bt-docs/docs/administration), [policies](https://docs.beyondtrust.com/bt-docs/docs/policies), [Mac install](https://docs.beyondtrust.com/bt-docs/docs/mac-manual-install) |
| 6 | Agents identified by process name, install path, code signature, launched-by lineage, observed LLM connections; any process calling a known LLM host is an agent; undeclared private gateways leave callers unrecognised | Confirmed | Both quotes found. The signal list is introduced with "such as", so it may not be exhaustive. Unknown hosts can also become "Learned" automatically from inference traffic (probe, 1 to 64 connections, tenant cap), so "undeclared" does not always mean "unrecognised". | [agent overview](https://docs.beyondtrust.com/bt-docs/docs/ai-agents-overview), [LLM endpoints](https://docs.beyondtrust.com/bt-docs/docs/visibility-llm-endpoints) |
| 7 | Approval relaxes the whole matching policy on that endpoint; Require Approval allows self-approval; self-approved grants cannot be revoked from the console | Corrected | Scope and self-approval confirmed ("relaxes the matching policy in full on that endpoint ... not only the one call"; "Approve it myself"). The revoke limit is narrower than stated: "A self-approved request cannot be revoked from this panel", with a "View on endpoint" link. No other revoke path is documented, but the docs do not say none exists. Use "no documented central revoke". | [exception details](https://docs.beyondtrust.com/bt-docs/docs/exception-requests-details), [exception requests](https://docs.beyondtrust.com/bt-docs/docs/exception-requests) |
| 8 | MCP servers controlled one at a time (Allow, Monitor, Require approval, Block, per tool); no allow-list that blocks unnamed servers | Confirmed | Verbatim: "controls MCP servers one at a time"; "There is no allow-list setting that blocks every server you have not named, so a server that first appears ... is allowed until you set access on it". | [workflow](https://docs.beyondtrust.com/bt-docs/docs/block-model-providers-and-unapproved-agents), [MCP server details](https://docs.beyondtrust.com/bt-docs/docs/mcp-server-details) |
| 9 | EPM is not a technical prerequisite (Intune, GPO, SCCM, Jamf or by hand); pricing not public | Confirmed | Windows path 2: "You do not run EPM, and you push software with Intune, Group Policy, SCCM, or a similar tool". Mac: Jamf, Intune, Iru, Munki or by hand. Pricing page is a contact form with no figures. Commercial prerequisite is still open: the June release said "initially offered as an add-on to Endpoint Privilege Management" and the GA release does not repeat or withdraw that. | [Windows install](https://docs.beyondtrust.com/bt-docs/docs/windows-manual-install), [pricing](https://www.beyondtrust.com/products/ai-agent-security/pricing), [June press](https://www.beyondtrust.com/press/ai-agent-security) |
| 10 | Whitepaper compares BeyondTrust, Idira (Palo Alto Networks, formerly CyberArk), SailPoint, Zscaler by where in the activity lifecycle each decides; per-vendor placement is inferred | Confirmed | Landing page wording matches exactly, including the Idira parenthetical and "distinct windows for control". Body is behind "Get Access". The SailPoint, Idira and Zscaler matrix rows remain inference and must not be cited as the paper's findings. | [landing page](https://www.beyondtrust.com/resources/whitepapers/ai-agent-security-comparison-vendor-approaches) |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Self-approval under Require Approval lasts "up to 24 h" | Confirmed | Not on the exception or policies pages the brief cites for it; found on the agent Policies tab: "approve it themselves for up to 24 hours". | [AI agents: policies](https://docs.beyondtrust.com/bt-docs/docs/ai-agents-policies) |
| The June 2026 announcement named Linux and containers, which GA dropped | Confirmed | June: "at the endpoint in real time, across Windows, macOS, Linux, and containers". GA: "for Windows and macOS endpoints". | [June press](https://www.beyondtrust.com/press/ai-agent-security), [GA press](https://www.beyondtrust.com/press/ai-agent-security-general-availability) |
| Traffic redirect "declines on corporate-proxy networks"; "a decryption failure falls back to uninspected pass-through" | Overstated | Decline condition is narrower: an endpoint "on a corporate-proxy-only network with TLS inspection off". Pass-through on decryption failure is not stated on the Administration page; it is implied by an "Uninspected signal enabled" setting (off by default) that records TLS connections that could not be decrypted. Treat as inference, not [V]. | [administration](https://docs.beyondtrust.com/bt-docs/docs/administration) |
