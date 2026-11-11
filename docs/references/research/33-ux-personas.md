# 33. User experience: personas, journeys, information architecture, approvals

_Researched 2026-11-09_

Method note: web search was unavailable for this run (the shared search budget was exhausted before this brief started). Everything below comes from primary pages fetched directly by URL, the gh CLI, and the vendor captures already in `research/_sources/`. Items I could not reach are listed at the end. Design recommendations follow the ui-architect manual; each names the principle it applies.

## TL;DR

- **Prompts fail by volume.** Anthropic reports users accept 93% of Claude Code permission prompts, and that sandboxing cut prompts by 84% internally. A prompt that is approved nine times in ten is a rubber stamp. Design for fewer, better prompts, with a measured prompt budget.
- **A classifier cannot be the only gate.** Anthropic's auto mode has a 0.4% false-positive rate but misses 17% of real overeager actions. Use it to remove routine prompts, keep hard blocks and human approval for irreversible actions.
- **One posture ladder for everything: Off, Watch, Ask, Block.** BeyondTrust ships exactly this (Off / Audit / Require Approval / Block), with self-approval at "Require Approval" and admin approval at "Block". Adopt the ladder; use plainer words.
- **Rules should read as sentences and be replayed before they bite.** BeyondTrust's builder is Describe, Build rules, Test and save, with replay tabs Matched / Almost matched / Did not match / Not enough detail. Cloudflare, AWS IAM and AWS WAF all offer test-before-enforce.
- **Simple, advanced and code must be three views of one file.** Tailscale's visual editor edits the same HuJSON policy file, shows a live JSON preview, and goes read-only under a GitOps lock. Fleet does the same with YAML.
- **Triage sessions, not alerts.** Origin sorts reviewed traces into "worth a look", "routine" and "noise" (34 / 2,353 / 136 in its public example, so 1.3% need a person) and anchors each finding to quoted evidence.
- **Competitors under-serve role separation.** BeyondTrust's GA console makes every user a full admin. Origin has eight roles that separate prompt content from metadata. Role-scoped content access is a first-day requirement for us.
- **Exceptions are too coarse elsewhere.** A BeyondTrust approval relaxes the whole policy on that endpoint for the grant window, not the one call. Scope ours to the exact action pattern.
- **The monitored developer is a persona nobody designs for.** Origin and ThreatLocker both let admins hide the tray icon. An open-source product can do the opposite: show what is collected, who sees it, and why something was blocked.
- **Time to value sets the bar.** ThreatLocker builds a baseline "within a few hours" of install; Huntress claims deployment in under 20 minutes. Our solo path should show the first agent and session in under five minutes with no account.
- **Accessibility is a build constraint, not polish.** WCAG 2.2 AA for the web console; AccessKit (UI Automation, NSAccessibility, AT-SPI) for the Rust desktop app. Rune's support for it is unverified.

## Findings

### 1. Approval fatigue and alert fatigue: what is published

- Anthropic, "Claude Code auto mode" (2026-03-25): users accept 93% of manual permission prompts. Auto mode layers a prompt-injection probe on tool output and a two-stage transcript classifier on actions. Measured: 0.4% false-positive rate on 10,000 real actions; 17% false-negative rate on 52 real overeager actions; 5.7% on synthetic exfiltration. A denial goes back to the agent with a reason so it can try a safer route; 3 consecutive or 20 total denials escalate to the human; headless runs terminate instead. https://www.anthropic.com/engineering/claude-code-auto-mode
- Anthropic, "Claude Code sandboxing" (2025-10-20): filesystem plus network isolation "safely reduces permission prompts by 84%" in internal use. https://www.anthropic.com/engineering/claude-code-sandboxing
- Claude Code permissions docs (fetched 2026-11-09): rules evaluate deny, then ask, then allow; modes are default (labelled Manual), acceptEdits, plan, auto, dontAsk, bypassPermissions; "Yes, and don't ask again" persists per repository and command for shell, until session end for edits; managed settings can disable auto and bypass modes; a PreToolUse hook can deny or force a prompt but cannot override a deny rule. https://code.claude.com/docs/en/permissions
- OpenAI Codex (fetched 2026-11-09): sandbox modes read-only, workspace-write, danger-full-access; approval policies on-request, never, or granular; `approvals_reviewer = "auto_review"` routes eligible requests to a reviewer agent, fails closed, and denies critical-risk actions. `approval_policy = "untrusted"` is retired. https://learn.chatgpt.com/docs/agent-approvals-security
- Alahmadi et al., USENIX Security 2022: SOC analysts report most false positives are benign triggers (true matches on legitimate behaviour). Useful alarms are Reliable, Explainable, Analytical, Contextual, Transferable. https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi
- Akhawe and Felt, USENIX Security 2013: click-through on browser warnings ranged from about 10% (Firefox malware) to 70.2% (Chrome SSL). Warning design changes behaviour. https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe

### 2. Request and approve flows

- **BeyondTrust AI Agent Security** (docs updated 2026-10-13). A block gives the user a link to a request form. At Block the user selects "Submit for review"; at Require Approval the user may "Approve it myself" for a time-limited exception. The admin queue has cards Pending, Approved today, Denied today, Oldest pending, Median time to answer, and the docs call Oldest pending "the card to watch". Approving sets a Grant window (for example 4h); it reaches the endpoint in 15 to 30 seconds. A denial reason is mandatory and is the only thing the requester sees. Self-approved grants cannot be revoked centrally. https://docs.beyondtrust.com/bt-docs/docs/exception-requests , https://docs.beyondtrust.com/bt-docs/docs/exception-requests-details
- **ThreatLocker** (KB fetched 2026-11-09). Learning Mode starts at install and creates baseline policies "within a few hours"; review after "a few days", then Secure Mode. A block popup offers "Request Access" and "Don't Show Again". The request window has an optional message and email. Since agent 7.3 an approval produces a popup with "Run Now". The Approval Center lets the admin set the policy level from computer up to Global, an expiry, suggested Ringfencing, a virtual Testing Environment and a VirusTotal lookup. The marketing page claims its Cyber Hero team answers in about 60 seconds. https://threatlocker.kb.help/end-users-guide-to-threatlocker-request-popups/ , https://threatlocker.kb.help/threatlocker-application-control-quick-start-guide/ , https://threatlocker.kb.help/approval-center-revamped/ , https://www.threatlocker.com/platform/allowlisting
- **LuLu** (fetched 2026-11-09). Alert shows process, destination, code-signing, process hierarchy and a VirusTotal button. Rule Scope is the whole process or "Remote Endpoint"; Rule Duration is indefinite, process lifetime, or "Expires in". Install defaults "Allow Apple Programs" and "Allow Installed Applications" remove most first-day prompts. Passive Mode applies rules silently. https://objective-see.org/products/lulu.html
- **Little Snitch 6** (fetched 2026-11-09). The connection alert creates a rule; lifetime is forever or until an event; scope is domain or host; rules can carry a note; alerts can be minimised to decide later; an Internet Access Policy button explains why the app connects. https://help.obdev.at/littlesnitch6/alert-overview

### 3. Policy authoring, simulation, one representation

- **BeyondTrust policy builder** (2026-10-13). Rules read as "Audit when Any AI agent reads a file on File path `*/.ssh/*`". Suggestion chips pre-fill the description. The builder refuses rules that would lock a human out. Replay runs over a chosen window. A "Cedar policy" type exists for hand-written policy. Everything is allowed by default. https://docs.beyondtrust.com/bt-docs/docs/policies
- **Tailscale visual policy editor** (validated 2026-03-13). Edits the HuJSON policy file; switch editors at any time; JSON preview panels; Tests run before save; GitOps lock makes the console read-only; some network options are JSON-only. https://tailscale.com/kb/1550/visual-editor
- **Fleet GitOps mode**: YAML in git is the source of truth and GitOps-managed UI sections become read-only. https://fleetdm.com/docs/configuration/yaml-files
- **Cloudflare Access policy tester**: before saving, shows the percentage of active users allowed or denied, plus a single-user test. https://developers.cloudflare.com/cloudflare-one/access-controls/policies/policy-management/
- **AWS IAM policy simulator**: no real request is made; reports allowed or denied and the statement responsible. AWS WAF advises count mode on production traffic before enabling. https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html , https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html
- **Natural-language authoring**: Amazon Bedrock AgentCore Policy turns English into Cedar, validates against the tool schema, and uses automated reasoning to flag rules that are overly permissive, overly restrictive or unsatisfiable. It also accepts Dogwood, a policy language with session-aware temporal conditions. https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- **CrowdStrike AIDR** (Pangea docs): a Sandbox tab beside the policy that does not log, and a Playground that does. `research/_sources/crowdstrike/aidr-docs-policies-testing.md`

### 4. Triage, session and attack-story views

- **Origin** (home page and changelog captured 2026-11-09). Automatic trace review; triage re-checks each finding against the session and marks it confirmed, refuted, overstated or unread; each finding opens on the turn with the evidence quoted. Roles: Tenant Admin, SecOps (prompt content stripped), Detection Engineer (raw content), IT / Fleet Admin, Viewer, Vendor Support, Security Engineering, No Data Access. https://www.originhq.com/ , https://docs.originhq.com/llms-full.txt
- **BeyondTrust session details**: Summary, Transcript, Timeline (consecutive like actions collapse into phases), Files split into Changed and Viewed, Findings. https://docs.beyondtrust.com/bt-docs/docs/ai-session-details
- **Microsoft Defender XDR** (2026-11-04): incident page has Attack story (graph that can be played over time), Alerts, Assets, Investigations, Evidence and Response (approve or reject pending remediation), Summary, Similar incidents, Activities. The page is now labelled legacy; "incident cases" are in preview. https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents
- **Microsoft Agent 365** (GA 2026-05-01, per user). Registry cards: Total agents, Agents without owners, Unmanaged agents. A Risks column merges Purview, Entra and Defender signals but can lag by an hour. Agent Map clusters by build platform (including Amazon Bedrock and Google Vertex AI); Single Agent Map (preview) shows top 50 users and tools. https://learn.microsoft.com/en-us/microsoft-agent-365/overview , https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview , https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-map
- **Trace tools**: Langfuse groups observations into traces and traces into sessions with a session replay; LangSmith uses runs, traces (25,000-run cap), threads and a flattened "trajectory"; Datadog adds topic clustering (Patterns) and Insights with root cause and fix; Honeycomb BubbleUp explains a selection against a baseline. https://langfuse.com/docs/observability/features/sessions , https://docs.langchain.com/langsmith/observability-concepts , https://docs.datadoghq.com/llm_observability/ , https://docs.honeycomb.io/investigate/analyze/identify-outliers/

### 5. Transparency for the monitored person

- Honest Security: trust rests on informed consent and transparency; expect personal use of work devices; educated users can make sound decisions. https://honest.security/
- Fleet's transparency page lists what the agent can and cannot see and points to the source code as proof. https://fleetdm.com/transparency
- Origin has an admin setting "Hide system tray icon"; ThreatLocker documents hiding the tray icon. `research/_sources/origin/docs-llms-full.md`, https://threatlocker.kb.help/getting-started/
- Microsoft offers "Conceal user, group, and site names in all reports", which also hides names in Single Agent Map.

### 6. Multi-tenant

- Defender multitenant management: cross-tenant Incidents, Alerts, Cases, Advanced hunting, Custom detection rules, and Tenant groups. https://learn.microsoft.com/en-us/unified-secops/mto-overview
- ThreatLocker: policy hierarchy from computer to Global, per-organisation tray branding, per-customer "Cyber Hero Approval Instructions".
- Huntress: "A human reviews every alert before it reaches you". https://www.huntress.com/platform/managed-edr

### 7. Accessibility and internationalisation

- WCAG 2.2 adds 2.4.11 Focus Not Obscured (AA), 2.5.7 Dragging Movements (AA), 2.5.8 Target Size 24 by 24 CSS px (AA), 3.2.6 Consistent Help (A), 3.3.7 Redundant Entry (A), 3.3.8 Accessible Authentication (AA). https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/
- AccessKit provides adapters for Windows UI Automation, macOS NSAccessibility and Unix AT-SPI; no rich text or hypertext yet; pushed 2026-11-09. https://github.com/AccessKit/accesskit
- fluent-rs (Apache-2.0) and ICU4X are the maintained Rust localisation libraries. https://github.com/projectfluent/fluent-rs , https://github.com/unicode-org/icu4x

## Matrix

| Product | First-run default | Prompt or request design | Test before enforce | Editors over one policy | End-user transparency |
|---|---|---|---|---|---|
| BeyondTrust AI Agent Security | Allow all; managed policies at Audit or Off | Link to form; self-approve or admin; grant window | Replay with "Almost matched" | Sentence builder plus Cedar type | Requester sees status and denial reason |
| ThreatLocker | Learning Mode, then Secure Mode | Popup, Request Access, Run Now on approval | Testing Environment (VM) | GUI only | Tray; can be hidden |
| LuLu | Allow Apple and installed apps | Allow or Block; scope; duration | Passive Mode | GUI, import and export | Local, open source |
| Little Snitch 6 | Alert or silent modes (names unverified) | Rule lifetime, domain or host, minimise | Silent mode | GUI plus `.lsrules` | Local |
| Claude Code | Manual mode | Yes / don't ask again / no; auto mode classifier | None built in | Settings JSON, `/permissions` | In terminal |
| Tailscale | Not verified this run | Not applicable | Tests section | Visual, JSON, GitOps lock | Not applicable |
| Cloudflare Access | Not verified this run | Not applicable | Policy tester (% of users) | UI, API, Terraform | Block page |
| Origin | Observe | No inline enforcement prompt documented | Not applicable | Not applicable | Tray; can be hidden |
| Agent 365 | Registry inventory | Admin approves agent publish requests | Not found | Admin centre, Graph API | Names can be concealed in reports |

## Weak points, gaps and risks

- BeyondTrust: allow-by-default; every console user is an Admin; an approval relaxes the whole policy on the endpoint; self-approved grants are not centrally revocable; list columns cannot be sorted; MCP rules are marked "limited".
- Microsoft: risk counts up to an hour stale; three portals with different roles (Purview insider-risk needs its own role); one agent appears as several registry rows by design; usage filters stop at 4,000.
- Anthropic and OpenAI: classifier review adds model cost and still misses real cases; neither gives an organisation a cross-agent view.
- ThreatLocker: Learning Mode bypasses deny policies while it runs; leaving the email field empty means no notification.
- Risk for us: three policy views drift apart unless one representation and round-trip tests are enforced from the first commit.
- Risk for us: a transparent tray that can be switched off by policy will be switched off; decide the floor now.

## Implications for our design

### Design review (ui-architect contract)

**Evaluation.** The category has good parts in separate products: posture ladder and replay (BeyondTrust), triage buckets (Origin), one-file editors (Tailscale), personal prompts (LuLu). Nobody combines them, and nobody serves the solo user and the monitored developer.

**Violations and opportunities.** Empty policy forms and allow-all first runs break Smart Defaults. Tenant-first onboarding is a signup wall before value. Flat alert lists ignore Chunking. Coarse approvals lack Ethical Friction where it matters and add it where it does not.

**Actionable fixes.** Sections below.

**Principles cited.** Smart Defaults, Reciprocity and IKEA Effect, Goal Gradient, Chunking, Zen of Clarity, Prioritize Intent, Safety Principle, Ethical Friction, Meaningful Highlights, Relationship Strength, Exponential Scaling, Optical Corrections.

### Core vocabulary (use these words everywhere: UI, CLI, API, docs)

| Object | Plain-language definition |
|---|---|
| Agent | A program that uses an AI model to do things on your behalf, such as Claude Code or an in-house bot. |
| Session | One stretch of work by an agent, from the request that started it to the end. |
| Action | One thing an agent tried: run a command, read or change a file, call a tool, reach a site. Outcome is allowed, watched, asked or blocked. |
| Policy | A named set of rules with a mode (Off, Watch, Ask, Block) and a scope (which people, machines, agents). |
| Rule | One sentence: when *who* does *what* on *which thing*, unless *exception*. |
| Detection | A pattern that flags risky behaviour across one or more actions. |
| Finding | One detection firing, pinned to the actions that prove it. |
| Incident | Related findings that a person must decide about; it has an owner and a status. |
| Approval | A person's yes or no on a paused action, with a scope and a time limit. |
| Exception | A temporary, scoped relaxation of a rule, with a reason and an expiry. |
| Pack | A versioned bundle of policies, detections and lists that can be installed, forked and updated. |

### Progressive disclosure over one representation

1. **Simple**: packs as switches, each with the four-step mode control. Default new packs to Watch. *Smart Defaults, Zen of Clarity.*
2. **Advanced**: sentence builder (who, does what, on what, unless), opened pre-filled from a real action or a suggestion, with replay tabs including "almost matched". *Never empty forms.*
3. **Code**: the policy text with tests, diff, and a GitOps lock that turns the other two views read-only.

Rules: every Simple or Advanced edit shows its code diff before save; constructs the builder cannot draw render as a read-only "written in code" card (Tailscale and BeyondTrust both hit this); comments survive round-trips; a property test asserts builder output is stable through parse and print. Natural-language authoring only ever produces a draft in Advanced view, with replay and over-permissive or unsatisfiable lints, and stores the sentence as the policy's intent.

### Approval prompt

Anatomy, top to bottom: who (agent, session task, repository); what in plain words with the literal call one click away; why it stopped (rule name, one-line reason); what is new (first contact with this host, outside the workspace, irreversible); choices. Choices are Deny (default focus), Allow once, Allow for this session, Allow for one hour, each scoped to the exact pattern shown. "Always" is a link into the rule builder, absent for destructive classes. High-risk prompts hold input for a short beat. *Ethical Friction, Prioritize Intent.*

Fatigue controls:
- Tier the work: allow and log in-workspace reads and edits; send the middle band to a reviewer model that fails closed; reserve people for irreversible, out-of-boundary or novel actions; never prompt for hard blocks.
- Return denials to the agent with a reason and a safer alternative, then escalate after repeated denials (Anthropic's 3 and 20).
- Seven-day Watch period on install, then propose rules with "this would have asked you N times last week".
- Collapse repeats per rule per session; allow minimise-and-decide-later.
- Flag any rule approved more than 90% of the time over 20 prompts, and any approver whose median decision is under two seconds.
- Headless or locked screen: fail closed, queue the request, notify out of band.

### What the monitored developer sees and controls

- A tray or menu-bar app that states status in one line, lists policies in force in plain language, and shows "My activity" exactly as an admin would see it.
- A Privacy panel: categories collected, a live sample of the user's own data for each, and which roles can read content versus metadata.
- Block explanation in three places (agent reply through the hook, toast, tray): rule, reason, what to do instead, one-click request with the justification pre-filled from the session task. Auto-resume or "Run now" on approval.
- Snooze: silence prompts for a set time (pending actions queue or are denied back to the agent). In managed mode, an admin-allowed "pause content capture" with a visible timer, logged to audit; metadata continues.
- Floor: the disclosure screen and tray status cannot be hidden without an audit entry visible to the user.

### Information architecture

**Web console** (five areas plus settings; *Chunking, Safety Principle*):
- Today: pending approvals, sessions worth a look, coverage gaps, one summary sentence with "explain why".
- Inventory: Agents, Tools and MCP servers, Endpoints, Identities.
- Activity: Sessions, Actions, Search.
- Protect: Policies, Packs, Approvals and Exceptions, Simulator.
- Respond: Review queue (Worth a look, Routine, Noise), Incidents, Detections.
- Settings: Deployment, Integrations, Roles, Privacy, Audit, Tenants.
Persistent: scope switcher, time range with UTC toggle, command palette.

**Desktop app**: tray popover (status, pending approvals, snooze); window with Now, My activity, Rules (Simple view only), Privacy, Settings. Approval prompts are native windows.

**Command line** (noun then verb, same nouns): `status`, `agents ls`, `sessions show`, `actions tail`, `policy test | diff | apply`, `approvals ls | approve | deny`, `exceptions grant --for 1h`, `packs install`, `explain <action>`, `doctor`. `--json` on every command.

### Personas

| Persona | Jobs to be done | First five minutes | Three journeys |
|---|---|---|---|
| Solo developer | See what my agents do; stop the dangerous few; not be nagged | Install, no account; agents found; first session listed; Watch mode on | Review a session; turn a seen action into a rule; answer a prompt |
| Small-team lead | Shared baseline; know who runs what | Invite link; baseline pack pre-selected; team inventory | Roll out a pack; approve a teammate; weekly summary |
| Endpoint or IT admin | Deploy, keep healthy, prove coverage | MDM snippet copied; first endpoint checks in; setup list already part-done | Staged rollout; fix an unhealthy sensor; move a pack Watch to Ask |
| Detection engineer | Write, test, ship detections and rules as code | Clone the pack repo; run tests; replay against last week | Author with replay; tune a noisy rule; promote via GitOps |
| SOC analyst | Decide fast what matters; respond | Review queue with three buckets; open the top item on its evidence | Triage a finding; build an incident story; contain an agent |
| CISO | Risk posture, trend, evidence for the board | One page: coverage, top risks, prompt health | Quarterly report; approve a policy change; review exceptions |
| Compliance or privacy officer | Prove controls; limit data seen | Roles and retention pre-set to least content | Export audit; answer an access request; review content access |
| MSP technician | Work many customers from one queue | Cross-tenant queue with tenant column | Approve per customer instructions; push a pack; onboard a tenant |
| MSP owner | Margin, service levels, standardisation | Tenant health table; approvals service level | Standardise baseline; spot drift; usage report |
| OEM partner | Embed engine and views under own brand | Run the engine locally; call the API; themed component renders | Map vocabulary; embed approvals; ship pack updates |
| Monitored developer | Keep working; understand and contest blocks | Disclosure screen; tray shows what is collected | Read a block reason; request an exception; snooze prompts |

### MSP patterns

Hierarchy of partner, customer, group, endpoint. Packs live in a partner library and are assigned to customers with version pinning; per-customer overrides show as a diff. One queue across customers with tenant groups. "Acting as" banner and audit entry on every cross-tenant action. Technicians see metadata by default; content needs a per-customer grant. Per-customer approval instructions and tray branding.

### Accessibility and internationalisation

WCAG 2.2 AA on web. Desktop: every control exposed through AccessKit with name, role and state; full keyboard path including approval prompts; no drag-only interactions (graphs need a table alternative); 24 px minimum targets; 4.5:1 text contrast; never colour alone for the four modes (icon from Lucide or Phosphor plus label); reduced-motion setting. Strings in Fluent files; ICU plurals, dates and numbers; pseudo-locale and right-to-left runs in CI; policy keywords stay untranslated while explanations translate; spacing tokens on an exponential scale with optical corrections.

### Acceptance criteria

| Measure | Target |
|---|---|
| Time to first insight, solo | 5 minutes from download to first agent and session, no account |
| Time to first insight, organisation | 30 minutes from tenant to first endpoint inventory |
| Notification to approval decision | 2 clicks |
| Finding to exact evidence | 1 click |
| Observed action to draft rule | 3 clicks |
| Watch to Block including replay | 5 clicks |
| Interruptive prompts per developer per active day | Median 3 or fewer; 95th percentile 8 or fewer |
| Rule approval rate | Flag outside 20% to 80% after 20 prompts |
| Admin exception answer time | Median 15 minutes; oldest pending under 4 hours |
| Decision reaches endpoint | 30 seconds |
| Block explanation visible | 1 second |
| Sessions needing a person | 2% or fewer; at least half judged useful |
| Developer finds "what is collected, who sees it, why blocked" | 2 clicks from tray |
| Builder round-trip | 100% stable in property tests |
| Accessibility | Zero WCAG 2.2 AA failures in automated and manual audit |

## Ideas worth stealing and whitespace

- Steal: "Almost matched" replay tab; "Oldest pending" card; LuLu's two install defaults; "Run now" on approval; Origin's evidence-quoted findings and three buckets; Tailscale's live code preview; AgentCore's lints on generated rules; Honeycomb's selection-versus-baseline to explain why a session is unusual.
- Whitespace: a prompt budget with rubber-stamp detection; exceptions scoped to one action pattern; a developer-facing privacy view; one product from laptop to MSP; cross-agent approvals in one native prompt; published approval-health metrics.

## Could not verify / open questions

- Complaints about the CrowdStrike Falcon and Microsoft Defender consoles: needs search; Falcon docs are behind login.
- Wiz, 1Password and Huntress console specifics: Wiz docs gated, 1Password Device Trust page returned 404, Huntress support returned 403. Only Huntress marketing was read.
- Little Snitch operation-mode names and ThreatLocker's dedicated Learning Mode, Installation Mode and Elevation articles did not load.
- Chrome's quieter-permission data (article body did not render).
- Whether the Rune UI framework integrates AccessKit, supports right-to-left text and input methods. No repository was identified. This gates the desktop accessibility target.
- The Fleet transparency URL returned a page framed around Secureframe's agent; treat its specifics with care.
- AccessKit's licence: GitHub reports BSD-3-Clause; confirm per crate.
- EN 301 549 and European Accessibility Act obligations were not re-read this run.
- Whether Origin shows end users their own data.

## Sources

- https://www.anthropic.com/engineering/claude-code-auto-mode , Claude Code auto mode, 2026-03-25
- https://www.anthropic.com/engineering/claude-code-sandboxing , Claude Code sandboxing, 2025-10-20
- https://code.claude.com/docs/en/permissions , Configure permissions, fetched 2026-11-09
- https://learn.chatgpt.com/docs/agent-approvals-security , Codex approvals and security, fetched 2026-11-09
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security , /policies , /exception-requests , /exception-requests-details , /ai-session-details , /administration , BeyondTrust AI Agent Security docs, 2026-10-13
- https://www.originhq.com/ , https://www.originhq.com/changelog , https://docs.originhq.com/llms-full.txt , Origin, captured 2026-11-09
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview , Agent 365 overview, 2026-08-19
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview , Agent Registry, 2026-09-21
- https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-map , Agent Map, 2026-10-15
- https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents , Investigate incidents (Legacy), 2026-11-04
- https://learn.microsoft.com/en-us/unified-secops/mto-overview , Defender multitenant management, 2026-05-27
- https://threatlocker.kb.help/end-users-guide-to-threatlocker-request-popups/ , /threatlocker-application-control-quick-start-guide/ , /approval-center-revamped/ , /tray-settings-application-control/ , ThreatLocker KB, fetched 2026-11-09
- https://www.threatlocker.com/platform/allowlisting , ThreatLocker Allowlisting, fetched 2026-11-09
- https://objective-see.org/products/lulu.html , LuLu, fetched 2026-11-09
- https://help.obdev.at/littlesnitch6/alert-overview , Little Snitch 6 connection alert, fetched 2026-11-09
- https://tailscale.com/kb/1550/visual-editor , Visual policy editor, validated 2026-03-13
- https://fleetdm.com/docs/configuration/yaml-files , Fleet GitOps YAML, fetched 2026-11-09
- https://fleetdm.com/transparency , Fleet transparency, fetched 2026-11-09
- https://developers.cloudflare.com/cloudflare-one/access-controls/policies/policy-management/ , Access policy management, fetched 2026-11-09
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html , IAM policy simulator, fetched 2026-11-09
- https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html , Testing and tuning AWS WAF, fetched 2026-11-09
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html , Policy in AgentCore, fetched 2026-11-09
- https://pangea.cloud/docs/aidr/policies/testing , CrowdStrike AIDR policy testing, captured 2026-11-09
- https://langfuse.com/docs/observability/features/sessions , https://docs.langchain.com/langsmith/observability-concepts , https://docs.datadoghq.com/llm_observability/ , https://docs.honeycomb.io/investigate/analyze/identify-outliers/ , fetched 2026-11-09
- https://www.huntress.com/platform/managed-edr , Huntress Managed EDR, fetched 2026-11-09
- https://honest.security/ , Honest Security, fetched 2026-11-09
- https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi , 99% False Positives, 2022
- https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe , Alice in Warningland, 2013
- https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/ , What's new in WCAG 2.2, fetched 2026-11-09
- https://github.com/AccessKit/accesskit , https://github.com/projectfluent/fluent-rs , https://github.com/unicode-org/icu4x , read via gh 2026-11-09

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (shared budget exhausted), so each claim was re-read on the primary page and, where one existed, cross-checked against a second primary page or the source repository through gh._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude Code users accept 93% of permission prompts; auto mode full pipeline 0.4% false positives on 10,000 real actions, 17% false negatives on 52 real overeager actions | Confirmed | Figures are for the full pipeline. Stage 1 alone is 8.5% FPR and 6.6% FNR. Synthetic exfiltration FNR 5.7% (n = 1,000). The 3-in-a-row and 20-total thresholds also appear in the current docs and are not configurable. | https://www.anthropic.com/engineering/claude-code-auto-mode , https://code.claude.com/docs/en/permission-modes |
| 2 | Sandboxing (filesystem plus network isolation) cut permission prompts by 84% in internal use | Confirmed | Exact wording: "In our internal usage, we've found that sandboxing safely reduces permission prompts by 84%." Published 2025-10-20. | https://www.anthropic.com/engineering/claude-code-sandboxing |
| 3 | BeyondTrust postures Off, Audit, Require Approval, Block; self-approval at Require Approval, admin approval at Block; allow unless a policy covers it | Confirmed | The status column also has Draft (never published), and endpoints can show an Exception label. "Everything is allowed by default." | https://docs.beyondtrust.com/bt-docs/docs/policies , https://docs.beyondtrust.com/bt-docs/docs/exception-requests |
| 4 | An approval relaxes the matching policy in full on that endpoint for the grant window, arrives in 15 to 30 seconds, and a self-approved grant cannot be revoked from the console | Confirmed | Exact wording: "relaxes the matching policy in full on that endpoint for the grant window"; "A self-approved request cannot be revoked from this panel" (the panel offers "View on endpoint" instead). | https://docs.beyondtrust.com/bt-docs/docs/exception-requests-details |
| 5 | Every BeyondTrust AI Agent Security console user is an Admin; no read-only or reviewer role (docs of 2026-10-13) | Confirmed | "Every user you add is an administrator, with full access to the tenant." "There is no way to give someone read-only access." The page adds "Additional roles are coming in a future release", so treat this as a point-in-time gap. | https://docs.beyondtrust.com/bt-docs/docs/administration |
| 6 | Origin buckets worth a look / routine / noise (34 / 2,353 / 136); triage marks findings confirmed, refuted, overstated or unread against quoted evidence | Confirmed | The bucket counts are on the home page. The four triage verdicts are not on the home page; they are in the changelog entry for v1.12.5 (2026-09-30). The counts are a marketing example, not a measured customer rate. | https://www.originhq.com/ , https://www.originhq.com/changelog |
| 7 | Tailscale visual editor edits the same HuJSON file as the JSON editor, shows live JSON previews, runs tests before save, is read-only under a GitOps lock; some network options are JSON-only | Confirmed | The lock is an explicit setting ("Prevent edits in the admin console" under Policy file management); with it on, users can still search, filter and preview. JSON-only items named: `derpMap`, `disableIPv4`, `OneCGNATRoute`, `randomizeClientPort`, and the Convert to grants button. No second independent page corroborates the lock wording. | https://tailscale.com/kb/1550/visual-editor |
| 8 | AgentCore Policy converts natural language to Cedar, validates against the tool schema, and uses automated reasoning to flag overly permissive, overly restrictive or unsatisfiable policies | Confirmed | Natural-language authoring targets Cedar only (the feature is called NL2Cedar) and needs a deployed Gateway and policy engine, because the Gateway schema drives generation. Dogwood is a separate hand-authored path. Cedar here is deny by default. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html , https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-natural-language.html |
| 9 | AccessKit has Rust adapters for UI Automation, NSAccessibility and AT-SPI, no rich text or hypertext yet; Rune's integration unverified | Corrected | The AccessKit part holds (it also ships Android and iOS adapters). The Rune part is verifiable: `anomalyco/rune` depends on `accesskit` 0.25.2 and has a default-on `accessibility` feature that pulls `accesskit_windows`, `accesskit_macos` and `accesskit_unix`, with an `a11y` module per platform. Right-to-left and input-method support were not checked. | https://github.com/AccessKit/accesskit , https://github.com/anomalyco/rune/blob/dev/crates/rune/Cargo.toml |
| 10 | ThreatLocker Learning Mode starts automatically at install and builds baseline policies within a few hours; blocked users get Request Access and, once approved, a Run Now popup | Confirmed | The cited popup article does not mention Learning Mode. Automatic entry is stated in the Automatic Policy Creation article ("your computers will automatically be placed into Application Control Learning Mode"); "Within a few hours" is in the quick start guide. The approval popup with Run Now exists from agent 7.3. Default learning duration is not stated on any page read. | https://threatlocker.kb.help/automatic-policy-creation/ , https://threatlocker.kb.help/threatlocker-application-control-quick-start-guide/ , https://threatlocker.kb.help/end-users-guide-to-threatlocker-request-popups/ |
| A | Section 1: in auto mode "headless runs terminate instead" | Corrected (outdated) | The March 2026 article says the headless process terminates. The current docs say the opposite for a `-p` run without `--permission-prompt-tool`: "the action doesn't run and Claude keeps working. Claude Code doesn't stop the run." Do not cite Claude Code as precedent for terminating a headless run. | https://code.claude.com/docs/en/permission-modes |
| B | Open questions: "AccessKit's licence: GitHub reports BSD-3-Clause" | Corrected | The README states Apache-2.0 or MIT at the user's option. The BSD-style licence (`LICENSE.chromium`) covers only the portions derived from Chromium. GitHub's licence detector picks up that file. | https://github.com/AccessKit/accesskit |
| C | Weak points: "ThreatLocker Learning Mode bypasses deny policies while it runs" | Unverifiable | No page read states this. The Automatic Policy Creation article says only that the group's Default Deny policy must exist for Learning Mode to work. The dedicated Learning Mode article returned 404. | https://threatlocker.kb.help/automatic-policy-creation/ |

Also spot-checked and found accurate: Agent 365 generally available 2026-05-01 per user (Microsoft Learn overview); Claude Code rule order deny, ask, allow, the "don't ask again" persistence, and hooks not overriding deny rules (permissions docs); LangSmith 25,000-run trace cap; Codex `approval_policy = "untrusted"` retired.
