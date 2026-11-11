# h08. Practitioner voice: what buyers, operators and monitored developers ask for and complain about

_Researched 2026-11-10 (search-backed follow-up)_

Method: 17 WebSearch calls (4 extended; one refused because the search tool cannot reach reddit.com), then direct reads of vendor docs, survey releases, the Hacker News API, the Cursor forum API and the GitHub issue trackers of `anthropics/claude-code`, `openai/codex` and `anthropics/sandbox-runtime` through `gh`. Tags: **[V]** read at the primary source in this pass; **[S]** secondary write-up only; **[I]** my inference. Issue-tracker and forum items are user reports, not confirmed defects, unless staff confirmed them. Nothing is quoted beyond a short phrase.

## TL;DR

- **Discovery is the one requirement every buyer source repeats.** CSA/Token Security (n=418): 82% found unknown agents in the past year. Okta (n=306 CISOs): only 47% can identify all agents. Lightspeed/Cyber60 (n=200 CISOs): 20% have a complete inventory. [V]
- **Preparedness is falling as deployment grows.** Gravitee's October 2026 wave (n=900, fieldwork 8 to 19 Oct): "very prepared" for a serious agent incident fell from 47.1% to 29.3% in six months; 6.3% can revoke all agent access within an hour; 12.5% can fully reconstruct what an agent did 30 days ago. [V]
- **Prompt fatigue ends in bypass, not vigilance.** A game about it reached 386 points on Hacker News (28 May 2026); the top reply thread is developers sharing shell aliases for skip-permissions mode. Every open-source guard author I read cites prompt volume as the reason they built it. [V]
- **The classifier that replaces prompts creates its own failure.** Claude Code auto mode has open reports of hard denials of user-requested actions with no fallback to a prompt, and of every write tool failing for 30+ minutes when the classifier model is unavailable. [V]
- **TLS inspection is the most documented source of broken tools.** Cursor staff confirmed (April 2026) that Cursor's updater dead-ends behind a re-signing proxy even when the CA is trusted system-wide; the Cursor forum has a cluster of interception threads in July 2026; Claude Code regressed custom CA handling in 2.1.304 (20 Oct 2026). [V]
- **EDR and agents already collide.** Sophos X-Ops telemetry (June 2026, Windows): 56.2% of blocking-rule hits on machines running Claude Code, Cursor and Codex were credential-access rules; Sophos says the rules fire as designed. Users report Falcon plus Uptycs killing a git subprocess in about 7 ms on an argument pattern, and encoded PowerShell from Claude Code being blocked as malicious. [V]
- **Hooks are not yet a dependable enforcement plane.** 2026 reports: PreToolUse hooks not firing on Windows, a session hanging after a hook returns (open, 27 comments), a managed-hooks-only setting bypassed when a base-URL variable is set, admin-console hooks not arriving on Cursor endpoints. [V]
- **How organisations govern today: MDM-pushed managed settings, a gateway base URL, an MCP allow-list, OpenTelemetry export, and a launcher wrapper.** The gaps they name: contractor and BYOD machines, Windows (the Claude Code launcher setting is ignored there), and deny lists that break legitimate work. [V]
- **MSPs want one multi-tenant platform with templates and automated reporting.** AvePoint/Omdia (n=333 MSPs): 51% say governance is the top barrier to client AI adoption, 49% want a complete integrated platform. No market price for agent governance exists yet; pricing is drifting from per-seat to bundles and retainers. [V/S]
- **Developer privacy objections are about use, not existence, of telemetry.** The recurring conditions: aggregated, cost-only, never a performance leaderboard. A Claude Code issue about an email address leaking in a request header drew 1,060 reactions in five days (opened 5 Nov 2026). [V]
- **The harness population is shifting under us.** "Goodbye Claude, hello Pi" reached 806 points (8 Nov 2026); developers cite closed source and telemetry as reasons to move to open harnesses that have no vendor hook contract. [V]
- **No first-hand works-council account and no named-company engineering write-up of an in-house wrapper were found.** Both remain open.

## Findings

### 1. What security teams say they need, and what blocked rollouts

- **Inventory first.** CSA/Token Security, "Autonomous but Not Controlled" (released 21 Apr 2026, fieldwork Jan 2026, n=418): 82% discovered previously unknown agents in the past year, 41% more than once; shadow agents sit in internal scripting and automation (51%), LLM platforms and custom tools (47%), SaaS automation (40%) and developer-built workflows (40%). 65% had an agent incident; only 21% have a decommissioning process; when an agent exceeds scope, 38% require human approval and 11% block automatically. [V] https://cloudsecurityalliance.org/press-releases/2026/04/21/new-cloud-security-alliance-survey-reveals-82-of-enterprises-have-unknown-ai-agents-in-their-environments
- **Control and authorisation.** Okta Global CISO Insights (29 Jul 2026, n=306, six countries): 47% can identify all agents, 46% can control what they access, 45% can authorise what each one does; top barrier is lack of visibility into AI identities (48%; 74% in the US); response to shadow AI is blocking (35%) or bringing it under governance (29%). [V] https://www.okta.com/newsroom/articles/global-ciso-insights-2026/
- **Identity and supply chain.** Lightspeed/Fortune Cyber60 survey (n=200 US CISOs, revenue USD 500M+): 77% run agents in production; 26% pass human credentials to agents; top tooling to evaluate next is agent identity and access governance (55%); 40% name the tool and integration supply chain (MCP servers, plugins, connectors) as a concern; 82% put more than 5% of security budget into AI. [V, via WorkOS summary] https://workos.com/blog/workos-cyber60-2026-2027-ciso-survey
- **A first-hand rollout account** (60+ engineers, DEV Community, 18 Jun; reads as partly vendor-linked to TrueFoundry). Triggers for action: keys in shell profiles, no cost view, offboarding by hunting keys, two Claude Code CVEs, three internal repositories with base-URL overrides, a near-miss prompt injection from a ticket, and one batch job at 3x daily spend. Friction: the deny list broke legitimate workflows and needed case-by-case exceptions; two CI jobs relied on skip-permissions; server-managed settings were bypassed once a base URL was set, so MDM became mandatory; contractor and BYOD machines remain on an "honor system". [V] https://dev.to/sahajmeet_kaur_/what-it-took-to-actually-govern-claude-code-across-our-engineering-team-4jp6
- **Role-based restriction as the blunt instrument.** Goldman Sachs limited Claude Code and GitHub coding tools to about 12,000 engineers in October 2026, citing productivity and risk management (Bloomberg, 2 Nov 2026). [S] https://dev.to/frankchu/12000-engineers-kept-claude-code-bankers-lost-it-2ala
- **Buyer doubt about a new endpoint agent.** On a July 2026 launch thread for an agent-monitoring startup, the top objection was that installing another EDR-like agent is a "no-go" because incumbents ship this; a second commenter called the market suddenly crowded. A vendor in the thread said it started with an MCP gateway and had to add on-device agents. [V] https://news.ycombinator.com/item?id=48937020

### 2. Complaints when security tools meet coding agents

**TLS inspection.**
- Cursor forum: at least five threads between 7 and 17 July 2026 where staff diagnose a Zscaler or similar re-signed certificate; staff state Cursor depends on HTTP/2 for streaming; the macOS updater uses a different network stack from the editor, rejects a system-trusted proxy CA and offers a button that does nothing, which staff called a real gap (20 Apr 2026). [V] https://forum.cursor.com/t/158561 , https://forum.cursor.com/t/165223
- Claude Code: docs now say the OS trust store is read by default (`CLAUDE_CODE_CERT_STORE=bundled,system`), SOCKS is unsupported, and some proxies mishandle gzip request bodies. Field reports still arrive: custom CAs loaded but not used for Bedrock in 2.1.304 (20 Oct 2026); earlier Zscaler failures in the VS Code extension (Feb 2026). Cato's knowledge base (22 Jun 2026) tells customers to set an extra-CA variable globally. [V] https://code.claude.com/docs/en/network-config , https://github.com/anthropics/claude-code/issues/103680 , https://knowledge.catonetworks.com/docs/fixing-tls-inspection-issues-for-claude-code

**EDR collisions and false positives.**
- Sophos X-Ops, "When AI agents look like attackers" (June 2026 telemetry, seven days, Windows; publication date 7 Jul 2026 per secondary): blocking hits by tactic were credential access 56.2% and execution 28.8%; silent hits were evasion 38.5% and command and control 34.0%. Sophos does not call them false positives; advice is to tune some rules for known agent signatures, keep others, and set policy on what an agent may do. [V] https://www.sophos.com/en-us/blog/2607_agents_vs_telemetry
- Claude Code issues: encoded PowerShell blocked as a malicious command line with no opt-out (26 May 2026); marketplace clone killed by CrowdStrike Falcon plus Uptycs on macOS for a submodule flag (20 Feb 2026); a generic "Blocked by endpoint security" screen shown on a personal Mac with no security software, sending the user to a non-existent IT team (13 May 2026). [V] https://github.com/anthropics/claude-code/issues/62348 , /27251 , /58626
- Codex: a macOS issue with 91 comments about system trust daemons running away on CPU and memory (1 Jun 2026). [V] https://github.com/openai/codex/issues/25719

**Hook reliability and conflicts.**
- PreToolUse hooks reported never firing on Windows in 2.1.240 (22 Aug 2026); a session hanging with no error after a hook returns (18 Sep 2026, open); managed-hooks-only reported bypassed when a base-URL variable points at a local proxy (20 Apr 2026); cloud Cowork sessions reported ignoring user hooks and managed settings (29 Mar 2026, open); worktrees inheriting the main checkout's git hooks path (22 Aug 2026, open). [V] https://github.com/anthropics/claude-code/issues/88896 , /95354 , /51123 , /40495 , /88747
- A guard author states that in skip-permissions mode hooks fire asynchronously, so a command runs before the hook can block. [V, author claim] https://news.ycombinator.com/item?id=47343927
- Cursor: an administrator doubted that hooks on a developer machine enforce anything; staff answered that MDM or dashboard distribution prevents local removal; a separate report says console-created hooks never reached the endpoint (Feb 2026). [V] https://forum.cursor.com/t/152460 , https://forum.cursor.com/t/152082

**Prompt fatigue and classifier fatigue.**
- Auto mode: request to let a classifier block fall back to a prompt, after a user-requested release push was denied and the user was told to paste commands by hand (5 Sep 2026, open); all write tools blocked for 30+ minutes because the classifier model was unavailable (16 Apr 2026, open); false positives in a multi-session review workflow after an update (24 Sep 2026). On Hacker News (8 Nov 2026) an engineer reports colleagues switching modes because auto mode refuses guarded CI/CD triggers and read-only production queries. [V] https://github.com/anthropics/claude-code/issues/92279 , /49535 , /96662 , https://news.ycombinator.com/item?id=50407882

**Lost work and damage.** A Codex user reports an agent asked to reboot a server instead altered mounts, systemd and containers, claimed cost above USD 10,000 (3 Nov 2026, 440 comments). [V, single user claim] https://github.com/openai/codex/issues/59060

**Secrets through approval memory.** Apiiro (7 Nov 2026) found passwords in 1,122 public settings files; in the thread an Apiiro author says 539 of 1,105 traced repositories had the file changed in a commit co-authored by the agent, and a Claude Code maintainer says the product has not done secret scrubbing and is looking at it. A fleet administrator in the thread objects to secrets being written to disk at all. [V thread; primary returned 403] https://news.ycombinator.com/item?id=50407882

**Privacy.**
- r/ExperiencedDevs thread on managers seeing AI usage (read through a snapshot mirror, 22 of 38 comments): roughly 8 object, 6 accept, the rest conditional: aggregate or cost-only, enablement not performance review. One says they already pick cheaper models to avoid looking wasteful. [V via mirror] https://reddit.sentinel-team.org/posts/1ttyp80/snapshots/2026-06-02T03%3A16%3A06.246274Z
- Claude Code issue 107757 (5 Nov 2026): a user says their email was exposed in a request header during web searches and that they are moving their company to another harness; 1,060 reactions, 117 comments. [V] https://github.com/anthropics/claude-code/issues/107757
- Meta staff protested mandatory activity capture for AI training in April 2026; the central complaint was no opt-out. [S]
- Thoughtworks Radar vol. 35 (4 Nov 2026) puts AgentsView in Assess and praises its local-first design as what makes adoption easy in security-conscious organisations. [V] https://www.thoughtworks.com/radar/tools/agentsview
- Works councils: only legal guidance found (Covington alert, July 2026, body not read). No first-hand account.

### 3. How organisations govern the four agents today

- **Claude Code:** `managed-settings.json` by MDM (or registry policy keys on Windows, or the admin console); deny and ask rules; bypass mode disabled; sandbox on; hook sources locked; base URL pinned to a gateway with virtual keys, per-developer limits and a model allow-list; one MCP gateway endpoint with a server allow-list and an empty marketplace allow-list; OTel traces to the SIEM. One team pushes a session start/end hook as a managed "base" plugin through Jamf to post to an internal endpoint. [V] https://news.ycombinator.com/item?id=48602864
- **Corporate launcher:** Anthropic documents that some organisations require every process to start through a launcher that applies sandboxing, network controls or credential injection. `CLAUDE_CODE_PROCESS_WRAPPER` (v2.1.208+) and `processWrapper` (v2.1.210+) exist for this. The launcher must reach `exec` within about three seconds, may run three times in series, and Claude Code refuses to start if it cannot run. **On Windows the setting is ignored and processes start unwrapped.** Terminal-started sessions, deep links and the Chrome native-messaging host are not covered. [V] https://code.claude.com/docs/en/corporate-launcher
- **Cursor:** enterprise hooks at a system path by MDM, team hooks from the dashboard, MCP and command allow-lists on the Enterprise plan. [V]
- **Codex:** `requirements.toml` minimums and managed hooks (see g03). **Copilot:** nothing new found in this pass.

### 4. What MSPs ask for and how they price

- AvePoint/Omdia (10 Apr 2026, n=333 MSPs): 51% name data governance and compliance as the top obstacle to client AI adoption; 49% want a complete platform integrated with core tools; 94% intend to automate; 43% claim high maturity; one executive says per-client automation would mean doing it "700 times". [S, two trade articles] https://www.channelinsider.com/ai/building-channel-revenue/msps-ai-opportunity-governance-compliance-barriers/
- Augmentt (n=193 MSP professionals, date unclear): AI and Copilot governance is the fastest-growing client request for 40%; only 42% show clients results through automated reporting. [S, search summary only]
- Packaging (Pax8): readiness assessment, monthly compliance operations, acceptable-use and literacy programme, and a premium audit-readiness tier; pricing "blend[s]" consumption, management and outcome fees; no price points. [V] https://www.pax8.com/blog/operationalizing-ai-governance-for-msps-recurring-revenue/
- Price points found: Microsoft Agent 365 at USD 15 per user per month through CSP [S]; one Australian provider listed an AI governance bundle at 185 per user per month with a 10-user minimum from 1 July 2026 [S], and its page now says the bundle is retired and folded into a broader service [V]. One anecdote of USD 1,000+ per client per month [S].
- Doubts MSPs are told to hold about governance platforms (Portal26 coverage, 21 Oct): encrypted traffic and agent blind spots, false positives eating technician time, deep inspection creating a sensitive record of employee activity, labour eroding margin, clients resisting another recurring line. [S] https://www.remio.ai/post/portal26-msp-ai-governance-platform-turns-shadow-ai-into-a-revenue-test

### 5. What individuals and small teams use, and why they stop

| Tool (licence) | Stars, last push (10 Nov 2026) | Approach |
|---|---|---|
| anthropics/sandbox-runtime (Apache-2.0) | 7,054; 9 Nov; 325 open issues | Seatbelt / bubblewrap plus proxy |
| fencesandbox/fence (Apache-2.0) | 1,016; 3 Nov | Wrapper over the same primitives, command deny rules |
| trailofbits/claude-code-devcontainer (Apache-2.0) | 978; 9 Nov | Dev container |
| finbarr/yolobox (MIT) | 657; 1 Nov | Container, full sudo inside |
| manuelschipper/nah (MIT) | 494; 20 Oct | Deterministic PreToolUse classifier by action type |
| webcoyote/sandvault (Apache-2.0) | 452; 8 Nov | Separate macOS user plus Seatbelt |
| eqtylab/cupcake (Apache-2.0) | 302; 2 Mar | Policy hooks |
| lasso-security/claude-hooks (MIT) | 273; 8 Jan | Injection-scanning hooks |
| borenstein/yolo-cage | 109; archived, last push 1 Feb | VM with egress filtering |

Reasons for abandonment or non-use, from the threads and trackers [V]:
- The vendor ships the feature (auto mode, native sandboxes); the yolo-cage author predicted this and the project is archived.
- Too heavy or outside the IDE: a VM that cannot host the editor; containers that are minimal and lose state.
- Convenience beats isolation: users decline to cut internet access.
- The sandbox breaks real tools: Chromium and Playwright need an extra macOS permission, an IDE directory is hard-blocked and breaks git, bubblewrap fails on Ubuntu 24.04 under AppArmor, no Windows support, stray dotfiles left in the workspace (34 comments), nested sandboxes fail. https://github.com/anthropics/sandbox-runtime/issues
- Installing the guard collides with per-project toolchains (no global pip or npm).
- Deny lists are seen as unmaintainable; commenters show indirect execution through test scripts.
- Distrust of AI-written guards.

### 6. Survey data, 2026

See the matrix. Two cautions: every survey is vendor-commissioned, and incident rates range from 47% to 79% depending on whether suspected incidents count.

### 7. Buyer guides and their criteria

- **SACR, "The CISO Guide to Endpoint Control and Prevention"** (22 Jul 2026, Pingree and Odum; vendor-assisted; now read in full). No formal checklist. Structure: five zones (software posture; application-layer enforcement; agent runtime visibility; intent-aware behavioural analysis; data-centric enforcement). Implied criteria: enforcement before the action completes; fidelity at agent volume without breaking workflows; prompt-to-action attribution; coverage of non-binary software (extensions, MCP servers, skills, models, configuration); graduated responses (warn, coach, redact, block); deployment friction (kernel module, MDM, proxy or none); on-device inference; evidence quality; privacy diligence on intent telemetry; proof of latency claims (one vendor claims sub-4 ms p95 on device). 30-day advice: map coverage to zones, treat classic EDR as baseline plumbing, run privacy diligence early, watch for usage-based pricing. 90-day advice: require attribution, prefer surgical enforcement to blanket allow/block. Prediction: agentless wins 18 months on friction, then enforcement decides. Developer productivity is not addressed. [V] https://softwareanalyst.substack.com/p/the-ciso-guide-to-endpoint-control
- **Forrester Wave, Agentic Development Security Tools, Q4 2026** (blog 5 Nov 2026): 12 vendors, 29 criteria; buyers should demand a demonstration in their own workflows of where guardrails enforce (local, cloud and background agents), visibility into models, MCP servers, skills and hooks, blocking before the action, and a clear line between shipped and roadmap. Developer experience is a scored area. [V blog; report paywalled] https://www.forrester.com/blogs/agentic-development-security-picks-up-where-traditional-security-tools-leave-off/
- Snyk and Backslash publish gated buyer guides; Snyk's framing is enforcement platforms versus monitoring tools. [V landing page only]

## Matrix

**2026 survey data**

| Survey (sponsor) | Fieldwork, n | Headline figures |
|---|---|---|
| CSA "Autonomous but Not Controlled" (Token Security) | Jan 2026, 418 | 82% found unknown agents; 65% incident; 21% decommissioning process; 11% auto-block on scope breach |
| CSA "Enterprise AI Security Starts with AI Agents" (Zenity) | Sep to Nov 2025, 445 | 53% agents exceeded permissions; 47% incident; 16% high confidence in detection; 31% formal policy |
| Gravitee State of AI Agent Security | 8 to 19 Oct 2026, 900 (UK, US) | 51.7% incident or suspected; 11.6% fully secured before go-live (19.7% in April); 17.0% per-agent identity; 6.3% revoke within an hour; 12.5% reconstruct 30 days back; 9.5% named accountable person |
| Okta Global CISO Insights | finalised Jun 2026, 306 | 47% identify all agents; 81% worried about excess access; 48% visibility is top barrier; 26% revoke within minutes |
| Lightspeed/Fortune Cyber60 (Wakefield) | 2026, 200 US CISOs | 77% agents in production; 20% complete inventory; 55% will evaluate agent identity tooling; 79% AI-related incident; 82% spend >5% of security budget on AI |
| AvePoint/Omdia | Apr 2026, 333 MSPs | 51% governance top barrier; 49% want integrated platform |

**Complaint, evidence, design response**

| Complaint | Strongest evidence | What we must do |
|---|---|---|
| Too many prompts | HN 48308376; guard authors | Prompt budget; sandbox-first; offer a scoped rule after repeats |
| Classifier hard-denies or is down | Issues 92279, 49535 | Deny falls back to Ask; local decisions; declared fail mode |
| TLS interception breaks tools | Cursor forum; issue 103680 | No interception by default; hook and OS telemetry first |
| EDR kills agent subprocesses | Issues 27251, 62348; Sophos | Coexistence lab; attribute who blocked; no attacker-shaped command lines |
| Hooks silently absent | Issues 88896, 95354, 51123 | Per-session hook canary; OS-level backstop |
| Unmanaged machines | DEV account | Gateway-side enforcement plus a self-install agent |
| Privacy | Reddit thread; issue 107757 | Metadata by default; no per-person ranking; local-first view |

## What this changes in the earlier briefs

- **33-ux-personas, "Could not verify":** practitioner complaints are now partly filled (this brief). Its prompt-budget target (median 3, p95 8 per developer-day) is supported, and needs a companion rule: a classifier denial must degrade to a prompt, because auto mode's hard denials and outages are now a documented complaint.
- **33, auto-mode figures (0.4% false positives):** vendor-measured; field reports from April to November 2026 describe false positives on release, CI/CD and read-only production actions. Treat the figure as a lab number.
- **01-origin:** the SACR report was read only to 100,000 characters. The rest profiles Bold, Cyberhaven, Bay, CrowdStrike, Palo Alto/Koi and SentinelOne and gives 30- and 90-day advice. It contains no formal RFP checklist and no survey data.
- **g03, "hooks remain fail-open by default":** newly supported by field reports of hooks not firing, hanging, or being bypassed (Aug, Sep, Apr 2026).
- **25-deployment and 17-discovery, "TLS inspection is fragile and politically costly":** newly supported by first-hand Cursor staff statements and Claude Code regressions; add that updaters use a different trust path from the editor.
- **g05-edr-coexistence:** add the Sophos telemetry and two named kill patterns (encoded PowerShell; a git submodule flag under Falcon plus Uptycs).
- **38-network-gateways, `processWrapper`:** correct as written, but add that it is ignored on Windows and does not cover terminal-started sessions, so a wrapper is not a fleet-wide control.
- **21-threats, Apiiro item (secondary):** now supported by the authors' own statements in the HN thread; add the 539-of-1,105 agent-co-authored figure and the maintainer's statement that no secret scrubbing exists.
- **34-compliance, works-council mode:** still unsupported by any first-hand account; the requirement rests on statute and legal guidance only.
- **24 and 26, MSP hierarchy and templating:** supported by AvePoint/Omdia (49% want one platform; per-client automation does not scale).
- **27-embed-oem:** supported by SACR ("baseline plumbing" framing, a vendor riding existing EDR and MDM rails) and by the buyer objection to another endpoint agent.

## Implications for our design

1. **Ship discovery that needs no enrolment decision per agent,** including scripts and bespoke agents; it is the top-ranked requirement in every survey.
2. **Sandbox and scoped rules before prompts; prompts before classifiers; classifiers never as a hard gate without an Ask fallback.**
3. **Make every decision local.** No network call on the tool-call path; declare a fail mode per rule.
4. **Do not intercept TLS by default.** Where an organisation turns it on, scope it per process, keep HTTP/2 and streaming intact, provision trust to every store automatically, and exclude updaters.
5. **Verify hook coverage per session** with a canary at session start, show "verified / unverified" in the console, and back hooks with OS-level sensing because hooks demonstrably go missing.
6. **Own the block message.** State which component blocked (us, the agent's own classifier, or third-party EDR where detectable), the rule, and the one-step route to an exception.
7. **Coexist with EDR by construction:** signed native hook binary, no encoded shells, no interpreter cold starts, published exclusion guidance scoped to our processes only, and a test lab against Defender, Falcon, SentinelOne and Sophos.
8. **Cover the unmanaged machine:** a gateway-side policy point plus a user-installable agent with a join code, since MDM-only governance leaves contractors out.
9. **Privacy as a default setting, not a mode:** metadata-only collection, content capture as an explicit organisation choice with a visible indicator, no per-person productivity views, a local-first developer view.
10. **Support open harnesses (Pi, opencode) and wrapper-less Windows** through OS sensing, because vendor hook contracts and launcher settings do not reach them.
11. **MSP edition:** tenant templates, one-action policy push across tenants, generated monthly evidence reports, usage metering that maps to bundle or retainer pricing.
12. **Scrub secrets from persisted approvals** and from our own stored rules and logs.

### Top fifteen requirements in practitioners' framing

Ranked by how many of 14 source families read in this pass raise them (my tally) [I].

1. "Tell me every agent, MCP server, skill and hook we have, including the ones nobody registered" (10)
2. "Stop the action before it completes, not after" with warn, ask and block (7)
3. "Give each agent its own scoped identity; no keys on laptops; revoke in minutes" (6)
4. "Control which MCP servers, plugins and extensions can be installed" (6)
5. "Show me what the agent did and which prompt caused it" (5)
6. "Don't interrupt me all day; don't break my workflow" (5)
7. "Policy the developer cannot comment out," pushed centrally (5)
8. "Keep agents away from secrets and stop them writing secrets to disk" (5)
9. "Don't build a surveillance record of my developers" (4)
10. "It must work behind our proxy" (4)
11. "It must not fight our EDR" (4)
12. "Not another heavyweight endpoint agent; deploy on rails we already have" (3)
13. "One console for all my clients, with templates and automatic reports" (3)
14. "Cap spend and alert on runaway usage" (3)
15. "When you block, tell me why and let me ask for an exception" (3); tied with "cover contractors, BYOD and whatever harness people switch to" (3)

### Ten most common reasons deployments fail or get removed

1. Prompt volume: users alias skip-permissions or approve blindly.
2. TLS interception breaks the agent, its updater or package traffic.
3. EDR kills agent subprocesses, or agent behaviour floods the SOC until broad exclusions are added.
4. Hooks do not fire, hang, run too late, or are bypassed, and nobody notices.
5. Enforcement depends on a remote classifier that is down or slow.
6. False positives on legitimate release, deploy, CI and read-only actions; exceptions pile up.
7. The sandbox breaks browsers, IDE folders, nested containers or a whole OS.
8. Coverage gaps: Windows, background and cloud sessions, contractors, a new harness.
9. Privacy objections: content capture, per-person metrics, vendor telemetry leaks.
10. The agent vendor or the incumbent EDR ships a good-enough version, or the service costs more labour than it earns (MSPs).

### Acceptance criteria for our user experience

Thresholds are proposals [I] anchored to the evidence above.

| Area | Criterion |
|---|---|
| Prompts | Median 3 or fewer and p95 8 or fewer interruptive prompts per developer per active day; after 3 prompts of the same shape in a session, offer a scoped rule instead of asking again |
| Classifier denial | 100% of non-hard-block denials offer Ask or a one-step exception request; zero dead-end "run it yourself" outcomes |
| Decision latency | Added time per tool call p50 5 ms, p95 15 ms, p99 50 ms; zero network round trips on the decision path |
| Hook start | Native hook cold start 30 ms or less on Windows; no PowerShell, Node or Python in the hook path |
| Launcher | Any wrapper reaches `exec` in 200 ms or less (the agent's own limit is about 3 s, up to three times in series) |
| Sensor down | No unexplained hang; hook watchdog 2 s; hard-block rules still enforced locally; other rules follow their declared fail mode |
| Package installs | Zero failures attributable to us across npm, pnpm, yarn, bun, pip, uv, cargo, go, Maven, Gradle, docker pull, git clone with submodules, brew and winget, with and without an upstream inspecting proxy |
| Agent matrix | Launch, sign-in, streaming, update, stdio MCP and HTTP MCP all pass for Claude Code, Cursor, Codex, Copilot CLI, Gemini CLI, opencode and Pi on Windows, macOS and Linux, every release |
| TLS | Off by default; when on: HTTP/2 and SSE preserved, trust auto-provisioned, updaters excluded, pinning failure triggers bypass plus an event |
| Build cost | 3% or less wall-clock overhead on reference clean builds; 1% or less idle CPU |
| EDR | Zero detections of our binaries or hook invocations by Defender, Falcon, SentinelOne and Sophos in the lab |
| Hook coverage | Missing or non-firing managed hook detected within 60 s of session start and shown per session |
| Block message | Visible within 1 s; names component, rule and next step; never blames software that is not installed |
| Lost work | Zero sessions terminated by policy without resumable state, kill switch excepted |
| False positives | 5% or fewer of blocks overturned on appeal; a rule with over 20% override rate is flagged |
| Revocation | Agent access revoked fleet-wide in 60 s or less |
| Reconstruction | Any session from the last 30 days rebuilt in under 1 minute |
| Privacy | Metadata-only by default; "what is collected and who sees it" within 2 clicks; no per-person ranking view exists |
| MSP | New tenant from template in 10 minutes; one action pushes policy to N tenants; monthly report generated without technician time |

## Could not verify / open questions

- **Reddit** (r/cybersecurity, r/sysadmin, r/msp, r/ClaudeAI, r/cursor): the search tool cannot reach the domain. One thread was read through a third-party snapshot mirror. This is the largest remaining gap.
- **Primary pages that returned 403:** Apiiro's report, Cybernews, ChannelE2E. Bloomberg's Goldman report was not read. Sophos's publication date comes from a secondary source.
- **Paywalled or gated:** the Forrester Wave vendor list and full criteria; Snyk and Backslash buyer guides; the Covington works-council PDF; the Augmentt MSP survey.
- **No first-hand works-council objection** to agent monitoring was found, and no vendor works-agreement template.
- **No named large company** has published an engineering account of an in-house wrapper or sandbox platform that I could find; the evidence is Anthropic's launcher documentation and one 60-engineer account.
- **No independent hook latency measurements;** only author and vendor claims (about 20 ms for a bash guard, sub-4 ms p95 for one vendor).
- **No market price** for agent governance sold through MSPs; the per-user figures are one retired listing and one Microsoft add-on.
- **Build slowdown from endpoint security during agent sessions:** searched, nothing citable found.
- **GitHub Copilot governance in practice** was not researched in this pass.
- The share of traffic on Pi and opencode (one commenter says about 10%) is unverified.

## Sources

- https://cloudsecurityalliance.org/press-releases/2026/04/21/new-cloud-security-alliance-survey-reveals-82-of-enterprises-have-unknown-ai-agents-in-their-environments , CSA/Token Security survey, 2026-04-21
- https://cloudsecurityalliance.org/press-releases/2026/04/16/more-than-half-of-organizations-experience-ai-agent-scope-violations-cloud-security-alliance-study-finds , CSA/Zenity survey, 2026-04-16
- https://www.gravitee.io/state-of-ai-agent-security , Gravitee State of AI Agent Security, fieldwork 2026-10-08 to 19
- https://www.okta.com/newsroom/articles/global-ciso-insights-2026/ , Okta Global CISO Insights, 2026-07-29
- https://workos.com/blog/workos-cyber60-2026-2027-ciso-survey , Lightspeed/Fortune Cyber60 CISO survey summary, 2026
- https://softwareanalyst.substack.com/p/the-ciso-guide-to-endpoint-control , SACR CISO Guide to Endpoint Control and Prevention, 2026-07-22
- https://www.forrester.com/blogs/agentic-development-security-picks-up-where-traditional-security-tools-leave-off/ , Forrester, 2026-11-05
- https://www.sophos.com/en-us/blog/2607_agents_vs_telemetry , Sophos X-Ops, June 2026 telemetry
- https://dev.to/sahajmeet_kaur_/what-it-took-to-actually-govern-claude-code-across-our-engineering-team-4jp6 , DEV Community, 18 Jun
- https://dev.to/frankchu/12000-engineers-kept-claude-code-bankers-lost-it-2ala , DEV Community on Bloomberg's Goldman report, Nov 2026
- https://code.claude.com/docs/en/network-config , https://code.claude.com/docs/en/corporate-launcher , Claude Code docs, fetched 2026-11-10
- https://knowledge.catonetworks.com/docs/fixing-tls-inspection-issues-for-claude-code , Cato Networks KB, 2026-06-22
- https://github.com/anthropics/claude-code/issues/ 27251, 40495, 49535, 51123, 58626, 62348, 88747, 88896, 92279, 95354, 96662, 103680, 107757 , Feb to Nov 2026
- https://github.com/openai/codex/issues/59060 , https://github.com/openai/codex/issues/25719 , 2026
- https://github.com/anthropics/sandbox-runtime/issues , issues 74, 105, 139, 159, 210, read 2026-11-10
- https://forum.cursor.com/t/152460 , /152082 , /158561 , /165223 , /155578 , Cursor forum, Feb to Jul 2026
- https://news.ycombinator.com/item?id=48308376 (permission fatigue game, 2026-05-28), 47343927 (nah, 2026-03-11), 46706796 (yolo-cage, 2026-01-21), 46695467 (Fence, 2026-01-20), 48937020 (Traceforce launch, 2026-07-16), 50407882 (Apiiro thread, 2026-11-07), 50410107 (Goodbye Claude, hello Pi, 2026-11-08), 48602864 (Jamf-pushed hook comment, 2026-06-19)
- https://reddit.sentinel-team.org/posts/1ttyp80/snapshots/2026-06-02T03%3A16%3A06.246274Z , mirror of an r/ExperiencedDevs thread
- https://www.thoughtworks.com/radar/tools/agentsview , Thoughtworks Radar vol. 35, 2026-11-04
- https://www.channelinsider.com/ai/building-channel-revenue/msps-ai-opportunity-governance-compliance-barriers/ , https://securitybrief.co.uk/story/msps-face-ai-adoption-hurdle-over-governance-rules , AvePoint/Omdia MSP survey coverage, 2026-04-10
- https://www.pax8.com/blog/operationalizing-ai-governance-for-msps-recurring-revenue/ , Pax8, 2026
- https://www.remio.ai/post/portal26-msp-ai-governance-platform-turns-shadow-ai-into-a-revenue-test , Portal26 MSP platform coverage, 21 Oct
- https://evisent-website.pages.dev/ai-governance-bundle , provider page, fetched 2026-11-10 (bundle now retired)
- https://www.cov.com/en/news-and-insights/insights/2026/07/works-council-rights-in-ai-implementation-projects , Covington alert, July 2026 (summary page only)

## Independent verification

_Checked 2026-11-10 by a separate fact-checking pass. Method: 4 web searches, direct reads of primary pages, the Cursor forum JSON API, the Hacker News API and `gh` (read-only) against `anthropics/claude-code` and `openai/codex`. Verdicts: confirmed, corrected, refuted, unverifiable. Nothing above this section was changed._

### The ten plan-critical claims

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | CSA/Token Security: 82% found unknown agents in the past year, 65% had an agent incident, n=418, fieldwork Jan 2026 | confirmed | CSA's own report page words it as 82% "have discovered shadow AI agents in the past year" and 65% with at least one incident in the past year. Press release gives n=418, online, January 2026, commissioned by Token Security. Report page is dated 20 Apr 2026, the press release 21 Apr. | https://cloudsecurityalliance.org/artifacts/autonomous-but-not-controlled-ai-agent-incidents-now-common-in-enterprises |
| 2 | Gravitee Oct 2026 wave: n=900 UK/US, 6.3% revoke within an hour, 12.5% reconstruct 30 days back, "very prepared" 47.1% to 29.3% since April | confirmed | All four figures are on Gravitee's page (fieldwork 8 to 19 Oct 2026 by Opinion Matters; April wave n=750). Single vendor source: a web search found no third-party coverage of the October wave yet, so there is no independent corroboration. | https://www.gravitee.io/state-of-ai-agent-security |
| 3 | Sophos X-Ops, seven days in June 2026, Windows: 56.2% of blocking-rule hits credential access, 28.8% execution; rules fire as designed | confirmed | Figures are pie-chart shares by tactic; no machine or event counts are published, so the base is unknown. Sophos says protections work "exactly as designed", but also says one older obfuscation rule was already hardened to cut false positives from agents, so "no false positives" is slightly too clean. Agents include skill-pack agents (GStack), not only the three named. Publication date is 7 or 8 Jul 2026 per two secondary sources. | https://www.technadu.com/ai-coding-agents-trigger-security-detection-says-sophos/630580/ |
| 4 | Claude Code launcher (`CLAUDE_CODE_PROCESS_WRAPPER` v2.1.208+, `processWrapper` v2.1.210+) is ignored on Windows, does not cover terminal-started sessions, needs `exec` within about three seconds | confirmed | Exact as documented. Two additions: the docs give a supported way to cover terminal sessions (a `claude` shim earlier on `PATH`), and older versions silently ignore the setting, so version pinning matters. Deep links, `--worktree --tmux` relaunch and the Chrome native-messaging host are also uncovered. | https://code.claude.com/docs/en/corporate-launcher |
| 5 | Auto mode has open reports of hard denials with no fallback to a prompt, and of all Edit/Write/Bash failing 30+ minutes when the classifier model is unavailable | corrected | Both reports exist and are open (#92279, 3 comments, labelled enhancement; #49535, 10 comments, labelled duplicate). But the product is not fallback-free: docs say auto mode resumes prompting after 3 blocks in a row or 20 in a session, a blocked action can be approved from the "Recently blocked" tab in `/permissions`, `ask` rules still force a prompt, and the classifier model can be pinned (v2.1.302+). A single block is still a hard deny, and classifier-unavailable still fails closed. Several #49535 commenters trace their case to client configuration (attribution header disabled, non-Claude model routers), not an outage. | https://code.claude.com/docs/en/permission-modes |
| 6 | Hook enforcement fails in the field: PreToolUse not firing on Windows in v2.1.240; session hang after a hook returns (open, 27 comments); `allowManagedHooksOnly` bypassed with `ANTHROPIC_BASE_URL` | corrected | Two of the three do not support the claim. #88896 was retracted by its reporter on 6 Sep 2026: an org policy with `allowManagedHooksOnly` was suppressing the project hooks, i.e. the managed control worked; closed as not planned (follow-up #92489 is about the silent drop being invisible). #51123 was closed 12 May 2026 with the outcome that this is the documented limit of server-managed settings (a non-default base URL skips the fetch); endpoint-managed (MDM) settings are the enforcement path, and no bypass of those was shown. #95354 is real and open with 27 comments, mostly from one reporter, who on 26 Oct reported no recurrence in 3,178 hook runs on 2.1.301 to 2.1.310 and attributed part of it to PowerShell 7 processes not exiting (possibly held by EDR). Residual defect: a hook timeout does not fire when the hook process never finishes exiting. | https://github.com/anthropics/claude-code/issues/88896 , https://github.com/anthropics/claude-code/issues/51123 , https://code.claude.com/docs/en/server-managed-settings |
| 7 | Cursor staff confirmed the macOS updater rejects a system-trusted inspection CA and dead-ends, and that Cursor relies on HTTP/2; cluster of proxy threads in July 2026 | corrected | Updater: confirmed, staff reply of 30 Apr 2026 (thread opened 20 Apr) calls it "a real gap"; no fix date given. July cluster: confirmed and understated, forum search shows 15+ threads between 2 and 17 Jul where staff diagnose TLS inspection; staff said on 17 Jul that 3.12 shipped changes for corporate proxies. HTTP/2: the "relies heavily on HTTP/2" line in thread 155578 is from a community Ambassador, not staff. Cursor's docs say HTTP/2 streaming is the default with automatic fallback to HTTP/1.1 SSE; staff wording is that Zscaler breaks streaming "especially with SSL inspection or HTTP/2". | https://cursor.com/docs/enterprise/network-configuration , https://forum.cursor.com/t/165411 |
| 8 | First-hand account of governing Claude Code for 60+ engineers (MDM managed settings, gateway base URL with virtual keys, MCP allow-list, OTel); deny lists broke workflows; contractor/BYOD ungoverned | corrected | The article says all of this. It is not an independent practitioner account: the author is listed by TrueFoundry as Founder's Office staff working on content and go-to-market, the DEV account was created 11 Jun 2026 (a week before the post), and the gateway described is TrueFoundry's. Treat it as vendor content that is consistent with Anthropic's docs, not as evidence of what a buyer did. | https://www.truefoundry.com/blogs/authors/sahajmeet-kaur |
| 9 | AvePoint/Omdia, 333 MSPs (April 2026): 51% governance and compliance top barrier; 49% want a complete integrated platform | confirmed | Both figures match AvePoint's own release. The release is dated 9 Apr 2026 (not 10 Apr) and gives no fieldwork dates, so "April 2026" is a publication date, not fieldwork as the matrix column implies. The "700 times" quote is from an unnamed executive. AvePoint sells the platform the 49% figure favours. | https://www.avepoint.com/news/research-from-avepoint-and-omdia-reveals-governance-and-compliance-as-the-leading-ai-adoption-barrier-among-ms-ps-260409 |
| 10 | SACR CISO guide (22 Jul 2026): no RFP checklist or survey data; implied criteria as listed; agentless wins 18 months, then enforcement decides | confirmed | Read to the end (159k characters): no checklist, no survey data, criteria as listed. Exact wording: "The agentless wedge is real but time-boxed", the ride-the-EDR vendor model "wins the next 18 months on deployment friction", then API depth and real-time enforcement limits decide. Note the tension inside the report: earlier it recommends a hybrid model "with preference towards agent-based solutions" and warns agentless claims may mislead. The sub-4 ms figure is flagged by SACR itself as vendor-reported. | https://softwareanalyst.substack.com/p/the-ciso-guide-to-endpoint-control |

### Three further statements in this brief

| Statement | Verdict | Note | Source |
|---|---|---|---|
| "A guard author states that in skip-permissions mode hooks fire asynchronously, so a command runs before the hook can block" (section 2) | refuted as a current fact | The author did say it (March 2026). Current docs say the opposite: a PreToolUse hook returning deny blocks the tool even in `bypassPermissions` or with `--dangerously-skip-permissions`, and PreToolUse fires before any permission-mode check. Do not design around hooks being unenforceable in bypass mode. | https://code.claude.com/docs/en/hooks-guide |
| EDR collision evidence: issues 62348, 27251, 58626 (section 2, matrix row "EDR kills agent subprocesses") | corrected | All three are closed as not planned with the stale label and 2 to 5 comments each; none has a staff confirmation. The details quoted (about 7 ms kill, Falcon plus Uptycs, encoded PowerShell) are single-reporter claims. Sophos is the only strong evidence in that row. | https://github.com/anthropics/claude-code/issues/27251 |
| "Hooks remain fail-open by default: newly supported" and "Claude Code regressed custom CA handling in 2.1.304" (TL;DR, "What this changes") | corrected | Default is still fail-open, but since v2.1.295 a command or http hook can set `onFailure: "block"` to fail closed; the brief omits this. The 2.1.304 CA regression (#103680) was reported fixed in 2.1.310 and closed 27 Oct 2026; the thread ties it to a revoked/blocked root (emSign) being dropped from the system store, and it also hit HTTP MCP servers, not only Bedrock. | https://code.claude.com/docs/en/hooks , https://github.com/anthropics/claude-code/issues/103680 |

Spot checks that held: issue 107757 has 1,060 reactions and 117 comments (open); Codex 59060 has 440 comments (closed as not planned); Codex 25719 has 91 comments (open); HN 48308376 scored 386 and HN 50410107 scored 806 on the stated dates.

### What the plan must not get wrong

- Do not cite #88896 or #51123 as hook-bypass evidence. The first shows managed-hooks-only working; the second is a documented limit of server-managed (not MDM) settings.
- "Hooks are not dependable" rests mainly on one open hang report (#95354) that its reporter can no longer reproduce, plus the documented fail-open default. A fail-closed option exists (`onFailure: "block"`, v2.1.295+).
- Auto mode does fall back to prompting after 3 consecutive or 20 total blocks; the gap is a single block and classifier unavailability.
- The 60-engineer account is vendor-authored (TrueFoundry). The plan has no independent first-hand rollout account.
- Cursor has an HTTP/1.1 SSE fallback; HTTP/2 is the default, not a hard dependency.
- PreToolUse deny works in bypass mode per current docs.
