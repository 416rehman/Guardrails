# Market news sweep, June to November 2026: entrants, deals, funding, pricing, analysts, testing

_Researched 2026-11-10 (search-backed follow-up)_

**Method.** WebSearch worked in this pass: 18 queries used (3 extended), the cap. Everything else is direct fetches and the GitHub API. Tags: **[P]** primary page or API read today; **[S]** secondary (trade press, vendor page describing a third party's report, aggregator); **[1S]** a single secondary source, not corroborated. Gartner, Forrester and Latio documents are gated; what is said about them rests on vendor pages that cite them.

## TL;DR

- **Nvidia entered with an Apache-2.0 runtime that is now a CNCF project.** Open Agent Safety Platform (28 Sep 2026) = OpenShell (kernel-enforced sandbox, egress policy check, credential injection, a policy prover; v0.1.7 on 3 Nov; 21.3k stars) plus Sentry (closed, BlueField-4 DPU watchdog, reference design). Partners include Anthropic, Microsoft, CrowdStrike, Palo Alto, Cisco. It governs only agents launched inside it; IDC's analyst put its coverage at "probably less than 25%" of the problem. [P][S]
- **Microsoft adopted Gartner's term.** "Guardian Agents" were added to Project Perception on 19 Oct 2026 (Perception itself: 27 Jul 2026); no price or GA date published. [S]
- **AARM conformance is now a real list, with a commercial gate.** The registry shows 123 builders and 11 conformant (Extended: Noma, Runlayer, Operant, Microsoft Agent Governance Toolkit, QuilrAi, Ultra; Core: Formal, MintMCP, Highflame, Airia, Unbound). Public conformance claims require five production customers for three months and a SOC 2 Type II, ISO 27001 or FedRAMP certificate. [P]
- **Still no independent comparative test of agent-security products.** AMTSO v1.0 guidelines are final (2 Sep 2026); SecureIQLab has a 32-scenario methodology with no agentic coverage and no results; nothing from AV-Comparatives, AV-TEST, SE Labs or MITRE surfaced. [P]
- **Deal count: 30 since 2024, 14 announced in 2026** per one public ledger built from SEC filings. New to our briefs: Fortinet/Virtue AI (17 Aug), Okta/Permiso (closed 26 Aug), Cyera/Oasis closed 3 Sep at about USD 1B, Snowflake/Natoma USD 128.3M. Proofpoint/Varonis at USD 6.3B (15 Oct) is reported by one secondary source only. [S][1S]
- **Several prices in brief 06 were trade-press guesses.** Filing-based figures: Koi USD 231M (not ">400M"), Portkey USD 117M (closed 29 May), CalypsoAI USD 145.2M, CyberArk USD 21.1B, SGNL USD 637.1M. [S]
- **Money since June is going to runtime control and discovery:** Onyx USD 113M B, HiddenLayer USD 100M B, AIR Security USD 50M seed, Harmonic USD 50M B, Reco USD 55M, Pluto USD 42M, Rein USD 25M, Opsin USD 21M, Rig USD 12M, Ultra USD 10M. [S]
- **Public price anchors now number four, not one:** Knostic USD 15 per user per month (free for 1 to 5 users); Aembit USD 20 per agent per month (free for 3 agents); Pomerium Zero USD 7 per user per month with MCP tool access control; Microsoft Agent 365 USD 15 per user per month. Everyone else is "contact sales". [P]
- **Analyst names to map to:** Gartner guardian agents and AI TRiSM; Forrester "agentic control plane" (33 vendors, Q2 2026); Latio's five categories (15 Sep 2026, about 400 vendors); KuppingerCole has six agent-related Leadership Compasses scheduled Dec 2026 to Dec 2027, including "Agentic Threat Detection and Response (ATDR)". [S][P]
- **MDR for agent activity is still unclaimed.** Arctic Wolf's Shadow AI Discovery (14 Oct, select customers from November) is an inventory of AI tools, not monitoring of agent actions. No launch found from Huntress, Expel, Red Canary, Blackpoint, ConnectWise, Kaseya or N-able. [P]
- **A vendor-neutral RFP exists and it reads like our feature list:** NHI Mgmt Group's template (updated 28 Oct 2026) has 36 requirements, 14 mandatory, with published weights. Its first mandatory item is discovery "without manual registration". [P]
- **Open-source entrants are single-layer.** OpenShell (sandbox), Numbat, Sage, Prempti, SolonGate (hooks or local gateway), Strands Box (sandbox with Dogwood policies), Halofy (AGPL governance layer). None combines discovery, OS sensor, console and multi-tenancy. Harden.Run AIF sits on GitHub with 1.9k stars under a proprietary beta licence. [P]

## Findings

### 1. New, renamed or newly visible products since June 2026

**Platform vendors**

- **Nvidia Open Agent Safety Platform**, 28 Sep 2026. OpenShell README [P]: "instruments the kernel to enforce policy on every file access, system call, and network connection"; agents "never see real credentials"; a prover uses formal verification to flag risky policy changes for human review. Runs on Linux, macOS on Apple Silicon, Windows through WSL 2 (experimental); a `windows` branch uses Microsoft MXC; Kubernetes gateway by Helm. Apache-2.0, created 24 Feb 2026, release cadence weekly (v0.1.6 on 27 Oct, v0.1.7 on 3 Nov). README states it "is now part of the CNCF" with development moving to the `ai-openshell` organisation. Sentry is not open source [S]. Partner list and analyst criticism from InfoWorld [S]: governs only infrastructure the customer controls; does not address unknown agents; OpenAI, Amazon and Google absent. https://github.com/NVIDIA/OpenShell ; https://www.infoworld.com/article/4227894/nvidia-releases-open-agent-safety-platform-to-monitor-and-govern-agentic-ai-2.html
- **Microsoft Project Perception** (unveiled 27 Jul 2026) gained Guardian Agents on 19 Oct 2026: supervisory agents that limit permissions or block actions; local discovery raised from 25 to 60 agent types. Pricing and availability unpublished. [S] https://redmondmag.com/articles/2026/10/19/microsoft-expands-project-perception-to-address-security-risks-from-ai-agents.aspx (403 on fetch; details from search result summary and https://wetheflywheel.com/en/guides/ai-agent-security-vendors-2026/)
- **Arctic Wolf** (14 Oct 2026): Shadow AI Discovery, Aurora MDR Connect for MSPs, Aurora Adaptive Threat Protection (beta endpoint product, not agent-specific). [P]

**Startups that surfaced in this window**

| Company | Date | What it does | Evidence |
|---|---|---|---|
| AIR Security | 1 to 3 Sep 2026, USD 50M seed (Sequoia, Greenoaks) | "Inline firewall" for what enters agent context: vets skills, plugins, MCP servers; revokes add-ons across agents; runs a pre-vetted marketplace | [S] https://dealroom.co/news/148163/air-raises-50m-seed-to-build-a-firewall-for-ai-agents |
| Onyx Security | USD 113M B, 29 Jul 2026 (Bessemer); USD 153M total | Runtime control plane that stops agent actions; Anthropic integration (June); Revolut named | [1S] https://softwarestrategiesblog.com/2026/10/26/cybersecurity-startups-to-watch-2027/ |
| Rig Security | USD 12M seed, 29 Sep 2026 (Ten Eleven, Brightmind, CrowdStrike Falcon Fund) | Identity graph plus "Bifrost" endpoint sensor that separates an agent's session from the user's session and enforces policy | [S] https://www.securityweek.com/rig-security-emerges-from-stealth-with-12m-to-tackle-agentic-ai-identity-risks/ |
| Ultra Security | USD 10M seed, 21 Oct 2026 | Sits between agents and MCP servers; local-first or hosted; AARM Extended conformant; SOC 2 Type II, ISO 27001, ISO 42001 | [S] https://www.securitysystemsnews.com/article/ultra-security-emerges-from-stealth-with-10m-seed-round-for-agentic-ai-platform ; [P] https://aarm.dev/builders |
| Pluto Security | USD 42M seed plus A, 13 Oct 2026 (Jump Capital) | Endpoint discovery of AI tools, skills, extensions, MCP servers; 30+ customers | [1S] wetheflywheel |
| Opsin | USD 21M, 15 Oct 2026 (SYN, Race) | Links agents on Copilot, Claude, ChatGPT Enterprise, Gemini to purpose and access | [1S] wetheflywheel |
| Rein Security | USD 25M A, 8 Oct 2026 (Glilot, Sienna) | Runtime security for enterprise agents | [S] |
| Asymptote Labs | USD 5.5M seed, 20 Oct 2026 | Runtime telemetry; GitHub org has `airlock` (MIT, "Cryptographic Context Broker", 10 Sep 2026) | [S] plus [P] GitHub API |

**Renames.** `mintmcp.com` now 308-redirects to `mintive.com`; the pricing page brands the company Mintive (date of rename not stated) [P]. Oasis now trades as Cyera Identity [S]. Prelude to Origin and Envoy AI Gateway to Agent Router were already in g03.

**Open source and source-available, checked through the GitHub API today [P]**

| Repo | Licence | Created | Stars | Layer |
|---|---|---|---|---|
| NVIDIA/OpenShell | Apache-2.0 | 2026-02-24 | 21,332 | Sandbox runtime, gateway, policy prover |
| uber/ADR | Apache-2.0 | 2026-04-19 | 2,129 | Discovery, sensor, benchmark, detector |
| hardenrun/aif | Proprietary "AIF Beta License" (VizopsAI, Inc.) | 2026-08-01 | 1,913 | Hooks for Claude Code, Codex, Cursor, Gemini CLI, Kiro; local dashboard |
| perplexityai/numbat | Apache-2.0 | 2026-07-24 | 1,164 | Hooks, on-device detection, forensics |
| solongate/agent-security | Apache-2.0 | 2026-09-27 | 615 | Local-first gateway for coding agents (Go), OpenSSF gold badge |
| strands-agents/box | Apache-2.0 | 2026-10-02 | 512 | OS-isolated sandbox with default-deny Dogwood policies |
| gendigitalinc/sage | Apache-2.0 | 2026-02-12 | 325 | Hook-based "ADR" layer |
| halofyai/halofy | AGPL-3.0-or-later | 2026-08-22 | 320 | Identity, policy, provenance, audit for agents' access to organisational context |
| falcosecurity/prempti | Apache-2.0 | 2026-03-18 | 232 (last push 21 Sep) | Falco rules over agent hooks |

Microsoft's Agent Governance Toolkit is listed AARM Extended conformant [P]. No project describing itself as an open-source or open-core "AI detection and response platform" was found.

### 2. Acquisitions and shutdowns

Source for the table is the public ledger at https://guptadeepak.com/agent-security/deals/ ("updated monthly", basis column cites SEC filings or press releases) [S]. Deals not in brief 06, or changed, since June:

| Announced | Deal | Closed | Price | Basis |
|---|---|---|---|---|
| 2026-05-27 | Snowflake / Natoma | 2026-06-03 | USD 128.3M | SEC filing |
| 2026-05-14 | Akamai / LayerX | 2026-07-02 | USD 205M | SEC filing |
| 2026-05-04 | Cisco / Astrix | 2026-06-29 | about USD 400M | trade press |
| 2026-06-15 | SailPoint / Entro | 2026-06-29 | USD 122.6M | SEC filing |
| 2026-07-28 | Cyera / Oasis | 2026-09-03 | about USD 1B | press release |
| 2026-07-30 | Okta / Permiso | 2026-08-26 | undisclosed | press release |
| 2026-08-17 | Fortinet / Virtue AI | 2026-08-17 | undisclosed ("immaterial") | press release |
| 2026-10-15 | Proofpoint / Varonis | expected H1 2027 | USD 6.3B, USD 49.75 per share | [1S] wetheflywheel; not confirmed at source |
| 2026-10-15 | Cohere / Aisle | letter of intent | undisclosed | [1S] |
| 2026-11-03 | CrowdStrike / Fiddler, Dreadnode | pending | undisclosed | g03 |
| 2026-11-09 | Vanta / Pillar | signed | undisclosed | g03 |

Earlier 2026 prices corrected by the same ledger: Palo Alto/Koi USD 231M (closed 14 Apr); Palo Alto/Portkey USD 117M (closed 29 May); Palo Alto/CyberArk USD 21.1B (closed 11 Feb); CrowdStrike/SGNL USD 637.1M (closed 20 Feb); ServiceNow/Veza USD 1.20B (closed 2 Mar); F5/CalypsoAI USD 145.2M; Check Point/Lakera USD 201.8M; SentinelOne/Prompt Security USD 160.2M. OpenAI/Promptfoo is still listed pending.

**Shutdowns:** none found. That is an absence in 18 searches, not a finding. Archived open-source projects (TensorZero, LLM Guard, Kuzu) are in g03.

### 3. Funding rounds over USD 10M since June 2026

Onyx Security USD 113M B (29 Jul); HiddenLayer USD 100M B (2 Sep, Delta-v); Zenity USD 125M (press-release slug on Zenity's newsroom, date not shown) [P]; MIND USD 72M B (17 Sep); Reco USD 55M (29 Sep; USD 140M total); AIR Security USD 50M seed (Sep); Harmonic USD 50M B (14 Oct, Crosspoint); Pluto USD 42M (13 Oct); BlueFlag USD 28M (date not verified); Rein USD 25M A (8 Oct); Opal Security USD 23M (4 Jun); Opsin USD 21M (15 Oct); Rig USD 12M (29 Sep); Ultra USD 10M (21 Oct); Oak USD 60M and Corma USD 60M seed (July, identity intelligence for AI); Cyera USD 400M at USD 12B (22 Sep). Adjacent: Daytona USD 60M B (20 Oct, agent sandboxes); Upwind USD 300M (Sep). Context: Crunchbase counted USD 855M across 150+ AI-security seed rounds in 2026 by late July, and at least 18 AI-security rounds of USD 100M or more by Q3. All [S]: https://softwarestrategiesblog.com/2026/10/26/cybersecurity-startups-to-watch-2027/ ; https://wetheflywheel.com/en/guides/ai-agent-security-vendors-2026/ ; https://aiweekly.co/alerts/ai-security-startups-pull-855m-across-150-seed-rounds-in-2026

### 4. Public price points

| Product | Unit | Price | Free tier | Evidence |
|---|---|---|---|---|
| Knostic Kirin | per user per month | USD 15 (Team); Enterprise custom | 1 to 5 users, no dashboard or audit log | [P] https://www.knostic.ai/pricing |
| Knostic AgentMesh (skill and MCP catalogue) | per user per month | USD 15 (300 API calls a month); USD 850 (unlimited API) | 300 items per category | [P] same |
| Aembit, agentic plan | per agent per month | USD 20 (10 to 500 agents, 7-day logs) | 3 agents, 5 MCP policies, 24-hour logs | [P] https://aembit.io/pricing/ |
| Aembit, workloads | per workload per month | USD 20 | 10 workloads | [P] same |
| Pomerium Zero | per monthly active user | USD 7 annual, USD 9 monthly; includes MCP server access, tool access control, OAuth token management | Personal: 1 cluster, 10 routes, 5 policies; Core is open source | [P] https://www.pomerium.com/pricing |
| Microsoft Agent 365 | per user per month | USD 15; inside E7 at about USD 99 | none | [S] Microsoft Tech Community post via search; brief 03 |
| HiddenLayer full platform | per year, AWS Marketplace | USD 5,000,000 listed | - | [1S] https://saaswithalex.pages.dev/posts/ai-agent-security-platforms-buyer-guide/ |
| Mintive (ex MintMCP) | per user plus platform fee | not published; four size bands | none | [P] https://www.mintive.com/pricing |
| Akto Atlas / Argus | "usage-based" | not published | none | [P] https://www.akto.io/pricing |
| Okta for AI Agents | - | contact sales; Workforce minimum USD 1,500 a year | - | [P] https://www.okta.com/pricing/ |
| OpenShell, Numbat, Sage, Prempti, SolonGate | - | free (Apache-2.0) | - | [P] |

Obsidian's own explainer (1 Jun 2026) says no major agentic security platform publishes enterprise list pricing and that quotes key on **agent count** or **non-human identity count**, with premiums for runtime over posture and enforcement over detection [P] https://www.obsidiansecurity.com/academy/agentic-security-pricing. One buyer guide says 12 of 25 benchmarked vendors are fully opaque [1S]. No per-endpoint or per-token list price for an agent-security product was found.

### 5. Analyst framing

- **Gartner.** Market Guide for Guardian Agents (25 Feb 2026, Litan and Plummer). Self-announced representative vendors: Astrix (agent identity segment), Cato Networks (IT or security platform segment), Polygraf AI, NeuralTrust, Orchid, AGAT Pragatix ("Risk and Security Specialists" segment) [S]. A second note, "Accelerate AI Agent Governance and Security Using Platform-Agnostic Guardian Agents" (14 May 2026), and a Hype Cycle for Agentic AI (2 Apr 2026) exist; Zenity says it is named in two Hype Cycle categories, in the Market Guide for AI TRiSM, and as a "Market Shaper" in an inaugural Gartner emerging-market quadrant [P, Zenity newsroom]. Gartner pages return 403.
- **Forrester.** "The Agentic Control Plane Solutions Landscape, Q2 2026" (analyst Leslie Joseph; questionnaires April 2026; vendor announcements from 9 Jul 2026). Definition: "a common enterprise governance and control platform that sits above and across" heterogeneous agents. 33 vendors across hyperscalers, observability platforms, API providers and agent frameworks; Airia, Fiddler and WSO2 announce inclusion. Extended use cases cited: cross-runtime agent management, compliance and regulatory audit, change risk management. [S] https://www.airia.com/blog/airia-named-in-forresters-agentic-control-plane-solutions-landscape-q2-2026/
- **Latio.** 2026 AI Security Market Report, 15 Sep 2026: about 400 vendors, practitioner survey, buyer's guide. Five categories: Endpoint Agent Specialists; Broader AI Security; Platform Providers; DLP and Insider Threat; Developer Governance. Dedicated AI-security budgets rose from 8% to 37% of teams in a year; attention moved from browser tools to endpoint agents. Backslash named a leader in endpoint AI security; Lasso a platform leader. Latio's advice relayed by Lasso: test runtime detection engines yourself because many underdeliver; innovation areas are intent-based detection, MCP and skills marketplaces, agent sandboxes, granular permissions and on-premise deployment. [S] https://www.backslash.security/resources/2026-ai-security-market-latio-report ; https://www.lasso.security/blog/lasso-named-a-leader-in-latios-2026-ai-security-market-report
- **KuppingerCole** research plan [P] https://www.kuppingercole.com/researchplan: Generative AI Defense (Dec 2026; first edition Dec 2025 had Microsoft as overall leader); Enterprise Secrets Management (Dec 2026); AI Security Posture Management (Jan 2027); Non-Human Identity Management update (Feb/Mar 2027); AI Agent Visibility and Observability Platforms, "AI-VOP" (Mar 2027); AI Agent Orchestration with Governance, "AI-ORC" (Mar 2027); AI SOC (Jun 2027); Agentic Threat Detection and Response, "ATDR" (Dec 2027).
- **IDC.** No MarketScape found. IDC's Brent Ellis is on record only as a commentator on Nvidia. **Software Analyst Cyber Research:** Zenity cites being named in SACR agent-security reports; the reports were not reached.
- **Vendor framing.** CrowdStrike's president describes AIDR as a category made of a gateway, prompt security, model security and "the harnesses" (1 Sep 2026) [S]. Zenity defines AIDR as a runtime layer that reads the full step sequence and records each finding as "Detected" or "Prevented" [P].

### 6. Independent testing

- **AMTSO**: "Guidelines for Testing of Agentic Security Products" final v1.0, adopted 2 Sep 2026; "Sandbox Evaluation Framework" v1.1 adopted the same day, adding LLM-as-sample handling [P] https://www.amtso.org/documents/. No public test under the agentic guidelines was found; the first public test under the sandbox framework was by Venak Security [S].
- **SecureIQLab**: "AI Security CyberRisk Validation Methodology v1.0", 32 scenarios over input, output and retrieval layers, mapped to OWASP LLM Top 10 and MITRE ATLAS; no tool-call or MCP scenarios, no schedule, no results [P] https://secureiqlab.com/ai-security-cyberrisk-validation-methodology-v1-0-report/
- **AV-Comparatives, AV-TEST, SE Labs, CyberRatings, MITRE**: an extended search returned only vendor-authored "top N" lists (Pillar, Straiker, Palo Alto, Sweet). No results, no schedules.
- **CSA AARM**: self-serve "Conformance Agent" assessment, evidence reviewed by the technical working group; two levels (Core R1 to R6, Extended R1 to R9); per-requirement minimum tests published; eligibility conditions listed in the TL;DR [P] https://aarm.dev/conformance ; https://aarm.dev/builders

### 7. Managed detection and MSP offerings

- **Arctic Wolf Shadow AI Discovery** (14 Oct 2026): inventories "sanctioned or unknown AI tools" from existing network, identity and endpoint telemetry "without requiring additional deployments"; "soon available" to Aurora MDR customers, select customers from November 2026. No mention of agents, MCP or coding tools, and no statement that analysts triage AI activity. [P] https://arcticwolf.com/resources/press-releases/arctic-wolf-expands-the-aurora-superintelligence-platform-to-deliver-ai-visibility-broader-security-coverage-and-new-generative-assistant-skills/
- **Huntress**: nothing agent-related on the blog index in the window [P]. **Expel, Red Canary, Blackpoint, ConnectWise, Kaseya, N-able**: one search, no launches found.
- "Agentic MDR" (CrowdStrike, March 2026; Pondurance; AiStrike; Critical Start) means agents doing SOC work, not monitoring customers' agents.
- **MSP channel governance products** [S]: Portal26 multi-tenant AI governance for MSPs; Inforcer Copilot Manager (April 2026); Acronis AI governance as a resellable service; Pax8 pushing Agent 365. All are usage visibility and policy for chat and Copilot, not agent runtime.

### 8. Buyer checklists and RFP templates

- **NHI Mgmt Group, "AI Agent Security Platform RFP"** (updated 28 Oct 2026; free to read, PDF behind a newsletter sign-up; names no vendors) [P] https://nhimg.org/ai-agent-security-platform-rfp-guide. Weights: authorisation and tool control 20%; discovery 15%; identity and credentials 15%; detection and triage 15%; containment 10%; logging and evidence 10%; assurance, deployment and exit 10%; commercials 5%. Failing any mandatory item eliminates the bid.
- **Encryption Consulting** (9 Aug 2026, ungated): eleven categories: discovery, identity, credentials, authorisation, MCP controls, auditability, signing, data boundaries, revocation, compliance, integration [P] https://www.encryptionconsulting.com/agentic-ai-security-rfp/
- **LayerX** AI usage control RFP (4 Mar 2026): eight pillars, browser-centric [S]. **Akeyless** runtime security for AI agents RFP (gated), **Cato** "ready-to-use RFP for AI security", **Akto** finance RFP, **Roval AI** (80+ questions, 12 categories): located, not read.

## Matrix

### Market map, November 2026

| Vendor | Category | Mechanism | Platforms | Status | Price |
|---|---|---|---|---|---|
| CrowdStrike Falcon Guardian | AIDR suite | Kernel sensor, hooks, gateway, kill switch | Windows GA; Mac early; Linux unstated | GA Sep 2026 | not public |
| Microsoft Defender, Agent 365, Perception | Platform | Named-agent discovery, hooks, guardian agents | Windows, macOS; runtime Windows preview | Mixed GA and preview | USD 15 per user per month (Agent 365) |
| Palo Alto XDR One, Prisma AIRS | Platform | Koi hooks, registry proxy, Portkey gateway | Win, macOS, Linux | GA Oct 2026 | not public |
| Nvidia OpenShell, Sentry | Sandbox runtime | Kernel sandbox, egress check, DPU watchdog | Linux, macOS arm64, WSL 2, Kubernetes | v0.1.7; CNCF | free; Sentry needs BlueField-4 |
| Sysdig AI Defense | Kernel plus hooks | Falco rules | Linux, Kubernetes, macOS, Windows | Announced 4 Nov | not public |
| Zenity | AIDR, AI-SPM | SaaS connectors, hooks, Anthropic inference hooks | SaaS, endpoint | GA | not public |
| Noma, Operant, Runlayer, Ultra | Runtime, MCP gateway | Hooks, gateway, Kubernetes sensor | Mixed | AARM Extended | not public |
| Onyx, Rein, AIR | Runtime control, add-on firewall | Inline control plane; supply-chain vetting | not stated | Funded 2026 | not public |
| Harmonic, Pluto, Reco, Opsin | Discovery and usage | Endpoint agent, SaaS connectors | macOS, Windows, SaaS | GA | not public |
| Knostic Kirin | Coding-agent endpoint | IDE and hook integration | macOS, Windows, Linux beta | GA | USD 0 / 15 per user |
| Aembit, Keycard, Rig, Okta, Cyera Identity | Agent identity | Token broker, MCP identity gateway, endpoint identity sensor | Cloud, endpoint (Rig) | GA | Aembit USD 20 per agent |
| Pomerium, Mintive, Cloudflare | MCP access gateway | Identity-aware proxy | Any | GA | Pomerium USD 7 per user |
| Arctic Wolf | MDR add-on | Shadow AI inventory from existing telemetry | - | Select customers Nov 2026 | not public |
| Numbat, Sage, Prempti, SolonGate, uber/ADR | Open-source layers | Hooks, local gateway, detector | Mostly macOS, Linux | Active | free |

### Capability checklist a buyer will hold us to

Merged from the NHI Mgmt Group mandatory items, Encryption Consulting's categories, AARM R1 to R9 and Gartner's three areas:

1. Discover agents on endpoints, cloud, SaaS and repositories with no manual registration; record owner, model, tools, MCP servers, credentials, data sources.
2. Discover local and remote MCP servers and which agents use them; flag ownerless or dormant agents.
3. Distinct identity per agent; both user and agent preserved in every record.
4. Find long-lived static secrets with age, scope and last use; support short-lived audience-bound tokens; block token pass-through.
5. Per-agent allow and deny on tools, MCP servers and API operations, evaluated before execution (AARM R1), with five decisions (allow, deny, modify, step-up, defer).
6. Granted-versus-used permission comparison with removal recommendations.
7. Recorded human approval for high-impact actions; restrict agent egress.
8. Detect indirect prompt injection in retrieved content and tool results; baseline behaviour and alert on drift; detect out-of-sandbox execution and memory poisoning.
9. Suspend one agent, agents by tool, or agents by business unit; revoke or rotate credentials as part of containment; show blast radius.
10. Log every tool call with identity, user, parameters and decision; tamper-evident; retention of 12 months or more; incident timeline reconstruction.
11. SIEM, SOAR and ticketing integration; alerts carry identity and call chain.
12. Version, dry-run and roll back policy.
13. Vendor assurance: SOC 2 Type II or ISO 27001, pen-test summary, justified permissions, deployment modes with latency, roadmap separated from shipped, full export and deletion on exit.
14. Signed agent requests or outputs; data-class boundaries per task; evidence mapped to frameworks.

## What this changes in the earlier briefs

- **06, TL;DR:** "Knostic (USD 0 / 15 per user per month) is the only list price found" is outdated. Aembit (USD 20 per agent), Pomerium Zero (USD 7 per user, MCP included) and Agent 365 (USD 15 per user) are public.
- **06, acquisitions table:** Koi ">USD 400M reported" should read USD 231M; CalypsoAI "~USD 180M" should read USD 145.2M; CyberArk "~USD 25B" should read USD 21.1B; Portkey "(intent)" closed 29 May 2026 at USD 117M; SGNL "not confirmed" closed 20 Feb 2026 at USD 637.1M. Add Fortinet/Virtue AI, Okta/Permiso, Snowflake/Natoma, Proofpoint/Varonis (unconfirmed).
- **06, funding line:** missing Onyx, HiddenLayer, AIR, Harmonic, Reco, Pluto, Opsin, Rig, Ultra, Zenity.
- **06, "MDR: none found":** still true for agent activity; Arctic Wolf now ships an AI-tool inventory to MDR customers and MSP-channel governance tools exist.
- **06, "CSA AARM ... 123 claimed builders":** newly supported at source, and sharpened: 11 conformant, with eligibility conditions that exclude a pre-revenue project from public claims.
- **06, whitespace "hook plus kernel correlation outside a proprietary EDR":** partly closed for agents launched inside OpenShell (Apache-2.0, CNCF). It remains open for agents already running on a host.
- **06, "IDC: nothing found" and Forrester "reported second-hand":** unchanged for IDC; Forrester title, definition and three named vendors now known.
- **07, TL;DR:** "Oasis to Cyera (LOI)" is closed (3 Sep 2026, about USD 1B). The list of independent identity vendors should add Rig Security and remove nothing; Permiso is now Okta.
- **g03, open questions:** CyberArk close date is 11 Feb 2026; Oasis close date is 3 Sep 2026. Prices for Fiddler, Dreadnode and Pillar remain unknown. g03's correction that MXC is an embed-only SDK is supported: OpenShell consumes MXC as its native Windows backend.
- **g08, TL;DR:** AMTSO v1.0 date confirmed at the documents index; "no independent comparative test" still holds after a search; SecureIQLab still has methodology only.

## Implications for our design

1. **Integrate OpenShell, do not compete with it.** Ship a policy exporter and an event ingester for OpenShell sandboxes and treat "agent runs inside a governed sandbox" as a posture attribute. Our value is everything outside it: discovery of unknown agents, attribution, detection, console.
2. **Name the product in analyst terms on day one.** Publish a mapping page: Gartner guardian-agent areas, Forrester agentic control plane, Latio "Endpoint Agent Specialists", KuppingerCole AI-VOP and ATDR. KuppingerCole's AI-VOP compass (March 2027) and ATDR (December 2027) are the two we should be ready to answer questionnaires for.
3. **Build the NHI Mgmt Group RFP as an acceptance suite.** All 14 mandatory items become release gates, each with an automated test. Ship a pre-filled RFP response in the repository.
4. **Make AARM evidence machine-generated.** Implement the published per-requirement minimum tests as a CI job that emits the evidence package. State openly that the public "conformant" label needs five production customers and a certificate, and say "passes the AARM R1 to R9 test set" until then.
5. **Publish the first AMTSO-vocabulary results ourselves.** No lab has. Release a reproducible harness and scorecards using the six AMTSO outcomes, and invite a lab to rerun them.
6. **Pricing for the hosted edition: per agent or per user, public, with a real free tier.** Anchors are USD 15 to 20 per user or agent per month; undercutting matters less than being published. Self-hosted stays free and complete.
7. **Ship an MSP mode early.** Multi-tenant console, per-tenant policy packs, detection content and a triage runbook an MDR can adopt. No MDR vendor has agent-action monitoring; Arctic Wolf's inventory shows demand.
8. **Session separation is becoming a named feature** (Rig "Bifrost", CrowdStrike agent insider threat). Our agent-versus-human attribution must be demonstrable in the console, not only in the schema.
9. **Add a supply-chain vetting surface** for skills, plugins and MCP servers with fleet-wide revoke (AIR, Knostic AgentMesh at USD 850 per user show willingness to pay). An open catalogue format is unclaimed.
10. **Licence signalling matters.** Harden.Run AIF shows a GitHub repository under a proprietary licence drawing 1.9k stars; say "Apache-2.0, every component, no telemetry by default" in the first line and publish OpenSSF Scorecard and Best Practices badges as SolonGate does.

**Positioning whitespace still open for a fully open-source product:** (a) one project spanning discovery, OS sensor, hooks, gateway and console; (b) discovery of unregistered and bespoke agents, the first mandatory RFP item, which Nvidia's critics and Microsoft's named-agent list both leave open; (c) native Linux workstation and Kubernetes coverage alongside Windows and macOS; (d) multi-tenant console for MSPs and MDRs; (e) published efficacy results in AMTSO terms; (f) transparent pricing and no acquisition risk, in a year with 14 deals; (g) open detection content for agent activity; (h) an embeddable sensor for EDR vendors without a Koi or Pangea.

## Could not verify / open questions

- **Proofpoint/Varonis** (USD 6.3B): one secondary source; Varonis IR returned 403 and Proofpoint's newsroom rendered empty. Treat as unconfirmed.
- **Fortinet/Virtue AI**: Fortinet press URL guessed and 404; deal rests on the ledger and one blog.
- **Microsoft Guardian Agents**: Redmond Magazine 403; no Microsoft primary page read. Availability and price unknown.
- **Gartner, Forrester, Latio, SACR**: documents gated. Full vendor lists, Gartner's "nine features", Forrester's core use cases and Latio's category definitions not read. No Gartner Magic Quadrant or Market Guide titled for AIDR was found.
- **Onyx** (SecurityWeek 403), **Zenity USD 125M** (no date), **BlueFlag USD 28M** (no date), **Asymptote's** "open-source telemetry layer" (not identified among its repositories).
- **Huntress, Expel, Red Canary, Blackpoint, ConnectWise, Kaseya, N-able**: one combined search plus the Huntress blog index. A per-vendor check is still owed.
- **Shutdowns**: no dedicated search budget left.
- "Agentic Trust Controls standards" cited by Ultra Security: not identified.
- Search tool is US-only; European and Israeli-press-only announcements may be missed.
- Whether OpenShell's CNCF status is sandbox or incubating; whether Sentry's "open APIs" allow a third-party enforcement plane.

## Sources

- https://github.com/NVIDIA/OpenShell (README and releases, GitHub API, 2026-11-10)
- https://www.infoworld.com/article/4227894/nvidia-releases-open-agent-safety-platform-to-monitor-and-govern-agentic-ai-2.html (2026-09-28)
- https://aarm.dev/conformance ; https://aarm.dev/builders (read 2026-11-10)
- https://www.amtso.org/documents/ (AMTSO documents index; adoptions dated 2026-09-02)
- https://secureiqlab.com/ai-security-cyberrisk-validation-methodology-v1-0-report/ (2026)
- https://guptadeepak.com/agent-security/deals/ and https://guptadeepak.com/identity-giants-bought-ai-agent-security/ (2026-10-01)
- https://wetheflywheel.com/en/guides/ai-agent-security-vendors-2026/ (2026-10-21)
- https://softwarestrategiesblog.com/2026/10/26/cybersecurity-startups-to-watch-2027/ (2026-10-26)
- https://aiweekly.co/alerts/ai-security-startups-pull-855m-across-150-seed-rounds-in-2026 (2026-07-29, updated 2026-08-10)
- https://dealroom.co/news/148163/air-raises-50m-seed-to-build-a-firewall-for-ai-agents (2026-09-01)
- https://www.securityweek.com/rig-security-emerges-from-stealth-with-12m-to-tackle-agentic-ai-identity-risks/ (2026-09-29)
- https://www.securitysystemsnews.com/article/ultra-security-emerges-from-stealth-with-10m-seed-round-for-agentic-ai-platform (2026-10-23)
- https://www.knostic.ai/pricing ; https://aembit.io/pricing/ ; https://www.pomerium.com/pricing ; https://www.mintive.com/pricing ; https://www.akto.io/pricing ; https://www.okta.com/pricing/ (read 2026-11-10)
- https://www.obsidiansecurity.com/academy/agentic-security-pricing (2026-05-22, updated 2026-06-01)
- https://saaswithalex.pages.dev/posts/ai-agent-security-platforms-buyer-guide/ (2026-06-15)
- https://www.airia.com/blog/airia-named-in-forresters-agentic-control-plane-solutions-landscape-q2-2026/ (2026-07-09)
- https://www.backslash.security/resources/2026-ai-security-market-latio-report ; https://www.lasso.security/blog/lasso-named-a-leader-in-latios-2026-ai-security-market-report (2026-09-15)
- https://www.kuppingercole.com/researchplan (read 2026-11-10)
- https://zenity.io/platform/ai-detection-and-response ; https://zenity.io/company-overview/newsroom (read 2026-11-10)
- https://siliconangle.com/2026/09/01/ai-detection-response-emerges-security-category-falcon/ (2026-09-01)
- https://arcticwolf.com/resources/press-releases/ and the three releases dated 2026-10-14 linked above
- https://www.huntress.com/blog (index, read 2026-11-10)
- https://nhimg.org/ai-agent-security-platform-rfp-guide (updated 2026-10-28)
- https://www.encryptionconsulting.com/agentic-ai-security-rfp/ (2026-08-09)
- https://thehackernews.com/2026/03/new-rfp-template-for-ai-usage-control.html (2026-03-04, LayerX)
- GitHub API, 2026-11-10: hardenrun/aif, solongate/agent-security, strands-agents/box, halofyai/halofy, perplexityai/numbat, uber/ADR, gendigitalinc/sage, falcosecurity/prempti, Asymptote-Labs
- Search-result summaries only (page not opened or 403): redmondmag.com Project Perception articles (2026-07-27, 2026-10-19); Gartner document 7856181 (2026-05-14); vendor announcements of Gartner Market Guide inclusion (Astrix, Cato, Polygraf, NeuralTrust, Orchid, AGAT)

## Independent verification

_Checked 2026-11-10 by a second reviewer. 4 searches used; the rest are direct fetches, the GitHub API and SEC EDGAR. Verdicts: confirmed, corrected, refuted, unverifiable._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | OpenShell: Apache-2.0, v0.1.7 (3 Nov 2026), "part of the CNCF", kernel-level policy, Linux / macOS arm64 / WSL 2 experimental / Kubernetes, governs only its own sandboxes | confirmed | GitHub API and README match. CNCF level is **Sandbox**: TOC vote passed 26 Sep 2026; onboarding issue still open. Kernel controls are Landlock (ABI 3, Linux 6.2+) and seccomp; network goes through a policy check at the sandbox edge. On macOS and WSL 2 these run in the Docker Desktop Linux VM, not the host kernel. Kubernetes 1.29+ by Helm. Anonymous telemetry is on by default. | https://github.com/cncf/sandbox/issues/522 ; https://github.com/cncf/sandbox/issues/535 ; https://docs.nvidia.com/openshell/latest/about/support-matrix |
| 2 | AARM registry: 123 companies, 11 conformant (6 Extended, 5 Core as named); public claims need 5 production customers for 3 months and a recognised certification | confirmed | Counts and names match. Certification wording is "e.g." SOC 2 Type II, ISO 27001, FedRAMP. Two further conditions: an active community representative and a commitment to future benchmarking. Unbound Security is listed both as Core and as Aligned. Site states it is a Cloud Security Alliance project. | https://aarm.dev/builders ; https://aarm.dev/conformance ; https://aarm.dev/ |
| 3 | No independent comparative results for agent-security products; AMTSO v1.0 adopted 2 Sep 2026; SecureIQLab has only a 32-scenario methodology | corrected | AMTSO date confirmed. No test with tool-call or MCP scenarios was found, so the headline holds for agent actions. But SecureIQLab **has published comparative results**: a report commissioned by Palo Alto Networks (tests June 2026, file dated 18 Sep 2026) scoring AWS Bedrock Guardrails, GCP Model Armor, Azure AI Content Safety and Prisma AIRS AI Runtime API on OWASP LLM Top 10; prompt and response only, no agent scenarios. SecureIQLab also states "18 vendors under consideration". NSS Labs published an AI Protection Systems methodology on 28 Apr 2026 with an "agentic AI and tool invocation security" dimension; no results found. | https://secureiqlab.com/wp-content/uploads/2026/10/AI-Security-Efficacy-Benchmark-Independent-CyberRisk-Validation_Final_20260918.pdf ; https://secureiqlab.com/rsa-2026 ; https://xpr.media/?p=763198 ; https://selabs.uk/reports/ |
| 4 | Public list prices: Knostic Kirin USD 15 per user per month (free 1 to 5 users), Aembit USD 20 per agent per month (free 3 agents), Pomerium Zero USD 7 per user per month with MCP tool control | corrected | All three figures confirmed. Pomerium's USD 7 is the annual-billing rate (USD 9 monthly). Aembit's paid tier spans 10 to 500 agents. **Missed anchor:** Unbound Security (AARM Core, coding-agent governance with hooks and gateway) lists Pro at USD 20 per user per month billed annually, no user minimum, and Enterprise "starting at $28/user/month" plus 10% of LLM passthrough. Runlayer has no pricing page. | https://getunbound.ai/pricing ; https://www.pomerium.com/pricing ; https://aembit.io/pricing/ ; https://www.knostic.ai/pricing |
| 5 | NHI Mgmt Group RFP (updated 28 Oct 2026): 36 requirements, 14 mandatory, weights 20 / 15 / 15 / 15; first mandatory item is discovery without manual registration | confirmed | Date, weights and first mandatory item (AP-3.1) match. The 36 and 14 are counts of the listed items, not figures the page states; the weights are labelled illustrative. | https://nhimg.org/ai-agent-security-platform-rfp-guide |
| 6 | Ledger: 30 deals since 2024, 14 in 2026; Fortinet/Virtue AI 17 Aug; Okta/Permiso closed 26 Aug; Cyera/Oasis closed 3 Sep at about USD 1B; Koi USD 231M, Portkey USD 117M, CalypsoAI USD 145.2M, CyberArk USD 21.1B | confirmed | Prices and close dates verified in the filings themselves: Palo Alto 10-K (Koi USD 231M closed 14 Apr 2026; Portkey USD 117M closed 29 May 2026; CyberArk USD 21.1B closed 11 Feb 2026), F5 10-K (CalypsoAI USD 145.2M cash, 26 Sep 2025), Okta 10-Q (Permiso completed 26 Aug 2026). Cyera's release of 3 Sep 2026 says "valued at $1 billion". Fortinet/Virtue AI: virtueai.com now redirects to Fortinet's FortiAIGate page, so the acquisition is real; the 17 Aug date has no primary source (no Fortinet release found, no EDGAR hit). | https://www.sec.gov/Archives/edgar/data/1327567/000132756726000023/panw-20260731.htm ; https://www.sec.gov/Archives/edgar/data/1048695/000104869525000157/ffiv-20250930.htm ; https://www.sec.gov/Archives/edgar/data/1660134/000166013426000069/okta-20260731.htm ; https://www.cyera.com/press-releases/cyera-completes-acquisition-of-oasis-security |
| 7 | No MDR vendor monitors AI agent actions; Arctic Wolf Shadow AI Discovery (14 Oct 2026, select customers from November) is an inventory with no mention of agents, MCP or coding tools | corrected | Arctic Wolf part confirmed. The blanket negative is **overstated**. Anthropic's Compliance API partner list names eSentire ("24/7 managed detection and response for Claude usage") and Daylight Security. Daylight announced MDR for Claude Enterprise in May 2026: detections on audit logs covering chat, Cowork and Claude Code, signals for unauthorised MCP servers and skill or plugin behaviour, analyst triage, Miro as customer. Both rely on vendor audit logs, not an endpoint sensor or per-tool-call telemetry. Accurate wording: no MDR was found doing endpoint-level or cross-vendor monitoring of agent actions. | https://support.claude.com/en/articles/15167101 ; https://techbullion.com/?p=761005 |
| 8 | KuppingerCole compasses: AI-SPM Jan 2027; AI-VOP Mar 2027; AI-ORC Mar 2027; ATDR Dec 2027 | confirmed | All four titles and dates match the research plan read today. | https://www.kuppingercole.com/researchplan |
| 9 | Latio 2026 report (15 Sep 2026, about 400 vendors), five categories, budgets 8% to 37%; known only through vendor pages | corrected | The **full report is publicly downloadable** (51 pages, linked from Pluto's page; file created 14 Sep 2026), so it is not gated. Five category names and "8% to 37% within one year" confirmed in the text (question: "Has your team allocated budget for an AI security tool?" 37% yes, 39% no, 24% undecided). "Roughly 400" is the number of AI security start-ups on the market, not vendors assessed. 45% name endpoint agents as primary concern. Badges are "AI Security Platform Leader", "Endpoint AI Security Leader" and "Technical Innovator". Survey size not stated. | https://147429201.fs1.hubspotusercontent-eu1.net/hubfs/147429201/2026-Latio-AI-Security-Report.pdf ; https://pluto.security/latio-ai-security-report/ |
| 10 | Funding: Onyx USD 113M B (29 Jul), HiddenLayer USD 100M B (2 Sep), AIR USD 50M seed (Sep), Harmonic USD 50M B (14 Oct), Rig USD 12M seed (29 Sep), Ultra USD 10M seed (21 Oct); all secondary | confirmed | Four now have primary support: Onyx's own blog (29 Jul 2026), HiddenLayer's own release (2 Sep 2026, Delta-v Capital), Ultra's own blog (21 Oct 2026), Harmonic's About page ("2026 October, Series B Announced"; the USD 50M figure and 14 Oct remain secondary). AIR is dated 1 Sep 2026 by Dealroom; Rig 29 Sep 2026 by SecurityWeek. | https://www.onyx.security/blog ; https://www.hiddenlayer.com/news/hiddenlayer-100m-series-b-ai-security ; https://ultra.security/blog/ultra-security-raises-10m-seed-to-secure-autonomous-agents ; https://www.harmonic.security/about |
| A | Brief: Proofpoint/Varonis USD 6.3B "one secondary source; treat as unconfirmed" | corrected | Confirmed at primary source. Varonis 8-K of 15 Oct 2026 carries the joint release: all cash, about USD 6.3B, USD 49.75 per share, expected close first half of 2027; preliminary proxy filed 6 Nov 2026. | https://www.sec.gov/Archives/edgar/data/1361113/000121390026109901/ea030861001ex99-1.htm |
| B | Brief: OpenShell's CNCF level is an open question; implication 10 proposes "no telemetry by default" as a signal | corrected | Level is CNCF Sandbox (see row 1), onboarding not yet complete, code still under NVIDIA/OpenShell. OpenShell ships anonymous telemetry enabled by default (opt-out by environment variable or Helm value), so "no telemetry by default" is a real point of difference. | https://github.com/cncf/sandbox/issues/522 ; https://github.com/NVIDIA/OpenShell |
| C | Brief: open-source table (licence, created date, stars) and the mintmcp.com redirect | confirmed | GitHub API today returns the same licences, creation dates and star counts for all nine repositories (hardenrun/aif reports no recognised licence, consistent with a proprietary one). mintmcp.com returns 308 to mintive.com. Cyera's USD 400M (22 Sep 2026) is a Series G extension from Goldman Sachs, "valued at over $12 billion". | GitHub API ; https://www.cyera.com/press-releases/cyera-announces-400-million-investment-from-goldman-sachs-to-build-the-trust-layer-for-the-agentic-enterprise |

**What to change in the plan.** (1) Do not write "no MDR monitors agent activity"; say audit-log-based MDR exists for Claude (eSentire, Daylight) and the gap is endpoint-level, cross-vendor coverage. (2) Add Unbound Security at USD 20 per user per month as the closest public price comparator for coding-agent governance. (3) Cite the SecureIQLab commissioned guardrail comparison and the NSS Labs methodology when claiming "no independent test"; the gap is specifically agent-action scenarios. (4) Read the Latio report directly rather than through vendor pages. (5) Treat Proofpoint/Varonis as confirmed.
