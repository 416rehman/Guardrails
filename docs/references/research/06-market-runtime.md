# Commercial market map: runtime security for AI agents

_Researched 2026-11-09_

Evidence labels used below: **[P]** primary source read directly (vendor docs, changelog, spec, repo); **[H]** independent hands-on write-up; **[V]** vendor press or blog claim, not independently tested; **[S]** secondary or competitor-authored summary; **[K]** prior knowledge, not re-verified this session. The shared web-search budget ran out before every seed vendor was covered; the gaps are listed under "Could not verify".

## TL;DR

- The category consolidated around three enforcement mechanisms in 2026: **native agent hooks** (pre-tool allow/deny/ask), **MCP/LLM gateways**, and **endpoint config-file discovery** delivered through an existing EDR or MDM. Almost every vendor ships some mix of the three.
- **Hooks are the weak foundation everyone builds on.** They are per-agent, opt-in, fail open in most products (Pillar, Numbat, Sage say so in their own docs), and have themselves been an attack vector (CVE-2025-59536). Practitioners say "hooks are advisory, capabilities are mandatory".
- **Kernel sensor plus hook correlation** is the new high end, and only EDR-class vendors have it: CrowdStrike, Microsoft Defender, Palo Alto Cortex XDR One (19 Oct 2026), Sysdig AI Defense (4 Nov 2026). Sysdig states the reason plainly: a hook sees a command but not the script the agent wrote and then ran.
- **Proxy-based endpoint inspection is fragile.** A hands-on review of SentinelOne's Prompt Security agent found a local mitmproxy on 127.0.0.1:3636 with WinDivert redirection, trivially bypassed by unsetting an environment variable, breaking SigV4-signed Bedrock calls in redact mode, and storing full prompts in clear in the console.
- **Network gateways cannot see local stdio MCP.** Cloudflare says so in its own docs; its MCP detection needs TLS inspection and keys on the `MCP-Protocol-Version` header.
- **Runtime blocking coverage is narrow and OS-skewed**: usually Claude Code, Cursor, Codex only; Microsoft runtime protection is Windows-only preview; Jamf is macOS-only; Linux desktop is rare; WSL is uncovered by the Windows agent in at least one product.
- **Bespoke in-house agents are nearly unserved.** Discovery is signature and config-path based (18 to 50+ named agents). Harmonic and Sysdig claim detection of direct inference-endpoint traffic and local model runtimes; nobody documents a general method.
- **Platform-native control points arrived**: Anthropic inference hooks (tool-call validation, beta, Claude Enterprise only) and the Claude Code Compliance API local-session endpoints (11 Aug 2026). They remove the need for an endpoint agent, but only for that vendor's first-party surfaces.
- **Acquisition churn is the buyer's top structural risk**: at least 17 relevant deals in 2025-2026. Astrix standalone sales ended 30 Jun 2026 after Cisco; Pillar was acquired by Vanta today with runtime enforcement deferred to summer 2027.
- **Public pricing is almost non-existent.** Knostic ($0 / $15 per user per month) is the only list price found. No vendor publishes independent test results.
- **Analyst vocabulary**: Gartner "guardian agents" (Market Guide, 25 Feb 2026) inside AI TRiSM; Forrester "agent control plane"; CSA's AARM spec (R1-R9) is becoming the conformance checklist with 123 claimed builders.
- **Open-source whitespace is real**: Numbat, Prempti and Sage are Apache-2.0 hook layers with no console, no multi-tenancy, no kernel sensor correlation and no tamper protection.

## Findings

### 1. Endpoint kernel or OS sensor

- **Sysdig AI Defense** (announced 4 Nov 2026) [P]: kernel sensor plus agent-side hooks, same Falco rule engine as its cloud product; policies are readable Falco rules; actions Alert, Block, Confirm (routes to the agent's own permission prompt), Kill process. Trial on macOS and Windows; "production Linux and Kubernetes" claimed without detail. Names Claude Code, Codex, Cursor, Copilot and local runtimes (Ollama, llama.cpp, LM Studio). By default it does not collect prompts or replies and strips file edits and tool results on-device. https://webflow.sysdig.com/blog/introducing-sysdig-ai-defense
- **Palo Alto Cortex XDR 6.0 / XDR One** (19 Oct 2026) [S]: one sensor combining XDR with Agentic Endpoint Security from Koi; discovers agents, MCP servers, plugins, models, extensions; risk scores; runtime block. Koi enforcement uses synchronous hooks and an npm registry proxy on macOS, Windows, Linux, for Cursor, Claude Code, Antigravity. "Additional licenses are required for some capabilities." https://tech-insider.org/mcp-security-cortex-xdr-one-vs-microsoft-defender-ai-agents-2026/
- **Microsoft Defender for Endpoint** [S]: local agent and MCP discovery GA 29 Oct 2026 on Windows and macOS, 50+ agents; runtime protection is Windows preview; needs Defender for Endpoint P2. (Studied elsewhere; included for baseline.)
- **ThreatLocker Zero Trust AI Control** (20 Oct 2026) [V]: default-deny application ringfencing applied to agents "from outside the AI deployment", covering what agents can access, execute and connect to, including child processes. No technical documentation on agent identification. https://www.prnewswire.com/news-releases/threatlocker-launches-zero-trust-ai-control-to-give-security-teams-command-over-ai-agents-302914016.html
- **Zero Networks Least Agency Enforcement** (3-4 Aug 2026) [V]: identity-based microsegmentation at the host firewall, default deny per agent identity, just-in-time MFA on RDP, SMB, WinRM. Acts after credentials are valid. How an agent is distinguished from a human on the wire is not documented. https://www.csoonline.com/article/4204394/zero-networks-targets-ai-agent-security-gaps-with-network-level-least-agency-controls.html
- **Jamf AI Governance for Mac** (available since June 2026) [P]: inventories Claude Code, Claude Desktop, Codex on managed Macs through the management channel; enforces configuration; mobile GA targeted Q1 2027. Paired with Okta Agent SSO (Cross App Access) and Okta Agent Gateway. https://www.jamf.com/blog/okta-jamf-ai-agent-governance-identity-device/
- **Elastic** (7 Aug 2026) [P]: attribution by process ancestry (`process.parent.command_line`); open rules in `elastic/detection-rules` such as "GenAI or MCP Server Child Process Execution" and "Persistence via GenAI Tool". Elastic itself says ancestry alerts are high-volume and mostly benign, and "no single production rule owns the full sequence". https://elastic.co/security-labs/coding-agent-launchagent-tunnel-detection

### 2. In-agent hooks

Per Pillar's 2 Oct 2026 comparison [S, competitor-authored but detailed] https://www.pillar.security/blog/best-ai-coding-agent-security-tools-for-the-enterprise-2026:

- **Pillar**: MDM-deployed scanner, detects 18 agents, parses 5, blocks on 3 (Claude Code, Codex CLI, Cursor); local decisions that work offline; fails open; macOS, Linux, Windows. Acquired by Vanta 9 Nov 2026.
- **Noma** (28 Sep 2026) [V]: agentless discovery through existing EDR or MDM; registry states approved, needs review, blocked; pre- and post-tool hooks on Claude Code and Cursor; "Contextual Policies" correlate a whole session; actions monitor, alert, steer, block, mask, route to human. OS support unstated. https://www.prnewswire.com/news-releases/noma-extends-agent-security-and-governance-to-the-employee-endpoint-302890925.html
- **Zenity**: native hooks plus MCP gateway; block or modify tool calls (vendor says GA July 2026); sandbox detonation of skills.
- **Dynamo AgentWarden** [P]: CLI (build-time evaluation), SDK (custom agents where you own the loop), hooks installer (coding agents) sending "normalized events" for policy decisions; unit of management is a "use case". Explicitly does not replace IdP, DLP or MCP scanners. https://docs.dynamo.ai/docs/AgentWarden/Overview
- **Knostic Kirin** [P]: in-IDE; Claude Code CLI, Claude Desktop/Cowork, Cursor, Windsurf, VS Code Copilot; macOS and Windows, Linux beta. https://www.knostic.ai/pricing
- **Straiker**: hooks or thin client, vendor-stated latency under 300 ms. **Snyk Agent Scan**: open-source discovery only; content sent to Snyk servers.
- **Open source** [P]: **Numbat** (Perplexity, Apache-2.0, Go single binary, CEL rules with sequence rules, versioned NDJSON schema v0.5.0, forensic reconstruction from on-disk session artifacts, blocking off by default); **Prempti** (Falco sandbox project, Apache-2.0, allow/deny/ask, self-described as "not a sandbox"); **Sage** (Gen Digital, Apache-2.0, 300+ YAML rules, Windows AMSI). https://github.com/perplexityai/numbat, https://github.com/falcosecurity/prempti, https://github.com/gendigitalinc/sage
- **Platform-native**: Anthropic inference hooks, used by Zenity (15 Oct 2026) [V]: each proposed tool call goes to the organisation's security server; verdict is binary and applied to all tool calls in a response; on timeout the default is allow; Claude Enterprise only, not Bedrock, Google Cloud or API. https://zenity.io/blog/zenity-launches-universal-runtime-control-for-claude-enterprise

### 3. Endpoint network inspection

- **SentinelOne Prompt Security endpoint agent** [H] https://www.cyberengage.org/post/sentinelone-prompt-security-the-endpoint-agent: local mitmproxy, WinDivert driver, tenant root CA, PAC file for desktop apps (fails open), proxy environment variables for CLIs (fails closed), auto-repair of edited config files. Findings: bypass by opening a terminal without the variables; Protect mode breaks signed requests; Block crashes code-assistant sessions; policy cache 10 to 14 minutes; no device inventory; local admin can stop the service without alert; tamper hardening macOS only; WSL and local models uncovered; new applications cannot be added, only URLs for supported apps; agent key written in clear to `C:\Windows\Temp`.
- **Netskope One** [S]: Client AI Discovery (GA) does periodic signature-based scans on Windows and macOS; inline allow, block, DLP on MCP traffic; no hook-level control.
- **Harmonic** [P]: endpoint agent via Intune, Jamf, Kandji on macOS and Windows; claims detection of direct inference-endpoint calls and "homegrown agents"; ~200 ms classification; mechanism undocumented. https://www.harmonic.security/solutions/endpoint-ai-security
- **Zscaler** [S]: Endpoint AI Security and AI Broker (MCP and agent-to-agent, with Agent Registry) announced June 2026.

### 4. LLM or AI gateway

- **Tailscale Aperture** [P]: reverse proxy inside the tailnet; identity from tailnet device auth, so no per-user provider keys; stores full request and response bodies including tool use; guardrails can inspect, modify, block; connectors proxy MCP; subscription plans need passthrough mode; alpha, free on Personal plan. https://tailscale.com/docs/aperture/what-is-aperture
- **Palo Alto**: Portkey acquisition announced 30 Apr 2026 to become the AI Gateway for Prisma AIRS; AIRS 3.0 (23 Mar 2026) AI Agent Gateway was limited preview at launch [S].
- **JetStream Clearance** (2 Sep 2026) [V]: reasoning engine in the gateway that authorises each MCP tool call against a versioned "AI Blueprint" (models, MCP servers, tools, datasets, identities) and evaluates sequences; GA "this fall"; CrowdStrike Falcon Fund backed. https://jetstream.security/insights/jetstream-clearance-zero-trust-ai-actions/
- **Broadcom AgentMinder** [S, primary page returned 403]: identity control plane, Layer7 AI Gateway data plane for MCP, model and HTTP traffic, observability plane.
- **F5 AI Guardrails** (CalypsoAI, launched 29 Sep 2025), **Kong** Agent Gateway, **Cisco AI Defense** (MCP Server Catalog, runtime MCP inspection, AgentSec SDK modules) [S].

### 5. MCP gateway or proxy

- **Cloudflare** [P] https://blog.cloudflare.com/mcp-security-updates (14 Aug 2026) and https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/: MCP server portals GA 24 Sep 2026; Gateway selector `experimental.is_mcp`; rule pattern `experimental.is_mcp == true and not traffic.onramp in ("mcp_portal")` to force portal-only access. Stated limits: TLS inspection required, stdio servers invisible, private MCP servers not yet reachable through portals, tool-level control "needs client-side hooks or server-side middleware".
- **Runlayer** (ToolGuard; hosted or self-hosted on ECS or Kubernetes), **Operant MCP Gateway**, **Backslash** endpoint MCP proxy (Linux, macOS, Windows), **Aurascape**, **Harmonic** local MCP gateway, **Docker MCP Gateway** (open source, container isolation, single-developer scope) [S].
- MCP reputation catalogues are now standard: Prompt Security 13,000+, Pillar 23,000+ servers [S].

### 6. Browser

Akamai bought LayerX (~$205M, completed July 2026, now Akamai Workforce Protector); Zscaler bought SquareX (early 2026); Harmonic, Prompt Security and Jamf ship or plan extensions. Pillar notes none of the usage-layer tools block an agent's tool calls on the machine [S].

### 7. SaaS and cloud posture (AI-SPM), identity

Zenity, Noma, Wiz, Orca for posture. Identity consolidated fast: Cisco/Astrix, SailPoint/Entro, CrowdStrike/SGNL, Palo Alto/CyberArk, Silverfort/Fabrix. 1Password for Agents (22 Oct 2026) lets agents sign in without seeing the credential with per-request approval [S]. Token Security and Geordie were RSAC finalists.

### 8. Cloud workload and Kubernetes runtime

Operant (3D Runtime Defense started in Kubernetes; Endpoint Protector 4 May 2026 for macOS, Windows, Linux, with a private mode keeping traces in the customer environment) https://www.helpnetsecurity.com/2026/05/04/operant-ai-endpoint-protector-secures-ai-agents-and-mcp-tools/; Sysdig (Falco, eBPF); Upwind (eBPF, $300M at $3.8B in Sep 2026 [S]); Wiz Sensor.

### 9. Code and CI

Pillar (hidden-Unicode rules-file and MCP config scanning in PRs), Snyk, Backslash, Crash Override, ZeroPath.

### 10. Managed detection

No MDR vendor launch for agent activity was found. This looks like a real gap rather than a search miss, but confidence is low.

### Analyst framing

- **Gartner Market Guide for Guardian Agents**, 25 Feb 2026 (Litan et al.) [S]: three capability areas (visibility and traceability; continuous assurance; runtime inspection and enforcement) and six delivery approaches (standalone oversight, AI/MCP gateways, embedded runtime modules, orchestration extensions, hybrid edge-cloud, coordination mechanisms). Gartner warns against over-centralising in one choke point and says standard interfaces are lacking. Deployments are "mainly prototypes or pilots". https://thehackernews.com/2026/03/5-learnings-from-first-ever-gartner.html
- **Gartner** "Emerging Tech: The Future of AI Security Is in Securing Agent Actions, Not Prompts" (20 Feb 2026) [S].
- **Forrester**: "agent control plane"; a Q2 2026 landscape of 33 vendors is reported second-hand [S].
- **CSA AARM v1.0** (Feb 2026, CC BY 4.0, arXiv:2602.09433) [P]: R1 pre-execution interception, R2 context accumulation, R3 intent-aligned policy, R4 five decisions (ALLOW, DENY, MODIFY, STEP_UP, DEFER), R5 tamper-evident receipts, R6 identity binding; extended R7 drift, R8 telemetry export, R9 least privilege. Four architectures: protocol gateway, SDK, kernel eBPF, vendor integration. https://aarm.dev/spec
- **IDC**: nothing found.

### Buyer complaints and unmet needs

- Hooks are not access control: nothing forces an agent to run with hooks; a credential blocked in one harness works in another [S, Aembit, 5 Nov 2026] https://securityboulevard.com/2026/11/agent-hooks-are-a-developer-tool-not-access-control/
- "There is no centralized console to monitor endpoint agents" across config, identity and runtime; EDR gives evidence but cannot tie activity to owner, intent or credentials [S, Token Security, Aug 2026] https://thehackernews.com/2026/08/securing-claude-code-new-compliance-api.html
- Hacker News (2026, via Algolia API) [P]: gateway filtering covers MCP tools but not the harness's built-in tools; MCP auth is the spec's weak point and gateway token-exchange roles are undefined; customers do not know which AI apps and MCP servers employees use; gateways are bloating; most gateway comments are vendor self-promotion.
- Developers move to personal accounts when controls bite, removing visibility [S].

### Acquisitions 2025-2026

| Date | Acquirer / target | Price | Evidence |
|---|---|---|---|
| 2025 | Palo Alto / Protect AI | ~$500M+ reported | S |
| Jun 2025 | Snyk / Invariant Labs | undisclosed | S, K |
| Sep 2025 | SentinelOne / Prompt Security | ~$159M (one source) | S |
| Sep 2025 | Check Point / Lakera | ~$202M (one source) | S |
| Sep 2025 | Cato / Aim Security; CrowdStrike / Pangea | undisclosed | S |
| Sep 2025 | F5 / CalypsoAI | ~$180M | S (one source misdates to Jan 2026) |
| Feb 2026 | Palo Alto / CyberArk | ~$25B | S |
| Feb 2026 | CrowdStrike / SGNL | not confirmed here | S |
| Early 2026 | Zscaler / SquareX; Proofpoint / Acuvity | undisclosed | S |
| 14 Apr 2026 | Palo Alto / Koi | >$400M reported | S |
| 23 Apr 2026 | Cyera / Ryft | undisclosed | S |
| 28 Apr 2026 | Silverfort / Fabrix | undisclosed | S |
| 30 Apr 2026 | Palo Alto / Portkey (intent) | undisclosed | S |
| 29 Jun 2026 | Cisco / Astrix | ~$400M reported | S |
| 29 Jun 2026 | SailPoint / Entro | ~$122.6M cash (one source) | S |
| Jul 2026 | Akamai / LayerX | ~$205M | S |
| 9 Nov 2026 | Vanta / Pillar Security | undisclosed | V |
| Pending | OpenAI / Promptfoo; Palo Alto / Clutch (talks only, ~$500M) | - | S |

Funding: Geordie AI $30M Series A (28 May 2026, RSAC 2026 Innovation Sandbox winner); Rein Security $25M A (8 Oct 2026); WitnessAI $58M B (Jan 2026); Runlayer $11M seed (Nov 2025); 7AI $130M A (Dec 2025); Noma $100M B (Jul 2025). Black Hat USA 2026 Startup Spotlight: Opnova won; Secure Agentics ("Adrian") honourable mention.

## Matrix

| Control point | Notable vendors | Enforces where | Standout | Known limit |
|---|---|---|---|---|
| Kernel / OS sensor | CrowdStrike, Microsoft, PANW XDR One, Sysdig AI Defense, ThreatLocker | Kernel sensor, app control, process kill | Sees agent-written scripts; survives hook removal | Windows-first runtime; licensing opaque; no bespoke-agent method |
| In-agent hooks | Pillar, Noma, Zenity, Koi, Straiker, Dynamo, Knostic; OSS Numbat, Prempti, Sage | PreToolUse-style callbacks | Rich semantics, agent gets a reason and adapts | Fail open, opt-in, 3 to 5 agents, tamperable |
| Platform-native | Anthropic inference hooks, Compliance API (via Zenity, Token) | Model vendor's servers | No endpoint software | One vendor, enterprise plan only, batch-level binary verdict, default allow on timeout |
| Endpoint network | Prompt Security, Netskope, Harmonic, Zscaler | Local proxy, PAC, driver | Works for hookless apps | Bypass, breaks signed requests, TLS MITM, prompt hoarding |
| LLM gateway | Aperture, Portkey/PANW, Kong, F5, Cisco, JetStream, Broadcom | Reverse proxy | Central keys, cost, identity | Subscription/OAuth plans, bypass, bottleneck |
| MCP gateway | Cloudflare, Runlayer, Operant, Backslash, Aurascape, Docker | Remote or local proxy | Tool-level RBAC, registry | Blind to stdio and built-in tools |
| Network segmentation | Zero Networks | Host firewall | Works with valid credentials, any agent | Agent identification undocumented |
| Browser | Akamai/LayerX, Zscaler/SquareX, Harmonic, Jamf | Extension | Shadow AI, personal accounts | No tool-call control |
| Identity | 1Password, Okta, Cisco/Astrix, SailPoint/Entro, Token, Aembit | IdP, broker, vault | Revocation as kill switch | Does not see actions |
| AI-SPM / cloud | Zenity, Noma, Wiz, Orca, Geordie | API connectors | SaaS agent inventory | Posture, not prevention |
| K8s runtime | Operant, Sysdig, Upwind, Wiz | eBPF sensor | Custom agents in production | Endpoint parity weak |
| MDR | none found | - | - | Gap |

## Weak points, gaps and risks

- **Fail-open is the norm** for hooks and PAC proxies; only CLI proxy variables failed closed in the hands-on test.
- **Attribution is unsolved**: process ancestry is noisy (Elastic); proxy tools attribute by an install-time `USER_EMAIL` value; nobody documents agent-versus-human separation under shared credentials.
- **Sensitive-data gravity**: products that log full prompts create a new breach target readable by every tenant admin.
- **Coverage is a named-product list**; custom URLs can be added for supported apps but not new apps.
- **Vendor instability**: the most detailed endpoint comparator (Pillar) and the leading NHI vendor (Astrix) both changed hands within five months.
- **No independent efficacy testing** and no public price lists; multi-tenant MSP and air-gapped deployment are rarely mentioned (Operant private mode and Runlayer self-host are exceptions).

## Implications for our design

1. **Layer, never rely on hooks alone.** Ship hooks for semantics, an OS sensor for ground truth, and correlate the two by process tree and time. Treat a hook that stops reporting while the agent process keeps acting as a detection.
2. **Make failure mode an explicit per-policy setting** (fail open, fail closed, fail to ask) and report hook health centrally; the market's silent fail-open is a differentiator to attack.
3. **Adopt AARM R1-R9 as the conformance target** and its five decisions (ALLOW, DENY, MODIFY, STEP_UP, DEFER) as the verdict enum; publish a self-assessment.
4. **Privacy by default like Sysdig**: decide locally, export metadata and findings, make content capture opt-in with on-device redaction.
5. **Reuse open formats**: evaluate Numbat's NDJSON schema and CEL sequence rules and Falco rule syntax before inventing a rule language; ingest Elastic's open rules as detection content.
6. **Generic agent discovery**: combine config-path signatures with behavioural signals (process that talks to an inference endpoint or local model runtime and spawns shells or writes files). This is the unserved bespoke-agent problem.
7. **Local MCP proxy for stdio**, since network gateways cannot see it, plus coverage of harness built-in tools through hooks.
8. **First-class Linux and WSL**, signed binaries (Smart App Control blocked an unsigned component in the hands-on test), tamper protection on all three OSes, and a device inventory that shows missing or stopped agents.
9. **Integrate platform-native checkpoints** (Anthropic inference hooks, Compliance API, managed settings, OpenTelemetry) as additional sensors rather than competing with them.
10. **Embeddable core**: a headless sensor and policy engine with a stable event schema is what EDR vendors lacking Koi or Pangea equivalents would license or embed.

## Ideas worth stealing and whitespace

- **Steal**: Noma's three-state registry (approved, needs review, blocked) with auto-enrolment; Sysdig's Confirm action that defers to the agent's own permission prompt; JetStream's versioned Blueprint as the unit of authorisation; Numbat's forensic reconstruction of sessions that predate install; Cloudflare's observe-then-enforce selector; Zero Networks' just-in-time MFA on lateral protocols; Pillar's offline local decisions; Koi's package-registry proxy.
- **Whitespace**: an open-source central console with multi-tenancy for MSPs; hook plus kernel correlation outside a proprietary EDR; bespoke-agent discovery; agent-versus-human attribution under shared credentials; managed detection content for agents; published, reproducible efficacy and bypass tests; transparent pricing; acquisition-proof licensing; air-gapped operation.

## Could not verify / open questions

- Search budget exhausted before covering: Wiz, Orca, Datadog, HiddenLayer, Mindgard, Lumia, Unbound, WitnessAI, Aurascape (beyond competitor pages), MCP Manager, Golf, 7AI, Trend Micro, Sophos, Fortinet, Check Point Harmony, Akamai and Docker docs, Kong release dates (sources conflict), Zscaler/SPLX.
- Blocked: Broadcom AgentMinder press release (403); Dynamo AgentWarden runtime integration page (403); Operant pricing (404); Cisco what's-new page (socket hang-up).
- Not read at source: Gartner and Forrester documents (gated); Microsoft Execution Containers (7 Oct 2026); Claude Code 2.1.317 fail-closed hook behaviour (3 Nov 2026, third-party report only).
- Open: how Zero Networks and ThreatLocker identify an agent; whether Sysdig's sensor supports Linux desktops; AARM repository licence (spec page says CC BY 4.0; GitHub repo shows none).

## Sources

- https://www.pillar.security/blog/best-ai-coding-agent-security-tools-for-the-enterprise-2026 - Pillar comparison, 2 Oct 2026
- https://www.cyberengage.org/post/sentinelone-prompt-security-the-endpoint-agent - hands-on, Nov 2026
- https://webflow.sysdig.com/blog/introducing-sysdig-ai-defense - 4 Nov 2026
- https://blog.cloudflare.com/mcp-security-updates - 14 Aug 2026
- https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/ - 24 Sep 2026
- https://tailscale.com/docs/aperture/what-is-aperture - Tailscale docs
- https://docs.dynamo.ai/docs/AgentWarden/Overview - Dynamo docs
- https://zenity.io/blog/zenity-launches-universal-runtime-control-for-claude-enterprise - 15 Oct 2026
- https://www.prnewswire.com/news-releases/noma-extends-agent-security-and-governance-to-the-employee-endpoint-302890925.html - 28 Sep 2026
- https://jetstream.security/insights/jetstream-clearance-zero-trust-ai-actions/ - 2 Sep 2026
- https://www.knostic.ai/pricing - Knostic pricing
- https://www.jamf.com/blog/okta-jamf-ai-agent-governance-identity-device/ - Jamf and Okta
- https://www.csoonline.com/article/4204394/zero-networks-targets-ai-agent-security-gaps-with-network-level-least-agency-controls.html - Aug 2026
- https://www.prnewswire.com/news-releases/threatlocker-launches-zero-trust-ai-control-to-give-security-teams-command-over-ai-agents-302914016.html - 20 Oct 2026
- https://www.harmonic.security/solutions/endpoint-ai-security - Harmonic
- https://www.helpnetsecurity.com/2026/05/04/operant-ai-endpoint-protector-secures-ai-agents-and-mcp-tools/ - 4 May 2026
- https://elastic.co/security-labs/coding-agent-launchagent-tunnel-detection - 7 Aug 2026
- https://aarm.dev/spec - AARM v1.0, Feb 2026
- https://github.com/perplexityai/numbat, https://github.com/falcosecurity/prempti, https://github.com/gendigitalinc/sage - repos, read 9 Nov 2026
- https://thehackernews.com/2026/03/5-learnings-from-first-ever-gartner.html - 24 Mar 2026
- https://thehackernews.com/2026/08/securing-claude-code-new-compliance-api.html - Aug 2026
- https://securityboulevard.com/2026/11/agent-hooks-are-a-developer-tool-not-access-control/ - 5 Nov 2026
- https://tech-insider.org/mcp-security-cortex-xdr-one-vs-microsoft-defender-ai-agents-2026/ - Nov 2026
- https://zeltser.com/media/rsac-2026-sandbox - RSAC 2026 finalists
- https://www.infosecurity-magazine.com/news-features/cybersecurity-ma-round-up-april-26/ - April 2026 M&A
- https://pipelab.org/blog/ai-agent-security-acquisition-wave-2026/ - 12 Apr 2026
- https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/ - 28 Mar 2026
- https://securityopswire.com/ai-agent-security-companies-market-map/ - 3 Sep 2026
- https://www.vanta.com/resources/vanta-acquires-pillar - 9 Nov 2026
- https://fortune.com/2026/05/28/geordie-security-governance-ai-agents/ - 28 May 2026
- https://hn.algolia.com/api/v1/search_by_date?query=%22MCP%20gateway%22&tags=comment - Hacker News comments, 2026

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. The shared web-search budget was already exhausted, so every check below was done by fetching primary pages directly or reading repositories with the `gh` CLI. Where no primary page could be reached, the verdict says so._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Hooks fail open in leading products (Pillar, Numbat, Sage); runtime blocking typically limited to Claude Code, Cursor, Codex CLI | corrected | Numbat and Sage say fail-open in their own docs. Pillar's docs are behind an access code, so only Pillar's blog supports that part. Fail-open is not universal: Prempti's Claude Code hook is fail-closed by default (`PREMPTI_FAIL_OPEN=0`), and Numbat notes Copilot CLI and OpenClaw can fail closed at the host. The three-agent limit is Pillar's own. Numbat can enforce on a dozen-plus hosts (Codex, Cursor, Kiro, Goose, Antigravity, Amp and others; OpenCode is monitor-only), Sage covers Claude Code, Cursor/VS Code/Copilot CLI, OpenClaw and OpenCode, and Microsoft covers Claude Code, Copilot CLI and app, Claude Desktop and two VS Code extensions. | https://github.com/perplexityai/numbat/blob/main/docs/enforcement.md, https://github.com/perplexityai/numbat/blob/main/docs/agent-coverage.md, https://github.com/gendigitalinc/sage/blob/main/docs/decision-pipeline.md, https://github.com/falcosecurity/prempti/blob/main/hooks/claude-code/README.md |
| 2 | SentinelOne Prompt Security agent: mitmproxy on 127.0.0.1:3636, WinDivert, PAC fails open, proxy variables fail closed, bypass by unsetting variable, breaks signed Bedrock requests, full prompts in clear | unverifiable | The brief reports the article accurately, but no second source was reachable (no public Prompt Security docs found). Caveats in the article itself: Windows only was tested; the author says a colleague saw a direct fallback for CLIs and the fail-closed result needs retesting; the Bedrock break was in Protect (redaction) mode and Block was not tested against Bedrock; clear-text prompt storage is with the default Detect rule that has "log all interactions" on. | https://www.cyberengage.org/post/sentinelone-prompt-security-the-endpoint-agent |
| 3 | Cloudflare Gateway detects MCP by the `MCP-Protocol-Version` header (`experimental.is_mcp`); blind to stdio; tool-level control needs hooks or middleware | corrected | The selector exists as "Is MCP" (Beta), `experimental.is_mcp == true`. The docs say detection uses "protocol-specific headers and payload characteristics", and the blog says the header is a strong indicator whose absence proves nothing, so it is not header-only. TLS decryption is required and stdio, off-network and Do Not Inspect traffic are invisible: confirmed. Tool-level control is partly available without hooks: MCP portals let admins turn individual tools and prompts off (with a `default_disabled` allowlist pattern) for remote HTTP servers behind the portal. Per-call and argument-level authorization is what needs hooks or middleware. The docs name the traffic-source field `net.onramp.type`, while the blog rule uses `traffic.onramp`; check the field name before copying the rule. | https://developers.cloudflare.com/cloudflare-one/traffic-policies/http-policies/, https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/ |
| 4 | Sysdig AI Defense (4 Nov 2026): kernel sensor plus hooks, Falco rules, Alert/Block/Confirm/Kill process, no prompt or reply collection by default, trial on macOS and Windows | confirmed | Matches the post on Sysdig's canonical domain. It is still a vendor blog: no product documentation page was found, and Linux endpoints are not in the trial. | https://www.sysdig.com/blog/introducing-sysdig-ai-defense |
| 5 | Anthropic inference hooks tool-call validation: Claude Enterprise only, not Bedrock, Google Cloud or API; binary verdict for all tool calls in a response; allow on timeout by default | confirmed | Anthropic's docs confirm each point: allow or deny only (no rewriting), one verdict covers all tool calls in a response, defaults of "Allow the request" and a 5,000 ms timeout. Design-relevant details the brief omits: failure handling can be set to "Block the request" (fail closed), there is a circuit breaker and a shadow mode, "Validate tool calls" is on by default in a new configuration, one hook covers Claude Code, Cowork, claude.ai, Claude in Chrome and Claude for Microsoft 365, and some built-in claude.ai tools are left out of `tool_call` events. The docs pages read carry no "beta" label; that wording is Zenity's. | https://platform.claude.com/docs/en/manage-claude/inference-hooks, https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration |
| 6 | CSA AARM v1.0 (Feb 2026, CC BY 4.0): six mandatory requirements, five decisions, three extended requirements | confirmed | Spec page: R1 to R6 are MUST, R7 to R9 are SHOULD, exactly one of ALLOW, DENY, MODIFY, STEP_UP, DEFER per action. R7 is titled "Semantic distance tracking". arXiv 2602.09433 was submitted 10 Feb 2026 by a single author (Herman Errico) under CC BY 4.0; aarm.dev labels it a Cloud Security Alliance project and says v2.0 is planned. The GitHub repo `aarm-dev/aarm` redirects to `herman-prod/aarm` (website code, no licence file). | https://arxiv.org/abs/2602.09433, https://aarm.dev/ |
| 7 | Open-source layers are hook-based, Apache-2.0, no central console: Numbat (Go, CEL, NDJSON v0.5.0, blocking off by default), Prempti (Falco sandbox, "not a sandbox") | confirmed | Repo metadata and READMEs match. Numbat writes records to stdout, a local file or an optional HTTP sink; there is no console. Prempti is Rust, supports Claude Code on Linux, macOS and Windows with Codex experimental, and its README says hook-level interception "should not be treated as a hard boundary". Numbat's repo was created 24 Jul 2026, so it is young. | https://github.com/perplexityai/numbat, https://github.com/falcosecurity/prempti |
| 8 | Microsoft Defender local agent and MCP discovery GA 29 Oct 2026 on Windows and macOS for 50+ agents, runtime protection Windows-only preview; Palo Alto Cortex XDR One with Koi-based Agentic Endpoint Security on 19 Oct 2026 | confirmed | Microsoft Learn lists the discovery GA under October 2026 (page dated 30 Oct; the exact day is not shown). The support matrix lists about 60 agent names per OS. Discovery in WSL and of VS Code extensions on macOS is still preview. Runtime protection is "Windows (preview)" only and works through agent hooks plus network inspection, which does not cover certificate pinning or HTTP/3. For Palo Alto, trade press dated 20 and 23 Oct 2026 corroborates the launch and says it is "available immediately"; the exact 19 Oct date and the "XDR 6.0" label were not confirmed at a primary source. | https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint, https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix, https://www.sdxcentral.com/news/palo-alto-networks-bolsters-ai-security-for-the-endpoint/ |
| 9 | Gartner Market Guide for Guardian Agents (25 Feb 2026): three capability areas, six delivery approaches, warns against a single choke point, deployments mainly prototypes or pilots | corrected | The three areas, six approaches and the "mainly prototypes or pilots" line are attributed to Gartner in the summary. The choke-point warning (and the gateway "bottleneck and a false comfort" line) is commentary by the article's contributor, which promotes Orchid Security, not a Gartner statement. The Gartner document itself returned 403 and was not read. | https://thehackernews.com/2026/03/5-learnings-from-first-ever-gartner.html |
| 10 | Vanta agreed to acquire Pillar on 9 Nov 2026, runtime enforcement summer 2027; Cisco closed Astrix 29 Jun 2026; Palo Alto closed Koi 14 Apr 2026 | confirmed | Vanta "signed a definitive agreement"; the deal is not closed, so the TL;DR and acquisitions table should say "agreed to acquire", not "acquired". Vanta's roadmap: inventory and runtime monitoring January 2027, red teaming spring 2027, runtime enforcement summer 2027. Palo Alto's press release dated 14 Apr 2026 confirms Koi completion. For Astrix, Cisco's list gives only the 4 May 2026 announcement date and Astrix's site says it is part of Cisco with standalone new-licence sales ended effective 30 Jun 2026; the exact 29 Jun closing date was not found at a primary source. | https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-koi-to-secure-the-agentic-endpoint, https://astrix.security/, https://www.cisco.com/c/en/us/about/corporate-strategy-office/acquisitions/acquisitions-list-years.html |
| A | Brief: "Fail-open is the norm" and silent fail-open is "a differentiator to attack"; Claude Code 2.1.317 fail-closed hooks known only from a third-party report | corrected | Fail-closed options already exist. Claude Code added `onFailure: "block"` for command and HTTP hooks in 2.1.295 and for Agent SDK hook callbacks in 2.1.317 (opt-in, not a default change). Prempti is fail-closed by default. Anthropic inference hooks have a "Block the request" setting. A per-policy failure mode is table stakes, not a differentiator; central hook-health reporting still is. | https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md, https://github.com/falcosecurity/prempti/blob/main/hooks/claude-code/README.md |
| B | Brief: Sage is "Apache-2.0, 300+ YAML rules" | corrected | Only the source code is Apache-2.0. The threat rules in `threats/` are under Detection Rule License 1.1, which matters if the rules are to be reused. Sage's URL reputation check is cloud-based, so it is not fully local. | https://github.com/gendigitalinc/sage |
| C | Brief TL;DR: Microsoft Defender has "kernel sensor plus hook correlation" | corrected | Microsoft's documentation describes runtime protection as two inline inspection methods, vendor hook interfaces and network inspection, each "a fast, inline check rather than continuous monitoring of the agent process". It does not document kernel-sensor and hook correlation for agents. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview |
