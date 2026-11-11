# Industry frameworks and agent protocols: what they ask of an AIDR platform

_Researched 2026-11-09_

Method note: the session's web-search budget was exhausted before this task started, so everything below comes from direct fetches of primary pages and from the GitHub API (spec repos, changelogs, release notes). Claims marked **[V]** were read in the primary source today; **[R]** are recalled from pre-June-2026 knowledge and not re-verified; **[I]** are my inference.

## TL;DR

- **MCP changed shape on 2026-07-28.** The current spec is stateless: no `initialize` handshake, no `Mcp-Session-Id`, identity and capabilities travel in `_meta` on every request, `server/discover` is mandatory, and HTTP POSTs must carry `Mcp-Method` / `Mcp-Name` headers. Roots, Sampling, Logging and Dynamic Client Registration are deprecated; Tasks moved to an extension. Any gateway built against 2025-11-25 session semantics is already legacy. [V]
- **MCP has no agent identity yet.** The August 2026 roadmap says authorization "is built around a person approving access in a browser" and makes agent identity a priority: DPoP, Workload Identity Federation, ID-JAG and token exchange, with IETF OAuth and WIMSE. [V]
- **Enterprise-Managed Authorization (ID-JAG) is the stable enterprise control point**: the IdP decides which MCP servers a user's client may reach. Extension id `io.modelcontextprotocol/enterprise-managed-authorization`. The underlying IETF draft is still an I-D (rev 06, 2026-10-31). [V]
- **OWASP published a wire protocol for exactly our product: the Agent Control Standard (ACS) v0.1.0** (2026-09-01). JSON-RPC hooks from an "Observed Agent" to a "Guardian Agent", five dispositions (`allow`, `deny`, `modify`, `ask`, `defer`), OTel + OCSF 1.9.0 trace mappings, and an AgBOM inventory. Reference implementation wraps Microsoft's Agent Governance Toolkit with Claude Code and OpenCode shims. Rust, Go, Python and Codex ports are unclaimed. [V]
- **OpenID AuthZEN is the PDP interface to adopt.** Authorization API 1.0 went final in January 2026; June 2026 working-group drafts add COAZ (a CEL-based mapping from MCP tool calls to AuthZEN requests) and AARP (asynchronous approval). [V]
- **Every identity body agrees: an agent is a workload with its own identity, acting under delegated, attenuated, short-lived, audience-bound authority, with the human principal preserved in the token.** None of them specify how to tell agent from human when both use the same local credential; only endpoint vendors (BeyondTrust) do that, with process classifiers. [V]
- **NIST has produced process, not controls.** AI Agent Standards Initiative (2026-02-17), NCCoE concept paper (2026-02-05, comments closed 2026-04-02), Cyber AI Profile IR 8596 still a preliminary draft, COSAiS agent overlays not yet published. No normative agent guidance exists to comply with. [V]
- **NIST renamed its AI work on 2026-10-20**: COSAiS is now "COSIS" (Control Overlays for Super Intelligence Systems) following a 2026-09-29 Executive Order directing agencies to say "Super Intelligence / SI" instead of "AI". Compliance mappings must key on stable document IDs, not titles. [V]
- **A2A is v1.0.1 and now sits in the Agentic AI Foundation alongside MCP.** Agent Card signing is optional (JWS over JCS-canonicalised JSON); identity is delegated to TLS and OAuth; implicit and password flows were removed. [V]
- **MITRE ATLAS v2026.10 (2026-10-28)** has 16 tactics, 129 techniques, 92 sub-techniques, 44 mitigations and about 40 agent-specific entries. SAFE-MCP has been renamed **SAF-MCP** (Secure Agentic Framework, an OpenSSF SIG) with permanent technique IDs and a detection coverage registry. [V]
- **Microsoft is the de facto enterprise reference**: Agent 365 GA 2026-05-01, per-user licence, E7 or add-on; Entra Agent ID token claims (`xms_act_fct=11`, `xms_sub_fct=13`) are the only shipping, documented way to distinguish an agent from a human in a token. [V]

## Findings

### 1. Model Context Protocol

Revisions: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, **2026-07-28** (RC 2026-05-29) [V, [releases](https://github.com/modelcontextprotocol/modelcontextprotocol/releases)].

**2025-11-25** added OIDC Discovery for AS discovery, incremental scope consent via `WWW-Authenticate`, URL-mode elicitation (SEP-1036), sampling with tools, Client ID Metadata Documents (CIMD, SEP-991), experimental Tasks (SEP-1686), HTTP 403 on invalid `Origin` [V, [changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)].

**2026-07-28** [V, [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)]:
- Stateless and sessionless (SEP-2575, SEP-2567). Per-request `_meta` keys `io.modelcontextprotocol/protocolVersion`, `clientCapabilities`, `clientInfo`; servers return `serverInfo`. Cross-call state uses server-minted handles passed as tool arguments (a new "State Handle Hijacking" entry appears in security best practices).
- `server/discover` MUST be implemented. `subscriptions/listen` replaces the GET stream and `resources/subscribe`.
- Multi Round-Trip Requests (SEP-2322): elicitation, sampling and roots are no longer server-initiated requests; the server returns `resultType: "input_required"` with `inputRequests` and the client retries. `notifications/elicitation/complete` and `elicitationId` are removed.
- Required headers `Mcp-Method`, `Mcp-Name` (SEP-2243); `x-mcp-header` lifts tool parameters into headers. This makes L7 policy possible without body parsing.
- OTel trace context in `_meta` (`traceparent`, `tracestate`, `baggage`) (SEP-414).
- `ttlMs` and `cacheScope` on list results; deterministic tool order.
- Auth: clients MUST validate `iss` when present (RFC 9207); client credentials MUST be keyed by issuer and never reused across authorization servers (SEP-2352); DCR (RFC 7591) deprecated in favour of CIMD.
- Deprecated with a 12-month minimum window: Roots, Sampling, Logging, HTTP+SSE.

**Authorization baseline** [V, [spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)]: OAuth 2.1 draft-13, RFC 8414, RFC 9728, RFC 8707, RFC 9207, CIMD. Servers MUST validate audience; clients MUST NOT send a token to any server other than the one whose AS issued it; token passthrough is forbidden.

**Extensions** (SEP-2133): Enterprise-Managed Authorization (stable), OAuth client credentials (SEP-1046), Tasks (SEP-2663), Apps (SEP-1865), Skills (SEP-2640), Server Cards (SEP-2127, Final: pre-connection metadata at `<url>/server-card`, linked from an "AI Catalog") [V].

**Local servers** [V, [guide](https://modelcontextprotocol.io/docs/tutorials/security/local-server-security)]: "the client and a stdio server share one trust domain"; isolation is the host's and operator's job. The guide tells administrators to allowlist pinned servers, set a default runtime posture, inventory client config files with endpoint tooling, log server/tool/time, and plan fleet incident response. Tool-definition pinning is recommended but "the protocol does not require this". SEP-1024 (Final) requires consent and full command display before one-click local installs.

**Registry**: still preview; `server.json`, DNS-verified namespaces, metadata only [V, [docs](https://modelcontextprotocol.io/registry/about)].

### 2. A2A, ACP, AG-UI

- **A2A v1.0.0** (2026-03-12), **v1.0.1** (2026-05-26). TLS required in production; `securitySchemes` in the Agent Card (API key, HTTP, OAuth2 with authorization-code/client-credentials/device-code, OIDC, mTLS). Card signing MAY use JWS (RFC 7515) over JCS (RFC 8785). `TASK_STATE_AUTH_REQUIRED` is the in-task step-up hook. Authorization is "agent-defined", "not prescribed by the protocol". Roadmap (2026-09-15) has no identity item [V, [spec](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)].
- **Agent Client Protocol** (editor to coding agent): Apache-2.0, release v1.16.0 and schema v2.0.0-alpha.14 on 2026-11-09, with RFDs for an agent registry, auth methods and MCP-over-ACP [V, [repo](https://github.com/agentclientprotocol/agent-client-protocol)]. It carries file-system, terminal and permission-request traffic, so it is a second interception point for coding agents [I].
- **AG-UI**: MIT, 17k stars, agent-to-frontend event stream [V]. Security model not reviewed.

### 3. OpenID Foundation and IETF

- **AIIM Community Group**: whitepaper "Identity Management for Agentic AI" (2025-10-07) says existing OAuth/OIDC cover bounded agents but not recursive delegation, cross-domain trust or scale; enterprises should treat agents as first-class IAM citizens with lifecycle and accountability [V, [post](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/)]. New paper 2026-10-12, "A Protocol-Agnostic Threat Classification for Cross-Boundary AI Agent Authorization": six threat classes (which agent is acting; cross-domain key trust; wrong resource after crossing; scope broadening in translation; access outliving the task; credential capture and replay), root cause "treating an agent as a human user", and a call to "invest in authorization-time controls rather than relying on detection after the fact" [V, [post](https://openid.net/oidf-publishes-threat-model-for-cross-boundary-ai-agents/)]. Protocol design is explicitly out of the CG's scope.
- **AuthZEN**: Authorization API 1.0 final (January 2026): Subject-Action-Resource-Context, Access Evaluation, batch Evaluations, Search APIs, signed PDP metadata. Working-group drafts 2026-06-15: **COAZ** framework plus **COAZ-MCP** binding (declarative CEL mappings stored with the tool), and **AARP** (request, track, satisfy and re-evaluate missing prerequisites such as approval or attestation). Contributors: Axiomatics, Cerbos, Indykite, Keycard, Okta, SailPoint, SGNL [V, [post](https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/), [repo](https://github.com/openid/authzen)].
- **Shared Signals**: three final specs approved 2025-09-02. CAEP events: Session Revoked, Token Claims Change, Credential Change, Assurance Level Change, Device Compliance Change. No agent-specific event types [V, [WG](https://openid.net/wg/sharedsignals/)].
- **IPSIE**: levels SL1-SL3 (session) and AL1-AL3 (account lifecycle). SL2 requires apps to revoke sessions and tokens on IdP request; SL3 requires bidirectional session, user and device state signals; AL1 requires deprovisioning. No agent scope [V, [levels](https://github.com/openid/ipsie/blob/main/ipsie-levels.md)].
- **IETF** [V, datatracker]: ID-JAG `draft-ietf-oauth-identity-assertion-authz-grant-06`; CIMD `-03`; `draft-ietf-wimse-arch-08`; `draft-ietf-oauth-transaction-tokens-11`; `draft-ietf-oauth-identity-chaining-17`; `draft-klrc-aiagent-auth-03` ("Agents are workloads"; WIMSE identifiers, WPT or HTTP Message Signatures, OAuth for delegation, transaction tokens, a section on monitoring and remediation); `draft-ni-wimse-ai-agent-identity-04`. The SCIM agent extension (`draft-abbey-scim-agent-extension-00`) and the on-behalf-of-user OAuth draft have **expired**. None is an RFC.

### 4. NIST

- **AI Agent Standards Initiative**, CAISI with ITL, 2026-02-17. Three pillars: industry-led standards, community-led open protocols, research on agent security and identity. No named deliverables [V, [news](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure)].
- **NCCoE concept paper** "Accelerating the Adoption of Software and AI Agent Identity and Authorization" (Booth, Fisher, Galluzzo, Roberts; 2026-02-05). Topics: identification, authorization, auditing, non-repudiation, prompt-injection controls. Still listed only as a draft concept paper [V, [CSRC](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)]. It names MCP, OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM and NGAC as candidates [R].
- **COSAiS / COSIS**: five overlays planned (generative, predictive, single agent, multi-agent, developers). Only a concept paper (2025-08-14) and a predictive-AI annotated outline (2026-01-08) are posted [V, [project](https://csrc.nist.gov/projects/cosais)].
- **Cyber AI Profile, IR 8596**: initial preliminary draft 2025-12-16, CSF 2.0-organised, focus areas Secure, Defend, Thwart; working sessions April-May 2026; no public draft yet [V, [CSRC](https://csrc.nist.gov/pubs/ir/8596/iprd)].

### 5. OWASP

- **Top 10 for Agentic Applications 2026** (2025-12-09): ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution [V via mappings]; ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents [R].
- **MCP Top 10** (beta): MCP01 Token Mismanagement and Secret Exposure, MCP02 Privilege Escalation via Scope Creep, MCP03 Tool Poisoning, MCP04 Supply Chain Attacks, MCP05 Command Injection, MCP06 Prompt Injection via Contextual Payloads, MCP07 Insufficient Authentication and Authorization, MCP08 Lack of Audit and Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection and Over-Sharing [V, [project](https://owasp.org/www-project-mcp-top-10/)].
- **NHI Top 10 2025**: Improper Offboarding, Secret Leakage, Vulnerable Third-Party NHI, Insecure Authentication, Overprivileged NHI, Insecure Cloud Deployment Configurations, Long-Lived Secrets, Environment Isolation, NHI Reuse, Human Use of NHI [V].
- **Agent Control Standard v0.1.0** [V, [repo](https://github.com/GenAI-Security-Project/agent-control-standard)]: Apache-2.0 code, CC BY-SA docs, 44 JSON Schemas. Hooks include `steps/toolCallRequest`, `toolCallResult`, user message, agent response, knowledge retrieval, memory store and retrieval, session/turn start and end, subagent start/stop, skill register/load/unload, pre/post compact, AgBOM snapshot/changed. Three pillars: Instrument (mandatory "ACS-Core", with HMAC-SHA256 envelope signing and an audit chain), Trace (OTel spans and OCSF events; "a decision event records the Guardian's verdict, not the enforced outcome"), Inspect (AgBOM as CycloneDX, SPDX or SWID). Deterministic policy (OPA/Rego, Cedar) runs first; optional LLM layer never sees policy source. The reference Guardian is unauthenticated and fails open by default, and only two of nineteen hooks are exercised live. Adapters exist for Claude Code, Cursor and NVIDIA NAT.
- **AIVSS**: v0.8 is the latest scoring document; a 1.0 calculator is live [V, [site](https://aivss.owasp.org/)]. **Agent Name Service**: now an IETF individual draft (`draft-narajala-courtney-ansv2-02`) with a Go reference implementation including a transparency log [V via repo metadata].
- Also: State of Agentic AI Security and Governance 2.01 (June 2026), Practical Guide for Secure MCP Server Development (February 2026), AIUC-1 crosswalk (May 2026) [V].

### 6. MITRE and OpenSSF

- **ATLAS v2026.10**: agent techniques include AML.T0053 AI Agent Tool Invocation, T0080 AI Agent Context Poisoning (.000 Memory, .001 Thread), T0081 Modify AI Agent Configuration, T0083 Credentials from AI Agent Configuration, T0084 Discover AI Agent Configuration, T0086 Exfiltration via AI Agent Tool Invocation, T0098 Tool Credential Harvesting, T0099 Tool Data Poisoning, T0100 AI Agent Clickbait, T0101 Data Destruction via Tool Invocation, T0103 Deploy AI Agent, T0104 Publish Poisoned AI Agent Tool, T0110 Tool Poisoning, T0143 LLM Prompt Propagation, T0145 Poison AI Agent Learning Environment. Mitigations: M0026 Manage Service AI Agent Access, M0027 Manage User-Delegated AI Agent Access, M0028 Enforce Access Controls for AI Agent Tools, M0029 Human In-the-Loop, M0030 Restrict Tool Invocation on Untrusted Data, M0031 Memory Hardening, M0032 Segmentation, M0037 Authority Expansion Controls, M0038 Scope Drift Detection, M0043 External Resource Lifecycle Management [V, [changelog](https://github.com/mitre-atlas/atlas-data/blob/main/CHANGELOG.md)].
- **SAF-MCP**: 14 ATT&CK-aligned tactics, profiles (Core, MCP, Code-Agent, RAG and Memory, Financial-Agent, Model-Lifecycle), typed technique relationships, generated detection coverage matrix [V, [repo](https://github.com/secure-agentic-framework/saf-mcp)].

### 7. CSA, CoSAI, Linux Foundation, W3C, NANDA

- **CSA MAESTRO** (2025-02-06): seven-layer threat model [V]. **Agentic Trust Framework** (2026-02-02, CC BY 4.0): five elements (Identity, Behavior, Data Governance, Segmentation, Incident Response), four autonomy levels mapped to AWS scopes, five promotion gates, and a kill switch "under one second" [V, [post](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents)]. **AICM** v1.1: 243 control objectives in 18 domains, mapped to ISO 42001, NIST AI RMF, AI 600-1, BSI AIC4, EU AI Act; no agentic-specific controls on the page [V].
- **CoSAI** (OASIS): WS4 "Secure Design Patterns for Agentic Systems" is active weekly with an Agentic Development Lifecycle SIG; also the CoSAI Risk Map (the donated SAIF map) and Project CodeGuard (security rules for coding agents) [V, [org](https://github.com/cosai-oasis)]. Publication list page returned 404.
- **Agentic AI Foundation**: hosts MCP, goose, AGENTS.md, A2A, agentgateway, plus Agent Router, Agent Skills, Open Responses, OpenEnv, OpenSandbox. Platinum members: AWS, Anthropic, Block, Bloomberg, Cloudflare, Google, Microsoft, OpenAI [V, [about](https://aaif.io/about/)].
- **AGNTCY**: OASF schema, Agent Directory, Identity (verifiable credentials for agents and MCP servers), SLIM (MLS-encrypted messaging), and **SHADI**, a "hardened runtime" with verified identity, gated secrets, OS sandboxing and encrypted local memory [V, [docs](https://docs.agntcy.org/)].
- **W3C AI Agent Protocol CG**: 282 participants, last drafts 2025-08-19, no working group [V]. **MIT NANDA**: registry and index repos active, low adoption signals [V].

### 8. Payments

AP2 v0.2.0 (2026-04-28) adds "Human Not Present flows" [V]; it expresses authority as signed mandates [R]. Visa Trusted Agent Protocol identifies approved agents with RFC 9421 HTTP Message Signatures verified against the agent's public key, plus consumer-recognition and payment signatures [V, [Visa](https://developer.visa.com/capabilities/trusted-agent-protocol/overview)]. The transferable pattern is per-request signatures bound to a registered agent key and a declared intent [I].

### 9. Vendor frameworks

- **Microsoft Agent 365** (GA 2026-05-01): registry with "Agents without owners", "Unmanaged agents" and consolidated risk signals from Entra, Purview and Defender (up to one hour stale); Graph `GET /copilot/admin/catalog/packages` [V, [docs](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview)]. **Entra Agent ID**: blueprint, agent identity, optional paired agent user, sponsor; on-behalf-of, autonomous and agent-user flows; "`idtyp` alone doesn't distinguish a human user from an agent's user account" [V, [claims](https://learn.microsoft.com/en-us/entra/agent-id/agent-token-claims)].
- **BeyondTrust AI Agent Security**: "Pathfinder" endpoint agent on Windows 11/Server 2022 x64 and macOS 14-26 only. Agents "run as the signed-in user"; classifiers on process naming, signatures and LLM API traffic separate them from humans. Enforcement at kernel and network level plus tool hooks; outcomes allow, audit, approval, block; policy replay against recorded activity. Requires a tenant root certificate for HTTPS inspection. No Linux [V, [docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security)].
- **AWS Agentic AI Security Scoping Matrix**: Scope 1 No Agency, 2 Prescribed, 3 Supervised, 4 Full; six dimensions (identity context; data, memory and state; audit and logging; agent and FM controls; agency perimeters; orchestration) [V].
- **Meta Agents Rule of Two** (2025-10-31): at most two of [A] untrusted input, [B] sensitive data or systems, [C] state change or external communication per session; all three requires human approval [V].
- **Google SAIF**: agent risks Rogue Actions, Sensitive Data Disclosure, Insecure Integrated Component [V]; principles of human controllers, limited powers, observable actions [R]. **Anthropic** (2025-08-04): human control, transparency, alignment, privacy across interactions, secured interactions [V].

## Matrix: standards alignment

| Document | What it asks for | What we implement | Where |
|---|---|---|---|
| MCP 2026-07-28 | Audience-bound tokens, `iss` validation, no passthrough, per-request identity, required headers | Stateless MCP gateway; header-level policy; issuer-keyed credential vault; dual support for 2025-11-25 | MCP gateway |
| MCP local-server guide, SEP-1024 | Inventory configs, pin tool definitions, isolate, log server/tool/time | Config-file collectors, tool-definition hashing and drift alerts, sandbox launcher | Endpoint sensor |
| MCP EMA / ID-JAG | IdP decides server access | Act as ID-JAG-aware resource AS for self-hosted; consume IdP policy | Identity service |
| OWASP ACS 0.1 | Hook wire contract, 5 dispositions, signed envelopes, OTel/OCSF, AgBOM | Native Rust Guardian; fail-closed default; adapters per agent | Hook layer, policy engine |
| AuthZEN 1.0, COAZ, AARP | SARC decisions, tool-to-request mapping, async approval | Expose and consume `/access/v1/evaluation(s)`; COAZ mappings; AARP for `ask` | Policy engine, approvals |
| SSF, CAEP, IPSIE SL2/SL3 | Session and token revocation on signal | Transmitter and receiver; map kill switch to Session Revoked | Response engine |
| IETF WIMSE, klrc, Transaction Tokens | Agents are workloads; attested short-lived credentials; preserved call-chain context | SPIFFE-style IDs for sensors and agents; transaction-token propagation in gateways | Identity service |
| OWASP ASI, MCP, NHI Top 10 | Risk coverage | Detection content tagged with each ID | Detection library |
| MITRE ATLAS, SAF-MCP | Technique taxonomy and mitigations | Tag every detection with AML.T and SAF IDs; publish a coverage matrix | Detection library |
| CSA ATF, AWS matrix | Autonomy tiers and gates | Per-agent autonomy tier that selects the policy bundle | Policy model, console |
| Meta Rule of Two | Break the lethal trifecta | Session taint tracking across A/B/C | Session engine |
| A2A 1.0 | TLS, declared schemes, optional signed cards | Verify card signatures; flag unsigned cards and API-key schemes | A2A gateway, discovery |
| Entra Agent ID | Distinct agent principals and claims | Parse `xms_*_fct`; sync registry via Graph | Cloud connectors |
| NIST COSIS, IR 8596, AICM | 800-53 and CSF mappings | Evidence export keyed to control IDs | Compliance module |

## The 15 requirements these sources agree on

1. Every agent has a unique identity distinct from its user and from generic service accounts (OIDF, Entra, ATF, klrc, NCCoE).
2. Every agent has an accountable human owner or sponsor; ownerless agents are a finding (Agent 365, ATF, NHI1).
3. Delegated authority keeps both principals visible: subject and actor (Entra, klrc, OIDF).
4. Credentials are short-lived, audience-bound and never passed through (MCP, NHI7, MCP01).
5. Least privilege per tool, with scopes that narrow down a delegation chain (MCP scope minimisation, ASI03, ATLAS M0028).
6. Authorization is evaluated before the action by a policy engine outside the model (ACS, AuthZEN, OIDF threat paper, BeyondTrust).
7. High-impact actions need human approval or step-up, asynchronously (AARP, A2A `AUTH_REQUIRED`, MCP elicitation, Rule of Two, ATLAS M0029).
8. Tool descriptions, tool results, retrieved content and memory are untrusted input (MCP guide, ASI01, ASI06, ATLAS T0080/T0099/T0110).
9. Continuous inventory of agents, MCP servers, tools, skills and models, including unregistered ones (MCP09, MCP guide, Agent 365, AgBOM).
10. Supply-chain provenance: pinned versions, signatures, SBOM, change detection on tool definitions (ASI04, MCP04, SEP-1024, ATLAS M0023).
11. Isolation: sandbox, restricted filesystem, controlled egress (MCP guide, ASI05, ATLAS M0032, SHADI).
12. Tamper-evident audit that attributes each action to agent, session and human, in standard formats (ACS Trace, MCP08, AWS, NCCoE non-repudiation).
13. Behavioural monitoring for goal and scope drift (ATF, ATLAS M0038, ASI10).
14. Fast revocation and containment: kill switch, session revocation, circuit breakers (ATF, CAEP, IPSIE SL2, AWS Scope 3-4).
15. Lifecycle governance including deprovisioning (NHI1, IPSIE AL1, OIDF, ATLAS M0043).

## Where they conflict

- **Agent as workload versus agent as user.** IETF says "agents are workloads"; OIDF names treating agents as humans the root cause; Entra nonetheless ships "agent user" accounts for compatibility.
- **Prevention versus detection.** OIDF and BeyondTrust favour authorization-time control; ATF and AWS lean on behavioural monitoring at higher autonomy. An AIDR needs both and must say which is authoritative.
- **Fail-open versus fail-closed.** The ACS reference defaults to `proceed`; ATF demands a sub-second kill switch.
- **Gateway versus endpoint.** MCP's enterprise path routes through an IdP and remote servers; BeyondTrust claims enforcement that "does not require a sandbox, gateway, or proxy"; MCP itself says stdio has no boundary to enforce.
- **Client registration.** MCP deprecates DCR for CIMD (URL-based, domain trust); enterprises prefer pre-registration or ID-JAG; A2A leaves it out of band.
- **Signed metadata.** A2A cards MAY be signed; MCP Server Cards and registry rely on DNS and HTTPS; AGNTCY and ANS want verifiable credentials and transparency logs.
- **Server-to-client model access.** MCP deprecated Sampling just as ATLAS and OWASP began cataloguing it.
- **Autonomy taxonomies.** AWS four scopes, ATF four levels, Rule of Two's three properties and ASI's ten risks do not map one-to-one.

## Weak points, gaps and risks

- No standard defines agent-versus-human attribution on a shared local credential. Every identity standard assumes the agent obtains its own token.
- Normative US government guidance does not exist yet; anything "NIST-aligned" for agents is forward-looking.
- ACS is v0.1.0, changes schemas in place under the same version, and its only Guardian is unauthenticated.
- MCP is mid-migration; clients on 2025-11-25 and 2026-07-28 will coexist for at least twelve months.
- The agent-specific IETF drafts are individual submissions, and the SCIM agent schema has lapsed, so there is no standard way to provision or deprovision agents across vendors.
- Shared Signals has no agent event vocabulary.

## Implications for our design

1. Build the hook layer on ACS and contribute the Rust Guardian. Default to fail-closed, implement the HMAC envelope from day one, and emit OCSF 1.9.0 and OTel exactly per the ACS trace mappings so EDR partners can ingest without custom parsers.
2. Make the policy decision point speak AuthZEN 1.0 in both directions: our engine is a PDP others can call, and customers can plug in Cerbos, OPA or Cedar. Store COAZ mappings per MCP tool.
3. The MCP gateway must be stateless and dual-version. Key sessions on our own correlation IDs and OTel trace context, not `Mcp-Session-Id`. Use `Mcp-Method` and `Mcp-Name` for fast-path policy.
4. Treat endpoint discovery as first-class, as the MCP guide prescribes: collect client config files, hash tool definitions, alert on drift, and record server, tool and time.
5. Model identity as a subject/actor pair everywhere, with an explicit "attribution confidence" field when the actor is inferred from process lineage rather than asserted by a token.
6. Ingest Entra agent claims and the Agent 365 registry; export our inventory as AgBOM (CycloneDX) and as Server Card / Agent Card observations.
7. Implement an SSF transmitter and receiver; a containment action should emit CAEP Session Revoked and call IdP revocation.
8. Ship a per-session taint tracker implementing the Rule of Two and an autonomy tier per agent aligned to AWS scopes.
9. Tag all detection content with ATLAS, SAF-MCP, ASI, MCP and NHI IDs from a single mapping file keyed on stable IDs.
10. Avoid inventing an agent identity scheme. Issue SPIFFE-compatible IDs and wait for WIMSE.

## Ideas worth stealing and whitespace

- BeyondTrust's policy replay against recorded history before enforcing.
- ACS's `modify` disposition (rewrite arguments rather than block) and its rule that a verdict is not proof of enforcement.
- ATF's promotion gates as a product workflow for raising an agent's autonomy.
- SAF-MCP's detection coverage registry, separating linkage, observation modality and validation maturity.
- Whitespace: an open classifier and evidence format for agent-versus-human attribution; CAEP event types for agents (agent quarantined, tool definition changed, delegation revoked); Linux coverage; an open ACS conformance suite; a bridge between ACS hooks, COAZ mappings and ID-JAG so one policy covers hook, gateway and IdP.

## Could not verify / open questions

- Web search was unavailable; coverage relies on known primary URLs. Newer documents may exist that I did not find.
- NCCoE project page (HTTP 403) and CoSAI publications page (404): CoSAI paper titles and the NCCoE standards list are recalled, not re-read.
- OWASP ASI06-ASI10 names, Google's three agent principles, AP2 mandate details, Mastercard Agent Pay, the Agentic Commerce Protocol, "Know Your Agent" schemes, OpenAI and Cisco frameworks, and the OWASP LLM Top 10 (a third-party mapping references "LLM03:2026", suggesting a 2026 edition) were not verified today.
- COSIS use-case page timed out, so agent overlay content is unknown.
- The "Super Intelligence" renaming was read on csrc.nist.gov and nist.gov; I did not locate the Executive Order text.
- Exact Agent 365 price and whether Defender or Intune surface local coding agents in the registry.
- Whether ACS 0.2 is planned and how it will relate to AAIF projects (agentgateway, Agent Router).

## Sources

- MCP releases and changelogs (2025-11-25, 2026-07-28): https://github.com/modelcontextprotocol/modelcontextprotocol/releases ; https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP authorization and security best practices (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization ; https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- MCP local server security: https://modelcontextprotocol.io/docs/tutorials/security/local-server-security
- MCP Enterprise-Managed Authorization: https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- "The New MCP Roadmap" (2026-08-22): https://modelcontextprotocol.io/development/roadmap
- MCP SEPs 990, 1024, 2127, 2133, 2640: https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/seps
- MCP Registry: https://modelcontextprotocol.io/registry/about
- A2A specification v1.0.1 and roadmap (2026-09-15): https://github.com/a2aproject/A2A
- Agent Client Protocol: https://github.com/agentclientprotocol/agent-client-protocol
- OWASP Agent Control Standard (2026-09-01; changelog 0.1.4, 2026-10-16): https://github.com/GenAI-Security-Project/agent-control-standard
- Microsoft Agent Governance Toolkit: https://github.com/microsoft/agent-governance-toolkit
- OWASP Top 10 for Agentic Applications (2025-12-09): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Agentic Security Initiative: https://genai.owasp.org/initiatives/agentic-security-initiative/
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- OWASP NHI Top 10 2025: https://owasp.github.io/www-project-non-human-identities-top-10/2025/top-10-2025
- OWASP AIVSS: https://aivss.owasp.org/
- OIDF AIIM CG: https://openid.net/cg/artificial-intelligence-identity-management-community-group/
- OIDF whitepaper (2025-10-07): https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/
- OIDF cross-boundary threat model (2026-10-12): https://openid.net/oidf-publishes-threat-model-for-cross-boundary-ai-agents/
- AuthZEN WG, drafts post (2026-06-15) and repo: https://openid.net/wg/authzen/ ; https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/ ; https://github.com/openid/authzen
- Shared Signals WG: https://openid.net/wg/sharedsignals/
- IPSIE levels: https://github.com/openid/ipsie/blob/main/ipsie-levels.md
- IETF drafts: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ ; https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/ ; https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ ; https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
- NIST AI Agent Standards Initiative: https://www.nist.gov/caisi/ai-agent-standards-initiative ; https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure
- NCCoE concept paper (2026-02-05): https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
- NIST COSAiS / COSIS (updated 2026-10-20): https://csrc.nist.gov/projects/cosais
- NIST IR 8596 (2025-12-16): https://csrc.nist.gov/pubs/ir/8596/iprd
- MITRE ATLAS data v2026.10 (2026-10-28): https://github.com/mitre-atlas/atlas-data
- SAF-MCP: https://github.com/secure-agentic-framework/saf-mcp
- CSA MAESTRO (2025-02-06): https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro
- CSA Agentic Trust Framework (2026-02-02): https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents
- CSA AICM: https://cloudsecurityalliance.org/artifacts/ai-controls-matrix
- CoSAI repositories: https://github.com/cosai-oasis
- Agentic AI Foundation: https://aaif.io/about/ ; https://aaif.io/projects/
- AGNTCY: https://docs.agntcy.org/
- W3C AI Agent Protocol CG: https://www.w3.org/community/agentprotocol/
- AP2: https://github.com/google-agentic-commerce/AP2
- Visa Trusted Agent Protocol: https://developer.visa.com/capabilities/trusted-agent-protocol/overview
- Microsoft Agent 365 (2026-08-19, 2026-09-21): https://learn.microsoft.com/en-us/microsoft-agent-365/overview ; https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview
- Entra Agent ID: https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities ; https://learn.microsoft.com/en-us/entra/agent-id/agent-token-claims
- BeyondTrust AI Agent Security: https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- AWS Agentic AI Security Scoping Matrix: https://aws.amazon.com/ai/security/agentic-ai-scoping-matrix/
- Meta Agents Rule of Two (2025-10-31): https://ai.meta.com/blog/practical-ai-agent-security/
- Google SAIF risk map: https://saif.google/secure-ai-framework/saif-map
- Anthropic agent framework (2025-08-04): https://www.anthropic.com/news/our-framework-for-developing-safe-and-trustworthy-agents

## Independent verification

_Checked 2026-11-09 by a second reviewer against spec repositories (GitHub API), the IETF datatracker API and direct page fetches. Web search was unavailable (budget exhausted), so every verdict rests on primary pages only._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Latest MCP revision is 2026-07-28; sessions and the `initialize` handshake are removed; version, capabilities and client info travel in `_meta`; `server/discover` is required | Confirmed | Release 2026-07-28 is the newest non-prerelease tag. `protocolVersion` and `clientCapabilities` are carried on every request; `clientInfo` is only a SHOULD. `server/discover` is a MUST for servers. | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx |
| 2 | 2026-07-28 deprecates Roots, Sampling, Logging and DCR (for CIMD) with a twelve-month minimum window; Tasks move to an extension | Confirmed | Earliest removal for all four is "first revision released on or after 2027-07-28". DCR stays for backwards compatibility. The window can be cut to 90 days for an active security risk (SEP-2596). | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/deprecated.mdx |
| 3 | OWASP ACS v0.1.0: JSON-RPC hooks, five dispositions, OTel and OCSF 1.9.0 mappings, AgBOM; reference Guardian unauthenticated and fail-open; Rust, Go, Python ports unclaimed | Corrected | Spec, dispositions, OCSF 1.9.0 pin, unauthenticated wire and fail-open default all hold. The ports are not unclaimed: open PRs #187 (Rust, issue #88 assigned), #169 (Go) and #183 (Python, draft) exist; the README text is stale. Current release is 0.1.4 (spec version still v0.1.0), and `modify` is SHOULD-support since 0.1.3. | https://github.com/GenAI-Security-Project/agent-control-standard/pull/187 |
| 4 | MCP has no standard agent identity; roadmap prioritises DPoP, Workload Identity Federation, ID-JAG and token exchange | Confirmed | Roadmap (updated 2026-08-22) says "MCP authorization assumes a person with a browser at consent time"; the phrase quoted in the TL;DR is not on the page. SEP-1932 (DPoP) and SEP-1933 (WIF) are still open PRs today. A stable OAuth client-credentials extension exists but is not agent-specific. | https://modelcontextprotocol.io/development/roadmap |
| 5 | AuthZEN Authorization API 1.0 final in January 2026; June 2026 WG drafts add COAZ and AARP | Confirmed | Final specification dated 11 January 2026. Post dated 2026-06-15. WG drafts listed: COAZ Framework, COAZ-MCP Binding, AARP, plus an Obligations profile. Paths `/access/v1/evaluation` and `/access/v1/evaluations` are correct. | https://openid.net/specs/authorization-api-1_0.html ; https://openid.net/wg/authzen/specifications/ |
| 6 | NIST has no normative agent guidance; NCCoE paper is a draft concept paper (comments closed 2026-04-02); IR 8596 is a preliminary draft; COSAiS, renamed COSIS on 2026-10-20, has no agent overlays | Confirmed | CSRC shows the rename and cites a 2026-09-29 Executive Order. Only the 2025-08-14 concept paper and the 2026-01-08 predictive-AI outline are posted. No IR 8596 initial public draft exists (the `/ipd` URL returns 404). CSRC publication search returns no final agent document. | https://csrc.nist.gov/projects/cosais |
| 7 | ID-JAG is still an I-D (rev 06, 2026-10-31); `draft-klrc-aiagent-auth-03` and WIMSE agent drafts are not RFCs; the SCIM agent extension draft has expired | Corrected | ID-JAG -06 confirmed. `draft-klrc-aiagent-auth` is no longer an individual draft: it was replaced by the WIMSE working-group document `draft-ietf-wimse-aims` (-00 2026-09-15, -01 2026-11-02). `draft-abbey-scim-agent-extension` expired, but `draft-wzdk-scim-agent-resource-00` is active (expires 2026-12-07). None is an RFC. | https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/ ; https://datatracker.ietf.org/doc/draft-wzdk-scim-agent-resource/ |
| 8 | Entra tokens mark agents with `xms_act_fct` / `xms_sub_fct` values 11 (AgentIdentity) and 13 (AgentIDUser); `idtyp` alone cannot tell a human from an agent's user account | Confirmed | Read in the docs source repository. Facet claims are multivalued and space-separated (for example `"3 9 11"`), so parse as a set, not as a scalar. | https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/agent-id/agent-token-claims.md |
| 9 | A2A is at v1.0.1; card signing optional (JWS over JCS); identity delegated to TLS and OAuth-family schemes; authorization agent-defined | Confirmed | v1.0.1 changelog date 2026-05-26, GitHub release 2026-05-28. A `v1.1.0-rc` tag exists (2026-10-29), so 1.1 is close. Clients SHOULD verify at least one signature when present. | https://github.com/a2aproject/A2A/releases |
| 10 | BeyondTrust: agents run as the signed-in user with no identity of their own; classifiers on process naming, signatures and LLM API traffic; Windows x64 and macOS only | Confirmed | Page (updated 2026-10-13) matches: Windows 11 or Server 2022+ on x64, Windows on Arm unsupported, macOS 14, 15, 26, no Linux. No second independent source was found; this rests on the vendor page alone. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |
| A | Brief, section 1: "Deprecated with a 12-month minimum window: Roots, Sampling, Logging, HTTP+SSE" | Corrected | HTTP+SSE is on a shorter track: earliest removal is three months after SEP-2596 reached Final, and SEP-2596 is Final. Treat the legacy transport as removable in the next revision, not protected until mid-2027. | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2596-spec-feature-lifecycle-and-deprecation.md |
| B | Brief, TL;DR and open questions: ACS v0.1.0 dated 2026-09-01; "whether ACS 0.2 is planned" unknown | Corrected | The repository changelog dates 0.1.0 to 2026-06-05 (0.1.1 on 2026-08-11, 0.1.4 on 2026-10-16). The README states spec v0.2.0 targets March 2027 and no v1.0 date is set. | https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CHANGELOG.md |
| C | Brief, TL;DR: ATLAS v2026.10 (2026-10-28) has 16 tactics, 129 techniques, 92 sub-techniques, 44 mitigations | Confirmed | Changelog text matches exactly. | https://github.com/mitre-atlas/atlas-data/blob/main/CHANGELOG.md |

Consequences for the plan:

- Implication 1 ("contribute the Rust Guardian") should become "review and build on PR #187", or the work will duplicate an assigned port. Port acceptance rules are in the merged PR #256 (AGT runtime as default evaluator, HMAC signing, conformance harness).
- The "Weak points" bullet saying the agent-specific IETF drafts are individual submissions is out of date: the main one is now a WIMSE working-group document (`draft-ietf-wimse-aims`). Implication 10 ("wait for WIMSE") has a concrete document to track.
- Dual-version MCP support should not assume HTTP+SSE survives the next revision.
