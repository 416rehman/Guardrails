# Standards, specifications and regulation for agent security: search-backed sweep (June to November 2026)

_Researched 2026-11-10 (search-backed follow-up)_

Tags: **[V]** verified today on a primary source; **[S]** secondary source only (law firm, vendor or recap; primary not read); **[K]** background knowledge, not re-checked; **[I]** inference. 16 of 18 permitted searches used.

## TL;DR

- **The "Super Intelligence" renaming is real and purely terminological.** Executive Order 14434, "Inaugurating the Era of Super Intelligence", signed 29 Sep 2026, published at 91 FR 63129 (2 Oct 2026), tells agencies to write "Super Intelligence / SI" for "AI". It defines SI by reference to the existing statutory AI definition (15 U.S.C. 9401(3)) and leaves prior documents unaltered. NIST COSAiS became COSIS on 20 Oct; the NCCoE project is now the "Agentic SI Identity and Authorization Project"; CISA retitled the Five Eyes guide "Careful Adoption of Agentic SI Services". No obligation changed. [V]
- **Two government documents now give concrete agent-security controls and neither is in the earlier briefs**: the Five Eyes guide "Careful adoption of agentic AI services" (1 May 2026) and the UK NCSC's "Managing the cyber risk of agentic AI" (20 Aug 2026, interim). The NCSC text reads like a requirements list for our product: unique non-human identity class, credential-injecting proxy, four-level network and compute isolation ladders, immutable logs including reasoning traces, 24/7 SOC coverage, attribution headers, and an emergency shutdown that cuts network and inference links. [V]
- **IETF 127 (San Francisco, 14 to 20 Nov 2026) is next week and nothing agent-specific will be an RFC before 2028.** agentproto meets Mon 16, the AUDIT BoF Tue 17 (09:00 to 10:30), webbotauth Tue 17, DAWN Thu 19, OAuth three times including a joint session with WIMSE. agentproto's charter targets IESG submission in March 2028 and DAWN's in Dec 2027 to Jan 2028. [V]
- **agentproto explicitly excludes "audit data structures" and "behavioral security"; the AUDIT BoF exists to take the first.** Its draft charter composes WIMSE, RATS, OAuth, SCITT, W3C Trace Context and vCon, and requires audit information to be "verifiable by a party that trusts neither the agent nor its operator". No IETF group owns agent enforcement points. [V]
- **MCP has had no specification revision since 2026-07-28.** The draft changelog holds two items. The security work sits in open proposals: trust and sensitivity annotations (SEP-1913), DPoP (1932), workload identity federation (1933), tool risk metadata (2793), audit context in `_meta` (2817), asynchronous approval (2848), interceptors (2624), HTTP message signing (2752). A tool-server attestation proposal (2809) was closed unmerged on 8 Nov. There is still no signing or provenance for tool definitions. [V]
- **OWASP Agentic Top 10 identifiers are now confirmed**: ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. [S, consistent across several mirrors]
- **EU harmonised standards are late on both Acts.** EN 18286 (AI quality management) is published but Official Journal citation is unconfirmed; the cybersecurity and logging parts are still drafts. No Cyber Resilience Act harmonised standard is cited in the Official Journal, and the drafting deadlines are slipping to 31 Oct and 31 Dec 2026. [S]
- **Schemas did not move**: OCSF 1.10 is still `1.10.0-dev`; OTel GenAI conventions have no tagged release and "Schema URL: TODO"; CycloneDX 2.0 is past its 31 Aug 2026 milestone with 79 issues open; SPDX 3.1 is still RC1. [V]
- **ISO/IEC 27090 (AI security threats guidance) was published in October 2026.** It is guidance, not certifiable. [S]
- **AIUC-1 is the fastest-moving certification buyers will name**: quarterly versions (Q4-2026 dated 15 Oct), 1,000 to 5,000 adversarial scenarios, quarterly retests, Schellman accredited, Cursor, Harvey, KPMG, Sierra and ElevenLabs certified. [V on vendor page]
- **No US state or federal law found that mandates agent audit logs.** HIPAA Security Rule final action slipped to a projected July 2027. PCI SSC's October 2026 AI guidance is non-mandatory. [S]

## Findings

### 1. IETF

**Meetings.** IETF 126 ran 18 to 24 July 2026 in Vienna; agentproto and dawn both held sessions there (BoF stage) and wimse met 20 July [V, [proceedings](https://datatracker.ietf.org/meeting/126/proceedings)]. IETF 127 agenda (updated 2026-11-09) [V, [agenda](https://datatracker.ietf.org/meeting/127/agenda.txt)]:

| Group | Slot (Pacific) |
|---|---|
| agentproto | Mon 16 Nov 14:00 to 16:00 |
| audit (BoF) | Tue 17 Nov 09:00 to 10:30 |
| webbotauth | Tue 17 Nov 16:30 to 18:30 |
| oauth | Wed 18 09:00; Thu 19 14:00 (joint with wimse); Fri 20 09:00 |
| scitt | Wed 18 Nov 16:30 to 17:30 |
| dawn, spice | Thu 19 Nov 16:30 to 18:30 |

Other BoFs (squad, mtahooks, evp, mole) are unrelated to agents.

**agentproto** (Agent Communication Protocols, ART area; chairs Leslie Daigle, Orie Steele). Scope: a baseline "agentic dialog management protocol" (dialog identifiers, lifecycle, context propagation) bound to HTTP, QUIC, WebTransport, WebRTC and MoQ. Out of scope: agent behavioural security, decision semantics, UI, and "audit data structures and their production, validation, or consumption". Milestones: adopt use cases by 2026-12-31, architecture by 2027-02-28, protocol drafts by 2027-03-31, IESG submission 2028-03-31. No adopted drafts [V, [charter page](https://datatracker.ietf.org/group/agentproto/about/)].

**dawn** (Discovery of Agents With Names, INT area; chairs Dapeng Liu, Frank Brockners). Scope: initial discovery of public properties of AI resources on a local network, inside one organisation, and between cooperating parties; DNS and mDNS considered; integrity of discovery data required. Out of scope: identity management, trust evaluation, capability catalogues, Internet-wide indexing. Protocol to IESG 2027-12-31 [V, [charter page](https://datatracker.ietf.org/group/dawn/about/)].

**AUDIT BoF** (Agent Use of Delegation and Interaction Traceability, SEC area; chairs Orie Steele, Yaroslav Rosomakho; not chartered). Draft charter, last edited 2026-10-19 [V, [repository](https://github.com/mirjak/audit-bof-preparation)]: cross-domain auditing of observable agent behaviour (intent declarations, tool interactions, invoked or declined actions, outcomes), not of models. It needs a common identifier linking user intent to resulting actions, authorisation captured as time-evolving state, selective disclosure, and third-party verifiability. Four deliverables: architecture (Informational), audit data models (Standards Track, with a registry), protocol extensions (HTTP headers, OAuth token formats, attestation claims), and deployment best practice. It will not define compliance policy or new identity primitives.

**OAuth** [V, [documents](https://datatracker.ietf.org/wg/oauth/documents/)]. Published in 2026: RFC 10017 (browser-based apps, BCP), RFC 10027 (cross-device flow security, BCP), RFC 10070 (JWT client authentication update, Nov 2026). RFC Editor queue: identity chaining -17, Token Status List -21, JWT BCP bis -10. WG consensus, awaiting write-up: Transaction Tokens -11, attestation-based client auth -12, first-party apps -04. Still WG documents: ID-JAG -06, Client ID Metadata Document -03 (2 Nov), SPIFFE client auth -03 (2 Nov), OAuth 2.1 -17. Newly adopted: Delegate SD-JWT -00, Deferred Token Response -01, RAR metadata and error remediation -00. At least 18 individual agent-named drafts are active (actor profile, actor proofs, actor receipts, agent revocation, attenuating agent tokens, transaction tokens for agents); none is adopted.

**WIMSE** [V, [documents](https://datatracker.ietf.org/wg/wimse/documents/)]. HTTP-signature workload authentication -08: publication requested. Workload Identity Practices -08: IETF Last Call ends 2026-11-13. AIMS -01 remains a WG document. Fifteen individual agent drafts exist, including "Per-Call Proof for Local Tool Invocation by AI Agents" and "Signed Authorization-Evidence Records"; these are the closest IETF text to an enforcement-point receipt, and none is adopted.

**Web Bot Auth**: one WG document, `draft-ietf-webbotauth-httpsig-protocol-01` (2026-10-29) [V, [documents](https://datatracker.ietf.org/wg/webbotauth/documents/)].

**SCITT**: architecture is RFC 9943; SCRAPI -11 is in the RFC Editor queue; the CCF receipt profile -06 awaits AD go-ahead. Thirteen-plus individual agent drafts (agent action capsule -05, permit profile for pre-execution authorisation records, refusal events, agent session receipts, an OTel extension) are not WG items [V, [documents](https://datatracker.ietf.org/wg/scitt/documents/)].

### 2. MCP and sibling protocols

- **Latest MCP release is still 2026-07-28** (tagged 2026-07-28; RC on 2026-05-29). The draft changelog contains only (a) repinning Client ID Metadata Documents from draft -00 to -03 and (b) restoring a dropped `_meta` field on five types [V, [releases](https://github.com/modelcontextprotocol/modelcontextprotocol/releases), [draft changelog](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/draft/changelog.mdx)].
- **Open security proposals** (all unmerged, activity 2 to 10 Nov 2026) [V, [pull requests](https://github.com/modelcontextprotocol/modelcontextprotocol/pulls)]: SEP-1913 trust and sensitivity annotations (`sensitiveHint`, `privateHint`, `openWorldHint`, `maliciousActivityHint`, `attribution`; sensitivity only escalates within a session); SEP-1932 DPoP profile; SEP-1933 workload identity federation; SEP-2343 elicitation requires authorisation on remote servers; SEP-2643 structured authorisation denials; SEP-2752 HTTP message signing for client authentication; SEP-2793 tool risk metadata; SEP-2817 AI invocation audit context in `_meta`; SEP-2848 asynchronous approval for tool calls; SEP-2624 interceptors (a new primitive to "intercept, validate and transform" context operations, motivated by the sprawl of proxies and gateways); SEP-3149 token endpoint auth methods in CIMD.
- **Closed unmerged**: SEP-2809 Attested Tool-Server Admission (8 Nov 2026). Tool-definition signing and provenance remain outside the protocol [V].
- **Accepted and in the repository** [V, `seps/`]: SEP-1024 client security requirements for local server installation, SEP-1036 URL-mode elicitation, SEP-990 enterprise IdP policy controls, SEP-991 CIMD, SEP-2127 server cards, SEP-2640 skills extension, SEP-2468 recommend issuer claim, SEP-2484 conformance tests required for final SEPs.
- **Process**: proposals now go "working-group-first" (PR 3529, 9 Nov 2026) [V]. Expect slower, more deliberate change [I].
- **Security best practices** lives as a per-revision tutorial (`docs/docs/<revision>/tutorials/security/security_best_practices.mdx`), not in the normative `basic/` folder, which now holds only authorization, patterns, transports and versioning [V, repository tree].
- **Registry**: server software is at v1.8.8 (2026-11-06) but the README still describes a preview with an API freeze at v0.1 dated 2025-10-24; no general-availability statement and no trust or signing tier [V, [registry](https://github.com/modelcontextprotocol/registry)].
- **A2A**: v1.0.1 (2026-05-28) is still the latest tag [V]. **Agent Client Protocol**: schema v1.30.0 and v2.0.0-alpha.14 both released 2026-11-09, so a breaking v2 schema is in alpha [V]. **AG-UI**: date-stamped releases, latest 2026-11-09 [V]. **AP2**: v0.2.0 (2026-04-28), nothing since [V]. **AGNTCY**: OASF 1.1.0 (2026-07-10), directory v1.8.0 (2026-10-15) [V]. The OpenID Foundation has responded to an EMVCo Agentic Payments framework draft (title seen only) [S, [openid.net](https://openid.net/tag/ai-agents/)].

### 3. Industry bodies

- **OWASP Agentic Top 10 (published 2025-12-09)**: list in TL;DR [S, [mirror](https://docs.modulos.ai/frameworks/owasp-top-10-agentic); the [OWASP page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) only offers a PDF]. No newer edition.
- **OWASP ACS**: resource page dated 2026-09-01, repository `GenAI-Security-Project/agent-control-standard`; the page states no version or roadmap [V, [page](https://genai.owasp.org/resource/agent-control-standard-acs/)].
- **OWASP MCP Top 10**: still beta, identifiers `MCP01:2025` to `MCP10:2025` (token mismanagement, scope creep, tool poisoning, supply chain, command injection, prompt injection via contextual payloads, insufficient authentication and authorisation, lack of audit and telemetry, shadow MCP servers, context over-sharing); licence CC BY-NC-SA 4.0 [V, [project](https://owasp.org/www-project-mcp-top-10/)].
- **OWASP AIVSS**: v0.8 is the latest publication; an "AIVSS 1.0 reference calculator" is live [V, [site](https://aivss.owasp.org/)].
- **New OWASP GenAI documents**: Red Teaming Manual v1.0 (20 Oct 2026), LLM Exploit Generation Guide 2.0 (27 Oct), Data Security Best Practices v2 part 1 (3 Nov), State of Agentic AI Security and Governance 2.01 (June), an AIUC-1 crosswalk (May) [V, listing].
- **CoSAI**: MCP Security paper (27 Jan 2026), Agentic Identity and Access Management (March or April 2026), "The Future of Agentic Security" (March 2026). Nothing found for September to November [S, [CoSAI](https://www.coalitionforsecureai.org/cosai-year-2-the-future-of-agentic-security/)].
- **MITRE ATLAS**: v2026.10 (28 Oct 2026); releases are roughly monthly (v2026.07 on 7 Aug, .08 on 1 Sep, .09 on 15 Sep) [V, [releases](https://github.com/mitre-atlas/atlas-data/releases)].
- **OpenTelemetry**: core conventions v1.45.0 (2 Nov 2026); the GenAI repository has no tags and "Schema URL: TODO" (last push 9 Nov) [V].
- **OCSF**: 1.9.0 (3 Aug 2026) is latest; `version.json` reads `1.10.0-dev`; unreleased additions include `ai_capability` (with `is_destructive`, `is_open_world`, schema and description fingerprints) and `ai_status` [V, [changelog](https://github.com/ocsf/ocsf-schema/blob/main/CHANGELOG.md)].
- **CycloneDX**: 1.7.2 (17 Sep 2026); the 2.0 milestone (due 31 Aug 2026) is open with 79 open and 107 closed issues; a 2.1 milestone is due 16 Apr 2027. **SPDX**: 3.1-rc1 (Jan 2026) is still the newest tag [V].
- **OpenID**: AuthZEN Authorization API 1.0 final on 11 Jan 2026; COAZ-MCP binding (Draft 1, 13 Feb 2026) and the Access Request and Approval Profile (ARAP, June 2026) are still working-group drafts; the AI Identity Management community group answered NIST's agent RFI in March 2026 and is running an MCP interop event [S, [spec](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html), [Cerbos](https://cerbos.dev/blog/mcp-authorization-standards)].
- **ISO/IEC 27090:2026** published October 2026 (14 Oct per Nemko) [S, [Nemko](https://digital.nemko.com/news/isoiec-27090-published-as-new-ai-cybersecurity-standard)].

### 4. Governments and regulators

**Five Eyes, "Careful adoption of agentic AI services" (1 May 2026).** CISA, NSA, ASD ACSC, Canada's Cyber Centre, NCSC-NZ and NCSC-UK; about 30 pages and 100-plus practices over four lifecycle stages (design, develop, deploy, operate). Five risk categories: privilege, design and configuration, behaviour, structural, accountability. Practices include a verifiable identity per agent, temporary credentials for sensitive actions, monitoring of internal processes and not only inputs and outputs, independent systems that cross-check agent reports against system logs, and approval checkpoints for high-impact actions [V for title, date and CISA authorship on [cisa.gov](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services); details S, [Mayer Brown](https://www.mayerbrown.com/en/insights/publications/2026/06/multi-agency-guidance-on-securing-agentic-ai-systems)].

**UK NCSC, "Managing the cyber risk of agentic AI" (20 Aug 2026)**, interim advice to be superseded by formal guidance [V, [PDF](https://www.ncsc.gov.uk/sites/default/files/2026-08/Managing-the-cyber-risk-of-agentic-AI_0.pdf)]:

- Do not rely on model or harness safeguards, or on prompting alone; add "classifiers, deterministic provers and wider controls".
- Oversight modes: human in, on, or out of the loop; approvals must be "guaranteed and gated"; named accountable people; judge models must be independently evaluated.
- "Always run AI agents within a sandboxed environment." Network ladder: 1 unrestricted, 2 domain allowlist, 3 model API only, 4 no external network with local model. Compute ladder: 1 none, 2 containers, 3 virtualisation, 4 dedicated hardware. Deny by default; protocol-aware proxies with manual approval for exceptions.
- "All agents should be assigned their own unique identity" in a class distinct from humans. Shortest-lived credentials; a proxy that injects credentials so the agent never holds them. It notes that an agent with host access can use the user's own credentials.
- Telemetry must include "chain of thought traces and transcripts" plus sandbox, proxy and network logs; logs protected from modification, immutable where possible; the log pipeline is itself an escape surface.
- "Agentic AI activity should be treated as a form of user activity" under 24/7 monitoring and incident response.
- Attribution to third parties: reverse-resolvable source addresses and identifying HTTP headers.
- Emergency shutdown must reach beyond process kill: restrict network access and cut selected agents from inference infrastructure.
- Points to ETSI EN 304 223 as the baseline.

**Germany and France**: no 2026 agent-specific BSI or ANSSI publication found; the joint zero-trust design principles for LLM systems (2025) remains the reference. A report that BSI is drafting agent security criteria is unconfirmed [S]. **ENISA, Japan**: nothing found.

**Singapore**: the CSA "Securing Agentic AI" addendum page is dated 17 June 2026; Baker McKenzie reports it as finalised that day, though the page still carries consultation wording [V page, S finality, [CSA](https://www.csa.gov.sg/resources/publications/addendum-on-securing-ai-systems/)].

**NIST**: see TL;DR. COSIS still lists only the August 2025 concept paper and the January 2026 predictive-AI outline; single-agent and multi-agent overlays are "proposed" [V, [COSIS](https://csrc.nist.gov/projects/cosais)]. The NCCoE resource hub reports 600-plus comments, a planned SP 1800-series practice guide and iterative outputs; no drafts, collaborators or dates [V, [hub](https://pages.nist.gov/nccoe-ai-identity/)]. The Executive Order asks for proposed statutory language within 60 days (about 28 Nov 2026), which may touch the statutory AI definition and possibly state pre-emption [S, [Wiley](https://www.wiley.law/alert-Executive-Order-Rebrands-AI-as-Super-Intelligence-and-Signals-Potential-Federal-Legislative-Changes); order text at [Federal Register](https://public-inspection.federalregister.gov/2026-20321.pdf)].

**EU AI Act**: the Omnibus is Regulation (EU) 2026/1744, Official Journal 24 July 2026, in force 27 July; Annex III duties 2 Dec 2027, Annex I 2 Aug 2028 [S, [National Law Review](https://natlawreview.com/article/eu-digital-omnibus-ai-enters-force)]. EN 18286 was approved 12 July 2026 and listed as published 31 July; presumption of conformity is limited to the Annex ZA table and Official Journal citation was not confirmed. prEN 18282 (cybersecurity), prEN 18228 (risk management), prEN 18284 (datasets) and EN 18229-1 (logging and other trustworthiness requirements) status not confirmed [S, [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-en18286-harmonised-standard-presumption-20/)].

**Cyber Resilience Act**: Article 14 reporting began 11 Sep 2026. As of September no harmonised standard was cited in the Official Journal. A draft amendment to standardisation request M/606 moves horizontal drafting deadlines to 31 Oct 2026 and product-specific (vertical) ones to 31 Dec 2026. ETSI opened public enquiry on 17 draft product standards on 13 Aug 2026; prEN 40000-1-3 (vulnerability handling) is expected to be cited first [S, [independent CRA guide](https://www.cyberresilienceact.eu/fr/news/cra-standardisation-deadlines-pushed-back-two-months.html)].

**US states**: California SB 813 and AB 1405 (signed September 2026; AI auditor registry and independent verification for consequential decisions, phased to 2029) and SB 1119 (companion chatbot audits from 1 July 2027); Colorado replaced its AI Act with a disclosure-based law effective 1 Jan 2027. None mandates agent action logs [S, [Akin Gump](https://www.akingump.com/en/insights/ai-law-and-regulation-tracker/california-enacts-ai-auditor-registry-and-independent-verification-framework-sb-813-and-ab-1405), [Bloomberg Law](https://news.bloomberglaw.com/daily-labor-report/colorado-joins-states-favoring-ai-disclosure-over-audit-mandates)].

**Sector rules**: PCI SSC issued additional, non-mandatory guidance on securing AI in payment environments (October 2026) and ran workshops on whether PCI DSS applies differently to AI agents (September 2026) [S, [PCI SSC](https://www.pcisecuritystandards.org/about_us/press_releases/pci-ssc-publishes-additional-guidance-on-securing-ai-in-payment-environments/)]. HIPAA Security Rule final action is now projected for July 2027 [S, [McDermott](https://www.mcdermottlaw.com/?p=50371417)]. Nothing found for NYDFS, SEC, DORA or NIS2 naming AI agents.

### 5. Certification schemes for 2027

| Scheme | Status checked today | What it needs from the product or service |
|---|---|---|
| SOC 2 Type II | [K] | Tenant isolation evidence, admin audit trail, change management, exportable control evidence over a 6 to 12 month window |
| ISO/IEC 27001, 27017, 27018 | [K] | ISMS at the operating company; cloud shared-responsibility statement; PII processor controls, deletion and sub-processor lists |
| ISO/IEC 27701 | [K] (2025 edition is standalone) | Records of processing, data-subject request tooling, privacy modes for prompt and transcript capture |
| ISO/IEC 42001 | [K] | AI system inventory, impact assessments, lifecycle records for our own detection models; customers want our agent inventory as their evidence |
| ISO/IEC 27090 | Published Oct 2026 [S] | Not certifiable; use as the threat checklist for our own classifiers |
| CSA STAR for AI | Not re-checked; see brief 34 | AI-CAIQ answers plus a base certificate |
| AIUC-1 | Q4-2026, 15 Oct 2026 [V] | Third-party adversarial testing (1,000 to 5,000 scenarios), quarterly retests, logging, human oversight, tool-call authentication, incident response; one-year certificate |
| FedRAMP 20x | Page snapshot [V]: Class B (Low) and C (Moderate); High pilot FY27 Q1 to Q2; new Rev5 stops 11 June 2027 | Machine-readable Key Security Indicator evidence, automated validation with trend history, assessor review of validation code |
| C5, Cyber Essentials, IRAP, TISAX, HDS | [K], not re-checked | Region-pinned hosting and support, customer-managed keys, documented sub-processors; HDS presupposes ISO 27001 and EEA hosting; TISAX is assessed against the VDA ISA catalogue; these attach to the hosted service, not the open-source code |

## Matrix: requirements

| Source | Clause | What the product must do | Covered earlier? |
|---|---|---|---|
| NCSC (Aug 2026) | Credentials | Give every agent a unique identity in a non-human class; flag agents running on a user's credentials | Partly (17, 18): identity yes, "class" label and reporting no |
| NCSC | Credentials | Offer a credential-injecting proxy so agents never hold secrets | Partly (35, 38) |
| NCSC | Sandbox ladders | Report each agent's network level (1 to 4) and compute level (1 to 4); alert on downgrade | New |
| NCSC | Observability | Capture reasoning traces and transcripts with sandbox, proxy and network logs; tamper-evident store | Yes (23), reasoning traces partly |
| NCSC | Observability | Treat the collector as attack surface an agent may abuse | Partly (37, g03 tamper resistance) |
| NCSC | Attribution | Stamp outbound agent traffic with identifying headers; handle abuse reports as incidents | New (Web Bot Auth in 18 is related) |
| NCSC | Shutdown | Kill switch that cuts network and inference links, not only processes | Yes (36, 38) |
| Five Eyes (May 2026) | Accountability | Independently cross-check agent self-reports against OS and network telemetry | Partly (17); should be a named detection |
| Five Eyes | Privilege | Temporary credentials and approval checkpoints for high-impact actions | Yes (19, 20, 36) |
| AUDIT BoF draft charter | Scope | Common identifier from user intent to action; authorisation as time-evolving state; third-party verifiable; selective disclosure | Partly (23 hash chain); selective disclosure new |
| agentproto charter | Out of scope | Do not wait for IETF to define enforcement or audit; keep our own schema | Yes (23) |
| MCP SEP-1913, 2793 | Draft | Ingest trust, sensitivity and risk annotations as policy inputs; never trust them as sole evidence | New |
| MCP SEP-2817, 2848, 2643 | Draft | Map audit context, async approval and structured denials onto our decision record | Partly (19 COAZ and approval) |
| MCP SEP-2624 | Draft | Be able to run as an MCP interceptor if adopted | New |
| OCSF 1.10-dev | `ai_capability` | Fingerprint tool descriptions and schemas; detect drift | Yes (23) |
| OWASP ASI01 to ASI10 | Identifiers | Tag every detection with ASI and MCP Top 10 identifiers | Partly (19 lacked ASI06 to ASI10) |
| EU AI Act Art. 26(6) | Logs | Retain deployer logs at least six months | Yes (34) |
| EN 18229-1, prEN 18282 | Drafts | Track; export logs in whatever format the logging part fixes | New |
| CRA Art. 14 | Live since 11 Sep 2026 | Vulnerability and incident reporting process for our own product | Yes (34) |
| CRA Art. 32 | Conformity | Without cited standards, Class I and II products need third-party assessment unless the open-source route in Art. 32(5) applies [K] | Partly (28, 34) |
| AIUC-1 | Domains B, D, E | Evidence pack: tool-call restrictions, logging, oversight, test results | Partly (19, g08) |
| FedRAMP 20x | KSI | Machine-readable evidence endpoint with history | Yes (34) |
| EO 14434 | Terminology | Compliance mappings keyed on document identifiers; UI label aliasing "AI" and "SI" | Yes (19, 34) |

## What this changes in the earlier briefs

- **19 and 34**: the NIST rename is no longer "anomalous, re-check". It is Executive Order 14434 (91 FR 63129), terminological only. Add that NCCoE and CISA pages were renamed too.
- **18**: "AUDIT BoF charter text was not read" is closed; the charter composes WIMSE, RATS, OAuth, SCITT, Trace Context and vCon.
- **18 and 19**: "MCP pins CIMD -00" holds for the 2026-07-28 release but the draft now pins -03. Brief 18's ID-JAG -06 date shows as 2026-10-30 on Datatracker.
- **19**: "AARP (asynchronous approval)" should read **ARAP**, the Access Request and Approval Profile. ASI06 to ASI10 names are now confirmed. ACS's public page states no version; "v0.1.0" rests on the repository.
- **19**: CoSAI titles previously recalled are confirmed by secondary sources, with nothing new after April.
- **23**: unchanged and re-confirmed (OCSF 1.10 unreleased, OTel GenAI untagged, CycloneDX 2.0 late, SPDX 3.1 RC1). Add ISO/IEC 27090.
- **34**: add the Five Eyes and NCSC documents, which the brief does not mention; they are more operational than Singapore's framework. HIPAA is not final (projected July 2027). The CRA standards slip means the presumption-of-conformity route is unavailable for now. Omnibus number 2026/1744 re-confirmed.
- **34**: "No finished US federal agent control set exists" still holds.

## Implications for our design

1. Ship an **NCSC profile**: a posture report that scores every discovered agent on the two four-level ladders, identity class, credential exposure, log immutability and shutdown reach. It is the first government text a UK or Commonwealth buyer will hand us.
2. Make **"agent report versus ground truth" divergence** a first-class detection; the Five Eyes guide asks for it and only an OS-level sensor can deliver it.
3. Kill switch must have three independent actuators: process, network, and inference route (gateway). Test each separately.
4. Label agent-originated egress (header plus optional Web Bot Auth signature) at the gateway and record it, to satisfy the attribution clause.
5. Treat the collector and log pipeline as hostile-reachable: one-way write path, no agent-readable credentials, schema-validated input.
6. Keep our own audit schema, but design the decision record so that it can be projected into whatever AUDIT standardises: stable intent identifier, authorisation-state transitions, signed, selectively disclosable (hash-committed fields).
7. Parse MCP trust, sensitivity and risk hints as untrusted inputs with our own fingerprints beside them; build the gateway so that it can also register as an MCP interceptor.
8. Version-pin external dialects per connector (MCP revision, ACP schema major, OTel GenAI commit, OCSF version); ACP v2 and OCSF 1.10 will both land during our build.
9. Tag content with ASI, MCP Top 10, ATLAS and SAF-MCP identifiers; ATLAS ships monthly, so the mapping must be data, not code.
10. Plan for third-party CRA assessment cost unless the open-source documentation route is confirmed, and publish technical documentation from day one.

## Could not verify / open questions

- Full text of the Five Eyes guide (cyber.gov.au timed out) and the Singapore addendum PDF; control details rest on law-firm summaries.
- Official Journal citation of EN 18286; current stage of prEN 18282, 18228, 18284 and EN 18229-1; the Omnibus number rests on secondary sources.
- CRA: the implementing regulation on technical descriptions of product categories, which class an AIDR sensor falls in, and whether Art. 32(5) covers a commercially hosted open-source product.
- CSA AARM, MAESTRO, Agentic Trust Framework and STAR for AI: no change found, not re-read. OWASP NHI Top 10: 2025 list not re-read (redirect); no 2026 edition seen. SAF-MCP: GitHub search rate-limited.
- OpenID IPSIE and Shared Signals status; AIIM whitepaper date.
- NYDFS, SEC, DORA, NIS2, ENISA, Japan AISI, BSI and ANSSI: no agent-specific 2026 text found; absence is not proof.
- FedRAMP 20x: the page fetched is an April 2026 snapshot; the Consolidated Rules for 2026 were not read.
- C5, Cyber Essentials, IRAP, TISAX and HDS requirements are from background knowledge.
- IETF 127 outcomes: the meeting starts 14 Nov; re-check after 20 Nov, especially whether AUDIT is approved to charter.

## Sources

- IETF 127 agenda, updated 2026-11-09: https://datatracker.ietf.org/meeting/127/agenda.txt
- IETF 126 proceedings (July 2026): https://datatracker.ietf.org/meeting/126/proceedings
- agentproto charter page: https://datatracker.ietf.org/group/agentproto/about/
- dawn charter page: https://datatracker.ietf.org/group/dawn/about/
- audit BoF page and draft charter (2026-10-19): https://datatracker.ietf.org/group/audit/about/ ; https://github.com/mirjak/audit-bof-preparation
- OAuth, WIMSE, webbotauth, SCITT document lists (read 2026-11-10): https://datatracker.ietf.org/wg/oauth/documents/ ; https://datatracker.ietf.org/wg/wimse/documents/ ; https://datatracker.ietf.org/wg/webbotauth/documents/ ; https://datatracker.ietf.org/wg/scitt/documents/
- MCP specification repository, releases, draft changelog, SEPs and pull requests (read 2026-11-10): https://github.com/modelcontextprotocol/modelcontextprotocol
- MCP registry (v1.8.8, 2026-11-06): https://github.com/modelcontextprotocol/registry
- Release pages: https://github.com/a2aproject/A2A/releases ; https://github.com/agentclientprotocol/agent-client-protocol/releases ; https://github.com/ag-ui-protocol/ag-ui/releases ; https://github.com/google-agentic-commerce/AP2/releases ; https://github.com/agntcy/oasf/releases ; https://github.com/mitre-atlas/atlas-data/releases ; https://github.com/ocsf/ocsf-schema ; https://github.com/open-telemetry/semantic-conventions-genai ; https://github.com/CycloneDX/specification/milestones ; https://github.com/spdx/spdx-3-model/releases
- OWASP Top 10 for Agentic Applications (2025-12-09): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ ; list mirror: https://docs.modulos.ai/frameworks/owasp-top-10-agentic
- OWASP Agentic Security Initiative; ACS (2026-09-01): https://genai.owasp.org/agentic-security-initiative/ ; https://genai.owasp.org/resource/agent-control-standard-acs/
- OWASP MCP Top 10 (beta): https://owasp.org/www-project-mcp-top-10/ ; AIVSS: https://aivss.owasp.org/
- NIST COSIS (notice 2026-10-20): https://csrc.nist.gov/projects/cosais ; NCCoE hub: https://pages.nist.gov/nccoe-ai-identity/
- Executive Order 14434 (2026-09-29): https://public-inspection.federalregister.gov/2026-20321.pdf ; https://www.govinfo.gov/app/details/DCPD-202600656 ; Wiley alert: https://www.wiley.law/alert-Executive-Order-Rebrands-AI-as-Super-Intelligence-and-Signals-Potential-Federal-Legislative-Changes
- CISA, Careful Adoption of Agentic SI Services (2026-05-01): https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services ; Mayer Brown summary (2026-06-10): https://www.mayerbrown.com/en/insights/publications/2026/06/multi-agency-guidance-on-securing-agentic-ai-systems
- NCSC, Managing the cyber risk of agentic AI (2026-08-20): https://www.ncsc.gov.uk/sites/default/files/2026-08/Managing-the-cyber-risk-of-agentic-AI_0.pdf ; Thinking carefully before adopting agentic AI: https://www.ncsc.gov.uk/sites/default/files/2026-06/Thinking-carefully-before-adopting-agentic-AI.pdf
- Singapore CSA addendum (2026-06-17): https://www.csa.gov.sg/resources/publications/addendum-on-securing-ai-systems/ ; Baker McKenzie: https://www.bakermckenzie.com/en/insight/publications/2026/07/singapore-csas-addendum-on-securing-agentic-ai-systems
- EU Omnibus in force: https://natlawreview.com/article/eu-digital-omnibus-ai-enters-force ; EN 18286: https://labs.cloudsecurityalliance.org/research/csa-research-note-en18286-harmonised-standard-presumption-20/
- CRA standards slip (updated 2026-09-11): https://www.cyberresilienceact.eu/fr/news/cra-standardisation-deadlines-pushed-back-two-months.html
- California SB 813 and AB 1405: https://www.akingump.com/en/insights/ai-law-and-regulation-tracker/california-enacts-ai-auditor-registry-and-independent-verification-framework-sb-813-and-ab-1405 ; Colorado: https://news.bloomberglaw.com/daily-labor-report/colorado-joins-states-favoring-ai-disclosure-over-audit-mandates
- PCI SSC AI guidance (Oct 2026): https://www.pcisecuritystandards.org/about_us/press_releases/pci-ssc-publishes-additional-guidance-on-securing-ai-in-payment-environments/
- HIPAA Security Rule timing (2026-07-16): https://www.mcdermottlaw.com/?p=50371417
- AIUC-1 (Q4-2026, 2026-10-15): https://www.aiuc-1.com/
- FedRAMP 20x: https://www.fedramp.gov/20x/
- ISO/IEC 27090:2026: https://digital.nemko.com/news/isoiec-27090-published-as-new-ai-cybersecurity-standard ; https://www.iso.org/fr/standard/56581.html
- OpenID AuthZEN profiles: https://openid.github.io/authzen/authzen-mcp-profile-1_0.html ; https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html ; https://cerbos.dev/blog/mcp-authorization-standards
- CoSAI year-two summary: https://www.coalitionforsecureai.org/cosai-year-2-the-future-of-agentic-security/

## Independent verification

_Checked 2026-11-10 by a separate fact-checker against primary sources (GitHub API, Datatracker, Federal Register API, the NCSC text itself) and secondary sources the brief did not cite. 4 web searches used._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | NCSC interim advice (20 Aug 2026): unique non-human identity class, always sandboxed, immutable logs with reasoning traces, 24/7 monitoring as user activity, shutdown covering network and inference | Confirmed, with wording caveats | All five points are in the text. It is an NCSC blog post ("interim practical advice"), to be applied "proportionately". Everything is "should", not "must": logs immutable "where possible"; telemetry "should include" chain of thought traces; the credential-injecting proxy is "for some use cases, a proxy can help". The brief's "Telemetry must include" and "shutdown must reach" overstate the modal verbs. | Text extracted from the NCSC PDF |
| 2 | COSAiS renamed COSIS on 20 Oct 2026 under EO 14434 (29 Sep 2026); terminological; earlier publications unaltered; agent overlays unpublished | Confirmed | NIST page carries the 20 Oct notice and "Previously issued documents and publications have not been altered"; single-agent and multi-agent overlays are listed only as proposed use cases. The NIST page does not print the order number; the Federal Register API gives EO 14434, signed 2026-09-29, 91 FR 63129. Section 2(b) of the order leaves historical documents alone; section 3(b) asks for legislative language within 60 days. | https://csrc.nist.gov/projects/cosais ; https://www.federalregister.gov/api/v1/documents/2026-20321.json |
| 3 | MCP latest release 2026-07-28; draft changelog has two entries; SEP-1913, 1932, 1933, 2793, 2817, 2848, 2624 open; SEP-2809 closed unmerged 8 Nov | Confirmed | Releases, tags and `docs/specification/` all stop at 2026-07-28. Draft changelog has exactly the CIMD -03 repin and the `_meta` restoration. All seven PRs open; 2809 closed 2026-11-08T05:04Z, `merged=false`. The 2809 thread shows a maintainer redirecting it to the Security Interest Group under the new process, so the closure looks procedural, not a rejection on the merits. | GitHub API, `modelcontextprotocol/modelcontextprotocol` |
| 4 | agentproto charter excludes behavioural security and audit data structures; IESG milestone 31 Mar 2028 | Confirmed | Out of scope, verbatim: "AI agent behavioral security, such as preventing the AI model itself from hallucinating" and "Audit data structures and their production, validation, or consumption, though dialog identifiers may be used in auditing." Milestone 2028-03-31. The behavioural exclusion is narrowly worded. | https://datatracker.ietf.org/group/agentproto/about/ |
| 5 | AUDIT BoF (17 Nov) not chartered; draft charter composes WIMSE, RATS, OAuth, SCITT, W3C Trace Context, vCon; third-party verifiability | Confirmed | Datatracker: type BOF, "Not chartered yet". Agenda: Tue 17 Nov 09:00 to 10:30. `audit-charter.md` (last commit 2026-10-19) contains the composition list and "verifiable by a party that trusts neither the agent nor its operator" verbatim. | https://datatracker.ietf.org/group/audit/about/ ; GitHub API, `mirjak/audit-bof-preparation` |
| 6 | Five Eyes guide (1 May 2026): five risk categories; per-agent verifiable identity, temporary credentials, approval checkpoints, independent cross-validation of agent reports against system logs | Confirmed in substance; one element single-sourced | Date and six authoring agencies confirmed (NCSC-NZ page, CISA page). Five categories confirmed by three independent summaries. Per-agent identity, short-lived credentials and approval gates corroborated by the CSA research notes. The cross-validation recommendation ("independent monitoring systems that can cross-validate agent reports and system logs") appears only in the Mayer Brown summary; no second source repeats it and the primary PDF on cyber.gov.au timed out three times. Design implication 2 leans on this one sentence: read the primary before quoting it. | https://ncsc.govt.nz/protect-your-organisation/careful-adoption-of-agentic-ai-services/ ; https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-agentic-ai-security-guide-enterprise/ ; https://www.insideprivacy.com/artificial-intelligence/cisa-releases-guidance-on-the-careful-adoption-of-agentic-ai-services/ |
| 7 | OCSF 1.10 unreleased (`1.10.0-dev`); OTel GenAI repository has no tagged release and no schema URL | Confirmed, with one nuance | OCSF `version.json` reads `1.10.0-dev`; latest release 1.9.0 (2026-08-03). OTel GenAI: 0 tags, 0 releases, README "Schema URL: TODO". However `model/manifest.yaml` already declares `schema_url: https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev` (stability: development) and `RELEASING.md` defines a `vX.Y.Z-dev` channel; that URL returns 404 today. So no published schema URL, but a dev one is reserved. | GitHub API, `ocsf/ocsf-schema`, `open-telemetry/semantic-conventions-genai` |
| 8 | No CRA harmonised standard cited in the Official Journal as of Sep 2026; drafting deadlines proposed to move to 31 Oct and 31 Dec 2026 | Corrected | No citation still holds in November 2026. The deadline half is stale and imprecise: the same site's state-of-play page (updated Nov 2026) says the July draft amendment "was never formally adopted", and gives the first core standards date as 30 Aug moved to 30 Oct 2026 (not 31 Oct) and the vertical date as 30 Oct moved to 31 Dec 2026. EN 40000-1-1 and EN 40000-1-2 passed CEN-CENELEC formal vote on 1 Oct 2026 with publication scheduled 17 Nov 2026. The Commission's own page (updated 31 Jul 2026) states neither deadlines nor citations. All dates remain secondary. | https://cyberresilienceact.eu/state-of-play.html ; https://digital-strategy.ec.europa.eu/en/policies/cra-standardisation |
| 9 | AIUC-1 quarterly versions (Q4-2026, 15 Oct); requires 1,000 to 5,000 adversarial scenarios with quarterly retests; Cursor, Harvey, KPMG, Sierra, ElevenLabs certified | Corrected | Quarterly cadence confirmed by the changelog (15 Jan, 15 Apr, 15 Jul, 15 Oct 2026). The scenario count is not a requirement: the page says red-teaming "typically involves 1,000 to 5,000 different test scenarios", and the changelog states no number. Quarterly retests are stated. The certified list is incomplete: the page also shows Fin and UiPath; Sierra appears through a 17 Sep 2026 news item. | https://standard.aiuc-1.com/changelog/ ; https://www.aiuc-1.com/ |
| 10 | OWASP Agentic Top 10: ASI01 Agent Goal Hijack to ASI10 Rogue Agents, with ASI06 to ASI09 as named | Confirmed | OWASP's own launch post lists all ten with matching names (it shortens ASI02 to "Tool Misuse" and writes "&" for "and"). The OWASP GitHub repository holds a file named `ASI06_Memory_and_Context_Poisoning`. | https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/ |

Further statements checked in the brief:

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| "A2A: v1.0.1 (2026-05-28) is still the latest tag" (section 2) | Corrected | v1.0.1 is the latest release, but a `v1.1.0-rc` tag exists (commit 2026-10-29, "merge main into dev 1.1"). A2A 1.1 is in release-candidate stage; add it to the version-pinning list in design implication 8. | GitHub API, `a2aproject/A2A` tags |
| "proposals now go working-group-first (PR 3529, 9 Nov 2026) [V]" (section 2) | Overstated citation | PR 3529 is an open draft opened by a bot on 9 Nov, not merged. The group-first rule is nonetheless already on `main` in `docs/community/sep-guidelines.mdx` ("Bring the idea to the working or interest group that covers the area first"), and a maintainer applied it on SEP-2809. The conclusion stands; the cited PR is not the evidence. | GitHub API, `modelcontextprotocol/modelcontextprotocol` |
| "prEN 40000-1-3 (vulnerability handling) is expected to be cited first" (section 4, CRA) | Outdated | By November 2026 EN 40000-1-1 (vocabulary) and EN 40000-1-2 (principles, risk management, lifecycle) are ahead: formal vote passed 1 Oct 2026, publication scheduled 17 Nov 2026. EN 40000-1-3 is still a draft with no publication date. | https://cyberresilienceact.eu/state-of-play.html |

Also confirmed in passing: IETF 127 slots for agentproto, audit, webbotauth, scitt, dawn, spice and oauth (agenda updated 2026-11-09); DAWN milestones (protocol to IESG 2027-12-31, architecture 2028-01-31); ACP schema v1.30.0 and v2.0.0-alpha.14 released 2026-11-09; MITRE ATLAS v2026.10 on 2026-10-28; MCP registry v1.8.8 on 2026-11-06; CycloneDX 1.7.2 on 2026-09-17 and the 2.0 milestone at 79 open, 107 closed.
