# Enhancing existing EDRs: embedding, OEM and white-label models for an open AIDR engine

_Researched 2026-11-09_

Method note: the shared web-search budget for this run was exhausted before this brief started, so everything below comes from directly fetched primary documentation and the GitHub API. Claims are tagged **[V]** (verified in a fetched primary source this session) or **[K]** (prior knowledge, not re-verified, may be stale).

## TL;DR

- The incumbents shipped endpoint AIDR in 2026. Microsoft Defender discovers 60+ local agents on Windows and macOS (GA) and blocks prompt injection through vendor hooks plus network inspection (Windows preview). CrowdStrike Falcon AIDR and BeyondTrust AI Agent Security use the same three control points: OS sensor, in-agent hooks, network/TLS inspection. **[V]**
- Defender's local discovery and runtime protection both require Defender Antivirus in **active mode**. A fleet whose primary EDR is CrowdStrike or SentinelOne (Defender passive) gets neither. That is our clearest opening for "enhance the EDR you already run". **[V]**
- An open verdict-provider contract already exists in production: Copilot Studio's external threat detection webhook (`POST /analyze-tool-execution?api-version=2025-05-01`, 1,000 ms budget, fail-open by default). Our engine should be able to serve it, and our own interface should copy its shape. **[V]**
- AMSI is the closest OS-level precedent for "submit content, let every installed security product vote". Any application can call it, but providers are in-process COM DLLs, Windows-only, and return a malware verdict. It is a useful cheap rung for shell-command tool calls, not a transport for agent semantics. **[V] mechanism, inference on fit**
- The lowest common denominator for feeding a third-party EDR locally is a **Windows Event Log channel**, **journald/syslog**, **macOS unified log** and **JSON-lines files**. Falcon LogScale Collector reads exactly those (no ETW). Raw ETW is consumable by Elastic (GA input) but not generally. **[V]**
- Licence determines embeddability. GPL engines (ClamAV, Suricata) force a daemon boundary or a paid non-GPL licence; permissive ones (YARA BSD-3, OPA/Falco/CRS Apache-2.0, osquery Apache-2.0 OR GPL-2.0) are linked directly into commercial products. **[V]**
- YARA-X is the packaging template for a Rust engine: one repo with `lib` (crate), `capi`, `go`, `py`, `js-wasm`, `cli`; v1.23.0 released 2026-11-05. **[V]**
- Content needs its own signed channel and its own licence. ClamAV 1.5 (2025-10-07) moved to external `.sign` files for FIPS; Sigma rules are DRL 1.1, which requires author attribution even in match views, which collides with white-labelling. **[V]**
- Telemetry standard to align with: OpenTelemetry GenAI conventions. Microsoft deprecated its bespoke Agent 365 Observability SDK (doc dated 2026-10-01) in favour of a "Microsoft OpenTelemetry Distro" that exports to Agent 365 and any OTLP endpoint at once. The GenAI semconv moved to its own repo and still logs breaking changes. **[V]**
- "No new sensor" mode is viable for discovery and coarse detection only. Every vendor that claims pre-execution blocking does it with hooks or inline network inspection, not with EDR telemetry. **[V] by vendor docs, inference on generality**
- Multiple vendors now write hooks into the same agents. Claude Code merges hook entries across settings levels and runs matching hooks in parallel, so coexistence works, but nobody brokers it. A neutral hook broker with a provider interface is unclaimed. **[V] mechanism, inference on gap**

## Findings

### Part 1: precedents for OEM and embedded engines

**Commercial OEM engines.** Avira OEM (oem.avira.com, fetched 2026-11-09) sells a tiered catalogue rather than one SDK **[V]**:

- Endpoint Protection SDK for Windows: delivered as a Windows service with "library and daemon service modes", bundled quarantine, firewall and AMSI support, and pre-approved under Microsoft's MVI programme so the licensee skips certification.
- SAVAPI: cross-platform libraries for Windows, macOS, Linux on Intel and ARM.
- MAVAPI for Android: roughly 6 MB, Kotlin and JNI interfaces, its own licensing mechanism and HTTPS updater.
- ICAP binary package activated by a licence file; a dependency-free C unpacker library.
- Cloud Sandbox API, File and Web Reputation APIs, reputation and intelligence feeds, and a separate "White Label" product.

Bitdefender states more than 200 licensees over 15+ years and "more than 20 security SDKs", grouped as Endpoint Protection, Gateway Protection, Sandbox Service and Threat Intelligence feeds/APIs **[V]** (bitdefender.com/oem). Neither site publishes update-channel mechanics, branding rules or telemetry terms; those sit behind NDA **[V] that they are absent**.

Pattern common to both: (1) in-process library, (2) local daemon/service, (3) protocol adapter (ICAP), (4) cloud lookup API, (5) data feeds, (6) full white label. That is the ladder customers already understand.

Kaspersky Scan Engine (HTTP and ICAP modes, key-file licensing), OPSWAT (MetaDefender multi-engine, OESIS endpoint SDK), Sophos, ESET and Cylance SDKs follow the same shapes **[K]**; I could not fetch their docs this session.

**Open-source analogues and what their licences did to adoption.**

| Project | Licence | Embedding interface | Content channel | Lesson |
|---|---|---|---|---|
| ClamAV | GPL-2.0 **[V]** | `libclamav` (`cl_init`, `cl_engine_new`, `cl_load`, `cl_engine_compile`, `cl_scanfile`), `clamd` socket | Signed CVD plus CDIFF; since 1.5.0 external `.cvd.sign`, `certs` dir, FIPS limits; `CL_DB_OFFICIAL_ONLY` **[V]** | Docs state closed-source software may not link libclamav, so vendors talk to `clamd`. 1.5 also deprecated `cl_scan*` for `_ex` variants: C API churn is real |
| Suricata | GPL-2.0, copyright held by OISF **[V]** | Process plus EVE JSON; library mode | Rule feeds (ET Open free, ET Pro paid **[K]**) | Non-GPL licence sold through OISF consortium membership **[V]**; only possible because one body owns copyright |
| YARA / YARA-X | BSD-3 **[V]** | C lib; YARA-X: Rust crate, C API, Go, Python, WASM | Rules are user-supplied | Permissive licence made it ubiquitous inside EDRs |
| ModSecurity + CRS | Apache-2.0 both **[V]** | Engine connector; CRS is pure content | Versioned rule releases | Content-only adoption: clouds ship CRS without the engine **[K]** |
| osquery | Apache-2.0 OR GPL-2.0-only **[V]** | Extensions are separate processes over Thrift on a UNIX socket; tables, config, logger plugins **[V]** | n/a | Out-of-process plugin ABI stays stable; a non-root extension cannot register with a root `osqueryd` |
| Falco | Apache-2.0 **[V]** | Plugins are shared libraries; plugin API 3.12.0 with semver and `get_required_api_version` **[V]** | Rules plus `falcoctl` artifact index; registry reserves plugin IDs and source names **[V]** | A registry of IDs prevents collisions between vendors |
| OPA | Apache-2.0 **[V]** | REST sidecar, Go SDK, WASM, IR plans **[V]** | Bundles; decision logs | Four embedding modes from one policy language; WASM is "fastest, any language" |
| Sigma | Spec public domain; rules DRL 1.1 **[V]** | Converters (pySigma) | Git | DRL requires author credit in views that show matches |
| OTel Collector | Apache-2.0 **[V]** | `ocb` manifest builds a custom binary from chosen Go modules **[V]** | n/a | "Distribution builder": vendors ship their own branded binary from upstream components |

Two licence shifts to note: Wazuh's engine (`src/engine/`) is now AGPL-3.0-or-later with the rest GPL-2.0 **[V]**, and Elastic's detection rules are Elastic License 2.0 **[V]**. Neither can be embedded by a proprietary EDR.

### Part 2: local mechanisms for feeding or extending an installed EDR

**Windows**

- **AMSI.** Designed for "application developers who want to make requests to antimalware products from within their apps" **[V]**. Providers are in-process COM servers registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers`, must be Authenticode-signed since Windows 10 1903, and cannot load into PPL processes **[V]**. Sessions let a provider correlate fragments. Consequences: a helper of ours can submit an agent's pending shell command or script and get the installed AV's verdict; provider DLLs load into the caller, so this must be a disposable helper process, never the core; providers apply malware heuristics and know nothing about prompts or MCP. Whether CrowdStrike, SentinelOne and others surface third-party AMSI submissions in their consoles is untested (inference).
- **ETW.** Elastic's filebeat ETW input is GA and takes `provider.guid` or `provider.name` for manifest, MOF and TraceLogging providers, with admin rights **[V]**. Falcon LogScale Collector's source list is file, Windows Event Log, syslog, unified logs, journald, exec and database; no ETW **[V]**. Defender for Endpoint does not ingest arbitrary third-party ETW **[K]**.
- **Windows Event Log channel.** One manifest can define both the ETW provider and an Operational channel **[K]**; the channel is what collectors read. This is the portable feed.
- **Kernel coexistence.** Minifilter altitudes and WFP sublayers allow several products to stack **[K]**. Microsoft's Windows endpoint security platform moves AV/EDR to user mode (private preview to MVI partners from July 2025; MVI 3.0 mandates staged rollouts) **[V]**. Inference: do not design around a kernel driver on Windows.

**macOS.** Endpoint Security clients need the `com.apple.developer.endpoint-security.client` entitlement, root and Full Disk Access; `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS` exists but Apple documents no number **[V]**. Multiple vendors' ES clients run side by side in practice **[K]**. Unified logging is the feed (LogScale Collector has a "Unified Logs" source **[V]**).

**Linux.** Audit user messages, journald and Falco source plugins are the equivalents; Falco plugins can add event sources and inject async events **[V]**. Pinned eBPF maps are a private contract and a poor public interface (inference).

**Cross-platform.** An osquery extension exposing `ai_agents`, `mcp_servers`, `agent_sessions` tables is cheap and reaches every osquery-based product **[V] mechanism**. OTLP is the telemetry lingua franca; Microsoft's distro sends to Agent 365, Azure Monitor and "any OTLP-compatible endpoint" simultaneously **[V]**.

**In-agent hooks as the shared choke point.** Defender's "agent-native event inspection" is explicitly the vendors' hook interfaces; its support matrix links to Claude Code hooks and GitHub Copilot hooks docs **[V]**. CrowdStrike lists hooks for Claude Code, Codex, GitHub Copilot, OpenCode and Cursor **[V]**. Claude Code specifics **[V]**: handler types `command`, `http`, `mcp_tool`, `prompt`, `agent`; matching hooks run in parallel; hook entries merge across settings levels; `PreToolUse` returns `permissionDecision` of `allow|deny|ask|defer` and may rewrite `updatedInput`; default timeout 600 s for command/http; managed settings support `allowManagedHooksOnly` and `allowedHttpHookUrls`.

### Part 3: cloud-side paths, vendor by vendor

- **Microsoft.** Ingest: Logs Ingestion API (DCR, Entra app, JSON array, custom `_CL` tables) **[V]**. Detect: Defender custom detections run on Defender and Sentinel tables; NRT for single-table queries; custom frequency of 5 minutes to 14 days for Sentinel-only data; 150 alerts per run **[V]**. Respond: isolate device, collect package, AV scan, restrict app execution, quarantine or block file, disable user, but automated actions apply "if your custom detection rule uses Defender data" **[V]**. Native agent data: `AgentsInfo` (`Platform == "LocalAgents"`, `RawAgentInfo.localAgentMetadata.autoApprove`, `localMcps`) plus `ExposureGraphNodes/Edges` **[V]**. Agent 365 GA 2026-05-01, per-user licence **[V]**.
- **CrowdStrike.** Falcon Foundry is the extension surface; official samples cover custom ingestion to LogScale, NG-SIEM import, scalable RTR, functions, collections and UI **[V]** (repo list). AIDR integrations are MIT-licensed on GitHub: `aidr-python`, `aidr-typescript`, `aidr-go`, `aidr-mcp-proxy`, `aidr-kong`, `aidr-apigee`, `aidr-azure-api-management`, `langchain-aidr` **[V]**. Falcon AIDR's own Linux/Kubernetes discovery and NG-SIEM behavioural baselining are "coming soon" **[V]**. HEC-style ingestion and Custom IOA limited to sensor event types are **[K]**.
- **Elastic.** Most open: ETW input, custom integrations, and it triggers response *through other EDRs* (CrowdStrike isolate/release/runscript; Defender isolate/runscript/cancel; SentinelOne isolate, get-file, processes, kill-process, runscript) **[V]**.
- **Sophos.** Partner, Organization and Tenant APIs with service principals; endpoint isolation and scan operations; Data Lake Search; an "AI Defense" API is listed **[V]**. Third-party ingestion not confirmed.
- **Bitdefender GravityZone.** API keys, blocklist, custom detection rules, remote shell and a Security Data Lake with inputs/forwarders appear in the docs index **[V]**; details not read.
- **Wazuh.** Active response scripts fire on rule ID, level or group, stateless or stateful **[V]**; JSON log ingestion with custom decoders **[K]**.
- **SentinelOne, Cortex XSIAM, Trend Vision One, Tanium.** Docs unreachable this session (429, 404, redirect loop). All offer HTTP/syslog ingestion, a query-based custom rule layer and marketplace programmes **[K]**.

### Part 4: "no new sensor" mode

What EDR telemetry supports, by the vendors' own evidence: Defender builds inventory from an observed process alone ("the user doesn't need to submit a prompt") and reads MCP configuration from disk **[V]**. So process, file and network tables are enough for discovery, version inventory, MCP config posture, auto-approve flags and child-process lineage (agent binary as ancestor, which also gives agent-versus-human attribution for spawned commands; inference).

What is missing: the tool call as a unit (name, arguments, MCP server), prompts and tool results, session and subagent identity, anything in-process or remote (hosted MCP, SaaS agents), and any pre-execution decision. Cloud custom detections poll on minute-scale schedules; even NRT is post hoc **[V]**. Network inspection needs a trusted root certificate (BeyondTrust requires the tenant root on every endpoint **[V]**) and fails on certificate pinning and HTTP/3 (Microsoft **[V]**).

How hooks close it: a hook is a config entry, not a sensor. It yields structured `tool_name`, `tool_input`, `session_id`, `agent_id` before execution and can deny. Microsoft calls each check "a fast, inline check rather than continuous monitoring" **[V]**. Hooks cover only cooperating agents; bespoke agents need an SDK/OTel path or a gateway.

### Part 5: packaging an embeddable engine

- **Shape.** Follow YARA-X: a pure Rust crate as the source of truth, a C ABI generated from it, thin Go/Python/Node bindings, a WASM build, and a CLI **[V] precedent**. Add a sidecar daemon (the `clamd`/OPA-REST pattern) for vendors who will not link foreign code into a sensor.
- **Deterministic, I/O-free core.** Input: normalized events plus a content bundle plus a clock value. Output: verdicts and derived events. No sockets, files, threads or wall-clock reads. This is what makes the same core run in a hook, in a sensor, in WASM and server-side over EDR telemetry, and what makes a conformance suite possible (inference; OPA's WASM/IR split is the precedent **[V]**).
- **Versioning.** Three independent numbers: engine semver, C ABI version negotiated at load (Falco's `get_required_api_version` **[V]**), and content schema version. Additive-only wire schemas with "tolerate unknown fields" (Microsoft's webhook guidance **[V]**).
- **Content channel.** Signed bundles with detached signatures, pinned trust roots, an "official only" switch (ClamAV **[V]**), plus tenant overlay bundles. OEMs must be able to re-host and re-sign.
- **Conformance and marks.** Golden input/output vectors any embedder runs in CI; a registry of provider and source IDs (Falco **[V]**). Use of "Compatible" or "Powered by" marks gated on passing; this is trademark policy, separate from the code licence (inference).
- **White label.** Avira and Bitdefender both sell it as a distinct tier **[V]**. Requirements (inference): API-first control plane, theme tokens, custom domains, per-tenant branding, parent/child tenancy for MSPs (Sophos Partner/Organization/Tenant API split is the model **[V]**), embeddable UI components, no hard-coded product name in agent-facing block messages.

## Matrix: adoption ladder

| Rung | What the adopter takes | Feasibility | Our effort | Precedent |
|---|---|---|---|---|
| 1. Content only | Agent fingerprints, MCP risk lists, detection rules compiled to KQL/CQL/XQL/EQL/Sigma | High; works today on EDR telemetry | Low: rule compiler plus signed feed | CRS in WAFs, Sigma, ET rules, Avira/Bitdefender feeds |
| 2. Local event feed | Our hooks/collector write Event Log, journald, unified log, JSONL, OTLP; EDR's collector ships it | High | Low-medium: schemas, manifests, osquery extension | LogScale Collector sources, Elastic ETW input, osquery extensions |
| 3. Open verdict-provider interface | A hook broker asks N providers (ours, the EDR's, AMSI) allow/deny within a deadline | Medium: needs vendors to implement a small API | Medium: spec, broker, reference provider | AMSI; Copilot Studio `/analyze-tool-execution` |
| 4. Embedded engine | Vendor links crate/C ABI/WASM or runs sidecar inside its sensor | Medium; long sales cycle | High: ABI discipline, conformance suite, support | SAVAPI, libclamav/clamd, YARA-X, OPA |
| 5. Cloud connector on EDR telemetry | Our engine runs server-side over the EDR's data lake and calls its response API | High for detection, none for prevention | Medium per vendor | Elastic third-party response actions; Foundry apps |
| 6. Full platform | Our sensors, gateways, console, SaaS or self-hosted | High | Highest | Falcon AIDR, BeyondTrust, Defender |
| 7. White-label distribution | MSP/OEM rebrands rung 6 | Medium | High: tenancy, theming, re-signing | Avira "White Label", Bitdefender OEM |

## Weak points, gaps and risks

- Incumbents bundle rung 6 into licences customers already own (Defender discovery needs only MDE P2 **[V]**). A standalone open platform competes with "free".
- Rung 3 depends on other vendors implementing an interface. AMSI succeeded because Microsoft owned the OS; we own nothing. The broker must be useful with a single provider.
- Hook-based control is advisory to the agent vendor: schema changes, a user with local admin, or an agent without hooks bypasses it. Managed-settings locks exist for Claude Code **[V]**; equivalents elsewhere are unverified.
- Fail-open is the industry default at 1 s (Copilot Studio **[V]**). A fail-closed engine embedded in someone else's product inherits their availability blame.
- Sending prompts and tool arguments into another vendor's data lake is a data-protection decision; Microsoft's own docs warn that provider handling may differ **[V]**.
- GenAI semantic conventions are still breaking **[V]**; pin a version and translate.
- Our content licence could block OEMs if we import DRL-licensed community rules (attribution in match views).

## Implications for our design

1. Build the core as an I/O-free Rust crate with stable event-in/verdict-out types; ship `capi`, WASM, Go/Python/Node bindings and a sidecar from the same repo, mirroring YARA-X.
2. Define one normalized event schema and emit it five ways: OTLP (GenAI conventions, version-pinned), Windows Event Log channel with ETW manifest, journald, macOS unified log, JSONL. Add an osquery extension.
3. Ship a hook broker: one managed hook entry per agent that fans out to registered verdict providers with a strict deadline, deny-wins merge, and per-provider fail policy. Model the provider API on `/analyze-tool-execution` and include an adapter so our engine can be registered as a Copilot Studio external provider.
4. On Windows, add an optional AMSI submission helper (separate process) for shell-command tool calls so the incumbent AV votes with no integration work. Lab-test which EDRs log it.
5. Make "Defender passive mode" a first-class target: on CrowdStrike or SentinelOne fleets we supply the discovery and hook protection Defender withholds.
6. Deliver rung 1 immediately: compile detection content to KQL (`DeviceProcessEvents`, `AgentsInfo`), LogScale query language, EQL/ES|QL, XQL and Sigma, with our own rules under Apache-2.0 so OEMs owe no attribution.
7. Separate content from engine: signed bundles, detached signatures, re-signable by OEMs, offline-installable, "official only" flag.
8. Licence the engine, sensors, SDKs and schemas Apache-2.0 (patent grant; matches OPA, Falco, CRS). Keep contributor terms that preserve relicensing options only if a dual-licence business is wanted; AGPL anywhere in the embeddable path ends OEM adoption.
9. Publish a conformance suite and an ID registry on day one; tie the trademark, not the code, to passing it.
10. Cloud connectors: start with Microsoft (Logs Ingestion API in, custom detections and device isolation out), CrowdStrike (Foundry app), Elastic (integration package), in that order.

## Ideas worth stealing and whitespace

- BeyondTrust's **policy dry-run by replaying recorded activity** before saving a policy **[V]**: trivial for a deterministic core.
- Microsoft's **audit then block** rollout, with audit alerts at Informational severity **[V]**.
- Microsoft's benign **prompt-injection demonstration string**, an EICAR for agents **[V]**: publish an open one inside the conformance suite.
- Elastic acting **through** other EDRs' response APIs **[V]**: respond without owning the sensor.
- Whitespace: native Linux and Kubernetes (Defender has WSL preview only; CrowdStrike "coming soon") **[V]**; a vendor-neutral hook broker; an open agent fingerprint database comparable to Defender's 60-entry matrix; AIDR for fleets where Defender is passive; agent-versus-human attribution exposed as a field other tools can join on.

## Could not verify / open questions

- Web search was unavailable; no forum, conference or news sources were consulted.
- SentinelOne (HTTP 429), Cortex XSIAM (404 after redirect), Trend Vision One (redirect loop), Kaspersky Scan Engine (404), Falco plugin architecture page (404): not read. Tanium, OPSWAT, ESET, Sophos OEM, Cylance: not attempted.
- Do CrowdStrike, SentinelOne and Sophos register AMSI providers on current builds and surface third-party `appName` submissions? Needs a lab test.
- Actual macOS limit on simultaneous Endpoint Security clients.
- CrowdStrike NG-SIEM ingestion limits, Custom IOA scope, and whether Foundry apps may be published by non-partners.
- Commercial terms of Avira/Bitdefender OEM (royalty basis, telemetry sharing, branding rules) and OISF non-GPL pricing.
- How Codex, Cursor, Copilot and OpenCode merge hooks from several vendors, and their managed-lock equivalents.
- Whether Microsoft will open Agent 365 or Defender's local runtime protection to third-party verdict providers as Copilot Studio did.

## Sources

- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (Agent 365 overview, 2026-08-19, updated 2026-10-23)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai (2026-10-30)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview (2026-10-08)
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection (2026-09-25)
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider (2026-06-01)
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers (2025-09-02, updated 2026-10-15)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/microsoft-opentelemetry (2026-10-22)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/archive/observability-sdk (deprecated SDK, 2026-10-01)
- https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules (2026-09-02)
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview (2026-08-13)
- https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal (2025-07-09)
- https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience (2025-06-12)
- https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ (2025-06-26)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (updated 2026-10-13)
- https://www.crowdstrike.com/en-us/platform/falcon-aidr-ai-detection-and-response/ (fetched 2026-11-09)
- https://www.crowdstrike.com/en-us/platform/next-gen-siem/falcon-foundry/ (fetched 2026-11-09)
- https://github.com/CrowdStrike (aidr-* and foundry-sample-* repositories, listed 2026-11-09)
- https://library.humio.com/falcon-logscale-collector/log-collector-config-advanced-example.html (fetched 2026-11-09)
- https://code.claude.com/docs/en/hooks (fetched 2026-11-09)
- https://oem.avira.com/en/solutions/anti-malware (fetched 2026-11-09)
- https://www.bitdefender.com/oem/ (fetched 2026-11-09)
- https://docs.clamav.net/manual/Development/libclamav.html (fetched 2026-11-09)
- https://blog.clamav.net/2025/10/clamav-150-released.html (2025-10-07)
- https://suricata.io/features/open-source/ (fetched 2026-11-09)
- https://github.com/VirusTotal/yara-x (v1.23.0, 2026-11-05)
- https://github.com/SigmaHQ/Detection-Rule-License (DRL 1.1)
- https://github.com/osquery/osquery/blob/master/LICENSE and https://osquery.readthedocs.io/en/stable/development/osquery-sdk/
- https://falco.org/docs/concepts/plugins/ (2024-12-17) and https://github.com/falcosecurity/libs/blob/master/userspace/plugin/plugin_api.h (API 3.12.0)
- https://github.com/falcosecurity/plugins/blob/main/registry.yaml
- https://www.openpolicyagent.org/docs/integration (fetched 2026-11-09)
- https://opentelemetry.io/docs/collector/extend/ocb/ (fetched 2026-11-09)
- https://github.com/open-telemetry/semantic-conventions-genai (pushed 2026-11-09)
- https://github.com/wazuh/wazuh/blob/main/LICENSE and https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- https://github.com/elastic/detection-rules/blob/main/LICENSE.txt (Elastic License 2.0)
- https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-etw (fetched 2026-11-09)
- https://www.elastic.co/docs/solutions/security/endpoint-response-actions/third-party-response-actions (fetched 2026-11-09)
- https://developer.sophos.com/intro (fetched 2026-11-09)
- https://www.bitdefender.com/business/support/en/77209-125277-public-api.html (index only)
- https://developer.apple.com/documentation/endpointsecurity/es_new_client_result_t (fetched 2026-11-09)

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: primary documentation re-fetched directly, sibling pages the brief did not rely on for the claim, and the GitHub API (read-only). The shared web-search budget was exhausted, so no search-engine, forum or news sources were consulted; every verdict rests on vendor documentation or repository contents._

### The ten architecture claims

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Defender local agent discovery and runtime protection both need Defender Antivirus in active mode with real-time protection, except VS Code extension inventory | Confirmed | Both prerequisite lists say so. The exception is narrower than it sounds: it covers agent inventory for the footnoted VS Code extensions only; MCP server configuration discovery for those extensions still needs active mode and real-time protection, and the exception gives no runtime protection. | https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents ; https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection |
| 2 | Copilot Studio external threat detection: `POST /validate`, `POST /analyze-tool-execution`, `api-version=2025-05-01`, under 1,000 ms, allow on timeout, Entra federated-credential auth | Confirmed, with two caveats | Endpoints, version, budget and default all match. Caveats: (a) the timeout/error behaviour is an admin setting ("Allow the agent to respond" by default, "Block the query" selectable), so fail-open is a default, not a fixed property; (b) the customer-side page is still titled "(preview)" and says preview features are not meant for production use. Auth is a customer Entra app with a Federated Identity Credential; the provider validates the Entra bearer token and decides how to authorise the app ID. It is called only for generative-orchestration agents. | https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider ; https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers |
| 3 | Defender agent-native runtime protection uses vendor hook interfaces (Claude Code hooks, GitHub Copilot hooks), is Windows-only preview, and network inspection does not support certificate pinning or HTTP/3 | Confirmed | Overview page independently states "vendor-supported event interfaces" and "Network inspection doesn't support agents that use certificate pinning or HTTP/3". Support matrix lists runtime protection under "Windows (preview)" only. Hook-based coverage today: Claude Code, Claude Desktop (Code mode), VS Code Claude Code extension, GitHub Copilot CLI, app and VS Code extension. The overview names Codex CLI as exposing such an interface, but the matrix does not list it as supported. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview ; https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix |
| 4 | Claude Code runs matching hooks in parallel, merges hook entries across settings levels, supports command/http/mcp_tool/prompt/agent handlers, and managed settings can restrict hooks with `allowManagedHooksOnly` and `allowedHttpHookUrls` | Confirmed, with nuances | All four points are in the hooks reference. Nuances that matter for a broker: identical handlers defined in several settings files run once; above 12 prompt/agent hooks only 12 run at a time; agent hooks are marked experimental; `allowedHttpHookUrls` takes effect when defined at any settings level (merged allowlist), not only in managed settings; with `allowManagedHooksOnly`, user, project, local and plugin hooks are blocked, so every vendor must be in managed settings. Conflicting PreToolUse decisions resolve as deny > defer > ask > allow; behaviour when several hooks return `updatedInput` is not documented. | https://code.claude.com/docs/en/hooks |
| 5 | Any application can submit to AMSI; providers are in-process COM DLLs under `HKLM\SOFTWARE\Microsoft\AMSI\Providers`, must be Authenticode-signed since Windows 10 1903, and cannot load into PPL processes | Corrected | Submission, in-process COM provider, registry key and the PPL limit are confirmed. The signing statement is wrong as written: Windows 10 1903 added an Authenticode signing check for providers that is disabled by default (`HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits`: 0x1 off and default, 0x2 on). An unsigned provider "may not be loaded (depending on how the host machine is configured)". Signing is effectively required only on hosts that enable the check, though any shipping provider should be signed. | https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider ; https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal ; https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience |
| 6 | libclamav is GPLv2 and its docs say closed-source software may not link it; Suricata is GPLv2, copyright held by OISF, non-GPL licence sold through consortium membership | Confirmed, wording softened | ClamAV repo reports GPL-2.0 and the docs say "you are not allowed to link commercial, closed-source software against it". Suricata's LICENSE is GPLv2 and suricata.io says the copyright is owned by OISF and that non-GPL licensing is "offered through OISF"; the page tells readers to contact OISF "to inquire about a non-GPL license and join the OISF consortium". No public page states price or that membership alone grants the licence; the OISF consortium page does not mention licensing at all. Treat "sold through membership" as the documented route, terms unpublished. | https://suricata.io/features/open-source/ ; https://oisf.net/consortium/ ; https://github.com/OISF/suricata/blob/master/LICENSE ; https://github.com/Cisco-Talos/clamav |
| 7 | YARA-X: BSD-3-Clause, v1.23.0 on 2026-11-05, Rust crate, C API, Go, Python, JS/WASM bindings and CLI in one repo | Confirmed | GitHub API: licence BSD-3-Clause; release v1.23.0 published 2026-11-05T12:56Z, not a pre-release; top-level directories `lib`, `capi`, `go`, `py`, `js-wasm`, `cli` (plus `parser`, `fmt`, `ls`, `macros`, `proto`). | https://github.com/VirusTotal/yara-x |
| 8 | Falcon LogScale Collector sources: file, Windows Event Log, syslog, macOS unified logs, journald, exec, database; no ETW. Elastic filebeat ETW input is GA for manifest, MOF and TraceLogging providers | Confirmed | The collector's Sources reference (versions 1.9.0 to 1.12.2) lists type values `cmd`, `file`, `internal`, `journald`, `mssql`, `mysql`, `oracle`, `postgres`, `syslog`, `syslog_tls`, `unifiedlog`, `wineventlog`. No ETW type. The brief's list omits `internal` and `syslog_tls`, which changes nothing. Elastic's doc source carries `applies_to: stack: ga, serverless: ga` and states manifest-based, MOF and TraceLogging are supported and WPP is not; admin rights required. | https://library.humio.com/falcon-logscale-collector/log-collector-config-common-sources.html ; https://github.com/elastic/beats/blob/main/docs/reference/filebeat/filebeat-input-etw.md |
| 9 | Sigma rules are DRL 1.1 with author attribution required in views that show matches; Elastic detection rules are Elastic License 2.0; Wazuh's engine is AGPL-3.0-or-later | Confirmed, one timing caveat | DRL 1.1 text: when rules are used on data, "messages based on matches with the Rules" must keep the author identification. SigmaHQ/sigma LICENSE confirms rules are DRL 1.1 and the specification is public domain. elastic/detection-rules LICENSE.txt is Elastic License 2.0. Wazuh: the AGPL-3.0-or-later engine licence is on `main` and in the 5.0.0 release candidates (rc2, 2026-10-30) only. The latest stable release, v4.14.10 (2026-11-09), is GPLv2 throughout and has no `src/engine/`. Shared libraries the engine links are dual `GPL-2.0-only OR AGPL-3.0-or-later`. | https://github.com/SigmaHQ/Detection-Rule-License ; https://github.com/SigmaHQ/sigma/blob/master/LICENSE ; https://github.com/elastic/detection-rules/blob/main/LICENSE.txt ; https://github.com/wazuh/wazuh/blob/main/LICENSE |
| 10 | Defender XDR custom detections take automated device actions only when the rule uses Defender data; Sentinel-only data supports 5-minute to 14-day frequency; 150 alerts per run | Confirmed | "If your custom detection rule uses Defender data, it can automatically take actions on devices, files, users, or emails." Device actions: isolate, collect investigation package, antivirus scan, initiate investigation, restrict app execution. Quarantine and allow/block are file actions, not device actions. Custom frequency "from 5 minutes to 14 days" applies only when the rule is based solely on Sentinel-ingested data. "Each rule can generate only 150 alerts each time it runs." Device actions key on `DeviceId` in the results, so events we ingest through the Logs Ingestion API alone cannot drive isolation; the rule must join to Defender tables. | https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules |

### Further statements in the brief

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| TL;DR: "An open verdict-provider contract already exists in production: Copilot Studio's external threat detection webhook" | Corrected (overstated) | The contract is published and Microsoft Defender uses it, but Microsoft's configuration page is still titled "(preview)", is flagged as prerelease documentation, and says preview features are not meant for production use. Describe it as a published preview interface, and expect the schema to move. | https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider |
| Part 1: "Wazuh's engine (`src/engine/`) is now AGPL-3.0-or-later with the rest GPL-2.0" | Corrected (timing) | True for `main` and 5.0.0 release candidates. Not true for any generally available Wazuh release as of 2026-11-09; 4.14.x is GPLv2 only. Also "the rest GPL-2.0" skips the dual-licensed shared libraries. | https://github.com/wazuh/wazuh/releases ; https://github.com/wazuh/wazuh/blob/v4.14.10/LICENSE |
| TL;DR and Part 2: Claude Code merges hooks and runs them in parallel, "so coexistence works" | Confirmed, but incomplete | Coexistence holds for allow/deny decisions (documented precedence deny > defer > ask > allow, which matches the proposed deny-wins broker). It is not established for input rewriting: the docs do not say which `updatedInput` wins when several parallel hooks return one. And when an administrator sets `allowManagedHooksOnly`, only managed hooks and hooks from force-enabled managed plugins run, so a second vendor's user-level or plugin hook is silently dropped. | https://code.claude.com/docs/en/hooks |

Also spot-checked and found accurate: Agent 365 generally available 2026-05-01 on a per-user basis; ClamAV 1.5.0 released 2025-10-07; Falco plugin API 3.12.0 with `get_required_api_version`; osquery `Apache-2.0 OR GPL-2.0-only`; `open-telemetry/semantic-conventions-genai` exists as a separate repository (created 2026-05-05); Elastic third-party response actions for CrowdStrike, Defender and SentinelOne as listed; CrowdStrike Falcon AIDR hook list and "coming soon" items; BeyondTrust tenant root certificate requirement, Windows/macOS-only support and policy replay.
