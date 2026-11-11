# Integration catalogue and integration framework for an open-source AIDR

_Researched 2026-11-09_

Method note: web search was unavailable for this run (shared search budget exhausted), so everything below comes from fetching vendor documentation directly and from read-only GitHub API calls. Claims are tagged **[V]** (verified today against the cited source) or **[K]** (from pre-2026 knowledge, not re-verified; treat as possibly stale).

## TL;DR

- **Vendors now expose "bring your own security server" verdict webhooks.** Anthropic Inference hooks (Claude Enterprise: `prompt` and `tool_call` events, allow/deny, 5 s default budget) and Copilot Studio external threat detection (`POST /analyze-tool-execution`, 1 s budget, fail-open by default) both call an external HTTPS service before an action runs. Our policy decision point should be that server. [V]
- **OCSF 1.9.0 (3 Aug 2026) is the first release with a real agent model**: `ai_operation` profile, `ai_agent` object (distinct from the sensor `agent`), `delegation`, `hosted_ai_agent_list` on `process`. `ai_capability` (MCP tool/resource/prompt) and `ai_status` are merged but unreleased. [V]
- **Amazon Security Lake custom sources accept OCSF 1.3 and earlier only**, as Parquet, max 50 custom sources per account. The AI profile cannot land there natively; a down-converter is required. [V]
- **Google SecOps Ingestion API is deprecated and shuts down 20 July 2027**; build against the Chronicle API. [V]
- **OpenTelemetry GenAI conventions moved to their own repo** (`open-telemetry/semantic-conventions-genai`, created May 2026) and are still "Development" status, including agent, MCP and A2A conventions. Pin a version; expect renames. [V]
- **Microsoft already deprecated the Agent 365 Observability SDK** (Oct 2026) in favour of the Microsoft OpenTelemetry Distro, which exports to Agent 365, Azure Monitor and any OTLP endpoint at once. OTLP is the lingua franca for agent telemetry. [V]
- **EDR incumbents ship agent inventory.** Defender for Endpoint discovers roughly 60 named local agents on Windows and macOS into the `AgentsInfo` hunting table (Plan 2 licence); CrowdStrike exposes an `/aidr/*` read API (agents, sessions, tools, skills, MCP server names, prompts, detections). Ingest these; do not only compete with them. [V]
- **Envoy AI Gateway was renamed Agent Router** (`theagentrouter/agent-router`, Agentic AI Foundation project); CRDs, images and the `aigw` CLI are unchanged. [V]
- **LiteLLM ships about 70 guardrail adapters and a vendor-neutral "Generic Guardrail API"** (`POST /beta/litellm_basic_guardrail_api`). Implementing that one contract makes us pluggable into LiteLLM without upstream code. [V]
- **The catalogues that scale are declarative-first**: Elastic (513 packages, YAML plus ingest pipelines), Airbyte (703 connector directories, mostly YAML manifests), Tracecat (YAML action templates over a few Python clients), Sentinel CCF (JSON, no code). Code plugins are the exception and are isolated by process, container or nsjail. [V]
- **Claude Code is the richest first-party integration surface**: about 30 hook events, an `http` hook type, `allowManagedHooksOnly`, `allowedHttpHookUrls`, OTel metrics/events/traces, plus the Compliance API for after-the-fact transcripts. [V]

## Findings

### 1. The seeds: what BeyondTrust and Microsoft document

**BeyondTrust AI Agent Security** (docs updated 2026-10-13). Endpoint "Pathfinder agent" on Windows 11 / Server 2022+ x64 (no Arm) and macOS 14, 15, 26. No Linux. Discovers coding tools, desktop AI apps, MCP servers, skills and the LLM endpoints they call, using process naming, signatures and LLM API traffic patterns. Enforcement is "at the kernel and network levels", with tool-call policy via hooks where the coding tool supports them; decisions are allow, audit, hold for approval, block. Requires endpoints to trust a tenant root certificate for HTTPS inspection. Policy can be replayed against recorded activity before saving. The docs describe no event export, API or connector. [V] https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security

**Microsoft Agent 365** (GA 1 May 2026, per-user licence, "works best" with E5). Registry in the M365 admin center, Entra Agent ID, Purview and Defender. Vertex AI and Bedrock agents can be registered automatically. Partner list has two classes: ready-to-deploy agents and "agent factories" (n8n, Kore, Kasisto, NVIDIA) whose agents inherit an Entra Agent ID. [V] https://learn.microsoft.com/en-us/microsoft-agent-365/overview , https://learn.microsoft.com/en-us/microsoft-agent-365/third-party-agents

- Telemetry: `pip install microsoft-opentelemetry`, `npm install @microsoft/opentelemetry`, `dotnet add package Microsoft.OpenTelemetry`; `use_microsoft_opentelemetry(enable_a365=True)`. Agent telemetry surfaces in Purview audit and Defender `CloudAppEvents`. [V] https://learn.microsoft.com/en-us/microsoft-agent-365/developer/microsoft-opentelemetry
- Defender for Endpoint local discovery: GA on Windows (AV platform 4.18.26090.9+) and macOS (101.26072.0017+); native Linux absent, WSL in preview for three CLIs. Tables: `AgentsInfo` (`Platform == "LocalAgents"`, `RawAgentInfo.localAgentMetadata` with `autoApprove`, `trustedProcess`, `localMcps`), `ExposureGraphNodes/Edges`. Risk scoring needs M365 E7 or Agent 365. Runtime protection is Windows preview, via agent-native hooks (Claude Code, Copilot CLI/app) or network inspection (no cert-pinned or HTTP/3 traffic). [V] https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents , https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix
- Copilot Studio external threat detection (preview): provider implements `POST /validate` and `POST /analyze-tool-execution?api-version=2025-05-01`; body carries `plannerContext` (user message, thought, chat history, previous tool outputs), `toolDefinition`, `inputValues`, `conversationMetadata`; response `{blockAction, reasonCode, reason, diagnostics}`; under 1,000 ms or the tool runs; Entra federated identity credential auth; configured per environment with no tenant-wide switch. [V] https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers

### 2. Model providers and agent vendors

**Anthropic.** [V]
- Compliance API: `/v1/compliance/*`, Activity Feed `GET /v1/compliance/activities` (cursor `after_id`, limit up to 5,000, queryable within 1 minute, retained 6 years, not backfilled before enablement), 600 requests/min per parent org. Actor is a discriminated union (`user_actor`, `api_actor`, `admin_api_key_actor`, `scim_directory_sync_actor`, `system_actor`, ...). Session endpoints return Claude Code, Cowork, Claude in Chrome transcripts. https://platform.claude.com/docs/en/manage-claude/compliance-api
- Inference hooks: Enterprise only; not on Bedrock or Google Cloud; API-platform orgs out of scope. Signed per Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature` HMAC-SHA256). Frame has `request_id`, `actor` (`id`, `email_address`), `session_id`, `model`, `messages`. Verdict `{"action":"allow"|"deny","deny_reason":<=500 chars}`; no redaction. Timeout 1 to 10,000 ms (default 5,000), one retry on connection failure only, configurable fail-open/closed, circuit breaker, shadow mode, rollout percentage. https://platform.claude.com/docs/en/manage-claude/inference-hooks
- Claude Code hooks: `PreToolUse` returns `permissionDecision` allow/deny/ask/defer plus `updatedInput`; handler types `command`, `http`, `mcp_tool`, `prompt`, `agent`; a timed-out `PreToolUse` hook does not block unless `onFailure: "block"`. https://code.claude.com/docs/en/hooks
- Claude Code OTel: events `claude_code.tool_decision`, `tool_result`, `user_prompt`, `api_request`, `mcp_server_connection`; content redacted unless opted in; managed settings lock the collector endpoint. https://code.claude.com/docs/en/monitoring-usage

**OpenAI, Google, Bedrock, Vertex, OpenRouter.** Not verified this run (OpenAI docs returned 403). [K] OpenAI has an org Audit Logs API and an Enterprise Compliance API; Bedrock has model invocation logging to S3/CloudWatch; Vertex has Cloud Audit Logs.

### 3. SIEM, data lakes and pipelines

- **Sentinel**: Logs Ingestion API (`POST {endpoint}/dataCollectionRules/{dcrImmutableId}/streams/{stream}`, Entra client-credential bearer, DCR with KQL transform, custom tables end `_CL`, TLS 1.2+ enforced since 1 Mar 2026). Codeless Connector Framework kinds `RestApiPoller`, `GCP`, `StorageAccountBlobContainer`; packaged as a Content hub solution (template version 3.0.0+, custom connectors are tier "Community"). Data lake stores Parquet, up to 12 years, fed by all existing connectors. [V] https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview , https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector , https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-overview
- **Google SecOps**: legacy endpoints `udmevents:batchCreate`, `unstructuredlogentries:batchCreate`; 1 MB per log; retiring 20 July 2027. [V] https://docs.cloud.google.com/chronicle/docs/reference/ingestion-api
- **Security Lake**: see TL;DR; partition `ext/{source}/region=/accountId=/eventDay=`; one OCSF class per source. [V] https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html
- **CrowdStrike NG-SIEM**: query API is LogScale-shaped (`/humio/api/v1/repositories/{repository}/queryjobs`); Foundry sample apps exist for NG-SIEM import. [V] https://github.com/CrowdStrike/falconpy . Ingest via HEC-style data connectors. [K]
- **Splunk HEC, Elastic `_bulk`/ECS, XSIAM HTTP collector, QRadar (syslog LEEF), Datadog/Sumo HTTP intake, Wazuh, Graylog (GELF)**: [K]. Wazuh's own outbound integrations are five Python scripts (`slack.py`, `pagerduty.py`, `virustotal.py`, `shuffle.py`, `maltiverse.py`) in v4.14. [V]
- **Pipelines** (Cribl, Tenzir v6.21 BSD-3, Vector v0.61 MPL-2.0): all accept HTTP, syslog, OTLP or S3. Supporting OTLP plus OCSF JSON over HTTP covers them without bespoke connectors. [V versions; K capability]

### 4. EDR/XDR, identity, devices

- **CrowdStrike**: OAuth2 API; host containment is `PerformActionV2` with `action_name: contain` (Hosts: Write); Real Time Response collections; `mssp` (Flight Control) collection for child CIDs; `aidr` collection is read-only today. [V] https://github.com/CrowdStrike/falconpy , https://github.com/TracecatHQ/tracecat
- **Defender**: read via advanced hunting (`AgentsInfo`, `CloudAppEvents`); isolate via machine actions API. [V tables; K actions]
- SentinelOne, Cortex XDR, Elastic Defend, Sophos, Trend, Bitdefender, Tanium, osquery/Fleet (v4.94): REST APIs for isolate/kill/script. [K]
- **Shared signals**: OpenID SSF 1.0 (spec dated 29 Aug 2025): push RFC 8935, poll RFC 8936, discovery at `/.well-known/ssf-configuration`, complex subjects (`user`, `device`, `session`, `application`, `tenant`). Okta receiver: register at `POST /api/v1/security-events-providers`, send SETs to `POST /security/api/v1/security-events`; needs Identity Threat Protection; feeds entity risk policy and Universal Logout. [V] https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html , https://developer.okta.com/docs/guides/configure-ssf-receiver/main/
- **SCIM for agents**: `draft-abbey-scim-agent-extension-00` (Oct 2025) is an expired individual draft. No standard yet. [V] https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension/
- Entra, Ping, Google Workspace, JumpCloud, Keycloak (OIDC/SAML/SCIM 2.0), Intune (Graph), Jamf, Kandji, Workspace ONE, ServiceNow CMDB, Axonius: [K].

### 5. Gateways and guardrail engines

- **LiteLLM** (v1.108.4): adapters include `crowdstrike_aidr`, `agent_365`, `microsoft_purview`, `model_armor`, `panw_prisma_airs`, `cisco_ai_defense`, `zscaler_ai_guard`, `lakera_ai_v2`, `bedrock_guardrails`, `presidio`, `mcp_security`, `tool_permission`. Generic contract: request `texts`, `images`, `tools`, `tool_calls`, `structured_messages`, `request_data` (key, user, team, org), `input_type`; response `action` BLOCKED / NONE / GUARDRAIL_INTERVENED, `blocked_reason`, modified `texts`; `unreachable_fallback: fail_closed`. [V] https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api
- **agentgateway** (v1.7.0, Apache-2.0, Rust): `policies.ai.promptGuard` with regex and built-in recognisers. [V] https://github.com/agentgateway/agentgateway
- **Agent Router** (v1.2.1): see TL;DR. [V] https://github.com/theagentrouter/agent-router
- **Bedrock `ApplyGuardrail`**: `POST /guardrail/{id}/version/{v}/apply`, `source: INPUT|OUTPUT`, returns `action` and per-policy `assessments`; works without invoking a model. [V] https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html
- **Azure Prompt Shields**: `userPrompt` plus up to five `documents`, returns `attackDetected`; the API never blocks by itself; tool-response scanning is preview. [V] https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection
- **Google Model Armor**: `SanitizeUserPrompt`, `SanitizeModelResponse`; single-turn only; injection filter returns no match under three words. [V] https://docs.cloud.google.com/model-armor/overview
- Portkey, Kong, Cloudflare AI Gateway, Lakera, Prisma AIRS, Cisco AI Defense APIs: not verified. [K]

### 6. Intelligence, registries, GRC

- **MCP Registry**: API frozen at v0.1 since 24 Oct 2025 (`GET /v0.1/servers`, `/v0.1/servers/{name}/versions/{version}`), cursor pagination, subregistry model with optional auth; README still describes preview. [V] https://github.com/modelcontextprotocol/registry
- OpenCTI connectors repo (Apache-2.0): 187 external-import, 84 enrichment, 40 stream connectors, each a container. MISP v2.5.50. Sigma release r2026-07-01. OSCAL v1.2.3 (Aug 2026). [V via GitHub]
- TAXII 2.1/STIX 2.1, OSV API, CISA KEV JSON, Vanta/Drata APIs, Purview label and `processContent` Graph APIs, MSP PSA/RMM APIs (ConnectWise, Kaseya/Datto, NinjaOne, N-able, HaloPSA, Pax8): [K], not verified this run.

### 7. How open-source catalogues are structured and sandboxed

| Project | Unit of contribution | Code? | Isolation | Quality gates |
|---|---|---|---|---|
| Elastic integrations (513 packages; package-spec v3.7.0) | `manifest.yml`, `data_stream/`, ingest pipelines, dashboards, `changelog.yml`, `_dev` tests | No (declarative; agent inputs do the I/O) | None needed | Spec validation, pipeline golden tests |
| OTel Collector contrib (v0.165.1; 114 receivers, 47 exporters, 40 processors) | Go module + `metadata.yaml` (stability per signal, codeowners, distributions) | Yes, compiled in | None; in-process | Named codeowner, stability ladder |
| Vector (v0.61.0) | Rust source/sink in-tree; user logic in VRL | In-tree only | VRL is a safe expression language | Core review |
| Airbyte (703 connector dirs) | `manifest.yaml` (`streams`, `check`, `spec`) via Connector Builder | Optional Python components | One container per connector | Acceptance tests |
| Tracecat (AGPL-3.0, 1.5.0-alpha.1) | YAML action template (`expects`, `steps`, `returns`) over a generic client UDF | Python UDFs | nsjail executor (default on Kubernetes only; `pid` runtime explicitly unsupported for breakout reports) | Template schema |
| Shuffle (AGPL-3.0) | `api.yaml` (OpenAPI-derived) + `Dockerfile` + `src/` per version | Python | One container per app | - |
| Steampipe | Go plugin via SDK (Apache-2.0) | Yes | Separate process over gRPC [K] | Table/doc standards, release checklist |
| OpenCTI connectors | Container per connector, typed by role | Python | Container | Role taxonomy |

Sources: https://github.com/elastic/integrations , https://github.com/open-telemetry/opentelemetry-collector-contrib , https://docs.airbyte.com/platform/connector-development/config-based/low-code-cdk-overview , https://github.com/TracecatHQ/tracecat/blob/main/SECURITY.md , https://github.com/Shuffle/python-apps , https://github.com/turbot/steampipe-plugin-sdk

## Matrix: prioritised catalogue

Tier: P0 = needed for first enterprise pilot, P1 = within two releases, P2 = community/partner driven. Programme column is [K] unless marked.

| Category | Dir | Mechanism / format | Tier | Certification or marketplace |
|---|---|---|---|---|
| Generic sinks | out | Standard Webhooks-signed HTTP, syslog (CEF/LEEF), OTLP logs, OCSF JSON/Parquet to S3-compatible | P0 | - |
| Splunk | out | HEC JSON; CIM field aliases | P0 | Splunkbase (AppInspect) |
| Microsoft Sentinel + data lake | out, in | Logs Ingestion API + DCR; CCF solution; hunt `AgentsInfo` | P0 | Content hub solution (Community vs Partner tier) [V] |
| CrowdStrike NG-SIEM / Falcon | out, in, act | HEC connector; `/aidr/*` read; contain, RTR | P0 | CrowdStrike Marketplace, Foundry apps |
| Elastic | out | `_bulk`, ECS, an Elastic integration package | P0 | elastic/integrations PR |
| Google SecOps | out | Chronicle API (not legacy Ingestion API), UDM | P1 | Google Cloud Marketplace |
| XSIAM, QRadar, Sumo, Datadog, Panther, Wazuh, Graylog | out | HTTP collector / syslog / OCSF | P1-P2 | Cortex Marketplace, IBM App Exchange, Datadog Marketplace |
| Security Lake, Snowflake, Databricks | out | Parquet; OCSF 1.3 down-conversion for Security Lake | P1 | AWS partner source |
| Cribl, Tenzir, Vector | out | OTLP / HTTP / S3; ship a pack | P1 | Cribl Packs |
| EDR/XDR (Defender, SentinelOne, Cortex, Elastic Defend, Sophos, Trend, Bitdefender, Tanium, Fleet/osquery) | in, act | REST: inventory, process telemetry, isolate/kill | P1 (Defender, S1), P2 rest | Vendor marketplaces |
| SOAR / AI SOC (Tines, Torq, XSOAR, Splunk SOAR, Swimlane, Shuffle, Tracecat) | both | Our REST + webhooks + MCP server; ship Tracecat templates and a Shuffle `api.yaml` | P1 | XSOAR content pack |
| Chat approvals (Slack, Teams, Google Chat) | both | Block Kit actions / Adaptive Cards; signed callbacks | P0 Slack, Teams | Slack Marketplace, Teams Store |
| Ticketing and paging (ServiceNow, Jira, PagerDuty, incident.io) | both | Table API, Jira REST, Events API v2 | P0 Jira, PagerDuty; P1 ServiceNow | ServiceNow Store, Atlassian Marketplace |
| IdP and HR (Entra, Okta, Ping, Google, JumpCloud, Keycloak) | in, out | OIDC/SAML SSO, SCIM 2.0, SSF/CAEP transmit and receive | P0 SSO+SCIM, P1 SSF | Okta Integration Network, Entra gallery |
| Device and asset (Intune, Jamf, Kandji, WS1, Fleet, CMDB, Axonius) | in, deploy | Inventory APIs; MDM profiles to deploy sensor and managed settings | P1 | - |
| Secrets (Vault/OpenBao, AWS/GCP/Azure, 1Password, CyberArk, Doppler, Infisical, Akeyless, Bitwarden) | in, act | Read audit logs; revoke/rotate on detection; broker short-lived creds | P1 Vault + clouds, P2 rest | - |
| Dev platforms (GitHub, GitLab, Bitbucket, Azure DevOps) | in, act | Audit log streams, app webhooks, checks, secret-scanning alerts | P0 GitHub, P1 rest | GitHub Marketplace |
| Agent hooks (Claude Code, Cursor, Copilot, Codex, Gemini CLI) | in, enforce | Native hooks, managed settings, OTel | P0 | - |
| Provider admin/compliance (Anthropic, OpenAI, Azure OpenAI, Bedrock, Vertex, OpenRouter) | in, enforce | Compliance API polling, Inference hooks server, audit logs | P0 Anthropic, OpenAI; P1 rest | - |
| Agent platforms (Agent 365/Entra Agent ID, Copilot Studio, Bedrock Agents, Vertex) | in, enforce | Registry sync; `analyze-tool-execution` provider; OTLP | P1 | Agent 365 partner ecosystem [V] |
| AI gateways (LiteLLM, agentgateway, Agent Router, Portkey, Kong, Cloudflare) | in, enforce | Generic Guardrail API, ext_proc/ext_authz, log export | P0 LiteLLM, P1 rest | - |
| Guardrail engines as detectors | call out | ApplyGuardrail, Prompt Shields, Model Armor, Lakera, AIRS, AI Defense, local models | P1 | - |
| DLP and classification (Purview, Google labels, DSPM) | in | Read labels; map to policy conditions | P2 | - |
| GRC (Vanta, Drata, ServiceNow GRC) | out | Evidence push; OSCAL component definition | P2 | - |
| Threat and vuln intel (MISP, OpenCTI, TAXII, OSV, KEV, package feeds, MCP registries) | in | STIX 2.1, OSV schema, registry API v0.1 | P0 OSV, KEV, MCP registry; P1 rest | - |
| MSP (ConnectWise, Kaseya/Datto, NinjaOne, N-able, HaloPSA, Pax8) | both | PSA tickets and billing usage; RMM deploy scripts | P1 for MSP edition | ConnectWise and Pax8 marketplaces |

## Weak points, gaps and risks

- **Latency budgets are hostile.** Copilot Studio allows 1 s and fails open by default; Claude Code hook timeouts do not block unless `onFailure: "block"`. A cloud-only decision point will silently fail open. [V]
- **Verdict webhooks are allow/deny only** (Anthropic states no rewriting or redaction; image bytes never sent). DLP by redaction needs the gateway or in-agent path. [V]
- **Schema drift on both standards.** OTel GenAI is Development status in a six-month-old repo; OCSF's MCP-level `ai_capability` is unreleased. [V]
- **Sink lag.** Security Lake at OCSF 1.3; most SIEM parsers will not know `ai_agent`. Expect to ship parsers, dashboards and detections per SIEM, which is the real cost of each "integration".
- **Licence contagion.** Tracecat and Shuffle are AGPL-3.0; Elastic and Airbyte repos are not plain OSI licences. Contribute content to them; do not vendor their code. [V]
- **Coverage gaps incumbents leave**: BeyondTrust has no Linux and documents no export; Defender has no native Linux, no cert-pinned or HTTP/3 inspection, and runtime protection is Windows preview. [V]
- **Per-environment configuration** (Copilot Studio has no tenant-wide switch) makes drift likely; needs continuous posture checks. [V]

## Implications for our design

1. **One policy decision point, many front doors.** Build thin adapters that translate into one internal `Decision(request) -> allow | deny | ask | modify` call: Anthropic Inference hooks server, Copilot Studio threat-detection provider, LiteLLM Generic Guardrail API, Claude Code/Copilot/Cursor HTTP hooks, Envoy ext_proc for Agent Router and agentgateway. Each adapter declares its capability set (can redact? can ask? budget in ms).
2. **Local-first evaluation with a hard deadline.** Evaluate in the endpoint daemon or a regional edge; return a cached or default verdict before the caller's budget (target p99 under 300 ms for the 1 s integrations). Fail-mode is an explicit per-adapter policy field.
3. **Canonical event = OCSF 1.9 with `ai_operation`**, stored natively; ingest OTLP using pinned GenAI conventions and map into it. Ship versioned down-converters: OCSF 1.3 (Security Lake), ECS, UDM, ASIM/custom `_CL`, CIM, CEF. Treat mappings as data files with golden tests.
4. **Three plugin tiers.**
   - Tier A, declarative YAML (target 80 percent): HTTP sink, poller with cursor, webhook receiver, action template. Fields: auth scheme, pagination, rate limit, mapping, required scopes, egress hosts.
   - Tier B, WebAssembly components run in-process by the Rust host (wasmtime; Extism v1.41 BSD-3 is an option) with capability grants: allowed hosts, named secrets, no filesystem.
   - Tier C, out-of-process (gRPC over stdio, or container) for vendor SDKs. Never load third-party native code into the sensor.
5. **Manifest metadata copied from OTel contrib**: `stability` per capability, `codeowners`, `distributions` (core, community, partner), plus `direction`, `data_classes` handled, and minimum permission scopes.
6. **Signing and supply chain**: Sigstore keyless signatures and SLSA provenance on every integration bundle; registry index is a signed, git-reviewable file; self-hosted installs can pin a mirror. Outbound webhooks follow Standard Webhooks so receivers can reuse libraries.
7. **Testing kit**: `integration test` runs recorded request/response fixtures against a mock server, validates emitted events against the OCSF schema, and replays golden inputs through mappings. No live credentials in CI; a nightly partner-sandbox lane where available.
8. **Importers before exporters.** First-run value comes from pulling existing truth: Defender `AgentsInfo`, CrowdStrike `/aidr/*`, Agent 365 registry, Anthropic Compliance directory and settings, MCP registry, LiteLLM `config.yaml` guardrails, Claude Code managed settings (hooks, permissions).
9. **Import/export requirements**:
   - Policy as code in git, compiled to a signed bundle (OPA-style bundle layout; Cedar v4 or Rego as the evaluated language is a separate decision).
   - Terraform provider (plugin framework) covering tenants, policies, integrations, destinations, exceptions.
   - Detection export as Sigma; IOC exchange as STIX 2.1/TAXII 2.1; compliance evidence as OSCAL component definitions.
   - Portable tenant bundle (config + policies + mappings) for SaaS to self-hosted moves and MSP templating.
10. **Expose ourselves as an MCP server and a webhook source**, so SOAR and AI SOC tools integrate without bespoke apps; ship Tracecat templates and a Shuffle `api.yaml` generated from our OpenAPI.

## Ideas worth stealing and whitespace

- **Policy replay** against recorded activity before enforcing (BeyondTrust) and **shadow mode plus rollout percentage** (Anthropic). Make both first-class for every adapter.
- **`deny_reason` written for the end user**, separate from the analyst reason code (Anthropic guidance; Copilot Studio `reason` vs `reasonCode`).
- **Agent profile as a graph node** with `runs on`, `uses` (MCP server), `used by` edges (Defender exposure graph). Whitespace: nobody documents this for Linux servers, Kubernetes or CI.
- **Declared vs observed tool behaviour**: OCSF `ai_capability` carries self-declared hints and schema/description fingerprints. Fingerprint drift detection for MCP tools ("rug pull") is a natural detector.
- **Whitespace**: a vendor-neutral verdict protocol. Three incompatible contracts exist (Anthropic, Copilot Studio, LiteLLM). An open spec with a conformance suite, implemented by our adapters, is a credible standards play.
- **Whitespace**: SSF/CAEP transmitter for agent risk (for example session-revoked on agent compromise) with `application` and `session` subjects; no AIDR vendor documents one.
- **Whitespace**: MSP multi-tenancy patterned on CrowdStrike Flight Control `member_cid`, with PSA ticket and usage-billing sync.

## Could not verify / open questions

- OpenAI Audit Logs and Compliance API details (403); Prisma AIRS scan API (404); Okta help-centre SSF page (404). Web search unavailable.
- Splunk HEC, XSIAM, QRadar, Datadog, Slack (3 s ack, Socket Mode marketplace limits), Teams Adaptive Card approvals, ServiceNow, Jira, PagerDuty, secrets managers, MDM, GRC and every MSP API are from prior knowledge.
- Does Sentinel CCF offer a GA push kind for third parties? The page fetched is titled "pull" and lists three poll-style kinds.
- OCSF release that will carry `ai_capability`/`ai_status` (presumably 1.10) and its date.
- Whether Anthropic will extend Inference hooks to API-platform organisations or add redaction.
- Cursor, Codex, Copilot and Gemini CLI hook contracts were not examined here (assumed covered by a sibling brief).
- Elastic and Airbyte licence terms for redistributing derived manifests.

## Sources

- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - AI Agent Security (BeyondTrust), 2026-10-13
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Microsoft Agent 365 overview, 2026-10-23
- https://learn.microsoft.com/en-us/microsoft-agent-365/third-party-agents - Ecosystem partner agents, 2026-10-02
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/microsoft-opentelemetry - Microsoft OpenTelemetry Distro, 2026-10-23
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents - Discover local AI agents, 2026-11-03
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix - AI agent support matrix, 2026-11-03
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai - Enable security for AI agents, 2026-11-03
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider - External threat detection (preview), 2026-10-15
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers - Build a runtime threat detection system, 2026-10-15
- https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector - Codeless Connector Framework, 2026-08-24
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview - Logs Ingestion API, 2026-10-15
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-overview - Sentinel data lake overview, 2026-05-14
- https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection - Prompt Shields, 2026-10-14
- https://platform.claude.com/docs/en/manage-claude/compliance-api - Compliance API, fetched 2026-11-09
- https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed - Activity Feed, fetched 2026-11-09
- https://platform.claude.com/docs/en/manage-claude/inference-hooks - Inference hooks, fetched 2026-11-09
- https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint - Develop an Inference hooks integration, fetched 2026-11-09
- https://platform.claude.com/docs/en/manage-claude/organization-webhooks - Organization webhooks (beta), fetched 2026-11-09
- https://code.claude.com/docs/en/hooks - Claude Code hooks, fetched 2026-11-09
- https://code.claude.com/docs/en/monitoring-usage - Claude Code OpenTelemetry, fetched 2026-11-09
- https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html - Security Lake custom sources, fetched 2026-11-09
- https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html - ApplyGuardrail, fetched 2026-11-09
- https://docs.cloud.google.com/chronicle/docs/reference/ingestion-api - SecOps Ingestion API (deprecated), fetched 2026-11-09
- https://docs.cloud.google.com/model-armor/overview - Model Armor overview, fetched 2026-11-09
- https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html - SSF 1.0, 2025-08-29
- https://developer.okta.com/docs/guides/configure-ssf-receiver/main/ - Okta SSF receiver, fetched 2026-11-09
- https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension/ - SCIM agent extension draft, 2025-10-16
- https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api - Generic Guardrail API, fetched 2026-11-09
- https://docs.airbyte.com/platform/connector-development/config-based/low-code-cdk-overview - Airbyte low-code CDK, fetched 2026-11-09
- https://github.com/ocsf/ocsf-schema (CHANGELOG, v1.9.0, 2026-08-03) and https://schema.ocsf.io/
- https://github.com/open-telemetry/semantic-conventions-genai (created 2026-05-05) and https://opentelemetry.io/docs/specs/semconv/gen-ai/
- https://github.com/CrowdStrike/falconpy - service collections incl. `aidr`, `ngsiem`, `mssp`, 2026-11
- https://github.com/modelcontextprotocol/registry - registry v1.8.8, API v0.1, 2026-11-06
- https://github.com/theagentrouter/agent-router - Agent Router v1.2.1, 2026-11-06
- https://github.com/agentgateway/agentgateway - v1.7.0, 2026-10-27
- https://github.com/BerriAI/litellm - v1.108.4, guardrail_hooks directory, 2026-11-09
- https://github.com/elastic/integrations , https://github.com/elastic/package-spec (v3.7.0)
- https://github.com/open-telemetry/opentelemetry-collector-contrib - v0.165.1, 2026-11-09
- https://github.com/TracecatHQ/tracecat - 1.5.0-alpha.1, SECURITY.md, 2026-11-05
- https://github.com/Shuffle/python-apps , https://github.com/wazuh/wazuh (v4.14), https://github.com/OpenCTI-Platform/connectors , https://github.com/turbot/steampipe-plugin-sdk , https://github.com/extism/extism (v1.41.0)

## Independent verification

_Checked 2026-11-09 by a second reviewer. Method: primary documentation re-fetched independently, plus read-only GitHub API calls against tagged source. Web search was unavailable (shared budget exhausted), so no secondary-source corroboration was possible; verdicts rest on primary docs and source code only._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Anthropic Inference hooks: every governed prompt (optionally tool calls) from all Claude Enterprise surfaces incl. Claude Code goes to a customer HTTPS server for allow/deny; timeout 1-10,000 ms, default 5,000; no redaction; not on Bedrock, Google Cloud or API-platform orgs | confirmed | All points hold. Additions that matter: first-save failure mode is **Allow the request** (fail open); **Validate tool calls** is on by default in a new configuration; one retry after 100 ms on connection failure only; endpoint must be public HTTPS on port 443 (no tunnels, no private IPs); Claude Code is governed only when signed in with the Enterprise account. | https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration , https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint |
| 2 | Copilot Studio external threat detection (preview): `POST /analyze-tool-execution?api-version=2025-05-01` before every tool invocation, `blockAction` response within 1,000 ms, allow on timeout by default, Entra federated identity credential auth | confirmed | One scope limit the brief omits: it is called only for agents using **generative orchestration**; classic agents are skipped. Error behaviour can be switched to "Block the query" per environment. Provider must also implement `POST /validate`. | https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider |
| 3 | OCSF 1.9.0 (3 Aug 2026) has `ai_operation` (added 1.8.0), `ai_agent`, `delegation`, `hosted_ai_agent_list` on `process`; `ai_capability` and `ai_status` merged but untagged | confirmed | Verified against tags: `profiles/ai_operation.json` exists at 1.8.0 and not 1.7.0; `objects/ai_agent.json` exists at 1.9.0 and not 1.8.0; `objects/ai_capability.json` is absent at 1.9.0; `main` is `1.10.0-dev`. Unreleased work also adds `scopes`/`audience`/`expiration_time` to `delegation`, so that object will change shape in 1.10. | https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0 , https://github.com/ocsf/ocsf-schema/blob/main/CHANGELOG.md |
| 4 | Security Lake custom sources: OCSF 1.3 and earlier only, Parquet, region/accountId/eventDay partitioning, one event class per source, max 50 custom sources per account | corrected | 1.3 cap, Parquet, partitioning and the 50-source limit are confirmed. "One event class per source" is a recommendation, not a hard rule: `CreateCustomLogSource` takes `eventClasses` (one or more); the hard rule is one class per Parquet object. Event classes must come from a closed enum that stops at OCSF 1.3 classes, so 1.8/1.9 classes cannot even be selected. | https://docs.aws.amazon.com/security-lake/latest/userguide/adding-custom-sources.html |
| 5 | Google SecOps Ingestion API (`malachiteingestion-pa.googleapis.com`) deprecated, discontinued 20 July 2027, replaced by Chronicle API | confirmed | Stated verbatim on the Ingestion API reference page. No second Google page carrying the date could be found (the ingestion-methods page does not mention it), so this rests on one primary page. | https://docs.cloud.google.com/chronicle/docs/reference/ingestion-api |
| 6 | OTel GenAI conventions (agent spans, MCP, A2A, execute_tool) live in `open-telemetry/semantic-conventions-genai`, still Development; core semconv at v1.45.0 | confirmed | Repo created 2026-05-05; `mcp.md`, `a2a.md`, `execute-tool.md`, `gen-ai-agent-spans.md` all marked Development; core v1.45.0 released 2026-11-02 and its gen-ai pages are "Moved" stubs. **Caveat for the brief's "pin a version" advice: the new repo has zero tags and zero releases, CHANGELOG is "Unreleased" only, and the README Schema URL is "TODO". The only thing to pin today is a commit SHA.** | https://github.com/open-telemetry/semantic-conventions-genai , https://github.com/open-telemetry/semantic-conventions/releases/tag/v1.45.0 |
| 7 | Defender for Endpoint discovers ~60 named local agents and their MCP servers on Windows and macOS (no native Linux) into `AgentsInfo`, Plan 2; runtime protection is Windows preview via agent hooks or network inspection | confirmed | Matrix lists 62 names on Windows and 59 on macOS. MCP configuration discovery is documented for only about half of them. macOS VS Code extension rows and WSL (3 CLIs) are preview. Commercial cloud only. Runtime protection: hooks for 6 Claude/Copilot surfaces, network inspection for 4 apps. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix , https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents |
| 8 | LiteLLM Generic Guardrail API (`POST /beta/litellm_basic_guardrail_api`; `BLOCKED`/`NONE`/`GUARDRAIL_INTERVENED`); ~70 adapters incl. CrowdStrike AIDR, Agent 365, Purview, Model Armor, Prisma AIRS, Cisco AI Defense | confirmed | Contract and named adapters confirmed in source at v1.108.4. Count is slightly high: `SupportedGuardrailIntegrations` has 64 entries (58 directories plus 7 files under `guardrail_hooks`), several of them internal (custom_code, llm_as_a_judge, generic_guardrail_api). The API is labelled BETA; `unreachable_fallback` defaults to `fail_closed`. | https://github.com/BerriAI/litellm/blob/main/litellm/types/guardrails.py , https://github.com/BerriAI/litellm/tree/main/litellm/proxy/guardrails/guardrail_hooks |
| 9 | Anthropic Compliance API Activity Feed (`GET /v1/compliance/activities`): queryable within 1 minute, retained 6 years, 600 requests/min per parent org, session endpoints return Claude Code and Cowork transcripts | confirmed | The 600/min limit is shared across all `/v1/compliance/*` endpoints, with a second budget on remote session endpoints. Session, chat and file endpoints need a Compliance Access Key and Claude Enterprise; an Admin API key reaches the Activity Feed only. Local-session page tokens expire after 24 hours. | https://platform.claude.com/docs/en/manage-claude/compliance-api |
| 10 | CrowdStrike Falcon API has a read-only `/aidr/*` collection (agents, agent-sessions, tools, skills, mcp-server-names, prompts, detections, process-tree) alongside host containment and RTR, per FalconPy | confirmed | `src/falconpy/_endpoint/_aidr.py` defines 33 operations, all `GET`, covering every resource named (plus executions, file-events, network-events, model-names, classified-file-access). Collection was added 2026-09-24 and ships in FalconPy v1.6.6. `PerformActionV2` (`/devices/entities/devices-actions/v2`) and the RTR collections are present. This shows SDK coverage, not licensing or scope requirements. | https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_endpoint/_aidr.py |

### Further statements checked in the brief

| Statement in brief | Verdict | Note | Source |
|---|---|---|---|
| OTel GenAI: "Pin a version; expect renames" (TL;DR) and "ingest OTLP using pinned GenAI conventions" (Implication 3) | corrected | There is no version to pin. `semantic-conventions-genai` has no tags or releases and no published Schema URL, and core semconv v1.44.0 and v1.45.0 carry only a `deprecated` GenAI model. Pin a commit SHA of the new repo and record it in the mapping files. | https://github.com/open-telemetry/semantic-conventions-genai |
| "Shuffle (AGPL-3.0)" in the catalogue table, and "Tracecat and Shuffle are AGPL-3.0 ... do not vendor their code" | corrected | The Shuffle platform (`Shuffle/Shuffle`) is AGPL-3.0, but the app catalogue the brief cites (`Shuffle/python-apps`, where `api.yaml` apps live) is MIT. Tracecat is AGPL-3.0 as stated. Shipping a Shuffle app does not carry AGPL obligations. | https://github.com/Shuffle/python-apps , https://github.com/Shuffle/Shuffle |
| Claude Code hooks: "about 30 hook events", five handler types, `PreToolUse` timeout does not block unless `onFailure: "block"` | confirmed | 33 events; handler types `command`, `http`, `mcp_tool`, `prompt`, `agent`. `onFailure` needs Claude Code v2.1.295 or later, so older clients fail open regardless. Default timeout for `command`/`http`/`mcp_tool` hooks is 600 seconds, so set an explicit short timeout. | https://code.claude.com/docs/en/hooks |

Also spot-checked and found accurate: the Agent Router rename (repo README states "Formerly Envoy AI Gateway", CRDs, images and `aigw` unchanged, v1.2.1 on 2026-11-06); BeyondTrust platform support and absence of documented export or API; `draft-abbey-scim-agent-extension-00` expired with no successor; agentgateway v1.7.0 Apache-2.0.
