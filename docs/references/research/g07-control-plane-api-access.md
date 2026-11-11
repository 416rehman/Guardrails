# G07 - Control-plane API, console access model, policy-as-code and our own MCP server

_Researched 2026-11-09_

Method note: the shared WebSearch budget for this run was already exhausted, so nothing here comes from search. Everything marked **[V]** was read today from the primary document or repository (WebFetch or `gh`). Items marked **[K]** are from prior knowledge (cutoff mid-2026) and were not re-verified; treat them as leads.

## TL;DR

- **Protobuf-first with Connect is now viable in Rust.** `connectrpc/connect-rust` (Apache-2.0, v0.9.1, Tower-based, serves Connect + gRPC + gRPC-Web from one handler, passes the full conformance suite) exists and uses `anthropics/buffa` for messages. It is pre-1.0. Unary RPCs are plain HTTP POST with JSON, so curl, browsers, the Rune desktop app and partners all use one contract. [V]
- **Every peer exposes REST + OAuth2 client credentials with per-collection scopes**, not GraphQL. Publish an OpenAPI description generated from the protos for partners, Terraform codegen and MCP "code mode".
- **MCP changed shape in 2026-07-28**: no sessions, no `initialize`, mandatory `server/discover`, Dynamic Client Registration deprecated in favour of Client ID Metadata Documents, tasks moved to an extension, 12-month deprecation policy. Build our MCP server stateless against this revision; `rmcp` v3.9.0 already implements it. [V]
- **Rivals ship MCP servers for their consoles**: CrowdStrike (falcon-mcp v0.20.2, now maintenance mode in favour of a hosted "CrowdStrike MCP"), Okta (GA, v1.1.7), Microsoft Sentinel (hosted, Entra auth), Cloudflare (2 tools covering 2,594 endpoints in about 1,000 tokens). We should ship one, read-only by default. [V]
- **Cedar can enforce console RBAC**: roles as principal groups, attributes instead of per-container roles, templates for time-boxed discretionary grants. `cedar-policy` v4.14.1 and `cedar-policy-symcc` v0.8.1 (formal subsumption/equivalence checks with counterexamples) were released 2026-11-02. [V]
- **AWS's own guidance favours per-tenant policy stores when tenants author their own policies** (isolation and off-boarding are "low effort"; global policies become "high effort"). That is our case. [V]
- **Webhooks: adopt Standard Webhooks 1.0.0** (`webhook-id`, `webhook-timestamp`, `webhook-signature`; HMAC `v1` and ed25519 `v1a`; multi-signature rotation). **Identity signals: OpenID SSF 1.0 final (2025-08-29)** with CAEP events. [V]
- **Policy-as-code baseline is Tailscale's**: `test` on pull request, `apply` on merge, console edit lock with "Edit anyway", OIDC workload identity federation instead of stored secrets. BeyondTrust adds replay of recorded activity against a draft policy. Nobody offers semantic (formal) policy diff. [V]
- **MSP delegation precedent**: Microsoft GDAP (customer-approved, role-scoped, time-bound, per-customer) is the model to copy; CrowdStrike Flight Control's `member_cid` is session-level and cannot switch child tenants mid-session. [V]
- **Transcript access precedent**: Microsoft requires dedicated Purview roles for prompt/response content ("Global Administrator alone is insufficient" for IRM alerts) and pseudonymises by default; Teleport scopes recordings with a `where` clause on participants. BeyondTrust documents one administrator role and no public API. [V]
- **Teleport gates just-in-time access requests to Enterprise and is AGPL-3.0.** Open-source JIT elevation with dual approval is whitespace. [V]

## Findings

### 1. API style and Rust tooling

| Option | State on 2026-11-09 | Fit |
|---|---|---|
| Protobuf + Connect (`connectrpc` crate) | v0.9.1 (2026-09-21), MSRV 1.88, Tower service, axum/hyper integration, health and reflection crates, `google.rpc` error details, signed release binaries with provenance. "Pre-1.0; API may shift in 0.x." [V] https://github.com/connectrpc/connect-rust | Best single contract for web, desktop, sensors and partners |
| tonic | Repository now lives at `grpc/grpc-rust`; `tonic-web` v0.14.9 (2026-10-29). [V] | Sensor-to-server streaming fallback if Connect 0.x proves unstable |
| OpenAPI-first (`utoipa` 6.x / `aide` / Dropshot) | All active, Apache-2.0. [V] | Good for REST-only; weaker for streaming and typed sensor protocol |
| GraphQL | No seed peer uses it for its management API. Wiz does [K]. | Avoid: field-level authz and query-cost control add attack surface |

Connect protocol facts that matter: unary calls are HTTP POST to `/package.Service/Method` with `application/json` or `application/proto`; methods marked `NO_SIDE_EFFECTS` may be served over cacheable GET; errors are string codes mapped to HTTP status with typed details; `Connect-Timeout-Ms` carries deadlines; only bidirectional streaming needs HTTP/2. [V] https://connectrpc.com/docs/protocol/

### 2. How mature products handle the mechanics

- **Versioning and deprecation.** Microsoft Graph: `v1.0` and `beta`; GA APIs get at least 24 months' notice; adding enum members, nullable properties or paging is declared non-breaking, so clients must tolerate unknowns. [V] https://learn.microsoft.com/en-us/graph/versioning-and-support. Okta: version in path (`/api/v1`), additive changes without notice. [V] https://developer.okta.com/docs/api/. MCP: Active/Deprecated/Removed lifecycle with a minimum twelve-month window. [V] Signal with `Deprecation: @<unix-ts>` (RFC 9745, March 2025) plus `Sunset` (RFC 8594) and a `rel="deprecation"` link. [V] https://www.rfc-editor.org/rfc/rfc9745.html
- **Pagination.** Google AIP-158: `page_size`/`page_token`, tokens opaque (base64 of a transparent value is "explicitly insufficient"), authorisation rechecked per page, token expiry about three days, adding pagination later is breaking. [V] https://google.aip.dev/158. Okta: opaque cursor, follow `Link: rel="next"`. [V] SCIM gained cursor pagination in RFC 9865 (October 2025: `cursor`, `count`, `nextCursor`, `expiredCursor`). [V] https://www.rfc-editor.org/rfc/rfc9865.html
- **Idempotency.** `Idempotency-Key` is still an Internet-Draft: `draft-ietf-httpapi-idempotency-key-header-08`, 2026-10-22. Semantics: 400 missing, 409 original still in flight, 422 key reused with a different payload. [V] https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/
- **Long-running operations.** AIP-151: return an `Operation`, never a custom shape; declare response and metadata types; `ABORTED` on conflicting parallel operations; validate-only requests return immediately. [V] https://google.aip.dev/151
- **Concurrency.** Okta uses `If-Match` + ETag, 412 on mismatch, on selected endpoints. [V]
- **Correlation.** Okta returns `X-Okta-Request-Id` on every response and it joins to the System Log. [V]
- **Filtering.** Okta uses SCIM operators (`eq`, `co`, `sw`, `pr`, `gt` ...). [V]
- **Webhooks.** Standard Webhooks 1.0.0: sign `id.timestamp.payload`; `whsec_` (HMAC-SHA256, `v1`) or `whsk_`/`whpk_` (ed25519, `v1a`); several space-separated signatures during rotation; payload `{type, timestamp, data}`, under about 20 KB, thin payloads preferred; retries from 5 s to about 75 h; `410 Gone` disables the endpoint; do not follow redirects. [V] https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md. Svix (MIT, Rust, v2.10.0) is an embeddable dispatcher. [V]
- **Security signals.** SSF 1.0 final, 2025-08-29: discovery at `/.well-known/ssf-configuration`, stream create/status/verify endpoints, push (RFC 8935) or poll (RFC 8936), SETs typed `secevent+jwt` with `sub_id`. [V] https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html

### 3. What peer APIs look like

- **CrowdStrike Falcon.** OAuth2 client credentials; scopes per API client; MSSP access by authenticating a parent client with `member_cid`. [V] https://developer.crowdstrike.com/sdks/python/authentication/. Terraform provider v1.2.1 (MPL-2.0) models `*_policy`, `*_policy_precedence`, `*_policy_attachment`, `host_group`, `user`, `user_role_assignment`, `cid_group`. [V] https://github.com/CrowdStrike/terraform-provider-crowdstrike. Token lifetime 30 min and per-minute rate limits are [K].
- **Microsoft Agent 365** (GA 2026-05-01, per-user licence, E5 recommended, included in E7). Registry counts "agents without owners" and "unmanaged agents"; risk counts can lag an hour. Registry Graph API is preview: `GET https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages`, scope `CopilotPackages.Read.All`, `@odata.nextLink` paging. Only Global Administrator and AI Administrator can approve or manage; Security Administrator, Security Reader, Global Reader and AI Reader are view-only. [V] https://learn.microsoft.com/en-us/microsoft-agent-365/overview, https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview, https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-roles-perms
- **BeyondTrust AI Agent Security** (page updated 2026-10-13). Pathfinder endpoint agent on Windows 11/Server 2022+ x64 and macOS 14/15/26; enforcement at kernel and network level plus hooks; actions allow/audit/hold-for-approval/block; sessions record prompts, commands, file and network activity; draft policy can be replayed over a past window before saving; needs a tenant root certificate for HTTPS inspection. Only "administrator access" is documented; no API on the page. [V] https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- **Okta.** See mechanics above; rate-limit headers and DPoP for service apps are [K].
- **Tailscale.** OAuth clients mint 1-hour tokens (`expires_in: 3600`, not configurable) from space-delimited scopes such as `devices:core`, `dns:read`; non-standard `tags` parameter. [V] https://tailscale.com/kb/1215/oauth-clients. Workload identity federation: trust an OIDC issuer, subject pattern with `*`, optional claim rules, exchange at `/api/v2/oauth/token-exchange` for a short-lived scoped token; AWS, GCP, Azure, GitHub Actions named. [V] https://tailscale.com/kb/1581/workload-identity-federation. Terraform resources include `acl`, `oauth_client`, `federated_identity`, `webhook`, `tailnet_key`. [V]
- **Cloudflare.** Account-owned tokens act as service principals that survive the creator leaving; scannable `cfat_` prefix; grantable permissions must be a subset of the creator's. [V] https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/
- **Elastic.** API keys: user, cross-cluster, managed; `manage_own_api_key` versus `manage_api_key`; simple keys on hosted default to 90-day expiry. [V] https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys. Kibana publishes OpenAPI JSON/YAML. [V]
- **Wazuh.** Policies = actions (`agent:restart`) + resources (`agent:id:001`, `node:id:*`) + effect; roles; rules map auth context to roles; white-list mode recommended. [V] https://documentation.wazuh.com/current/user-manual/api/rbac/how-it-works.html
- **Teleport.** Role v8: `request.{roles,thresholds,max_duration,reason}`, `review_requests`, `require_session_mfa`, `device_trust_mode`, `pin_source_ip` (enterprise), `max_session_ttl`; recordings limited with `where: contains(session.participants, user.metadata.name)`; preset `auditor` overrides. [V] https://goteleport.com/docs/reference/access-controls/roles/. Access requests in the Web UI, resource requests and dual authorisation are Enterprise; Community gets CLI role requests only. [V] https://goteleport.com/docs/identity-governance/access-requests/

### 4. Console identity

- **Passkeys.** `webauthn-rs` (MPL-2.0, v0.5.2, SUSE-audited) covers passkeys and attested security keys. [V] https://github.com/kanidm/webauthn-rs
- **SCIM.** RFC 7643/7644 plus RFC 9865 cursors. Authorisation must be rechecked on every page. [V]
- **Session binding.** Chrome DBSC: `Secure-Session-Registration` on login, TPM-held key, short-lived cookie refreshed via `Secure-Session-Challenge`/`Secure-Session-Response`; falls back silently without secure storage. [V] https://developer.chrome.com/docs/web-platform/device-bound-session-credentials. DPoP (RFC 9449) for API tokens is [K].
- **MSP delegation.** GDAP: per-customer relationship, explicit customer grant, least-privilege role choice, time-bound, partner security groups (limit 100 per customer). [V] https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction
- **Enterprise-managed MCP authorisation.** Stable extension dated 2026-07-28: the IdP issues an ID-JAG, exchanged at our authorisation server via JWT bearer grant. Okta, Ping (13.1+), Descope, Janssen (2.2.0) available; Keycloak 26.7.0 experimental; Auth0, WorkOS, Scalekit early access. [V] https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization.md

### 5. Cedar for console authorisation

Cedar's documented patterns map directly: membership (`principal in Role::"X"`), attribute conditions to avoid role explosion ("one role per country ... may not scale well"), relationship attributes on resources, and templates with `?principal`/`?resource` slots for run-time grants where editing the template updates every linked policy. [V] https://docs.cedarpolicy.com/overview/patterns.html. SymCC verifies never-errors, always-allows/denies, implies, equivalent and disjoint, with counterexamples, using cvc5 1.3.1. [V] https://github.com/cedar-policy/cedar. `cedar-for-agents` generates a Cedar schema from an MCP `tools/list` response (one action per tool, inputs as context). [V] https://github.com/cedar-policy/cedar-for-agents. OpenFGA (v1.22.1, Apache-2.0) is the ReBAC alternative with native list-objects queries [K on the query point]. AWS advises 403 rather than 404 for unauthorised resources and permissions named after resources, not API operations. [V] https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/design-multi-tenancy-considerations.html

### 6. Policy as code

- Tailscale: `tailscale/gitops-acl-action@v1`; `test` validates and runs policy tests without changing live state, `apply` re-tests then applies; "Prevent edits in the admin console" with an external reference URL and an "Edit anyway" emergency path; OIDC federation, OAuth secret or API key for CI. [V] https://tailscale.com/kb/1306/gitops-acls-github
- Grafana Git Sync: bidirectional, UI save commits to a branch or PR, 60 s polling or webhooks. [V] https://grafana.com/docs/grafana/latest/as-code/observability-as-code/git-sync/
- HashiCorp's OpenAPI-to-provider codegen is still "tech preview". [V] https://github.com/hashicorp/terraform-plugin-codegen-openapi. Providers are Go (`terraform-plugin-framework`); OpenTofu consumes the same binaries [K].

### 7. MCP servers for security consoles

| Server | Facts |
|---|---|
| CrowdStrike falcon-mcp | MIT, v0.20.2 (2026-11-03), about 30 modules incl. RTR, IOC, policies; `--read-only`, `--tools`, `--exclude-tools`; dynamic mode = 3 meta-tools; "HTTP transports have no authentication by default"; Flight Control child CID fixed per server process; now maintenance mode, features go to hosted CrowdStrike MCP (US-1, US-2, EU-1). [V] https://github.com/CrowdStrike/falcon-mcp |
| Okta MCP server | Apache-2.0, GA, v1.1.7; device authorisation grant or private-key JWT; tools registered only for granted scopes; destructive operations confirmed via MCP elicitation. [V] https://github.com/okta/okta-mcp-server |
| Microsoft Sentinel MCP | Hosted, Entra identity, scenario collections (data exploration, triage, agent creation). [V] https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview |
| Cloudflare API MCP | `search()` + `execute()` over the OpenAPI spec in a sandbox: about 1,000 tokens versus 1.17 M for 2,594 native tools; OAuth with user-selected permissions or bearer API token. [V] https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/ |
| Teleport (as gateway) | `allow.mcp.tools` / `deny.mcp.tools` with globs and anchored regex, deny wins, tools from IdP claims via `{{external.mcp_tools}}`, JWT signed by Teleport CA. [V] https://goteleport.com/docs/enroll-resources/mcp-access/rbac/ |

MCP normative points for our server: protected resource metadata (RFC 9728) MUST; audience-bound tokens (RFC 8707) MUST; token passthrough forbidden; `insufficient_scope` 403 challenges for step-up; state handles MUST NOT be treated as authentication and should be keyed to the verified user; publish minimal `scopes_supported`; validate `iss` (RFC 9207). [V] https://modelcontextprotocol.io/specification/2026-07-28/changelog.md, https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices.md

### 8. Transcript access

Microsoft: prompts and responses land in the unified audit log and the user's mailbox; content viewing sits behind Purview roles; IRM and Communication Compliance pseudonymise usernames by default; retention policies apply. [V] https://learn.microsoft.com/en-us/purview/ai-agent-365. No surveyed product documents a mandatory purpose field for viewing AI transcripts.

## Matrix

**Authentication by deployment size (proposed)**

| Deployment | Humans | Automation | Elevation / break-glass | Session binding |
|---|---|---|---|---|
| Single laptop | Passkey or OS-user unlock on loopback/UDS; CLI device flow | Local token, file-permission protected | None; recovery codes | Loopback only |
| Small self-hosted team | Passkeys + optional OIDC (Google, GitHub, Entra) | Service-account tokens with expiry and scannable prefix | One sealed local owner passkey | DBSC where present |
| Enterprise | OIDC and SAML SSO, SCIM 2.0 + RFC 9865, group-to-role mapping | OAuth client credentials (1 h tokens), workload identity federation, private-key JWT | JIT requests with threshold, max duration, reason; two break-glass passkeys with alarm | DBSC, DPoP, optional IP pin, SSF/CAEP receiver |
| MSP | Technicians authenticate at the partner IdP; per-customer delegation approved by customer | Partner client + token exchange to a tenant-audience token | Delegation is itself time-bound; customer can revoke | As enterprise; tenant in token audience |
| Embedded EDR partner | Partner console SSO; optional white-label passthrough via ID-JAG | Federated identity or private-key JWT; tenant provisioning scope | Partner-level break-glass held by partner | mTLS or DPoP |

**Role catalogue (proposed)**

| Persona | Role | Can | Cannot |
|---|---|---|---|
| Single user | Owner | Everything locally | n/a |
| Enterprise | Org Owner | Identity, roles, keys, delegation approval | Read transcript content without a grant |
| | Security Admin | Sensors, integrations, response actions | Approve own policy change |
| | Policy Author / Policy Approver | Draft, simulate / approve, deploy | Author cannot approve own change |
| | SOC Analyst / Responder | Detections, sessions metadata / containment actions | Edit policy |
| | Privacy Reviewer | Approve transcript-content grants | Read content themselves by default |
| | Auditor | Read all config and audit log | Any write; content |
| | Agent Owner (developer) | Own agents, own sessions, request exceptions | Others' data |
| MSP | Partner Admin / Technician / Read-only | Within delegated role and expiry | Customer identity settings, transcripts unless customer grants |
| Partner | Integration principal | Create tenants, push/pull via API | Console login |
| Automation | Policy deployer, SIEM exporter, MCP agent | Scoped to one function | Mint tokens, change roles |

## Weak points, gaps and risks

- `connectrpc` is 0.x; pin, vendor the generated code, keep tonic as an escape hatch.
- Cedar has no native "list everything this principal can see" query; tenant and delegation listings must come from the relational store, with Cedar as the check. Running console authz and runtime agent policy on one engine risks schema and store confusion unless namespaces are hard-separated.
- Per-tenant policy stores make global guardrails a replication problem (AWS rates it "high effort").
- An MCP server over a security console is a prime indirect-prompt-injection target: detections, transcripts and agent names contain attacker-controlled text. CrowdStrike and Okta docs describe no injection guardrails beyond tool filtering and confirmation.
- DBSC silently degrades; do not treat it as a guarantee.
- Terraform providers must be Go; a second language in a Rust project, and codegen is preview.
- `Idempotency-Key` and OAuth 2.1 are still drafts; MCP auth moved twice in twelve months.

## Implications for our design

**API design standard**
1. Protobuf is the source of truth (`aidr.<domain>.v1`), linted and `buf breaking`-gated. Serve Connect, gRPC and gRPC-Web from one Tower stack; emit OpenAPI 3.1 from the protos for partners, the Terraform provider and MCP.
2. Resource-oriented methods per Google AIPs: Get/List/Create/Update/Delete plus named custom verbs; opaque encrypted page tokens bound to principal and filter; `etag` + `If-Match`; `validate_only` on every mutation; `request_id` field mirrored by `Idempotency-Key` (400/409/422 semantics, 24 h retention).
3. Anything over about 10 s returns an `Operation` (policy rollout, bulk export, sensor upgrade, replay simulation). Bulk export is an Operation that writes NDJSON/Parquet to object storage and returns a short-lived URL; live tail is server-streaming; SIEM pull is a cursor feed.
4. Errors: Connect code + `google.rpc.ErrorInfo` with stable `reason` and `domain`; never branch on message text. Every response carries a request ID that appears in the audit log.
5. Channels `v1alpha`, `v1beta`, `v1`; GA removal needs at least 12 months, announced with `Deprecation`, `Sunset` and a changelog entry. Unknown enum values and fields must be tolerated by all first-party clients.
6. Webhooks follow Standard Webhooks with ed25519 by default; identity-provider signals follow SSF/CAEP in both directions.
7. Return 403 for cross-tenant probes; name permissions after resources.

**Resource model outline**
`organizations` (partner or customer) > `tenants` > `groups`; `delegations` (partner-to-tenant, role, expiry, approver); `principals` (`users`, `serviceAccounts`, `oauthClients`, `federatedIdentities`); `roles`, `roleBindings`, `accessRequests`; `identityProviders`, `scimEndpoints`; `sensors`, `enrollmentTokens`; `agents`, `agentInstances`, `mcpServers`, `skills`; `policyBundles` > `versions`, `policyAssignments`, `rollouts`, `simulations`, `approvals`; `events`, `sessions` > `transcript` (separate permission), `detections`, `incidents`, `responseActions`; `transcriptGrants`; `exports`, `webhookEndpoints`, `signalStreams`; `auditEvents`; `operations`.

**Authorisation**
- Enforce the console with Cedar: entities `User`, `ServiceAccount`, `AgentSession`, `Tenant`, `Role`; roles are groups scoped by tenant ancestry; delegation, JIT elevation and transcript grants are template-linked policies with expiry in `context`. Ship built-in roles as a signed, immutable base bundle with `forbid` guardrails; tenants add policies in their own store.
- Keep `Console::` and `Runtime::` Cedar namespaces and stores separate.
- Model MCP access as principal `AgentSession` acting for a user, so our own audit log distinguishes agent from human.

**Tokens**
- Prefer federation, then OAuth client (1 h), then static tokens with prefix, mandatory expiry, creator attribution and last-used metadata. Account-owned service principals survive user removal. Partner credentials obtain per-tenant tokens through token exchange with the tenant in the audience; no ambient cross-tenant token.

**Policy-as-code workflow**
`edit in Git` > CI `validate` (schema) > `test` (fixtures) > `simulate` (replay last N days of recorded events) > `diff` (SymCC: does the new set permit anything the old denied?) > approval by a different principal > `apply` as a staged rollout Operation (audit-only > canary group > all) > drift detection. Console honours a GitOps lock with an audited "edit anyway". Provide a CLI, a GitHub/GitLab action using OIDC federation, and a Go Terraform/OpenTofu provider with `policy_bundle`, `policy_assignment`, `policy_precedence`, `role_binding`, `service_account`, `federated_identity`, `webhook`.

**Our MCP server**
Stateless 2026-07-28 Streamable HTTP via `rmcp`; OAuth resource server with RFC 9728 metadata, audience-bound tokens, CIMD, and ID-JAG acceptance; stdio mode for the laptop install. Two surfaces: a small curated read-only tool set, and a code-mode `search`/`execute` pair over the OpenAPI spec. Writes require a step-up scope and an out-of-band approval in the console; policy changes via MCP only create proposals. Every tool call passes the same Cedar check. Attacker-controlled fields are returned in a typed `untrusted` envelope, and once a session has read such content, write tools require human approval. Register and monitor this server in our own inventory.

**Transcript access**
Metadata visible to analysts; content requires `transcript.readContent`, a purpose code plus case reference, a time-boxed grant, and produces an audit event the tenant can see. Pseudonymise users by default; redact secrets at ingest; deny MSP and SaaS-operator access unless the customer approves.

## Ideas worth stealing and whitespace

- Steal: Cloudflare code mode; Okta scope-driven tool registration and elicitation confirmation; Tailscale federated identities and edit lock; GDAP time-bound delegation; BeyondTrust policy replay; Teleport thresholds and `where`-scoped recordings; Cloudflare scannable token prefixes.
- Whitespace: formally verified policy diff in CI; open-source JIT elevation with dual approval; purpose-bound transcript access; an MCP server that defends against poisoned security data; MSP delegation that can switch tenant per call under one audited identity; a documented public API and role model for an AI agent security product (BeyondTrust shows neither).

## Could not verify / open questions

- No web search was possible; coverage of newer entrants and of Wiz, Splunk and Google SecOps MCP servers is absent.
- CrowdStrike hosted MCP: endpoint, auth, RBAC and audit not found on the public pages fetched.
- BeyondTrust: no sub-pages or API reference reachable (`llms.txt` 404). Anthropic Compliance API page returned 404.
- Not re-verified [K]: Zalando and Microsoft REST guidelines details, AIP-155/193, IETF RateLimit header draft status, Okta rate-limit headers and DPoP, CrowdStrike token lifetime and limits, Elastic `Elastic-Api-Version`, Wazuh JWT lifetime, Cloudflare Terraform v5 generation history, a proto-to-OpenAPI generator for Connect, Cedar partial evaluation status, OpenTofu registry requirements.
- Open: can SymCC run fast enough on real tenant policy sets for CI? Does `connectrpc` support the browser/wasm client we need for Rune?

## Sources

- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - AI Agent Security, updated 2026-10-13
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Agent 365 overview, 2026-08-19
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview - Agent Registry, 2026-09-21
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-365-overview - Agent overview, 2026-10-20
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-roles-perms - Roles and permissions, 2026-05-08
- https://learn.microsoft.com/en-us/purview/ai-agent-365 - Purview for Agent 365, 2026-05-01
- https://learn.microsoft.com/en-us/graph/versioning-and-support - Graph versioning, 2024-11-07
- https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction - GDAP, 2026-04-28
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview - Sentinel MCP, 2026-05-07
- https://modelcontextprotocol.io/specification/2026-07-28/changelog.md - MCP key changes, 2026-07-28
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization - MCP authorization, 2025-11-25
- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices.md - MCP security best practices
- https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization.md - Enterprise-managed authorization
- https://github.com/modelcontextprotocol/rust-sdk - rmcp v3.9.0, 2026-11-05
- https://github.com/CrowdStrike/falcon-mcp and https://developer.crowdstrike.com/falcon-mcp/ - falcon-mcp v0.20.2, 2026-11-03
- https://developer.crowdstrike.com/falcon-mcp/usage/flight-control/ - Flight Control
- https://developer.crowdstrike.com/sdks/python/authentication/ - FalconPy authentication
- https://github.com/CrowdStrike/terraform-provider-crowdstrike - v1.2.1, 2026-11-02
- https://github.com/okta/okta-mcp-server - v1.1.7, 2026-09-29
- https://developer.okta.com/docs/api/ - Okta API conventions
- https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/ - Cloudflare MCP servers
- https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/ - Account-owned tokens
- https://tailscale.com/kb/1215/oauth-clients, https://tailscale.com/kb/1581/workload-identity-federation, https://tailscale.com/kb/1306/gitops-acls-github - Tailscale
- https://goteleport.com/docs/identity-governance/access-requests/, https://goteleport.com/docs/reference/access-controls/roles/, https://goteleport.com/docs/enroll-resources/mcp-access/rbac/ - Teleport
- https://grafana.com/docs/grafana/latest/as-code/observability-as-code/git-sync/ - Grafana Git Sync
- https://documentation.wazuh.com/current/user-manual/api/rbac/how-it-works.html - Wazuh RBAC
- https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys - Elastic API keys
- https://github.com/connectrpc/connect-rust - v0.9.1, 2026-09-21; https://connectrpc.com/docs/protocol/
- https://github.com/cedar-policy/cedar - v4.14.1 and symcc v0.8.1, 2026-11-02; https://docs.cedarpolicy.com/overview/patterns.html; https://github.com/cedar-policy/cedar-for-agents
- https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/design-multi-tenancy-considerations.html - Multi-tenancy
- https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md - v1.0.0
- https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html - SSF 1.0, 2025-08-29
- https://www.rfc-editor.org/rfc/rfc9865.html (SCIM cursors, Oct 2025); https://www.rfc-editor.org/rfc/rfc9745.html (Deprecation header, Mar 2025)
- https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/ - draft-08, 2026-10-22
- https://google.aip.dev/151, https://google.aip.dev/158 - Google AIPs
- https://developer.chrome.com/docs/web-platform/device-bound-session-credentials - DBSC
- https://github.com/kanidm/webauthn-rs - v0.5.2; https://github.com/hashicorp/terraform-plugin-codegen-openapi; https://github.com/openfga/openfga (v1.22.1); https://github.com/svix/svix-webhooks (v2.10.0)

## Independent verification

_Checked 2026-11-09 by a second reviewer against primary sources (GitHub API via `gh`, vendor documentation fetched directly). Nothing above this heading was changed._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | MCP 2026-07-28 removed sessions and the `initialize` handshake, requires `server/discover`, moved tasks to an extension, deprecated DCR in favour of CIMD | Confirmed | Changelog major changes 1, 2, 3, 6 and Deprecated item 4 say exactly this. The spec repo has a non-prerelease `2026-07-28` release (published 2026-07-28) and the `rmcp` README states it implements stable 2026-07-28. DCR is deprecated, not removed (MAY, kept for backwards compatibility); CIMD is SHOULD. | https://modelcontextprotocol.io/specification/2026-07-28/changelog ; https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28 |
| 2 | `connectrpc/connect-rust` Apache-2.0, v0.9.1 on 2026-09-21, Tower-based, Connect + gRPC + gRPC-Web, full conformance, pre-1.0 | Confirmed | GitHub API: licence Apache-2.0, v0.9.1 published 2026-09-21. README: "pre-1.0 ... may shift in 0.x", passes 3,600 server and 6,872 client conformance tests, MSRV 1.88. The README also answers the brief's open question: the core crate compiles for `wasm32-unknown-unknown` and ships a Fetch-based `examples/wasm-client`. | https://github.com/connectrpc/connect-rust |
| 3 | `cedar-policy` v4.14.1 and `cedar-policy-symcc` v0.8.1 released 2026-11-02; SymCC checks implication, equivalence, disjointness, always-allow/deny with counterexamples via cvc5 | Confirmed | Both tags published 2026-11-02. The SymCC README lists `check_never_errors`, `check_always_allows`, `check_always_denies`, `check_implies`, `check_equivalent`, `check_disjoint`, each with a `_with_counterexample` variant; it needs an external cvc5 1.3.1 binary. Checks run per request environment (principal type, action, resource type) on validated policies, so a CI diff must iterate all environments. | https://github.com/cedar-policy/cedar/releases ; https://github.com/cedar-policy/cedar/tree/main/cedar-policy-symcc |
| 4 | AWS rates per-tenant policy stores low effort for isolation and off-boarding, high for global policy and schema management, and recommends them for many tenant-specific policies | Confirmed | Table matches. It also rates per-tenant stores "Medium" for authorization flow (tenant-to-store mapping) and "Low" for quotas. The recommendation trigger is "many tenant-specific policies, or uses multiple identity sources". | https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/design-multi-tenancy-considerations.html |
| 5 | MCP servers must publish RFC 9728 metadata, accept only audience-bound tokens (RFC 8707), must not pass tokens through, must not treat state handles as authentication | Confirmed (with scope note) | All four are MUST / MUST NOT in the 2026-07-28 authorization spec and security best practices. Caveats: authorization as a whole is OPTIONAL in MCP and does not apply to stdio; the RFC 8707 `resource` parameter is a client MUST, the server MUST is audience validation; the 403 `insufficient_scope` challenge is SHOULD; `iss` (RFC 9207) validation is a client duty and the authorization server SHOULD emit it. | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization ; https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices |
| 6 | falcon-mcp MIT, v0.20.2, maintenance mode, features only in hosted CrowdStrike MCP; HTTP transports unauthenticated by default; Flight Control child CID fixed for server lifetime | Confirmed | v0.20.2 published 2026-11-03, MIT. README: "now in maintenance mode ... new features will only ship in CrowdStrike MCP"; "HTTP transports have no authentication by default" (default bind is loopback, `--api-key` available). `docs/usage/flight-control.md`: "Cannot switch mid-session ... persists for the server's lifetime". | https://github.com/CrowdStrike/falcon-mcp ; https://github.com/CrowdStrike/falcon-mcp/blob/main/docs/usage/flight-control.md |
| 7 | Standard Webhooks 1.0.0: three headers, HMAC-SHA256 `v1` and ed25519 `v1a` over `id.timestamp.payload`, multi-signature rotation | Confirmed | Spec header "Version: 1.0.0"; headers, `whsec_` / `whsk_` / `whpk_` prefixes and the space-delimited signature list for zero-downtime rotation are all present. The repository's library releases are at v1.0.2 (2026-02-18); the spec text is still 1.0.0. | https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md |
| 8 | Tailscale GitOps: `test` on pull request, `apply` on merge, OIDC workload identity federation, console lock with "Edit anyway" | Confirmed | KB page and action README agree. Tailscale's own wording is "federated identity" (`oauth-client-id` + `audience`, GitHub `id-token: write`), which is OIDC token exchange. | https://tailscale.com/kb/1306/gitops-acls-github ; https://github.com/tailscale/gitops-acl-action |
| 9 | Agent 365: only Global Administrator and AI Administrator can approve or manage agents; Security Administrator and readers are view-only; registry Graph API still preview | Corrected | The role part holds for tenant-wide governance in the Microsoft 365 admin center, but the same page says product admins (Power Platform Administrator, Fabric Administrator) govern within their products, and Entra has separate Agent ID Administrator, Agent ID Developer and Agent Registry Administrator roles. The API part is out of date: List and Get packages are published on `v1.0` with application permission `CopilotPackages.Read.All`; only Update, Block, Unblock and Reassign are preview, `/beta` only, and delegated-only (`CopilotPackages.ReadWrite.All`, no app-only). The registry page heading still says "(preview)". | https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-roles-perms ; https://learn.microsoft.com/en-us/microsoft-365-copilot/extensibility/api/admin-settings/package/overview ; https://learn.microsoft.com/en-us/microsoft-365-copilot/extensibility/api/admin-settings/package/copilotpackage-block ; https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference |
| 10 | Teleport JIT requests with Web UI, resource requests and dual authorization are Enterprise-only; repo is AGPL-3.0; so open-source JIT elevation is unclaimed ground | Corrected | The Teleport facts hold (feature matrix: Community "Only can request roles through CLI", dual authorization not included; source AGPL-3.0, and Community binaries carry a commercial licence limited to companies under 100 employees and US$10M revenue). The conclusion does not: open-source JIT elevation with approval exists, for example Google JIT Groups (Apache-2.0, time-boxed group membership with approval), AWS TEAM for IAM Identity Center (MIT-0, approver workflow), hoop (MIT), and the archived ConsoleMe and Common Fate Glide. The defensible whitespace is narrower: JIT elevation with dual approval built into an open-source security or AI-agent console. | https://goteleport.com/docs/feature-matrix/ ; https://github.com/GoogleCloudPlatform/jit-groups ; https://github.com/aws-samples/iam-identity-center-team |

**Further statements checked in the brief**

| Statement | Verdict | Note | Source |
|---|---|---|---|
| "Nobody offers semantic (formal) policy diff" and the whitespace item "formally verified policy diff in CI" | Corrected | True only for the surveyed peer consoles. Cedar's own analysis CLI has `analyze compare`, which reports per request type whether one policy set is equivalent to, more permissive than, less permissive than or incomparable to another, and AWS IAM Access Analyzer `CheckNoNewAccess` compares an updated policy against the existing one from the CLI or API. The gap is productising it in an agent-policy GitOps workflow, and the Cedar CLI can be reused rather than built. | https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean-cli ; https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html |
| "Cedar has no native 'list everything this principal can see' query" | Corrected | `cedar-policy` has an experimental `tpe` feature (type-aware partial evaluation) exposing `query_resource`, `query_principal` and `query_action` permission queries. They are marked experimental and work over entities supplied in memory, so the brief's design choice (list from the relational store, Cedar as the check) still stands, but "no native query" is too strong. | https://github.com/cedar-policy/cedar/blob/main/cedar-policy/src/api/tpe.rs |
| tonic "now lives at `grpc/grpc-rust`; `tonic-web` v0.14.9 (2026-10-29)" | Confirmed | `hyperium/tonic` resolves to `grpc/grpc-rust` (MIT); `tonic-v0.14.9` and `tonic-web-v0.14.9` published 2026-10-29. | https://github.com/grpc/grpc-rust/releases |

Also spot-checked and found accurate: `rmcp` v3.9.0 (2026-11-05) implements 2026-07-28; `Idempotency-Key` is still an Internet-Draft at revision 08 dated 2026-10-22; OpenID SSF 1.0 is dated 2025-08-29; Agent 365 has been generally available since 2026-05-01 on a per-user licence.
