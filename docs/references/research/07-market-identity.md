# Commercial market map: agent identity, access and secrets

_Researched 2026-11-09_

Evidence labels: **[V]** read in a primary source this session; **[S]** secondary source only; **[B]** background knowledge, not re-verified. The shared web-search budget ran out near the end, so several seeds (Akeyless, Doppler, Veza, Saviynt, Ping, SailPoint, Silverfort, Oso, Clutch, Composio, Stytch, WorkOS, Scalekit) rest on [S] or [B] and are listed under "Could not verify".

## TL;DR

- **The market converged on one architecture**: register the agent in a directory with a human sponsor, never hand it a long-lived secret, broker short-lived audience-scoped tokens through token exchange, and enforce at an MCP/API gateway. Okta, Microsoft, AWS, Google, HashiCorp, Descope, Keycard and Aembit all ship variants of it.
- **ID-JAG / Cross App Access is the winning cross-vendor standard for "user's agent connects to a SaaS/MCP server".** MCP made it a stable extension (Enterprise-Managed Authorization, spec dated 2026-07-28). The IETF draft is still a draft (-06, 2026-10-30). Okta, PingFederate 13.1, Descope, Athenz, Janssen and ThunderID issue ID-JAGs; Keycloak 26.7 accepts them experimentally.
- **EMA governs the connection, not the tool call.** One ID-JAG covered every tool call in a session in AWS's own test, and opened a second session inside its 5-minute life. Tool-level control still needs a gateway or in-agent hook.
- **Every commercial identity product assumes the agent is a registered OAuth client.** None gives an identity to an unregistered local process. BeyondTrust's endpoint product states it outright: agents "run as the signed-in user and have no identity of their own". This is our whitespace.
- **Endpoint coverage is thin and Linux is missing.** BeyondTrust AI Agent Security supports Windows 11/Server 2022 x64 and macOS 14 to 26 only. 1Password's mounted `.env` feature is Mac/Linux only and its Cursor hook is a no-op on Windows.
- **Coding agents still store credentials in plaintext files.** Claude Code keeps `~/.claude/.credentials.json` (mode 0600) on Linux and `%USERPROFILE%\.claude\.credentials.json` on Windows, and `claude setup-token` mints a one-year token. Vendors now offer keyless alternatives (Anthropic and OpenAI workload identity federation) but adoption is opt-in.
- **Credential-injecting egress proxies are the practical way to keep secrets out of the model.** Infisical Agent Vault (open source, 2.5k stars), Aembit, Keycard and Tailscale Aperture all do MITM-style injection so the agent holds only a placeholder or session token.
- **Delegation semantics are diverging.** Vault computes the intersection of user policy and an agent "ceiling"; Entra evaluates Conditional Access against the user in OBO flows; AWS documents its flow as "impersonation"; Okta nests `act` claims per hop. The ID-JAG draft defines no normative `act` processing.
- **Consolidation is nearly complete.** Astrix to Cisco, SGNL to CrowdStrike (closed 2026-02-20), CyberArk to Palo Alto (now "Idira"), Entro to SailPoint, Natoma to Snowflake, Oasis to Cyera (LOI). Independent NHI vendors left: Token Security, Clutch, Aembit, Keycard.
- **The good parts are paywalled.** Vault Agentic IAM is Enterprise-only (2.1.0+). Entra agent Conditional Access needs Agent 365 or E7. Okta's gateway needs the Okta for AI Agents subscription. An open-source equivalent does not exist as one coherent module.

## Findings

### 1. How agents get an identity

**Microsoft Entra Agent ID** [V]. Three object types: agent identity blueprint (template, holds the credentials, has one permission, `AgentIdentity.CreateAsManager`), agent identity (the per-agent principal), and an optional agent user account (1:1 with the agent identity, for mailbox-style scenarios). Credentials live on the blueprint only; managed identities via federated identity credentials are preferred and client secrets are discouraged. All flows are multi-stage token exchanges in which the blueprint impersonates the agent identity. Interactive `/authorize` flows and public clients are unsupported, so this model cannot directly represent a CLI agent on a laptop. Disabling a blueprint blocks all of its agent identities. Sources: [blueprints](https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint) (2026-04-28), [OAuth protocols](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols) (updated 2026-08-13).

**Microsoft Agent 365** [V]. GA 2026-05-01, licensed per user, "works best" with E5. The agent registry moved from Entra to Agent 365. An agent appearing in the registry does not automatically have an Entra Agent ID, and Entra controls apply only to agents that do. Pricing reported as $15/user/month or inside M365 E7 at $99 [S]. Sources: [overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview) (2026-08-19), [Entra capabilities](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/capabilities-entra) (2026-05-12).

**Okta** [V]. Agents are registered in Universal Directory and authenticate with a signed `client_assertion` (private key JWT). Okta accepts a CIMD URL as `client_id`. Okta for AI Agents GA spring 2026 (2026-04-30 announced, "since May 2026" in a later release); Agent SSO GA 2026-08-24 and included in core SSO, capped at 250 ID-JAGs per user per resource app per month. Sources: [token exchange guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/authserver/main/), [Agent SSO release](https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso/) (2026-08-24), [MCP EMA table](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization).

**AWS Bedrock AgentCore Identity** [V]. Agents are "workload identities" in an agent identity directory, with ARNs of the form `arn:aws:bedrock-agentcore:region:account:workload-identity/directory/default/workload-identity/agent-name`. Works for agents on AgentCore Runtime, self-hosted or hybrid. Source: [features](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/key-features-and-benefits.html).

**Google Cloud Agent Identity** [V]. Each agent gets a SPIFFE ID `spiffe://agents.global.org-ORG_ID.system.id.goog/resources/SERVICE/PATH` and a Google-managed X.509 certificate valid 24 hours. Access tokens are bound to the certificate (mTLS); calls through Agent Gateway add DPoP. Agent identities cannot be impersonated and cannot mint service-account keys. Trap: identity derives from the hosting resource ID, so redeploying creates a new principal and deleted agents leave inactive IAM grants. Supported on Agent Runtime, Gemini Enterprise and Cloud Run. Source: [Agent Identity overview](https://docs.cloud.google.com/iam/docs/agent-identity-overview).

**HashiCorp Vault Agentic IAM** [V]. Enterprise only, 2.1.0+. Vault acts as an OAuth resource server; an Agent Registry record binds one Vault identity entity to `display_name`, free-form `owner`, and `ceiling_policies`. Tokens are not stored; JWT claims are re-evaluated on every request. Sources: [Vault + agentic AI](https://developer.hashicorp.com/vault/ai), [agent registry](https://developer.hashicorp.com/vault/ai/iam/concepts/agent-registry).

**Teleport Agentic Identity Framework** [V]. Short-lived X.509 from attested workload identity; delegation design in RFD 0238; `tsh mcp config` / `tsh mcp connect` for MCP. Most identity, access and security components are marked "in-progress" and the scheduling layer "not started". Source: [framework docs](https://goteleport.com/docs/agentic-identity-framework/).

**Keycard** [V]. Early access. `keycard run` wraps Claude Code, Codex, OpenCode and Cursor; credentials are scoped to the tuple user + agent + device + task, issued per tool call and held in memory. Source: [Keycard for Coding Agents](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/) (2026-03-19).

**Model providers** [V]. Anthropic and OpenAI both offer workload identity federation: exchange an OIDC (OpenAI also SPIFFE) token for a short-lived API token. Claude Code managed settings add `forceLoginMethod`, `forceLoginOrgUUID`, `allowedProviders`, and block `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `apiKeyHelper` under those policies. OpenAI Codex access tokens still offer a "No expiration" option. Sources: [Claude Code authentication](https://code.claude.com/docs/en/authentication), [OpenAI WIF](https://developers.openai.com/api/docs/guides/workload-identity-federation), [Codex access tokens](https://developers.openai.com/codex/enterprise/access-tokens).

### 2. Binding a human owner or sponsor

- Entra records the creating user as **sponsor**; ID Governance adds sponsor tasks and agent lifecycle workflows [V].
- Okta for AI Agents assigns discovered and shadow agents to **named human owners** and adds certification reviews [V, press release].
- Vault's `owner` is an optional free-form string, not an enforced principal [V].
- Idira (ex-CyberArk) enriches discovered agents with owner and permission level [V, [product page](https://www.paloaltonetworks.com/idira)].
- Token Security infers "declared and observed" intent and owner; the mechanism is undisclosed [V, [release](https://www.token.security/news/token-security-introduces-intent-based-security-for-ai-agents) 2026-03-18].
- Nobody binds an owner to an unregistered local process except by inference from the OS user (BeyondTrust, 1Password Discover).

### 3. Credential issuance, brokering and injection

| Mechanism | Who | What the agent holds |
|---|---|---|
| IdP token exchange to ID-JAG, then `jwt-bearer` at the resource AS | Okta, Ping, Descope, Athenz, Janssen | 300 s ID-JAG, then a resource access token (3600 s in Okta's examples) |
| Token vault, token handed to app code | Auth0 Token Vault, AgentCore `@requires_access_token`, Google auth manager | Short-lived provider access token in process memory |
| Token vault, server-side injection at tool execution | Nango, Arcade, Composio, Okta Agent Gateway | Nothing |
| MITM egress proxy with placeholder substitution | Infisical Agent Vault, Aembit, Keycard gateway, Tailscale Aperture | Proxy session token or placeholder |
| Vaulted static secret released under policy | Okta `STS_VAULT_SECRET` / `STS_SERVICE_ACCOUNT` via Okta Privileged Access, Idira Secrets Hub | Static secret, time-boxed |
| Workload identity federation | Anthropic, OpenAI, cloud IAM | 1-hour bearer token |

Details worth keeping:

- Okta connection types [V]: `IDENTITY_ASSERTION_CUSTOM_AS`, `IDENTITY_ASSERTION_APP_INSTANCE`, `IDENTITY_ASSERTION_MCP_SERVER`, `IDENTITY_ASSERTION_A2A_SERVER`, `STS_ACCESS_TOKEN` (brokered consent), `STS_VAULT_SECRET`, `STS_SERVICE_ACCOUNT`.
- Infisical Agent Vault [V]: `infisical agent-vault run` sets `HTTPS_PROXY`, installs its CA into the agent's trust store, matches host/method/path rules, attaches the credential as a header, logs MCP tool names. Weaknesses stated in its docs: session tokens travel over plain HTTP to a shared proxy, the session token is a bearer credential, and network isolation is recommended but not enforced. Node built-in `fetch` needs `NODE_USE_ENV_PROXY=1`. Source: [how it works](https://infisical.com/docs/documentation/platform/agent-vault/how-it-works).
- 1Password [V]: Environments mount `.env` files locally; the Environments MCP server never returns secret values; agent hooks (`1password-validate-mounted-env-files`, MIT, supports Claude Code, Cursor, Copilot, Windsurf) block shell commands when mounts are invalid; shell plugins replace API keys in shell profiles with biometric unlock; agentic autofill fills browser logins without exposing them to the model. Unified Access (2026-03-17) ships Discover and Secure; runtime scoped credential issuance was still "later this year". Sources: [security for AI](https://www.1password.dev/security-for-ai), [Unified Access](https://1password.com/press/2026/mar/1password-unified-access), [agent-hooks](https://github.com/1Password/agent-hooks).
- AgentCore token vault [V]: KMS-encrypted OAuth tokens, client credentials and API keys; built-in providers for Google, GitHub, Slack, Salesforce, Atlassian; `@requires_access_token` and `@requires_api_key` decorators; credential providers now support `grantType: TOKEN_EXCHANGE` ([AWS blog](https://aws.amazon.com/blogs/machine-learning/govern-ai-agent-access-with-okta-cross-app-access-and-amazon-bedrock-agentcore-part-2/), 2026-11-06).
- Composio reportedly had a May 2026 incident exposing about 5,000 connections and API keys [S, competitor source: [Nango](https://nango.dev/blog/best-token-vaults-and-credential-management-tools-for-ai-agents), 2026-07-30]. A hosted token vault is a concentrated target.

### 4. Delegation and on-behalf-of chains

- **Vault** [V]: for OBO, subject policies and agent ceiling policies are evaluated independently and both must allow. An agent with no ceiling is denied. The agent's own ACL policies are ignored for OBO. A default ceiling stops the agent using the subject's rights to edit its own constraints. Rich Authorization Requests (`authorization_details`) carry the task scope.
- **Entra** [V]: in OBO the user is the token subject, so Conditional Access evaluates the user's policies; a policy targeting the agent identity does not cover OBO requests. Intermediate token exchanges at the "AAD Token Exchange Endpoint: Public" are not evaluated by Conditional Access. API-key access bypasses it entirely. Source: [Conditional Access for agents](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id) (2026-07-31).
- **Okta** [V]: ID-JAG carries `act.sub` (agent principal) with `sub_profile: "ai_agent"`; agent-to-agent flows nest one `act` per hop.
- **AWS** [V]: docs say AgentCore Identity "supports impersonation flow". In the XAA sample the agent is identified by `client_id`, with Cedar principals `AgentCore::OAuthUser`.
- **Keycard** [V]: sub-agents and tools cannot exceed the parent's privileges; RFC 8693 exchange narrows at each hop (multi-agent launch 2026-05-14 [S]).
- **Standards** [V]: draft-ietf-oauth-identity-assertion-authz-grant-06 says processing of `actor_token` and `act` is not normatively defined. WIMSE adopted draft-ietf-wimse-aims-00 "AI Identity Management System" (2026-09-15) [S, datatracker listing]. No RFC exists for agent delegation chains.

### 5. MCP authorisation gateways

- **Okta Agent Gateway** [V]: presents as an MCP server, brokers XAA or STS consent, logs each tool call against agent and user, "instant revocation at the gateway endpoint". Self-hosted "MCP Bridge" only via Professional Services. ([blog](https://www.okta.com/blog/product-innovation/agent-gateway-runtime-governance/), 2026-07-23)
- **AgentCore Gateway + Policy** [V/S]: Cedar, default deny, evaluated on tool list and tool call; Policy GA 2026-03-03 [S]. Caveats from AWS's own post: a `forbid` whose `hasTag` guard is skipped blocks nothing; a policy that is not `ACTIVE` denies everything; tool-named policies did not attach to dynamically listed targets.
- **Cloudflare MCP server portals** [V]: one endpoint, up to 120 servers, per-tool enable/allowlist, Gateway DLP on routed traffic, Code Mode (`off|opt_in|default_on|enforced`), stateless MCP 2026-07-28. Limits: remote HTTP servers only (no stdio), 60 s tool timeout, admin tokens expire silently, and Access features such as independent MFA and purpose justification are not enforced for portal-authorised servers. ([docs](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/))
- **Tailscale Aperture** [V]: GA 2026-08-26; LLM and MCP proxy keyed on tailnet identity, default tool permissions, request/response hooks, per-machine approval. ([blog](https://tailscale.com/blog/aperture-ga))
- **Descope Agentic Identity Hub** [V]: Clients (DCR, CIMD, JWT bearer), Resources, Connections vault, Gateways (early access), policies evaluated at token issuance and exchange, issues and validates ID-JAGs. ([docs](https://docs.descope.com/agentic-identity-hub))
- **Open source**: agentgateway (Apache-2.0, 6.1k stars), ToolHive (Apache-2.0, 2.3k), AuthPlane authserver (AGPL-3.0, accepts ID-JAGs since v0.2.0), Cloudflare `workers-oauth-provider` (MIT, experimental EMA since 0.7.0), FastMCP 4.0 beta. [V via GitHub API and the MCP EMA table]

### 6. Discovery of non-human identities and secrets

- **Agentless API posture scanning** of IdPs, clouds and SaaS for service accounts, OAuth grants and keys: Astrix (Cisco), Oasis, Token Security, Clutch, Entro (SailPoint), Idira [S]. Idira lists AWS Bedrock and Copilot Studio as discovery sources [S].
- **Endpoint discovery**: BeyondTrust Pathfinder classifies "agentic processes" by process naming, signatures and LLM API traffic patterns, and discovers MCP servers, LLM endpoints and skills [V, [docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security), 2026-10-13]. 1Password Discover finds AI tools plus unencrypted SSH keys and plaintext `.env` files on devices [V]. Okta claims browser, endpoint and network detection [V, press release; mechanism undocumented].
- **Agent 365 local-agent detection** reportedly covers only one first-party platform at GA, and third-party platforms sync to the registry without runtime enforcement [S, competitor blog].

### 7. Lifecycle, revocation and continuous evaluation

- Entra: lifecycle workflows, sponsor tasks, ID Protection for risky agents (unfamiliar resources, sign-in spikes), Conditional Access at token issue/refresh, CAE on some resources, preview "Agent execution environments" condition for device compliance [V].
- CrowdStrike: SGNL closed 2026-02-20; "Continuous Identity for AI Agents" announced June 2026, based on CAEP signals [S].
- Vault and AgentCore Policy re-evaluate every request [V].
- Okta: kill switch and agent deactivation [V]; whether ID-JAG redemption re-checks the user was not confirmed.
- BeyondTrust: "pre-enforcement replay" runs a draft policy against recorded activity before saving [V].

### 8. What is still unsolved

1. **Local developer credentials.** `gh`, `aws`, `gcloud`, `kubectl`, SSH agent and cloud CLIs all sit in the user profile. Any agent process inherits them. No identity product intermediates these; only endpoint sensors see the use.
2. **Long-lived keys in dotfiles and `mcp.json`.** 1Password and Infisical offer opt-in fixes. Nothing enforces migration or detects regression fleet-wide in open source.
3. **Agent inherits the whole user session.** BeyondTrust separates agent-process actions from human actions under the same credentials, but by kernel and network controls, not by giving the agent a distinct credential. Browser agents reuse the user's cookies.
4. **Sub-agent delegation.** Attenuation per hop exists in Keycard and Vault only. No interoperable format; `act` nesting is vendor-specific.
5. **Cross-vendor identity.** An Entra agent identity, an Okta UD agent, an AgentCore workload identity and a Google SPIFFE ID for the same agent are unrelated objects. WIMSE AIMS is at -00.
6. **Stdio MCP servers.** Gateways and EMA cover remote HTTP only. Local stdio servers take credentials from environment variables.
7. **Revocation latency.** Bearer tokens of 1 hour are normal; only Google binds tokens to keys by default.
8. **Tool-level authorisation in the standard.** EMA stops at the connection.

## Matrix

| Vendor (status) | Agent identity | Owner binding | Credential delivery | Delegation | MCP gateway | Discovery | Standards |
|---|---|---|---|---|---|---|---|
| Microsoft Entra Agent ID + Agent 365 (GA 2026-05) | Blueprint, agent identity, agent user | Sponsor, lifecycle workflows | FIC / managed identity on blueprint; sidecar SDK | OBO; CA evaluated on user | Via Foundry / GSA | Agent 365 registry, Defender | OAuth 2.0 OBO, CAE |
| Okta for AI Agents (GA 2026-05) | UD agent, private key JWT, CIMD | Named owner, certifications | ID-JAG, STS consent, OPA vault | Nested `act` | Agent Gateway | Browser, endpoint, network, ISPM | ID-JAG, RFC 8693, 7523 |
| AWS AgentCore (GA) | Workload identity ARN | IAM ownership | KMS token vault, 2LO/3LO, TOKEN_EXCHANGE | "Impersonation" | Gateway + Cedar Policy | None beyond own runtime | OAuth, Cedar, SigV4 |
| Google Agent Identity | SPIFFE ID, 24 h X.509 | IAM | Auth manager vault, 2LO/3LO, API key | Delegated identity via 3LO | Agent Gateway | Agent Registry | SPIFFE, mTLS, DPoP |
| Vault Agentic IAM (Ent 2.1+) | Entity + registry record | Free-form `owner` | Dynamic secrets | Ceiling intersection, RAR | Vault MCP server (beta) | No | OAuth RS, RAR |
| Idira / Palo Alto (ex-CyberArk) | Registered agent | Owner enrichment | JIT, Secrets Hub | Not documented | AI Agent Gateway [S] | SaaS, cloud, dev envs | Not verified |
| CrowdStrike (SGNL) | Via IdP | Via IdP | Runtime access decisions | Not documented | No | Falcon | CAEP |
| 1Password | None (user's vault) | Vault owner | Mounted `.env`, autofill, shell plugins, hooks | No | No | Endpoint: AI tools, SSH keys, `.env` | None |
| BeyondTrust AI Agent Security | None ("runs as user") | OS user | Not described | No | No (kernel + network) | Endpoint classifiers | None |
| Keycard (early access) | Attested agent + device + user + task | Developer | In-memory per tool call; gateway exchange | Attenuation per hop | Optional gateway | No | OAuth 2.1, RFC 8693 |
| Aembit (GA 2026-04 [S]) | Trust-provider attestation | "Blended identity" | MCP Identity Gateway injection | Agent + user blend | Yes | No | OAuth, OIDC |
| Infisical Agent Vault (OSS) | Session token | Orchestrator | MITM proxy header injection | No | Logs MCP tools | No | None |
| Cloudflare MCP portals | Access identity or service token | Access user | Per-user OAuth or admin credential | No | Yes | Gateway logs | OAuth, EMA (library) |
| Tailscale Aperture (GA 2026-08) | Tailnet node identity | Tailnet user | Proxy holds provider keys | No | Yes | Tailnet | WireGuard identity |
| Descope | OAuth client, CIMD, DCR | Consent record | Connections vault, RFC 8693 | User to agent | Gateways (EA) | No | ID-JAG, CIMD |
| Teleport | X.509 workload identity | Bot owner / RFD 0238 | Short-lived certs | In progress | MCP proxy | In progress | SPIFFE, MCP |

## Weak points, gaps and risks

- **Registration is the precondition for everything.** Unregistered agents get no identity, so shadow agents are visible only to posture scanners and endpoint sensors, never to the control plane.
- **Policy fail-open hazards.** AWS documents that a skipped `forbid` blocks nothing. Entra's Conditional Access silently does not apply to API keys or intermediate exchanges.
- **Identity churn.** Google mints a new principal per redeploy and leaves stale bindings.
- **MITM proxies are fragile.** They depend on `HTTPS_PROXY` and CA trust; pinned clients and non-HTTP protocols bypass them, and the proxy session token is itself a bearer secret.
- **Vendor lock and paywalls.** Entra, Okta, Vault and Idira gate agent controls behind top-tier licences. Acquired products (Astrix, SGNL, Entro, Natoma) are being folded into suites; CSA flags roadmap and pricing risk ([note](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons/), 2026-05-06).
- **Draft churn.** ID-JAG implementations target different revisions (Keycloak targets -01, Janssen -04, current is -06).

## Implications for our design

Recommended feature set for the open-source identity and secrets module.

**Build**

1. **Process-derived agent identity.** Give every discovered agent process an identity from attested local facts: binary hash and signer, parent chain, launching user, device, repo, session. Emit it as a SPIFFE-style ID and a signed, short-lived JWT. This covers agents nobody registered, which no commercial product does.
2. **Local credential broker daemon (Rust).** One per endpoint. Serves as `apiKeyHelper` for Claude Code, a credential helper for git, a `credential_process` for AWS, and an SSH agent shim. Releases short-lived, audience-scoped credentials only to attested agent processes and records agent versus human on every release.
3. **Egress injection proxy.** Same idea as Infisical Agent Vault but bound to process identity through the OS sensor rather than a bearer session token, with enforced network isolation and placeholder substitution for stdio MCP server environments.
4. **Dotfile and config secret inventory.** Continuous scan of `.env`, `mcp.json`, shell profiles, `~/.claude/.credentials.json`, `~/.aws`, `~/.config/gh`, SSH keys; map each secret to the agents that can read it; offer one-step migration into the broker.
5. **Delegation ledger with ceilings.** Copy Vault's rule: effective rights are the intersection of the human's policy and the agent's ceiling, attenuating per sub-agent hop. Encode as nested `act` claims and RAR-style `authorization_details`.
6. **Owner binding and lifecycle.** Mandatory sponsor (a principal, not a string), expiry, orphan detection, kill switch that revokes broker leases and pushes a CAEP event.
7. **Policy replay.** Run a draft policy against recorded activity before enforcing, as BeyondTrust does.

**Integrate, do not rebuild**

- Identity providers: consume Entra Agent ID, Okta UD agents and Google SPIFFE IDs as external identities and correlate them to our process identities. Act as an ID-JAG requesting client and accept ID-JAGs at our gateway.
- Workload identity: SPIFFE/SPIRE (Apache-2.0) for server and Kubernetes attestation.
- Secret stores: OpenBao (MPL-2.0), Vault, Infisical, 1Password (`op` and service accounts), cloud secret managers as back ends behind one broker interface.
- Gateways: agentgateway (Apache-2.0) as the default MCP/LLM data plane; feed decisions to AgentCore Gateway, Cloudflare portals and Okta Agent Gateway rather than replacing them.
- Authorisation engines: Cedar or Cerbos (Apache-2.0) for policy, SpiceDB (Apache-2.0) for relationships.
- Model-provider keyless auth: configure Anthropic and OpenAI workload identity federation with our issuer so agents never need static model keys; push Claude Code managed settings (`forceLoginMethod`, `allowedProviders`).
- Signals: emit and consume OpenID Shared Signals / CAEP so CrowdStrike, Okta and Entra can react to our revocations.

**Avoid**

- A hosted multi-tenant token vault as the only mode. Keep secrets in the customer's store; our broker holds leases, not long-lived tokens.
- Bearer session tokens for the proxy. Bind to process identity or use DPoP.
- Policies that fail open on missing attributes.

## Ideas worth stealing and whitespace

- **Vault's OBO ceiling** with a default policy that stops an agent editing its own constraints.
- **Google's double binding** (mTLS certificate plus DPoP) with a default policy that rejects unbound tokens.
- **Keycard's 4-tuple scope** (user, agent, device, task) and per-tool-call issuance.
- **BeyondTrust's pre-enforcement replay** and "hold for approval" as a first-class verdict.
- **1Password's rule that an MCP server never returns secret values**, only handles.
- **Entra's blueprint**: one template, many instances, policy at the template.
- **Okta's connection-type enum** as a clean taxonomy of credential patterns.

Whitespace nobody covers well: identity for unregistered local agents; Linux endpoints; stdio MCP credential hygiene; a cross-vendor correlation graph linking Entra, Okta, AWS and Google agent objects to actual processes; open-source OBO with ceilings (Vault's is Enterprise-only); tool-call-level authorisation that travels with the token; embeddable SDK form for EDR vendors.

## Could not verify / open questions

- Akeyless, Doppler, Veza (ServiceNow, announced late 2025 [B]), Saviynt Agent Access Gateway, Ping "Identity for AI", SailPoint Agent Identity Security, Silverfort, Oso, Clutch, Stytch, WorkOS, Scalekit: no primary source read this session beyond the MCP EMA table.
- Palo Alto and CyberArk close date; `docs.cyberark.com/.../secureai/introduction.htm` returned 404 and cyberark.com now redirects to paloaltonetworks.com/idira.
- Cisco/Astrix close date (2026-06-29 [S]) and Cyera/Oasis status (LOI 2026-07-28 [S]); Natoma to Snowflake (2026-05-27 [S]); Entro price ($122.6M versus about $200M [S]).
- Agent 365 list price; the scope of its local-agent detection.
- Whether Okta re-checks the user at ID-JAG redemption.
- OpenAI Codex "Agent Identity" per-task assertions: secondary and speculative.
- DCR deprecation in MCP 2026-07-28: reported by Descope only; core spec not read.
- Okta shadow-agent detection mechanics.
- agentgateway identity features (token exchange, upstream credential injection): docs index only.

## Sources

- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security : BeyondTrust AI Agent Security, 2026-10-13
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview : Agent 365 overview, 2026-08-19
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/capabilities-entra : Protect agent identities with Entra, 2026-05-12
- https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities : What are agent identities, updated 2026-06-15
- https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint : Agent identity blueprints, 2026-04-28
- https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols : Agent authentication protocols, updated 2026-08-13
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id : Conditional Access for agents, 2026-07-31
- https://developer.okta.com/docs/guides/ai-agent-token-exchange/authserver/main/ : Okta AI agent token exchange
- https://www.okta.com/blog/product-innovation/agent-gateway-runtime-governance/ : Okta Agent Gateway, 2026-07-23
- https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso/ : Okta Agent SSO, 2026-08-24
- https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization : MCP Enterprise-Managed Authorization, spec 2026-07-28
- https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ : ID-JAG draft -06, 2026-10-30
- https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/00/ : WIMSE AI Identity Management System, 2026-09-15
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/key-features-and-benefits.html : AgentCore Identity features
- https://aws.amazon.com/blogs/machine-learning/govern-ai-agent-access-with-okta-cross-app-access-and-amazon-bedrock-agentcore-part-2/ : Okta XAA with AgentCore, 2026-11-06
- https://docs.cloud.google.com/iam/docs/agent-identity-overview : Google Agent Identity overview
- https://developer.hashicorp.com/vault/ai : Vault + agentic AI
- https://developer.hashicorp.com/vault/ai/iam/concepts/agent-registry : Vault agent registry
- https://goteleport.com/docs/agentic-identity-framework/ : Teleport Agentic Identity Framework
- https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/ : Keycard for Coding Agents, 2026-03-19
- https://www.1password.dev/security-for-ai : 1Password security for AI
- https://1password.com/press/2026/mar/1password-unified-access : 1Password Unified Access, 2026-03-17
- https://github.com/1Password/agent-hooks : 1Password agent hooks (MIT)
- https://infisical.com/docs/documentation/platform/agent-vault/how-it-works : Infisical Agent Vault
- https://github.com/Infisical/agent-vault : Agent Vault repository
- https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/ : Cloudflare MCP server portals
- https://tailscale.com/blog/aperture-ga : Tailscale Aperture GA, 2026-08-26
- https://docs.descope.com/agentic-identity-hub : Descope Agentic Identity Hub
- https://code.claude.com/docs/en/authentication : Claude Code authentication
- https://developers.openai.com/api/docs/guides/workload-identity-federation : OpenAI workload identity federation
- https://developers.openai.com/codex/enterprise/access-tokens : Codex access tokens
- https://www.paloaltonetworks.com/idira : Idira (formerly CyberArk)
- https://www.token.security/news/token-security-introduces-intent-based-security-for-ai-agents : Token Security, 2026-03-18
- https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons/ : CSA note on consolidation, 2026-05-06
- https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-sgnl-transform-identity-security-ai-era : CrowdStrike to acquire SGNL, 2026-01-08
- https://nango.dev/blog/best-token-vaults-and-credential-management-tools-for-ai-agents : Nango token vault comparison, 2026-07-30 (competitor source)
- https://aembit.io/iam-for-agentic-ai/ : Aembit IAM for Agentic AI (not fetched; search summary)
- https://github.com/agentgateway/agentgateway : agentgateway (Apache-2.0)

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Each claim was re-read in the primary source and, where one existed, tested against a source the brief did not cite (spec repository, draft text, vendor release notes, source repositories). The shared web-search budget was exhausted, so BeyondTrust (claim 5) and the AWS sample (claim 9) could only be re-read in the vendor's own page; no second source was found for either._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | MCP Enterprise-Managed Authorization is a stable extension (2026-07-28) built on ID-JAG; Okta, PingFederate 13.1, Descope, Athenz, Janssen, ThunderID issue ID-JAGs; Keycloak 26.7 accepts them experimentally | Confirmed | The ext-auth repo holds the spec under `specification/stable/enterprise-managed-authorization/2026-07-28`. PingFederate 13.1 release notes (June 2026), Janssen docs, ThunderID docs and the Athenz ZTS doc each confirm both roles. Keycloak 26.7.0 release notes list it as experimental, accept-only, behind `identity-assertion-jwt`, targeting draft -01. Janssen is off by default behind a feature flag and targets -04. Okta and Descope were checked only through the MCP table. | [ext-auth](https://github.com/modelcontextprotocol/ext-auth/tree/main/specification/stable/enterprise-managed-authorization), [Keycloak release notes](https://www.keycloak.org/docs/latest/release_notes/index.html), [PingFederate 13.1](https://docs.pingidentity.com/pingfederate/13.1/release_notes/pf_release_notes_131.html), [Janssen](https://docs.jans.io/stable/janssen-server/auth-server/endpoints/identity-assertion-authz-grant/), [ThunderID](https://thunderid.dev/docs/use-cases/ai-agents/mcp-authorization/enterprise-managed-authorization/) |
| 2 | ID-JAG draft is at -06 (2026-10-30), still an Internet-Draft, no normative processing for `actor_token` or `act` | Confirmed | Datatracker API: rev 06, state Active, "I-D Exists", intended status Standards Track, no WG Last Call. The document itself is dated 31 October 2026 (submitted 2026-10-31T00:32Z; the datatracker page shows 2026-10-30). Text: "This specification does not define normative processing requirements for actor_token or whether an act claim is included in the issued ID-JAG." `act` is still a defined OPTIONAL claim. Also relevant to claim 9: the draft lets a client re-submit the same ID-JAG, and single use (tracking `jti`) is optional for the resource AS. | [draft -06 text](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-06.txt), [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) |
| 3 | Entra agent identities are confidential clients only; credentials on the blueprint; multi-stage token exchanges; no interactive `/authorize`, no public clients | Confirmed | Wording matches the protocols page and the blueprint page ("Credentials used to authenticate an agent identity are configured on the agent identity blueprint"). One exception to note: a blueprint may carry a web redirect URI for consent only (`response_type=none`). User sign-in happens in a separate client application that calls the agent through OBO. | [protocols](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols), [blueprints](https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint) |
| 4 | Entra Conditional Access for agents evaluates the user in OBO, skips intermediate exchanges and API-key access, needs Agent 365 or M365 E7 | Confirmed, with a licensing precision | Licence is Microsoft 365 E7, or Agent 365 paired with at least Entra ID P1 or Microsoft 365 E3 (P2 or E5 for agent-risk conditions). Agent 365 alone is not enough. The OBO token exchange itself is evaluated; only the exchange at "AAD Token Exchange Endpoint: Public" is not. Conditional Access also does not apply when security defaults are on. Page updated 2026-10-07. | [Conditional Access for agents](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id), [autonomous agents policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents) |
| 5 | BeyondTrust AI Agent Security supports only Windows 11/Server 2022 x64 and macOS 14 to 26; agents run as the signed-in user with no identity | Confirmed | "Windows 11, or Windows Server 2022 or later, on x64 hardware"; Windows on Arm unsupported; macOS 14, 15 and 26 (current major plus two prior); "supports Windows and macOS endpoints only". The exact sentence is "An agent runs as the signed-in user, with no identity of its own"; the brief's quotation is a paraphrase, not verbatim. | [BeyondTrust docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security) |
| 6 | Claude Code stores credentials in `~/.claude/.credentials.json` on Linux and Windows, `claude setup-token` mints a one-year token, managed settings can block `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `apiKeyHelper` | Confirmed | Linux file is mode 0600; Windows relies on profile ACLs; macOS uses the Keychain and falls back to the file. The three credential sources are "blocked at startup" when `forceLoginMethod` or `forceLoginOrgUUID` is set. Gaps worth knowing: `claude setup-token` enforces only `forceLoginMethod`, so it can mint a token in a different organisation; the token is printed, not stored, and is inference-only. | [Claude Code authentication](https://code.claude.com/docs/en/authentication) |
| 7 | Vault Agentic IAM is Enterprise-only (2.1.0+); OBO is the intersection of subject policies and agent ceiling; no ceiling means deny | Confirmed | "Available in Vault Enterprise 2.1.0+". Release notes show an Enterprise public beta from 2.0.3 (2026-06-17) and GA in 2.1.0 (2026-09-01). "If the agent has no ceiling policies, Vault denies every OBO request from that agent." Vault adds two built-in ceiling policies unless `no_default_ceiling_policy` is true. | [Vault AI](https://developer.hashicorp.com/vault/ai), [release notes](https://developer.hashicorp.com/vault/docs/updates/release-notes), [agent registry](https://developer.hashicorp.com/vault/ai/iam/concepts/agent-registry) |
| 8 | Google Agent Identity: SPIFFE IDs, 24-hour X.509, tokens bound with mTLS and DPoP, new principal on every redeploy | Corrected | SPIFFE ID, 24-hour certificate and certificate-bound tokens are confirmed. A new principal is created only when an agent is deleted and a replacement deployed ("the new agent receives a new resource ID and therefore a new principal identifier"); the page does not say an in-place update or redeploy changes the identity. mTLS binding is the default for direct Google API calls; DPoP is added only for traffic across Agent Gateway. | [Agent Identity overview](https://docs.cloud.google.com/iam/docs/agent-identity-overview) |
| 9 | AWS Okta XAA sample: one ID-JAG covered every tool call and opened a second session within its 5-minute life; a Cedar `forbid` whose `hasTag` guard is skipped blocks nothing | Confirmed, wording clarified | The post says "one single-use ID-JAG serves every tool call in a session" and "it also opened a second session within its 5-minute life". On Cedar the precise statement is: a policy that reads a missing tag errors and is skipped, and "a skipped `forbid` blocks nothing"; the `hasTag` guard is the fix, so the failing case is a `forbid` written without the guard. Cedar's own docs confirm errored policies are skipped. Single-vendor test result, not reproduced elsewhere. | [AWS blog](https://aws.amazon.com/blogs/machine-learning/govern-ai-agent-access-with-okta-cross-app-access-and-amazon-bedrock-agentcore-part-2/), [Cedar authorization](https://docs.cedarpolicy.com/auth/authorization.html) |
| 10 | Infisical Agent Vault is an open-source MITM credential proxy using `HTTPS_PROXY` and an installed CA; session tokens travel over plain HTTP to a shared proxy; isolation recommended, not enforced | Corrected | The mechanism and the caveats are confirmed: plain HTTP applies to the common-proxy setup ("use this setup only if your agents and the proxy share a private network"), and isolation is listed under "we recommend". The "open source" label conflates two products. The standalone MIT repository (2,494 stars, v0.40.2 on 2026-10-22) now opens with "This open-source Agent Vault project is no longer the recommended way to run Agent Vault for any use case". The cited docs describe Agent Vault inside the Infisical platform, whose server code sits in `backend/src/ee` under the Infisical Enterprise License (production use needs a valid licence). The docs do not call the session token a "bearer credential"; they say a leaked token gives the same access until expiry or revocation. | [agent-vault README](https://github.com/Infisical/agent-vault), [Infisical ee licence](https://github.com/Infisical/infisical/blob/main/backend/src/ee/LICENSE.md), [how it works](https://infisical.com/docs/documentation/platform/agent-vault/how-it-works) |

### Further statements checked

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Section 8, item 6: "Gateways and EMA cover remote HTTP only" for stdio MCP servers | Corrected | True for EMA and Cloudflare MCP portals. Not true for the open-source gateways the brief recommends: agentgateway lists "stdio/HTTP/SSE/Streamable HTTP transports" and has a stdio upstream (`crates/agentgateway/src/mcp/upstream/stdio.rs`); ToolHive runs MCP servers in containers and fronts them. The gap is credential hygiene for stdio servers launched directly by the agent, not gateway transport support. | [agentgateway](https://github.com/agentgateway/agentgateway), [ToolHive](https://github.com/stacklok/toolhive) |
| Design items "broker serves as `apiKeyHelper` for Claude Code" and "push Claude Code managed settings (`forceLoginMethod`, `allowedProviders`)" | Corrected (the two conflict) | With `forceLoginMethod` or `forceLoginOrgUUID` set, Claude Code blocks `apiKeyHelper`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` at startup, "even when managed settings supply them". A broker acting as `apiKeyHelper` cannot coexist with those login policies on the same machine. Workload identity federation profiles and gateway sign-in are not blocked by them. | [Claude Code authentication](https://code.claude.com/docs/en/authentication) |
| TL;DR: 1Password mounted `.env` is Mac/Linux only and its Cursor hook is a no-op on Windows | Confirmed | Hook README: local `.env` files "are only available on Mac and Linux. Windows is not yet supported. If you're on Windows, the hook will skip any validations." This applies to every supported agent (Cursor, Claude Code, Copilot, Windsurf), not only Cursor. | [1Password agent-hooks](https://github.com/1Password/agent-hooks/tree/main/hooks/1password-validate-mounted-env-files) |
