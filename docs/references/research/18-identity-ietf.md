# Internet standards for agent identity, authorisation and delegation (IETF, OAuth, WIMSE, SPIFFE)
_Researched 2026-11-09_

Method: document versions, dates and states were read from the IETF Datatracker API and draft text on 2026-11-09. Vendor facts come from the vendors' own docs pages. "Inferred" marks my reasoning. Web search was cut off early by a shared budget, so implementer coverage is thinner than document coverage.

## TL;DR

- **No agent-specific identity standard is an RFC.** The stable base is OAuth RFCs (8693, 8705, 8707, 9068, 9126, 9396, 9449, 9470, 9700, 9728), RFC 9421, SD-JWT (RFC 9901) and SCITT architecture (RFC 9943). Everything that names "agent" is a draft.
- **The IETF's consensus direction is "agents are workloads".** `draft-ietf-wimse-aims-01` (WG document, 2026-11-02) composes WIMSE/SPIFFE identifiers, WIT or X.509 credentials, OAuth delegation, Transaction Tokens, identity chaining, CIBA and OpenID SSF. It defines no new protocol.
- **Three new IETF venues exist as of this month.** `agentproto` and `dawn` were chartered October 2026 and first meet at IETF 127 (San Francisco, 14-20 Nov 2026). `audit` is a WG-forming BoF on 17 Nov. agentproto and dawn both explicitly refuse to define identity and defer to OAuth, WIMSE and webbotauth.
- **Delegation representation is converging on RFC 8693 nested `act` plus a `sub_profile` entity-type claim** (`ai_agent`), but the profile that says so (`draft-mcguinness-oauth-actor-profile-01`) is an individual draft. ID-JAG-06 still leaves `actor_token` processing undefined.
- **ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant-06`, 2026-10-31) is the enterprise path**: it underlies Okta Cross App Access and MCP's stable "Enterprise-Managed Authorization" extension. MCP pins draft -04; the IETF is at -06.
- **MCP authorisation (revision 2026-07-28) deprecates Dynamic Client Registration** in favour of Client ID Metadata Documents, requires RFC 9728 and RFC 8707, and forbids token passthrough. It pins OAuth 2.1 draft -13 (current -17) and CIMD -00 (current -03).
- **Near-RFC items to build on now**: identity chaining (-17, RFC Editor queue), Token Status List (-21, RFC Editor queue), RFC 10070 (7523bis, published 2026-11-07), WIMSE HTTP-signature profile (-08, publication requested), Transaction Tokens (-11, WG consensus reached).
- **SPIFFE now has a WIT-SVID** (Incubating, merged 2026-07-01; SPIRE v1.16.0 released 2026-11-05). It is a proof-of-possession credential, never a bearer token. `draft-ietf-oauth-spiffe-client-auth-03` lets an SVID act as OAuth client authentication.
- **Standards do not solve "agent and human share one credential".** Every specification assumes the agent is a distinct OAuth client or workload. BeyondTrust's own docs state the agent "runs as the signed-in user and has no identity of its own". Attribution on endpoints must be synthesised by sensors.
- **Vendors diverge from the drafts.** Microsoft Entra Agent ID signals agent-ness with proprietary claims (`xms_act_fct`, `xms_sub_fct` value `11`/`13`) rather than `act`. A claim normaliser is required.
- **Draft volume is a risk in itself**: 164 Internet-Drafts with "oauth" in the name had Datatracker activity in 2026, plus 36 WIMSE-named (since April), 38 SCITT-named (since June), 29 DAWN-named and 21 agentproto-named. Most are single-author and will expire.
- **Post-quantum is ready for TLS, not yet for token chains.** RFC 10024 (hybrid ECDHE-ML-KEM) and RFC 9964 (ML-DSA for JOSE/COSE) are published, but WIT-SVID permits only RSA/ECDSA algorithms.

## Findings

### 1. OAuth core and extensions

| Topic | Document, version, date | State | Role in human -> agent -> sub-agent -> tool |
|---|---|---|---|
| OAuth 2.1 | `draft-ietf-oauth-v2-1-17`, 2026-10-31 | WG document (still not in last call) | Baseline: PKCE, no implicit, exact redirect match |
| Token exchange | RFC 8693, 2020-01 | Proposed Standard | `subject_token` + `actor_token` yields a token with `sub` = human and nested `act` = agent chain; `may_act` pre-authorises an actor |
| DPoP / mTLS binding | RFC 9449 (2023-09) / RFC 8705 (2020-02) | Proposed Standard | Binds each hop's token to a key via `cnf.jkt` or `cnf.x5t#S256` |
| RAR | RFC 9396 (2023-05); `draft-ietf-oauth-rar-metadata-remediation-00` (2026-08-23) | PS; WG document | Structured `authorization_details` for tool-level permission; the draft adds type discovery and an insufficient-details error |
| Resource indicators | RFC 8707 | PS | Audience restriction per tool or MCP server |
| Protected resource metadata | RFC 9728 (2025-04-23) | PS | Tool advertises its authorisation server; mandatory in MCP |
| Client registration | RFC 7591; `draft-ietf-oauth-client-id-metadata-document-03` (2026-11-02) | PS; WG document | CIMD: `client_id` is an HTTPS URL the AS fetches; AS metadata flag `client_id_metadata_document_supported` |
| Attestation-based client auth | `draft-ietf-oauth-attestation-based-client-auth-12` (2026-10-18) | WG consensus, waiting for write-up | A client instance presents a key-bound attestation from an attester; carrier for agent-instance claims |
| JWT grants | RFC 10070 (2026-11-07, updates RFC 7523) | PS | Tightens audience rules for assertions |
| Identity chaining | `draft-ietf-oauth-identity-chaining-17` (2026-08-21) | RFC Editor queue | Cross-domain: token exchange in domain A for a JWT grant, redeemed in domain B |
| ID-JAG | `draft-ietf-oauth-identity-assertion-authz-grant-06` (2026-10-31) | WG document | IdP-brokered cross-app access; `typ: oauth-id-jag+jwt` |
| Transaction Tokens | `draft-ietf-oauth-transaction-tokens-11` (2026-08-21) | WG consensus, waiting for write-up | Short-lived, per-transaction JWT inside one trust domain; claims `txn`, `sub`, `scope`, `tctx`, `rctx`, `req_wl` |
| Step-up | RFC 9470 (2023-09) | PS | Resource demands stronger or fresher authentication |
| Deferred Token Response | `draft-ietf-oauth-deferred-token-response-01` (2026-10-31) | WG document | AS returns `deferral_code` and polls or calls back; AS-initiated asynchronous approval for any grant |
| Delegate SD-JWT | `draft-ietf-oauth-delegate-sd-jwt-00` (2026-10-30) | WG document | Holder delegates an SD-JWT to a delegate holder; text says it targets agentic systems |
| SD-JWT / SD-JWT VC | RFC 9901 (2025-11-20); `draft-ietf-oauth-sd-jwt-vc-26` (2026-11-06) | PS; IESG evaluation | Selective-disclosure credentials; basis of mandate proposals |
| Token Status List | `draft-ietf-oauth-status-list-21` (2026-11-03) | RFC Editor queue | Compact revocation status for JWT/CWT credentials |
| GNAP | RFC 9635 (2024-10), RFC 9767 (2025-04) | PS | Key-bound, interaction-flexible alternative to OAuth; I found no agent product using it |

Sources: https://datatracker.ietf.org/wg/oauth/documents/ and the per-document Datatracker pages (all read 2026-11-09).

**ID-JAG detail (verified from -06 text).** Required claims are `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat`. Optional claims include `resource`, `scope`, `authorization_details`, `act`, `tenant`, `aud_tenant`, `aud_sub`, `sub_id`, `auth_time`, `acr`, `amr`. Section 9.10 states that the token exchange may carry `actor_token` but the draft "does not define normative processing requirements for it". Section 9.11 defines DPoP and mTLS binding of the grant. Appendix A.4 is an AI-agent-with-external-tools use case using CIMD URLs as client IDs.

**MCP (verified).** The 2026-07-28 authorisation spec makes MCP servers OAuth resource servers that MUST implement RFC 9728 and validate audience per RFC 8707, and MUST NOT accept or transit other tokens. CIMD is SHOULD; DCR is MAY and "deprecated". STDIO transports are told not to use this spec and to take credentials from the environment. Two extensions are Stable at 2026-07-28: Enterprise-Managed Authorization (ID-JAG: `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`) and OAuth Client Credentials. Sources: https://modelcontextprotocol.io/specification/latest/basic/authorization, https://github.com/modelcontextprotocol/ext-auth.

**Human approval.** OpenID CIBA Core 1.0 is Final (2021-09-01): `backchannel_authentication_endpoint`, modes poll/ping/push, `binding_message`, grant `urn:openid:params:grant-type:ciba`. It does not define `authorization_details`. AIMS section 10.8 says local UI confirmation "MUST NOT" be treated as authorisation on its own, and notes CIBA is client-initiated and fits mid-execution approval poorly. The gap fillers are drafts: Deferred Token Response (WG) and `draft-rosomakho-oauth-txn-challenge-01` (2026-11-02, individual; resource returns a transaction challenge, AS obtains approval and issues a RAR-scoped token).

### 2. WIMSE, SPIFFE and SPIRE

| Document | Version, date | State |
|---|---|---|
| WIMSE Architecture | `draft-ietf-wimse-arch-08`, 2026-07-06 | WG document |
| Workload Identifier | `draft-ietf-wimse-identifier-04`, 2026-10-30 | WG document |
| Workload Credentials (WIT, WIC) | `draft-ietf-wimse-workload-creds-03`, 2026-10-30 | WG document |
| Workload Proof Token | `draft-ietf-wimse-wpt-02`, 2026-08-27 | WG document |
| Workload-to-workload HTTP signatures | `draft-ietf-wimse-http-signature-08`, 2026-10-28 | Publication requested |
| Mutual TLS | `draft-ietf-wimse-mutual-tls-03`, 2026-10-30 | WG document |
| Workload Identity Practices | `draft-ietf-wimse-workload-identity-practices-08`, 2026-10-30 | IETF Last Call |
| AI Identity Management System | `draft-ietf-wimse-aims-01`, 2026-11-02 | WG document (replaced `draft-klrc-aiagent-auth`) |

The former `draft-ietf-wimse-s2s-protocol` was split into the four credential and proof documents above. The WIMSE charter text does not mention AI agents and its milestones are dated 2024-2026; none is met.

Verified mechanics:
- **Identifier**: a URI with a trust-domain authority and a path, with no query, fragment, userinfo or port, and at most 2048 bytes. Schemes are `spiffe://` or the new `wimse://`.
- **WIT**: JWT with `typ: wit+jwt`, `sub` = workload identifier, `exp`, optional `iss` and `jti`, and `cnf.jwk` (with mandatory `alg`). It "MUST NOT be used as a bearer token". HTTP header `Workload-Identity-Token`.
- **WPT**: `typ: wpt+jwt`, `aud` = target URI, lifetime of seconds to minutes, `jti`, `wth` (WIT hash); it can also bind a transaction token.
- **HTTP-signature profile**: RFC 9421 with `tag="wimse-workload-to-workload"`; `keyid` and `alg` are forbidden because the key comes from the WIT.
- **AIMS rules**: an agent "MUST be assigned exactly one WIMSE identifier, which MAY be a SPIFFE ID". Identifiers are never reassigned after retirement. Static API keys are called an antipattern. Tools forwarding a received access token downstream is called an anti-pattern.

**SPIFFE/SPIRE.** WIT-SVID was merged into the SPIFFE standards on 2026-07-01 and is labelled Incubating. It requires `kid`, forbids `aud`, and allows only RS/ES/PS algorithms. SPIRE releases: v1.16.0 (2026-11-05), v1.15.5 and v1.14.9 (2026-10-20). `draft-ietf-oauth-spiffe-client-auth-03` (2026-11-02, WG document) defines `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` for JWT-SVIDs, X509-SVID over RFC 8705, and CIMD members `spiffe_id` and `spiffe_bundle_endpoint`. Sources: https://spiffe.io/docs/latest/spiffe-specs/wit-svid/, https://github.com/spiffe/spire/releases.

### 3. Agent-specific drafts (all individual unless stated)

| Draft | Version, date | What it adds |
|---|---|---|
| `draft-mcguinness-oauth-actor-profile` | -01, 2026-10-09 | Profiles `act`: each actor object MUST carry `iss`, SHOULD carry `sub_profile`; nested chain, outermost = current presenter; cross-domain implementations SHOULD support depth 4; `may_act` does not propagate |
| `draft-mora-oauth-entity-profiles` | -02, 2026-10-16 | Registry for `client_profile` and `sub_profile`; defines `ai_agent` |
| `draft-mcguinness-oauth-ai-agent-instance` | -00, 2026-07-04 | `agent_instance_id` (attester-minted, stable, not key-derived), `agent_platform`, model and runtime provenance; attested sub-agent chains |
| `draft-mcguinness-oauth-mission` | -02, 2026-11-02 | A durable "Mission" object: task intent via PAR, derived RAR, every token carries a `mission` claim, revocation stops issuance |
| `draft-araut-oauth-transaction-tokens-for-agents` | -03, 2026-10-31 | `agentic_ctx` claim in Txn-Tokens; replaces `draft-oauth-transaction-tokens-for-agents-06`; not WG-adopted |
| `draft-mw-oauth-actor-chain` | -03, 2026-11-02 | Per-hop actor proofs with full, subset or actor-only disclosure |
| `draft-niyikiza-oauth-attenuating-agent-tokens` | -02, 2026-10-26 | Offline-verifiable attenuating capability tokens over tool names and argument constraints |
| `draft-hardt-oauth-aauth-protocol` | -11, 2026-09-25 | AAuth: every agent instance has an `aauth:local@domain` identifier and signs every request (RFC 9421); person server, missions |
| `draft-rosenberg-oauth-aauth` | -02, 2026-11-01 | A different "AAuth": an OAuth 2.1 grant with human-in-the-loop approval at access time |
| `draft-goswami-agentic-jwt` | -01, 2026-06-27 | Agent identity as a checksum of prompt, tools and config; `agent_checksum` grant |
| `draft-lee-wimse-local-tool-call-proof` | -01, 2026-10-12 | Per-call, single-use proof for MCP stdio tools, issued by a Call Authority outside the agent process |
| `draft-ni-wimse-ai-agent-identity` | -04, 2026-10-28 | WIMSE applicability; binding an agent to an accountable user or organisation |
| `draft-oauth-ai-agents-on-behalf-of-user` | -02 | Expired 2026-02-27 |

### 4. HTTP Message Signatures and Web Bot Auth

RFC 9421 is the base. The `webbotauth` WG's only adopted document is `draft-ietf-webbotauth-httpsig-protocol-01` (2026-10-29, Cloudflare and Google authors). The agent's identifier is the HTTPS URL in `Signature-Agent`; the signature uses `tag="web-bot-auth"`; keys are a JWKS at `/.well-known/http-message-signatures-directory`. The charter covers AI agents acting for users but excludes authenticating the end user, HTTP APIs and agent-to-agent interfaces. Its milestones (April and August 2026) are missed. Cloudflare's docs (2026-10-08) implement it with Ed25519 and still cite the older `draft-meunier-*` versions. Source: https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/.

### 5. SCIM for agents

No WG-adopted agent schema exists. `draft-wzdk-scim-agent-resource-00` (2026-06-05, Microsoft and Okta authors) defines resource type `urn:ietf:params:scim:schemas:core:2.0:Agent` with `active`, a unique name and multi-valued `owners`. `draft-kushwaha-scim-agent-governance-00` (2026-07-27, Oracle) adds lifecycle state, autonomy class and validity window. Earlier attempts (`draft-wahl-scim-agent-schema-01`, `draft-abbey-scim-agent-extension-00`) expired.

### 6. Audit: SCITT and the AUDIT BoF

RFC 9943 (SCITT architecture, 2026-06-30) is published; `draft-ietf-scitt-scrapi-11` is in the RFC Editor queue. `draft-kuehlewind-audit-architecture-01` (2026-09-07) proposes distributed audit records, propagated audit context, and optional RATS attestation plus SCITT transparency; it maps the agent to "Workload (with sub_profile=ai_agent)". `draft-liu-audit-enforcement-points-00` (2026-11-02) classifies enforcement points as Agent (hooks, citing Claude Code and Cursor hooks), Gateway and Host (EDR). That is our architecture, written up as an IETF draft. The `audit` group is in BoF state in the Security Area and is not chartered.

### 7. New groups and meetings

- IETF 124 (Montreal, Nov 2025): agent side meeting with about 125 people in the room (IETF blog, 2026-01-22).
- IETF 126: WG-forming BoFs for agentproto and dawn; audit side meeting.
- IETF 127: first meetings of **agentproto** (ART area; dialog management protocol; milestones to March 2028; "will not define new identity, authentication, authorization") and **dawn** (INT area; discovery via DNS/mDNS; identity management out of scope; protocol due 2027-12-31). **audit** BoF and a proposed IRTF **net4ai** group also meet.
- OpenID: Authorization API 1.0 (AuthZEN) is Final, 2026-01-11. The AIIM community group explicitly defers protocol work.

Sources: https://www.ietf.org/blog/ietf127-new-topics/, https://datatracker.ietf.org/group/agentproto/about/, https://datatracker.ietf.org/group/dawn/about/.

### 8. Post-quantum

RFC 9954 (hybrid key exchange design, 2026-07-15), RFC 10024 (hybrid ECDHE-ML-KEM groups for TLS 1.3, 2026-08-10) and RFC 9964 (ML-DSA for JOSE and COSE, 2026-05-20) are published. `draft-ietf-tls-mlkem-11` is in the RFC Editor queue; `draft-ietf-jose-pq-composite-sigs-06` and `draft-ietf-jose-hpke-encrypt-22` are active. Inferred: ML-DSA signatures are several kilobytes, so a request carrying WIT + WPT + transaction token + nested `act` in headers will exceed common proxy header limits. `draft-uppalapati-wimse-pq-agent-identity-01` argues retained delegation records need post-quantum time anchoring.

## Matrix: who implements what (verified from vendor docs unless marked)

| Implementer | Evidence |
|---|---|
| Keycloak 26.8.2 (2026-11-05) | JWT authorisation grant supported (26.6); DPoP supported (26.4); federated client auth supported (26.6); CIMD experimental (26.6); ID-JAG experimental, receiving side (26.7); token-exchange delegation with `act` preview (26.8); attestation-based client auth, SSF and AuthZEN experimental (26.7). SPIFFE client auth not yet "supported" (open issue #44413). |
| SPIRE 1.16.0 | X.509-SVID and JWT-SVID stable; WIT-SVID Incubating |
| MCP 2026-07-28 | RFC 9728, 8707, 8414, 9207, CIMD, ID-JAG extension |
| Okta | Cross App Access = ID-JAG; SAML flow added (https://xaa.dev/, undated) |
| Microsoft Entra Agent ID | Agent identity blueprint -> agent identity -> agent user. Grants `client_credentials`, `jwt-bearer` (OBO), `refresh_token`; agents cannot use `/authorize`. Proprietary `fmi_path`, `xms_act_fct`, `xms_sub_fct`, `xms_par_app_azp`. No `act` claim. |
| Microsoft Agent 365 | GA 2026-05-01, per-user licence, registry in the Microsoft 365 admin centre; overview names no open identity standard |
| AWS Bedrock AgentCore Identity | "Agent identities are implemented as workload identities"; inbound JWT authoriser; protocol detail not verified |
| Cloudflare | Web Bot Auth verification, Ed25519 |
| BeyondTrust AI Agent Security (2026-10-13) | No agent identity standard. Classifies agents by process name, signature and LLM traffic; kernel and network enforcement; Windows 11 x64 and macOS 14+ only |

## Weak points, gaps and risks

- **Shared-credential attribution is unaddressed.** A coding agent using the developer's `gh` token, SSH key or cloud profile is invisible to every token-based standard.
- **Local transports are out of scope.** MCP says STDIO should not use its authorisation spec. The only draft covering local tool calls is a two-revision individual draft.
- **`act` is unauthenticated history.** The actor profile itself says the chain records prior actors "without independently proving each hop". Per-hop proof exists only in competing individual drafts.
- **ID-JAG has no actor semantics yet**, so MCP enterprise authorisation identifies the user and the client application, not the agent instance.
- **Version skew is already real**: MCP pins ID-JAG -04, OAuth 2.1 -13 and CIMD -00.
- **Naming collisions**: two unrelated "AAuth" drafts; "ACP" is used by agentproto and by other agent protocols.
- **Algorithm mismatch**: Web Bot Auth deployments use Ed25519; WIT-SVID excludes EdDSA.
- **Mid-execution approval** has no finished standard.
- **Discovery of unregistered agents** is not a standards topic at all. DAWN covers agents that want to be found.

## Implications for our design

**Recommended identity profile**

Phase 1 (build on RFCs only):
1. Canonical agent identifier is a WIMSE/SPIFFE URI. Sensors and gateways authenticate to the control plane with X.509-SVIDs over mTLS; offer SPIRE integration and an embedded minimal issuer for the single-laptop case.
2. MCP and LLM gateways are RFC 9728 resource servers with strict RFC 8707 audience checks, never pass tokens through, and use RFC 8693 exchange to mint downstream tokens with nested `act`. Bind tokens with DPoP (RFC 9449) or mTLS (RFC 8705).
3. Express tool permissions as RFC 9396 `authorization_details`. Use RFC 9470 semantics and MCP scope challenges for step-up; CIBA for out-of-band approval.
4. Every policy enforcement point (hook, gateway, OS sensor) calls the decision point through the OpenID Authorization API 1.0. This is the embedding interface for EDR vendors.
5. Sign audit records (JWS or COSE) in a hash chain; keep the envelope SCITT-compatible.

Phase 2 (near-RFC, behind version-tagged adapters): identity chaining, ID-JAG as both issuer-side validator and gateway client, CIMD, Transaction Tokens inside the gateway, Token Status List, SPIFFE client authentication, WIT + WPT or the WIMSE HTTP-signature profile, SCIM Agent resource export, OpenID SSF/CAEP receivers for revocation.

Phase 3 (watch, do not ship as defaults): actor profile and entity profiles, agent-instance profile, Mission, Deferred Token Response, transaction challenge, attestation-based client auth, Delegate SD-JWT, Web Bot Auth (detect `Signature-Agent` as a discovery signal now; sign later), agentproto, dawn, audit outputs, AAuth, ML-DSA tokens.

**Data model for agent identity**

- `agent_id`: WIMSE URI, stable, never reused. Suggested path: `/t/<tenant>/agent/<software-slug>/<instance-uuid>`.
- `entity_profile`: `ai_agent`, `service`, `user`, `device` (aligned with `sub_profile`).
- `software`: publisher, product, version, binary hash, code-signing identity, optional CIMD `client_id` URL.
- `instance`: `agent_instance_id` (not derived from a key), host identifier, OS user, process start identity, session, parent instance (for sub-agents).
- `provenance`: platform, model, runtime evidence.
- `principal`: `iss` + `sub` + `tenant` of the human or system the agent acts for.
- `delegation`: ordered actor chain (`iss`, `sub`, `sub_profile` per hop), depth, mission or intent reference, `authorization_details`, transaction identifier.
- `credentials[]`: type (X.509-SVID, WIT, JWT-SVID, access token, DPoP key, Web Bot Auth key, legacy API key), key thumbprint, issuer, expiry, binding.
- `assurance`: observed-by-sensor, self-asserted, IdP-issued, or attested. This field is ours; no standard has it.
- `owners[]` and `lifecycle`: discovered, registered, active, suspended, retired (SCIM `active` plus the richer states proposed in the governance draft).
- Ingest normaliser: map Entra `xms_*` facets, standard `act`, and SPIFFE IDs into the same model.

**Avoid**: inventing a token format; trusting local UI approval as authorisation; forwarding tokens; treating an agent-supplied identifier as identity before key proof; hard-coding draft claim names without a version tag.

## Ideas worth stealing and whitespace

- **Call Authority outside the agent process** (local tool-call proof draft): our OS sensor can be that authority for stdio MCP servers.
- **Agent/Gateway/Host enforcement-point taxonomy** from the audit drafts: adopt the vocabulary and contribute to it; an open-source AIDR is a natural reference implementation for the AUDIT BoF.
- **Instance identifier independent of keys**, so identity survives key rotation.
- **Mission lifecycle gating** token issuance, as a model for task-scoped sessions.
- **Whitespace 1**: an endpoint credential broker that swaps a human's ambient credentials for agent-scoped, key-bound, short-lived tokens with `act` set, so shared credentials stop being shared.
- **Whitespace 2**: an "observed identity" record for unregistered agents that upgrades to an issued identity without changing its identifier.
- **Whitespace 3**: a cross-vendor claim normaliser and conformance suite for agent tokens.

## Could not verify / open questions

- Web search was unavailable after the first queries, so I could not confirm current implementer lists for ID-JAG (beyond Okta, Keycloak and MCP), Web Bot Auth signers (OpenAI, AWS, Google), or Auth0, Ping and Google Cloud support.
- NIST NCCoE agent identity project page returned 403. The AUDIT BoF charter text (GitHub `mirjak/audit-bof-preparation`) was not read.
- Okta Cross App Access availability status and dates; AWS AgentCore token formats; A2A 1.0 signing and delegation details (page truncated).
- OpenID SSF/CAEP final status and the OpenID AIIM whitepaper date are from memory, not re-checked today.
- Whether OAuth 2.1 will reach last call in 2027 is unknown; it has been a WG document through 17 revisions.

## Sources

- IETF Datatracker API and draft texts, read 2026-11-09: https://datatracker.ietf.org/doc/ plus each draft name cited above (for example https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/, https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/, https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/, https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/, https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/, https://datatracker.ietf.org/doc/draft-liu-audit-enforcement-points/)
- RFCs: https://www.rfc-editor.org/rfc/rfc8693, rfc9449, rfc9396, rfc9728, rfc9470, rfc9421, rfc9901, rfc9943, rfc9964, rfc10024, rfc10070
- WG pages: https://datatracker.ietf.org/group/agentproto/about/, https://datatracker.ietf.org/group/dawn/about/, https://datatracker.ietf.org/group/wimse/about/, https://datatracker.ietf.org/group/webbotauth/about/, https://datatracker.ietf.org/group/audit/about/
- IETF blog, "IETF 127 new topics": https://www.ietf.org/blog/ietf127-new-topics/; "Agentic AI communications" (2026-01-22): https://www.ietf.org/blog/agentic-ai-standards/
- MCP authorisation, revision 2026-07-28: https://modelcontextprotocol.io/specification/latest/basic/authorization; extensions: https://github.com/modelcontextprotocol/ext-auth
- SPIFFE WIT-SVID (v1.16.0 docs): https://spiffe.io/docs/latest/spiffe-specs/wit-svid/; SPIRE releases: https://github.com/spiffe/spire/releases
- Keycloak release notes: https://www.keycloak.org/docs/latest/release_notes/index.html; issues: https://github.com/keycloak/keycloak/issues/44413
- OpenID Authorization API 1.0 (2026-01-11): https://openid.net/specs/authorization-api-1_0.html; CIBA Core 1.0 (2021-09-01): https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html; AIIM CG: https://openid.net/cg/artificial-intelligence-identity-management-community-group/
- Microsoft Entra Agent ID token claims (updated 2026-08-27): https://learn.microsoft.com/en-us/entra/agent-id/agent-token-claims; OBO flow (updated 2026-08-10): https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow
- Microsoft Agent 365 overview (updated 2026-10-23): https://learn.microsoft.com/en-us/microsoft-agent-365/overview
- BeyondTrust AI Agent Security (2026-10-13): https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- Cloudflare Web Bot Auth (2026-10-08): https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/
- AWS Bedrock AgentCore Identity: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html
- Okta Cross App Access: https://xaa.dev/
- A2A specification 1.0.0: https://a2a-protocol.org/latest/specification/

## Independent verification

Checked 2026-11-09 by a second researcher against primary sources not relied on above: Datatracker JSON API (`doc.json`, `/api/v1/doc/document/`, `/api/v1/group/`), archived draft and charter text on ietf.org, rfc-editor.org, and source files read through the GitHub API (MCP spec and ext-auth repos, `spiffe/spiffe`, `spiffe/spire`, `keycloak/keycloak` at tag 26.8.2, `MicrosoftDocs/entra-docs`).

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | `draft-ietf-wimse-aims-01` (2026-11-02) is a WIMSE WG document; agent MUST have exactly one WIMSE identifier, which MAY be a SPIFFE ID; defines no new protocols | Confirmed | Stream state "WG Document", rev 01 dated 2026-11-02. Text: "MUST be assigned exactly one WIMSE identifier, which MAY be a SPIFFE ID"; abstract: "Rather than defining new protocols". Intended status is Informational, so its MUSTs are best practice, not a standards-track requirement. | https://www.ietf.org/archive/id/draft-ietf-wimse-aims-01.txt |
| 2 | ID-JAG is at -06 (2026-10-31), WG document; section 9.10 defines no normative processing for `actor_token` or `act` | Confirmed | -05 was posted 2026-10-30 and -06 one day later. Section 9.10 "Actor Delegation Extensions" and section 4.3 both carry the "does not define normative processing requirements" wording. | https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-06.txt |
| 3 | MCP authorisation 2026-07-28: RFC 9728 and RFC 8707 required, no other tokens accepted or transited, DCR deprecated for CIMD, STDIO told not to use the spec | Confirmed | Servers MUST implement RFC 9728 and validate audience per RFC 8707; clients MUST send `resource`. "MUST NOT accept or transit any other tokens". DCR is MAY and "deprecated"; CIMD is SHOULD. STDIO is "SHOULD NOT", not MUST NOT. Pins OAuth 2.1 -13 and CIMD -00 as stated. | https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/docs/specification/2026-07-28/basic/authorization |
| 4 | MCP Enterprise-Managed Authorization (stable, 2026-07-28) profiles ID-JAG and links to draft -04 | Confirmed | Lives under `specification/stable/`, protocol revision 2026-07-28 (dated revision committed 2026-10-23). All section links point to `...authz-grant-04`; the `draft` copy also still points to -04. IETF is at -06. | https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx |
| 5 | agentproto and dawn chartered October 2026, first meet at IETF 127 (14-20 Nov); both charters exclude agent identity and defer to OAuth and WIMSE; AUDIT is an unchartered WG-forming BoF | Corrected | Dates and states hold: agentproto charter approved 2026-10-08, dawn 2026-10-22, IETF 127 starts 2026-11-14 for 7 days, AUDIT is in BoF state with an approved "WG forming" request. DAWN lists "Identity management of AI agents, tools, and skills" as out of scope. agentproto does **not** list identity as out of scope: its reference architecture describes building blocks to reuse "including identity, authentication, authorization, and encryption, rather than defining new ones", and its key considerations call for mechanisms to establish and verify agent and user identity. The phrase quoted in section 7 ("will not define new identity, authentication, authorization") is not in the charter. | https://www.ietf.org/charter/charter-ietf-agentproto-01.txt ; https://www.ietf.org/charter/charter-ietf-dawn-01.txt |
| 6 | Identity chaining -17 and Token Status List -21 in RFC Editor queue; Transaction Tokens -11 has WG consensus; RFC 10070 published 2026-11-07; OAuth 2.1 a WG document at -17 | Confirmed | All five states match Datatracker. RFC 10070 updates RFCs 7521, 7522, 7523 and 9126, not only 7523. Revision dates in the section 1 table are wrong, see row A. | https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/doc.json ; https://www.rfc-editor.org/rfc/rfc10070.txt |
| 7 | WIT is `wit+jwt` with `sub` = workload identifier and `cnf.jwk`; not a bearer token. WIT-SVID is Incubating and allows only RS/ES/PS algorithms | Confirmed | workload-creds-03: "MUST NOT be used as a bearer token", `cnf.jwk.alg` mandatory. WIT-SVID header reads "Stability: Incubating"; algorithm tables list only RS, ES and PS families for both the signature and `cnf.jwk.alg`; merged 2026-07-01. | https://github.com/spiffe/spiffe/blob/main/standards/WIT-SVID.md |
| 8 | Entra Agent ID uses `xms_act_fct`, `xms_sub_fct` (11 AgentIdentity, 13 AgentIDUser) and `xms_par_app_azp` instead of `act`; no interactive `/authorize` | Confirmed | Doc source matches; the actor is carried in `azp`/`appid` and no `act` claim is documented. "Agents aren't supported for interactive (`/authorize`) flows." Normaliser trap: the same page's `xms_idrel` claim uses 11 = GDAP user and 13 = SPLess application, so the values must be read per claim. There is also an `xms_tnt_fct` tenant facet. | https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/agent-id/agent-token-claims.md ; https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/agent-id/agent-oauth-protocols.md |
| 9 | Per-actor `iss` and `sub_profile` (`ai_agent`) on nested `act` exist only in individual drafts | Confirmed | Both drafts are in "Individual Submissions" with no stream. `sub_profile` appears zero times in ID-JAG-06, AIMS-01, Transaction Tokens -11 and workload-creds-03, and no `draft-ietf-*` document carries an actor or entity-profile name. Nested `act` itself (and the option of `iss` inside it) is already RFC 8693 section 4.1; only the mandatory `iss` and the entity-type claim are draft-only. | https://www.ietf.org/archive/id/draft-mcguinness-oauth-actor-profile-01.txt |
| 10 | Keycloak 26.x: ID-JAG and CIMD experimental; token-exchange delegation with `act` preview in 26.8; SPIFFE client auth not promoted | Confirmed | `Profile.java` at tag 26.8.2: `IDENTITY_ASSERTION_JWT` and `CIMD` are EXPERIMENTAL, `TOKEN_EXCHANGE_DELEGATION` is PREVIEW (EXPERIMENTAL in 26.7.5), `SPIFFE` is PREVIEW, `CLIENT_AUTH_ABCA`, `SSF`, `AUTHZEN` EXPERIMENTAL. Issue #44413 is still open. | https://github.com/keycloak/keycloak/blob/26.8.2/common/src/main/java/org/keycloak/common/Profile.java |
| A | (extra) Section 1 table dates for identity chaining -17 (2026-08-21), Token Status List -21 (2026-11-03) and Transaction Tokens -11 (2026-08-21) | Corrected | Those are Datatracker last-state-change timestamps. The revisions were published 2026-07-19, 2026-06-21 and 2026-07-30 respectively. Versions and states are right. | https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/doc.json |
| B | (extra) Matrix row "SPIRE 1.16.0: WIT-SVID Incubating" | Corrected | "Incubating" is the SPIFFE spec label. In SPIRE 1.16.0 WIT-SVID support is experimental and off by default; it needs the `enable_wit_svids` server and agent options. Do not assume a stock SPIRE deployment issues WITs. | https://github.com/spiffe/spire/releases/tag/v1.16.0 |
| C | (extra) Matrix row "BeyondTrust ... Windows 11 x64 and macOS 14+ only" | Corrected | The page lists Windows 11 **or Windows Server 2022 or later** on x64 (no Arm), and macOS 14, 15 or 26. The quote "runs as the signed-in user, with no identity of its own", the classifier description and the 2026-10-13 date hold. Read through a summarising fetch, so treat the exact wording as medium confidence. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |

Also spot-checked and found correct: document states for attestation-based client auth -12, SD-JWT VC -26, WIMSE HTTP signatures -08, workload identity practices -08, SPIFFE client auth -03, SCRAPI -11, TLS ML-KEM -11 and webbotauth -01; RFC numbers and dates for 9901, 9943, 9954, 9964, 10024, 9635, 9767 and 9728; SPIRE and Keycloak release dates; Microsoft Agent 365 GA date, per-user licensing and registry location. One wording nuance: `draft-ietf-wimse-identifier-04` says identifiers SHOULD NOT exceed 2048 bytes and implementations MUST support at least that length, rather than a hard "at most 2048 bytes".
