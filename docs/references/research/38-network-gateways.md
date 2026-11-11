# Network control for AI traffic: endpoint proxy, AI gateway, MCP broker, egress control, browser extension

_Researched 2026-11-09_

Method note: the shared web-search quota was already exhausted when this brief started, so no search-engine queries were run. Everything marked **[V]** was read directly from a primary source (vendor docs, spec, GitHub API) on 2026-11-09. Everything marked **[K]** is from prior knowledge (cutoff mid-2026) and was not re-verified. Everything marked **[I]** is my inference.

## TL;DR

- **Build both an endpoint-local proxy and a central gateway, sharing one parser and policy core.** The market leaders ship both: CrowdStrike Falcon Guardian (the renamed AIDR) has agent hooks and an AI gateway GA, and "endpoint network inspection" still pre-beta as of 2026-11-03 **[V]**. BeyondTrust does endpoint-only with a tenant root CA and no gateway **[V]**.
- **Steering needs three tiers per OS.** Tier 1 is per-tool configuration (base URL, proxy variables, managed settings). Tier 2 is a sandbox that removes every route except our proxy. Tier 3 is transparent redirection (WFP connect-redirect driver, macOS `NETransparentProxyProvider`, Linux cgroup eBPF). Tier 3 is the only one that catches unregistered bespoke agents.
- **Claude Code can be pinned to a gateway by policy.** Managed setting `allowedProviders: ["customEndpoint"]` plus `ANTHROPIC_BASE_URL` makes it refuse any other destination (v2.1.285+) **[V]**. It trusts the OS certificate store by default, so TLS inspection works without extra configuration **[V]**.
- **Runtime trust stores are inconsistent.** Node ignores the OS store unless `--use-system-ca` / `NODE_USE_SYSTEM_CA=1` is set, and ignores proxy variables unless `NODE_USE_ENV_PROXY=1` is set **[V]**. Deno defaults to Mozilla roots **[V]**. The endpoint agent must inject CA and proxy variables per process tree, not only install a root certificate.
- **MCP 2026-07-28 is stateless and gateway-friendly.** No `initialize`, no `Mcp-Session-Id`, mandatory `Mcp-Method` / `Mcp-Name` HTTP headers, `server/discover`, deterministic `tools/list` order, and `ttlMs` / `cacheScope` on list results **[V]**. Microsoft's MCP gateway already supports only this revision **[V]**.
- **Reuse agentgateway (Rust, Apache-2.0, v1.7.0) as the central data plane.** It is a Linux Foundation / Agentic AI Foundation project that parses Chat Completions, Responses, Anthropic Messages, Gemini, Realtime WebSocket, MCP and A2A **[V]**. Do not build on LiteLLM.
- **LiteLLM's 2026 security record is poor.** It has 18 published advisories, five critical (SQL injection in key verification, three authentication bypasses, master-key leak), plus the 2026-03-24 PyPI compromise of v1.82.7 and v1.82.8 **[V]**.
- **Two reference projects moved.** TensorZero's repository is archived (last push 2026-06-11) **[V]**. `envoyproxy/ai-gateway` now redirects to `theagentrouter/agent-router` (v1.2.1, 2026-11-06) **[V]**.
- **Every MCP gateway has shipped authorization-bypass bugs in 2026.** Examples: fail-open CEL evaluation, cross-route session reuse, argument canonicalisation gaps, tool-name shadowing **[V]**. A fail-closed policy core with a conformance suite is a differentiator.
- **Nobody documents hash-pinning of tool descriptions at a gateway.** CrowdStrike's MCP proxy scans descriptions with a prompt-injection detector but describes no change detection **[V]**.
- **A Manifest V3 extension cannot read response bodies or WebSocket frames through `webRequest`,** and blocking `webRequest` is limited to policy-installed extensions **[V]**. Full visibility needs page-context instrumentation.
- **Hard limits:** hosted connectors that run server-side (for example `mcp-proxy.anthropic.com`), SigV4-signed bodies, pinned apps, QUIC and ECH in transparent mode, and any machine where the user is local admin.

## Findings

### 1. Endpoint proxy, central gateway, or both

Each placement sees something the other cannot.

- **Central gateway.** It holds provider keys, enforces budgets, and covers servers, Kubernetes and SaaS callers that have no sensor. It cannot attribute a request to a process or tell agent from human on shared credentials. Claude Code's own docs note that a gateway must be kept current or it breaks new client features, and that Anthropic does not audit third-party gateways ([llm-gateway](https://code.claude.com/docs/en/llm-gateway), read 2026-11-09) **[V]**.
- **Endpoint proxy.** It knows the PID, process ancestry, signing identity and user session, and it sees traffic from tools nobody registered. It requires a local trust anchor and breaks on pinned or QUIC flows.
- **What vendors ship.**
  - CrowdStrike Falcon Guardian: agent hooks for Claude Code, Codex, GitHub Copilot, OpenCode and Cursor (available); Falcon AI Gateway (GA, includes an "AI kill switch" that cuts model access at the gateway); endpoint network inspection (pre-beta, macOS expansion planned); Linux sensor coverage for Claude Code and Codex (pre-beta) ([blog, 2026-11-03](https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-ai-security-and-safety-falcon-guardian/)) **[V]**.
  - CrowdStrike's public AIDR docs list collectors rather than one proxy: browser extension, SDK, gateway plug-ins (Kong, LiteLLM, Portkey, Apigee, Azure API Management), MCP proxy, cloud logs (Bedrock), and OpenTelemetry ([AIDR docs](https://pangea.cloud/docs/aidr/)) **[V]**.
  - BeyondTrust AI Agent Security: the "Pathfinder" endpoint agent enforces "at the kernel and network levels" and states no gateway or MCP proxy is required. It needs a tenant root certificate trusted on Windows and an MDM profile approving system extensions on macOS. It supports Windows 11 / Server 2022+ x64 and macOS 14 to 26 only. It classifies agent processes by name, signature and LLM API traffic pattern ([docs, updated 2026-10-13](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security)) **[V]**.
  - Microsoft: Agent 365 (GA 2026-05-01, per-user licence) governs MCP servers through a Tools registry and a Tools Gateway in the admin centre ([overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview), [tooling servers](https://learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview)) **[V]**. Entra Global Secure Access forwards Copilot Studio agent traffic (HTTP node, custom connectors, MCP Server Connector) to its cloud proxy for web, threat-intel and file filtering ([docs, updated 2026-10-06](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-secure-web-ai-gateway-agents)) **[V]**. This is cloud-only and Microsoft-agent-only.

How CrowdStrike's endpoint network inspection works internally is not public. The BeyondTrust prerequisites (trusted root CA, macOS system extension, "LLM API traffic patterns") point to a local TLS-terminating inspector fed by OS-level redirection **[I]**.

### 2. Steering traffic and attributing flows to a process

**Tier 1: per-tool configuration (no kernel code).**

- Claude Code honours `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`, does not support SOCKS, and supports mTLS client certificates. Managed settings can pin the gateway (above). A `processWrapper` setting forces every Claude Code process, including background agents, through a corporate launcher. Shell exports do not reliably reach background agents; the settings `env` block does ([network-config](https://code.claude.com/docs/en/network-config)) **[V]**.
- Codex ships its own local policy proxy, `codex-network-proxy` (Rust, in the Apache-2.0 `openai/codex` repo): HTTP on `127.0.0.1:3128`, SOCKS5 on `:8081`, domain allow/deny, and a "limited" mode that permits only GET/HEAD/OPTIONS ([README](https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md)) **[V]**.
- Node only honours proxy variables with `--use-env-proxy` / `NODE_USE_ENV_PROXY=1` (added v24.5.0 / v22.21.0, still "active development") ([Node CLI docs, v26.13.0](https://nodejs.org/api/cli.html)) **[V]**. Bun reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` on every `fetch` and ignores SOCKS values ([Bun fetch docs](https://bun.com/docs/runtime/networking/fetch)) **[V]**.
- The Codex README warns that Go's `net/http` always bypasses proxies for loopback **[V]**.

**Tier 2: sandbox that removes other routes.** Anthropic's `sandbox-runtime` (`srt`, Apache-2.0, v0.0.82) is the reference design ([repo](https://github.com/anthropics/sandbox-runtime)) **[V]**:

- Linux: bubblewrap with the network namespace removed; the only exit is a Unix socket bind-mounted to host HTTP and SOCKS5 proxies.
- macOS: a `sandbox-exec` Seatbelt profile allowing only one localhost port.
- Windows: the process runs as a dedicated `srt-sandbox` local user, and machine-wide WFP filters keyed on that account's SID block everything except loopback to the proxy port range. No kernel driver is needed. Documented gaps: threads that impersonate another token, and traffic carried by system services.
- `--control-fd` accepts live policy updates, which gives per-session dynamic allow-lists.

ToolHive does the equivalent for containers: an internal-only network, a Squid egress container (Envoy optional since v0.41.0), injected proxy variables, HTTP and HTTPS only ([network isolation](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)) **[V]**.

**Tier 3: transparent redirection.**

| OS | Mechanism | Process attribution | Cost |
|---|---|---|---|
| Windows | WFP callout driver at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`; rewrite the destination to a local proxy, set `localRedirectTargetPID` and `localRedirectHandle`; the proxy recovers the original destination with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` and marks its own outbound socket with `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` ([Microsoft docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)) **[V]** | PID and app path are ALE classify metadata **[K]** | A signed kernel driver; must coexist with other vendors' callouts (the docs describe the multi-callout protocol) |
| macOS | `NETransparentProxyProvider` system extension (macOS 11+); returning `false` from `handleNewFlow` lets a flow go direct; matching uses `includedNetworkRules` ([Apple docs](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)) **[V]** | Flow metadata carries the source app audit token and signing identifier **[K]** | MDM approval or user consent; ordering conflicts with other network extensions **[K]** |
| Linux | cgroup v2 eBPF `cgroup/connect4`, `connect6` and `sendmsg4/6` rewrite the destination; the original is stored in a map keyed by socket cookie **[K]** | PID/TGID and cgroup ID in the program; the cgroup identifies the pod or systemd unit **[K]** | Root or CAP_BPF; a per-node DaemonSet in Kubernetes |

Tier 3 also supports attribution without decryption: destination, SNI and process identity alone can classify "this unknown binary is talking to an LLM API".

### 3. TLS inspection on endpoints

| Runtime | Default trust | How to add our CA | Status |
|---|---|---|---|
| Node.js | Bundled Mozilla snapshot | `NODE_EXTRA_CA_CERTS` (read once at launch; ignored when code passes an explicit `ca`); `--use-system-ca` (v23.8.0) or `NODE_USE_SYSTEM_CA=1` (v24.6.0 / v22.19.0) reads Windows machine and user root stores, macOS keychains, or OpenSSL paths | **[V]** [Node docs](https://nodejs.org/api/cli.html) |
| Claude Code | Bundled **and** OS store (`CLAUDE_CODE_CERT_STORE=bundled,system`); npm installs need Node 22.15+ | OS store or `NODE_EXTRA_CA_CERTS`; `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` if the inspector mishandles gzip request bodies | **[V]** [docs](https://code.claude.com/docs/en/network-config) |
| Deno | Mozilla (`DENO_TLS_CA_STORE` default) | `DENO_TLS_CA_STORE=system` or `DENO_CERT` | **[V]** [Deno docs](https://docs.deno.com/runtime/reference/env_variables/) |
| Bun | Bundled roots; a per-request `tls.ca` option is documented | `NODE_EXTRA_CA_CERTS` | Option **[V]**; env behaviour **[K]** |
| Python | `ssl` uses OpenSSL paths; `requests` and `httpx` use certifi | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | **[K]** |
| Go | OS store | Install in OS store; `SSL_CERT_FILE` / `SSL_CERT_DIR` on Unix | **[K]** |
| Rust | Depends on crate features (webpki roots, native certs, or platform verifier) | Per application | **[K]** |
| Java | JRE `cacerts` keystore | `-Djavax.net.ssl.trustStore` through `JAVA_TOOL_OPTIONS` | **[K]** |
| Electron | Chromium side uses the OS store; Node-side code follows Node rules | Both | **[K]** |

Other protocol facts:

- **Codex pattern worth copying.** When MITM is on, the proxy keeps the CA private key in memory only and injects CA-bundle variables that point at immutable public files into spawned commands **[V]**.
- **Pinning.** Claude Code is documented to work behind TLS inspection, so it does not pin **[V]**. I could not verify pinning behaviour for Cursor, ChatGPT desktop, Copilot or others.
- **QUIC / HTTP/3.** Bun's `fetch` uses HTTP/3 only when asked (`protocol: "http3"`) **[V]**. Chromium has `QuicAllowed` and `EncryptedClientHelloEnabled` enterprise policies (policy definition files confirmed in the Chromium tree; contents not read) **[V]**. Standard practice is to block UDP/443 for inspected processes so clients fall back to TCP **[K]**.
- **ECH.** It hides the SNI in transparent mode; explicit-proxy `CONNECT` still exposes the hostname **[K]**.
- **WebSockets.** OpenAI Realtime runs over WebSocket and agentgateway proxies it with token accounting **[V]**. Codex routes `wss://` through `CONNECT` under the same host policy and uses `WS_PROXY` / `WSS_PROXY` variables **[V]**.

### 4. Parsing provider APIs into one normalised form

agentgateway's supported API types are the practical first list: Chat Completions, Responses, Anthropic Messages (plus token count), native Gemini, Embeddings, Audio, OpenAI Realtime, Rerank, Models, and Passthrough ([API types](https://agentgateway.dev/docs/standalone/latest/llm/api-types/)) **[V]**.

Streamed tool calls arrive differently in each API **[K]**:

- Anthropic Messages: `content_block_start` (tool_use) then `input_json_delta` fragments.
- Chat Completions: `choices[].delta.tool_calls[]` fragments keyed by `index`.
- Responses: `response.function_call_arguments.delta` and `.done` events.
- Gemini: complete `functionCall` parts.
- Bedrock ConverseStream: `contentBlockDelta.toolUse.input` inside binary `vnd.amazon.eventstream` frames.

Parser hazards already found in the field (Agent Router advisories, 2026-09 and 2026-10) **[V]**:

- An upstream-controlled SSE `index` drove an unbounded allocation (GHSA-vgp6-h389-r473).
- A duplicated JSON key on `stream_options` suppressed forced usage accounting (GHSA-w5rr-gc4v-5946).
- Malformed 2xx responses crashed the processor (GHSA-99m8-cq7v-gw4g).

**Signed requests.** Bedrock now accepts bearer API keys (`Authorization: Bearer`, `AWS_BEARER_TOKEN_BEDROCK`; short-term keys last up to 12 hours; governed by `bedrock:CallWithBearerToken`) ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)) **[V]**. With a bearer key the body can be altered. With SigV4 the payload hash is signed, so a proxy can observe and block but cannot redact unless it holds AWS credentials and re-signs **[K]**.

**Inline redaction of a stream** **[I]**: buffer complete tool-call arguments before releasing them (they are not usable until complete anyway), and run text through a short hold-back window (a few hundred bytes or about 50 ms) so a secret spanning two chunks is caught. Claude Code runs stream watchdogs (180 s byte-level on the direct API) and counts keep-alive pings **[V]**, so a holding proxy must keep emitting pings.

### 5. MCP brokering

**Protocol baseline.** MCP 2026-07-28 ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)) **[V]**:

- Removes sessions and the initialisation handshake; each request carries protocol version and client info in `_meta`, and servers identify themselves in each result.
- Adds `server/discover`.
- Requires `Mcp-Method` and `Mcp-Name` headers on Streamable HTTP POSTs, with a `HeaderMismatch` error (-32020).
- Replaces server-initiated requests with multi-round-trip results (`resultType: "input_required"`).
- Deprecates Dynamic Client Registration in favour of Client ID Metadata Documents, and deprecates Roots, Sampling, Logging and HTTP+SSE.
- Requires clients to key stored credentials by issuer and validate `iss` (RFC 9207).

There is no tool-description signing or server-signature mechanism in this changelog. The official registry's README still describes a preview with a v0.1 API freeze ([registry](https://github.com/modelcontextprotocol/registry)) **[V]**.

**How existing brokers are built** **[V]**:

- **CrowdStrike AIDR MCP proxy.** `npx -y @crowdstrike/aidr-mcp-proxy -- <original command>` is written into the client config. It is stdio only (remote servers need `mcp-remote`), needs Node 22.15+ and npm registry access, and has three checkpoints (`tool_listing`, `tool_input`, `tool_output`) with block, allow or transform ([docs](https://pangea.cloud/docs/aidr/collectors/agentic)).
- **Docker MCP Gateway** (Go, MIT, v0.44.3). Each server is a container with `no-new-privileges`, 1 CPU and 2 GB by default, and no host environment. Flags: `--verify-signatures`, `--block-secrets`, `--block-network`, `--log-calls`, and `--interceptor before|after:exec|docker|http:…`. HTTP transports require a bearer token and check `Origin`. Profiles carry per-tool allow-lists and ship as OCI artefacts ([security model](https://github.com/docker/mcp-gateway/blob/main/docs/security.md)).
- **ToolHive** (Go, Apache-2.0, v0.63.0). Container per server, egress proxy, Cedar policies with actions `call_tool`, `get_prompt`, `read_resource`; tool arguments exposed as `arg_*`, JWT claims as `claim_*`, tool annotations as resource attributes; list responses filtered by the same policies; default deny and errors deny ([Cedar docs](https://docs.stacklok.com/toolhive/concepts/cedar-policies)). Object and array arguments are not available to policy.
- **agentgateway** (Rust, Apache-2.0, v1.7.0). Federates servers behind one endpoint; `mcpAuthorization` CEL rules over `mcp.tool.name`, `mcp.tool.target`, `jwt`; guardrail processors run in-process CEL or a remote "ExtMCP" policy server on request (`mcp.params`) and response (`mcp.result`) and can reject, mask or rewrite; translates between spec versions including 2026-07-28 ([guardrails](https://agentgateway.dev/docs/standalone/latest/mcp/guardrails/about/)).
- **IBM ContextForge** (Python, Apache-2.0, v1.1.0). Registry plus proxy for MCP, A2A, REST and gRPC with 40+ plugins.
- **Microsoft mcp-gateway** (C#, MIT, no tagged releases). Kubernetes reverse proxy with per-request authorization; 2026-07-28 only.
- **Lasso mcp-gateway** (Python, MIT). Plugin-based stdio wrapper with a reputation scanner; last push 2026-01-22, so likely stale.
- **Snyk Agent Scan** (formerly Invariant `mcp-scan`; Apache-2.0, v0.6.11). Scans configs, servers and skills; requires a Snyk token; warns that scanning starts stdio servers.

**A2A.** Version 1.0.0 (v1.0.1 tagged 2026-05-28) defines JSON-RPC, gRPC and HTTP+JSON bindings, an `A2A-Version` header, operations such as `SendMessage`, `SendStreamingMessage`, `GetTask`, `CancelTask`, and Agent Card signing in section 8.4 ([spec](https://a2a-protocol.org/latest/specification/)) **[V]**. agentgateway and ContextForge both proxy it **[V]**.

### 6. AI gateway baseline, licences and security history

See the matrix. The baseline feature set (virtual keys, budgets, rate limits, fallback, caching, model allow-lists, guardrail hooks, logging) is commodity. Kong AI Gateway 2.x names prompt guards, a sanitizer, semantic cache, AI rate limiting and cloud-guardrail integrations; its overview page does not say which are enterprise-only ([Kong docs](https://developer.konghq.com/ai-gateway/)) **[V]**. Bifrost keeps guardrails, clustering and its MCP gateway in the enterprise edition and claims 11 µs overhead at 5,000 requests per second ([README](https://github.com/maximhq/bifrost)) **[V]**. Cloudflare AI Gateway is a hosted service with caching, rate limiting, dynamic routing and logging on all plans ([docs](https://developers.cloudflare.com/ai-gateway/)) **[V]**.

### 7. Egress control

- Codex expresses host allow/deny with scoped wildcards (the global `*` is rejected), re-checks resolved IPs so an allow-listed name pointing at a private address is still blocked, and adds MITM hooks that match host + method + path prefix and can strip or substitute credentials **[V]**.
- Docker MCP Gateway rejects loopback, private, link-local and metadata addresses and validates redirects and the dialled address **[V]**.
- DNS-rebinding and SSRF bugs recur across the field: Docker (CVE-2025-64443), ContextForge (CVE-2026-53708 DNS TOCTOU), Bifrost (CVE-2026-55245), Portkey (CVE-2025-66405) **[V]**.
- Encrypted DNS: with an explicit proxy the proxy resolves names, so the client's DoH is irrelevant; in transparent mode, DoH endpoints must be blocked or intercepted **[K]**.

### 8. Browser

- `webRequestBlocking` in Manifest V3 is only available to policy-installed extensions. `onBeforeRequest` exposes request bodies as `formData` or `raw` bytes. No response bodies are exposed. WebSocket visibility stops at the handshake ([Chrome docs](https://developer.chrome.com/docs/extensions/reference/api/webRequest)) **[V]**.
- CrowdStrike's browser collector is a force-installed extension for Chrome, Edge and Firefox, configured through managed storage and deployed with Jamf, Intune, Chrome Enterprise or Group Policy ([docs](https://pangea.cloud/docs/aidr/collectors/browser)) **[V]**.
- Chrome's Content Analysis Connector lets a local DLP agent receive content from the browser over protobuf IPC; the SDK is BSD-3-Clause ([SDK](https://github.com/chromium/content_analysis_sdk), last push 2026-08-11) **[V]**. Policies `OnBulkDataEntryEnterpriseConnector`, `OnFileAttachedEnterpriseConnector` and `EnterpriseRealTimeUrlCheckMode` exist in the Chromium policy tree **[V]**. Whether a new vendor can register as a provider without Google adding it to Chromium's list is unverified.

## Matrix

LLM gateways (data from the GitHub API on 2026-11-09 unless noted):

| Project | Language / licence | Latest release | Published advisories | Note |
|---|---|---|---|---|
| agentgateway | Rust / Apache-2.0 | v1.7.0 (2026-10-27) | 7, none critical | LLM + MCP + A2A; AAIF project |
| LiteLLM | Python / MIT, with a separately licensed `enterprise/` directory | v1.108.4 (2026-11-09) | 18, 5 critical | PyPI compromise 2026-03-24 |
| Agent Router (was Envoy AI Gateway) | Go / Apache-2.0 | v1.2.1 (2026-11-06) | 20+ | Fail-open CEL deny bypass (GHSA-qcwp-vgvh-h3cm) |
| Bifrost | Go / Apache-2.0 | transports v2.5.0 (2026-11-06) | 3, 1 critical | Guardrails and MCP gateway are enterprise |
| Portkey gateway | TypeScript / MIT | v1.15.2 (2026-01-12) | 1 | Open-source repo quiet since 2026-05 |
| Kong | Lua / Apache-2.0 | n/a | 0 on the repo | AI plugin tiers not confirmed |
| TensorZero | Rust / Apache-2.0 | n/a | n/a | Repository archived |
| Cloudflare AI Gateway | Hosted | n/a | n/a | Not self-hostable |

MCP gateways:

| Project | Language / licence | Isolation | Policy | Advisories |
|---|---|---|---|---|
| Docker MCP Gateway | Go / MIT | Container per server | Tool allow-lists, interceptors | 10, 2 critical |
| ToolHive | Go / Apache-2.0 | Container + egress proxy | Cedar | 20+, none critical in the sample |
| agentgateway | Rust / Apache-2.0 | None (proxy only) | CEL + remote policy server | 7 |
| ContextForge | Python / Apache-2.0 | None | Plugins, RBAC | 19+, several critical (default JWT secret) |
| Microsoft mcp-gateway | C# / MIT | Kubernetes pods | Bearer token / RBAC | n/a |

## Weak points, gaps and risks

- **Server-side tool execution is invisible to the endpoint.** Claude Code routes claude.ai connectors through `mcp-proxy.anthropic.com` **[V]**. We can only allow, block, or disable it (`disableClaudeAiConnectors`).
- **Authorization bypass is the norm.** 2026 examples: stateful sessions crossing routes (agentgateway GHSA-mvgg-jvj2-4frq; Agent Router GHSA-72hp-5vm2-frr7), large numeric arguments vanishing from the Cedar context (ToolHive GHSA-9r8f-m39c-5rv5), URI respelling (ToolHive GHSA-gxq5-f6xj-f7w2), tool-name shadowing and case variants (Docker CVE-2026-76097, GHSA-qg99-jrvf-j9fh), signature verification off by default (Docker CVE-2026-76094) **[V]**.
- **stdio MCP test endpoints are an RCE surface.** LiteLLM CVE-2026-42271 and Bifrost GHSA-86gf-xh3g-rvxq **[V]**. A central gateway should never spawn stdio servers from API input.
- **Supply chain.** The CrowdStrike MCP shim runs `npx -y` on every launch **[V]**; the LiteLLM incident shows how that fails.
- **Coexistence.** Our WFP callout or macOS network extension will run beside CrowdStrike, Zscaler and Netskope components. Double TLS interception and redirect loops are likely **[I]**.
- **Kernel driver on Windows** means signing, crash liability and slow release cycles.

## Implications for our design

**Components**

1. **Shared Rust core crate.** Provider parsers, MCP and A2A parsers, a normalised event model, a policy evaluator and redactors. It compiles into the endpoint proxy, the gateway extension, the MCP shim, and a WASM build for the browser extension. This is also the embeddable artefact for EDR vendors.
2. **Endpoint proxy (Rust, per machine).** Explicit HTTP CONNECT and SOCKS5 listeners on loopback, plus a transparent listener fed by the OS redirector. Per-machine CA with the private key non-exportable or memory-only; name constraints where runtimes honour them. Selective MITM: decrypt only known AI and MCP hosts and unknown destinations from processes classified as agents; pass everything else through with metadata only. Study `codex-network-proxy` (Apache-2.0) for MITM hooks, credential substitution and "limited" mode; lift modules where its coupling to Codex config allows.
3. **Central gateway.** Deploy agentgateway and attach our policy as a remote guardrail (ExtMCP for MCP, its guardrail and external-authorization hooks for LLM routes). Contribute upstream rather than fork. Ship thin collectors for LiteLLM, Kong and Portkey so existing users are covered, as CrowdStrike does.
4. **MCP broker.** A single static Rust shim binary for stdio (no Node, no network fetch at launch), installed by rewriting client configs and kept in place by a config watcher. HTTP servers go through the endpoint proxy or central gateway. Policy in Cedar (the engine is Rust and Apache-2.0) following ToolHive's entity model, extended to nested arguments. Optionally launch servers under `srt` or ToolHive rather than building a sandbox.
5. **Browser extension.** Manifest V3, force-installed. Page-context wrappers for `fetch`, XHR, `WebSocket` and `EventSource` on a maintained list of AI sites; `declarativeNetRequest` for blocking; native messaging to the endpoint agent for identity and policy. Add the Chrome Content Analysis Connector as an optional path.

**Parse first:** Anthropic Messages; OpenAI Responses, then Chat Completions (which also covers OpenAI-compatible servers such as Ollama and vLLM); MCP 2025-06-18, 2025-11-25 and 2026-07-28 over stdio and Streamable HTTP; Gemini; Bedrock Converse and InvokeModel event streams; then A2A 1.0 and Realtime WebSocket.

**Steering by OS**

| OS | Phase 1 (no kernel code) | Phase 2 |
|---|---|---|
| Windows | Managed settings and environment injection; WFP user-mode block filters by SID or app ID to force traffic to the proxy (the `srt` pattern) | Signed ALE connect-redirect callout driver |
| macOS | Managed settings and environment; Seatbelt for launched agents | `NETransparentProxyProvider` system extension through MDM |
| Linux / Kubernetes | Environment; bubblewrap with no network namespace | cgroup eBPF connect redirect, DaemonSet per node |

**Performance targets** (proposed, not measured) **[I]**: pass-through tunnel overhead under 1 ms p99; MITM added latency under 5 ms p99 after a cached leaf certificate; per-chunk streaming overhead under 1 ms; synchronous local detectors under 30 ms p95, with slower model-based checks asynchronous or applied only to tool-call arguments; idle memory under 60 MB on endpoints. Bifrost's 11 µs claim and TensorZero's "<1 ms p99" claim show that the proxy hop itself is not the bottleneck **[V]**.

**Rules to adopt from others' failures**

- Fail closed on every policy evaluation error.
- Canonicalise tool names (case, Unicode), URIs and numbers before evaluation.
- Bind any session state to route and principal.
- Bound every upstream-controlled index and length in stream parsers.
- Reject duplicate JSON keys.
- Verify `Mcp-Name` and `Mcp-Method` headers against the body.
- Resolve DNS once and dial the vetted IP.
- Verify signatures by default.

## Ideas worth stealing and whitespace

- **Tool-definition pinning.** Hash the canonical name, description, schemas and annotations per server identity; alert or hold on change. The 2026-07-28 rules (deterministic order, `ttlMs`, per-result `serverInfo`) make this cheap, and no gateway I read documents it.
- **Per-session dynamic egress.** `srt --control-fd` and Codex's `policy_decider` callback (which receives the triggering command) show the mechanism **[V]**. Nobody ties the allow-list to the declared task.
- **Cross-layer correlation.** Join hook events, MCP calls and network flows by PID and time into one record. Vendors describe this (CrowdStrike "Agent Graph") but nothing open does it.
- **Credential substitution at the proxy.** The agent holds a placeholder; the proxy injects the real token for allowed host + method + path (Codex MITM hooks, Docker `--block-secrets`).
- **Policy replay.** BeyondTrust replays recorded activity against a draft policy before saving **[V]**.
- **Kill switch at two layers.** Gateway model cut-off (CrowdStrike) plus endpoint egress block per agent type (which CrowdStrike lists as coming soon) **[V]**.
- **Linux, self-hosted and single-laptop coverage.** BeyondTrust has no Linux; CrowdStrike's is pre-beta **[V]**.
- **A public conformance and bypass test suite for MCP gateways,** built from the 2026 advisories.

## Could not verify / open questions

- No web searches were possible; coverage of late-2026 announcements depends on the pages I fetched directly.
- CrowdStrike endpoint network inspection internals (docs are behind login).
- Whether `envoyproxy/ai-gateway` was renamed, donated or forked: I saw only the GitHub redirect and the new repo's description.
- Why TensorZero was archived.
- Chrome and Edge connector provider lists and schemas (Google support page returned 404; the policy site renders with JavaScript); Edge and Purview equivalents.
- Certificate pinning in Cursor, ChatGPT desktop, Copilot and Windsurf.
- Bun's system-CA flag; current defaults in Python `httpx`, `uv` and Rust `reqwest`.
- Kong's open-source versus enterprise AI plugin split; LiteLLM's enterprise feature list (page returned 404).
- Codex sandboxing docs (the OpenAI developer site redirected to another host and the sandboxing page was not fetched).
- Advisory counts marked "+" were truncated at 20 rows.

## Sources

- https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-ai-security-and-safety-falcon-guardian/ (CrowdStrike blog, 2026-11-03)
- https://www.crowdstrike.com/en-us/platform/falcon-aidr-ai-detection-and-response/ (Falcon Guardian product page, read 2026-11-09)
- https://pangea.cloud/docs/aidr/ , /collectors/agentic , /collectors/browser (AIDR docs, read 2026-11-09)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (updated 2026-10-13)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (updated 2026-10-23)
- https://learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview (2026-10-08)
- https://learn.microsoft.com/en-us/entra/global-secure-access/concept-secure-web-ai-gateway-agents (updated 2026-10-06)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection (updated 2025-07-11)
- https://developer.apple.com/documentation/networkextension/netransparentproxyprovider (read 2026-11-09)
- https://nodejs.org/api/cli.html (Node v26.13.0 docs)
- https://bun.com/docs/runtime/networking/fetch ; https://docs.deno.com/runtime/reference/env_variables/
- https://code.claude.com/docs/en/network-config ; https://code.claude.com/docs/en/llm-gateway
- https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md
- https://github.com/anthropics/sandbox-runtime (v0.0.82, 2026-11-09)
- https://modelcontextprotocol.io/specification/2026-07-28/changelog ; https://github.com/modelcontextprotocol/registry
- https://a2a-protocol.org/latest/specification/ (v1.0.0)
- https://agentgateway.dev/docs/standalone/latest/about/introduction/ , /llm/api-types/ , /mcp/ , /mcp/guardrails/about/
- https://github.com/docker/mcp-gateway/blob/main/docs/security.md ; https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- https://docs.stacklok.com/toolhive/concepts/cedar-policies ; https://docs.stacklok.com/toolhive/guides-cli/network-isolation
- https://github.com/IBM/mcp-context-forge ; https://github.com/microsoft/mcp-gateway ; https://github.com/lasso-security/mcp-gateway ; https://github.com/snyk/agent-scan
- https://docs.litellm.ai/blog/security-update-march-2026 ; https://github.com/BerriAI/litellm/security/advisories
- https://github.com/theagentrouter/agent-router/security/advisories ; https://github.com/agentgateway/agentgateway/security/advisories ; https://github.com/stacklok/toolhive/security/advisories ; https://github.com/docker/mcp-gateway/security/advisories ; https://github.com/maximhq/bifrost
- https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html
- https://developer.konghq.com/ai-gateway/ ; https://developers.cloudflare.com/ai-gateway/
- https://developer.chrome.com/docs/extensions/reference/api/webRequest ; https://github.com/chromium/content_analysis_sdk

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. The shared web-search quota was exhausted, so no search-engine queries were run; every verdict rests on a direct read of a primary page, the GitHub API, the OSV API, PyPI or the npm registry._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | MCP 2026-07-28 removes sessions and `initialize`, requires `Mcp-Method` / `Mcp-Name`, adds `server/discover`, requires deterministic `tools/list` order and `ttlMs` / `cacheScope`, deprecates DCR for CIMD | Corrected | Deterministic `tools/list` order is a SHOULD, not a requirement. `Mcp-Name` is required only on `tools/call`, `resources/read` and `prompts/get`; `Mcp-Method` on all requests. `clientInfo` and `serverInfo` are SHOULD. Everything else holds, and the revision is a final release (tag `2026-07-28`, not prerelease). DCR stays available for backwards compatibility. | [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog), [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), GitHub releases of `modelcontextprotocol/modelcontextprotocol` |
| 2 | agentgateway: Rust, Apache-2.0, v1.7.0 (2026-10-27), AAIF project, supports the listed LLM APIs, MCP (CEL authorization, CEL or ExtMCP guardrails, version translation) and A2A | Confirmed | AAIF's own project list includes agentgateway. Version handling is documented in the source tree: the proxy downgrades for clients when a server lacks 2026-07-28. `mcpAuthorization` CEL rules cannot see tool arguments; argument checks need a guardrail processor. The guardrails page documents no failure-mode default. | [AAIF projects](https://aaif.io/projects/), GitHub API, `crates/agentgateway/src/mcp/README.md`, [guardrails](https://agentgateway.dev/docs/standalone/latest/mcp/guardrails/about/) |
| 3 | LiteLLM: 18 published 2026 advisories, five critical; PyPI 1.82.7 and 1.82.8 compromised 2026-03-24 | Confirmed | Repo advisory list has 18 entries, all 2026, five critical. OSV `PYSEC-2026-2` / `MAL-2026-2144` (published 2026-03-24) names exactly 1.82.7 and 1.82.8; both are gone from PyPI. The count is a floor: OSV lists five more GHSA entries for the package that the repo list omits (for example CVE-2026-12773, MCP proxy improper authentication). | GitHub API `BerriAI/litellm/security-advisories`, [OSV PYSEC-2026-2](https://api.osv.dev/v1/vulns/PYSEC-2026-2), PyPI JSON API |
| 4 | Claude Code trusts bundled plus OS stores by default, honours `HTTPS_PROXY` but not SOCKS, and `allowedProviders: ["customEndpoint"]` with `ANTHROPIC_BASE_URL` pins the gateway (v2.1.285+) | Confirmed | Reading the OS store on npm installs needs Node 22.15+. The pin must sit in the managed settings file with the base URL in that file's `env` block. | [network-config](https://code.claude.com/docs/en/network-config), [llm-gateway](https://code.claude.com/docs/en/llm-gateway) |
| 5 | Node uses the bundled CA snapshot unless `--use-system-ca` (v23.8.0), `NODE_USE_SYSTEM_CA=1` (v24.6.0 / v22.19.0) or `NODE_EXTRA_CA_CERTS`; proxy variables need `--use-env-proxy` or `NODE_USE_ENV_PROXY=1` (v24.5.0 / v22.21.0) | Corrected | `NODE_USE_ENV_PROXY=1` was added in v24.0.0 / v22.21.0; only the `--use-env-proxy` flag dates from v24.5.0. The rest holds. The default CA store is selectable at build time, so distribution builds of Node may default to the OpenSSL store. | `doc/api/cli.md` in `nodejs/node` (main) |
| 6 | Windows transparent redirection needs a WFP callout driver at `ALE_CONNECT_REDIRECT`; the proxy reads the original destination with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` and must set redirect records on its outbound socket | Confirmed | On Windows 8+ the proxy must also call `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` on the accepted socket before `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the new one. The driver must call `FwpsQueryConnectionRedirectState0` to avoid redirect loops. | [Microsoft docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection) |
| 7 | sandbox-runtime (Apache-2.0, v0.0.82): bubblewrap without a network namespace on Linux, Seatbelt on macOS, dedicated user plus SID-keyed WFP filters on Windows, `--control-fd` live updates | Corrected | Linux is the opposite of "without": the code always passes `bwrap --unshare-net`, which puts the process in a new, empty network namespace; `socat` bridges to host proxies over bind-mounted Unix sockets. Windows support is labelled alpha, uses user-mode filters at `ALE_AUTH_CONNECT`, and Schannel-based clients cannot complete HTTPS under the restricted token. Each `--control-fd` line replaces the whole config. | `src/sandbox/linux-sandbox-utils.ts` and README in `anthropics/sandbox-runtime` |
| 8 | Falcon Guardian: hooks and AI Gateway available, endpoint network inspection and Linux pre-beta (2026-11-03); MCP proxy is an `npx` stdio wrapper with three checkpoints and no description pinning | Confirmed | The proxy's own repository and npm package agree: stdio only, `mcp-remote` for remote servers, Node 22.15+, MIT, last release 1.6.1 on 2026-06-11. Neither the blog nor the product page says Guardian is a rename; they call it the flagship AIDR solution, and the docs still say AIDR. | [blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-ai-security-and-safety-falcon-guardian/), `CrowdStrike/aidr-mcp-proxy` README, npm registry |
| 9 | In MV3, `webRequestBlocking` is policy-install only; `webRequest` exposes request bodies but not response bodies and sees only the WebSocket handshake | Corrected | True for Chromium browsers only. Firefox documents `webRequest.filterResponseData`, which reads and rewrites response bodies with the `webRequestBlocking` permission and no policy-install condition. WebTransport is also handshake-only in Chrome. | [Chrome docs](https://developer.chrome.com/docs/extensions/reference/api/webRequest), [MDN webRequest](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest) |
| 10 | TensorZero archived (last push 2026-06-11); `envoyproxy/ai-gateway` resolves to `theagentrouter/agent-router` (v1.2.1, 2026-11-06) with 20+ advisories including a fail-open CEL deny bypass | Confirmed | The exact count is 24 published advisories. AAIF lists Agent Router as a hosted project, which answers the open question about the move. | GitHub API, [AAIF projects](https://aaif.io/projects/) |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| LiteLLM's five criticals are "SQL injection in key verification, three authentication bypasses, master-key leak" | Corrected | Two authentication bypasses (Host header injection, OIDC cache-key collision), one privilege escalation to proxy admin through salt-key reuse, one SQL injection, one unauthenticated file read that leaks the master key. | GitHub API `BerriAI/litellm/security-advisories` |
| Steering table: Linux phase 1 is "bubblewrap with no network namespace"; Windows phase 1 is the `srt` SID-filter pattern | Corrected | Linux should read "bubblewrap with an isolated network namespace (`--unshare-net`)". The Windows pattern requires running the agent as a separate local account under a write-restricted token, is alpha, breaks Schannel TLS clients, and does not follow threads that assume another token. | `anthropics/sandbox-runtime` README and source |
| Open question: was `envoyproxy/ai-gateway` renamed, donated or forked | Resolved | It is now Agent Router, an AAIF-hosted project alongside agentgateway, MCP and A2A. | [AAIF projects](https://aaif.io/projects/) |

Also re-checked and found accurate as written: Microsoft `mcp-gateway` supports only 2026-07-28 (README breaking-change notice); release versions and licences for Docker MCP Gateway, ToolHive, ContextForge, Snyk Agent Scan, Portkey, Bifrost and A2A; the BeyondTrust prerequisites and OS support; Agent 365 general availability on 2026-05-01 with per-user licensing.
