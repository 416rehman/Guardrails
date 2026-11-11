# Sidekick Security and AI-in-SaaS control at the browser and identity edge

_Researched 2026-11-09_

Legend: **[V]** verified this run against the linked primary source. **[S]** secondary source or search summary only. **[K]** prior knowledge (cutoff mid-2026), not re-fetched. **[I]** my inference.

The shared web-search budget ran out about two thirds of the way through. Push, Nudge, Harmonic, Microsoft, Google, Anthropic, OpenAI-header and LayerX/Akamai findings are sourced; Grip, Obsidian, Valence, Reco, SquareX, Island and Prompt Security were not re-verified and are marked [K].

## TL;DR

- **Sidekick is a Chrome extension with a cloud console, and it has just repositioned.** Its own structured data links a Chrome Web Store listing, "Sidekick: Forward-Deployed" (ID `lbbkokkcdaonjenckieahjlnjhepalco`). Until recently it sold "guardian agents" against social engineering; the homepage republished around 2026-11-10 now says "Agentic SaaS under control" and the blog subdomain 301s to the homepage. No public docs, pricing, integrations list or funding amount exist.
- **The category has four data planes and no vendor owns all of them:** browser extension (Push, Harmonic, LayerX/Akamai, Prompt, Obsidian), mailbox and IdP mining (Nudge, Grip), SaaS admin APIs (Reco, Valence, Obsidian, Zenity), and the browser vendor itself (Edge + Purview, Chrome Enterprise). Nudge's own comparison states no single method gives full coverage.
- **Personal-versus-corporate detection is mostly email-domain matching on observed logins** (Push documents exactly this), plus session-riding calls to the app's own API using the user's cookie (Push documents this for MFA status). Harmonic claims account type and plan per session but publishes no mechanism.
- **Tenant-restriction headers now exist for the major AI providers** and are the only provider-enforced control: `anthropic-allowed-org-ids`, `ChatGPT-Allowed-Workspace-Id`, `X-GoogApps-Allowed-Domains`, `sec-Restrict-Tenant-Access-Policy` (Entra TRv2), `sec-GitHub-allowed-enterprise`. Vendor docs assume a TLS-inspecting proxy.
- **A force-installed MV3 extension can inject those headers with `declarativeNetRequest` `modifyHeaders`, with no TLS interception.** An Apache-2.0 extension already does it generically (`jay0lee/forced-headers-chrome-ext`). Nobody ships a maintained AI-provider rule pack. This is the cheapest high-value feature available to us.
- **Microsoft's Edge-only answer is strong but narrow:** Purview inline DLP covers 19 named unmanaged AI apps, Windows + Intune only for unmanaged apps, 4 MB text / 3 MB file limits, and it "solves" Chrome by pushing a URL blocklist and blocking Firefox outright.
- **Browser AI agents are governable only by each vendor's own policy keys.** Gemini auto browse (`GeminiActOnWebSettings` + allowed/blocked URL lists, off by default for managed users), Claude in Chrome (admin allowlist/blocklist), Edge Agent Mode (approved sites). ChatGPT Atlas was retired on 2026-08-09.
- **Agent-versus-human attribution inside the browser is partial.** The one open-source attempt (AI Browser Guard, Apache-2.0) admits CDP-driven agents use native input the page cannot intercept; the categorical control is `RemoteDebuggingAllowed=false`.
- **Consolidation is fast:** Seraphic to CrowdStrike (announced 2026-01-13, about $400M), LayerX is now "Akamai Workforce Protector", Prompt Security to SentinelOne [K]. EDR vendors without a browser sensor are the natural embed customers.
- **Nobody tracks "does this account train on our data" as a verified per-account fact.** Sidekick markets it; Nudge's own article only recommends looking for tools that surface vendor training policy. It is whitespace.

## Findings

### 1. Sidekick Security (Sidekick Labs, Inc.)

**Company.** Legal name Sidekick Labs, Inc.; founded 2023; Boston and Denver; founders Brian Hazzard and David "Moose" Wolpoff, the Randori co-founders (Randori was acquired by IBM in 2022). Investors listed as "funder" in the site's JSON-LD: Ten Eleven Ventures, Accomplice, .406 Ventures, Underscore VC, Step Function. No round size or date is published. [V] https://sidekicksecurity.ai/ (page source, 2026-11-09)

**Mechanism.** [V] The JSON-LD `sameAs` array includes `https://chromewebstore.google.com/detail/sidekick-forward-deployed/lbbkokkcdaonjenckieahjlnjhepalco`. The store page returned an empty shell to a non-JS fetch and a store text search found nothing, so the listing may be unlisted. [V] The JSON-LD description still carries the earlier pitch: a platform that "forward-deploys a team of expert guardian agents beside every user", covering social engineering, identity threats, shadow SaaS, AI misuse and risky browsing. [V] The privacy policy (effective 2026-09-01) says the company may send "operational data, security event information, and related usage data" to third-party AI services, and mentions a mobile application; it names no sub-processors.

[I] Reading the homepage against that: Sidekick is an in-browser sensor that watches three moments (sign-up, sign-in, settings change), reads identity, account settings and connected apps from the page or the app's session-authenticated endpoints, and overlays guidance generated by cloud LLM "agents". "Applications with no central management" means apps with no admin API or SSO, which only a browser sensor can reach. There is no evidence of API connectors, IdP log ingestion, a desktop agent, or Firefox/Safari support.

**Features claimed** [V]: per-account answers to which accounts train on your data, where personal identities access company data, which apps are connected (OAuth and integrations), where SSO/MFA is missing; intervention at sign-up, sign-in and settings change with "the right identity, the right setting, the approved app".

**Limits** [I]: Chrome-family only; nothing for desktop apps, CLIs, coding agents or MCP; no enforcement beyond in-page guidance is described; SaaS-only with cloud LLM processing; zero public technical documentation. Treat it as a positioning signal, not a technical benchmark.

### 2. How the category leaders work

**Push Security (extension-first).** [V] Deployed by MDM, Google Admin, Group Policy or manual enrolment. Default scope is logins using company email domains to recognised work apps; an opt-in "Monitor all domains" setting also records personal-email logins to work apps (email, timestamp, apps, findings) and Push advises getting employee consent first. https://pushsecurity.com/help/can-i-use-push-to-detect-personal-or-non-work-accounts [V] It captures login method (password, SAML, OIDC), MFA usage and method, and inventories apps, accounts, OAuth integrations and extensions. https://pushsecurity.com/help/how-does-push-browser-extension-work [S] Password reuse is detected with a locally generated UUIDv4 salt and the first 8 characters of SHA-256(salt+password), stored only in extension storage; MFA status is read by using the user's existing session to query the app's API. https://pushsecurity.com/help/how-does-the-push-browser-extension-securely-track-reused-passwords/ and https://pushsecurity.com/help/how-does-mfa-enforcement-work

**Nudge Security (mailbox-first).** [S] Patented discovery from machine-generated SaaS emails via a Microsoft 365 or Google Workspace integration, giving historical coverage with no agent; an OAuth grant inventory with scope-based risk scoring and revocation; a browser extension added for real-time nudges and prompt monitoring (ChatGPT, Gemini, Copilot, Perplexity, January 2026); browser-based AI agent discovery in research preview (May 2026). [V] Its 2026-08-19 method comparison: email misses personal-email sign-ups; extensions miss mobile, BYOD and history; network misses off-network users; IdP logs miss password accounts; SSPM misses anything outside its connector list. https://www.nudgesecurity.com/post/ai-discovery-methods-compared

**Harmonic Security (extension + endpoint + MCP gateway).** [V] Extension for Chrome, Edge, Firefox, Safari and Chromium forks including Arc, Brave, Island, Comet and Dia; MDM deployment; "identifies the specific account type and subscription plan in use"; purpose-built small language models with about 200 ms inline classification; covers AI features embedded in SaaS (Canva Magic Write, Grammarly). Where inference runs is not stated. https://www.harmonic.security/solutions/browser-based-genai-security [S] A local MCP Gateway (October 2025) and an endpoint agent cover Claude Code, Cursor and similar.

**LayerX, now Akamai Workforce Protector.** [V] layerxsecurity.com redirects to Akamai; the page says "Following Akamai's acquisition" (date not given). Extension for Chrome, Edge, Safari, Firefox and AI browsers (Atlas, Comet, Dia); claims agent-versus-human attribution, AI side-panel control, prompt and response capture, extension risk scoring, anti-tamper including incognito. No mechanism is published. https://www.akamai.com/products/akamai-workforce-protector

**Seraphic, now CrowdStrike.** [S] Announced 2026-01-13 at a reported $400M; injects an abstraction layer around the browser's JavaScript engine in any browser, including agentic browsers, on managed and unmanaged devices. Closing and Falcon packaging were not verified. https://www.crowdstrike.com/en-us/blog/crowdstrike-to-acquire-seraphic/

**Microsoft Edge for Business + Purview.** [V] Inline DLP is built into Edge with no device onboarding. For unmanaged AI apps it requires Windows 10/11 managed by Intune and Edge 144+, and applies across work, personal and InPrivate profiles. Supported unmanaged apps are a fixed list of 19 (ChatGPT consumer, Gemini, DeepSeek, Perplexity, Grok, Meta AI, Notion AI, Otter, Cohere, You.com and others); Claude is not in the DLP list. Limits: 4 MB text and 3 MB file; consumer and enterprise ChatGPT cannot be told apart when the URL is shared; some apps send encoded content that defeats inspection; B2B guests and Intune multi-admin approval are unsupported. https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn (updated 2026-10-30) [V] Anti-bypass: saving a policy auto-creates Edge and Intune policies; Chrome stays usable but a Microsoft-managed list of AI sites is added to `URLBlocklist`; Firefox and other browsers are blocked. https://learn.microsoft.com/en-us/deployedge/microsoft-edge-dlp-purview-configuration (updated 2026-10-06) [V] Agent Mode in Edge: IT enables it and limits it to approved sites; it cannot access saved passwords or payment methods; existing DLP applies. A connector framework exists (Trellix DLP GA, Devicie telemetry GA). https://blogs.windows.com/msedgedev/2026/03/23/protect-your-enterprise-from-shadow-ai-and-more-announcements-at-rsac-2026/ [S] Expansion to a much broader set of unmanaged AI apps: preview November 2026, GA January 2027 (roadmap RM571396).

**Chrome Enterprise.** [V] `GenAiDefaultSettings` sets defaults for built-in AI features; cloud-managed browsers default to "allow without improving AI models", while third-party-managed browsers default to "allow and improve AI models". https://support.google.com/chrome/a/answer/14443058 [V] Gemini in Chrome needs both the Gemini app setting and the `GeminiSettings` policy; auto browse is off by default for managed users and controlled by `GeminiActOnWebSettings`, `GeminiActOnWebAllowedForURLs` and `GeminiActOnWebBlockedForURLs`; `GeminiSparkSettings` governs Gemini Spark driving the live browser session. https://support.google.com/chrome/a/answer/16291696 [S] Reporting connector events include `loginEvent`, `passwordReuseEvent`, `sensitiveDataEvent`, `urlFilteringInterstitialEvent`, plus extension telemetry and URL navigation; content events need Chrome Enterprise Premium. [V] `chromium/content_analysis_sdk` (BSD-3-Clause, pushed 2026-08-11) is the official way for a local DLP agent to become a Content Analysis Connector provider over protobuf. [K] Chromium hard-codes the list of permitted local providers, so a new agent cannot self-register without an upstream change.

**SaaS-API and identity side** [K unless marked]: Reco, Valence and Obsidian are connector-based SSPMs that read admin APIs and audit logs for OAuth grants, AI feature settings and agent configurations; Obsidian also ships an extension. Grip mines IdP and mailbox data and revokes via IdP. [V] Zenity names Copilot Studio, Agentforce, Bedrock and Vertex AI, correlates Okta and Entra identity with agent activity, and offers endpoint monitoring for local agents; nothing on agentic browsers. https://zenity.io/platform. Island is a Chromium-fork enterprise browser with a companion extension. Prompt Security (SentinelOne) and SquareX are extension-based.

### 3. Tenant-restriction headers offered by AI providers

| Provider | Header | Value | Verified notes |
|---|---|---|---|
| Anthropic | `anthropic-allowed-org-ids` | Comma-separated org UUIDs, no spaces; up to 500 across 10 header lines using `;n=K` continuation | [V] Enterprise plans and Console orgs. Covers web, desktop, API-key and OAuth auth. Apply on claude.ai, api.anthropic.com, claude.com, anthropic.com. Violation: 403 `tenant_restriction_violation`; duplicate or malformed: 400. Proxy must overwrite, not append. https://support.claude.com/en/articles/13198485 |
| OpenAI | `ChatGPT-Allowed-Workspace-Id` | Comma-separated workspace UUIDs | [S] Enterprise only; checked at login on chatgpt.com, not api.openai.com; logged-out use needs a separate block of `chatgpt.com/backend-anon/`. Help article 20001323 returned 403 to my fetch. |
| Google | `X-GoogApps-Allowed-Domains` | Comma-separated Workspace domains | [V] Applies to all Google sign-in, not only Gemini; does not guarantee every Gemini access path; existing personal sessions may persist. Fortinet tech tip, 2026-10-16 |
| Microsoft | `sec-Restrict-Tenant-Access-Policy` (TRv2); legacy `Restrict-Access-To-Tenants`, `Restrict-Access-Context`, `restrict-msa` | Tenant and policy IDs | [V] Cloudflare tenant-control doc. [S] Consumer Copilot is reachable at copilot.cloud.microsoft, so URL blocks are not enough; no per-user granularity for personal accounts. |
| GitHub | `sec-GitHub-allowed-enterprise` | Enterprise ID | [V] EMU only; apply on github.com, api.github.com, `*.githubcopilot.com`. Alternative: block `*.individual.githubcopilot.com`. https://docs.arcjet.com/coding-agents/block-personal-accounts (2026-09-29) |
| Codex CLI | `allowed_chatgpt_workspaces`, `allowed_login_methods` in `/etc/codex/requirements.toml` or `%ProgramData%\OpenAI\Codex\requirements.toml` | Workspace UUID | [V] same Arcjet doc. API keys bypass unless `api` is excluded. |
| Cursor | MDM `AllowedTeamId` | Team ID | [V] same doc. `CURSOR_API_KEY` bypasses. |

### 4. Browser AI agents

- **ChatGPT Atlas:** [S] retired, stopped working 2026-08-09; capabilities moved into ChatGPT and Codex. https://help.openai.com/en/articles/20001371-chatgpt-atlas-retirement
- **Claude in Chrome:** [V] three approval modes, per-site permissions, Team and Enterprise allowlists and blocklists that override user choices. https://support.claude.com/en/articles/12902446-claude-in-chrome-permissions-guide [S] On by default for Enterprise from 2026-09-10 unless disabled (single third-party source).
- **Gemini in Chrome:** policies above; not available in Incognito.
- **Comet, Dia:** [S] Chromium forks that read their own policy locations, so Chrome-targeted policy does not reach them. Comet Enterprise has MDM deployment and domain blocking.
- **Detection from an extension:** [V] AI Browser Guard combines `navigator.webdriver` checks, `chrome.debugger` target inspection, CDP stack traces and input-timing heuristics; it names Playwright, Puppeteer, Selenium, Anthropic Computer Use and OpenAI Operator, and states its limits plainly (below). https://opena2a.org/aibrowserguard, https://github.com/opena2a-org/ai-browserguard (6 stars, pushed 2026-11-05)

### 5. Adjacent technical docs named in the request

- **BeyondTrust AI Agent Security** [V] (doc updated 2026-10-13): endpoint-only discovery on Windows 11 / Server 2022+ x64 and macOS 14, 15, 26. Identifies agents by process naming, signatures and LLM API traffic patterns; inventories MCP servers, LLM endpoints and skills; enforces at kernel and network level plus tool-call hooks where the agent supports them; separates agent from human activity for the same user; needs a tenant root certificate for HTTPS inspection; lets admins replay recorded activity against a draft policy. It does not screen prompts and has no browser or SaaS discovery. https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- **Microsoft Agent 365** [V] (updated 2026-10-23): GA 2026-05-01, licensed per user, "works best" with E5. A registry and agent map in the Microsoft 365 admin centre, with Entra for access, Purview for data and Defender for threats. The overview describes registered and partner agents; it does not describe discovering unregistered local or browser agents. https://learn.microsoft.com/en-us/microsoft-agent-365/overview

## Matrix

| Vendor | Primary sensor | Personal vs corporate | Training setting | OAuth grants | Browser agents | Enforcement | Open source |
|---|---|---|---|---|---|---|---|
| Sidekick | Chrome extension [V] | Claimed | Claimed | Claimed | Not stated | In-page guidance | No |
| Push | Extension + IdP API | Email domain, opt-in for personal [V] | No | Yes | Not verified | Banner, block, MFA/SSO enforce | No |
| Nudge | Mailbox + extension + APIs | Email only; misses personal-email sign-ups [V] | Recommended, not confirmed | Yes, with revoke | Research preview | Nudges, revoke | No |
| Harmonic | Extension + endpoint + MCP gateway | Account type and plan [V claim] | Not stated | No | Logs agent tool calls | Warn, block, about 200 ms | No |
| Akamai (LayerX) | Extension | Not stated | No | No | Agent vs human claimed | Warn, redact, block | No |
| CrowdStrike (Seraphic) | JS-engine layer | Not verified | No | No | Agentic browsers claimed | In-runtime | No |
| Edge + Purview | Native browser | Entra profile; cannot split ChatGPT tiers [V] | No | Via Entra/Defender | Agent Mode site list | Block, audit, redirect to Copilot | No |
| Chrome Enterprise | Native browser + connectors | Profile sign-in | Own features only | Workspace admin | Auto browse URL lists | URL filter, DLP (Premium) | SDK only |
| Reco / Valence / Obsidian [K] | SaaS APIs | From tenant data | Tenant settings where exposed | Yes | No | Remediate via API | No |
| Zenity | SaaS + cloud APIs + endpoint | n/a | n/a | Agent connections | Not covered [V] | Runtime allow/block | Some tools [K] |
| forced-headers ext | MV3 DNR | Provider-enforced | No | No | No | Header injection | Apache-2.0 |
| AI Browser Guard | MV3 + debugger | No | No | No | Detect, kill tabs | Best effort | Apache-2.0 |

## Weak points, gaps and risks

- **Extension blind spots are structural:** only enrolled browsers and profiles; nothing on mobile, desktop apps, CLIs or unmanaged devices [V, Nudge]. Standalone AI browsers ignore Chrome policy [S].
- **Network inspection is weak in MV3.** [V] `webRequest` exposes request bodies for PUT/POST but no response bodies, and WebSocket frames after the handshake are invisible; `webRequestBlocking` survives only for policy-installed extensions. Prompt and response capture therefore depends on per-app content scripts that break when the app changes; Microsoft documents the same fragility for its native implementation ("encoded form", "dynamically generated endpoints").
- **CDP-driven agents cannot be blocked per action from a page.** [V] AI Browser Guard: external frameworks "act through native input that the page cannot intercept"; its kill switch can be undone by a persistent driver. [K] `event.isTrusted` is true for CDP-dispatched input.
- **Header injection has holes:** API keys bypass ChatGPT and Cursor pins; the Google header is all-or-nothing across Google services; logged-out ChatGPT needs a path block; existing sessions persist; native apps and CLIs never pass through the extension.
- **Session-riding is legally and technically delicate.** Calling an app's private endpoints with the user's cookie is how MFA, plan and settings are learned [S, Push], but endpoints are undocumented and may breach provider terms. Push itself tells customers to get consent before monitoring personal-domain logins.
- **A security extension is a prime target.** It needs `<all_urls>`, sees credentials in forms, and other extensions already hijack AI chats [S, G DATA June 2026]. A compromised update channel is a fleet-wide incident.
- **Chromium's Content Analysis Connector is gated** [K]: we cannot rely on becoming a provider.
- **Vendor opacity:** none of Sidekick, Harmonic, LayerX or Seraphic publish detection mechanics. Claims of "agent versus human" attribution are unverifiable.

## Implications for our design

1. **Ship an MV3 extension as one sensor among several, paired with the endpoint agent over native messaging.** [K] Deploy with `ExtensionInstallForcelist` / `ExtensionSettings` (Chrome, Edge, Brave), `policies.json` (Firefox) and an MDM-managed app wrapper (Safari). Configure with `chrome.storage.managed`. The endpoint agent writes the policy keys, registers the native host, and detects extension removal; the extension gives the agent page-level context it cannot get from the OS.
2. **First feature: a tenant-restriction rule pack.** Static and dynamic DNR `modifyHeaders` rules with `set` for the headers in section 3, driven by managed config (org UUIDs, workspace IDs, domains), plus block rules for `chatgpt.com/backend-anon/` and `*.individual.githubcopilot.com`. [V] DNR limits are generous (30,000 dynamic rules; `set` is unrestricted, `append` is allowlisted). Pair it with the device-side controls the extension cannot reach: Codex `requirements.toml`, Cursor `AllowedTeamId`, Claude Code managed settings. One policy object, three enforcement points.
3. **Model an "account context" record per (app, browser profile):** email, IdP used, login method, MFA, tenant/workspace ID, plan tier, training-opt-out state, connected apps. Fill it from per-app adapters kept as signed, versioned data files (selectors and endpoint descriptors), not code, so the community can maintain them and updates do not need store review. Mark each field with provenance and confidence.
4. **Classify identity locally.** Compare observed login emails against managed corporate domains; hash non-corporate emails by default and reveal only under an explicit admin setting with a user-visible notice. Copy Push's salted truncated-hash design for password reuse and keep it on-device.
5. **Generate browser-vendor policy instead of competing with it.** Emit `GeminiActOnWeb*`, `GeminiSettings`, `GenAiDefaultSettings`, `RemoteDebuggingAllowed=false`, Edge AI settings and `URLBlocklist` from our policy model, and report drift. Ingest Chrome and Edge reporting-connector events (`loginEvent`, `sensitiveDataEvent`, extension telemetry) as a free telemetry source for orgs that already have them.
6. **Treat browser-agent attribution as layered evidence, not a verdict.** In-extension: `chrome.management` inventory of AI extensions, `chrome.debugger.getTargets()` attachment state, side-panel presence, UA brand for AI browsers. From the endpoint agent: process ancestry and `--remote-debugging-port/pipe` flags. Join both on tab and timestamp to label a session "agent-driven", with a stated confidence.
7. **Run prompt DLP on-device.** Regex and small classifiers in the extension or the local agent; never ship prompt text to our cloud by default. Budget for Microsoft's observed limits (multi-megabyte pastes, encoded payloads) and fail open with an audit event.
8. **Expose the extension as an embeddable module** with a stable event schema (login observed, account context changed, tenant header applied, agent attached, prompt policy decision). Browser sensors are being bought by the EDR vendors that lack one.
9. **Borrow BeyondTrust's policy replay:** let admins run a draft browser policy against recorded events before enforcing.

## Ideas worth stealing and whitespace

- **Moment-of-action guidance** (Sidekick, Push, Nudge): intervene at sign-up, sign-in and settings change with the approved alternative, instead of a block page.
- **Block-and-redirect** (Edge): a blocked prompt offers a button that reopens it in the sanctioned tool.
- **Session-riding posture checks** (Push): reuse the user's session to read MFA, plan and settings from apps that have no admin API.
- **Whitespace 1: a verified training-status ledger.** Per account: plan tier, opt-out toggle state, and the provider's default for that tier, with evidence. Nobody documents doing this.
- **Whitespace 2: an open, maintained tenant-restriction pack** covering browser headers and CLI/IDE managed settings together.
- **Whitespace 3: cross-surface identity join.** The same human using a personal Claude account in the browser, an API key in a CLI and a corporate seat in the desktop app is three unrelated records in every product reviewed.
- **Whitespace 4: governance of standalone AI browsers** through their own policy locations, generated from one model.
- **Whitespace 5: honest attribution.** Publishing detection methods and confidence, as AI Browser Guard does, is itself a differentiator against opaque vendors.
- **Whitespace 6: self-hosted.** Every product here is cloud-console SaaS; none runs on one laptop.

## Could not verify / open questions

- Sidekick's extension manifest, permissions, user count and whether the store listing is public (not downloaded; store page is JS-rendered). Funding amount and round dates. Whether it uses IdP or API connectors at all.
- OpenAI's own help article for `ChatGPT-Allowed-Workspace-Id` (403); header details come from Cloudflare, Fortinet and Arcjet docs.
- Whether `anthropic-allowed-org-ids` covers Claude Code explicitly (the Anthropic article lists web, desktop, API-key and OAuth auth; Arcjet's doc says it does).
- Exact values of `GeminiActOnWebSettings` and `GeminiSettings`; chromeenterprise.google policy pages are JS-rendered.
- The "Claude in Chrome admin controls" article and the 2026-09-10 default-on date.
- Grip, Obsidian, Valence, Reco, SquareX, Island and Prompt Security specifics; CrowdStrike/Seraphic closing and packaging; Akamai/LayerX acquisition date.
- Whether DNR `modifyHeaders` on provider domains is tolerated by Chrome Web Store review for a general-purpose listing (the forced-headers extension is listed, which suggests yes).
- Safari managed-extension capabilities and whether DNR header modification behaves identically there.
- Private endpoints that reveal plan and training state for each AI app: must be mapped by hand per app.

## Sources

- https://sidekicksecurity.ai/ - Sidekick homepage and JSON-LD, page metadata 2026-11-10
- https://sidekicksecurity.ai/privacy - Privacy policy, effective 2026-09-01
- https://pushsecurity.com/help/can-i-use-push-to-detect-personal-or-non-work-accounts - Push help, fetched 2026-11-09
- https://pushsecurity.com/help/how-does-push-browser-extension-work - Push help, fetched 2026-11-09
- https://pushsecurity.com/help/how-does-the-push-browser-extension-securely-track-reused-passwords/ - Push help (via search summary)
- https://www.nudgesecurity.com/post/ai-discovery-methods-compared - Nudge, 2026-08-19
- https://www.harmonic.security/solutions/browser-based-genai-security - Harmonic, fetched 2026-11-09
- https://www.akamai.com/products/akamai-workforce-protector - Akamai (former LayerX), fetched 2026-11-09
- https://www.crowdstrike.com/en-us/blog/crowdstrike-to-acquire-seraphic/ - CrowdStrike, 2026-01-13 (via search summary)
- https://zenity.io/platform - Zenity, fetched 2026-11-09
- https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn - Microsoft Learn, updated 2026-10-30
- https://learn.microsoft.com/en-us/deployedge/microsoft-edge-dlp-purview-configuration - Microsoft Learn, updated 2026-10-06
- https://learn.microsoft.com/en-us/deployedge/microsoft-edge-management-service-customizations - Microsoft Learn, updated 2026-10-06
- https://blogs.windows.com/msedgedev/2026/03/23/protect-your-enterprise-from-shadow-ai-and-more-announcements-at-rsac-2026/ - Edge blog, 2026-03-23
- https://mc.merill.net/message/RM571396 - Microsoft roadmap item (via search summary), updated 2026-09
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Microsoft Learn, updated 2026-10-23
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - BeyondTrust docs, updated 2026-10-13
- https://support.google.com/chrome/a/answer/14443058 - Chrome generative AI features and policies, 2026
- https://support.google.com/chrome/a/answer/16291696 - Gemini in Chrome admin help, 2026
- https://github.com/chromium/content_analysis_sdk - Content Analysis Connector SDK, pushed 2026-08-11
- https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest - Chrome API reference, fetched 2026-11-09
- https://developer.chrome.com/docs/extensions/reference/api/webRequest - Chrome API reference, fetched 2026-11-09
- https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions - Anthropic, updated about 2026-10
- https://support.claude.com/en/articles/12902446-claude-in-chrome-permissions-guide - Anthropic, updated 2026-11
- https://developers.cloudflare.com/cloudflare-one/traffic-policies/http-policies/tenant-control/index.md - Cloudflare, fetched 2026-11-09
- https://community.fortinet.com/fortigate-3/technical-tip-inline-casb-tenant-control-limitations-for-chatgpt-gemini-and-claude-on-fortios-8-0-0-230606 - Fortinet, 2026-10-16
- https://docs.arcjet.com/coding-agents/block-personal-accounts - Arcjet docs, 2026-09-29
- https://help.openai.com/en/articles/20001371-chatgpt-atlas-retirement - OpenAI (via search summary), 2026
- https://github.com/jay0lee/forced-headers-chrome-ext - Apache-2.0, pushed 2026-04-07
- https://github.com/opena2a-org/ai-browserguard and https://opena2a.org/aibrowserguard - Apache-2.0, pushed 2026-11-05

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. The shared web-search budget was already exhausted, so every check below is a direct fetch of a primary document, Chromium source (main branch), or Google's extension update endpoint. No search-engine results were used. OpenAI's help centre returned 403 to every fetch._

### Claims the architecture depends on

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | `anthropic-allowed-org-ids`: comma-separated org UUIDs, max 500 across 10 header lines, Enterprise and Console orgs, web/desktop/API-key/OAuth, 403 `tenant_restriction_violation` | Confirmed | Article text matches on every point. The 403 body has type `permission_error` with error_code `tenant_restriction_violation`. Claude Code is not named in the article. Claude Code routed through Bedrock, Vertex, Foundry or a gateway never reaches Anthropic hosts, so the header cannot apply there. | https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions ; https://code.claude.com/docs/en/network-config |
| 2 | DNR `modifyHeaders` can `set` arbitrary request headers (only `append` is allowlisted), with up to 30,000 dynamic rules | Corrected | `set` is unrestricted beyond header-name validity and `append` has a 21-header allowlist: both hold in source. The 30,000 figure is wrong for this use: it applies only to "safe" rules (`block`, `allow`, `allowAllRequests`, `upgradeScheme`). `modifyHeaders` rules are unsafe and capped at 5,000 dynamic plus 5,000 session. Static rulesets have a 30,000 guaranteed minimum with no unsafe cap. Host permissions for the target hosts are required. Not checked this run: force-installed extensions do not run in Incognito unless separately allowed. | https://github.com/chromium/chromium/blob/main/extensions/common/api/declarative_net_request.webidl ; https://github.com/chromium/chromium/blob/main/extensions/browser/api/declarative_net_request/indexed_rule.cc ; https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest |
| 3 | MV3: `webRequestBlocking` only for policy-installed extensions; request bodies yes, response bodies no; WebSocket frames after the handshake not observable | Confirmed | Docs state all three. Request bodies need the `requestBody` extraInfoSpec and cover POST and PUT only. The page documents no response-body access at all. Handshake interception since Chrome 58; individual messages and close are not intercepted. | https://developer.chrome.com/docs/extensions/reference/api/webRequest |
| 4 | `ChatGPT-Allowed-Workspace-Id` pins chatgpt.com logins to Enterprise workspace UUIDs, does not cover api.openai.com or logged-out use; block `chatgpt.com/backend-anon/` | Corrected | Header name, chatgpt.com scope and the api.openai.com gap are in the Arcjet doc. Arcjet says a workspace UUID needs ChatGPT Enterprise or Team, not Enterprise only. Arcjet does not mention logged-out use or `backend-anon`; that comes from a Fortinet community tip, so it is an undocumented path that may change. OpenAI's own article (20001323, "Corporate Network Controls in ChatGPT Enterprise") could not be read. Keep confidence at medium. | https://docs.arcjet.com/coding-agents/block-personal-accounts ; https://community.fortinet.com/fortigate-3/technical-tip-inline-casb-tenant-control-limitations-for-chatgpt-gemini-and-claude-on-fortios-8-0-0-230606 |
| 5 | Purview inline DLP for unmanaged AI apps: Edge for Business on Intune-managed Windows only, fixed list of 19 apps, 4 MB text and 3 MB file, cannot split consumer and enterprise ChatGPT on a shared URL | Confirmed | All figures match the page updated 2026-10-30. The 19 are catalog entries, about 17 distinct products (QwenAI and Qwen Chat, Textcortex and Textcortex Zenochat are listed separately). Requires Edge 144 or later. Claude is not on this list. | https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn |
| 6 | Microsoft auto-creates Intune and Edge policies that add a Microsoft-managed AI-site list to Chrome's URLBlocklist and block Firefox and other browsers | Confirmed, with scope limits | Auto-creation, the Microsoft-managed list and the Firefox block are all documented. Two limits: the browser restrictions apply to users in a DLP policy whose action is block, and Chrome "might be allowed depending on policy scope", so Chrome can be blocked outright too. The list currently has 37 apps and includes claude.ai. The docs name the `URLBlocklist` policy and an Intune policy that blocks "select apps in the Google Chrome browser"; they do not spell out the Chrome registry key. | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-dlp-purview-configuration ; https://learn.microsoft.com/en-us/deployedge/microsoft-edge-management-service-customizations |
| 7 | Gemini auto browse is off by default for managed users; governed by `GeminiActOnWebSettings`, `GeminiActOnWebAllowedForURLs`, `GeminiActOnWebBlockedForURLs`; Gemini in Chrome also needs `GeminiSettings` | Corrected | The help page does say "off by default for managed users" and names the three policies. The Chromium policy definition disagrees on the client default: `GeminiActOnWebSettings` 0 or unset means allowed, 1 means disallowed, default 0. "Off by default" is therefore server-side edition and rollout gating, not a policy default. To guarantee it is off, set the policy to 1 explicitly. A URL on both lists is allowed. Settings policy from Chrome 143, URL lists from 146. `GeminiSettings` unset follows `GenAiDefaultSettings`. | https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/GenerativeAI/GeminiActOnWebSettings.yaml ; https://support.google.com/chrome/a/answer/16291696 |
| 8 | Push separates personal from work accounts by login email domain against configured company domains; monitoring personal-domain logins is opt-in and Push advises employee consent | Confirmed | Setting is "Monitor all domains", described as opt-in. Push tells admins to get explicit employee consent first. With it on, Push logs email and login timestamp for work apps only, never passwords, and never personal logins to non-work apps. | https://pushsecurity.com/help/can-i-use-push-to-detect-personal-or-non-work-accounts |
| 9 | Sidekick is delivered as a Chrome extension; JSON-LD links store listing "Sidekick: Forward-Deployed" (ID `lbbkokkcdaonjenckieahjlnjhepalco`); no other mechanism documented | Confirmed | The `sameAs` entry is in the raw homepage HTML. Google's extension update endpoint returns status ok for that ID: version 0.0.531, CRX about 3.1 MB, so the extension is published even though the store page does not render to a non-JS fetch. The homepage and platform page text contain no mention of "extension" or "Chrome". The privacy policy mentions a mobile application. The CRX was not downloaded, so permissions remain unknown. | https://sidekicksecurity.ai/ (page source) ; `clients2.google.com/service/update2/crx` update check for the ID |
| 10 | An extension cannot block per-action input from CDP-driven agents; the categorical control is `RemoteDebuggingAllowed=false` | Confirmed, narrower than it reads | The project's `docs/enforcement-scope.md` says exactly this and adds that Chrome 136 and later already block remote debugging of the default profile. The Chromium policy covers only the `--remote-debugging-port` and `--remote-debugging-pipe` switches of the browser that reads the policy (desktop from Chrome 93). By its own description it does not cover extension-based agents using `chrome.debugger`, a separately installed or bundled browser, or OS-level input agents. | https://github.com/opena2a-org/ai-browserguard/blob/main/docs/enforcement-scope.md ; https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/Miscellaneous/RemoteDebuggingAllowed.yaml |

### Further statements checked in the brief

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Implication 5: emit `GenAiDefaultSettings` from our policy model alongside the other keys | Overstated | Chromium marks `GenAiDefaultSettings` as `cloud_only: true`, which the policy schema defines as settable only from the Admin console, with no support for platform management tools such as GPO. A local endpoint agent should set the per-feature policies (`GeminiSettings`, `GeminiActOnWebSettings` and the rest) instead. The defaults the brief quotes are right: 0 generally, 1 for Admin-console-managed enterprise users. | https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/GenerativeAI/GenAiDefaultSettings.yaml ; https://github.com/chromium/chromium/blob/main/components/policy/resources/new_policy_templates/policy.yaml |
| [K] Chromium hard-codes the permitted local Content Analysis providers, so a new agent cannot self-register | Confirmed | The provider map is a compile-time constant: `google`, `local_user_agent`, `local_system_agent`, `brcm_chrm_cas`, `trellix`. Trellix is pinned to signer subject names. `local_user_agent` is labelled "Test user agent", uses pipe name `path_user`, and has no signer check; it is usable for a prototype but carries a TODO to be replaced, so it is not a base to ship on. | https://github.com/chromium/chromium/blob/main/components/enterprise/connectors/core/service_provider_config.cc |
| Microsoft Agent 365: GA 2026-05-01, per-user licence, "works best" with E5, overview does not describe discovering unregistered local or browser agents | Confirmed | The overview (updated 2026-10-23) matches. It covers the registry, agent map, Entra, Purview and Defender, and says nothing about unregistered local or browser agents. The BeyondTrust summary in section 5 also matches its doc (updated 2026-10-13). | https://learn.microsoft.com/en-us/microsoft-agent-365/overview ; https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |

Not resolved: the ChatGPT Atlas retirement date (OpenAI help centre returned 403) and the Seraphic price (CrowdStrike's press release of 2026-01-13 states no figure; "$400M" is a media report).
