# Data control, secrets handling and information-flow control for agents

_Researched 2026-11-09_

Method note: the web-search budget for this run was already exhausted, so nothing here comes from a search engine. Everything marked "verified" was read today from a primary URL (vendor docs, specs, arXiv, GitHub API). Items marked "from memory" were not re-fetched and should be re-checked before they become load-bearing.

## TL;DR

- **No agent protects credential stores by default.** Claude Code's sandbox lets commands read the whole machine, including `~/.ssh` and `~/.aws/credentials`, and its docs say there is no built-in credential deny list. Native Windows is unsandboxed. This is the cheapest high-value gap for us to close.
- **Keeping secrets out of the model is now a documented pattern with a concrete shape:** the agent holds a per-session sentinel ("phantom token"), and a proxy outside the boundary swaps in the real value only for named hosts. Claude Code (`sandbox.credentials` with `mode: "mask"`, `injectHosts`), nono, Infisical Agent Vault and Fly's tokenizer all do this.
- **Hooks can redact, not only block.** Claude Code `PreToolUse` returns `updatedInput`; `PostToolUse` returns `updatedToolOutput`. `UserPromptSubmit` can block or add context but cannot rewrite the prompt. Cursor has `beforeReadFile`, `beforeSubmitPrompt`, `beforeMCPExecution` and a `failClosed` flag (hooks fail open by default).
- **Hostname allow-lists are weak on their own.** Anthropic's docs warn that allowing `github.com` creates an exfiltration path and that a proxy trusting the client-supplied hostname is open to domain fronting. Real egress control needs TLS termination or method/path rules on the allowed hosts.
- **Deterministic IFC works in the lab but nobody ships it.** CaMeL solves 77% of AgentDojo tasks with provable security against 84% undefended, at about 2.8x tokens. FIDES cuts successful injections from 163 to 1 on gpt-4o. The public code is a research repo and a notebook, both untouched since mid-2025.
- **The practical version is session taint plus sink gating.** Meta's Agents Rule of Two (2025-10-31) explicitly allows a session to change configuration mid-flight and names human approval as the fallback when all three properties are present.
- **Purview is callable.** Graph v1.0 `processContent` returns `restrictAccess`/`block` verdicts for a piece of text and a user, and sensitivity labels are plain key-value metadata (`MSIP_Label_<GUID>_Enabled`, `_SiteId`, `_Name`) readable without the MIP SDK on unencrypted Office files.
- **Tenant restriction for AI services exists and needs TLS inspection:** Anthropic `anthropic-allowed-org-ids`, Microsoft `Restrict-Access-To-Tenants`, Google `X-GoogApps-Allowed-Domains`. A local proxy can inject these without a corporate SWG.
- **Undo is file-only everywhere.** Claude Code checkpoints miss files changed only by Bash and most subagent edits. Gemini CLI uses a shadow git repo and is off by default. nono uses a SHA-256 content store with a Merkle root. Nothing reverses external side effects.
- **Competitors are thin on data.** BeyondTrust's AI Agent Security doc describes no secrets brokering or DLP. Microsoft Defender's endpoint agent runtime protection (preview, Windows only) targets prompt injection, not data.
- **Canarytokens now has an "MCP Configuration" token type** alongside AWS keys, kubeconfig and WireGuard. Honeytokens for agents are an accepted idea with no fleet-managed open implementation.

## Findings

### 1. Where data can be inspected and controlled

**In-agent hooks (verified, code.claude.com/docs/en/hooks, cursor.com/docs/agent/hooks).**
Claude Code events relevant to data: `UserPromptSubmit` (block, add context, no rewrite), `PreToolUse` (`allow`/`deny`/`ask`/`defer` plus `updatedInput`), `PostToolUse` (`updatedToolOutput` replaces what the model sees; the tool has already run), `ConfigChange` (can block except `policy_settings`), `InstructionsLoaded` (observe only), `FileChanged`, `Elicitation`. Handler types are `command`, `http`, `mcp_tool`, `prompt`, `agent`. `allowManagedHooksOnly` restricts hooks to managed settings.
Cursor events: `beforeSubmitPrompt`, `beforeReadFile`, `beforeTabFileRead`, `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` (with `updated_input`), `postToolUse` (can replace MCP tool output). Crashes and timeouts fail open unless `failClosed: true`. Enterprise hook files live at `/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json`.

**LLM gateway.** `ANTHROPIC_BASE_URL` gives a proxy plaintext prompts and responses with no TLS interception. `HTTPS_PROXY` gives only an opaque CONNECT tunnel unless the proxy terminates TLS (verified, code.claude.com/docs/en/agent-sdk/secure-deployment).

**Sandbox and egress proxy.** Claude Code's sandbox covers shell commands and children only. File tools, WebFetch, MCP servers, hooks and mods run outside it. On Linux commands get a network namespace with no route out; on macOS Seatbelt blocks everything except the local proxy. UDP, QUIC and ICMP cannot leave. Codex is off-network by default and uses Seatbelt, bwrap plus seccomp, and Microsoft MXC on Windows (`[features] prefer_mxc = true`) (verified, learn.chatgpt.com/docs/agent-approvals-security). GitHub's cloud agent firewall applies only to processes started by the Bash tool, not to MCP servers or setup steps (verified, docs.github.com).

**OS sensor.** BeyondTrust enforces "at the kernel and network level", distinguishes agent from human under the same credentials by process, and installs a root certificate to inspect HTTPS. Windows 11 x64 and macOS 14/15/26 only, no Linux (verified, docs.beyondtrust.com). Microsoft Purview Endpoint DLP already gates paste-to-browser, copy-to-clipboard, upload to restricted domains and access by restricted apps on Windows and macOS, but classifies only files saved to disk (verified, learn.microsoft.com/purview/endpoint-dlp-learn-about).

**Computer-use agents.** Claude Code states computer use runs on the real desktop with per-app prompts and no sandbox. MXC exposes a UI policy for clipboard, display and GUI access. Windows agent workspace (Insider preview) runs each agent under its own account in a separate session with access to six known folders (verified, support.microsoft.com).

**Git push and package publish.** No agent treats these as distinct sinks. They are reachable through any allow-listed `github.com` or registry host. nono's profile language is the closest: "`gh` can read issues and PRs, but can only post to `org/foo`" (verified, nono README).

### 2. Classification sources

- **Purview labels on local files (verified, MIP metadata doc, 2026-09-18).** Keys follow `MSIP_Label_<GUID>_<Attr>` with `Enabled`, `SiteId` (tenant), `Name`, `Method`, `SetDate`, `ContentBits` (0x8 means encrypted). One label per tenant per file. With co-authoring enabled the metadata moves to a LabelInfo stream defined in MS-OFFCRYPTO; readers must check both. Email carries a single `MSIP_Labels` header. Endpoint DLP cannot detect another tenant's label.
- **Purview verdict API (verified, Graph v1.0, doc 2026-04-22).** `POST /users/{id}/dataSecurityAndGovernance/processContent`, permissions `Content.Process.User` or `Content.Process.All`, activity types such as `uploadText`, response `policyActions` containing `restrictAccessAction` with `restrictionAction: "block"`. `protectionScopes/compute` plus ETag tells the caller when to refresh.
- **Agent 365 and Purview (verified, 2026-05-01 doc).** Agent 365 is GA since 2026-05-01, per-user licensed. Content created by agents does not inherit sensitivity labels from sources. DLP for agents covers Teams, SharePoint/OneDrive and email only, and "an agent instance is unaware of the block action".
- **Google Drive labels (partly verified).** Structured metadata on a Drive file read through the Drive API. Nothing indicates they are embedded in file bytes, so a synced local copy carries no label (inference).
- **Local detectors.** Kingfisher (Apache-2.0, Rust, embeddable, live validation), gitleaks (MIT, Go), TruffleHog (AGPL-3.0), Presidio (MIT). ProtectAI llm-guard was archived in 2026-07 (verified via GitHub API).
- **Path and repo rules** are what agents actually use today (Claude Code `denyRead`, Codex protected paths).

### 3. Secrets

**Known credential locations (verified, Anthropic secure-deployment table):** `.env*`, `~/.git-credentials`, `~/.aws/credentials`, `~/.config/gcloud/application_default_credentials.json`, `~/.azure/`, `~/.docker/config.json`, `~/.kube/config`, `.npmrc`, `.pypirc`, `*-service-account.json`, `*.pem`, `*.key`. Add `~/.ssh`, `~/.config/gh/hosts.yml`, browser cookie and login databases, OS keychains, and agents' own token files (`~/.claude/.credentials.json`, `~/.claude.json`).

**Masking and injection (verified, code.claude.com/docs/en/sandboxing).**
- `mode: "deny"` blocks file reads and unsets env vars before each command.
- `mode: "mask"` shows a per-session sentinel and the proxy substitutes the real value only for `injectHosts`. It requires experimental `network.tlsTerminate`. On macOS masked files are simply denied. It falls back to deny for directories, globs, files over 8 MiB and non-UTF-8 files.
- Masking both AWS key variables lets the proxy re-sign SigV4. Streaming uploads, presigned URLs and SigV4A cannot be re-signed.
- Mask entries are honoured only from user, managed or `--settings` scopes, never from a repository.

**nono (verified, nono.sh docs; Apache-2.0, Rust).** Two modes. Proxy mode points SDK base URLs at a local reverse proxy (`OPENAI_BASE_URL=http://127.0.0.1:<port>/openai`), so most routes need no TLS interception. The child gets a 256-bit `NONO_PROXY_TOKEN`; requests without it get 401. Sources include OS keyring, `op://`, `bw://`, `apple-password://`, `file://`, `cmd://`. Formats cover header, URL path, query, basic auth, OAuth2 client credentials and SigV4. Env mode leaks through `/proc/PID/environ`. Proxy mode is blocked by default on WSL2.

**Infisical Agent Vault (verified, repo README and docs).** A MITM forward proxy that replaces placeholders such as `__anthropic_api_key__`. The standalone open-source binary now carries a notice telling users to move to the Infisical platform version, with time-bound sessions and access bundles. `unmatched_host_policy=deny` makes it a strict egress filter.

**Just-in-time cloud credentials (verified, AWS docs, helper 1.8.6 dated 2026-11-04).** `aws_signing_helper credential-process` works through `credential_process`, with sessions from 900 s to 12 h. The private key can stay in a TPM, PKCS#11 token, Windows CNG or macOS Keychain. `serve` exposes an IMDSv2-compatible endpoint on 127.0.0.1:9911 that any local process can read; 1.8.6 added Host/Origin checks against DNS rebinding. `update` writes credentials to disk.

**MCP tokens (verified, MCP draft authorization spec and ext-auth repo).** Clients must send RFC 8707 `resource`; servers must validate audience and "MUST NOT accept or transit any other tokens". STDIO servers take credentials from the environment, which is where they leak. Enterprise-Managed Authorization (ID-JAG) and OAuth Client Credentials are Stable extensions at revision 2026-07-28. Dynamic Client Registration is deprecated in favour of Client ID Metadata Documents. AWS AgentCore Identity offers workload identities and credential providers as a managed service (landing page only verified).

**Env scrubbing.** Claude Code has `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`. nono has an env allow-list. Codex's `shell_environment_policy` could not be confirmed today.

**Honeytokens (verified, docs.canarytokens.org).** Types include AWS API keys, Azure login certificate, Entra ID login, kubeconfig, WireGuard, MySQL dump, credit card, sensitive command, Windows directory and MCP Configuration.

### 4. Information-flow control

- **CaMeL (verified, arXiv 2503.18813v2, 2025-06-24).** A privileged LLM sees only the trusted query and writes Python. A quarantined LLM with no tools parses untrusted data into a schema. A custom interpreter tracks provenance and allowed readers per value and runs policy functions before each tool call. A denied call becomes a user confirmation in a real deployment. Out of scope: text-to-text attacks. Travel suite utility was 25% on Claude 3.5 Sonnet.
- **FIDES (verified, arXiv 2505.23643v2, 2025-09-03).** Integrity is trusted or untrusted; confidentiality is a set of permitted readers. The context label is the join of everything in the conversation. Policy P-T allows a consequential tool call only from a trusted context; P-F allows data to flow only to permitted readers. `HIDE` stores more-restricted results in variables so the context is not tainted. A quarantined LLM with constrained output (bool, enum, string by capacity) inspects hidden values. Labels are assigned by developers through trusted tool wrappers. Policies cost up to 24.5% utility on o3 and o4-mini.
- **Rule of Two (verified, Meta, 2025-10-31).** [A] untrusted input, [B] sensitive systems or data, [C] state change or external communication. At most two per session without supervision.
- **Lethal trifecta (verified, Willison, 2025-06-16).** Same three legs. He calls a 95% catch rate from guardrail products a failing grade.
- **Shipping approximations.** Claude Code summarises web-search results before they enter context, a form of quarantine. Its auto mode refuses unlisted hosts unless a classifier approves. FIDES's capacity lattice justifies letting a tainted sub-session return only a bool or enum to an untainted parent (inference).

### 5. Exfiltration channels and egress control

Verified points: the Claude Code proxy decides on the client-supplied hostname and does not inspect TLS by default; UDP and QUIC are blocked inside the sandbox; hostnames resolving to loopback or link-local (including 169.254.169.254) are refused; tools ignoring proxy variables fail. Node `fetch()` ignores proxy variables unless `NODE_USE_ENV_PROXY=1` (Node 24+). EchoLeak (CVE-2025-32711, arXiv 2509.10540) chained a classifier bypass, reference-style Markdown links, auto-fetched images and an allow-listed Teams proxy.

Design consequence (inference): with an explicit proxy the client names the host in CONNECT, so ECH hides nothing from us. ECH and encrypted DNS only hurt passive sensors watching unsandboxed processes. The channel table is in the Matrix section.

### 6. Provider posture

- **Anthropic (verified, support.claude.com).** `anthropic-allowed-org-ids`: comma-separated org UUIDs, up to 10 header lines and 500 UUIDs, injected on claude.ai, api.anthropic.com, claude.com, anthropic.com. Other orgs get 403. Covers web, desktop, API-key and OAuth authentication. Enterprise plans and Console organisations. The proxy must overwrite the header.
- **Microsoft (verified).** `Restrict-Access-To-Tenants` and `Restrict-Access-Context` on login.microsoftonline.com, login.microsoft.com, login.windows.net; `sec-Restrict-Tenant-Access-Policy: restrict-msa` on login.live.com. Needs Entra ID P1/P2.
- **Google (verified).** `X-GoogApps-Allowed-Domains` on `*.google.com`; omit `consumer_accounts` to block Gmail accounts.
- **OpenAI.** A workspace-restriction header exists (from memory); not verified today.

### 7. Undo and integrity

- **Claude Code checkpoints (verified).** Snapshot before each prompt, 100 checkpoints kept, about 30 days retention. Files changed only by Bash are not tracked. Most subagent edits are not restored. Symlinks and hard links are skipped.
- **Gemini CLI (verified, repo doc).** Shadow git repo at `~/.gemini/history/<project_hash>`, off by default.
- **nono (verified).** Baseline and final snapshots, SHA-256 content store, APFS clones, Merkle root, atomic rename on restore, default 10 sessions and 5 GB.
- **AgentFS (verified README; beta; no SPDX licence detected).** SQLite-backed filesystem over FUSE on Linux and NFS on macOS; snapshot is a file copy.
- **Files that control agents (verified).** Claude Code write-protects `.claude/settings*`, `.claude/{skills,agents,commands,hooks}`, `.mcp.json`, `.bashrc`, `.zshrc`, `.gitconfig`, `.vscode`, `.idea`, `.git/hooks`, `.git/config`, `~/.claude`, `~/.claude.json`. Codex keeps `.git`, `.codex`, `.agents`, `.aws` read-only. nono verifies skills, hooks and instruction files with Sigstore.

## Matrix

### Control points

| Control point | Sees | Can do | Main bypass |
|---|---|---|---|
| Prompt hook | User prompt | Block, add context | Cannot rewrite in Claude Code |
| Pre-tool hook | Tool name and arguments | Deny, ask, rewrite input | Hooks disabled; fail-open in Cursor |
| Post-tool hook | Tool output | Replace output before the model reads it | Side effect already happened |
| LLM gateway (base URL) | Full prompts and responses | Redact, route, block | Agent pointed at another endpoint |
| MCP gateway | MCP tool I/O | Redact, deny, vault tokens | Local STDIO servers |
| Egress proxy | Host; with TLS termination, method, path, body | Allow-list, inject credentials, add tenant headers | Tools that ignore proxy outside a sandbox |
| OS sandbox | File and network syscalls of children | Deny read/write, no route out | Unsandboxed tools, native Windows |
| OS sensor | Process, file, DNS, connect events | Attribute, alert, kill | ECH and DoH hide destinations |

### Exfiltration channels

| Channel | Mitigation |
|---|---|
| DNS queries | Sandbox has no resolver; proxy resolves. Outside a sandbox, attribute DNS per process and alert on high-entropy labels |
| DoH, DoT, ECH | Explicit proxy makes them moot; block 853 and known DoH hosts; enterprise browser policy (from memory) |
| QUIC / UDP 443 | Drop UDP from agent processes |
| Rendered images and link previews | Strip or proxy remote images in agent UIs; CSP; no auto-fetch of model-authored URLs |
| Allow-listed APIs (gists, issues, S3 PUT, upload endpoints) | Method and path rules, destination org or repo pinning, credential bound to host and scope |
| Domain fronting | Terminate TLS and require Host to equal SNI to equal CONNECT host |
| Tunnels, paste sites, webhooks | Deny categories by default, even in permissive mode |
| git push | Remote allow-list, credential helper as choke point, pre-push secret scan |
| Package publish | Publish tokens exist only in the broker; `publish` is a gated sink |
| Clipboard, screenshots | UI policy per session; sensor events |
| Model provider itself | Tenant headers, account posture, classification-based routing |

## Weak points, gaps and risks

- Session-level taint creeps. Once a session reads one web page everything is untrusted, and approval prompts become noise. Meta itself notes users blindly confirm.
- TLS termination is required for masking, tenant headers and body inspection. It breaks certificate-pinned tools and Go binaries on macOS, and makes us a root CA on the endpoint.
- Masking breaks on streaming SigV4, presigned URLs, non-HTTP protocols (SSH, database drivers) and macOS file masks.
- Hooks are bypassable by design unless managed-only settings are enforced, and each agent has different semantics.
- Classification by label is sparse in developer environments. Source code, `.env` and database dumps carry no Purview label.
- Rollback never covers network side effects, databases or remote git.
- Reusing code: TruffleHog is AGPL-3.0; Canarytokens and Agent Vault report non-standard licences; AgentFS reports none.
- Local credential endpoints are a new attack surface (see the `serve` DNS-rebinding fix).

## Implications for our design

**Architecture.** One policy decision point per host, many enforcement points. Each agent session gets an ID, a label set, an egress profile and a credential scope. Enforcement points report reads (sources) and request sinks; the decision point owns the labels.

**Policy primitives.**
1. `source` rules that add labels: path glob, repo or remote, MIP label GUID or name, Drive label, detector hit (secret, PII, exact-match fingerprint), tool name, URL origin.
2. Labels on two axes: integrity (`trusted`, `untrusted:<origin>`) and confidentiality (`public`, `internal`, `class:<name>`, `secret`).
3. `sink` classes: `net:<host,method,path>`, `git.push:<remote>`, `pkg.publish:<registry>`, `message.send`, `mcp:<server.tool>`, `clipboard.write`, `file.write:<outside workspace>`, `llm:<provider,tenant,region>`.
4. Flow rules: `deny|ask|allow sink when labels match`, with the Rule of Two as a built-in default.
5. `declassify`: a human approval bound to session, sink, payload hash and expiry, recorded in the audit log.
6. `transform`: redact, tokenise with reversible placeholders, truncate.
7. `quarantine`: run a read in a sub-session with no sinks that returns only a typed, low-capacity result.
8. Egress profile per session: allowed hosts with method and path rules, deny categories, header injection.
9. Credential grants: which helper or route, which scope, which TTL, for which process lineage.
10. Protected paths: deny-read, deny-write, monitor, with a shipped default list.
11. `canary`: plant and watch.
12. `checkpoint`: when to snapshot and thresholds for mass change.

**Secrets broker.**
- A Rust daemon outside every agent boundary. Stores in OS keychain or DPAPI, with adapters for 1Password, Vault, Infisical and cloud STS.
- Route injection first: base-URL reverse-proxy routes for LLM providers and common APIs, no TLS interception. TLS-terminating mode per host is opt-in.
- Phantom tokens per session, bound to host, method and path. A request carrying a session's phantom token is proof the agent made it, which solves agent-versus-human attribution on shared credentials.
- Helper protocol endpoints so tools need no change: AWS `credential_process`, git credential helper, SSH agent (sign-only, per-key and per-host approval), Docker credential helper, kubectl exec plugin, gcloud executable-sourced credentials. Each call is checked against the caller's process lineage and session grant.
- Mint short-lived credentials where possible (Roles Anywhere with TPM or keychain-held keys, 15-minute sessions; OIDC federation).
- MCP: the broker is the OAuth client, stores refresh tokens, sends audience-bound access tokens, supports ID-JAG.
- Launcher builds the agent's environment from an allow-list and replaces known credential variables with phantoms.
- No unauthenticated localhost credential endpoints. Use Unix sockets or named pipes with peer-credential checks.

**Build order.**
1. Protected-path defaults (deny-read credential stores, write-protect agent control files), env scrubbing, and integrity monitoring of control files. Ship as managed settings for Claude Code, Codex and Cursor plus sensor detections.
2. Runtime secret detection and redaction in pre/post-tool hooks and the LLM gateway, using Kingfisher in-process.
3. Session labels and sink gating with approval-based declassification.
4. Per-session egress proxy with method and path rules, UDP drop and DNS handling. Reuse sandbox-runtime (Apache-2.0), nono (Apache-2.0) and MXC (MIT, Rust crate, Windows backends).
5. Secrets broker with phantom tokens and helper protocols.
6. Honeytokens: decoy AWS profile, `.env`, kubeconfig and MCP config per endpoint, alert on read by an agent lineage and on use.
7. Checkpoints (content-addressed store with APFS, btrfs or ReFS clones) and mass-delete or overwrite detection.
8. Classification connectors: MSIP metadata reader, Purview `processContent`, Drive labels.
9. Provider posture: tenant headers, account-type detection, routing by classification.
10. A deterministic IFC planner as an SDK mode for in-house agents.

Avoid: embedding AGPL code; relying on hostname-only allow-lists; a prompt-injection classifier as the main control; depending on the standalone Agent Vault binary.

## Ideas worth stealing and whitespace

- Policy replay against recorded sessions before enforcing (BeyondTrust).
- Audit then block rollout modes with a benign test string (Microsoft Defender).
- Sigstore attestation of skills, hooks and rules files (nono).
- Capacity-typed quarantine results (FIDES).
- Trust scoping: credential and TLS settings ignored when they come from a repository (Claude Code).
- Whitespace: fleet-managed honeytokens for agents; label inheritance for agent-created content (Microsoft states it does not happen); git push and package publish as first-class sinks; a broker that speaks every helper protocol; phantom tokens as attribution; tenant-header injection without a SWG; cross-agent rollback that includes Bash and subagent changes; a Windows-native story (Claude Code has none, BeyondTrust excludes Arm).

## Could not verify / open questions

- OpenAI's workspace-restriction header name and scope; Codex `shell_environment_policy` details.
- Chrome and Edge enterprise policies for ECH, DoH and QUIC (from memory only).
- Docker Sandboxes credential handling; the overview page had no detail.
- Whether Drive for desktop exposes label or file-ID metadata locally.
- Exact LabelInfo part path and how labels appear in PDFs and encrypted containers.
- AgentCore Identity token-vault semantics (does agent code see raw tokens).
- APFS, VSS, btrfs and ZFS snapshot mechanics were not re-read today; unprivileged per-session snapshots on Windows are an open design question.
- Latency of `processContent` in a tool-call hot path.
- Real-world false-positive rates for session-taint gating on coding agents.

## Sources

- https://arxiv.org/abs/2503.18813 and https://arxiv.org/html/2503.18813v2 — Defeating Prompt Injections by Design (CaMeL), v2 2025-06-24
- https://arxiv.org/abs/2505.23643 and https://arxiv.org/html/2505.23643v2 — Securing AI Agents with Information-Flow Control (FIDES), v2 2025-09-03
- https://github.com/microsoft/fides — tutorial notebook, last push 2025-05-30
- https://github.com/google-research/camel-prompt-injection — last push 2025-06-20
- https://ai.meta.com/blog/practical-ai-agent-security/ — Agents Rule of Two, 2025-10-31
- https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ — The lethal trifecta, 2025-06-16
- https://arxiv.org/abs/2509.10540 — EchoLeak, 2025-09-06
- https://code.claude.com/docs/en/sandboxing — Claude Code sandboxing, read 2026-11-09
- https://code.claude.com/docs/en/agent-sdk/secure-deployment — Securely deploying AI agents, read 2026-11-09
- https://code.claude.com/docs/en/hooks — Hooks reference, read 2026-11-09
- https://code.claude.com/docs/en/checkpointing — Checkpointing, read 2026-11-09
- https://learn.chatgpt.com/docs/agent-approvals-security — Codex agent approvals and security, read 2026-11-09
- https://cursor.com/docs/agent/hooks — Cursor hooks, read 2026-11-09
- https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall — Copilot agent firewall
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — BeyondTrust AI Agent Security
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Agent 365 overview, updated 2026-10-23
- https://learn.microsoft.com/en-us/purview/ai-agent-365 — Purview for Agent 365, 2026-05-01
- https://learn.microsoft.com/en-us/information-protection/develop/concept-mip-metadata — MIP label metadata, 2026-09-18
- https://learn.microsoft.com/en-us/graph/api/userdatasecurityandgovernance-processcontent — Graph processContent, 2026-04-22
- https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about — Endpoint DLP, 2026-08-05
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection — Defender AI agent runtime protection (preview), 2026-09-25
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai — Defender security for AI agents, 2026-10-30
- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tenant-restrictions — Entra tenant restrictions
- https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions — Anthropic tenant restrictions
- https://knowledge.workspace.google.com/admin/security/block-access-to-consumer-accounts — Google consumer account blocking
- https://developers.google.com/workspace/drive/api/guides/about-labels — Drive labels
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html — IAM Roles Anywhere credential helper, 1.8.6 on 2026-11-04
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html — AgentCore Identity
- https://modelcontextprotocol.io/specification/draft/basic/authorization — MCP authorization (draft)
- https://github.com/modelcontextprotocol/ext-auth — MCP authorization extensions, revision 2026-07-28
- https://nono.sh/docs/cli/features/credential-injection and https://nono.sh/docs/cli/features/atomic-rollbacks — nono docs; https://github.com/nolabs-ai/nono
- https://github.com/Infisical/agent-vault and https://infisical.com/docs/documentation/platform/agent-vault/overview — Agent Vault
- https://github.com/anthropics/sandbox-runtime, https://github.com/microsoft/mxc, https://github.com/superfly/tokenizer, https://github.com/tursodatabase/agentfs, https://github.com/mongodb/kingfisher, https://github.com/gitleaks/gitleaks, https://github.com/trufflesecurity/trufflehog — repository metadata read 2026-11-09
- https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md — Gemini CLI checkpointing
- https://docs.canarytokens.org/guide/ — Canarytokens guide
- https://support.microsoft.com/en-us/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3 — Windows agent workspace

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: primary docs re-read in full (including the sections past the first 100k characters), plus sources the brief did not cite: the Claude Code CHANGELOG, the `anthropics/sandbox-runtime` README, Microsoft Graph docs source, paper HTML, Node.js docs source and the GitHub API. Web search was unavailable (budget exhausted), so nothing below comes from a search engine._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude Code sandbox reads the whole machine by default incl. `~/.ssh` and `~/.aws/credentials`, no built-in credential deny list, covers only shell commands and children, unsandboxed on native Windows | Confirmed | Docs: "read access to the entire computer, except certain denied directories"; "There is no built-in credential deny list"; scope is Bash, PowerShell and Monitor commands and their children; "On native Windows, Claude Code runs commands unsandboxed". Caveat for design: the underlying `anthropics/sandbox-runtime` library has had an alpha Windows backend since 2026-05 (`srt-win`: dedicated `srt-sandbox` user, WFP egress fence, write-restricted token; optional `mxc` backend). Claude Code does not use it on native Windows yet. | https://code.claude.com/docs/en/sandboxing ; https://github.com/anthropics/sandbox-runtime (README "Windows (alpha)") |
| 2 | PreToolUse can rewrite input (`updatedInput`), PostToolUse can replace output (`updatedToolOutput`), UserPromptSubmit can block or add context but not rewrite | Confirmed | Hooks reference: `updatedToolOutput` "works for all tools" (value must match the tool's output shape); `updatedMCPToolOutput` is the older MCP-only field. "UserPromptSubmit: can't replace the prompt; it only injects additionalContext". CHANGELOG: "PostToolUse hooks can now replace tool output for all tools ... (previously MCP-only)". Telemetry (OTel spans) still records the original output. Confidence can be raised to high. | https://code.claude.com/docs/en/hooks ; https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md |
| 3 | Credential masking: per-session sentinel, proxy substitutes real value only for `injectHosts`, needs experimental `network.tlsTerminate`, deny on macOS files, ignored from repository settings | Confirmed | One precision: a `mask` entry with no `injectHosts` is substituted on every host in `network.allowedDomains`, so `injectHosts` must be set to get host binding. Also: default `onExtractNoMatch: warn` skips the entry and leaves the real file readable. CHANGELOG independently confirms Linux/WSL-only file masking and the scope restriction. | https://code.claude.com/docs/en/sandboxing ; https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md |
| 4 | Docs state the proxy trusts the client-supplied hostname without TLS inspection, so domain fronting is possible and broad domains such as `github.com` create exfiltration paths | Confirmed | Verbatim in the "Security limitations" warning. Docs add that `tlsTerminate` "does not add content filtering", and recommend a custom TLS-terminating proxy for stronger guarantees. | https://code.claude.com/docs/en/sandboxing#security-limitations |
| 5 | CaMeL 77% vs 84% undefended at ~2.8x tokens; FIDES 163 to 1 on gpt-4o; both public repos untouched since mid-2025 | Confirmed (numbers); the conclusion drawn from it is wrong, see A | CaMeL v2 abstract: 77% vs 84%; body: 2.82x input and 2.73x output tokens for the median task. FIDES Table 1 (gpt-4o, 949 attacks): Basic 163, FIDES without policy checks 24, FIDES with policy checks 1. GitHub API: `google-research/camel-prompt-injection` last push 2025-06-20, `microsoft/fides` last push 2025-05-30. | https://arxiv.org/html/2503.18813v2 ; https://arxiv.org/html/2505.23643v2 ; GitHub API |
| 6 | Graph v1.0 `processContent` (`POST /users/{id}/dataSecurityAndGovernance/processContent`, `Content.Process.User`/`.All`) returns `policyActions` such as `restrictAccess` with `restrictionAction: block` | Confirmed | Also `POST /me/...`. `restrictionAction` enum is `warn`, `audit`, `block`. The call may return 202 or 204 with no body, so callers need a default. Not available in the China (21Vianet) cloud; personal Microsoft accounts not supported. | https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/userdatasecurityandgovernance-processcontent.md |
| 7 | Purview label metadata keys `MSIP_Label_<GUID>_Enabled/_SiteId/_Name/_Method/_SetDate/_ContentBits`, LabelInfo stream with co-authoring, `MSIP_Labels` email header | Confirmed | Only `Enabled` and `SiteId` are mandatory; `ActionId` was removed in MIP SDK 1.8+. LabelInfo applies to Word, Excel and PowerPoint; the SDK falls back to the legacy location when LabelInfo is absent, so a reader must check both. | https://learn.microsoft.com/en-us/information-protection/develop/concept-mip-metadata |
| 8 | Anthropic tenant restriction: `anthropic-allowed-org-ids` injected by a TLS-inspecting proxy on claude.ai, api.anthropic.com, claude.com, anthropic.com; others get 403 | Confirmed | 403 `permission_error` with code `tenant_restriction_violation`. Personal accounts are blocked because they are not on the allow-list (article: "Block personal account usage from corporate networks"). Proxy must overwrite, not append. Article does not mention Bedrock, Vertex or mobile. | https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions |
| 9 | Checkpoints track only file-editing-tool changes; Bash-only files and most subagent edits not restored; symlinks and hard links skipped | Confirmed | Two precisions: once a file has been edited by a file tool, later Bash changes to that same file are rewound; edits by a foreground forked skill are restored. CHANGELOG confirms the symlink/hard-link skip. | https://code.claude.com/docs/en/checkpointing ; https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md |
| 10 | Standalone Infisical Agent Vault repo tells users to use the Infisical platform version, so it is not a safe dependency | Confirmed (fact); the risk is strategic, not abandonment | README banner (commits of 2026-10-27 and 2026-11-03): "Use Agent Vault in Infisical instead of this repository ... no longer the recommended way to run Agent Vault for any use case". The repo is not archived and is still maintained: v0.40.2 released 2026-10-22, dependency update 2026-11-07. Licence is MIT Expat with an `ee/` carve-out (no `ee/` directory at the root today); GitHub reports NOASSERTION only because of the preamble, so "non-standard licence" in the brief overstates it. Forking or borrowing code is legally fine; depending on upstream direction is not. | https://github.com/Infisical/agent-vault (README, LICENSE, releases) |

### Further statements checked

| # | Statement in the brief | Verdict | Note | Source |
|---|---|---|---|---|
| A | "Deterministic IFC works in the lab but nobody ships it ... The public code is a research repo and a notebook" (TL;DR) | Refuted | Microsoft Agent Framework (MIT) ships a FIDES implementation in `agent-framework-core` (Python, `agent_framework/security.py`: `IntegrityLabel`, `ConfidentialityLabel`, `ContentVariableStore`, `SecureAgentConfig`, `SecureMCPToolProxy`). Merged 2026-05-05, MCP auto-labelling added 2026-06-29, per-session state isolation 2026-09-08. Status: listed under "Experimental features"; ADR 0024 still "proposed"; not supported with CodeAct providers. This is a maintained reference for build-order item 10 and for label semantics. | https://github.com/microsoft/agent-framework/blob/main/python/PACKAGE_STATUS.md ; https://github.com/microsoft/agent-framework/blob/main/python/samples/02-agents/security/FIDES_DEVELOPER_GUIDE.md |
| B | "Node `fetch()` ignores proxy variables unless `NODE_USE_ENV_PROXY=1` (Node 24+)" | Corrected | `NODE_USE_ENV_PROXY` was added in v24.0.0 and backported to v22.21.0; still "Stability 1.1 - Active development". Also available as `--use-env-proxy`. | https://github.com/nodejs/node/blob/main/doc/api/cli.md |
| C | BeyondTrust AI Agent Security runs on "Windows 11 x64 and macOS 14/15/26 only, no Linux" | Corrected | Doc (updated 2026-10-13): "Windows 11, or Windows Server 2022 or later, on x64 hardware. Windows on Arm is not supported"; macOS 14, 15, 26; "supports Windows and macOS endpoints only". It also acts on tool calls through hooks for coding tools that support them, not only at kernel and network level. No secrets brokering or DLP described, as the brief says. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |

Also spot-checked and consistent with the brief: Agent 365 GA on 2026-05-01, per-user licensed (learn.microsoft.com/microsoft-agent-365/overview); `protectai/llm-guard` archived, last push 2026-07-08; Kingfisher Apache-2.0 Rust; `microsoft/mxc` MIT Rust; `anthropics/sandbox-runtime` Apache-2.0; AgentFS has no detected licence.

Correction to carry into the plan: the whitespace item "a Windows-native story (Claude Code has none ...)" holds for Claude Code itself, but `sandbox-runtime` already has an alpha Windows backend, so a Windows egress and filesystem sandbox is something to reuse and harden rather than invent.
