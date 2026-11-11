# Coding agents and AI IDEs: hooks, managed settings, sandboxes, telemetry, on-disk layout

_Researched 2026-11-09_

Legend used throughout: **[V]** verified this session against the vendor's own docs or source; **[S]** secondary source only (blog, news, search summary); **[P]** prior knowledge, not re-verified in November 2026 and possibly stale.

## TL;DR

- **A de facto hook dialect exists: Claude Code's.** JSON on stdin, `hook_event_name`, `tool_name`, `tool_input`, exit code 2 = block, `hookSpecificOutput.permissionDecision`. Codex, Copilot CLI, VS Code, Factory Droid, Devin Local, Auggie, OpenHands and goose all copy it with small deviations, and Copilot CLI, VS Code and Devin read `.claude/settings.json` hooks directly. One "Claude-dialect" hook binary plus thin per-agent translators covers most of the market. [V]
- **Every hook system fails open by default.** A crashed or timed-out pre-tool hook lets the tool run in Claude Code, Codex, Cursor, Gemini CLI, Auggie, OpenHands, goose and Cline. Opt-in fail-closed exists only in Claude Code (`"onFailure": "block"`, v2.1.295+), Cursor (`failClosed: true`), goose (`on_failure: block`) and Cline (`hookErrorMode: "throw"`). Copilot CLI command hooks fail closed on crash but fail open on timeout. [V]
- **Only six products have a real admin tier for hooks** (machine-scope files a user cannot override): Claude Code, Codex, Cursor, Copilot, Factory Droid, Auggie. Antigravity, Devin Local, Kiro, goose, OpenHands, opencode plugins and Cline are user or project scope only, so a hook there is advisory and needs an OS sensor behind it. [V]
- **Managed settings converge on one shape**: a JSON/TOML file in a system directory, an HKLM policy key, a macOS managed-preferences domain, and a server-delivered copy. Claude Code, Copilot, Codex, opencode and Amp all document this. [V]
- **Windows `C:\ProgramData` is a known weak spot.** Claude Code moved to `C:\Program Files\ClaudeCode\` and explicitly no longer reads the ProgramData path [V]; a 2026 CVE (reported as CVE-2026-35603) covers insecure machine-wide config paths across several agents [S]. Cursor hooks, Copilot `policy.d`, Gemini CLI, Codex, Auggie and Amp still document ProgramData locations. [V]
- **Sandboxes do not cover hooks, MCP servers or built-in file tools.** Claude Code states that Read/Edit/Write, hooks, local MCP servers and LSP servers run outside the sandbox, and native Windows has no sandbox at all. [V]
- **Native OpenTelemetry is real in Claude Code and Codex** (events for prompts, tool decisions, tool results, API requests), configurable from the managed tier and lockable in Claude Code. Gemini CLI has it too. Elsewhere it is thin or undocumented. [V]
- **Transcripts are plaintext JSONL on disk** for Claude Code (`~/.claude/projects/<project>/<session>.jsonl`) and Copilot CLI (`~/.copilot/session-state/<id>/events.jsonl`), and hooks hand you `transcript_path`. They contain secrets that tools read. [V]
- **The landscape moved in 2026**: Gemini CLI was replaced by Antigravity CLI (`agy`) on 2026-06-18; Windsurf docs now redirect to "Devin Desktop / Devin Local"; Codex docs moved to `learn.chatgpt.com`; Cline hooks moved into an SDK plugin API; goose moved to `aaif-goose/goose`; opencode to `anomalyco/opencode`. [V]
- **Hooks are not standardised.** The Agent Plugins Specification v1.0.0 covers only skills and MCP servers and explicitly leaves hooks out. [V]
- **Competitors already combine hooks with kernel and network sensors** (BeyondTrust Pathfinder, Windows and macOS only). Nobody ships this open source or on Linux. [V]

## Findings

### 1. Hook events, payloads, decisions, failure behaviour

**Claude Code** (docs, code.claude.com/docs/en/hooks, read 2026-11-09) [V]
- 33 events: `SessionStart`, `Setup`, `UserPromptSubmit`, `UserPromptExpansion`, `PreToolUse`, `PermissionRequest`, `PermissionDenied`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `Notification`, `MessageDisplay`, `SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`, `StopFailure`, `TeammateIdle`, `InstructionsLoaded`, `ConfigChange`, `CwdChanged`, `DirectoryAdded`, `FileChanged`, `WorktreeCreate`, `WorktreeRemove`, `PreCompact`, `PostCompact`, `PreModelSwitch`, `PostModelSwitch`, `Elicitation`, `ElicitationResult`, `SessionEnd`.
- Common fields: `session_id`, `prompt_id` (equals OTel `prompt.id`), `transcript_path`, `cwd`, `scratchpad_dir`, `permission_mode` (`default|plan|acceptEdits|auto|dontAsk|bypassPermissions`), `effort`, `hook_event_name`, `agent_id`, `agent_type`. Tool events add `tool_name`, `tool_input`, `tool_use_id`.
- Handler types: `command` (exec form with `args`, or shell), `http` (POSTs the JSON; `headers`, `allowedEnvVars`), `mcp_tool`, `prompt`, `agent`.
- Decisions on `PreToolUse`: `permissionDecision` = `allow|deny|ask|defer`, `updatedInput`, `additionalContext`, `continue:false`. Exit 2 blocks and cannot be overridden by JSON.
- Timeouts: 600 s for command/http/mcp_tool; 30 s on `UserPromptSubmit`; 30 s prompt; 60 s agent; `SessionEnd` shares 1.5 s.
- Failure: fail-open unless `"onFailure": "block"` (v2.1.295+, command and http only).
- `ConfigChange` fires on settings-file edits and can block them: a built-in tamper signal.

**OpenAI Codex** (learn.chatgpt.com/docs/hooks) [V]
- Hooks are on by default (`[features] hooks`). Events: `SessionStart`, `SessionEnd`, `SubagentStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreModelRequest`, `PostModelRequest`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `SubagentStop`, `Stop`, `Interrupt`.
- Fields: `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`, `turn_id`, `permission_mode`.
- Covers Bash, `apply_patch` (matchable as `Edit`/`Write`), MCP tools (`mcp__server__tool`). Hosted tools such as web search are not covered.
- `PreToolUse`: `deny`, or `allow` + `updatedInput`. `ask` is not supported. Default timeout 600 s. Docs call tool hooks "a useful guardrail, not a complete enforcement boundary."
- Non-managed hooks need per-hash trust review; `--dangerously-bypass-hook-trust` skips it.

**Cursor** (cursor.com/docs/agent/hooks) [V]
- Events: `sessionStart`, `sessionEnd`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `subagentStart`, `subagentStop`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `beforeReadFile`, `afterFileEdit`, `beforeSubmitPrompt`, `preCompact`, `stop`, `afterAgentResponse`, `afterAgentThought`, `beforeTabFileRead`, `afterTabFileEdit`, `workspaceOpen`.
- Fields: `conversation_id`, `generation_id`, `model`, `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`, `transcript_path`.
- Output: `permission` `allow|deny|ask`, `user_message`, `agent_message`, `updated_input`, `additional_context`, `updated_mcp_tool_output`. `deny` beats `ask` beats `allow` across sources. `failClosed` per hook.
- Cloud agents run a subset (no `sessionStart`, no MCP hooks) and ignore user-level hooks.

**GitHub Copilot** (docs.github.com hooks-configuration; VS Code hooks page, Preview) [V]
- Events: `sessionStart`, `sessionEnd`, `userPromptSubmitted`, `userPromptTransformed`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `agentStop`, `subagentStart`, `subagentStop`, `errorOccurred`, `preCompact`, `permissionRequest`, `notification`. PascalCase aliases accepted.
- Fields: `sessionId`, `timestamp`, `cwd`, `toolName`, `toolArgs`, `toolResult` (snake_case in the VS Code format).
- `preToolUse` output: `permissionDecision` `allow|deny|ask`, `permissionDecisionReason`, `modifiedArgs`. In the cloud agent `ask` becomes `deny`.
- Handlers: command (`bash`, `powershell`, `exec`+`args`), `http`, `prompt`. Default `timeoutSec` 30.

**Antigravity (app, IDE, `agy` CLI)** (antigravity.google/docs/hooks) [V]
- Events: `SessionStart`, `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`. camelCase fields: `conversationId`, `workspacePaths`, `transcriptPath`, `artifactDirectoryPath`, `modelName`, `toolCall{name,args}`, `stepIdx`.
- `PreToolUse.decision`: `allow|auto_approve|deny|ask|force_ask|deny_unless_prior_grant`; `overwrite` merges into args. Timeout 30 s. Failure behaviour undocumented.

**Gemini CLI** (legacy) [V]: `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `BeforeTool`, `AfterTool`, `PreCompress`, `Notification`. Uniquely lets a hook rewrite the LLM request or return a synthetic response. Timeout 60 000 ms.

**Others** [V unless marked]
- **Factory Droid**: Claude dialect, nine events, `permissionDecision allow|deny|ask`, `updatedInput`, 60 s timeout, `allowManagedHooksOnly`.
- **Devin Local / Devin CLI** (ex-Windsurf): `PreToolUse`, `PostToolUse`, `PermissionRequest`, `UserPromptSubmit`, `Stop`, `PostCompaction`, `SessionStart`, `SessionEnd`; `decision: approve|block`; `updatedInput`; payload lacks `cwd` and transcript path.
- **Auggie**: `PreToolUse`, `PostToolUse`, `Stop`, `SessionStart`, `SessionEnd`, `PromptSubmit`, `Notification`; only `deny` supported; `updatedInput`; 60 s.
- **Kiro (IDE and CLI V3)**: Prompt Submit, Agent Stop, Session Start/End, Pre/Post Compaction, Pre/Post Tool Use, File Create/Save/Delete, Pre/Post Task Execution; stdin `hook_event_name`, `cwd`, `session_id`, `tool_name`, `tool_input`; MCP tool ids are `mcp_<server>_<tool>`; 60 s.
- **goose**: `SessionStart`, `SessionEnd`, `Stop`, `UserPromptSubmit`, `PreToolUse`, `PreToolUseResult`, `PostToolUse`, `PostToolUseFailure`, `BeforeReadFile`, `AfterFileEdit`, `BeforeShellExecution`, `AfterShellExecution`; only `PreToolUse` and `Stop` block; 30 s; no input rewrite.
- **OpenHands**: `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SessionStart`, `SessionEnd`; exit 2 blocks; fail-open.
- **opencode** (and forks): in-process JS plugin; `tool.execute.before` can throw to block or mutate `output.args`; also `permission.asked`, `permission.replied`, `session.*`, `shell.env`.
- **Cline SDK**: in-process `AgentPlugin` hooks `beforeRun`, `afterRun`, `beforeModel`, `afterModel`, `beforeTool`, `afterTool`, `onEvent`; hook timeout 3 s; five consecutive failures mark the plugin `failed`.
- **ACP (Zed, JetBrains hosts)**: no hooks, but the protocol itself carries `session/update` `tool_call` / `tool_call_update` (`toolCallId`, `kind`, `status`, `rawInput`, `rawOutput`, `locations`) and `session/request_permission` (`allow_once|allow_always|reject_once|reject_always`). An ACP proxy is a viable interception point (inference).

### 2. Enterprise managed configuration

- **Claude Code** [V]: precedence inside the managed tier is server-managed, then MDM (macOS domain `com.anthropic.claudecode`; Windows `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings`, REG_SZ JSON), then files (`managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json`), then user-writable `HKCU`. Server settings poll hourly, MDM every 30 minutes. Lock-down keys: `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `allowManagedMcpServersOnly`, `strictPluginOnlyCustomization`, `forceRemoteSettingsRefresh` (fail-closed startup), `forceLoginMethod`, `forceLoginOrgUUID`, `allowedProviders`, `allowedHttpHookUrls`, `sandbox.failIfUnavailable`, `sandbox.network.allowManagedDomainsOnly`. Unparseable admin documents make Claude Code refuse to start. Docs concede a local administrator can edit the managed source, and that `/etc/claude-code` is user-writable on WSL. An embedding host can inject policy via the Agent SDK `managedSettings` option.
- **Codex** [V]: `requirements.toml` (enforced) and `managed_config.toml` (defaults). Layers: system file, cloud "Agent security" bundle, legacy managed config, macOS MDM `com.openai.codex` (`requirements_toml_base64`, `config_toml_base64`). Keys: `allowed_approval_policies`, `allowed_sandbox_modes`, `allowed_permission_profiles`, `[rules] prefix_rules`, `[mcp_servers.<name>] identity` allowlist, `[features]` pins, `[hooks]` with `managed_dir` / `windows_managed_dir`, `allow_managed_hooks_only`, `[otel]` (CLI 0.166.0), `[network_proxy]`, `[marketplaces]`.
- **Copilot** [V]: server (`copilot/managed-settings.json` in the org `.github-private` repo), MDM (`HKLM\SOFTWARE\Policies\GitHubCopilot`, macOS `com.github.copilot`), file. MDM beats server beats file; `permissions.*` and `sandbox` merge most-restrictive. Keys seen: `permissions.disableBypassPermissionsMode`, `sandbox.enabled`, `enabledPlugins`, `forceRemoteSettingsRefresh`. On POSIX the file must be root-owned, not a symlink, not group or world writable. Policy hooks live in `policy.d`.
- **Cursor** [V]: enterprise `hooks.json` in system paths, team hooks synced from the dashboard, editor policies (`AllowedExtensions`, `AllowedTeamId`, `WorkspaceTrustEnabled`, ...) via ADMX on Windows and `.mobileconfig` (`com.todesktop.230313mzl4w4u92`) on macOS. Linux policy is `~/.cursor/policy.json`, which is user-writable. Admins can restrict Run Modes and sandbox networking.
- **Gemini CLI** [V]: system settings override everything; `admin.secureModeEnabled`, `admin.mcp.config`, `security.disableYoloMode`, `adminPolicyPaths`.
- **opencode** [V]: system dirs plus macOS domain `ai.opencode.managed`; settings alone do not stop users adding MCP servers or plugins (a separate policies feature does).
- **Amp** [V]: `managed-settings.json` per OS; `amp.mcpPermissions` allow/reject rules.
- **Factory Droid** [V]: org-managed settings from Enterprise Controls, `allowManagedHooksOnly`; no local path documented.
- **Auggie** [V]: system `settings.json` is highest precedence and "immutable".
- **Antigravity, Devin Local, Kiro, goose, OpenHands, Cline**: no machine-scope managed tier documented. [V for absence on the pages read]

### 3. Sandboxes, permission modes, bypass flags

- **Claude Code** [V]: Seatbelt (macOS), bubblewrap + socat (Linux, WSL2), none on native Windows. Off by default. `dangerouslyDisableSandbox` retry unless `sandbox.allowUnsandboxedCommands: false`. `--dangerously-skip-permissions` skips prompts but not the sandbox. Network isolation is a TCP proxy by hostname only.
- **Cursor** [V]: Seatbelt; Landlock + seccomp (kernel 6.2+), bubblewrap fallback; Windows not documented. Run Modes: Auto-review, Allowlist, Run Everything. `~/.cursor/sandbox.json`, `~/.cursor/permissions.json`.
- **Codex** [P, partly V]: Seatbelt, Landlock/seccomp, a Windows sandbox; modes `read-only|workspace-write|danger-full-access`; `--dangerously-bypass-approvals-and-sandbox`. Permission profiles replace sandbox modes from 0.138.0 [V].
- **Gemini CLI / Antigravity** [V]: `sandbox-exec` profiles, docker, podman, lxc, `windows-native`; Antigravity uses Seatbelt and bubblewrap; "Turbo / Always proceed" is the bypass; `--yolo` on Gemini CLI.
- **Copilot CLI** [V]: `sandbox.enabled`, `copilot sandbox ca` for a TLS-inspecting CA, `/yolo` and `/allow-all`.

### 4. Telemetry, transcripts, credentials

- **Claude Code OTel** [V]: `CLAUDE_CODE_ENABLE_TELEMETRY=1`; log events `claude_code.user_prompt`, `assistant_response`, `tool_result`, `tool_decision` (with `source` = `config|hook|user_permanent|user_temporary|user_abort|user_reject` and `permission_mode`), `api_request`, `api_error`, `api_refusal`, `api_request_body`, plus `managed_settings_resolved`, `plugin_loaded`, `mcp_server_connection`. Attributes `session.id`, `organization.id`, `user.account_uuid`, `user.email`, `agent_id`, `parent_agent_id`. Content gated by `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_RAW_API_BODIES`. Traces are beta. A managed endpoint strips user-set endpoints; repositories cannot configure exporters. Subprocesses do not inherit `OTEL_*`.
- **Codex OTel** [V, from source `codex-rs/otel`]: `codex.conversation_starts`, `codex.api_request`, `codex.sse_event`, `codex.user_prompt`, `codex.tool_decision`, `codex.sandbox_outcome`, `codex.turn_cost`, `codex.websocket_request`.
- **Gemini CLI** [V]: `telemetry.enabled`, `target`, `otlpEndpoint`, `otlpProtocol`, `logPrompts`.
- **Credentials** [V]: Claude Code uses macOS Keychain, else `~/.claude/.credentials.json` (0600; Windows relies on profile ACLs). Copilot CLI keeps auth in `~/.copilot/config.json` when no OS store exists, and BYOK keys in plaintext `providers.json`. Antigravity enterprise uses gcloud ADC.

### 5. Known bypasses and CVEs (2025 to 2026)

- **Plugin4Shell** (Help Net Security, 2026-09-18) [V article]: plugin SHA-pin bypass giving zero-click RCE in Claude Code (fixed 2.1.179), Codex (fixed 0.146.0), Copilot (unpatched at publication), Gemini CLI (deprecated, unpatched).
- Reported, not confirmed against advisories [S]: CVE-2025-59536 and CVE-2026-21852 (Claude Code project hooks and MCP consent before trust); CVE-2026-40068 (trust dialog skipped via spoofed `.git/commondir`); CVE-2026-48124 (Cursor executed hooks from a workspace `.claude` settings file, unsandboxed; fixed 3.0.0); CVE-2026-35603 (Windows machine-wide config paths); CVE-2026-25723 (Claude Code write restrictions); deny rules dropped beyond 50 subcommands; malicious `.git` config execution across seven agents (September 2026).
- Pattern: almost every bypass is **repository-supplied configuration executing before or without trust**, or **the control plane's own files being writable**.

## Matrix

Adapter matrix. "Admin tier" means a machine or org scope the user cannot override.

| Agent | Pre-tool hook | Rewrite input | Fail-closed option | Admin-tier hooks | Managed settings | OS sandbox | Native OTel | Local transcript |
|---|---|---|---|---|---|---|---|---|
| Claude Code / Agent SDK | Yes: command, http, mcp_tool | Yes | Yes (`onFailure`) | Yes (`allowManagedHooksOnly`) | File, HKLM, plist, server | macOS, Linux; not Windows | Yes, lockable | JSONL |
| Codex | Yes: command | Yes | No | Yes (`requirements.toml`) | File, plist, cloud | Yes [P] | Yes | JSONL [P] |
| Cursor | Yes: command, prompt | Yes | Yes (`failClosed`) | Yes (system file, team) | ADMX, mobileconfig, dashboard | macOS, Linux | Not documented | `transcript_path` given |
| Copilot CLI / VS Code / cloud | Yes: command, http | Yes (`modifiedArgs`) | Crash yes, timeout no | Yes (`policy.d`) | File, HKLM, plist, server | Yes (CLI) | Unverified | `events.jsonl` |
| Antigravity | Yes: command | Yes (`overwrite`) | Undocumented | No | Cloud console only | macOS, Linux | To Google Cloud | `transcriptPath` given |
| Gemini CLI (legacy) | Yes | Yes | No | System settings | File | Several | Yes | Local [P] |
| Factory Droid | Yes | Yes | No | Yes (org) | Org console | Unverified | Unverified | `transcript_path` given |
| Devin Local (ex-Windsurf) | Yes: command, prompt | Yes | No | No | Not documented | Unverified | Unverified | Not in payload |
| Auggie | Yes | Yes | No | Yes (system file) | System file | Unverified | Unverified | Unverified |
| Kiro | Yes | Not documented | Not documented | No | Unverified | Unverified | Unverified | Unverified |
| goose | Yes | No | Yes (`on_failure`) | No | No | No | Unverified | Local [P] |
| OpenHands | Yes | Not documented | No | No | No | Docker [P] | Unverified | Local [P] |
| opencode / forks | Plugin (in-process) | Yes | Throw = block | No (config only) | File, plist | No | Unverified | Local |
| Cline | SDK plugin (in-process) | Yes | `hookErrorMode: throw` | No | Unverified | No | Unverified | Local [P] |
| Amp | Plugins (unverified) | Unverified | Unverified | Unverified | File | Unverified | Unverified | Server-side [P] |
| Zed + ACP agents | Via ACP proxy | Via proxy | Proxy decides | No | Unverified | No | No | Local [P] |
| Aider, Continue, Warp, Roo, Kilo, Junie, Amazon Q | Not verified | | | | | | | |

## Weak points, gaps and risks

- **Fail-open defaults** mean a hook-only product can be silently disabled by killing or slowing the hook process.
- **Timeout asymmetry**: Copilot denies on crash but allows on timeout; an attacker who can stall the hook wins.
- **User-scope-only agents** (Antigravity, Devin Local, Kiro, goose, OpenHands) let the agent itself edit the hook file. Claude Code protects `.claude/settings*` from sandboxed writes; most others document nothing similar.
- **Project-scope hooks are an attack surface, not just a control**: several CVEs are hooks or MCP config executing from an untrusted repo. Our installer must never place enforcement in project scope.
- **Cross-reading of `.claude/` config** by Copilot, Devin and Cursor means one malicious file targets several agents, and one legitimate hook may fire twice (duplicate events to de-duplicate).
- **Cloud agents** see only repo-committed or org-synced hooks; device-level policy does not reach them.
- **Tool name and argument schemas differ per agent** (`Bash` vs `shell` vs `exec` vs `run_terminal_cmd`; `mcp__s__t` vs `mcp_s_t`), so policy must target a normalised action, not raw tool names.
- **Windows**: no Claude Code sandbox, ProgramData-based policy paths in several agents, HKCU fallbacks.
- **Docs churn**: three vendors moved documentation domains this year; adapters need version probes and conformance tests, not static assumptions.

## Implications for our design

### Deliverable 2: normalised hook-event schema (proposal)

```json
{
  "schema": "aidr.hook/1",
  "event": "session.start|session.end|prompt.submit|tool.pre|tool.permission_request|tool.post|tool.failed|model.pre|model.post|subagent.start|subagent.stop|turn.stop|compact.pre|compact.post|config.change|file.read.pre|file.edit.post|notification",
  "agent": {"product": "claude-code", "version": "2.1.319", "surface": "cli|ide|desktop|cloud|sdk", "adapter": "claude-dialect/3"},
  "session": {"id": "", "turn_id": "", "prompt_id": "", "parent_agent_id": "", "agent_id": "", "agent_type": ""},
  "actor": {"os_user": "", "account_email": "", "org_id": "", "pid": 0, "ppid": 0, "process_start_time": ""},
  "context": {"cwd": "", "workspace_roots": [], "repo": "", "transcript_path": "", "permission_mode": "default|plan|accept_edits|auto|dont_ask|bypass", "model": "", "sandboxed": null},
  "tool": {"call_id": "", "raw_name": "", "class": "shell|file_read|file_write|file_delete|net_fetch|web_search|mcp|subagent|browser|other", "mcp": {"server": "", "tool": ""}, "input": {}, "input_normalised": {"command": "", "paths": [], "urls": []}, "response": null, "error": null},
  "prompt": {"text": null, "sha256": ""},
  "native": {}
}
```

Decision returned by our daemon, translated per agent:

```json
{"decision": "allow|deny|ask|defer", "reason": "", "user_message": "", "agent_context": "", "updated_input": null, "stop_session": false, "policy_id": "", "ttl_ms": 0}
```

Translation notes: `ask` degrades to `deny` on Codex, Auggie, goose, Devin and Copilot cloud; `updated_input` is unavailable on goose; `pid`/`process_start_time` are filled by the hook binary from its parent chain so the OS sensor can join hook events to process trees (this is the agent-versus-human attribution key). Keep the untouched payload in `native`.

### Deliverable 3: adapter build order, install and tamper protection

1. **Claude Code (+ Agent SDK, VS Code/JetBrains extensions, desktop)**. Install: drop-in `managed-settings.d/50-aidr.json` (system dir), or HKLM / plist via MDM, or server-managed. Use an `http` hook to the local daemon plus a `command` fallback, `"onFailure": "block"`, `allowManagedHooksOnly` optional, `allowedHttpHookUrls` pinned to loopback, managed OTel endpoint pointing at our collector. Subscribe to `ConfigChange`.
2. **Copilot CLI / VS Code / app**. Install: `policy.d/*.json` hook plus `managed-settings.json` with `permissions.disableBypassPermissionsMode`. Prefer `exec`+`args` (no shell). Treat timeouts as a detection, since they fail open.
3. **Codex CLI / IDE / app**. Install: `requirements.toml` with `[hooks]`, `managed_dir`, `[features] hooks = true`, `allow_managed_hooks_only`, and `[otel]`. Managed hooks skip the trust prompt.
4. **Cursor**. Install: system `hooks.json` with `failClosed: true`; team hooks for cloud agents.
5. **Factory Droid and Auggie**. Near-free once the Claude dialect exists; both have an admin tier.
6. **Antigravity** (`~/.gemini/config/hooks.json`) and **Devin Local** (`~/.config/devin/config.json`): user scope only, so pair with file-integrity watch.
7. **Kiro, goose, OpenHands**: user-scope command hooks, same binary.
8. **opencode family and Cline**: a small JS shim plugin that forwards to the daemon.
9. **ACP proxy** for Zed and JetBrains-hosted agents.
10. **No hook surface** (Aider and others): OS sensor, MCP gateway and LLM gateway only.

Tamper protection, common to all:
- One signed static Rust hook binary in a root/SYSTEM-owned directory (`C:\Program Files\...`, never ProgramData), invoked by absolute path in exec form.
- The hook binary is a thin client; decisions live in the privileged daemon. If the daemon is unreachable it exits 2.
- The OS sensor watches every config path in the table below and alerts on drift, and correlates: **agent process observed without a matching `session.start` hook event within N seconds means "hook dark"**, which is itself a detection.
- Detect bypass flags on process command lines: `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--dangerously-bypass-hook-trust`, `--yolo`, `--allow-all`, `--settings '{"disableAllHooks":true}'`.
- Reapply managed files on a timer (vendors themselves recommend MDM redeploy against local admins).
- Never write enforcement into project scope; do scan project scope for hostile hooks, MCP servers and plugins before the agent trusts the folder.

### Deliverable 4: on-disk paths

| Agent | Managed / system config | User config, hooks, MCP | Transcripts | Credentials |
|---|---|---|---|---|
| Claude Code | macOS `/Library/Application Support/ClaudeCode/`; Linux `/etc/claude-code/`; Windows `C:\Program Files\ClaudeCode\` (`managed-settings.json`, `managed-settings.d/`, `managed-mcp.json`); `HKLM\SOFTWARE\Policies\ClaudeCode`; plist `com.anthropic.claudecode` | `~/.claude/settings.json`, `~/.claude.json` (MCP, trust), `.claude/settings(.local).json`, `.mcp.json`, `~/.claude/{skills,agents,commands,rules,plugins}/`, cached `~/.claude/remote-settings.json` | `~/.claude/projects/<project>/<session>.jsonl`, `.../subagents/`, `~/.claude/history.jsonl` | macOS Keychain; else `~/.claude/.credentials.json`; profiles in `~/.config/anthropic` or `%APPDATA%\Anthropic` |
| Codex | `/etc/codex/requirements.toml`, `/etc/codex/managed_config.toml`; Windows `%ProgramData%\OpenAI\Codex\requirements.toml`; plist `com.openai.codex` | `~/.codex/config.toml`, `~/.codex/hooks.json`, `<repo>/.codex/` | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` [P] | `~/.codex/auth.json` or OS keyring [P] |
| Cursor | macOS `/Library/Application Support/Cursor/hooks.json`; Linux `/etc/cursor/hooks.json`; Windows `C:\ProgramData\Cursor\hooks.json`; Linux policy `~/.cursor/policy.json` | `~/.cursor/hooks.json`, `permissions.json`, `sandbox.json`, `cli-config.json`, `.cursor/` | Path supplied as `transcript_path` | Unverified |
| Copilot | macOS `/Library/Application Support/GitHubCopilot/managed-settings.json`; Linux `/etc/github-copilot/managed-settings.json` and `policy.d/*.json`; Windows `%ProgramFiles%\GitHubCopilot\managed-settings.json`, `C:\ProgramData\GitHub\Copilot\policy.d\*.json`; `HKLM\SOFTWARE\Policies\GitHubCopilot`; plist `com.github.copilot` | `~/.copilot/settings.json`, `mcp-config.json`, `hooks/`, `agents/`, `skills/`, `installed-plugins/`, `permissions-config.json`; `.github/hooks/*.json`, `.github/copilot/settings.json` | `~/.copilot/session-state/<id>/events.jsonl`, `~/.copilot/session-store.db` | OS store, else `~/.copilot/config.json`; `providers.json` plaintext; `mcp-secrets/` |
| Antigravity | None documented | `~/.gemini/config/hooks.json`, `~/.gemini/config/config.json`, `~/.gemini/antigravity-cli/settings.json`, `.agents/hooks.json`, `.agents/skills/` | `transcriptPath` in payload; logs `~/.gemini/antigravity-cli/cli.log` | gcloud ADC `~/.config/gcloud/application_default_credentials.json` (enterprise) |
| Gemini CLI | Linux `/etc/gemini-cli/settings.json`; macOS `/Library/Application Support/GeminiCli/settings.json`; Windows `C:\ProgramData\gemini-cli\settings.json` | `~/.gemini/settings.json`, `.gemini/settings.json` | `~/.gemini/tmp/<project_hash>/` | `~/.gemini/oauth_creds.json` [P] |
| Devin Local | None documented | `~/.config/devin/config.json` (`%APPDATA%\devin\config.json`), `.devin/hooks.v1.json`, `.devin/config(.local).json`, also reads `.claude/` | Unverified | Unverified |
| Factory Droid | Org console | `~/.factory/hooks.json`, `~/.factory/settings.json`, `.factory/` | `transcript_path` in payload | Unverified |
| Auggie | `/etc/augment/settings.json`; Windows `C:\ProgramData\Augment\settings.json` | `~/.augment/settings.json`, `.augment/settings(.local).json` | Unverified | Unverified |
| Kiro | None documented | `~/.kiro/hooks/`, `.kiro/hooks/*.json` | Unverified | Unverified |
| goose | None | `~/.agents/plugins/<name>/hooks/hooks.json`, `<project>/.agents/plugins/` | Unverified | Unverified |
| opencode | Linux `/etc/opencode`; macOS `/Library/Application Support/opencode`; Windows `%ProgramData%\opencode`; plist `ai.opencode.managed` | `~/.config/opencode/opencode.json(c)`, `~/.config/opencode/plugins/`, `.opencode/` | `~/.local/share/opencode/` [P] | `~/.local/share/opencode/auth.json` [P] |
| Amp | macOS `/Library/Application Support/ampcode/managed-settings.json`; Linux `/etc/ampcode/managed-settings.json`; Windows `%ProgramData%\ampcode\managed-settings.json` | `~/.config/amp/settings.json`, `.amp/settings.json` | Server-side threads [P] | Unverified |

## Ideas worth stealing and whitespace

- **goose's `PreToolUseResult`**: a post-decision observation event carrying `decision`, `blocked_by`, `cause` (`policy_denial` vs `hook_failure`) and `policy_evaluated`. Emit the same from our daemon for every agent.
- **BeyondTrust's policy replay**: run a draft policy over recorded activity before saving it. Our normalised event log makes this cheap.
- **Claude Code's `http` hook type** removes process-spawn cost and lets one daemon serve all sessions.
- **Copilot's file validation** (root-owned, no symlink, not group or world writable) should be our installer's self-check on every platform.
- **Whitespace**: an open conformance test suite that measures, per agent version, whether a hook really blocks, what happens on crash and timeout, and whether the agent can rewrite its own hook config. Nobody publishes this.
- **Whitespace**: "hook dark" detection by joining OS process telemetry to hook events; hook coverage for cloud agents; a vendor-neutral hooks spec (Agent Plugins v1 left it out); Linux and Windows parity for kernel-level agent attribution.

## Could not verify / open questions

- The shared web-search budget ran out mid-task. Not researched from primary docs: Roo Code, Kilo Code, Continue, Warp, Aider, JetBrains Junie and AI Assistant (docs page rendered empty), Amazon Q Developer, Devin cloud, Zed tool-permission details, Amp plugin API and permissions, Copilot CLI OTel variables, Cursor Admin API and audit logs, Cursor Windows sandbox, Cursor CLI hook coverage.
- Codex config reference, sandbox and session-storage pages returned 404 at guessed `learn.chatgpt.com` URLs; Codex sandbox and path rows are marked [P].
- CVE identifiers other than Plugin4Shell come from search summaries of secondary blogs; NVD did not render. Confirm each against vendor advisories before citing.
- Whether legacy Windsurf Cascade hooks (`pre_run_command` and similar) and legacy Cline file hooks still work.
- Microsoft Agent 365 overview (GA 2026-05-01, per-user licence) does not say whether local coding agents on endpoints are discovered; the Defender sub-pages were not read.
- Antigravity hook failure semantics and any system-level policy path.

## Sources

- Claude Code hooks, https://code.claude.com/docs/en/hooks (read 2026-11-09)
- Claude Code settings, https://code.claude.com/docs/en/settings
- Claude Code managed settings, https://code.claude.com/docs/en/managed-settings.md
- Claude Code directory reference, https://code.claude.com/docs/en/claude-directory.md
- Claude Code monitoring (OpenTelemetry), https://code.claude.com/docs/en/monitoring-usage
- Claude Code sandboxing, https://code.claude.com/docs/en/sandboxing
- Claude Code authentication, https://code.claude.com/docs/en/authentication.md
- Codex hooks, https://learn.chatgpt.com/docs/hooks
- Codex managed configuration, https://learn.chatgpt.com/docs/enterprise/managed-configuration
- Codex source, https://github.com/openai/codex (`codex-rs/otel/src/events/session_telemetry.rs`, `docs/config.md`)
- Cursor hooks, https://cursor.com/docs/agent/hooks
- Cursor run modes and sandbox, https://cursor.com/docs/agent/security/run-modes
- Cursor enterprise deployment, https://cursor.com/docs/enterprise/deployment-patterns
- GitHub Copilot hooks reference, https://docs.github.com/en/copilot/reference/hooks-configuration
- VS Code agent hooks (Preview), https://code.visualstudio.com/docs/copilot/customization/hooks
- Copilot managed settings deployment, https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings
- Copilot CLI config directory, https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference
- Copilot MDM changelog, https://github.blog/changelog/2026-07-08-deploy-managed-copilot-settings-via-mdm-in-vs-code-and-cli/ (2026-07-08, via search)
- Gemini CLI hooks reference, https://geminicli.com/docs/hooks/reference/
- Gemini CLI configuration, https://geminicli.com/docs/reference/configuration/
- Antigravity hooks, https://antigravity.google/docs/hooks
- Antigravity enterprise, https://antigravity.google/docs/enterprise
- Devin CLI hooks, https://docs.devin.ai/cli/extensibility/hooks/overview.md
- Devin Desktop hooks (Windsurf redirect), https://docs.devin.ai/desktop/cascade/hooks
- Factory Droid hooks, https://docs.factory.com/reference/hooks-reference
- Kiro hooks, https://kiro.dev/docs/hooks/ and https://kiro.dev/docs/hooks/types/
- Auggie hooks, https://docs.augmentcode.com/cli/hooks
- OpenHands hooks, https://docs.openhands.dev/sdk/guides/hooks
- goose hooks, https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/context-engineering/hooks.md
- opencode plugins and config, https://opencode.ai/docs/plugins/ , https://opencode.ai/docs/config/ , https://github.com/anomalyco/opencode
- Cline SDK plugins, https://docs.cline.bot/sdk/plugins.md
- Amp CLI settings, https://ampcode.com/docs/cli/settings
- Agent Client Protocol tool calls, https://agentclientprotocol.com/protocol/tool-calls
- Agent Plugins Specification 1.0.0, https://agent-plugins.org/agent-builders/components/hooks
- BeyondTrust AI Agent Security, https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- Microsoft Agent 365 overview, https://learn.microsoft.com/en-us/microsoft-agent-365/overview (updated 2026-10-23)
- Plugin4Shell, https://www.helpnetsecurity.com/2026/09/18/plugin4shell-ai-coding-agents-vulnerability/ (2026-09-18)
- Git-config flaws across agents, https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html (2026-09, via search)
- Coding-agent vulnerability roundups, https://adversa.ai/blog/top-ai-coding-agent-security-resources-october-2026/ (secondary, via search)

## Independent verification

_Checked 2026-11-09 by a second reviewer. Method: vendor docs re-read directly, source code and security advisories read through the GitHub API (`openai/codex`, `anthropics/claude-code`, `google-gemini/gemini-cli`, `github/copilot-cli`), and the original Plugin4Shell write-up. The shared web-search budget was exhausted, so no search-engine cross-checks were possible; claims 5 and 9 could only be re-read against the vendor page the researcher already used._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude Code PreToolUse hooks fail open on crash, timeout or non-zero exit unless `onFailure: block` (v2.1.295+, command and http only); exit 2 always blocks | Confirmed | Docs state exit 1, failed start, invalid JSON and timeouts do not block; `onFailure` is `continue` (default) or `block`, documented on command and http handlers only. `mcp_tool`, `prompt` and `agent` handlers cannot fail closed. `onFailure` has no effect on `Stop`, `SubagentStop`, `TaskCompleted`, `TeammateIdle` or async hooks. | https://code.claude.com/docs/en/hooks |
| 2 | Claude Code managed settings sources and paths; legacy `C:\ProgramData` not read; local admin can edit | Confirmed | All paths, the `Settings` value (REG_SZ or REG_EXPAND_SZ) and the local-admin caveat match. Missed detail that matters: the default is `managedSourcesBehavior: "first-wins"`, so only the highest-ranked source with any policy key applies and lower ones are skipped (see extra check C). Server-managed settings are fetched only when the session authenticates directly to Anthropic's API or a gateway. | https://code.claude.com/docs/en/managed-settings |
| 3 | Codex hooks on by default, cover Bash, apply_patch and MCP, deny and updatedInput but no ask, 600 s default, fail open, enforceable via `requirements.toml` | Confirmed | Source confirms `timeout_sec.unwrap_or(600)` and that a runner error, timeout or any exit code other than 0 or 2 sets status Failed without blocking. Two details: exit 2 with empty stderr is also treated as a failure and the tool runs; `allow_managed_hooks_only` is a top-level key in `requirements.toml`, while `managed_dir` and `windows_managed_dir` sit under `[hooks]`. Latest release is rust-v0.167.0 (2026-11-06). | https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/pre_tool_use.rs ; https://github.com/openai/codex/blob/main/docs/config.md |
| 4 | Copilot CLI and VS Code read hooks from `policy.d`, `.github/hooks`, `~/.copilot/hooks`, `.claude/settings.json`; command hooks deny on crash, timeouts fall through | Corrected | True for Copilot CLI. For VS Code the hooks page lists `.github/hooks`, `~/.copilot/hooks`, inline Copilot settings and repo `.claude/settings.json`, but does not list `policy.d`; GitHub's reference lists `policy.d` under Copilot CLI sources, and the cloud agent does not support policy hooks. Also missed: a registry source for policy hooks (`HKLM\Software\Policies\GitHub\Copilot`, `Policy` REG_SZ); macOS uses the same `/etc/github-copilot/policy.d`; HTTP `preToolUse` hooks fail open on network error, timeout or non-2xx and must be `https://`. | https://docs.github.com/en/copilot/reference/hooks-reference ; https://code.visualstudio.com/docs/copilot/customization/hooks |
| 5 | Cursor enterprise `hooks.json` paths, team hooks, deny over ask over allow, `failClosed` default false | Confirmed | Re-read on the vendor page only. Team hooks are Enterprise-only and sync every 30 minutes. For non-permission fields "the last response wins", so a lower-priority source can override a higher one. | https://cursor.com/docs/agent/hooks |
| 6 | Claude Code sandbox: Seatbelt, bubblewrap, off by default, none on native Windows, does not cover file tools, hooks, local MCP or LSP servers | Confirmed | Also outside the sandbox: WebFetch, WebSearch, status-line and `apiKeyHelper` commands, plugin monitors, `!` commands and `excludedCommands`. WSL1 is unsupported. Without `sandbox.failIfUnavailable` an unavailable sandbox silently degrades to unsandboxed. | https://code.claude.com/docs/en/sandboxing |
| 7 | Claude Code OTel events incl. `tool_decision` with `source` and `permission_mode`; managed endpoint removes user endpoints; repos cannot configure exporters | Confirmed | `permission_mode` on `tool_decision` needs v2.1.301+. One gap: a repository can still set an exporter selector such as `OTEL_LOGS_EXPORTER` to `none` and turn a signal off unless managed settings pin that variable, so the managed policy must set the exporter selectors, not only the endpoint. | https://code.claude.com/docs/en/monitoring-usage |
| 8 | Copilot managed settings via HKLM, `com.github.copilot`, files; MDM beats server beats file; POSIX file validation | Confirmed | Registry values are one REG_SZ per dot-separated key, not a single JSON document. No Windows ACL validation is documented for `%ProgramFiles%\GitHubCopilot\managed-settings.json`. Linux has no MDM path. | https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings |
| 9 | Antigravity hooks live only in `.agents/hooks.json` and `~/.gemini/config/hooks.json`; camelCase; six PreToolUse decisions | Corrected | Decisions, camelCase and the absence of a system tier hold (the enterprise page describes Cloud Console controls only). But there is a third source: installed CLI plugins can ship a `hooks.json`. Hooks in `~/.gemini/antigravity-cli/settings.json` are not loaded. Failure behaviour is still undocumented. | https://antigravity.google/docs/hooks ; https://antigravity.google/docs/enterprise |
| 10 | Plugin4Shell: Claude Code fixed 2.1.179, Codex fixed 0.146.0, Copilot unpatched, Gemini CLI deprecated and unpatched | Corrected | Claude Code fix is confirmed by Anthropic's advisory GHSA-pq7j-f95f-qfcv, CVE-2026-86063, patched 2.1.179. Codex 0.146.0 (released 2026-07-29) is per the researchers; OpenAI has no advisory and the release notes do not mention it. The Copilot status is outdated: the original write-up now says Microsoft fixed it in VS Code 1.136.0 (released 2026-09-02); I could not confirm this in VS Code's release notes, and no Copilot CLI fix version is given. Gemini CLI stays unpatched. "Zero-click" is conditional: the plugin must already be installed with auto-update, and the shared variant needs a git host that allows hash-like branch names (GitHub blocks them). | https://github.com/anthropics/claude-code/security/advisories/GHSA-pq7j-f95f-qfcv ; https://www.air.security/blog-posts/plugin4shell |

### Further statements checked

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| A. "CVE-2026-35603 covers insecure machine-wide config paths across several agents" (TL;DR, section 5) | Corrected | CVE-2026-35603 is a Claude Code advisory only (GHSA-5cwg-9f6j-9jvx, "Insecure System-Wide Configuration Loading Enables Local Privilege Escalation on Windows", fixed 2.1.75). It is not a cross-agent CVE. The other CVE ids in section 5 that I could match (CVE-2025-59536, CVE-2026-21852, CVE-2026-40068, CVE-2026-25723) exist as Claude Code advisories with matching subjects. | https://github.com/anthropics/claude-code/security/advisories/GHSA-5cwg-9f6j-9jvx |
| B. "Gemini CLI was replaced by Antigravity CLI on 2026-06-18" and the "legacy" label | Corrected (overstated) | Only free and Google AI Pro/Ultra access moved to Antigravity CLI on 2026-06-18. Gemini CLI is still maintained for Gemini Code Assist Standard/Enterprise and Code Assist for GitHub; the repository is not archived and was pushed to on 2026-11-10. Enterprises are the remaining user base, so it should not be deprioritised as legacy. | https://github.com/google-gemini/gemini-cli (README) |
| C. Deliverable 3, step 1: install by dropping `managed-settings.d/50-aidr.json`, "or" HKLM/plist, "or" server-managed | Corrected | These are not interchangeable. Under the default `first-wins`, if server-managed settings or an MDM policy deliver any policy key, the whole file tier is skipped, including its `hooks`; `hooks` is not one of the cross-source keys. A drop-in only composes with a higher source when that source sets `managedSourcesBehavior: "merge"` (v2.1.242+). The installer must detect which source is selected (`/status` shows it) and either write into that source or require the merge key. | https://code.claude.com/docs/en/managed-settings |
