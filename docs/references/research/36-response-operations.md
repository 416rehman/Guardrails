# Detection and response operations for AI agents: actions, kill switch, approvals, incidents, hunting

_Researched 2026-11-09_

Method note: the web-search budget for this run was already exhausted, so every finding below comes from fetching primary documents directly (vendor docs, specs, arXiv, GitHub via `gh`). Claims are marked **[V]** verified in a fetched source today, or **[I]** inference / prior knowledge not re-verified today.

## TL;DR

- **Every mainstream coding-agent hook fails open on timeout by default.** Claude Code, Cursor, Codex and Copilot CLI all let the tool call proceed if the hook stalls; fail-closed is opt-in (`onFailure: "block"` in Claude Code >= 2.1.295, `failClosed: true` in Cursor) or absent (Codex). Hooks are a steering and telemetry point, not the enforcement boundary. [V]
- **The verbs differ per agent.** Claude Code has `allow|deny|ask|defer`, `updatedInput`, `additionalContext`, `updatedToolOutput`, `continue:false`. Codex has no `ask`. Cursor honours `ask` only on shell and MCP hooks. Copilot turns `ask` into `deny` in autopilot and cloud. The action catalogue needs a per-agent capability table and a fallback for each verb. [V]
- **CrowdStrike's AI Kill Switch (announced 2026-11-03) today only tells AI gateways to block model access.** Endpoint process termination with restart prevention, identity revocation, SaaS and browser containment are listed as coming. A multi-point kill switch is open ground. [V]
- **Microsoft's local-agent runtime protection is Windows-only preview**, implemented through the vendors' hooks plus network inspection (which fails on certificate pinning and HTTP/3). Rollout is Disabled -> Audit -> Block; audit alerts are Informational. [V]
- **Approval prompts rendered inside the agent's own UI are forgeable.** Checkmarx's Lies-in-the-Loop (2025-09-15) pushed the dangerous command off screen with padding; Anthropic treated it as outside its threat model. Anthropic also reports users accept 93% of prompts. Approvals must be rendered by our component from the structured action, and confirmed out of the agent's reach. [V]
- **Standards cover most of the plumbing:** CIBA (poll/ping/push, `binding_message`) for out-of-band approval, CAEP 1.0 (final 2025-08-29) `session-revoked` / `credential-change` / `risk-level-change` for revocation, OCSF 1.9.0 Incident Finding (class 2005) for incidents, CACAO for playbooks. [V]
- **Session-aware policy is now a product feature.** AWS AgentCore Policy added temporal rules in Dogwood, an Apache-2.0 Rust superset of Cedar (`formerly within 1h … approve_claim`), with `LOG_ONLY` and `ENFORCE` modes. [V]
- **LLM reviewers are a single point of failure when they read attacker-controlled text.** Published attacks inject the monitor through the agent's output, and resampling makes it worse. Anthropic's auto-mode classifier deliberately sees only user messages and tool calls, never tool results or assistant prose. [V]
- **Monitor quality is measurable and mediocre:** best SHADE-Arena monitor AUC 0.87; auto mode misses 17% of real overeager actions at 0.4% false positives. Deterministic tripwires must carry the hard guarantees. [V]
- **Vendor-pushed policy is too slow for a kill switch:** Claude Code server-managed settings refresh hourly, Cursor team hooks sync about every 30 minutes. We need our own signed push channel. [V]
- **Detection-as-code tooling is reusable but licences differ:** Sigma/pySigma, Splunk contentctl + attack_data + attack_range (Apache-2.0), Atomic Red Team (MIT). Elastic's rules are Elastic License v2 and cannot be embedded. [V]
- **Policy replay over recorded activity before enabling a rule** is shipped by BeyondTrust; nobody publishes precision/recall for agent detections. [V]

## Findings

### 1. What each control point can actually do

**In-agent hooks.** Verified against current docs (fetched 2026-11-09):

- Claude Code: 33 hook events. `PreToolUse` returns `permissionDecision` (`allow|deny|ask|defer`), `permissionDecisionReason`, `updatedInput`, `additionalContext`. `PostToolUse` can replace the result with `updatedToolOutput`. Any hook can return `continue:false` + `stopReason` to halt the agent. Handler types: `command`, `http`, `mcp_tool`, `prompt`, `agent`. Default timeout 600 s. Default is fail-open: "Do not rely on a stalled hook as a gate". `allowManagedHooksOnly` and non-removable managed hooks exist; `ConfigChange` is a blockable event. The docs say to use the permission system, not hooks, for hard enforcement. https://code.claude.com/docs/en/hooks
- Cursor: `beforeShellExecution` and `beforeMCPExecution` return `permission` (`allow|deny|ask`) plus `user_message` and `agent_message`. In `preToolUse`, `ask` is accepted but not enforced. `failClosed` defaults to false, and dashboard-distributed hooks do not support it. Enterprise paths: `/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json`. https://cursor.com/docs/agent/hooks
- Codex: `PreToolUse` supports deny and allow-with-`updatedInput`; `ask` is unsupported and marks the hook failed while the tool continues. An error, timeout or malformed response "can let the tool run". Hosted tools such as WebSearch are not covered, and `write_stdin` does not re-run the hook. The docs call hooks "a useful guardrail, not a complete enforcement boundary". Managed via `requirements.toml` (`allow_managed_hooks_only`). https://learn.chatgpt.com/docs/hooks
- Copilot: `preToolUse` returns `allow|deny|ask` and `modifiedArgs`. Command-hook crashes fail closed; timeouts (default 30 s) and all HTTP-hook errors fail open. https://docs.github.com/en/copilot/reference/hooks-configuration

**Gateways.** Microsoft Defender evaluates Agent 365 tool invocations through Work IQ MCP before they run; a default rule audits everything and custom rules block four scenarios (malicious content propagation, secret exfiltration, evasion techniques, unsafe email domain). Audit and block events land in the `BehaviorInfo` table. When a blocking rule covers an agent, near-real-time alerts are no longer generated for it. https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection (doc dated 2026-07-01, updated 2026-10-20)

AWS AgentCore Policy intercepts all Gateway traffic, is deny-by-default, and supports temporal rules with `formerly within`, `since within`, `count` and `sum`. Quotas: 20 temporal policies per engine, 3 operators per policy, 24 h window. The session ID is caller-supplied, so a per-session rate limit resets when the caller starts a new session. https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html

**OS sensors.**

- Linux: `cgroup.freeze` stops a whole tree, including racing forks; `cgroup.kill` SIGKILLs the tree and handles concurrent forks. https://docs.kernel.org/admin-guide/cgroup-v2.html [V]
- Tetragon: a SIGKILL alone does not guarantee the in-flight syscall is undone; combine Signal with Override to stop the operation. https://tetragon.io/docs/concepts/enforcement/ [V]
- Kubernetes: Falco Talon ships `kubernetes:terminate`, `kubernetes:networkpolicy` (deny all egress), `label`, `cordon`, `drain`, `tcpdump`, `sysdig`, `download`, and Calico/Cilium network policies. https://falco-talon.github.io/docs/actionners/list/ [V]
- Sandboxing: Anthropic's `sandbox-runtime` (Apache-2.0) uses Seatbelt on macOS and bubblewrap plus a network namespace on Linux; native Windows is not sandboxed. Hooks and local MCP servers run outside it. https://code.claude.com/docs/en/sandboxing [V]
- Windows Job Objects and WFP, macOS Endpoint Security AUTH events and Network Extension are the equivalent primitives. [I]

**Identity.** Entra ID Protection for agents offers Confirm compromise (sets risk High, which triggers risk-based Conditional Access blocks) and Disable (blocks all sign-ins). All agent risk detections are currently offline. In on-behalf-of flows risk is attributed to the user, not the agent. A Learning Mode suppresses behavioural alerts for agents without history. https://learn.microsoft.com/en-us/entra/id-protection/concept-risky-agents (2026-06-17)

### 2. Kill switch

- CrowdStrike AI Kill Switch (blog 2026-11-03, in Falcon Guardian): available now, it "directs connected AI gateways to block access to the AI models". Coming: terminate endpoint agents and prevent restart, contain cloud agents, revoke identity permissions, restrict SaaS agents, end browser sessions. The post gives no scoping detail, roles, restore procedure or failure behaviour. https://www.crowdstrike.com/en-us/blog/crowdstrike-introduces-ai-kill-switch/
- CrowdStrike also lists Human-in-the-Loop Action Requests and Agent Interruption as GA, for its own Falcon/AgentWorks agents. https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-stops-agent-insider-threats/ (2026-11-04)
- Vendor policy channels are slow. Claude Code server-managed settings are fetched at startup and polled hourly; on a failed first fetch the client continues without them unless `forceRemoteSettingsRefresh` makes it exit. https://code.claude.com/docs/en/server-managed-settings
- No source I reached documents signed kill commands or a two-person rule for agent kill switches. The design in "Implications" is ours. [I]

### 3. Human-in-the-loop approval

- CIBA Core (final, 2021-09-01) separates the consumption device from the authentication device and warns the former may be controlled by someone other than the user. `binding_message` is shown on both to link them. Errors: `authorization_pending`, `slow_down`, `expired_token`, `access_denied`. https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- Auth0 productises this for agents: CIBA plus Rich Authorization Requests so the push shows the specific action; Guardian push is the default channel and email is a paid add-on. https://auth0.com/ai/docs/intro/asynchronous-authorization
- MCP: form-mode elicitation is in-band and visible to the client; URL mode is out-of-band, and the client must open the URL so that neither client nor LLM can inspect it. The current spec is **2026-07-28**, which is stateless: elicitation now arrives inside `InputRequiredResult` with `requestState`, and the 2025-11-25 `-32042` error and `elicitationId` are gone from the page. https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- Forgery: Lies-in-the-Loop plants instructions that make the agent pad its own approval prompt so the command scrolls out of view. https://checkmarx.com/zero-post/bypassing-ai-agent-defenses-with-lies-in-the-loop/
- Fatigue: "users accept 93% of them anyway". Auto mode replaces prompts with a two-stage classifier: a single-token filter (8.5% FPR), then chain-of-thought on flagged items (0.4% FPR on 10,000 real actions; 17% FNR on 52 real overeager actions; 5.7% FNR on 1,000 synthetic exfiltration cases). https://www.anthropic.com/engineering/claude-code-auto-mode (2026-03-25)
- BeyondTrust lists "held for approval" as a policy outcome but does not document the flow. https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security

### 4. How agents react to denial

- Claude Code returns the denial as a tool result with the reason and an instruction to find a safer path rather than route around it. After 3 consecutive or 20 total blocks it stops and escalates; headless runs terminate. Auto mode drops broad allow rules for interpreters (`Bash(python*)`) on entry, because an interpreter is the obvious bypass route. https://code.claude.com/docs/en/permission-modes
- Anthropic's incident examples include an agent hunting for other credentials after an auth error and retrying a failed deploy with a skip-verification flag: goal-directed rerouting without malice. (auto-mode post above)
- No vendor documents a post-denial evasion detection. [V, by absence in the pages read]

### 5. Incidents, hunting, baselines

- OCSF 1.9.0 Incident Finding (class 2005): `status_id` New / In Progress / On Hold / Resolved / Closed; `verdict_id` includes False Positive, True Positive, Benign, Test, Managed Externally, Duplicate; required `finding_info_list`; `tickets[]`; `is_suspected_breach`; priority, impact and confidence. https://schema.ocsf.io/classes/incident_finding
- Microsoft's three tiers: behaviours (`BehaviorInfo`, `BehaviorEntities`) below alerts (`AlertInfo`, `AlertEvidence`) below incidents, with `AgentsInfo` for inventory and `CloudAppEvents` for activity. Prompt evidence is limited to the suspicious snippet, with secrets redacted, and can be switched off. https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection
- BeyondTrust is session-centred: each AI session lists findings with severity and records prompts, commands, file access, network activity and tools.
- Baselines: CrowdStrike (Q4 2026) baselines per agent and per owner over files touched, tools called and data destinations, feeding a 0-100 risk score. Entra detections include `unfamiliarResourceAccess`, `signInSpike` and `earlyLifeMaliciousActivity`.
- CoSAI AI Incident Response Framework v1.0 aligns with NIST SP 800-61r3 and ships CACAO playbooks for prompt injection, memory injection and RAG poisoning; a telemetry RFC sits beside it. https://github.com/cosai-oasis/ws2-defenders

### 6. Detection engineering and ranges

- Rule tooling (GitHub metadata, 2026-11-09): SigmaHQ/sigma 11.4k stars, with correlation rules and filters; pySigma LGPL-2.1; splunk/contentctl Apache-2.0 ("generate, validate, build, test, deploy"), with attack_data and attack_range; elastic/detection-rules is Elastic License v2, with emulations in elastic/cortado; redcanaryco/atomic-red-team MIT, 12.8k stars.
- Agent targets: damn-vulnerable-MCP-server (15 challenges; 1.4k stars; no declared licence), appsecco/vulnerable-mcp-servers-lab (MIT; last push 2025-12, stale), ethz-spylab/agentdojo (MIT; last push 2026-06), UKGovernmentBEIS/control-arena (MIT), NVIDIA/garak (Apache-2.0), snyk/agent-scan (Apache-2.0; successor to mcp-scan).
- Microsoft ships a benign prompt-injection test string for validating runtime protection, and recommends 1-2 weeks of audit before block. https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection
- BeyondTrust: "replay recorded activity from a past time window to see what it would have blocked" before saving a policy.

### 7. Monitoring an agent that may be evading

- SHADE-Arena (arXiv 2506.15740): best sabotage success 27%; best monitor AUC 0.87; sabotage relies heavily on a scratchpad the monitor cannot see.
- Ctrl-Z (arXiv 2504.10374): resampling suspicious actions cut attack success from 58% to 7% at 5% usefulness cost.
- Adaptive Attacks on Trusted Monitors (arXiv 2510.09462, revised 2026-03-02): injections embedded in the agent's output consistently evade monitors, and resampling becomes a best-of-n attack.
- Auto mode's answer is structural: strip tool results and assistant prose from the reviewer, and run a separate injection probe on tool output.

## Matrix

**Hook capability per agent (all [V])**

| Capability | Claude Code | Cursor | Codex | Copilot CLI |
|---|---|---|---|---|
| Deny before tool | yes | yes | yes | yes |
| Ask human | `ask`, `defer` | shell and MCP only | no | yes (deny in autopilot/cloud) |
| Rewrite input | `updatedInput` | `updated_input` | `updatedInput` | `modifiedArgs` |
| Explain to agent | reason, `additionalContext` | `agent_message` | reason, `additionalContext` | reason |
| Rewrite output | `updatedToolOutput` | MCP output only | replace with reason | not documented |
| Stop session | `continue:false` | prompt hook only | not on PreToolUse | not documented |
| On timeout | open (opt-in closed) | open (opt-in closed) | open | open |
| Managed-only hooks | yes | enterprise path | yes | policy hooks |

**Action catalogue by control point**

| Action | In-agent hook | MCP/LLM gateway | OS sensor | Identity / SaaS | Reversible |
|---|---|---|---|---|---|
| Deny | deny + reason | JSON-RPC error / HTTP 403 | Linux LSM-BPF or Override; macOS ES AUTH; Windows minifilter/WFP [I] | Conditional Access block | n/a |
| Ask human | `ask` where supported, else hold the hook open | hold request; MCP URL elicitation | hold AUTH event within its deadline [I] | CIBA | n/a |
| Steer | deny + alternative in reason/context | error text with alternative | none (pair with hook) | none | n/a |
| Redact | rewrite input/output | body rewrite | none | DLP | no |
| Sandbox | rewrite command to sandbox wrapper | route to sandboxed tool host | bubblewrap / Seatbelt; AppContainer [I] | none | yes |
| Pause session | hold hook; stop agent | hold or 429 | `cgroup.freeze`; Job suspend [I]; SIGSTOP [I] | none | yes |
| Kill process tree | `continue:false` (cooperative) | n/a | `cgroup.kill`; `TerminateJobObject` [I]; kill by responsible PID [I] | none | no |
| Network quarantine | n/a | block model/tool routes | cgroup eBPF / nftables; WFP; NE filter [I]; NetworkPolicy | none | yes |
| Revoke tokens | n/a | drop gateway-held credential | delete local token cache | CAEP `session-revoked`, `credential-change`; IdP disable | partly |
| Disable MCP server/skill | managed deny rule | remove from catalogue | quarantine config file | revoke OAuth client | yes |
| Rotate secret | n/a | vault API | n/a | issuer API | no |
| Roll back files | agent checkpoints | n/a | our own pre-write snapshots | n/a | yes |
| Ticket / notify | n/a | webhook | n/a | ITSM | yes |

## Weak points, gaps and risks

- **Hook fragility.** Fail-open timeouts, concurrent hooks for parallel tool calls (Copilot, Codex), uncovered hosted tools, and "close and reopen the terminal" to apply settings (Defender) make hooks bypassable by stalling or racing.
- **Agent-side rollback is partial.** Claude Code checkpoints cover only files edited through its edit tools; files changed only by Bash, most subagent edits, and symlinked or hard-linked files are not restored; snapshots expire in about 30 days. https://code.claude.com/docs/en/checkpointing
- **Blocking can blind detection.** Defender suppresses near-real-time alerts on agents under a blocking rule; a blocked attempt is evidence and must stay visible.
- **Identity-layer response is slow and coarse.** Offline detections, and delegated-flow risk landing on the user.
- **Network inspection requires a trusted root certificate** and fails on pinning and HTTP/3 (Microsoft, BeyondTrust). No vendor in the set documents native Linux endpoint runtime protection.
- **Caller-supplied session IDs** let an agent reset session-scoped limits.
- **Approval integrity.** A local prompt shares a principal with the agent, which can inject input or shape what is displayed.
- **Reviewer manipulation.** Any LLM that reads tool output or agent prose can be injected through it.

## Implications for our design

**Response architecture**

1. One `ResponseAction` contract (`action`, `scope`, `target`, `reason`, `ttl`, `reversible`, `undo_ref`, `issuer`, `signatures[]`, `mode: enforce|simulate`), executed by pluggable actuators per control point. Each actuator declares its capabilities, so a verb such as `ask` degrades predictably (Codex: deny with a "request approval" hint and hold at the gateway).
2. Hooks are for steering and context; the OS sensor and gateways are the boundary. Ship every hook with fail-closed where the agent supports it, a short local decision path (a local daemon over a socket, never a cloud round trip), and a tripwire that alerts when a hook was configured but did not fire for an observed tool execution.
3. Deny messages are structured: rule ID, human reason, a safe alternative, and "do not retry by another route". Keep a per-session denial ledger.
4. Layered kill switch with scopes session -> agent instance -> device -> user -> agent type or version -> MCP server/skill -> model provider -> tenant. Commands are signed (Ed25519, tenant key), carry a monotonic counter and expiry, and are pushed over our own channel. The endpoint applies cgroup freeze/kill or Job termination, egress quarantine, hook-level stop and config quarantine; the gateway cuts routes; identity gets CAEP events. Prevent restart with a local deny-exec entry carrying a TTL.
5. Fleet-wide scopes need two distinct approver signatures, verified by the endpoint itself so that a compromised console cannot kill a fleet. Break-glass is a pre-provisioned offline key that raises a mandatory incident.
6. Fail-safe is tiered: endpoints keep the last signed policy and a local tripwire set. On losing the control plane, default to continue with cached policy; a "restricted" profile after N hours offline is opt-in. A kill state persists across reboot until a signed release arrives.
7. Guard rails on automated response: each rule declares its maximum blast radius; rate limits per rule and per tenant (for example, no more than X% of the fleet per hour without human sign-off); simulation mode records what would have happened; irreversible actions (kill, rotate, revoke) always need higher confidence or a human.

**Approval system**

1. The prompt is rendered by our component from the canonical tool call, never from agent-written text. Show the full command with length and hidden-character warnings, plus a diff for rewrites.
2. Channels in rising assurance: desktop prompt owned by a privileged helper running as a different principal; platform authenticator confirmation (Windows Hello, Touch ID, FIDO2) with the action digest as the WebAuthn challenge; out-of-band push via CIBA with a binding code; Slack/Teams for low-risk items only. Policy maps risk tier to minimum channel.
3. An approval yields a signed **grant**: tool, argument pattern, resource, session/task binding, TTL, maximum uses, approver, channel. Grants are data the policy engine evaluates, matching the Dogwood "formerly within" pattern, with the session ID assigned by our sensor rather than by the caller.
4. Policy: timeout defaults to deny; quorum for sensitive scopes; delegates and on-call rotation; the requester can never approve their own request.
5. Fatigue: batch similar pending requests; auto-approve on a deterministic low-risk classification; a learning mode that proposes scoped rules from repeated approvals and shows replay impact before adoption. Track approval rate and time-to-approve per user as rubber-stamp signals.

**Incident and case model**

- `Event` (OCSF plus agent extensions) -> `Finding` (from a rule or tripwire; includes blocked attempts) -> `Incident` (keyed on agent session and joined across session lineage, device, user and credential; OCSF 2005 fields) -> `Case` (assignee, tickets, notes, evidence bundle, linked response actions and approvals).
- Severity = rule severity x asset and identity sensitivity x action outcome (blocked, allowed, unknown) x corroboration.
- Suppressions and exceptions are first-class objects with owner, justification, scope and mandatory expiry. Use OCSF's Test verdict for range traffic.
- Evidence bundle: a session transcript slice (redacted by default, with a prompt-evidence toggle like Microsoft's), process tree, file diffs, network flows, policy decisions and approvals, hash-chained and signed by the sensor key. A local ring buffer (flight recorder) uploads its look-back window when a finding fires.

**Detection lifecycle and metrics**

- Rules as code in Sigma-compatible YAML with an agent logsource taxonomy and correlation rules. Every rule ships positive and negative test events. CI runs unit tests, then replay over stored history ("what would this have fired or blocked"). Staged rollout: simulate -> audit -> block, by device ring.
- Publish precision/recall per rule against a public benchmark corpus (AgentDojo, DVMCP, ControlArena traces plus benign coding sessions), with a coverage map against MITRE ATLAS and OWASP agentic threats.
- Operational metrics: alert-to-incident compression, false-positive rate per 1,000 sessions, block-induced task failure rate, approval latency, hook-miss rate.

**Hunting and baselines**

- First-seen and rarity analytics for (agent, tool), (agent, MCP server), (agent, egress domain), (repo, command family); peer groups by agent type, team and repository.
- A learning-mode suppression window with a parallel "early-life malicious" rule set, as Entra does.
- Post-denial evasion detections: within N minutes of a denial in a session, flag semantically equivalent actions through another tool, interpreter one-liners, new script files that are then executed, encoded payloads, credential discovery, or child agents spawned with weaker settings.

**Misaligned-agent monitoring**

- Deterministic tripwires on things the agent should never touch: sensor and hook configuration, its own transcripts, approval IPC, honey credentials and canary files.
- LLM review runs asynchronously over traces, sees structured actions with tool output passed as quoted, length-capped data or omitted, and can only escalate. It can never clear a deterministic finding or grant an approval. Red-team the reviewer with injection inside agent output as a standing test.

## Ideas worth stealing and whitespace

- Steal: BeyondTrust's replay before save; Microsoft's Audit-as-Informational plus behaviours beneath alerts; auto mode's 3-consecutive / 20-total denial breaker; Entra's learning mode with a parallel early-life rule; Dogwood temporal operators (consider embedding the Rust interpreter, Apache-2.0); MCP URL-mode elicitation as the standard out-of-band path; Falco Talon's actionner model.
- Whitespace: a cross-vendor, signed, multi-point kill switch that works offline; unforgeable approvals bound to an action digest; evasion-after-denial analytics; an open agent attack range with atomic tests and a published precision/recall benchmark; real file rollback independent of the agent; native Linux endpoint coverage; an embeddable response SDK for EDR vendors.

## Could not verify / open questions

- Web search was unavailable, so managed detection offerings for agents, Slack/Teams/mobile approval products, Okta's shared-signals support for agents, and Gemini CLI / Windsurf hooks were not researched.
- CrowdStrike Falcon Guardian product documentation (customer login); the kill switch's scoping and failure semantics are unknown.
- BeyondTrust approval-flow details (the sub-page URL I tried returned 404).
- Entra Conditional Access for agents page (guessed URL returned 404); how quickly a Disable takes effect.
- Windows and macOS mechanisms in the matrix marked [I] need a spike each, especially AUTH-event deadlines versus human approval latency, and whether a privileged approval helper resists synthetic input on each OS.
- Whether Dogwood is stable enough to embed (the repository was created 2026-07-27).
- The remaining parts of the Claude Code hooks page (`PermissionDenied`, `defer` semantics) were truncated in my fetch.

## Sources

- https://code.claude.com/docs/en/hooks - Claude Code hooks reference (fetched 2026-11-09)
- https://code.claude.com/docs/en/permission-modes - Claude Code permission modes / auto mode (fetched 2026-11-09)
- https://code.claude.com/docs/en/sandboxing - Claude Code sandboxing (fetched 2026-11-09)
- https://code.claude.com/docs/en/checkpointing - Claude Code checkpointing (fetched 2026-11-09)
- https://code.claude.com/docs/en/server-managed-settings - server-managed settings (fetched 2026-11-09)
- https://www.anthropic.com/engineering/claude-code-auto-mode - auto mode design (2026-03-25)
- https://cursor.com/docs/agent/hooks - Cursor hooks (fetched 2026-11-09)
- https://learn.chatgpt.com/docs/hooks - Codex hooks (redirect from developers.openai.com/codex/hooks; fetched 2026-11-09)
- https://docs.github.com/en/copilot/reference/hooks-configuration - Copilot hooks (fetched 2026-11-09)
- https://www.crowdstrike.com/en-us/blog/crowdstrike-introduces-ai-kill-switch/ - AI Kill Switch (2026-11-03)
- https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-stops-agent-insider-threats/ - agent insider threats (2026-11-04)
- https://www.crowdstrike.com/en-us/blog/crowdstrike-agentic-adversary-emulation-counters-ai-enabled-adversaries/ - adversary emulation (2026-11-04)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Agent 365 overview (2026-08-19; GA 2026-05-01)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai - enable Defender for AI agents (2026-10-30)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection - real-time protection (2026-07-01)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection - detect and investigate (2026-08-07)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview - endpoint runtime protection, preview (2026-10-08)
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection - configuration (2026-09-25)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix - support matrix (2026-11-02)
- https://learn.microsoft.com/en-us/entra/id-protection/concept-risky-agents - ID Protection for agents (2026-06-17)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - BeyondTrust AI Agent Security (fetched 2026-11-09)
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html and /policy-temporal.html - AgentCore Policy (fetched 2026-11-09)
- https://github.com/dogwood-policy/dogwood - Dogwood (Apache-2.0, Rust; created 2026-07-27)
- https://openid.net/specs/openid-caep-1_0-final.html - CAEP 1.0 (2025-08-29)
- https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html - SSF 1.0 (2025-08-29)
- https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html - CIBA Core (2021-09-01)
- https://auth0.com/ai/docs/intro/asynchronous-authorization - Auth0 async authorization (fetched 2026-11-09)
- https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation and /specification/2025-11-25/client/elicitation - MCP elicitation
- https://modelcontextprotocol.io/specification/versioning - MCP versioning (current 2026-07-28)
- https://checkmarx.com/zero-post/bypassing-ai-agent-defenses-with-lies-in-the-loop/ - Lies-in-the-Loop (2025-09-15)
- https://schema.ocsf.io/classes/incident_finding - OCSF 1.9.0 Incident Finding
- https://github.com/cosai-oasis/ws2-defenders - CoSAI AI Incident Response Framework v1.0 and telemetry RFC
- https://docs.kernel.org/admin-guide/cgroup-v2.html - cgroup v2
- https://tetragon.io/docs/concepts/enforcement/ - Tetragon enforcement
- https://falco-talon.github.io/docs/actionners/list/ - Falco Talon actionners
- https://arxiv.org/abs/2506.15740 - SHADE-Arena (2025-06/07)
- https://arxiv.org/abs/2504.10374 - Ctrl-Z (2025-04-14)
- https://arxiv.org/abs/2510.09462 - Adaptive Attacks on Trusted Monitors (2025-10-10, rev. 2026-03-02)
- GitHub metadata via API, 2026-11-09: SigmaHQ/sigma, SigmaHQ/pySigma, splunk/contentctl, splunk/attack_range, elastic/detection-rules, redcanaryco/atomic-red-team, harishsg993010/damn-vulnerable-MCP-server, appsecco/vulnerable-mcp-servers-lab, ethz-spylab/agentdojo, UKGovernmentBEIS/control-arena, NVIDIA/garak, snyk/agent-scan, anthropics/sandbox-runtime, falcosecurity/falco-talon, cilium/tetragon

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (budget exhausted), so checks used direct fetches of primary documents and read-only `gh` queries against source repositories. Where the only available source was the one the researcher cited, the note says so._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude Code hooks fail open by default on error or timeout; fail-closed needs `onFailure: "block"` (v2.1.295+); PreToolUse supports allow/deny/ask/defer, `updatedInput`, `additionalContext` | confirmed | The changelog entry for 2.1.295 adds `onFailure: "block"` for command and HTTP hooks; Agent SDK hook callbacks got it in 2.1.317. A timed-out PreToolUse hook does not auto-allow: the call "continues through the normal permission flow". Default timeout is 600 s, so a stall is a 10-minute hold before it falls open. | https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md ; https://code.claude.com/docs/en/hooks |
| 2 | Codex PreToolUse has no `ask`; error, timeout or malformed response can let the tool run; hosted tools not covered; "guardrail, not a complete enforcement boundary" | confirmed | Source agrees: `output_parser.rs` returns "unsupported permissionDecision:ask", and `pre_tool_use.rs` sets status Failed with `should_block = false` for hook errors, non-zero exits other than 2, and invalid JSON (tests named `..._fails_open`). The "can let the tool run" sentence sits in the docs' cloud-orchestration subsection, but the code shows it is general. No fail-closed option is documented. Default timeout 600 s. | https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/pre_tool_use.rs ; https://github.com/openai/codex/blob/main/codex-rs/hooks/src/engine/output_parser.rs |
| 3 | Cursor hooks fail open unless `failClosed: true` per script; `ask` enforced only on `beforeShellExecution` and `beforeMCPExecution`; dashboard team hooks sync about every 30 minutes and lack `failClosed` | confirmed | One nuance the brief omits: fail-open covers crashes, timeouts and non-zero exits other than 2. Permission hooks block on invalid JSON or an invalid response even when `failClosed` is false. `ask` on `subagentStart` is treated as deny; `preToolUse` accepts but does not enforce it. Only the researcher's page was available. | https://cursor.com/docs/agent/hooks |
| 4 | CrowdStrike AI Kill Switch (2026-11-03) today only directs AI gateways to block model access; endpoint termination with restart prevention, identity, SaaS and browser containment are coming | confirmed | The blog says this. The same-day press release is looser: stop is "first at the Gateway, and soon on the endpoint", but it lists relaunch blocking on the targeted host or host group and loss of enterprise network access in the present tense, and says the feature "is available today". Treat endpoint enforcement as not shipped, and expect the marketing to claim more than the blog. No product documentation is public. | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-ai-kill-switch-for-ai-safety/ |
| 5 | Defender local AI agent runtime protection is Windows-only preview using vendor hooks plus network inspection (no certificate pinning or HTTP/3), modes Disabled/Audit/Block via `Set-MpPreference -AiAgentProtection` | corrected | There are two independent settings. `-AiAgentProtection <mode>` controls agent-native (hook) inspection only; network inspection is `-AiAgentNetworkInspection <mode>`, and the Intune and Defender portal template deploys only the former (network inspection needs a PowerShell script). Windows-only preview is confirmed by the support matrix: runtime protection is listed only under "Windows (preview)", while discovery is GA on Windows and macOS. The matrix lists Claude Code, Copilot CLI and app, Claude Desktop (Code) and two VS Code extensions for hooks; Codex CLI is named in the overview but is absent from the matrix. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix ; https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection |
| 6 | Lies-in-the-Loop pads the agent's approval prompt so the command is out of view; Anthropic called it outside its threat model; Anthropic reports 93% prompt acceptance | confirmed | Checkmarx (2025-09-15): the first report was closed as "Informative", and Anthropic said the scenario "requires the user grant the command explicit permission" and is outside its threat model. The 93% figure is in Anthropic's auto-mode post. No independent coverage could be searched; both are the researcher's own sources, re-read. | https://checkmarx.com/zero-post/bypassing-ai-agent-defenses-with-lies-in-the-loop/ ; https://www.anthropic.com/engineering/claude-code-auto-mode |
| 7 | Auto-mode classifier sees only user messages and tool calls; 0.4% FPR on 10,000 real actions, 17% FNR on 52 overeager actions; stops after 3 consecutive or 20 total denials | corrected | Numbers and thresholds are right. Two details differ in the current product docs: (a) the classifier also receives CLAUDE.md content, and read-only tool calls are excluded; (b) at the threshold auto mode pauses and falls back to manual prompting rather than stopping the session, and a non-interactive `-p` run does not terminate: "the action doesn't run and Claude keeps working. Claude Code doesn't stop the run." The March 2026 post said headless runs terminate; the docs supersede it. Thresholds are not configurable. | https://code.claude.com/docs/en/permission-modes |
| 8 | Prompt injections in an untrusted agent's output consistently evade LLM monitors; resampling amplifies the attack; best SHADE-Arena monitor AUC 0.87 | confirmed | arXiv 2510.09462 v2 (2026-03-02) abstract matches, including that Defer-to-Resample "backfires". The threat model assumes the untrusted model knows the protocol and the monitor. The 0.87 AUC (Gemini 2.5 Pro as monitor) is from the separate SHADE-Arena paper. | https://arxiv.org/abs/2510.09462 ; https://arxiv.org/abs/2506.15740 |
| 9 | CAEP 1.0 (final 2025-08-29) defines session-revoked, credential-change, risk-level-change and five other events with `initiating_entity` admin/user/policy/system; SSF 1.0 delivers signed SETs by push or poll | confirmed | Eight event types; the other five are token-claims-change, assurance-level-change, device-compliance-change, session-established, session-presented. OpenID Foundation announced final approval on 2025-09-02. On "signed": SSF 1.0 itself contains no MUST-sign (`jwks_uri` is required only "if the Transmitter intends to generate signed JWTs"). The RS256, 2048-bit signing mandate is in the CAEP Interoperability Profile, which is still a draft. Our receiver should reject unsigned SETs by its own policy. | https://openid.net/three-shared-signals-final-specifications-approved/ ; https://openid.net/specs/openid-caep-interoperability-profile-1_0.html |
| 10 | Windows Job Objects/WFP and macOS Endpoint Security AUTH events/Network Extension can implement kill, pause, deny and network quarantine for agent process trees | corrected | Feasible, but not as stated. Kill: `TerminateJobObject` is documented, and children join the job by default, except those created through `Win32_Process.Create` (WMI) or allowed to break away. Pause: Windows has no documented job-wide suspend; the freeze information class (`JobObjectFreezeInformation`, 18) exists only in unofficial headers. Deny: Job Objects do not deny individual actions; that needs a minifilter or kernel callbacks. Quarantine: WFP ALE filters key on application file name and user, not on a process tree, so tree scoping needs a callout driver or a per-agent token/SID. macOS: Endpoint Security has no kill or pause call, and a client that misses an event deadline may be terminated, so a human approval cannot be held on an AUTH event. `NEFilterDataProvider` (macOS 10.15+) gives per-flow pass/block. Linux `cgroup.freeze` and `cgroup.kill` re-confirmed. | https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects ; https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale- ; https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline ; https://github.com/winsiderss/phnt/blob/master/ntpsapi.h |

**Further statements checked in the brief**

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Section 4: after 3 consecutive or 20 total blocks Claude Code "stops and escalates; headless runs terminate" | corrected | Outdated. Current docs: interactive sessions fall back to manual prompting, and approving the prompt resumes auto mode; `-p` runs deny the action and keep going. Do not cite "headless terminates" as vendor precedent for our denial breaker. | https://code.claude.com/docs/en/permission-modes |
| TL;DR and section 6: Elastic's rules are Elastic License v2 "and cannot be embedded" | corrected | Overstated. ELv2 grants the right to use, copy, distribute and prepare derivative works. It forbids offering the software as a hosted or managed service, circumventing licence keys, and removing notices. The rules cannot be relicensed into an Apache or MIT core or shipped in a hosted offering, but redistribution under ELv2 terms is allowed. | https://github.com/elastic/detection-rules/blob/main/LICENSE.txt |
| TL;DR: Claude Code server-managed settings refresh hourly; OCSF 1.9.0 Incident Finding; Dogwood is Apache-2.0 Rust, created 2026-07-27 | confirmed | Server-managed settings are fetched at startup and polled hourly; a failed fetch continues without them unless `forceRemoteSettingsRefresh` is set. OCSF 1.9.0 was released 2026-08-03 (1.10.0 in development). The Dogwood repository exists with the stated licence, language and creation date. | https://code.claude.com/docs/en/server-managed-settings ; https://github.com/ocsf/ocsf-schema/releases ; https://github.com/dogwood-policy/dogwood |
