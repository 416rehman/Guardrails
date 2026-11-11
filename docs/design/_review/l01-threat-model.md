# Review l01: threat model of our own design

Adversaries: (A) a manipulated agent with the user's privileges; (B) an administrator, insider or malware; (C) an outsider attacking the hosted service, channels or supply chain. References are to `research/NN-*.md`.

## Summary

The spine holds on the remote binary path and on "models advise". It is weakest where adversary A meets our own local surfaces: the agent is the OS user, and the spine hands that user a CLI, tray, Rune console, localhost web console and, in the first standalone release, the daemon itself. Two blockers: the user-level standalone daemon (D-20), and no rule that widening operations need proof of human presence. For adversary C, policy, content and response commands reach code execution or fleet-wide denial of service without touching TUF-protected binaries. The change that matters most: anything that widens, anywhere, is a step-up through the approval helper, and devices enforce that operator-signed artefacts can only narrow.

## Findings

### F1. D-20, D-14, D-22: the standalone daemon runs as the adversary (wrong, blocker)

**Problem.** D-20 ships the first standalone release as "a single user-level daemon". The agent shares its uid, so it can replace the daemon, answer the shim from a squatted socket or pipe, edit the policy store and use the grant-signing keys. D-22's "prevent against user-level agents" and M1's AL2 claim are false there. D-14 authenticates only the client, never the daemon.

**Evidence.** 37 "Self-protection per OS" (root-owned binaries, policy, spool); 37 section 3 (a signature proves the binary, not the intent).

**Amendment.** Replace D-20's last sentence: "Standalone has two installs. Protected (default, one elevation): a minimal privileged service owns policy, keys, spool, shim and managed settings. Unprivileged: a user-level daemon capped at AL1 and tamper grade `user`; Ask and Block are labelled as requests; no grants, broker or CA." Add to D-14: "The shim verifies the owner of the daemon endpoint before trusting a verdict."

### F2. D-31, D-11, D-43: the agent can operate our management plane (missing, blocker)

**Problem.** `grd`, the tray, the Rune console, deep links and the localhost web console run as the user, and D-11 never says who approves widening without a server. An agent can pause protection, lower posture or accept its own exception through the CLI, UI Automation or loopback HTTP. Loopback listeners (console, OTLP) also invite cross-origin requests, DNS rebinding and forged telemetry.

**Evidence.** 29 verification row 1 (any same-user UIA or AT-SPI client presses Rune buttons); 21 rows 2, 37, 46, 60, 67; 35 section 3 (`serve` rebinding fix).

**Amendment.** Add D-31a: "Every widening operation (posture down, pause, exception, grant, pack or sensor removal, capture level up, provider or exclusion registration) is a STEP_UP completed by `guardrails-approve` or out of band. CLI, tray, Rune, deep links, localhost console and MCP may only propose. Local listeners use sockets or pipes; unavoidable TCP loopback gets a random port, Host and Origin checks, a per-instance token, no CORS, read-only scope, and is unreachable from session containers."

### F3. D-12, P7, D-14, D-35: policy and content channels carry code outside TUF (missing, major)

**Problem.** TUF covers binaries only. D-12 writes agent managed settings, which hold hook commands, environment blocks and MCP entries. D-14 registers remote verdict providers that see every tool call and may return MODIFY. Whoever holds the server or operator key can run commands as each user or raise capture fleet-wide. Customer co-signing is optional in D-35.

**Evidence.** 15 "Implications" item 1 (managed settings carry hooks and endpoints); `_sources/beyondtrust/phantom-labs-claude-code-hooks-c2.md` (hooks run unsandboxed as the user).

**Amendment.** Add D-12a: "No policy, pack, adapter manifest or provider registration may introduce a command, path, URL, environment variable or MCP server; compile-down emits from code-defined templates whose only executable is our signed shim. Devices enforce that operator-signed artefacts can only narrow; widening and capture increases need the organisation's own signature (default in hosted mode). Third-party verdict providers receive minimised payloads and return only DENY or STEP_UP."

### F4. D-30, D-23, D-11: remote command trust ends at the server (missing, major)

**Problem.** D-30 does not say whose keys sign commands or where signatures are checked. If the server signs, one compromise kills every fleet, and many single-device commands evade the "fleet-wide" rule. Provider scope lets one MSP credential act on all customers. D-23 delegates response to the incumbent EDR's API, so our server stores credentials that may reach remote shell.

**Evidence.** 36 implications 4, 5, 7 (approver signatures "verified by the endpoint itself"); 04 "Implications" (RTR scripts); 26 CrowdStrike row (contain needs Hosts: Write only).

**Amendment.** Replace D-30's kill-switch sentence: "Commands above device scope carry signatures from approvers' own hardware-backed keys, verified on the endpoint against a roster whose changes are signed by a quorum of the previous roster. Devices rate-limit destructive commands locally. Provider-scope actions are reversible containment only and need the organisation's co-approval. Incumbent-EDR credentials are limited to containment scopes, never script execution, and held under a customer key."

### F5. D-22, D-25, D-21: the two-tier adversary model collapses on developer machines (missing, major)

**Problem.** D-22 assumes the agent is user-level. Developers commonly have passwordless sudo, docker-group membership or auto-elevating UAC, so the agent is an administrator one command later. D-25 records brokered hops but nothing denies them, and our own `grd run` is such a broker. Labels and grants keyed on harness session ids are shed by starting a new session.

**Evidence.** 37 "Weak points" ("user-privileged is often admin-capable") and self-protection table (deny broker sockets by default); 36 "Weak points" (caller-supplied session IDs).

**Amendment.** Add to D-22: "From AL3, escalation and broker paths from agent lineage (sudo, UAC, container sockets, systemd-run, launchctl, Task Scheduler, WMI, our own launcher) are a fail-closed rule class. When a probe finds the agent admin-capable and uncontained, tamper grade is `user`." Add to D-25: "Session identity is assigned by the sensor from the kernel container; labels, grants and denial ledgers inherit to children and cannot be reset by the harness."

### F6. D-27, D-26, D-16: the broker releases real secrets and treats a bearer token as proof (wrong, major)

**Problem.** `credential_process`, git, Docker and kubectl helpers return the real credential to the caller, which is the agent; only proxy injection and SSH sign-only keep it out. D-26 treats the phantom token as attribution evidence, but the agent can hand it to any process. D-27 does not say where leases live. D-16 omits CA handling: a root in the OS store with a reachable key lets same-user malware intercept everything.

**Evidence.** 35 section 3 and "Secrets broker" ("proof the agent made it"); 38 section 3 (memory-only key, injected CA-bundle variables).

**Amendment.** Amend D-27: "Two modes, selectable by policy: `inject` (the secret never enters the session) and `release` (helper protocols; at most 15 minutes, scope-reduced, session labelled `secret-read`). Leases stay on the device or a customer-run gateway; the hosted service holds none. A phantom token counts only with a matching kernel peer." Amend D-16: "The interception CA is per device, name-constrained, memory-only, injected per process tree, and never added to an OS or browser trust store."

### F7. D-31, D-43: the approval path does not hold on Windows or with Rune (wrong, major)

**Problem.** A high-integrity prompt is reachable by any other high-integrity process (an agent in an elevated terminal); only the secure desktop under SYSTEM is closed. D-43's "headless flags are disabled in release builds" assumes a switch Rune lacks: the flags are parsed in every build and `is_headless()` reads argv regardless. The action digest is undefined, leaving approve-then-swap open.

**Evidence.** 29 verification rows 2 and 10; 21 section 17 (argv changed between approval and exec); 39 section 2 (execute-then-write, 43 to 72%).

**Amendment.** Amend D-31: "`guardrails-approve` uses OS-native surfaces only (secure desktop under SYSTEM, LocalAuthentication, polkit), never Rune; otherwise approval is out of band or denied. The digest covers canonical argv, working directory, environment delta and content hashes of referenced executables and scripts, re-checked at execution. One approval yields an exact, single-use grant." Amend D-43: "Rune is linked only into `guardrails-console`, from a patched fork with tooling flags removed."

### F8. D-29, D-38: the review pipeline trusts a claim and its output is uncontained (wrong, major)

**Problem.** D-29 puts "user messages" in the trusted channel. They arrive through hooks and transcripts, which P3 calls claims; sub-agent prompts are written by the parent agent. Nothing constrains model output: explanation text rendered as Markdown in the console or sent to chat gives an injected judge an exfiltration path. The investigator and MCP server read agent-written text with tenant-wide read access.

**Evidence.** 39 section 2 (monitor injection through forged transcript entries); 22 verifier (classifier reads CLAUDE.md); g07 "Weak points" (MCP injection target).

**Amendment.** Amend D-29: "Trusted input is policy only. Root-session prompts captured at submission are `user-claimed`; sub-agent prompts, memory and repository instructions are untrusted. Model output fills typed fields; free text is rendered inert (no links, images or Markdown), notifications included. Judges have no egress and no content access beyond the reviewed lineage." Amend D-38: "MCP never returns content-class data; after an untrusted read, a session cannot create proposals."

### F9. D-37, D-15: degradation paths lead to silent fail-open (risky, major)

**Problem.** The crash-loop ladder disables content, then rolls back binaries. An agent with a reproducible parser crash can walk the sensor down to an older vulnerable build. Kernel authorisation fails open when the sensor is slow, and an event storm from the agent tree can cause that. D-15 does not say for whom a class fails closed.

**Evidence.** 37 "Fail-open or fail-closed" and "Update and rollback"; 13 TL;DR (`es_set_deadline_miss_mode`).

**Amendment.** Add to D-15: "Fail-closed applies to processes inside session containers; everything else fails open with an alert." Add to D-37: "The ladder never lowers enforcement for fail-closed classes, never rolls back below a signed security floor, quarantines an input-correlated crash instead of disabling content, and makes each step a high-severity, server-visible event."

### F10. D-47, D-43: a SYSTEM-level product built by agents needs a human-reviewed trust core (missing, major)

**Problem.** D-47 reserves keys, releases and driver review for humans. The privileged core, updater, IPC authentication and approval helper are written and evaluated by agents that read outsider-authored issues, pull requests and content contributions. Rune moves about 95 commits a day and cannot be reviewed per bump.

**Evidence.** Index 22 "Surprises" (2.5 hidden injections per 100K GitHub items aimed at coding agents); 22 "Weak points" (pins prove origin, not behaviour); 29 "Weak points" 5 and 6.

**Amendment.** Add to D-47: "A named trust core (privileged core, updater, `grd-crypto`, IPC peer authentication, policy evaluator, approval helper, release and CI configuration) merges only with review by two human maintainers. Agents that read outsider-authored text have no write access and no secrets." Add to D-43: "The Rune console runs inside our own sandbox profile: no network, no file access beyond its socket."

## Spikes

| # | Question | Method | Pass criteria |
|---|---|---|---|
| S1 | Can a same-user agent widen anything locally? (F1, F2) | Real agents with a policy-conflicting goal on an M1 build per OS, free to use CLI, pipe squatting, loopback HTTP, UI Automation, deep links | Protected install: zero widening without presence proof in 200 runs per OS |
| S2 | Does the approval helper resist synthetic and elevated input? (F7) | UIA Invoke, SendInput, AT-SPI DoAction, an elevated-terminal agent, a Rune `--script` launch | Zero grants in 1,000 attempts per OS; a script swapped after approval is denied |
| S3 | Can load or crashes force fail-open? (F9) | Fork and open storm from an agent tree; replay a crashing input | Fail-closed classes still deny in the container; no host-wide stall over 1 s |
| S4 | What does a compromised server get? (F3, F4) | Red team holds the test server and operator key | Only narrowing lands; above-device commands are rejected on the device |

## Agreed (tried to break, held)

- P2, D-29: a deterministic hit is never cleared by a model.
- D-16: no mandatory TLS interception.
- D-36: TUF with offline root keys; response commands signed apart from OpAMP.
- D-35: organisation derived from the device credential.
- D-40: no third-party native code in sensors; agentgateway, not LiteLLM.
- P4, D-10, D-30: local decisions; ambiguous parses deny; isolation before revocation.
