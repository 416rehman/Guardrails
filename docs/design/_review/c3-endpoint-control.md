# Review C3: endpoint control (D-13 to D-23, P1, P3, P9, AL0 to AL4)

Decision challenger, 2026-11-10. References are `research/NN-*.md`; "verification" is each brief's closing table.

## Summary

The direction holds. The claims built on top do not. The assurance ladder is drawn as a total order, but containment, system-wide blocking, observation and failure behaviour vary independently and per action class. On Windows and macOS the stated means do not reach the stated levels for agents we did not launch, and the hook broker's install and failure rules contradict verified vendor behaviour. The change that matters most: replace the single ordinal with a per-action-class assurance record that separates opt-in from mandatory containment, and derive AL0 to AL4 from it as a label.

## Findings

### F1. AL0 to AL4 is not a ladder (assurance levels; wrong; blocker)

**Problem.** AL3 and AL4 are independent. A BPF LSM host running a hookless bespoke agent is "AL4" with no claims to cross-check; a Seatbelt-launched agent is AL3 with no observation. Reach differs per action class: fanotify blocks open and exec but not write, unlink or rename; Endpoint Security has no documented network authorisation. AL3 also says nothing about whether the agent can start outside the container.

**Evidence.** 14 section 3 and verification row 9; 13 section 1; 12 "Weak points" bullet 3.

**Amendment.** Replace the definition with: "Assurance is a record per device, agent instance and action class: `visibility` (none, claimed, observed, cross-checked), `control` (none, request, scoped-boundary, mandatory-boundary), `on_failure` (open, closed), `tamper` (user, admin, platform). AL0 to AL4 is a label computed by a published function over the record. Cedar reads the record, never the label." Add the third class to P1: a scoped boundary holds only for processes that entered it.

### F2. Windows AL3 without kernel code is opt-in only (D-17, D-21; wrong; blocker)

**Problem.** User-mode WFP matches path, user SID or package SID, never a process instance, so every Phase 0 control keys on a principal only a launcher can assign, and nothing forces agents through it. Cursor starts from the shell; IDE extensions share `Code.exe` with the human's terminal. A dedicated local user loses the human's DPAPI secrets, and sandbox-runtime's Windows mode breaks Schannel clients.

**Evidence.** 10 verification "Findings 4"; 12 section 5 and weak point 3; index 38 correction 2.

**Amendment.** In D-17 replace "This reaches AL3 with no kernel code" with: "This gives scoped-boundary control to processes that enter by one of four routes: `grd run`; the agent's process-wrapper setting; the agent's own sandbox, whose principals we enumerate and key filters on; a hook `updatedInput` rewrite of a shell call into the launcher. Agents that enter by none stay at request level until the Phase 1 driver or a host EDR supplies process-create control." Add a per-agent entry table; move user-mode WFP to M2.

### F3. Vendor flags cannot deliver fail-closed per rule class (D-14 with D-15; wrong; major)

**Problem.** `onFailure: "block"` and `failClosed` apply to a hook entry, not a rule class. Setting "every vendor fail-closed flag" means a missing, quarantined or crashed shim blocks every tool call, though D-15 says the rest allow and log. Codex has no flag: a kill, a timeout, exit 2 with empty stderr or an `ask` reply all let the tool run.

**Evidence.** 15 verification rows 1, 3 and 4; 36 line 30.

**Amendment.** Add to D-14: "The shim carries a signed last-known-good floor bundle and evaluates fail-closed classes itself when the daemon is unreachable. Vendor fail-closed flags are set only on entries whose matchers cover those classes." Add to D-15: "Each adapter publishes its achievable failure mode per agent version, proven by the conformance suite. Where closed is not achievable, the class is backed by a boundary or the instance reports `on_failure: open`."

### F4. Hook install meets first-wins, the managed-only lock and standalone (D-14; wrong; major)

**Problem.** Under Claude Code's default `first-wins`, a file drop-in is skipped without warning when a server-managed or MDM source carries any policy key. Setting `allowManagedHooksOnly` silently stops the user and plugin hooks of Zscaler, Palo Alto, Noma and 1Password, contradicting D-23. A standalone user-level install cannot write admin paths. The fan-out broker needs other vendors to register.

**Evidence.** 15 verification C; 37 verification row 2; h03 line 179; 27 line 114; vendor managed-settings page, read 2026-11-10.

**Amendment.** Replace the install sentence with: "The installer reads which managed source is selected and installs there, or emits the snippet for the admin's MDM or server source and requires `managedSourcesBehavior: merge`; a skipped source is a Degraded state. `allowManagedHooksOnly` is never set by default; when policy sets it, foreign hooks found at install are re-hosted as broker providers. Standalone installs in user scope and reports tamper `user`. The broker must be useful with one provider."

### F5. Whole-agent sandboxes do not compose with the agents' own (D-21, D-19; wrong; major)

**Problem.** Landlock filesystem rules deny `mount` and `pivot_root`, so Codex's default bubblewrap and Claude Code's sandbox should fail inside our Landlock launcher (spike S2). Nested Seatbelt is a listed conflict. The ES descendants client is not a sandbox: it needs the Apple entitlement, drops every restriction when the client exits, and a non-root supervisor stops the subtree running `sudo`.

**Evidence.** Kernel Landlock documentation, "Current limitations" (fetched 2026-11-10); 14 TL;DR bullet 6; 13 matrix (Seatbelt launcher row), verification rows 3 and 4.

**Amendment.** Replace D-21's first sentence with: "Every session gets a session container, which is attribution only. Containment is one of three modes chosen per agent from the catalogue: delegate (configure and lock the agent's own sandbox, verify at exec), wrap-tools (launch tool subprocesses in ours), wrap-agent (only for agents with no sandbox of their own)." Move the descendants client to D-18 tier three as launch-scoped authorisation with a kill-subtree watchdog.

### F6. macOS tiers contradict coexistence (D-18 with D-23; wrong; major)

**Problem.** D-18 ships a DNS proxy; D-23 forbids taking that slot, which ZTNA clients usually own. A full ES client cannot hold for a human: only descendants clients may raise the deadline floor. Santa's inverted muting does not follow a tree across exec. Until the ES entitlement arrives macOS has no supported process event stream, so D-13's cross-check and P3 do not apply.

**Evidence.** g05 TL;DR bullet 4; 13 section 1 "Deadlines", verification rows 6 and 7.

**Amendment.** In D-18 strike "and DNS proxy" and add: "content filter at a grade chosen by the slot broker; DNS proxy only when the slot is free and policy opts in. Full ES clients never hold for a human: `STEP_UP` becomes deny with a grant and retry. Tiers one and two report `visibility: claimed` for exec and file." Replace "inverted muting to watch only agent trees" with "our own tree follower that re-selects the exec target on every exec".

### F7. Linux tier list misses one tier and overstates another (D-19; risky; major)

**Problem.** The verifier found a no-reboot synchronous deny on Ubuntu 22.04 and 24.04 through `fmod_ret` or kprobe override on `security_*`; the spine skips it. fanotify has no permission event for write, unlink, rename or create, allows every pending event when the listener closes, and a stalled listener blocks every opener on a marked filesystem. "Destructive actions fail closed" is unreachable there.

**Evidence.** 14 verification "Fallback ladder (1)" and row 9; 14 section 3.

**Amendment.** Order the tiers: BPF LSM; `fmod_ret` or kprobe override on `security_*`; cgroup BPF network plus fanotify marks on the protected-path set only; launch sandbox; observe. State per tier which action classes can be blocked. Holds are capped (default 30 seconds), then become deny with a grant and retry.

### F8. "No matching tool call" is not a tamper signal by itself (D-13, P3; risky; major)

**Problem.** P3 cites Origin's 27 missed executions, but 26 were harness housekeeping (`git`, `tasklist`, `reg query`), not tool calls. MCP servers, LSP servers and the human's `!` commands share the lineage. Evaluating one policy twice also needs a rule for how a hook-level approval reaches the OS check, or the user is asked twice.

**Evidence.** 01 verification row 4; 15 verification row 6; 15 "Deliverable 3".

**Amendment.** Reword D-13: "The hook evaluates intent and issues an expectation bound to tool-use id and process key. The OS control point evaluates effects against floor rules and that expectation, and honours the same grant. Hook dark (an agent process with no session-start event within N seconds) is a tamper detection. An unmatched effect is scored against the agent's catalogued baseline and labels the session." Cheapest test: 50 scripted benign sessions per M1 agent, counting unmatched effects.

### F9. Standalone's single user-level daemon voids self-protection (D-20, D-22; wrong; major)

**Problem.** A daemon running as the user can be killed, replaced or read by an agent running as that user, so "prevent against user-level agents" is false in the first release. On developer machines the agent is often one command from admin (cached sudo, docker group, UAC auto-elevation). One process in M1 and five later leaves IPC boundaries untested until M2.

**Evidence.** 37 "Weak points" bullet 2, threat-model and architecture tables.

**Amendment.** D-20: "Process topology is fixed from M1 (core, engine, shim over the real IPC); only privilege varies. The core holds a compiled floor policy so fail-closed classes never wait on the engine." D-22: "The prevent goal applies only where the core runs as root or SYSTEM. Elevation gateways (sudo, pkexec, docker socket, launchctl, schtasks, UAC) are a protected action class for agent lineage, Ask by default."

### F10. No decision on adopting agents already running (missing; major)

**Problem.** The spine promises a container "at launch or first sighting"; the means differ. Linux can migrate a tree into a new scope. Windows can add a running process to a job object but cannot replace its primary token, so no sandbox SID, WFP rule or deny ACL applies. macOS cannot apply Seatbelt from outside.

**Evidence.** 12 matrix row "Process start"; 13 section 1 "Descendants client"; 17 line 169.

**Amendment.** Add D-21a: "Adoption gives attribution, not containment. An adopted session is `control: request` at most until restarted through the launcher. Policy may deny credential release (D-27) to sessions that are not contained."

## Spikes

| Question | Method | Pass criteria |
|---|---|---|
| S1. Which M1 agents work under a Windows sandbox principal? | Windows 11 24H2: run the four M1 agents by each F2 route, under MXC and under a dedicated user with a SID-keyed WFP fence; script sign-in and git push | Three of four finish with the fence holding; else narrow the claim to wrap-tools |
| S2. Do agent sandboxes survive inside ours? | Claude Code (sandbox on), Codex and Cursor inside outer Landlock (kernels 6.8, 6.12, 7.0) and outer Seatbelt (macOS 26, 27) | Inner sandbox applies and the task completes; a failure fixes that agent to delegate mode |
| S3. What does each hook do on failure, and does our entry load? | Per M1 agent: kill, stall and delete the shim, stop the daemon, return `ask` to Codex; repeat on Claude Code with an MDM source present | Results match the published table; a tool run on a fail-closed class marks the agent `on_failure: open` |
| S4. Is there a no-reboot deny on stock Ubuntu? | 22.04 and 24.04, x64 and arm64: `fmod_ret` on `security_file_open` by cgroup; fanotify on the protected set with a 30-second hold; kernel build | Synchronous deny, no deadlock on listener stall, build overhead under 3% |

## Agreed

- D-16: no mandatory TLS interception (38, g05).
- D-17: driverless first; WESP and PPL only through an MVI member (12).
- D-18: three tiers; Network Extension under a Developer ID needs no Apple request (13 verification row 5).
- D-19: Linux as reference; LSM, VFS and socket hooks; io_uring denied in launch sandboxes.
- D-20: untrusted content parsed outside the privileged core (37).
- D-22: prevent against users, detect against administrators, on privileged installs.
- D-23: slot broker, no exclusive slots, coexistence pack (g05).
- D-14: command shim, peer credentials, Claude Code dialect (15).
