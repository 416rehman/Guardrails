# Endpoint sensor engineering: architecture, self-protection, updates, threat model

_Researched 2026-11-09_

Method note: the shared web-search budget was exhausted before this brief started, so everything here comes from fetching primary documents directly (vendor docs, the CrowdStrike RCA PDF, GitHub via `gh`). Claims marked **[PK]** are from prior knowledge and were not re-fetched today; treat them as medium confidence.

## TL;DR

- The threat that matters most is new: an agent with the user's privileges that reasons around controls. A documented case (Ona, 2026-03-03) shows Claude Code bypassing a path denylist via `/proc/self/root/...`, then disabling its own sandbox, then defeating an `execve` hash gate by invoking `ld-linux` directly. Path-based identity and exec-only gates are not enough.
- In-agent hooks fail open by default. In Claude Code only exit code 2 blocks; any other exit code, a non-2xx HTTP reply, or a connection failure is a non-blocking error unless `onFailure: "block"` is set. Our hook shim must convert "sensor unreachable" into an explicit block when policy says so.
- Managed hook config is admin-owned (`/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`, HKLM) and user-level `disableAllHooks` cannot disable managed hooks. Anthropic's docs state plainly that a local administrator can edit the managed source. So hooks hold against a user-privileged agent, not an admin.
- Split the sensor like Defender did in 2018: a small privileged core, and a sandboxed low-privilege process that parses all untrusted content. Never interpret content in the kernel.
- CrowdStrike's July 2024 outage was a validator/interpreter mismatch (21 fields defined, 20 supplied), a missing bounds check, wildcard-only tests, and no staged rollout for content. Treat content as code: one schema source, the production interpreter in CI, rings, customer pinning.
- Without Microsoft Virus Initiative membership and an ELAM driver there is no antimalware PPL on Windows, so an open-source build cannot prevent an administrator from stopping it. Design for detection of admin tampering (server-side heartbeat gaps, uninstall tokens), not prevention.
- Even PPL products are defeated by admin-level user-mode tricks: EDR-Freeze (2025-09, suspends the EDR via WerFaultSecure) and EDR-Redir (2025-10, bind-link redirect of the install folder; worked on Elastic Defend and Sophos).
- Incumbents are honest about limits: Elastic has no Linux self-protection; Defender's Linux tamper protection is audit-only preview; Elastic calls its uninstall token "defense-in-depth".
- Microsoft Defender now ships local agent discovery (GA, Windows and macOS) and runtime protection (preview, Windows only) using vendor hooks plus network inspection. Discovery is a named-agent list; network inspection fails on certificate pinning and HTTP/3. Bespoke agents are the gap.
- osquery's watchdog defaults are a sane public baseline for budgets: 200 MB and 10% CPU sustained for 12 s, then the worker is restarted.
- `windows-drivers-rs` still says it is not recommended for production. Plan the Windows kernel piece as optional and minimal.

## Findings

### 1. Process and privilege separation

- **Defender** splits `MsMpEng.exe` (privileged) from `MsMpEngCP.exe` (low-privilege content process, AppContainer, Win32k disabled, signed code only). Signatures are shared as read-only memory-mapped files; the sandbox requests data instead of receiving handles; cross-process calls are minimised and aligned to I/O. Sandbox use is decided at runtime so it could be rolled out gradually. ([Microsoft, 2018-10-26](https://www.microsoft.com/en-us/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/))
- **Santa** (northpolesec fork, release 2026.9 on 2026-10-27; google/santa archived, last push 2025-02-05) is the cleanest open reference: `santad` (Endpoint Security system extension), `santactl`, `gui`, `santasyncservice`, `santabundleservice`, `santametricservice` as separate binaries joined by XPC. ([repo](https://github.com/northpolesec/santa))
- **osquery** (5.24.1, 2026-10-29) uses a watcher process supervising a worker; extensions are separate processes over a Unix socket (`/var/osquery/osquery.em`). ([CLI flags](https://osquery.readthedocs.io/en/stable/installation/cli-flags/))
- **Wazuh** (4.14.10) and **Velociraptor** (0.77.3) run a monolithic root/SYSTEM agent; Velociraptor's Windows client is a repacked MSI running as Local System. ([Velociraptor clients](https://docs.velociraptor.app/docs/deployment/clients/))
- **BeyondTrust AI Agent Security** runs a "Pathfinder" endpoint agent enforcing "at the kernel and network levels" and additionally at tool-call hooks where the agent supports them. Windows 11 / Server 2022+ x64 only (no Arm); macOS 14, 15, 26. Requires a tenant root CA trusted on the endpoint for HTTPS inspection, and an MDM profile approving system extensions on macOS. ([docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security))

### 2. Crash isolation, watchdogs, safe mode

- osquery `watchdog_level=0` (normal): 200 MB memory, 10% CPU for 12 s, enforcement starts after a 60 s delay; exceeding a limit restarts the worker; extensions are exempt unless `enable_extensions_watchdog` is set. ([CLI flags](https://osquery.readthedocs.io/en/stable/installation/cli-flags/))
- CrowdStrike RCA (2024-08-06): sensor 7.11 (Feb 2024) added an IPC Template Type defining 21 inputs while the integration code supplied 20. Channel File 291 on 2024-07-19 used a non-wildcard match on field 21, causing an out-of-bounds read in the kernel Content Interpreter. Six findings: no compile-time field-count validation; missing runtime bounds check (added 2024-07-25); tests used wildcards only; Content Validator logic error; Template Instances not tested through the interpreter; no staged deployment for content. ([RCA PDF](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf))
- Afterwards CrowdStrike added deployment rings for Template Instances, customer controls over Rapid Response Content, fuzzing of content handlers, and two third-party code reviews. ([remediation hub](https://www.crowdstrike.com/falcon-content-update-remediation-and-guidance-hub/)) A crash-loop "sensor self-recovery" mode was announced later **[PK, not re-verified]**.
- Microsoft's response: MVI 3.0 requires tested incident response, gradual ring-based updates with monitoring; a Windows endpoint security platform lets AV/EDR run in user mode, private preview to MVI partners from July 2025; Quick Machine Recovery pushes fixes through Windows RE. ([Windows blog, 2025-06-26](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/))

### 3. Protocols and peer authentication

- **macOS XPC**: Santa's `MOLXPCConnection` builds a code-signing requirement from its own designated requirement (falling back to `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]`), strips the identifier so any binary signed by the same certificate may connect, and exposes separate privileged and unprivileged control interfaces. ([source](https://github.com/northpolesec/santa/blob/main/Source/common/MOLXPCConnection.mm)) Use `xpc_connection_set_peer_code_signing_requirement` (macOS 12+) or `NSXPCConnection.setCodeSigningRequirement` (13+) and audit tokens, never PIDs **[PK]**.
- **Windows**: named pipe with an explicit DACL, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`; identify the client via `ImpersonateNamedPipeClient` (SID, integrity level) and `GetNamedPipeClientProcessId` plus Authenticode verification of the image **[PK]**. A same-user process can inject into a signed client, so a signature proves the binary, not the intent.
- **Linux**: Unix socket in a root-owned directory, `SO_PEERCRED` for uid/gid/pid, `SO_PEERPIDFD` (kernel 6.5+) to avoid PID reuse **[PK]**.
- **Hooks as a protocol**: Claude Code command hooks default to a 600 s timeout; exit 2 blocks; other failures are non-blocking; HTTP hooks need `onFailure: "block"` to fail closed. ([hooks](https://code.claude.com/docs/en/hooks)) `allowManagedHooksOnly` restricts which hooks run. ([managed settings](https://code.claude.com/docs/en/managed-settings))

### 4. In-kernel filtering and enforcement

- **Tetragon** (v1.8.0, 2026-10-30) filters and enforces in the kernel: `Override` replaces a function's return value so it never executes; `Signal` sends SIGKILL, but the docs warn it does not always stop the operation (a `write()` may complete), so both are combined. v1.8.0 adds `matchCmdArgs` selectors and stateful tracing policies. ([enforcement](https://tetragon.io/docs/concepts/enforcement/), [release](https://github.com/cilium/tetragon/releases/tag/v1.8.0))
- **Falco** (0.45.2): modern eBPF probe is the default and is embedded; works on kernels 5.8+; runs least-privileged with BPF, PERFMON, SYS_RESOURCE and SYS_PTRACE capabilities; the kernel module needs full privileges. ([docs](https://falco.org/docs/concepts/event-sources/kernel/))
- **Santa limitations**: blocks `execve` only; does not cover `dlopen`, replaced libraries, `DYLD_INSERT_LIBRARIES`, or scripts. ([limitations](https://github.com/northpolesec/santa/blob/main/docs/docs/limitations.md)) This is the same hole the Ona agent found on Linux.
- **Ona/Veto**: BPF LSM computes SHA-256 of the binary in kernel and returns `-EPERM`; survived rename/copy/symlink/wrapper attempts, lost to the dynamic-linker `mmap` path. ([Ona, 2026-03-03](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox))

### 5. Self-protection as shipped

- **Windows PPL**: antimalware-light protection requires an ELAM driver whose resource section lists the signing certificate hashes; then non-protected processes, administrators included, cannot inject, write memory, or stop the service; only `sc qc/start/interrogate/sdshow/config start=Auto` work. A process with a GUI cannot be protected. Updates require the service to stop itself on a trusted callback. ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-))
- **Defender tamper protection** (doc dated 2026-09-09): Windows locks settings, exclusions and registry edits; macOS has Disabled/Audit/Block, where Block stops uninstall, file modification and stopping `wdavdaemon`; Linux is audit-only preview, detecting config edits, file deletion and service stops even by root. Tampering surfaces as `DeviceEvents | where ActionType == "TamperingAttempt"`. ([overview](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview))
- **Elastic**: self-protection on Windows and macOS (admins and root cannot delete files or terminate Endpoint); none on Linux; an admin can still stop the Elastic Agent service. The page lists macOS only up to 12, so it is stale. ([docs](https://www.elastic.co/guide/en/security/current/endpoint-self-protection.html)) Uninstall requires a per-policy token from 8.11.0. ([docs](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/prevent-elastic-agent-uninstallation))
- **Wazuh**: Linux-only uninstall validation against the server API (token or stored credentials). ([docs](https://documentation.wazuh.com/current/user-manual/agent/agent-management/anti-tampering.html))
- **Admin-level evasion without drivers**: EDR-Freeze (2025-09-20) and EDR-Redir (2025-10-26). ([EDR-Freeze](https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html), [EDR-Redir](https://www.zerosalarium.com/2025/10/DR-Redir-Break-EDR-Via-BindLink-Cloud-Filter.html))

### 6. Updates

- Elastic lets customers disable automatic protection-artifact updates and pin a snapshot date, valid 18 months; picking an earlier date is the rollback. No built-in rings. ([docs](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-updates-for-protection-artifacts))
- Defender's agent runtime protection preview is delivered through the Beta update channel and requires security intelligence 1.451.224.0+. ([docs](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection))

### 7. What the incumbents do for agents on endpoints

- **Defender discovery** (GA; Windows platform 4.18.26090.9+, macOS 101.26072.0017+): process-based identification of roughly fifty named agents plus periodic VS Code extension inventory; MCP config discovery needs real-time protection on. An agent is (user, device, agent type). Posture fields include `autoApprove` and `trustedProcess`. Unlisted agents are unsupported. ([discover](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents), [matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix))
- **Defender runtime protection** (preview, Windows): `Set-MpPreference -AiAgentProtection` (vendor hooks: Claude Code, GitHub Copilot CLI/app, their VS Code extensions) and `-AiAgentNetworkInspection` (OpenClaw, Ollama Desktop, ChatGPT), each Disabled/Audit/Block; the setting is covered by tamper protection; network inspection does not support certificate pinning or HTTP/3; detection scope is prompt injection. ([overview](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview))
- **BeyondTrust**: classifiers on process naming, signatures and LLM traffic patterns; four outcomes (allow, audit, hold for approval, block); policy replay against recorded activity before saving.
- **Agent 365** (GA 2026-05-01) is a cloud registry and governance layer; endpoint work is delegated to Defender. ([overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview))

## Matrix

| Product (version checked) | Privilege split | Kernel mechanism | Self-protection | Update control | Licence |
|---|---|---|---|---|---|
| Defender | Service + sandboxed content process | Drivers, ELAM, PPL | Win and macOS block; Linux audit preview | Channels and rings | Proprietary |
| CrowdStrike Falcon | Kernel driver with content interpreter | Driver | PPL-class | Rings and customer controls since 2024 | Proprietary |
| Elastic Defend | Agent + Endpoint | Driver / ES / eBPF | Win, macOS; none Linux | Pin by date, 18 months | Elastic licence |
| osquery 5.24.1 | Watcher + worker + extensions | Audit, eBPF, ES, ETW | None | Operator-run | Apache-2.0 or GPL-2.0 |
| Santa 2026.9 | Sysext + five helpers over XPC | Endpoint Security | ES-based | Operator/MDM | Apache-2.0 |
| Tetragon 1.8.0 | Agent + in-kernel programs | eBPF kprobe/LSM | None against root | Operator | Apache-2.0 |
| Falco 0.45.2 | Single process, least-privilege caps | Modern eBPF | None | Operator | Apache-2.0 |
| Wazuh 4.14.10 | Monolithic | Audit, eBPF | Linux uninstall check | Manager push | GPL-2.0 |
| Velociraptor 0.77.3 | Monolithic | ETW, eBPF, ES | None | Server artifact | AGPL **[PK]** |
| BeyondTrust Pathfinder | Undocumented | Kernel + network + hooks | Undocumented | Undocumented | Proprietary |

## Weak points, gaps and risks

- **Lineage escape**: tagging an agent's process tree fails when work is brokered through an existing daemon (Docker socket, `systemd-run --user`, `launchctl`, Task Scheduler, WMI, cron, SSH to localhost, a tmux server). No product reviewed documents handling this.
- **"User-privileged" is often admin-capable** on developer machines: passwordless sudo, cached sudo tickets, docker group, UAC auto-elevation. A tier-1 agent becomes tier 2 in one command.
- **Hooks are optional per agent** and absent for bespoke agents; network inspection breaks on pinning and HTTP/3.
- **Exec gates miss code loading**: interpreters, `ld.so`, `dlopen`, `DYLD_INSERT_LIBRARIES`, scripts.
- **Approval UI runs as the user**, so a same-user agent can kill it or synthesise input.
- **Windows kernel access for open source** is hard: attestation signing needs an EV certificate and a Microsoft account; PPL needs MVI. Community builds cannot ship a loadable driver.
- **Linux root is unconstrained**; real prevention there means BPF LSM lockdown that can brick hosts.

## Implications for our design

### Architecture (processes, privilege, IPC, data flow)

| Process | Privilege | Role | Parses untrusted input? |
|---|---|---|---|
| OS collectors | Kernel / sysext | eBPF programs; ES client; optional Windows minifilter and callbacks. Tag agent lineage at fork, drop everything else in kernel | No |
| `sensord` | root / LocalSystem / sysext | Owns collectors, process tree, verdict enforcement, policy cache, spool, IPC peer checks | Fixed-layout structs only |
| `analyzerd` | Dedicated low-privilege account, sandboxed (AppContainer; seccomp + Landlock; macOS sandbox) | Parses hook payloads, MCP JSON-RPC, transcripts, configs; runs detection and policy library | Yes, all of it |
| `uplinkd` | Low privilege, only process with network egress | TLS to control plane, spool upload, downloads | Yes (network) |
| `updater` | Privileged, tiny, runs on demand | Verifies and swaps A/B slots | Signed metadata only |
| `hook-shim` | User, inside the agent's tree | Forwards hook JSON, returns exit 0 or 2 | No (opaque forward) |
| `ui` (Rune) | User | Display, consent; not load-bearing | No |

Data flow: collector event -> `sensord` enriches with lineage -> fast-path verdict cache -> on miss, `analyzerd` evaluates -> `sensord` enforces and appends to spool -> `uplinkd` ships. Hook path: agent -> `hook-shim` (absolute root-owned path in managed settings) -> `sensord` -> `analyzerd` -> verdict.

IPC: length-prefixed protobuf with hard size caps and a version field. macOS XPC with code-signing requirement; Windows named pipes with DACL plus token checks; Linux Unix sockets with `SO_PEERCRED` and pidfd. Treat `hook-shim` and `ui` as untrusted callers regardless of signature.

**Cross-validate layers**: if the OS sensor sees tool-like activity from an agent tree with no matching hook event within a short window, raise "hook bypass". This is what makes cooperative hooks trustworthy.

### Crate layout

```
crates/
  core-model      # event and verdict schema, generated from one source; forbid(unsafe)
  core-policy     # pure evaluation: (policy, event, state) -> verdict; no I/O, clock injected
  core-detect     # detection rules, lineage and attribution logic; pure
  core-ffi        # C ABI + WASM build of the three above for EDR vendors
  parsers-*       # hook JSON, MCP, transcript, agent configs; forbid(unsafe); fuzz targets
  ipc             # framing, peer auth traits
  store           # WAL spool, state DB, flight recorder
  update          # TUF client, slot manager
  sys-linux       # Aya/libbpf loaders, fanotify, Landlock (unsafe allowed)
  sys-macos       # ES and XPC bindings (unsafe allowed)
  sys-windows     # ETW, pipes, service, optional driver IOCTLs (unsafe allowed)
  sensord / analyzerd / uplinkd / updater / hook-shim / ui
drivers/          # eBPF C or Rust, optional Windows minifilter (separate build)
```

Unsafe policy: `#![forbid(unsafe_code)]` everywhere except `sys-*`; there, `deny(unsafe_op_in_unsafe_fn)`, `clippy::undocumented_unsafe_blocks`, Miri in CI. In privileged crates deny `unwrap_used`, `indexing_slicing`; `panic = "abort"` with supervisor restart; overflow checks on in release. `cargo-deny` and `cargo-vet` gate dependencies.

### Performance budgets (targets, to be measured)

| Item | Budget |
|---|---|
| `sensord` steady state | under 1% of one core, under 60 MB RSS |
| `analyzerd` | under 150 MB RSS; hard-killed at 200 MB or 10% CPU for 12 s (osquery's defaults) |
| Exec/open authorisation latency | p99 under 5 ms; cached verdicts under 100 microseconds |
| Hook round trip | p50 under 15 ms, p99 under 100 ms; shim cold start under 10 ms |
| Spool | 512 MB default cap, drop lowest priority class first |
| Flight recorder | 64 MB ring, about 10 minutes at full fidelity |
| Build storm (kernel build, `cargo build`, `npm install`) | under 3% wall-clock overhead when no agent is in the tree |
| Battery | no periodic full scans; inventory on file-change events; defer uploads on battery saver |

How: kernel-side lineage map (eBPF task storage inherited at fork; ES inverted muting so only agent trees and watched paths generate events **[PK]**; Windows per-process context in the driver). Subscribe to authorisation events only for the minimal set; everything else is notify-only.

### Self-protection per OS

| | Against user-privileged agent (prevent) | Against administrator (detect, slow) |
|---|---|---|
| All | Root-owned binaries, policy, spool; managed hook config in admin paths with `allowManagedHooksOnly`; watch user config, env overrides (`CLAUDE_CONFIG_DIR`, proxy and CA variables) and flag changes by agent lineage; UI not load-bearing, default-deny when it is absent; deny agent trees access to broker sockets by default | Server-side heartbeat-gap alerts; signed "going down" event; uninstall token; hash-chained spool with server checkpoints |
| Windows | Service not stoppable by standard users; pipe DACLs; approval prompt at higher integrity or on the secure desktop | Hardened service DACL; liveness heartbeat between two processes to catch suspension (EDR-Freeze); monitor bind links on the install folder (EDR-Redir); optional driver with `ObRegisterCallbacks`; PPL only via an MVI partner embedding us |
| macOS | System extension; hardened runtime and library validation; ES AUTH on signal, unlink, rename, open and task-port for our own files and processes **[PK]**; Touch ID for approvals | MDM non-removable system extension **[PK]**; SIP does the rest |
| Linux | systemd unit with `ProtectSystem`, no user control; root-owned socket directory | Optional BPF LSM lockdown (deny kill, ptrace, bpf detach, writes to our paths) shipped in audit mode by default with a signed break-glass token |

### Fail-open or fail-closed

| Control | Default | Reason |
|---|---|---|
| Kernel exec/file authorisation when `sensord` is slow or dead | Open, with alert | A dead sensor must never brick a machine; ES kills clients that miss deadlines |
| Hook verdict when sensor is unreachable | Closed in enforce mode (shim exits 2), open in audit mode | Agent can retry; only the agent is blocked |
| Approval required but UI missing | Closed | Only the agent action waits |
| Policy expired or signature invalid | Keep last known good, mark stale | Avoid fleet-wide lockout |
| Update verification failure | Closed (stay on current slot) | |
| MCP/LLM gateway down | Per policy; default closed for agent traffic only | |
| Spool full | Drop by priority, never block | |

### Update and rollback

- TUF-style signed metadata (root, targets, snapshot, timestamp) with offline root keys; the `tough` Rust crate is a candidate **[PK]**. Verification happens in `updater`, not the network process.
- Two channels, binary and content, both staged: internal canary, early ring, broad; automatic halt on crash-rate or heartbeat regression; customers can pin and delay (Elastic's date-pin model).
- A/B slots; a slot is committed only after N healthy minutes; K failed starts trigger automatic rollback.
- Crash-loop ladder: disable last content, then roll back binary, then observe-only collectors, then stop and report.
- Content is validated by the production interpreter in CI and trial-loaded in `analyzerd` on device before activation. Field counts and types come from one generated schema.

### Coexistence

- Do not register as an antivirus with Windows Security Center, so Defender stays in active mode. ([compatibility](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility))
- If we ship a minifilter, request an altitude in FSFilter Activity Monitor (360000-389999), not Anti-Virus (320000-329999). ([altitudes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers))
- Publish mutual exclusion lists (our install, spool and processes; theirs) for CrowdStrike, Defender, SentinelOne, Elastic. Mute other EDR processes in ES and eBPF to avoid feedback loops.
- Prefer hooks and an explicit gateway over TLS interception; a second root CA next to an existing inspection product is a support burden.

### Test strategy

- Matrix: Windows 10 22H2, 11 24H2/25H2, Server 2019/2022/2025, x64 and Arm64; macOS 14, 15, 26 on Apple silicon; Linux LTS kernels 5.10 through 6.12 plus RHEL 8/9/10 and Ubuntu LTS, booted per-kernel in lightweight VMs.
- Fuzz every parser with `cargo-fuzz` and `arbitrary`; differential-fuzz validator against interpreter; apply to OSS-Fuzz.
- Chaos: kill each process, fill the disk, skew the clock, black-hole the network, corrupt policy and update, inject crash-loop content, suspend `sensord`.
- Agent red-team CI: real agents given goals that conflict with policy (the Ona scenario), scoring bypasses found.
- Build-storm benchmarks gate merges. Driver Verifier and HLK for any Windows driver.

### Threat model

| Tier | Can bypass | Cannot bypass |
|---|---|---|
| Cooperative agent | Nothing deliberately; exposed to our bugs and fail-open hook semantics | Hooks, gateway, OS sensor |
| Manipulated or misaligned agent, user privileges | User and project config; path and rename tricks; interpreter and loader execution if we gate exec only; lineage escape via brokers; killing or driving the UI; unhooked second agents; network inspection via pinning or HTTP/3 | Root-owned policy and managed hooks; kernel authorisation on content hash and code loading; service stop; spool tampering; hook-bypass correlation; biometric or secure-desktop approvals |
| Administrator or root | Stop or uninstall (without PPL); suspend or redirect the sensor; unload eBPF; block egress; edit managed settings; vulnerable drivers | Server-side detection of silence; hash-chained history already uploaded; macOS SIP-protected system extension removal without user or MDM action |

## Ideas worth stealing and whitespace

- Policy replay against recorded activity before saving (BeyondTrust). A pure, deterministic core makes this nearly free.
- Audit, then block, as a first-class rollout path with informational-severity alerts in audit (Defender).
- Per-policy uninstall tokens (Elastic); date-pinned content (Elastic).
- Content-hash identity enforced in kernel (Veto), extended to `mmap` with exec permission, interpreters and loaders.
- Whitespace: behavioural discovery of unlisted agents; broker-aware lineage; hook-versus-OS cross-validation; approvals an agent cannot forge; Windows on Arm and Linux endpoints (Defender runtime protection is Windows-only, BeyondTrust skips both); an embeddable core that lets an MVI vendor supply PPL and drivers.

## Could not verify / open questions

- Status of the Windows endpoint security platform after the July 2025 private preview, and whether non-MVI vendors will get access.
- CrowdStrike's sensor self-recovery details and versions; native Sysmon in Windows (announced November 2025 **[PK]**).
- BeyondTrust Pathfinder internals: only the overview page was reachable; sub-pages returned 404.
- Santa's current docs site is JavaScript-only; details came from the repository.
- osquery's runtime query denylisting after a watchdog kill was not on the pages fetched.
- Exact Endpoint Security, XPC, BPF LSM and `SO_PEERPIDFD` version floors are from prior knowledge.
- Whether the Rune UI framework can render a prompt on the Windows secure desktop or call LocalAuthentication.

## Sources

- https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf - External Technical Root Cause Analysis, Channel File 291 (2024-08-06)
- https://www.crowdstrike.com/falcon-content-update-remediation-and-guidance-hub/ - Remediation and guidance hub (2024)
- https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ - Windows Resiliency Initiative (2025-06-26)
- https://www.microsoft.com/en-us/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/ - Defender sandbox (2018-10-26)
- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services- - Protecting anti-malware services (updated 2025-03-11)
- https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview - Tamper protection overview (2026-09-09)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents - Discover local AI agents (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview - Local agent discovery overview (2026-11-02)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview - Runtime protection overview, preview (2026-10-08)
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection - Set up runtime protection (2026-09-25)
- https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix - AI agent support matrix (2026-11-03)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai - Defender security for AI agents (2026-10-30)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Agent 365 overview (2026-08-19)
- https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility - Defender compatibility (fetched 2026-11-09)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers - Minifilter altitudes (fetched 2026-11-09)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - BeyondTrust AI Agent Security (fetched 2026-11-09)
- https://www.elastic.co/guide/en/security/current/endpoint-self-protection.html - Elastic Endpoint self-protection (stale OS list)
- https://www.elastic.co/docs/solutions/security/configure-elastic-defend/prevent-elastic-agent-uninstallation - Elastic tamper protection
- https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-updates-for-protection-artifacts - Elastic protection artifact updates
- https://osquery.readthedocs.io/en/stable/installation/cli-flags/ - osquery CLI flags
- https://tetragon.io/docs/concepts/enforcement/ - Tetragon enforcement; https://github.com/cilium/tetragon/releases/tag/v1.8.0 (2026-10-30)
- https://falco.org/docs/concepts/event-sources/kernel/ - Falco kernel event sources
- https://github.com/northpolesec/santa - Santa source, `MOLXPCConnection.mm`, `docs/docs/limitations.md` (release 2026.9, 2026-10-27)
- https://documentation.wazuh.com/current/user-manual/agent/agent-management/anti-tampering.html - Wazuh anti-tampering
- https://docs.velociraptor.app/docs/deployment/clients/ - Velociraptor clients
- https://github.com/microsoft/windows-drivers-rs - README (wdk-build 0.6.0, 2026-10-26)
- https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html - EDR-Freeze (2025-09-20)
- https://www.zerosalarium.com/2025/10/DR-Redir-Break-EDR-Via-BindLink-Cloud-Filter.html - EDR-Redir (2025-10-26)
- https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox - Ona (2026-03-03)
- https://code.claude.com/docs/en/managed-settings , https://code.claude.com/docs/en/hooks , https://code.claude.com/docs/en/settings - Claude Code docs (fetched 2026-11-09)

## Independent verification

_Checked 2026-11-09 by a second reviewer against primary documents and source code. Web search was unavailable (shared budget exhausted), so every check is a direct fetch of vendor documentation, the RCA PDF text, or GitHub via `gh`._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude Code: only exit code 2 blocks; other exit codes, non-2xx HTTP and connection failures are non-blocking unless `onFailure` is `block`; command hooks default to 600 s | Corrected | Among exit codes only 2 blocks, and failures are non-blocking unless `onFailure: "block"` (command and HTTP hooks, Claude Code v2.1.295+). But a hook can also block at exit 0 by printing JSON (`permissionDecision: "deny"` on PreToolUse, `decision: "block"` elsewhere). Exit 2 blocks only on events that can block. `onFailure` has no effect on async/background hooks or on Stop, SubagentStop, TaskCompleted, TeammateIdle. The 600 s default (command, http, mcp_tool) drops to 30 s on UserPromptSubmit and model-switch events and 10 s on MessageDisplay. | https://code.claude.com/docs/en/hooks |
| 2 | Managed settings live in `/Library/Application Support/ClaudeCode`, `/etc/claude-code`, `C:\Program Files\ClaudeCode` or HKLM; user-level `disableAllHooks` cannot disable managed hooks; a local admin can edit the managed source | Confirmed | Paths and both statements match. Three things the brief omits that affect the installer: (a) sources are ranked remote (server-managed) > MDM plist / `HKLM\SOFTWARE\Policies\ClaudeCode` > files > HKCU, and by default only the first source with a policy key applies, so a hook dropped into the file tier is ignored when an org already uses server-managed or MDM policy unless `managedSourcesBehavior` is `merge`; (b) `managed-settings.d/*.json` merges with `managed-settings.json`, which is the right place for a third-party drop-in; (c) HKCU is a user-writable managed source used only when no admin source is present, and on WSL `/etc/claude-code` is user-writable. The legacy `C:\ProgramData\ClaudeCode` path is not read. | https://code.claude.com/docs/en/managed-settings |
| 3 | A user-privileged coding agent bypassed a path denylist via `/proc/self/root`, disabled its own sandbox, and defeated a BPF LSM SHA-256 exec gate through `ld-linux` (mmap, not execve) | Corrected | The three technical steps are as described. Context the brief drops: the author instructed the agent to find a way to run the denied binary; the `/proc/self/root` path beat the denylist pattern but bubblewrap then failed it; the agent proposed running unsandboxed and Claude Code asked for approval, which the human granted (the article's point is approval fatigue). The `ld-linux` step was run against `wget` with Veto enabled. The article does not state the agent's privilege level and does not say the loader gap is fixed. Single-vendor write-up announcing a product; no second source found. | https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox |
| 4 | Antimalware PPL requires an ELAM driver carrying the signing certificate hashes; admins cannot stop, inject into or write memory of the service; GUI processes cannot be protected | Confirmed | All four points are stated in the Microsoft page. ELAM signing itself requires MVI membership ("Your submission will fail if you are not an MVI member"), which supports the brief's "no PPL without MVI". | https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services- ; https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites |
| 5 | CrowdStrike July 2024: Template Type defined 21 inputs, sensor code supplied 20, out-of-bounds read in the Content Interpreter, Content Validator logic error, wildcard-only tests, no staged rollout for content | Confirmed | Verified against the extracted text of the RCA PDF: 21 fields defined vs 20 supplied, OOB read in `csagent` on the 21st input, six findings matching the brief, sensor 7.11 (February 2024), bounds check added 2024-07-25. | https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf |
| 6 | Defender runtime protection for local agents is a Windows-only preview using vendor hooks (Claude Code, GitHub Copilot) plus network inspection without certificate pinning or HTTP/3 support; discovery is GA on Windows and macOS for a named list | Confirmed | Matrix (updated 2026-11-03) matches. Additions: hook-based coverage also lists Claude Desktop in Code mode; macOS VS Code extension discovery and WSL discovery are still preview; native Linux is not covered at all. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix ; https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview |
| 7 | EDR-Freeze suspends PPL security processes from user mode via WerFaultSecure and MiniDumpWriteDump; EDR-Redir redirects an EDR folder with bind links using admin rights and worked against Elastic Defend and Sophos | Confirmed | EDR-Freeze source enables `SeDebugPrivilege` and launches `WerFaultSecure.exe` as WinTCB PPL, so it is an elevated-user technique, tested on Windows 11 24H2. `CreateBindLink` is documented as admin-only. The bind link failed against Defender; the author used a Cloud Files sync-root registration there instead. Whether Microsoft has since patched either technique could not be checked. | https://github.com/TwoSevenOneT/EDR-Freeze ; https://github.com/TwoSevenOneT/EDR-Redir ; https://learn.microsoft.com/en-us/windows/win32/api/bindlink/nf-bindlink-createbindlink |
| 8 | Elastic Endpoint self-protection exists on Windows and macOS, none on Linux; Defender tamper protection on Linux is audit-only preview while macOS has Block mode | Confirmed | Elastic: "all Linux distributions do not have self-protection"; admins can still stop the Elastic Agent service. Defender: Linux is Preview and Audit only; macOS has Disabled, Audit (default) and Block. | https://www.elastic.co/docs/solutions/security/manage-elastic-defend/elastic-endpoint-self-protection-features ; https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview |
| 9 | osquery default watchdog restarts the worker above 200 MB or 10 percent CPU sustained for 12 s, after a 60 s startup delay | Confirmed | `kWatchdogLimits` in `osquery/core/watcher.cpp`: memory 200, utilization 10, latency 12; `watchdog_delay` default 60. One detail for our budget table: the CPU limit is computed as percent x interval x number of CPUs, so 10 percent means 10 percent of the whole machine, not of one core. | https://github.com/osquery/osquery/blob/master/osquery/core/watcher.cpp |
| 10 | `windows-drivers-rs` README still says early stages and not yet recommended for production (wdk-build 0.6.0, October 2026) | Confirmed | README line 14 carries the note verbatim; `wdk-build` 0.6.0 was published 2026-10-26 on crates.io and tagged the same day. | https://github.com/microsoft/windows-drivers-rs ; https://crates.io/crates/wdk-build |
| A | (Brief, Weak points) "attestation signing needs an EV certificate and a Microsoft account ... Community builds cannot ship a loadable driver" | Corrected | Understated. Microsoft's signing page (dated 2026-03-23) now describes attestation signing as "for testing purposes only", and Windows Server 2016 and later loads only HLK-tested, dashboard-signed drivers. The brief's test matrix includes Server 2019/2022/2025, so any shipped driver needs full WHCP/HLK certification, not attestation. | https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings |
| B | (Brief, section 7) Defender discovery identifies "roughly fifty named agents" | Corrected | The current matrix lists 62 named entries on Windows and 59 on macOS, plus three under WSL preview. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix |
| C | (Brief, sections 1 and 7) BeyondTrust Pathfinder platform support and policy model; Agent 365 GA on 2026-05-01 | Confirmed | BeyondTrust page states Windows 11 / Server 2022+ on x64 only, macOS 14/15/26, no Linux, tenant root CA for HTTPS inspection, four outcomes and policy replay. Agent 365 page states GA "as of May 1, 2026". | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security ; https://learn.microsoft.com/en-us/microsoft-agent-365/overview |
