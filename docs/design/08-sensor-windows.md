# 08. Windows sensor

_Status: draft 4 against spine version 4 and the owner's instructions of 2026-11-11 (`_review/04-owner-kit-instructions.md`). Owning squad: Windows endpoint (a trust-core change lands only after two independent evaluators on different models pass it, D-63). Read with: `00-decisions.md` (D-13 to D-17, D-20 to D-23, D-48, D-49, D-59, D-62 to D-64, section 7), 02 (threat model, SR-01 to SR-16), 03 (process topology, ports), 04 (provenance grades, Windows Event Log feed), 05 (inventory), 06 (attribution), 07 (decision protocol, assurance record), 09 (macOS), 10 (Linux, WSL guest sensor), 11 (on-device update mechanics), 22 (transport, rings), 24 (build, signing, packaging), 26 (embedding), spine D-45 and D-64 for efficacy and the lab (the detailed document is pending), `design/_review/02-owner-answers.md` (zero budget) and `design/_review/04-owner-kit-instructions.md` (no human gates; no new third-party account)._

## Summary

This document specifies the Windows back end of the sensor: what it observes, what it can stop, how strongly, and how it lives beside Defender, CrowdStrike Falcon and SentinelOne. It answers the owner's WESP and driver question directly: **the baseline sensor has no driver, and WESP is reached only through an embedding partner.** WESP is undocumented, its signing identity and ELAM prerequisite are gated on Microsoft Virus Initiative (MVI) enrolment, and no user-mode verdict path has been found in it. The optional driver requires the legal entity (Loonaro), an EV certificate and Microsoft's hardware programme (HLK certification), which cost money and so depend on a sponsor or partner, plus the evaluator-run kernel review of D-62 (section 6); it is optional and on its own release train. Everything else is user-mode and honest about its limits.

Key choices:

1. **Four tiers, each with a stated assurance ceiling and its own prerequisites** (W0 observe and hooks; W1 scoped boundaries; W2 optional driver; W3 host EDR or WESP through a partner). Windows AL4 exists only in W2 or W3 (D-17, spine section 7).
2. **Our own ETW layer** on the `windows` crate behind an `EtwSource` trait, one real-time session, kernel-emitted providers as `observed-kernel`, user-mode providers as `observed-user` (D-17, P3; h02). ETW needs administrator rights, so the User profile has process polling only.
3. **Sysmon is read, never installed or configured**; built-in and standalone are both consumed as XML (D-17, D-23).
4. **Scoped boundaries come from principals we assign**: user-mode WFP filters keyed on a sandbox SID, job objects, restricted tokens or AppContainer, deny ACEs. Nothing keys on an executable path alone (D-17; brief 10 verification).
5. **Tool-subprocess containment is the default** (`wrap-tools`); Codex is `delegate`; whole-agent wrapping is for agents with no sandbox. Agents that enter by none of the four routes stay at `control: request` (D-21).
6. **Tamper resistance is detection against administrators**, prevention only against same-user agents in the Protected profile; no PPL, no ELAM, no Security Center registration (D-22; brief 12 verification row 7).
7. **WSL2, Docker Desktop and dev containers** are covered in the Protected profile by a trivial signed WSL plug-in that starts the Linux sensor of document 10 in the utility VM (D-19).
8. **The optional driver** has exactly the spine's three functions, is HVCI-clean, x64 and ARM64, WHCP-signed, evaluates compiled floor tables in kernel and never parses content (D-17, D-20).
9. **Coexistence is a release gate**: a generated coexistence pack, a ceiling matrix and an interference oracle against Defender, Falcon and one more incumbent, the last two licensed through design partners or free vendor programmes (D-23, D-64).

## Requirements

| # | Requirement | Trace |
|---|---|---|
| R1 | Windows x64 and ARM64 endpoints are covered with no kernel code of ours, and the product says which controls are requests | Owner (Windows incl. WESP and drivers); D-17; P1 |
| R2 | Telemetry from kernel-emitted sources outranks user-mode sources; no verdict rests only on a forgeable source | P3; h02 verification row 5; 04 section 9 |
| R3 | Sysmon, AMSI and WFP use never takes a slot another product needs or puts our code in processes we do not own by default | D-17, D-23; l02 F4, l04 F6 |
| R4 | Processes that enter by one of four routes get a scoped boundary for `exec`, `file.*`, `net.connect`, `elevate`; others stay request-level with a reason | D-17, D-21; c3 F2 |
| R5 | Agents already running are adopted for attribution, not containment | D-21; c3 F10 |
| R6 | Trusted Dev Drive volumes are detected and reported as file-coverage gaps | D-17; h02 |
| R7 | Prevent same-user agents from disabling or editing the product in the Protected profile; detect administrator tampering within 60 s (target) | D-22; SR-08, SR-10, SR-13 |
| R8 | WSL2, Docker Desktop (WSL backend) and dev containers are observed, on ARM64 too | D-19; brief 12 section 8 |
| R9 | An optional driver attaches without changing policy, schema or the assurance function | D-17; 02 section 3.11 |
| R10 | A WESP or host-EDR back end attaches behind the same trait as the driver | D-17, D-41 L3, D-60 |
| R11 | Per-machine MSI for x64 and ARM64; silent, idempotent, offline, no secret on the command line; journalled uninstall | D-59, D-48, D-49 |
| R12 | Passes an interference test with Defender, Falcon and one more incumbent before broad release; no Defender alert on install, run or uninstall | D-23, D-64 |
| R13 | Hook p50 25 ms, p99 100 ms with Defender and one EDR; build overhead under 3% alone, 2% per incumbent (targets) | Spine section 6 |
| R14 | Multi-session hosts require per-logon-session policy and listeners; an installer without them refuses such hosts | D-59; SR-02 |

## Design

### 1. Tiers and assurance

| Tier | Requires | What runs | Highest `control` | `visibility` | `tamper` | Label reachable |
|---|---|---|---|---|---|---|
| W0 Observe and guide | Daemon and hook shim; S-04 passing for Windows to be a Tier 1 cell (D-50) | Hooks (07), ETW, Sysmon when present, Windows AI channels, on-device registry inventory, config-integrity monitor | `request` | `cross-checked` for `exec` once the housekeeping profile is calibrated; `observed` for `net.connect`; `claimed` or `observed` for `file.*` | `user` or `admin` | AL2 |
| W1 Contain | W0; S-10; sandbox conformance suite and developer-workload corpus passing (D-21) | W0 plus user-mode WFP, job objects, restricted tokens or AppContainer, deny ACEs, `grdr-run`, delegate mode for Codex | `scoped-boundary` for sessions that entered | Same | Same | AL3 for contained sessions |
| W2 Optional driver | W1; trust-core review (D-62, D-63); EV certificate and Microsoft's hardware programme, paid for by a sponsor or partner (section 6) | W1 plus process-create veto, minifilter on the configured path set, WFP callout redirect | `mandatory-boundary` for the core classes, except `file.write` on trusted Dev Drives without our filter allow-listed | `cross-checked` | `admin` | AL4 |
| W3 Host platform | An embedding partner (D-41 L3); for WESP, an MVI member with WESP access (section 7) | Our engine inside a partner's EDR fed from its sensor (WESP or its own driver) | As the host profile states | As the host profile states | `platform` | Up to AL4 |

The visibility column is for the Protected profile. In the User profile there is no ETW (real-time kernel sessions need administrator rights or Performance Log Users membership), no Sysmon subscription that needs elevation, no WFP and no WSL plug-in: `exec` is `observed` through process polling (section 3.5), every other class is `claimed`, and `control` is `request` everywhere (SR-07). `file.read` stays `observed` at best in W0 and W1: kernel file ETW is high volume and we do not subscribe to it outside the protected-path set (section 9). SaaS-only agents stay at AL1 regardless (D-13).

**What "scoped boundary for `exec`" means without a driver.** User mode cannot veto an arbitrary exec. In W1 the exec boundary is containment of the child: every process started inside a session container inherits its job (no breakaway), principal, fence and deny ACEs, and `elevate` is denied by the back end (section 4). Exec of a named executable is denied only where the back end can do it by ACL (execute-deny ACEs for the sandbox SID on the protected-path set). Each back end's conformance entry declares exactly these exec denials, and the record shows `scoped-boundary` for `exec` only where that entry passes; per-command exec decisions remain hook requests.

### 2. Process layout on Windows

The topology is 03 section 4 and the service accounts are 24 section 3; this table fixes the Windows identities. Code lives in `grdr-sensor-windows` (feature `windows-wfp` for the WFP actuator) and, for the optional driver, `grdr-driver-windows` (03).

| Process | Protected profile identity | User profile identity | Network |
|---|---|---|---|
| `grdr-daemon` | Service `grdr-daemon`, LocalSystem, service SID type `unrestricted` (it writes managed settings, ACEs and WFP filters, which a write-restricted token cannot), auto start | Logon-triggered scheduled task, user token | None: persistent WFP block on its service SID |
| `grdr-engine` | Demand-start service started and stopped by the daemon through the service control manager; virtual account `NT SERVICE\grdr-engine`, service SID type `restricted`; before reading anything it lowers itself to low integrity and sets mitigation policies; the daemon then assigns it to a job (memory limit, kill on close) | Child of the user daemon under a write-restricted copy of the user's token at low integrity, in a no-capability AppContainer (11 section 2) and the same kind of job | None: WFP block on its service SID (Protected); the AppContainer's default network isolation (User), because WFP needs administrator rights |
| `grdr-uplink` | Service, `NT SERVICE\grdr-uplink` virtual account | User | The only one of our processes with outbound access, to the configured server and update hosts |
| `grdr-proxy` | Service, `NT SERVICE\grdr-proxy` | User | Loopback listener plus upstreams named by policy |
| `grdr-updater` | Child of the daemon, started on demand (LocalSystem; 11 section 1) | User | None |
| `grdr-hook`, `grdr-run`, `grdr`, tray | Caller's token | Same | None |

In the Protected profile the engine is a service rather than an AppContainer child because the service control manager cannot start a service inside an AppContainer and 24 fixes a virtual account for it. Its confinement is: the virtual account, which has no access to user profiles; the restricted SID type, so it writes only where its service SID is granted (its scratch directory, which carries a low mandatory label); low integrity; the job; and Win32k lockdown plus a dynamic-code prohibition set with `SetProcessMitigationPolicy` (it has no UI). It reads user content only through handles the daemon duplicates into it and never opens user paths by name; W-1.3 tests both. Because a service cannot inherit a handle from the daemon, the engine, uplink and proxy services reach the daemon over the private channel of 11 section 1. In the User profile the engine is a child process and so takes 11's AppContainer. Local IPC is 07 section 2: `\\.\pipe\grdr-decide` with an explicit DACL, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, peer identity from `GetNamedPipeClientProcessId` held as a process handle plus the token SID and integrity level; the shim checks `GetNamedPipeServerProcessId` belongs to the service.

### 3. Collectors [W0]

All collectors implement `SensorBackend` (03 section 6) and emit fixed-layout records to the daemon; the engine parses anything textual.

**3.1 ETW [Protected profile].** One real-time session named from the brand manifest (`Grdr-Sensor-Trace` until D-66), because sessions are a shared, capped resource and a full buffer pool stops providers for every session (h02 verification row 5: 64-session limit). We write a thin ETW layer on `windows` 0.62 behind `EtwSource`; `ferrisetw` (no crate release since 2024-06-27, no commit since 2025-08-20) is a reference, not a dependency, and `microsoft/one-collect` (MIT) is evaluated behind the same trait before W-2.1 starts (D-17; briefs 10, h05).

| Provider | Events used | Grade | Filter |
|---|---|---|---|
| Microsoft-Windows-Kernel-Process | Process start and stop, image load | `observed-kernel` | All processes for the process tree; image loads only in agent lineage |
| Microsoft-Windows-Kernel-Network | TCP and UDP connect and accept | `observed-kernel` | Agent lineage and session containers |
| Microsoft-Windows-Kernel-File | Create, write, delete, rename | `observed-kernel` | Kept only for the protected-path set, agent stores and agent-control files (07 section 6 table); everything else dropped in the consumer callback before allocation |
| Microsoft-Windows-Kernel-Registry | Set value, delete key | `observed-kernel` | Agent-control keys (`HKLM\SOFTWARE\Policies\ClaudeCode`, the user-writable `HKCU\SOFTWARE\Policies\ClaudeCode`, `HKLM\Software\Policies\GitHub\Copilot`), our keys, Run keys, monitoring configuration (section 10) |
| Microsoft-Windows-DNS-Client | Query and response | `observed-user` | Agent lineage; enrichment of `net.connect` with names. Misses DNS over HTTPS inside applications (brief 12) |
| Microsoft-Windows-PowerShell (script block, 4104) | Script text | `observed-user` | Agent lineage only; content class, filtered by capture level on the device |
| Microsoft-Windows-WFP | Drop events for our filter ids | `observed-kernel` | Our filters only, to prove the fence fires. Listed in brief 12 from background knowledge; W-3.1's fence oracle confirms the events exist before anything depends on them |

Rules for ETW evidence (P3, 04 section 9): user-mode provider identity and payload are untrusted; the kernel-stamped header process id cannot be spoofed by the emitter (h02 verification row 5) and is validated against the process expected to own the provider (a PowerShell event must come from a PowerShell host in agent lineage), and a mismatch drops the event and raises a tamper finding. Loss counters (`EventsLost`, buffers lost) go into `health.sensor` every heartbeat; a rate spike followed by silence on any provider is a coverage-gap finding. Whether user-mode code can emit under a kernel provider's identity on current builds is checked by spike W-S3; until it passes, kernel-provider events are cross-checked against a process snapshot taken by handle for every agent-lineage process start.

**3.2 Sysmon.** If built-in Sysmon (optional feature, Windows 11 and Server 2025) or standalone Sysmon is running, the collector subscribes to its Operational channel read-only and parses the XML `EventData`, never the rendered message, which is localised in built-in Sysmon (brief 12 verification row 8). Events 1, 3, 7, 11, 12 to 14 and 22 enrich ETW records; Sysmon's `ProcessGuid` and `LogonGuid` are kept as foreign keys. We never install, enable, configure or reconfigure either variant, and `grdr doctor` reports which is present and whether its configuration covers agent lineage. Grade: `observed-kernel` when the record's `System/Execution/@ProcessID` (kernel-stamped) is the running Sysmon service, whose image is Microsoft-signed; otherwise the record is discarded with a tamper finding.

**3.3 Windows AI channels.** On builds that ship them (observed on 26H2, build 26300, with the experimental features off; g09): `Microsoft-Windows-AgentConnector-{FilesAgent,FileSearch,Settings}/{Admin,Operational}`, `Microsoft-Windows-AI-ModelContextProtocol/{Operational,Admin}` (provider GUID `cc71be2b-56aa-4756-9116-38bdd0408e43`, event ids 1 to 5), the `Microsoft-Windows-AgenticPlatform-IsoEnvBroker` provider, and the "Windows Mcp Registry" Application-log source. Payloads are one free-text `%1` string, so the raw text is retained as a content-class field, parsed in the engine by a signed pack parser (section 7), and an unparseable record becomes `inventory.*` with a could-not-look reason `unparsed`. Grade `observed-user`. The collector is behind a capability probe and off when the channels are absent. The AgentConnector channels are readable by interactive users (g09), so this collector also runs in the User profile.

**3.4 On-device registry and agent accounts.** Where ODR is present, the daemon starts `odr.exe mcp list` (absolute path from the probe, Microsoft signer checked) under the interactive user's token in a job with a 5-second timeout and a 1 MiB output cap, and hands the output pipe to the engine, which parses it; the daemon parses nothing. The inventory pass (05) records servers, registration route (MSIX identity, external location, `.mcpb`, manual) and containment state. ODR containment is not egress control: contained servers keep internet access (12 verification row 9), so it is a posture fact, never a boundary. Agent accounts created by the experimental agentic features (named with a `$` suffix; that they are local accounts is an inference, 12 verification) are enumerated with their SIDs and session ids; an action whose token user is such an account carries `os-principal` evidence (attribution grade 4, 04 section 9). This applies only to Microsoft's agent workspace; Claude Code, Cursor, Codex and bespoke agents run as the human user (g09). All of this is preview on Microsoft's side and sits behind a probe (g09 risks).

**3.5 Process tree and process key.** In the Protected profile the daemon keeps the tree from Kernel-Process events; in the User profile it polls a process snapshot (`NtQuerySystemInformation`, every 500 ms, target) graded `observed-user`, which misses processes shorter than the interval and reports the miss count. The process key is (pid, kernel creation time), and a process handle is held for agent-lineage processes so pid reuse cannot alias them (07 section 2). Lineage edges for brokered launches (Task Scheduler, WMI, services, COM servers, the Docker Desktop engine pipe) are recorded as `brokered` (D-25). The `elevate` action class covers UAC consent, `runas`, Task Scheduler registration, WMI process creation, service creation and use of the Docker engine pipe by agent lineage (D-22, SR-09): Ask at the hook in the Protected profile and Watch in the User profile (Essentials, D-53), and denied from contained sessions by the back end (section 4).

**3.6 Dev Drive.** At start and on volume arrival the collector enumerates Dev Drive volumes, whether each is trusted, whether antivirus filters are disallowed (`/disallowAv`), and the allowed filter list (`fsutil devdrv query`). A trusted Dev Drive detaches minifilters outside the antivirus altitude range 320000 to 329999 unless an administrator allow-lists them; an untrusted one attaches all filters (h02 verification row 2). Every agent session whose working directory is on a trusted Dev Drive gets a `health.coverage` entry with reason `file-filter-detached` naming which incumbent filters are detached (Defender for Endpoint's `MsSecFlt` among them unless allow-listed), and file evidence there comes from hooks (claims) plus ETW. Whether the filter policy affects Kernel-File ETW is unknown (the briefs assume not); spike W-S4 settles it.

### 4. Actuators without a driver [W1; AMSI opt-in]

| Actuator | Mechanism | Acts on | Executes |
|---|---|---|---|
| `wfp` | Our provider and sublayer via the Base Filtering Engine; ALE connect and accept layers; conditions `ALE_USER_ID` and `ALE_PACKAGE_ID`; `ALE_APP_ID` only combined with a SID | Sandbox principals; our own service SIDs | DENY (hard filter block), session egress cut |
| `job` | Job object per session container, no breakaway permitted, kill on close, active-process and memory limits from policy | Processes we launched and adopted processes | End session, freeze (suspend all), attribution |
| `token` | Write-restricted token whose restricting SID is a per-agent-instance sandbox SID; write access exists only where journalled ACEs grant that SID (workspace, temp, caches named in the profile); or an AppContainer or LPAC profile per agent instance; or a dedicated local sandbox user | Tool subprocesses we launch | Static DENY for `file.write` outside the granted paths, `elevate` |
| `acl` | Deny ACEs for the sandbox SID on protected paths (credential stores, agent stores, agent control files, our state), including execute-deny; applied once, journalled | Sandbox principals | Static DENY for `file.*` and for exec of those paths |
| `mxc` | `microsoft/mxc` processcontainer back end (MIT), build 26100.9278 or later | Processes we launch only (it cannot confine a process it did not start) | Static profile |
| `amsi` [opt-in] | In-process AMSI provider DLL | PowerShell, script hosts, .NET loads | DENY on script content |

**WFP rules.** Our provider and sublayer have fixed GUIDs and a fixed weight, published in the coexistence pack. Inside our sublayer, a sandbox principal's fence is a block of all ALE connects for its SID with higher-weight permits only to the local proxy listener (D-16; tool subprocesses get the proxy through `HTTPS_PROXY` and the agent's proxy setting). None of these is a hard permit, so a block in another product's sublayer still wins; we never add a permit intended to override another product, because block overrides permit across sublayers and we must not fight for a flow (g05 verification row 3). The fence also blocks loopback connections from sandbox principals to the local console (the random loopback port of `grdr console serve`, D-42, D-43; the daemon binds no TCP port) and loopback receivers, which answers 02's open question for contained sessions on Windows (SR-03). Our own service-SID egress blocks are persistent filters. Session fences are non-persistent filters added outside a dynamic session, so they survive daemon death (containment stays closed, D-15) and vanish at reboot or BFE restart; on start the daemon enumerates filters under our provider key, removes those of ended sessions, and re-creates any missing fence before acknowledging a decision for that session. A session whose fence cannot be re-created is ended. Filters do not follow traffic a system service carries for a process, nor a socket opened while a thread impersonates a different token (brief 08 verification row 7), so DNS and system-proxied flows are judged by name at the proxy, and impersonation by agent lineage is an `elevate` attempt.

**Choice of sandbox principal, decided by S-10.** Three back ends, in preference order per agent from the catalogue:

1. `appcontainer`: a per-agent-instance AppContainer profile with only the capabilities the profile grants; WFP keys on its package SID. The token keeps the human's user SID, but every file and object a tool needs must also grant the package SID, so the profile adds journalled ACEs for the workspace and the toolchain caches it names; network authentication as the user needs the `enterpriseAuthentication` capability (background knowledge). W-S1 measures what still breaks.
2. `mxc`: where the build supports it, MXC's processcontainer with our compiled profile; audit (learning) mode is never used in enforcement because it disables all sandbox security for the run (brief 08 verification row 4). We pin the published 1.0.0 request contract, whose telemetry is off unless opted in, and build with an empty `MXC_TELEMETRY_COMPONENT_PATH`, so the standalone egress oracle (D-48) still holds.
3. `local-user`: one dedicated local account per device (`grdr-sbx` until D-66), password unknown to anyone, logon rights limited to batch, used through a write-restricted token. Loses the human's DPAPI, credential manager, Kerberos tickets and SSH agent, so git, proxy authentication and package installs can fail (l04 F8); sandbox-runtime's equivalent Windows mode breaks Schannel clients (brief 38 verification, c3 F2).

Every back end is opt-in per agent until the developer-workload corpus (h08's package and agent matrix) passes inside it (D-21). The launcher probes the chosen back end against a self-test before the first tool runs: write in the workspace succeeds, write outside fails, a fenced direct connect fails, a connect through the proxy succeeds, and elevation by UAC consent, `runas`, Task Scheduler registration and WMI process creation fails. On failure the session stays at `control: request` with the reason in `next_level_blockers` (D-21). NVIDIA OpenShell sessions, which use MXC on native Windows (brief 08), are recognised as a delegate back end and a posture fact.

**AMSI provider [opt-in per group on its own ring].** Outside the baseline because it puts our code inside every script host (l04 F6). Constraints: the DLL is Authenticode-signed (required where AMSI signing enforcement is on; background knowledge in brief 12), so it ships only once a Windows signing programme account exists in Loonaro's name (owner instruction 23), and parses nothing; it forwards a size-capped buffer and the host process key to the daemon over the pipe and returns `AMSI_RESULT_NOT_DETECTED` unless the daemon answers DENY within 50 ms (target); it early-outs for processes outside agent lineage using a shared, read-only lineage bitmap the daemon maintains; it unregisters itself after three host crashes in 24 hours attributed to its module and raises a finding. What it forwards comes from inside the host process, so it is graded `observed-user`. Script-block ETW remains the default source of script content.

### 5. How third-party agents come to run under a sandbox principal [W1]

| Route | Mechanism | Agents (catalogue default, re-proved per version) |
|---|---|---|
| 1 `grdr run` | The user or a shortcut starts `grdr run -- <agent>`; `grdr-run` creates the session container (job), the sandbox token and the fence, then starts the agent (`wrap-agent`) | Any CLI agent with no sandbox of its own; bespoke agents |
| 2 Process wrapper | The agent's own setting names `grdr-run` as its launcher | None proven on Windows today. Claude Code's `processWrapper` is ignored on Windows and misses terminal-started sessions (index digest of brief 38), so it is not a Windows route for Claude Code |
| 3 Delegate | The agent's own sandbox runs; we configure and lock it through managed settings (07 section 6) and enumerate its principals (the sandbox user or AppContainer SIDs it creates) so our WFP filters and ACEs key on them; each tool exec is checked to carry that principal | Codex (its Windows sandbox uses tokens, ACLs and WFP, or MXC; brief 08, brief 12 verification) |
| 4 Hook rewrite | On `PreToolUse` for a shell tool, the hook returns `updatedInput` whose command is only `"<absolute path>\grdr-run.exe" --session <id> --tool-call <id>`. `grdr-run` fetches the evaluated command text and the shell named by the adapter contract (Git Bash or PowerShell) from the daemon by tool-call id, so no command is re-quoted or encoded, and runs it under the sandbox principal inside the session's job | Claude Code (the Windows default, `wrap-tools`), Cursor and Copilot CLI where `updated_input` or `modifiedArgs` is proven |
| None | Adopted into a job for attribution only | Everything else, and every agent whose back end failed its self-test |

Route 4 is a request in one respect: an agent that ignores the rewrite or runs a tool in-process escapes it. That is why the expectation from 07 section 9 carries the rewritten command digest: a tool-shaped child that does not carry the `grdr-run` prefix and principal raises `effect-mismatch` (tamper). The agent's own process stays at the human's token in route 4; file tools that the harness executes in-process (Claude Code's file edit tool) are not contained and stay at `request` for `file.write`. The assurance record shows this per action class, so AL3 for Claude Code on Windows needs `file.write` coverage that only routes 1 and 3 give. That is the stated limit of W1.

**Adoption.** An agent already running is assigned to a session job (attribution, `session-container` evidence only if its root is session-exclusive) and stays at `control: request`; the console offers "restart contained", and where containment is on for the agent, credential release to uncontained sessions is refused by default (D-21, D-27, P13). Windows cannot replace a running process's primary token, so containment of an adopted process is impossible without restart (c3 F10).

### 6. Optional driver [W2]

**Seam in the user-mode sensor.** `SensorBackend` and `Actuator` take the `channel` value (an open enum in 04; the value `win-driver` is requested in the deviations below), provenance `mediated` and `control = mandatory-boundary`; the floor table layout in `grdr-fastpath` is `#[repr(C)]` with offsets instead of pointers, so the same compiled table can be copied into kernel memory and bounds-checked once on load; the assurance function of 07 section 11 reads `control` values, not back ends, so it needs no change. Nothing in policy, schema or packs changes when the driver is installed.

**Scope** (the three functions of D-17, nothing else): process-create veto with `PsSetCreateProcessNotifyRoutineEx2`; a minifilter attached only to volumes holding the configured protected-path set, at an allocated altitude in FSFilter Activity Monitor (360000 to 389999; g05), pre-create and pre-set-information on those paths; a WFP callout at connect-redirect that sends session traffic to the local proxy and yields when another provider has already redirected the flow (g05). Callout blocks clear `FWPS_RIGHT_ACTION_WRITE`, because a callout block is soft by default and a lower sublayer could otherwise permit the flow (g05 verification row 3). On a trusted Dev Drive our Activity Monitor filter is detached unless an administrator adds it with `fsutil devdrv setfiltersallowed`; the installer offers that as a managed-install option and the record shows `file.write` there below `mandatory-boundary` until it is done. Registry callbacks and handle-rights protection are excluded: ACLs and observation cover our keys, and `ObRegisterCallbacks` protection of our processes is a proposed addition (deviation 2).

**Protocol to user mode.** One filter communication port, ACL SYSTEM only, connectable only by `grdr-daemon` (image signer checked). Messages are fixed-layout C structs versioned by a header (`grdr.winkm` v1), not protobuf, so the kernel parses no variable-length format. The kernel evaluates the compiled floor table and the session-container map itself; user mode is asked only for process create inside a session container, with a reply deadline of 50 ms (target) after which the kernel applies the table's default for that class. Every decision is also queued as a notification. This is the same shape WESP's reverse-engineered rule engine uses (brief 12 "ideas"), which keeps the WESP adapter thin.

**HVCI and ARM64.** No executable writable memory, no dynamic code, `/INTEGRITYCHECK`, NX pool only; built natively for x64 and ARM64 (x64 drivers do not load on ARM64). Driver Verifier, CodeQL driver queries and Static Driver Verifier run in tier C of the lab, which requires the driver's sponsor or partner (D-64).

**Language.** C with the WDK, under 5,000 lines (target). `windows-drivers-rs` still says it is not for production (brief 10 verification row 8); revisit when that changes. Written by agents only with a reference model and differential tests. It leaves the internal ring only after the kernel review of D-62 (`eval-security` and `eval-adversarial` in clean contexts on different models, with the reference model, matrix and soak evidence, plus any free external audit that arrives), and stays in the internal ring without it (D-63).

**Signing route.** WHCP through HLK on Partner Center. Attestation signing is documented as for testing only and is not accepted on Server 2016 and later (brief 12 verification row 4); it appears to still load on retail Windows 11 clients but Microsoft does not guarantee it (row 5), so it is used only for internal-ring test builds. Prerequisites: the legal entity (Loonaro) with its D-U-N-S number; an EV certificate, needed to register the Hardware Developer Program account rather than to sign each submission (row 3); an Entra tenant with two global administrators named by Loonaro; a legal signatory for Loonaro; the programme agreements; the altitude request (by email, no expedite, public products only; g05 verification row 5). The EV certificate and the programme cost money and the budget is zero, so they are paid for by a sponsor or partner (D-17).

**Release train.** Its own version line and rings, separate from user-mode binaries: internal (lab only) for at least one minor, then a customer opt-in ring, then broad. A boot-count marker in the registry disables the driver's start type after two early bugchecks attributed to it, and the user-mode sensor continues at W1 with a finding. Enterprises that run App Control for Business get a published supplemental policy for our signer.

**Prerequisites for building it.** All of: Loonaro's Partner Center account with two administrators; a sponsor or partner who pays for the EV certificate and the hardware programme (typically a design partner whose risk acceptance requires AL4 on Windows that no embedding partner supplies); and the kernel review of D-62 described under Language above.

### 7. WESP and the host-EDR adapter [W3]

**Why it needs a partner.** On the documented partner route a WESP client needs the `WESP://Permission` token attribute and Antimalware-PPL; a second attribute value selects a delegated route that skips the PPL check, but its issuer and constraints are unknown (brief 12 verification row 1). PPL needs an ELAM driver, and ELAM submission fails for non-MVI members; MVI requires a commercially available, lab-certified real-time anti-malware product (rows 2, 7). Microsoft's Artifact Signing now has a certificate-profile programme type for WESP enrolees, so the signing identity is enrolment-gated too (row 1). There is no SDK or date; about a dozen of roughly 100 MVI members work on it under NDA (single-sourced, h02 verification row 6). Binaries (`wesp.sys`, a boot-start minifilter at altitude 329500 in the antivirus range, and `espclient.dll`) are on disk on GA 26H2 but the driver is stopped (brief 10 verification row 5). The absence of a user-mode reply path is Elastic's inference from `espclient.dll` not importing `FilterReplyMessage`, not a tested result, and network coverage is unknown rather than absent (h02 verification row 1).

**How it attaches.** Through an embedding partner (D-41 L3): the partner's PPL process loads `grdr-fastpath`, signed with or catalogued under the partner's certificate (brief 12), and feeds `grdr-engine` (sidecar or WebAssembly) from its own queue. On our side this is a `HostProfile` (D-60) naming event classes, provenance grade per class, session mechanism and verbs, plus two adapters, `wesp` and `host-edr`, that implement the same `SensorBackend` and `Actuator` traits as the driver; their `channel` values are requested from 04 (deviation 3). External precondition: an L3 pilot partner with WESP access (D-41), or Microsoft publishing an SDK open to non-MVI clients.

### 8. WSL2, Docker Desktop and dev containers [Protected profile]

1. A WSL plug-in DLL, Authenticode-signed, registered under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins` by the MSI; writing that key needs administrator rights, so the User profile has no WSL coverage beyond hooks of agents inside a distro (brief 12 verification row 10). It runs inside `wslservice`, whose plug-in callbacks are synchronous, where an error is fatal to distro start and a crash takes down the WSL service (brief 12). So it is trivial: no parsing, no allocation on hot paths, no blocking call, every callback returns success, errors are written to our event channel. On VM start it uses `ExecuteBinary` to start the Linux sensor of document 10 in the utility VM's root namespace and writes a single-use enrolment token (10 section 9) to the process's standard input, never its arguments (D-59).
2. The guest sensor is a child device linked to the host device id; it sees every distro, Docker Desktop's WSL backend and dev containers running there. The Windows host sees only `vmmem` and `wslhost`; host-side events for those images are tagged `wsl-host`.
3. Hook installs for agents inside a distro are the Linux sensor's job. `/etc/claude-code` is user-writable under WSL (brief 37 verification row 2), so those instances report `tamper: user`.
4. Enforcement in the VM follows document 10's probe; BPF LSM is active in the WSL kernel only from 6.18.54.1 and override is absent there (index, brief 14), so the probe decides.
5. Docker Desktop's Hyper-V backend and other VMs are not covered: inventory records them with a could-not-look reason `vm`.
6. ARM64 and custom kernels are supported where document 10's probe passes; Microsoft's Defender plug-in covers neither and is visibility-only (brief 12 verification).

The plug-in API loads in process today and Microsoft's source carries notes about moving plug-ins out of process; the conformance suite runs against each WSL release (latest 3.0.5, 2026-11-03), and a WSL release that breaks the plug-in contract drops the guest link to `could-not-look` with reason `vm` rather than blocking distro start.

### 9. Performance on developer workloads

Coding agents spawn many short processes and touch package caches heavily. Performance targets (spine section 6): all processes, excluding the on-demand Rune window, under 1% of one core idle, 250 MB resident and a 1 GB disk cap; build overhead under 3% alone and 2% per incumbent; hook p50 25 ms, p99 100 ms with Defender and one EDR.

Means:

- The ETW consumer callback drops events not in agent lineage, the protected-path set or the interest set (D-05) before copying them; only the process provider is unfiltered.
- No hashing on process start outside agent lineage; executable identity is cached by file id and last-write time.
- Kernel file events are never subscribed for whole volumes.
- The shim is a static binary with no runtime start-up work beyond the pipe connect; S-04 measures whether Defender and Falcon scanning of each shim spawn fits the hook latency target. If not, 07's fallback applies (an `http` handler for non-strict tools).
- Benchmarks published per release: `cargo build` of a large workspace, `npm ci`, `git status` on a large repository, an `msbuild` solution, and a scripted agent loop launching 5,000 short processes, each with the sensor off, W0, W1, and beside each incumbent, on a normal volume and a trusted Dev Drive. Tetragon's 1.68% on a kernel build is the public bar (h02).

### 10. Tamper resistance without protected-process status

Prevention against same-user agents (Protected profile only):

- Binaries in `%ProgramFiles%\<brand>\`, state in `C:\ProgramData\grdr\` (11 section 5): SYSTEM and Administrators full control, engine and uplink accounts read on their subdirectories, Users nothing. The installer verifies the ACL on every start and reports drift.
- Service DACLs deny stop, pause and configuration change to non-administrators.
- Agent control files, our configuration and monitoring configuration are a protected-path class: agent-lineage writes are Block in Essentials (SR-08), denied by ACE for contained sessions, and observed by kernel file and registry ETW elsewhere. On Windows, monitoring configuration means Sysmon's service and configuration, Event Log channel settings (`wevtutil sl`), ETW autologger keys under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`, audit policy (`auditpol`) and Defender preferences (`Set-MpPreference`); the hook classifies the commands and the registry ETW filter covers the keys.
- Agents' local stores (tokens, MCP secrets, transcripts, conversation databases) against processes outside agent lineage (D-22, SR-12): detection only on Windows without the driver, as a finding on each Kernel-File open of a store path by a non-agent process; 02 records this limit.
- Uninstall, pause, Mode down and leave are step-ups (D-31, SR-23); on an enrolled device the MSI's uninstall action also needs an authorisation file or an MDM-issued command, and forced removal is a tamper finding (24 section 3).

Detection against administrators, because an administrator can stop us without PPL (brief 37):

- Daemon and engine watch each other's liveness over the pipe; suspension of either is a tamper finding (SR-13). EDR-Freeze-style suspension through `WerFaultSecure` needs elevation (brief 37 verification row 7), so this is detection, not prevention.
- Changes to the install directory's reparse and bind-link state, Cloud Files sync-root registrations over our directories (the variant used against Defender, brief 37 verification row 7) and changes to our service configuration are monitored (SR-13).
- WFP filters added by others that block our uplink are detected by enumerating filters matching our service SID or server addresses.
- The server alerts on heartbeat gaps, except inside its own outages and after a signed going-down event (sleep, shutdown) (D-22, SR-10).
- The spool is hash-chained, so a gap is provable afterwards (D-39).

Kernel-grade tamper resistance comes from a host EDR in embedded mode (W3, D-22). The driver of W2 does not change the `tamper` grade, because an administrator can still unload it. The record says `tamper: admin` in the Protected profile and `tamper: user` otherwise, or when the admin-capable probe (02) shows the agent could elevate silently.

### 11. Installer, service layout, paths and registry

| Item | Value (names final under D-66, fixed by the namespace search before the first release) |
|---|---|
| Package | Per-machine MSI, x64 and ARM64, features `Core`, `Proxy`, `Tray`, `Desktop`, Sigstore-signed with SLSA provenance, and Authenticode-signed once Loonaro holds an account with a free open-source signing programme (for example SignPath Foundation); until then the release manifest marks it "not platform-signed" and nothing waits for it (D-17, owner instruction 23; 24 owns the signing identity and the authoring tool choice, SP-24-1); the User profile installs from the signed user archive into `%LOCALAPPDATA%\grdr\`, no elevation (24 section 3) |
| Binaries, slots, state, configuration | 11 section 5 (`%ProgramFiles%\<brand>\`, `C:\ProgramData\grdr\`); MDM `HKLM\SOFTWARE\Policies\<brand>` from a published ADMX and Intune OMA-URI set |
| Services | `grdr-daemon` (auto start); `grdr-engine`, `grdr-uplink`, `grdr-proxy` as demand-start services the daemon starts (section 2); the updater is a daemon child |
| Event Log | Provider and channels of 04 section 15, installed by the MSI, ACL write by the service SID only |
| Pipes | `\\.\pipe\grdr-decide`, `\\.\pipe\grdr-local` (Protected); `\\.\pipe\grdr-decide-<user SID>` (User) |
| WSL plug-in | `grdr-wsl.dll` in the binaries directory and its `Lxss\Plugins` value |
| Enrolment | Enrolment file delivered by MDM or `grdr join`; MSI property values are never logged; nothing secret on the command line (D-59) |
| Distribution | Intune Win32 or LOB, Configuration Manager, GPO, winget manifest (brief 25) |

First run changes nothing (D-48): the read-only scan runs from the per-user binary without elevation. The install journal (D-49) records every external write (managed settings, registry values, ACEs, WFP persistent filters, the WSL plug-in value) with its prior value; `grdr uninstall` restores byte for byte and removes all filters, ACEs and the sandbox account. The installer refuses Windows multi-session hosts, Windows 365 multi-session and Server with Remote Desktop Session Host unless per-logon-session policy and listeners are present (D-59, SR-02; 24). Non-persistent VDI enrols at boot after rename through `grdr image prepare` (D-36).

Supported: Windows 11 releases in Microsoft servicing at our release date with a floor of 24H2 (MXC needs build 26100.9278), and Server 2022 and 2025; x64 and ARM64 for Windows 11, x64 for Server (24 section 9). Windows 10 is not supported: it reached end of support in October 2025, paid extended updates aside (background knowledge, not re-verified), and none of the 2026 features above exist there.

### 12. Coexistence

Defender runs need no licence. Falcon and third-incumbent runs require licences through design partners or free vendor programmes (D-64).

| Incumbent | What we do | What we never do |
|---|---|---|
| Defender (active) | Do not register with Security Center so it stays active; ship exclusions by signer and path in the coexistence pack; signed binaries in default paths; no encoded PowerShell, WMI process creation or PsExec-style launches (ASR rules apply to us; g05) | Ask users to disable ASR or tamper protection |
| Defender passive, Falcon or SentinelOne primary | The slot broker probes and records owners; Falcon and SentinelOne exclusions in the pack; L1 feed and incumbent inventory import (05) as the no-new-agent path (D-23, D-41) | Inject into any process; load a driver in W0 or W1; take the AV registration |
| Standalone or built-in Sysmon | Read its channel | Install, enable or reconfigure it |
| Other WFP providers (ZTNA, firewalls) | Own sublayer, blocks only; yield on existing redirect | Add permits to override them |
| DLP and inspecting proxies | Explicit local proxy chains to the system proxy and trusts the OS store (D-16) | Install a root CA in the OS store |

**Slot broker on Windows.** At install and every start it records the owner of each shared slot and picks enforce, observe or ingest per slot (D-23): WFP providers, sublayers and callouts (`FwpmProviderEnum`, `FwpmCalloutEnum`), loaded minifilters and altitudes (`FilterFindFirst`; for the W2 ordering, Falcon's `csagent` sits at 321410 and SentinelOne's current filter at 329355.5, both in the antivirus range below Activity Monitor; g05 verification), registered AMSI providers, the ETW session count against the 64 cap, Sysmon presence, antivirus and firewall products registered with Security Center, the system proxy, PAC and any inspecting root CA, and registered WSL plug-ins. Where Defender runtime protection for local agents is on (`-AiAgentProtection`, preview), it is reported as another hook owner, and we neither disable nor duplicate it (brief 25).

The coexistence pack (generated per release by `xtask dist`, 11 section 9; published by 24): signer subject and thumbprints, every binary path, service names and SIDs, pipe names, ETW session and provider names and GUIDs, WFP provider and sublayer GUIDs and weight, the WSL plug-in path, and ready exclusion snippets for Defender (including per-rule ASR exclusions), Falcon, SentinelOne, Elastic and Cortex. The ceiling matrix lists, per Windows build, agent and incumbent, the reachable assurance record (D-23).

Known risk: Defender's ASR rule for low-prevalence executables can block a newly released `grdr-hook`; with a vendor fail-closed flag set that would deny every tool call. Hence vendor flags are set only after the on-device self-test (D-14) and every binary release bakes in the internal ring under Defender with ASR in block before any customer ring.

## Interfaces and contracts

| Interface | Shape | Counterpart |
|---|---|---|
| `SensorBackend` implementations `etw`, `win-process-poll` (User profile), `sysmon`, `win-ai-channels`, `odr`; `driver` (optional driver), `wesp`, `host-edr` (embedding partner) | Fixed-layout records to the daemon; capability probe result | 03 (port), 04 (events, `channel`, provenance) |
| `Actuator` implementations `wfp`, `job`, `token`, `acl` | Verbs declared per action class; result and fallback | 07 (verbs), 18 (response actions) |
| `SandboxBackend` implementations `win-appcontainer`, `win-mxc`, `win-local-user`, `win-delegate` | Compiled profile in, self-test result out | 07 section 1, sandbox conformance suite (spine D-45, D-64; detailed document pending) |
| `grdr.winkm` v1 (optional driver) | Fixed-layout structs over a filter port | Driver; `grdr-fastpath` table layout |
| `HostProfile` for Windows hosts (embedding partner) | D-60 profile | 26 |
| `health.sensor`, `health.coverage` Windows fields | ETW loss counters, Dev Drive state, Sysmon presence, WSL guest link | 04, 22 (heartbeat) |
| Coexistence pack and ceiling matrix | Generated JSON and Markdown per release | 11 (generator), 24 (publication), the lab (spine D-64; detailed document pending) |
| WSL plug-in to guest sensor | Enrolment ticket and binary path | 10 |
| ADMX, Intune OMA-URI | Policy keys of the configuration schema | 03 section 9, 24 |

## Behaviour by deployment shape

- **Standalone.** Same processes. In the User profile there is no ETW, no WFP fence, no ACEs on paths the user does not own, no sandbox account and no WSL plug-in (all need administrator rights), so W1 is unavailable, process visibility comes from polling, and every class reports `request`; the record says why. The Protected profile gives W0 and W1 with one elevation.
- **Platform, self-hosted or SaaS.** Configuration through Intune or Configuration Manager; the server sees health, coverage and the assurance record per device; driver rings, where the optional driver is installed, are a group setting. The hosted service requires revenue, sponsorship or donated cloud credits (D-63); self-hosting is the default.
- **Embedded.** A partner may run only the L1 feed or host our engine (L3). Our services may be absent; the partner's host profile sets provenance and `tamper: platform`. No Loonaro network call (D-60).

## Extension points

- **ETW collector manifests** (pack type `collector.etw`): provider GUID, keywords, event ids, field mapping to the canonical model, data classes read. A manifest cannot name a command, path to execute or URL (P7, SR-25). This is how contributors add a provider without touching the core.
- **Channel parsers** for the Windows AI channels and other free-text logs, as signed pack data with golden tests.
- **Housekeeping profiles** per agent version for Windows (07 section 9).
- **Sandbox back ends** through `SandboxBackend` in the contrib repository, gated by the sandbox conformance suite.
- **Coexistence entries** for further incumbents as data in the content repository.

## Security and privacy

- The daemon, the WSL plug-in, the AMSI provider and the driver are trust core (D-63). The plug-in and AMSI provider parse nothing; all text is parsed in the engine (SR-05).
- Script-block text, channel payloads and command lines are content or argument class and obey the capture level on the device (D-51); default upload is metadata.
- The sensor installs no input hooks and reads no keystrokes, screen or clipboard (D-51); synthetic-input evidence on Windows is limited to process-side signals.
- Grants and ACE changes are journalled and reversible; the sandbox account has no password anyone holds.
- Threats specific to Windows (forged user-mode telemetry, admin-level suspension or redirection of the sensor, account suspension at Microsoft) are in 02; this document's mitigations map to SR-01, 03, 07 to 10, 12, 13 and 15.

## Test and evaluation strategy

| Property | Oracle |
|---|---|
| Process coverage | The harness launches N scripted processes in agent lineage; every one appears as `process.start` with correct parent, and loss counters explain any miss |
| No verdict on forgeable input | Synthetic user-mode provider events injected by a lab tool; assert no verdict, label or finding state changes except a tamper finding |
| WFP fence | A listener outside the VM counts connections from fenced sessions; must be zero, and the WFP channel shows our filter's drop |
| Scoped boundary | Sandbox conformance suite: each declared denial attempted at execution time, including children, scripts and files created before the task |
| Route 4 integrity | A harness agent that drops the rewritten prefix raises `effect-mismatch` within the window |
| Dev Drive | Agent edits on a trusted Dev Drive produce a coverage entry; on an untrusted one they do not |
| Tamper detection | Stop, suspend, redirect the install directory and block uplink as administrator; server finding within 60 s (target) |
| Update handover | A daemon update during a 1,000-call hook storm produces zero update-induced denials (D-15); the shim waits for the handover marker's deadline, never beyond 2 s, before using its device-signed fail-safe table (D-14) |
| Coexistence | Each incumbent's own alert interface after install, run, upgrade and uninstall: zero alerts; Defender's Operational log is read locally |
| Performance | Section 9 benchmarks against the sensor-off baseline, five runs, median and spread published |
| WSL | A scripted agent in a distro and in a dev container produces guest events linked to the host device; a plug-in fault leaves WSL starting |

**Test matrix (tier A hosted unless marked B or C).** Tier A is free hosted CI runners for the public repository; tier B is optional self-hosted runners, including snapshot-revert Windows guests where a machine can host them; a cell no available machine can run is marked "requires hardware" and runs when one is available (D-64). Windows 11 24H2, 25H2, 26H2 on x64 (A, B) and ARM64 (A `windows-11-arm`, B); Server 2022 and 2025 x64 (B); HVCI on and off (B); Defender active (A; on a B machine where hosted Windows runners do not allow real-time protection; D-64); Defender passive with Falcon (B, licence through a design partner or a free vendor programme); SentinelOne or Elastic as third incumbent (B, licence on the same terms); domain-joined with an inspecting proxy (B); trusted and untrusted Dev Drive; WSL 3.x with and without Docker Desktop; agents: Claude Code, Codex, Cursor and Copilot CLI, each at current and two prior minors. Driver work adds tier C: HLK controller and clients on x64 and ARM64, Driver Verifier soak of 72 hours; tier C requires the driver's sponsor or partner (D-64).

## Work breakdown

**E1 Windows back end skeleton**
- W-1.1 Cross-compile the four skeleton programs for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`; Sigstore-signed test binaries, Authenticode-signed once a signing programme account exists (D-17, owner instruction 23). Accept: `verify` green on both triples in CI; binaries start and stop cleanly.
- W-1.2 Named-pipe transport with both-way owner checks (07 section 2). Accept: a pipe pre-created by another user makes the shim use its table and leave a tamper marker.
- W-1.3 Service layout and engine confinement of section 2 in both profiles. Accept: the engine fails to open any `%USERPROFILE%` file by name, to write outside its scratch directory and to make any connection; killing it yields floor-table answers and Degraded within 60 s (03 C1); the daemon's service SID has no outbound flow.

**E2 Collectors**
- W-2.1 `EtwSource` on `windows` with one session, the provider table, loss counters and header-PID validation. Accept: process coverage oracle at 100% over 10,000 launches with zero lost buffers at idle; injected user-mode events change no verdict.
- W-2.2 Process tree and process key held by handle; process polling for the User profile. Accept: pid reuse test cannot alias an agent-lineage process; in the User profile every scripted process living 1 s or longer appears, shorter ones are counted as misses, and the record shows `observed` only for `exec`.
- W-2.7 `elevate` and monitoring-configuration coverage of sections 3.5 and 10. Accept: UAC consent, `runas`, `schtasks /create`, WMI `Win32_Process.Create`, `sc create` and a Docker engine pipe call from agent lineage each produce an `elevate` action; an agent-lineage change to each monitoring-configuration item is blocked at the hook and raises a finding; a non-agent open of an agent store raises a finding.
- W-2.3 Sysmon reader, both variants, XML only. Accept: localised built-in Sysmon on a non-English image parses identically; the product never writes Sysmon configuration (asserted by file and registry diff).
- W-2.4 Dev Drive probe and coverage entries. Accept: Dev Drive oracle passes.
- W-2.5 Windows AI channel collector and ODR inventory behind probes. Accept: on a 26H2 image with the experimental features on, registered MCP servers appear in inventory; absent channels produce no error.
- W-2.6 Hook-against-OS reconciliation on Windows with calibrated housekeeping profiles. Accept: S-07 criteria on Windows. Requires: W-2.1 and the hook shim.

**E3 Containment**
- W-3.1 WFP actuator (own provider and sublayer, SID-keyed blocks with proxy carve-outs, loopback block to our console and receivers, non-dynamic session filters, service-SID egress blocks). Accept: fence oracle zero; the fence still holds while the daemon is killed; stale fences are removed and missing ones re-created before the next decision; a contained process cannot reach the local console port; the WFP drop events of section 3.1 are observed for every blocked attempt.
- W-3.2 Job-object session containers and adoption. Accept: no child escapes a session job in the conformance suite; freeze and end-session work on 100 trials.
- W-3.3 `win-appcontainer`, `win-mxc`, `win-local-user` back ends with launch self-test. Accept: S-10 pass (three of four agents finish the scripted task with the fence holding); every elevation route in the self-test fails from inside each back end; `grdr egress` shows no MXC destination; failures stay at `request` with a reason. Requires: W-3.1, W-3.2.
- W-3.4 Route 4 rewrite for Claude Code, Cursor, Copilot CLI and `win-delegate` for Codex. Accept: route 4 integrity oracle; the executed command's digest equals the evaluated one on 1,000 commands from the normaliser corpus, quoting cases included; Codex sandbox principals enumerated and fenced. Requires: W-3.3.
- W-3.5 Protected-path ACEs for sandbox principals, journalled. Accept: contained session cannot read `%USERPROFILE%\.ssh`; uninstall restores ACLs byte for byte.

**E4 Self-protection and tamper detection**
- W-4.1 Directory, service and pipe ACLs with drift check. Accept: same-user agent cannot stop, edit or replace any product file in the Protected profile (S-17 cell on Windows).
- W-4.2 Liveness, bind-link, Cloud Files sync-root, foreign-filter and gap detections. Accept: tamper oracle within 60 s (target) for each technique class.

**E5 Packaging**
- W-5.1 Per-machine MSI for both architectures with the Windows parts of 24's user archive, journal, uninstall authorisation, multi-session refusal. Accept: silent install, repair, upgrade and uninstall leave no residue (file, registry, WFP, ACE diff); no secret in MSI logs; install is refused on a multi-session image.
- W-5.2 ADMX and Intune templates. Accept: every `security` configuration key settable by Intune on a lab tenant (a free developer or trial tenant).

**E6 WSL**
- W-6.1 Signed WSL plug-in and guest-sensor start. Accept: WSL oracle on x64 and ARM64; a forced plug-in error leaves distros starting.

**E7 Coexistence and performance**
- W-7.1 Coexistence pack generator and Defender interference job. Accept: zero Defender alerts with ASR in block across install, run, uninstall.
- W-7.2 Falcon and third-incumbent interference runs and ceiling matrix. Accept: published with each release; zero alerts. Requires: incumbent licences through design partners or free vendor programmes (D-64).
- W-7.3 Benchmarks of section 9 in CI with a regression gate. Accept: measured baselines are published for every row; once they exist, a release that misses a section 9 target is blocked.
- W-7.4 Windows slot broker. Accept: on every tier B image the reported slot owners match the image's ground-truth manifest; a slot owned by an incumbent selects observe or ingest, never a competing registration.

**E8 AMSI provider [opt-in]**
- W-8.1 Forward-only provider with lineage early-out, 50 ms fail-open and crash self-unregister. Accept: zero host crashes over a 72-hour soak of Office and PowerShell workloads; DENY reaches agent-lineage scripts only.

**E9 Driver [optional]**
- W-9.1 Driver design frozen, altitude requested, reference model and differential tests written. Accept: design review by `eval-security` and `eval-adversarial` on different models (D-63). Requires: the prerequisites of section 6.
- W-9.2 Driver, WHCP submission, its own rings, boot-loop disable. Accept: HLK pass on x64 and ARM64; 72-hour Verifier soak with zero bugchecks; the findings of section 6's kernel review closed. Requires: W-9.1; tier C lab.

**E10 Host adapter**
- W-10.1 `host-edr` adapter and Windows host profile with the L3 partner. Accept: S-21 criteria on the partner's sensor. Requires: an L3 embedding partner (D-41).

## Risks, open questions and spikes

| Item | Kind | Settles it |
|---|---|---|
| S-04 Windows hook latency beside Defender and Falcon | Spike (spine) | Decides whether Windows is a Tier 1 cell (D-50) |
| S-10 Which agents run under a sandbox principal, by which route | Spike (spine) | Default back end per agent |
| W-S1 Does AppContainer break git, proxy authentication or package managers for Claude Code tool subprocesses on a domain-joined machine? | Spike; decides whether `win-appcontainer` is the default back end | h08's package matrix under `win-appcontainer`; zero failures or a probe per failure |
| W-S2 Can `ALE_USER_ID` key on a restricting SID, avoiding a separate account? | Spike | WFP test on 24H2 and 26H2; if yes, add a fourth back end with the human's identity intact |
| W-S3 Can user-mode code emit under kernel provider identities on current builds? | Spike | Lab test with an open forging tool; if yes, kernel-provider grade requires the snapshot cross-check permanently |
| W-S4 Are ETW file events affected on trusted Dev Drives? | Spike | Lab test |
| Partner Center account suspension freezes driver updates (reported for WireGuard and VeraCrypt in April 2026, single source in brief 12) | Risk | Two administrators named by Loonaro, documented re-sign path (spine section 9) |
| Attestation-signed loading is unguaranteed | Risk | Driver plans for WHCP from the start |
| Windows AI features change before GA | Risk | Probes; re-read Microsoft's documentation with each Windows feature update |

**External preconditions**

None of these gates daily work: each is a precondition only for the artefact it names, and until it exists that artefact ships without it or waits (owner instruction 7).

| Item | Needed for | Owner |
|---|---|---|
| Legal entity (Loonaro), D-U-N-S | Signing that needs an organisation identity | Owner |
| Acceptance into a free open-source signing programme for Windows user-mode binaries (for example SignPath Foundation), verified at setup | Authenticode on test binaries, the MSI, the WSL plug-in and the AMSI DLL; until then they carry Sigstore signatures only (D-17) | Loonaro, then release squad (24) |
| Incumbent licences for Falcon and SentinelOne through a design partner or the vendors' free test programmes | Falcon and third-incumbent interference runs, ceiling matrix (D-64) | Owner (partner conversation) |
| Tier B machines: optional self-hosted runners, with snapshot-revert Windows guests where a machine can host them, and an ARM64 device where one is available | Tier B cells of the test matrix; cells no machine can run are marked "requires hardware" (D-64) | Lab squad (spine D-64; detailed document pending) |
| EV certificate and Microsoft's hardware programme, Partner Center with two administrators | Driver | Loonaro; paid for by a sponsor or partner (D-17) |
| Minifilter altitude request | Driver | Windows squad drafts; sent in Loonaro's name once the driver's other prerequisites exist |
| HLK lab (tier C) | Driver | Lab squad; requires the driver's sponsor or partner (D-64) |
| Kernel review: `eval-security` and `eval-adversarial` on different models, plus any free external audit that arrives | The driver leaving the internal ring; without it the driver stays in the internal ring (D-62, D-63) | Windows squad; the evaluators |
| MVI-member embedding partner | W3 | Owner (D-41) |

## Deviations from the spine and objections

1. D-17 says WESP "shows no user-mode blocking path". The briefs' fact-check says this is Elastic's inference from imports, not a test, and that network coverage is unknown rather than absent. The design is unaffected; the wording should say "no user-mode blocking path has been found".
2. Proposed addition to D-17's driver scope: `ObRegisterCallbacks` stripping terminate, suspend and write rights on our processes from non-SYSTEM callers. It protects the sensor from user-level agents that obtain a handle and costs little code, but D-17 lists three functions, so the body follows the spine and this waits for a spine change before the driver design freezes (W-9.1).
3. Requests to 04, open-enum additions that break nothing: `channel` values `sysmon`, `win-event-channel` (the AI channels and Application-log sources), `win-driver`, `wesp` and `host-edr`; `health.coverage` reasons `file-filter-detached`, `unparsed` and `vm`. Until 04 lists them, the sensor emits `_OTHER` with the sibling string, which 04's rules allow. Resolved by R-15: 04 adds these channels and `health.coverage` reasons.

Items 1 and 2 remain open: spine v4 keeps D-17's wording and its three driver functions.

## Sources

Research briefs: `research/12-windows.md`, `research/10-oss-sensor-blocks.md`, `research/g05-edr-coexistence-testlab.md`, `research/37-sensor-engineering.md`, `research/g09-os-native-agent-platforms.md`, `research/25-deployment.md`, `research/08-oss-agent-security.md`, `research/h02-conference-talks-sensors.md`, `research/38-network-gateways.md` (verification), `research/h05-open-source-sweep.md`, `research/00-index.md` (digests of 14, 15 and 38). Design documents: 02, 03, 04, 07, 24. Review notes: `design/_review/c3-endpoint-control.md`, `l04-it-endpoint-engineer.md`, `l02-enterprise-buyer.md`, `00-resolution.md`.

Primary URLs (as cited and verified in those briefs):
- https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites
- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview
- https://learn.microsoft.com/en-us/windows/dev-drive/
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
- https://learn.microsoft.com/en-us/windows/wsl/wsl-plugins
- https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/PluginManager.cpp
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai
- https://github.com/microsoft/mxc
- https://github.com/openai/codex/tree/main/codex-rs/windows-sandbox-rs
- https://github.com/anthropics/sandbox-runtime
- https://github.com/microsoft/windows-drivers-rs
- https://falconforce.nl/in-your-logs-now/
- https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818
