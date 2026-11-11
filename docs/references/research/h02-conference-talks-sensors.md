# H02: 2025-2026 conference and practitioner work on endpoint sensors, read for defensive sensor design

_Researched 2026-11-10 (search-backed follow-up)_

Legend: **[V]** verified this session in a primary source (programme, vendor post, Apple/Microsoft doc, kernel tree, LWN conference report). **[S]** secondary source only. **[I]** my inference. **[K]** background knowledge, not re-checked. All 18 permitted web searches were used; several returned nothing useful, which is itself a finding (see section 5).

## TL;DR

- **The Windows endpoint security platform (WESP) is still an undocumented preview on 10 November 2026.** Binaries ship in Insider builds, there is no SDK, no date, and Elastic's 26 October teardown finds no path for a user-mode client to return a block verdict. About a dozen of roughly 100 MVI members work on it under NDA; the named ones are Bitdefender, CrowdStrike, ESET, SentinelOne, Sophos, Trellix, Trend Micro and WithSecure. Plan for a driverless-plus-optional-driver sensor for at least 2027. [V/S]
- **Dev Drive silently detaches non-antivirus minifilters.** On a Dev Drive only filters in the antivirus altitude range (320000-329999) attach by default; everything else, including Microsoft's own Defender for Endpoint EDR filter, needs an administrator allow-list entry. Developers and coding agents are told to put repositories and package caches there. A file sensor at an activity-monitor altitude will be blind exactly where agents work. [V]
- **User-mode ETW is not a trustworthy sole source.** Black Hat USA 2025 (Olaf Hartong) showed that many providers accept events from low-privileged emitters, that the emitting process cannot be trusted from the event, and that capped or shared buffers can be flooded to hide later activity. [S, talk summary]
- **Apple documented the descendants client.** `es_new_descendants_client` (macOS 27.0) gives AUTH+NOTIFY over the caller's subtree, with no root and no TCC approval, but still needs the ES entitlement. Two semantics matter: the caller and its descendants cannot exec setuid/setgid binaries unless the caller is root, and a denied exec produces no EXEC event, only an EXIT. [V]
- **macOS 27 adds Apple-native execution control through declarative device management**, built on Endpoint Security: allow/deny by code-signing properties and termination of running processes of a denied binary. We must coexist with it and can lean on it. [V, WWDC26 session 206]
- **Objective by the Sea v9 has not happened yet** (talks 18-20 November 2026, Hawaii). Its programme is the strongest signal of where macOS practice is going: at least four talks are about AI agents as an execution layer, including an inline local judge fed by hooks plus ES ground truth. [V, abstracts only]
- **BPF LSM enforcement is not tamper-proof and upstream has not agreed a fix.** LSFMM+BPF 2026: programs unload when the loader's descriptors close, and maps are writable from user space; signing does not stop unloading. Tetragon 1.8.0 (30 October 2026) added keeping LSM enforcement alive after agent exit. [V]
- **Signed BPF programs are in mainline since 6.18** (UAPI `signature`, `signature_size`, `keyring_id`); the policy layer (IPE/Hornet) is still disputed. [V]
- **fanotify moved on:** a permission-event watchdog now exists, restartable permission events are near, but the page-fault pre-content hook was reverted after deadlocks, so mmap access is only seen at map time. [V]
- **CrowdStrike's post-outage list is the industry baseline:** crash-loop detection that drops the sensor into a safe mode, ring-based content distribution, host-group schedules, content pinning, a per-host content dashboard. [V]
- **EDR killers moved to user mode.** ESET (19 March 2026) tracked almost 90 tools: 54 BYOVD across 35 drivers, 7 script-based, 15 anti-rootkit abuses, plus driverless tools that block sensor communications or freeze sensor processes. [V]
- **Nobody has published a credible measurement of sensor overhead on coding-agent workloads.** Three searches found only vendor-adjacent blogs. The usable primary numbers are Tetragon's (1.68% on a kernel build) and Microsoft's Dev Drive figure (about 25% average). This is whitespace we can own. [V for the numbers, I for the gap]

## Findings

### 1. Windows

**WESP status.** Elastic Security Labs (2026-10-26) describes WESP as early-stage, shipping as `wesp.sys` plus `espclient.dll` in Insider builds, not broadly available and not documented. It expects clients to need elevation and probably a Microsoft-signed PPL. It finds notify routines for process, thread and image and a dependency on Filter Manager, with rule/filter exports that imply in-driver filtering of noisy events. It finds no reply channel from user mode, so a "user-mode service decides, kernel enforces" verdict is probably not implemented yet; network is not covered and EDRs still need a WFP callout. Elastic says Defend is preparing support and that existing drivers must keep working through a gradual migration. [V] [Elastic](https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp)

**Who is in.** Cybersecurity Dive (2026-03-02) reports about 100 MVI members, roughly a dozen working directly with Microsoft, under NDA; publicly named: Bitdefender, CrowdStrike, ESET, SentinelOne, Sophos, Trellix, Trend Micro, WithSecure. Microsoft asked vendors to inventory product features so they can be preserved in user mode. ESET's Tony Anscombe called it a very large task with a long horizon; independent experts flagged after-the-fact process notification, slower API access and weaker tamper resistance in user mode. Microsoft declined to answer basic questions. No GA date. [S] [Cybersecurity Dive](https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/)

**Vendor posture.** CrowdStrike (2025-07-14) says it participates in WESP, will adopt user-mode capabilities only if they match kernel efficacy, security and performance, and created "Project Ascent" under Alex Ionescu to explore capabilities outside kernel space. [V] [CrowdStrike](https://www.crowdstrike.com/en-us/blog/reflecting-on-building-resilience-by-design/)

**Driver-signing policy in 2026.** Microsoft's post (published 2026-03-26, version 3.0 updated 2026-10-22) removes default trust for cross-signed kernel drivers on Windows 11 24H2/25H2/26H1 and Server 2025 from the April 2026 update. Enforcement is staged per device: an evaluation mode audits driver loads and only flips to enforcement after 250 system hours and 3 restarts (2 on Server) with no failing driver; the bar was raised from 100 hours on 9 June 2026, and a failing load resets the clock. Exceptions need an App Control policy signed by a Secure Boot PK/KEK authority. The post does not mention attestation signing. [V] [Microsoft Tech Community](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818). Secondary coverage says the WHCP bar will add compiler safeguards, driver isolation and DMA-remapping tests. [S]

**MVI 3.0.** Still described publicly only as reliability requirements: safe deployment practices, staged rollouts, monitoring, incident-response drills. I found no public checklist. [S]

**ETW as a telemetry source.** Olaf Hartong (FalconForce), Black Hat USA 2025: many ETW providers do not authenticate the emitter, the process ID in an event does not prove who wrote it, telemetry caps and shared sessions can be flooded so later real events are dropped, and fabricated events reached Defender for Endpoint's cloud. Microsoft fixed one provider; over 100 reported providers were open at disclosure. Requirement: user-mode ETW is corroborating evidence only; kernel-emitted providers and callbacks are the ground truth; we must export loss counters and alert on "spike then silence". [S] [talk summary](https://conference-intel.pages.dev/c/blackhat-usa-2025/BH25-023/)

**Call stacks.** "LACUNA Chain" (Mohamed Alzhrani, 2026-06-20) claims fabricated-but-plausible call stacks defeated stack-based detection in Elastic, Bitdefender and Kaspersky with CET and ETW-TI stack walking on. Author-tested only, no vendor confirmation. Requirement: never let a call stack be the only input to a verdict. [S] [Cyberpress](https://cyberpress.org/lacuna-attack-chain-bypasses/)

**Tamper resistance.** ESET's "EDR killers explained" (Jakub Souček, 2026-03-19): almost 90 tools in the wild; 54 BYOVD using 35 drivers (24 with no public proof of concept); 7 script-based (service-control commands, Safe Mode reboots); 15 legitimate anti-rootkit tools; and driverless tools that block sensor-to-cloud traffic or freeze sensor processes. ESET's lessons: driver blocklists act late and miss validly signed drivers; the sophistication now sits in user mode; attribution by driver is unreliable. [V] [ESET](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/)

**Dev Drive.** Microsoft Learn (updated 2026-06-01): Filter Manager turns off all filters on a Dev Drive except those in the `FSFilter Anti-Virus` range; an administrator may allow more with `fsutil devdrv setfiltersallowed`, and the documented table of filters that need allow-listing includes `MsSecFlt` (Defender for Endpoint EDR sensor), `PrjFlt`, `bindFlt`/`wcifs` and Process Monitor. Performance mode (asynchronous scanning) is Defender-only. Microsoft recommends placing repositories, npm/pip/cargo/NuGet/Maven/Gradle caches and build output on it. [V] [Dev Drive](https://learn.microsoft.com/en-us/windows/dev-drive/)

### 2. macOS

**WWDC 2026.** Search found no dedicated Endpoint Security session; the last one is WWDC22. The only ES content I could verify is in session 206 ("What's new in managing Apple devices"): macOS 27 adds declarative settings that allow or deny binary execution using Endpoint Security, match on code-signing properties, can auto-allow managed apps, and can shut down running processes of a denied binary. [V] [WWDC26 206](https://developer.apple.com/videos/play/wwdc2026/206)

**Descendants client, from Apple's documentation (macOS 27.0).** The client gets NOTIFY for the caller and AUTH+NOTIFY for the whole subtree, including descendants that already exist. Other processes are invisible; process muting only works inside the subtree. It needs the ES entitlement but not root and not TCC. The caller and its descendants cannot exec setuid/setgid binaries unless the caller's effective uid is 0. A blocked exec is killed before it runs and emits no EXEC event; subscribers see only EXIT. Companion APIs: `es_set_deadline_miss_mode` (KILL default, FAIL_CLOSED, FAIL_OPEN) and per-event minimum/maximum deadline getters and setters; new `AUTH/NOTIFY_BOOTSTRAP_CHECK_IN`, `_LOOK_UP`, `AUTH_XPC_CONNECT`. [V] [Apple docs](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:))

**Full Disk Access.** Apple's notice "Updates to Full Disk Access in macOS" (2026-10-02) says FDA exists for backup apps, that some developers use it in ways that expose files, mail, messages and browsing history, and that granting it will require very explicit action, with AI agents named as a growing risk. It says nothing about Endpoint Security, system extensions, MDM or dates. [V] [Apple](https://developer.apple.com/news/?id=p6zjojqw)

**Objective by the Sea v9** (training 15-17 November, talks 18-20 November 2026, Hawaii). Not yet delivered; abstracts only. [V] [programme data](https://objectivebythesea.org/v9/talks.html)

| Talk (speaker) | What the abstract promises | Requirement it implies |
|---|---|---|
| Naughty or Nice: Alignment on the Cheap (Pete Markowsky) | An on-device judge (Apple Foundation Models) that reads harness telemetry, hooks and ES ground truth, then allows, blocks or prompts before the action runs | Our policy engine needs a local, inline, model-backed verdict option fed by hook plus OS evidence; expect Santa's maintainers [K] to ship something similar |
| AI LOTL: Investigating Agent-Driven Execution (Shannon McCormick) | A data-source matrix pairing user prompts with resulting actions for Claude; cites the Nx "s1ngularity" worm (August 2025) hijacking installed AI CLIs | Store prompt-to-action joins as first-class evidence; ship the forensic matrix as product documentation |
| The Toolchain Is the Loader (Adel Karimi) | Telemetry shows Python, VS Code, Xcode or a shell but not which package, extension or project supplied the code | Record the artifact that selected the code (lockfile entry, extension ID, module path, working tree revision) with each interpreter exec |
| Unix Pipes (Maggie Zirnhelt) | A mental model of macOS IPC built on ES | Lineage must include IPC edges, not only fork/exec |
| AEMonitor (Pepe Berba) | Apple Events observed via unified logs to see osascript activity that exec/file events miss | Add an Apple Event collector; treat osascript as a broker |
| Reversing macOS Tahoe's ClickFix protections (Ferdous Saljooki) | XProtect uses ES to intercept paste and exec, with a now-patched bypass | Apple is itself an inline ES consumer; test deadline behaviour alongside it |
| Click Happens (Yannis Hofmann) | Clickjacking of TCC consent prompts by an unprivileged app | Our approval prompts must resist synthetic or stolen clicks |
| EvidenceForge (Sydney Marrone, Lauren Proehl) | Open-source deterministic synthetic ESF telemetry with audit tokens, signing identity, ancestry | Use synthetic, labelled ES streams as test-lab fixtures |

### 3. Linux

**Linux Plumbers 2026 (Prague, 5-7 October).** eBPF track, 24 talks. Relevant by abstract [V] [track](https://lpc.events/event/20/sessions/249/): "Scaling BPF LSM hooks and error injection across the kernel" (Anton Protopopov) on blocking code paths at runtime; "One Layer of the Onion: A Daemonless eBPF LSM for Confidential VMs in a WhatsApp TEE" (Joshua Lilly, Liam Wisehart, Meta) on binary identity and process protection with no user-space agent; "BPF-RBACd" (Toke Høiland-Jørgensen) on fine-grained delegation with BPF tokens plus an LSM; "shirudo: BPF live-patching infra for the agentic era" (Borkmann, Fastabend); "eBPF Security: The Uneven Landscape" (ZHAW); an ETH Zurich abstract stating eBPF runs 1.7-2.1x slower than native code; and, in the System Boot and Security microconference, "Extending BPF Signing into an IMA Integrity Lifecycle". The Live Patching microconference had two sessions on livepatch and tracing (kprobe, ftrace, BPF) sharing the same functions. No session title mentioned Landlock, fanotify, seccomp or io_uring.

**Out-of-tree tracers.** LWN (2026-10-14) on Mathieu Desnoyers' session: the kernel will not export symbols without an in-tree user, so LTTng reimplements infrastructure and cannot use new facilities such as SFrame unwinding; no path forward was agreed. Requirement: no kernel module, ever; CO-RE BPF only. [V] [LWN](https://lwn.net/Articles/1099300/)

**Tamper resistance of BPF LSM (LSFMM+BPF, Zagreb, 4-6 May 2026).** LWN (2026-07-17): Christian Brauner showed that programs on LSM hooks are reference-counted and disappear when the submitting descriptor closes, and that user space can rewrite map data the program trusts. His workaround hooks every path that could modify loaded programs. Signed programs can still be unloaded; exclusive maps are one per program. Options floated: immutable programs, self-protecting programs, pinned refcounts, maps detached from user space. Nothing was settled. [V] [LWN](https://lwn.net/Articles/1082111/)

**Signing and tokens.** Verified in the kernel tree: `include/uapi/linux/bpf.h` has no signature fields at v6.17 and has `signature`, `signature_size`, `keyring_id` and `excl_prog_hash` at v6.18 (merge "signed-bpf-programs", 2025-09-22). KP Singh's 13-patch "Signed BPF + IPE Policies" series (2026-05-22) adds a post-integrity LSM hook and IPE properties and states that the BPF maintainers NACKed Hornet; I could not confirm it merged. `bpf_token_create/cmd/capable` LSM hooks are present at v7.3. [V] [LWN posting](https://lwn.net/Articles/1074083/)

**io_uring.** At v7.3 the io_uring-specific LSM hooks are `uring_override_creds`, `uring_sqpoll`, `uring_cmd` and `uring_allowed`; there is no per-opcode hook, so visibility comes from the ordinary file and socket LSM hooks that io_uring operations still traverse. [V for the hook list, I for the consequence]

**fanotify (LWN, 2026-06-08, Amir Goldstein).** Pre-content events carry byte ranges; the page-fault hook for mmap was merged then backed out after regressions and deadlocks, so content must be populated at mmap time. A watchdog now logs when a daemon fails to answer a permission event. Restartable permission events (control descriptor held in systemd's descriptor store, separate queue descriptor) are described as mature. Mount-namespace watching landed in 6.15, inside user namespaces in 6.16. cgroup watching is requested, not available. Filesystem freeze can deadlock pre-content daemons. [V] [LWN](https://lwn.net/Articles/1075829/)

**BPF written by AI agents.** Alexei Starovoitov's "BPF in the agentic era" (LWN, 2026-06-03): LLMs struggle with the verifier and sometimes give up; the plan is better verifier diagnostics, a Rust front end and fewer verifier limits. This applies directly to a product whose BPF will be written by coding agents. [V] [LWN](https://lwn.net/Articles/1075067/)

**Releases.** Falco 0.45.2 (2026-10-29). Tetragon v1.8.0 (2026-10-30): CEL expressions in selectors, stateful tracing policies, LSM enforcement kept active after agent exit, and a fix for pin-path collisions that could silently switch an enforcement policy to monitor-only. [V, GitHub releases]

### 4. Safe deployment

CrowdStrike, "One Year Later" (2025-07-14) [V]: Sensor Self-Recovery detects crash loops and moves the host to a safe mode on Windows and macOS; a remediation toolkit handles out-of-band recovery; a new content distribution system rolls every content release through automated rings gated by health signals; customers get host-group deployment schedules, content pinning, a dashboard of rollout progress and each host's last update time, and SOAR hooks; a "Super Lab" tests OS, kernel, hardware and third-party combinations; a Digital Operations Center watches fleet health; outside experts review code and process. No versions, ring counts or thresholds are given.

Microsoft's driver-trust rollout is a second reference design: audit on every device, flip to enforce only after a clean soak, reset on any failure. [V]

Tetragon's monitor-only regression shows the inverse failure: a sensor can stop enforcing without crashing. [V]

### 5. Performance and coexistence

- Tetragon 1.0 post (2023-10-31): kernel build with process-exec tracking, 1.68% overhead; 2.46% when also writing every exec event as JSON; netperf TCP_CRR connection rate down 5.88% with network monitoring. [V] [Isovalent](https://isovalent.com/blog/post/tetragon-release-10/)
- Microsoft (2023-05-24): Dev Drive with asynchronous Defender scanning, around 25% average improvement on clone, build, copy and package restore; no methodology. [V] [Visual Studio blog](https://devblogs.microsoft.com/visualstudio/devdrive)
- Bitrise's documentation warns that EDR on short-lived CI runners costs CPU, memory and I/O for limited benefit. [S]
- I found no vendor engineering post on handling coding agents that spawn thousands of short processes, and no reproducible benchmark of any commercial sensor on `npm install`, `cargo build` or agent loops. The practitioner literature instead documents the detection side: the Cloud Security Alliance note (2026-07-16) says agent process trees look like living-off-the-land chains, so lineage rules produce noise or misses, and recommends file-integrity monitoring on agent memory and configuration files, alerting on persistence writes regardless of parent, pairing endpoint telemetry with agent context logs, and logging agent egress to ordinary SaaS channels. [V] [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-semantic-malware-promptware-20260716-csa-s/)

### 6. Documented blind-spot classes

See the matrix. Each row is a test-lab case.

## Matrix

| Blind-spot class | Source (date) | Platform | Design requirement | Test-lab case |
|---|---|---|---|---|
| File filter detached on Dev Drive | Microsoft Learn (2026-06-01) | Windows | Detect Dev Drive volumes and the allow-list; report coverage loss; document `setfiltersallowed`; do not rely on a minifilter for agent file evidence | Agent edits and installs on a trusted Dev Drive with and without allow-listing |
| Spoofed or flooded user-mode ETW | Black Hat USA 2025 | Windows | Kernel providers and callbacks as truth; per-session loss counters; spike-then-silence alert | Inject synthetic provider events and floods; assert no verdict changes |
| Fabricated call stacks | LACUNA Chain (2026-06-20) | Windows | Stacks are enrichment, never the sole verdict input | Regression rule: verdict unchanged when stack field is absent |
| Sensor muted without a driver (traffic blocked, process frozen, Safe Mode) | ESET (2026-03-19) | Windows | Server-side heartbeat-gap detection; watch for filters targeting our binaries; local spool with gap markers | Block sensor egress and suspend the service; assert server alert within budget |
| Enforcement lost on loader exit or map rewrite | LSFMM+BPF (2026-07-17); Tetragon 1.8.0 | Linux | Pin links and programs in bpffs; deny map and program access to non-sensor tasks; attest enforcement mode in every heartbeat | Kill and restart the agent mid-policy; attempt map writes as root |
| Silent enforce-to-monitor downgrade | Tetragon PR 5754 | Linux | Enforcement state is asserted, not assumed | Load colliding policy names; assert mode |
| io_uring bypass of syscall hooks | kernel v7.3 hook list; ARMO 2025 (brief 14) | Linux | Hook LSM file and socket layers; optional `uring_allowed` deny for agent cgroups | Same file and network actions via io_uring |
| mmap access after open | LWN fanotify (2026-06-08) | Linux | Treat a mapped file as fully read at map time | mmap-read a protected file |
| Denied exec leaves no EXEC event | Apple docs (macOS 27.0) | macOS | Synthesize a "denied exec" record from our own verdict plus EXIT | Deny exec in a subtree; assert one audit record |
| setuid exec blocked under a non-root descendants client | Apple docs | macOS | Run the supervisor as root or document that `sudo`, `ping`-style tools fail | Agent runs a setuid binary under supervision |
| Interpreter and toolchain hide which artifact ran | OBTS v9 abstract (Karimi) | All | Capture artifact identity with interpreter execs | Malicious-package fixture: assert package and version in the event |
| Broker hand-offs (XPC, Apple Events, launchd) | OBTS v9 abstracts (Zirnhelt, Berba) | macOS | IPC edges in the lineage graph | Agent drives osascript and an XPC service |
| Activity that never leaves model context; agent memory poisoning | CSA note (2026-07-16) | All | FIM on agent memory and config files; join hook transcripts to OS events | Modify `CLAUDE.md`/`AGENTS.md` out of band; assert event |
| Consent prompt clickjacking | OBTS v9 abstract (Hofmann) | macOS | Approval UI on a protected surface with input-origin checks | Synthetic click against our prompt |

## What this changes in the earlier briefs

- **12-windows.md** says the private preview went to "a set of MVI partners". Now specific: about a dozen of roughly 100, eight named. Its statement that process creation can be vetoed only by in-driver rule is newly supported by Elastic's independent finding of no user-mode reply path.
- **12-windows.md** lists "ETW kernel providers" under "a lot is possible with no driver". Keep that, but user-mode ETW providers must be downgraded to corroboration (Black Hat 2025).
- **12-windows.md** and **g05** discuss a minifilter without Dev Drive. Add: non-antivirus-altitude filters are detached on Dev Drives by default.
- **12-windows.md** on cross-signed trust removal: add the per-device evaluation mode (250 hours, 3 restarts, since 9 June 2026) and the PK/KEK-signed App Control exception.
- **13-macos.md** read the macOS 27 ES changes from a third-party header diff. Apple's documentation now confirms them and adds two behaviours the brief lacks: setuid/setgid exec restriction and no EXEC event for a denied exec.
- **13-macos.md** does not mention declarative-management execution control in macOS 27; add it as a coexistence item and a possible enforcement channel.
- **13-macos.md** FDA statement is confirmed word for word in substance; still no date. No dedicated WWDC26 ES session was found, and OBTS v9 is next week, so "OBTS talks on ES" are abstracts only.
- **14-linux.md** open question "whether a permission-event watchdog exists upstream": yes (diagnostic message, kernel version not stated). Add that the mmap page-fault pre-content hook was reverted.
- **14-linux.md** calls BPF LSM the only synchronous system-wide deny. Still true, but add that upstream considers it tamperable by user space and has no agreed fix.
- **37-sensor-engineering.md** open question on CrowdStrike self-recovery: partly answered (crash-loop detection to safe mode on Windows and macOS, content pinning, host-group schedules); versions remain unpublished.
- **g05** open question on published CPU and memory budgets from CrowdStrike, SentinelOne and Cortex: still unanswered after three searches.

## Implications for our design

Ranked requirements for the sensor and its test lab.

1. **Enforcement state is a measured, reported fact.** Every heartbeat carries, per hook, whether we are attached, enforcing or monitoring, plus loss counters. (Tetragon PR 5754; Black Hat 2025; ESET 2026)
2. **Content is rolled out like code, with customer pinning and automatic crash-loop fallback to a safe mode** that keeps discovery and audit but drops inline enforcement. Enforcement policies start in per-device audit and flip only after a clean soak. (CrowdStrike 2025; Microsoft driver policy 2026)
3. **Windows ships driverless first and treats WESP as a later adapter** behind the same internal interface as our optional driver; no roadmap item depends on a WESP date. (Elastic 2026-10-26; Cybersecurity Dive 2026-03-02)
4. **Dev Drive awareness on day one**: enumerate Dev Drives and allowed filters, raise a coverage finding, and get agent file evidence from hooks and gateways rather than a minifilter. (Microsoft Learn)
5. **Evidence tiers.** Kernel-origin events outrank user-mode ETW, call stacks and agent-reported hook data; a verdict must cite at least one kernel-origin or gateway fact where one exists. (Black Hat 2025; LACUNA)
6. **Linux enforcement survives loader death**: pinned links, map access denied to other tasks, an in-kernel default when user space is absent, signed light skeletons on 6.18+. (LSFMM+BPF 2026; kernel tree)
7. **macOS supervisor built on the descendants client**, with explicit deadline-miss mode per policy (FAIL_CLOSED for protected paths), synthetic denied-exec records, and a documented setuid limitation; coexist with DDM execution rules and XProtect. (Apple docs; WWDC26 206; OBTS v9)
8. **Lineage is a graph with IPC and artifact edges**: XPC, Apple Events, launchd, COM, D-Bus, plus the package, extension or project that selected the code. (OBTS v9 abstracts; CSA 2026)
9. **File-integrity coverage of agent memory and configuration files**, and prompt-to-action joins stored as evidence. (CSA 2026; OBTS v9 McCormick)
10. **Publish our own overhead benchmark**: kernel build, `npm ci`, `cargo build`, and a scripted agent loop spawning thousands of short processes, sensor on and off, with Tetragon's 1.68% as the public bar. Gate releases on it. (Tetragon 2023; absence of any other data)
11. **BPF code written by agents needs a tight verifier loop in CI** across the kernel matrix, including livepatched kernels and kernels with other vendors' programs on the same hooks. (LWN 2026-06-03; LPC 2026 Live Patching MC)
12. **Out-of-band tamper detection**: server-side gap alerts, detection of local rules that block our egress, and a spool that proves the gap afterwards. (ESET 2026)

## Could not verify / open questions

- WESP: whether a blocking reply path, network events or non-MVI access are planned; any date. Microsoft Ignite 2026 may change this within weeks; I could not confirm its dates.
- The public text of MVI 3.0 requirements; the Windows Central article on the raised driver bar rendered only its headline.
- Whether any WWDC26 session covered Endpoint Security directly; Apple's session catalogue was not enumerated.
- OBTS v9 content beyond abstracts (conference is 18-20 November 2026). Pete Markowsky's affiliation is from memory.
- Kernel versions for the fanotify watchdog and for restartable permission events; whether KP Singh's May 2026 IPE series merged.
- LPC 2026 abstracts in full: individual contribution pages resolved to other years' events, so talk descriptions come from the track listing.
- eBPF Summit 2026 programme (page returned 404). Linux Security Summit 2026 programme not checked.
- LACUNA Chain: primary write-up not retrieved; vendor responses unknown.
- Any published sensor CPU or memory budget from CrowdStrike, SentinelOne, Palo Alto or Microsoft for developer workloads; any vendor statement on coding-agent process churn.
- Whether Dev Drive's filter policy also affects non-file telemetry (I assume not).

## Sources

- https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp - Elastic Security Labs, inside wesp.sys, 2026-10-26
- https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/ - Cybersecurity Dive, making security software safer, 2026-03-02
- https://www.crowdstrike.com/en-us/blog/reflecting-on-building-resilience-by-design/ - CrowdStrike, One Year Later, 2025-07-14
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818 - Microsoft, cross-signed driver trust removal, 2026-03-26, updated 2026-10-22
- https://learn.microsoft.com/en-us/windows/dev-drive/ - Microsoft Learn, Dev Drive, updated 2026-06-01
- https://devblogs.microsoft.com/visualstudio/devdrive - Visual Studio blog, Dev Drive measurements, 2023-05-24
- https://conference-intel.pages.dev/c/blackhat-usa-2025/BH25-023/ - summary of Olaf Hartong's Black Hat USA 2025 briefing, 2025-08
- https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/ - ESET Research, EDR killers explained, 2026-03-19
- https://cyberpress.org/lacuna-attack-chain-bypasses/ - coverage of LACUNA Chain, 2026-06 (secondary)
- https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:) - Apple, descendants client, macOS 27.0
- https://developer.apple.com/documentation/endpointsecurity - Apple, Endpoint Security index (deadline-miss modes, bootstrap and XPC events)
- https://developer.apple.com/videos/play/wwdc2026/206 - WWDC26 session 206, What's new in managing Apple devices, 2026-06
- https://developer.apple.com/news/?id=p6zjojqw - Apple, Updates to Full Disk Access in macOS, 2026-10-02
- https://objectivebythesea.org/v9/talks.html - Objective by the Sea v9 programme (talks 2026-11-18 to 20)
- https://lpc.events/event/20/sessions/249/ - Linux Plumbers Conference 2026, eBPF track, 2026-10-05 to 07
- https://lpc.events/event/20/contributions/ - LPC 2026 contribution list
- https://lwn.net/Articles/1099300/ - LWN, Collaborating with out-of-tree tracers, 2026-10-14
- https://lwn.net/Articles/1082111/ - LWN, Securing BPF LSMs against tampering, 2026-07-17
- https://lwn.net/Articles/1075829/ - LWN, An update on fanotify, 2026-06-08
- https://lwn.net/Articles/1075067/ - LWN, BPF in the agentic era, 2026-06-03
- https://lwn.net/Articles/1074083/ - LWN posting of "Signed BPF + IPE Policies", 2026-05-22
- https://bpfconf.ebpf.io/ - bpfconf 2026 agenda (LSFMM+BPF, Zagreb, 2026-05-04 to 06)
- https://github.com/torvalds/linux - `include/uapi/linux/bpf.h` at v6.17, v6.18, v7.3 and `include/linux/lsm_hook_defs.h` at v7.3 (read 2026-11-10)
- https://github.com/cilium/tetragon/releases/tag/v1.8.0 - Tetragon v1.8.0, 2026-10-30
- https://github.com/falcosecurity/falco/releases - Falco 0.45.0 to 0.45.2, 2026-09-21 to 2026-10-29
- https://isovalent.com/blog/post/tetragon-release-10/ - Tetragon 1.0 overhead figures, 2023-10-31
- https://labs.cloudsecurityalliance.org/research/csa-research-note-semantic-malware-promptware-20260716-csa-s/ - CSA research note on promptware and process lineage, 2026-07-16
- https://docs.bitrise.io/en/bitrise-platform/integrations/endpoint-detection-and-response - Bitrise, EDR on build machines (seen in search results only)

## Independent verification

_Checked 2026-11-10 by a separate fact-checker. Method: raw page text, Apple's documentation JSON, the kernel tree and GitHub releases through `gh`, and sources the brief did not cite where they exist. Two web searches used._

Two claims need correcting before the plan relies on them: the ETW attribution statement (claim 5) and the WESP network statement (claim 1). The other eight held.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | WESP is preview-only in Insider builds, undocumented, no user-mode block reply, network not covered | corrected | Insider-only and undocumented hold: Elastic says two binaries ship in an Insider build and the platform is not publicly documented, and a Microsoft Learn search for the product name returns no WESP page today. The missing reply path is Elastic's inference from `espclient.dll` not importing `FilterReplyMessage` ("probably not implemented, at least not yet"), not a tested result. Elastic does NOT say network events are not covered: it lists the WFP callout only as today's mechanism, says WESP "should provide all of these" and that not everything will arrive on day one. Network non-coverage is the brief's inference. Also in the article and not in the brief: `wesp.sys` is a minifilter at altitude 329500, inside the antivirus range. | [Elastic](https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp); [Learn search](https://learn.microsoft.com/api/search?search=%22Windows%20endpoint%20security%20platform%22&locale=en-us) |
| 2 | Dev Drive detaches all minifilters except altitude 320000-329999; others, including MsSecFlt, need an administrator allow-list entry | confirmed | Wording and range match Microsoft Learn, and the altitude table independently gives FSFilter Anti-Virus as 320000-329999 and Activity Monitor as 360000-389999. Scope limit: the filter policy applies to a trusted Dev Drive (the default at format time). An untrusted Dev Drive, or one moved to another machine, is treated as an ordinary volume and all filters attach. An administrator can also remove antivirus filters (`fsutil devdrv enable /disallowAv`). | [Dev Drive](https://learn.microsoft.com/en-us/windows/dev-drive/); [altitude ranges](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers) |
| 3 | `es_new_descendants_client` (macOS 27.0): entitlement required, no root, no TCC; setuid/setgid exec blocked unless caller is root; blocked exec gives EXIT only | confirmed | Apple's documentation JSON states each point verbatim, `introducedAt` 27.0, entitlement `com.apple.developer.endpoint-security.client`. No SDK header mirror was found to cross-check. | [Apple doc JSON](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_new_descendants_client(_:_:).json) |
| 4 | BPF LSM programs unload when the loader's descriptors close, maps are alterable from user space, LSFMM+BPF 2026 agreed no fix, signing does not prevent unloading | confirmed | LWN matches. Tetragon PR 5254 (merged 2026-07-13) independently shows LSM enforcement stopped on agent exit before the fix. Pinning keeps programs alive but privileged user space can still unpin. A keyword search of torvalds/linux through v7.4-rc2 found no merged tamper-proofing change (weak negative evidence). | [LWN](https://lwn.net/Articles/1082111/); [Tetragon PR 5254](https://github.com/cilium/tetragon/pull/5254) |
| 5 | Many ETW providers accept events from low-privileged emitters; the emitting process cannot be trusted from the event; buffers can be flooded | corrected | Emission from an un-elevated process and flooding hold (cloud caps where "the first events win", a full session buffer pool stops providers for every session, 64-session limit). The attribution part is wrong as written: Hartong's own write-up says the kernel overwrote the header process ID with the real emitter and he could not spoof it. What cannot be trusted is provider identity and payload fields. The header PID is therefore a usable check (is this event from the component that should own the provider). Microsoft's fix is an undocumented `NtTraceControl` disallow list on a small set of providers. | [FalconForce, 2026-08-26](https://falconforce.nl/in-your-logs-now/); [BamboozlEDR](https://github.com/olafhartong/BamboozlEDR) |
| 6 | About a dozen of roughly 100 MVI members work with Microsoft under NDA; eight named vendors; no GA date | confirmed | Figures are single-sourced (ESET's Tony Anscombe via Cybersecurity Dive). The eight names are the partners quoted in Microsoft's 26 June 2025 blog; Microsoft has not published the full participant list. No date found anywhere. | [Cybersecurity Dive](https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/); [Microsoft, 2025-06-26](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/) |
| 7 | CrowdStrike: sensor self-recovery (crash loop to safe mode, Windows and macOS), ring-based content distribution, host-group schedules, content pinning | confirmed | All four are in the 14 July 2025 post. No independent second source was checked. | [CrowdStrike](https://www.crowdstrike.com/en-us/blog/reflecting-on-building-resilience-by-design/) |
| 8 | ESET: almost 90 EDR killers; 54 BYOVD using 35 drivers; 7 script-based; 15 anti-rootkit; plus driverless tools | confirmed | Numbers match. The three itemised classes sum to 76; ESET gives no count for the driverless class (EDRSilencer, EDR-Freeze) or the remainder. | [ESET](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/) |
| 9 | Signed BPF loading in mainline from 6.18 (UAPI `signature`, `signature_size`, `keyring_id` absent at 6.17); IPE policy layer still only a posted series | confirmed | Re-read in the tree: fields absent at v6.17, present at v6.18 with `bpf_prog_verify_signature` in `kernel/bpf/syscall.c`. At master (v7.4-rc2) `security/ipe` has no BPF references, there is no `security/hornet`, and `lsm_hook_defs.h` has no post-integrity BPF hook, so the IPE layer is still unmerged on 2026-11-10. | [torvalds/linux](https://github.com/torvalds/linux) |
| 10 | fanotify has a watchdog for unanswered permission events; the page-fault pre-content hook was reverted after deadlocks | confirmed | Watchdog is commit b8cf8fda522d, first released in v6.18, and is off by default (`/proc/sys/fs/fanotify/watchdog_timeout` = 0), so it must be enabled to be useful. The revert is commit 955fbe0ef19d, in v6.14 (March 2025), for a deadlock with filesystem freeze; `mm/filemap.c` at master has no fsnotify hook and the mmap-time hook (`fsnotify_mmap_perm`) is in `mm/util.c`. This answers the brief's open question on the watchdog's kernel version. | [watchdog commit](https://github.com/torvalds/linux/commit/b8cf8fda522d); [revert](https://github.com/torvalds/linux/commit/955fbe0ef19d) |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| ESET: "35 drivers (24 with no public proof of concept)" | corrected | The 24 refers to BYOVD-based EDR killers with no known public proof of concept they are based on, not to 24 of the 35 drivers. | [ESET](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/) |
| Cross-signed driver trust removal: April 2026 update, evaluation mode of 250 hours and 3 restarts (2 on Server), raised from 100 hours on 9 June 2026, PK/KEK-signed App Control exception | confirmed | Matches version 3.0 of the Microsoft post (updated 2026-10-22). | [Microsoft](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818) |
| Dates and figures: OBTS v9 talks 18-20 November 2026 in Hawaii; LPC 2026 in Prague 5-7 October; Tetragon v1.8.0 on 2026-10-30; Falco 0.45.2 on 2026-10-29; Tetragon 1.68% / 2.46% / 5.88%; Dev Drive about 25% | confirmed | All match the organisers' pages, GitHub release timestamps and the two vendor posts. | [OBTS](https://objectivebythesea.org/v9/index.html); [LPC](https://lpc.events/event/20/); [Tetragon](https://github.com/cilium/tetragon/releases/tag/v1.8.0); [Isovalent](https://isovalent.com/blog/post/tetragon-release-10/); [Visual Studio blog](https://devblogs.microsoft.com/visualstudio/devdrive) |

Effect on the brief's requirements: requirement 5 and the "Spoofed or flooded user-mode ETW" matrix row should say that provider identity and payload are untrusted while the kernel-stamped header PID is trustworthy and should be validated. Requirement 3 should not assume WESP lacks network events; that is unknown. Requirement 4 should scope the Dev Drive blind spot to trusted Dev Drives and note that WESP's own filter sits in the antivirus altitude range.
