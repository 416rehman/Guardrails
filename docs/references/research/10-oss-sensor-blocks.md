# Open-source building blocks for the endpoint sensor

_Researched 2026-11-09_

Method note: licence, version and activity data were read from the GitHub and crates.io APIs on 2026-11-09. Docs were fetched directly from vendor sites. The shared web-search budget ran out after four searches, so several items rest on direct fetches of known URLs plus prior knowledge; those are marked "(not re-verified)".

## TL;DR

- **Licence choice decides the embedding goal.** Apache-2.0 userland plus dual-licensed (`Dual MIT/GPL` or `GPL-2.0 OR BSD-2-Clause`) eBPF programs is the only combination a proprietary EDR vendor can embed. The kernel docs say LSM BPF programs must be GPL-compatible and that GPL BPF programs may be packaged with non-GPL userspace. AGPL for the sensor would block embedding.
- **A permissive Rust stack exists for the whole observe path**: `aya` 0.16 (Linux), `endpoint-sec` 0.6.2 (macOS), `windows` 0.62 + `ferrisetw` 1.2 (Windows ETW), `rsigma-eval` 0.26 (Sigma), `yara-x` 1.23, `cel` 0.15, `tough` 0.24 (TUF), `sigstore` 0.15. Rustinel (Apache-2.0, v1.11.0, 2026-11-08) already ships almost exactly this bill of materials and is the closest prior art.
- **Blocking is the hard part, and it is gated by platform owners, not by code.** macOS needs an Apple-granted Endpoint Security entitlement. Windows kernel blocking needs an EV certificate plus Microsoft dashboard signing, and Microsoft's docs now describe attestation signing as "for testing purposes only". Linux is the only platform where an open-source project can block without a gatekeeper (BPF LSM, fanotify permission events).
- **Windows is mid-transition.** Built-in Sysmon is a documented optional feature of Windows 11 and Server 2025 (Learn page dated 2026-02-24). The Windows Endpoint Security Platform (`wesp.sys` + `espclient.dll`) is in Insider build 29661, gated by a token attribute and Antimalware PPL, with no user-mode veto found yet.
- **eBPF for Windows is not a sensor foundation yet**: v1.7.0 (2026-10-16), every GitHub release still flagged pre-release, README says "work-in-progress", hooks are network plus process only, and each program must be compiled to a signed `.sys` under HVCI.
- **Santa (North Pole Security, Apache-2.0, 2026.9) is the best macOS enforcement prior art**: CEL rules over exec context, file-access authorisation with four rule types, Touch ID or security-key step-up. Consume it where present; borrow its policy model.
- **No reusable Rust OpAMP client exists** under an open licence. New Relic's is under a proprietary licence; `otel-opamp-rs` is stale. We write this.
- **Avoid as dependencies**: OpenEDR (Comodo "available source" licence, last release 2022), WinDivert (last release 2022-09), Wazuh agent (GPL-2.0-only), Elastic `protections-artifacts` and non-GPL eBPF (Elastic License 2.0), Sealighter (no licence file, dead since 2022).
- **GPL-3.0 Rust or driver code is learn-only** for an Apache-2.0 sensor: Kunai, Chainsaw, Portmaster's Rust WFP kext, Fort, Sandboxie, LuLu, BlockBlock.
- **`windows-drivers-rs` still says "not yet recommended for production"** (wdk 0.5.0, 2026-10-26). Portmaster proves a Rust WFP callout driver can ship, but with its own bindings.

## Findings

### 1. Licence compatibility

- Kernel BPF licensing doc: BPF programs follow kernel-module licence checks; programs using "GPL only" helpers must be GPL-compatible; since August 2021, LSM and struct_ops programs must be GPL-compatible even without calling such helpers; proprietary userspace and GPL BPF programs can be packaged together. https://docs.kernel.org/bpf/bpf_licensing.html
- Existing practice confirms the split. Pulsar: Apache-2.0 userspace, GPL-2.0 probes (LICENSE read 2026-11-09). Sysmon for Linux: MIT, eBPF programs GPL-2, SysinternalsEBPF LGPL-2.1. Elastic `ebpf`: `GPL/` directory is GPL-2.0 OR BSD-2-Clause, `non-GPL/` is Elastic License 2.0.
- Consequences for us, by project licence:

| Upstream licence | Into an Apache-2.0 sensor | Into an AGPL-3.0 sensor |
|---|---|---|
| MIT, BSD, Apache-2.0 | Link freely | Link freely |
| MPL-2.0 (Vector) | Use as library; file-level copyleft | Same |
| LGPL (libbpf-rs option, WinDivert, SysinternalsEBPF) | Dynamic link only | Dynamic link or absorb |
| GPL-3.0 (Kunai, Chainsaw, Portmaster, Fort, Sandboxie, LuLu) | Separate process only | Can combine |
| AGPL-3.0 (Hayabusa, Velociraptor, Wazuh engine) | Separate process only | Can combine |
| GPL-2.0-only (Wazuh agent, most kernel-side BPF) | Separate process only | Not combinable in one binary |
| Elastic License 2.0, Comodo CASL, New Relic licence | Do not use | Do not use |

- `libbpf-rs` is `LGPL-2.1-only OR BSD-2-Clause`, so the BSD option makes it usable. `osquery` is `Apache-2.0 OR GPL-2.0-only`. `aya` is `MIT OR Apache-2.0`.

### 2. Linux

- **aya** (v0.16.0, 2026-10-28, MIT/Apache, 4.9k stars, 5.2M downloads). Pure Rust loader and `aya-ebpf` program crate. Used by Kunai, bombini and Rustinel. Reuse as the primary dependency. https://github.com/aya-rs/aya
- **libbpf-rs** (v0.27.2, 2026-09-25). Mature fallback when a C program and CO-RE skeleton are preferable. `blazesym` (BSD-3) for symbolisation.
- **bombini** (Apache-2.0, v1.2.0, 2026-11-07, 80 stars). Rust + aya, built on LSM BPF hooks. Rules compile into eBPF maps and are evaluated in kernel; sandbox mode returns `EPERM` for exec, file open and connect. Needs Linux 6.2+ with BPF LSM. Has an io_uring detector and a BPF-activity detector. Closest architectural match; small community. Learn from, possibly vendor. BPF-side licence string not verified. https://github.com/bombinisecurity/bombini
- **Kunai** (GPL-3.0, v0.6.2 released 2025-11-12, commits to 2026-11-09). Rust + aya, Sysmon-like events, observe only. Learn only for an Apache project.
- **Pulsar** (Apache-2.0 + GPL-2.0 probes, v0.10.1, 2026-09-30). Rust, modular, kernel 5.5+, rules engine, IoT focus. Learn from; module layout is reusable thinking.
- **Tetragon** (Apache-2.0, v1.8.0, 2026-10-30). Go agent. Enforcement via return-value override, signals and LSM hooks; docs warn that SIGKILL alone does not stop an in-flight operation and should be combined with Override. v1.8 adds CEL in register overrides and keeps LSM enforcement alive after agent exit. Windows support is preview with process exec/exit only. Consume as a data source over gRPC or JSON on Kubernetes; do not embed. https://tetragon.io/docs/concepts/enforcement/
- **Falco** (0.45.2, libs 0.26.1, Apache-2.0). Observe only. Plugins are shared libraries that add event sources, fields, parsing and async events. Rust plugin SDK exists but is "incubating" with 12 stars. Consume Falco alerts; optionally ship a Falco plugin that exposes our agent events to Falco rules. https://falco.org/docs/concepts/plugins/
- **Tracee** (Apache-2.0). Last release v0.24.1 on 2025-11-19; newest commits late September 2026. Momentum risk. Data source only.
- **KubeArmor** (Apache-2.0, v1.7.7-rc1). Enforces through AppArmor, SELinux or BPF-LSM; supports VM and bare-metal mode. Data source and policy-model reference.
- **Elastic quark** (Apache-2.0, v0.11, 2026-11-02). C library that abstracts process-event backends and handles ordering and aggregation of fork/exec/exit. Useful reference for the process-cache problem.
- **Sysmon for Linux** (MIT, 1.6.0, 2026-11-06, repo now `microsoft/Sysmon-Linux`). Data source via syslog.
- **Kernel primitives we call directly**: fanotify permission events (`FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`; `FAN_DENY_ERRNO` since 6.13 with pre-content class) as the fallback where BPF LSM is off; fanotify does not see mmap or remote network-filesystem events. `landlock` crate (0.4.7, MIT/Apache) for self-sandboxing agent child processes. https://man7.org/linux/man-pages/man7/fanotify.7.html

### 3. macOS

- **Entitlement**: `com.apple.developer.endpoint-security.client` must be requested from Apple; without it `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`. Anyone who rebuilds our sensor needs their own grant. https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- **Event surface**: Apple's `es_event_type_t` reference lists 44 AUTH and 67 NOTIFY events in the topic sections (plus XPC and bootstrap cases in the table). AUTH covers exec, open, rename, unlink, mmap, signal, get_task, UIPC connect and more. There is no network AUTH event; network control needs a Network Extension content filter.
- **endpoint-sec** (HarfangLab, MIT/Apache, 0.6.2, 2026-09-08, 228k downloads, MSRV 1.88). Safe wrappers plus `-sys`. Reuse. https://github.com/HarfangLab/endpoint-sec
- **Santa** (northpolesec/santa, Apache-2.0, 2026.9 on 2026-10-27; Google's repo archived 2025-02-05). Rule types CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID. CEL policy since 2025.6 with `target.*` fields (cacheable) and `path`, `args`, `envs`, `euid`, `cwd`, `ancestors` (not cacheable). 2026.9 adds `REQUIRE_TOUCHID`, `REQUIRE_SECURITY_KEY`, `REQUIRE_PRESENCE` with cooldowns. File-access authorisation: plist `WatchItems` with `PathsWithAllowedProcesses`, `PathsWithDeniedProcesses`, `ProcessesWithAllowedPaths`, `ProcessesWithDeniedPaths`, `AuditOnly`, `AllowReadAccess`; no globstar, symlinks not followed, glob expansion is point-in-time. Some CEL helpers are marked Workshop-only (the commercial server). Consume as a data source and enforcement point when installed; borrow the model. https://northpole.dev/features/binary-authorization/ and https://northpole.dev/features/faa/
- **Mac Monitor** (now `Brandon7CC/mac-monitor`, BSD-3-Clause per GitHub, v3.0.0 on 2026-11-02, Swift). ES system extension that only processes events during a trace. Learn from its enrichment and schema.
- **osquery** `es_process_events` needs Full Disk Access; an MDM PPPC profile with `SystemPolicyAllFiles` grants it silently. OpenBSM is deprecated. https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
- **LuLu** (GPL-3.0, v4.5.7, 2026-11-02) and **BlockBlock** (GPL-3.0): Network Extension and ES references. Learn only.
- **eslogger** (not re-verified): Apple's built-in ES-to-JSON tool, root plus Full Disk Access, notify events only, not a stable interface. Useful for a no-entitlement "laptop mode" and for tests.
- Rustinel's macOS path uses `endpoint-sec` with a packaged entitlements file, plus `/dev/bpf` packet capture for network with 250 ms socket-list attribution. Marked experimental. https://docs.rustinel.io/limitations/

### 4. Windows

- **Signing**. Kernel drivers must be Microsoft-signed through the Hardware Dev Center. Attestation signing needs an EV certificate, is described as "for testing purposes only", does not produce ELAM signature levels, and is not accepted on Windows Server 2016+ (HLK required). Page dated 2026-03-23. https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
- **Protected service**. Running as Antimalware PPL requires an ELAM driver carrying the service's certificate hashes; ELAM needs an HLK submission. PPL is also the gate for the ETW Threat-Intelligence provider (Rustinel docs confirm it ships no driver and cannot read TI). https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- **Built-in Sysmon**. Optional feature on Windows 11 and Server 2025; `sysmon -i [config]`; serviced through Windows Update; cannot coexist with standalone Sysmon; rendered messages are localised but XML is stable; "raw telemetry rather than active prevention". https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview
- **WESP**. Elastic Security Labs (2026-10-26): `wesp.sys` is a minifilter at altitude 329500 talking over `ESPFilterPort`; `espclient.dll` has about 120 `Esp*` exports; no `FilterReplyMessage` import, so no user-mode veto yet. Jonathan Johnson (2026-09-11, build 29661): `EspRegisterClient`, `EspCreateEventQueue`, `EspCreateRule`; events for process, thread, image, file, registry, handle; access gated by a `WESP://Permission` token attribute and Antimalware PPL. No public SDK. https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp and https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/
- **ETW in Rust**. `ferrisetw` 1.2.0 (MIT/Apache; crate last published 2024-06-27, repo touched 2025-10) is thinly maintained but in production use by Rustinel. `krabsetw` (MIT) is C++ and .NET only. Plan to fork ferrisetw or write a thin layer on `windows` crate ETW bindings.
- **windows-rs** (`windows` 0.62.2, MIT/Apache): reuse for all Win32. **windows-drivers-rs** (wdk 0.5.0, wdk-build 0.6.0, 2026-10-26): README states early stage, not recommended for production, crates.io builds target KMDF 1.33 only.
- **WFP from user mode**. The Base Filtering Engine accepts permit and block filters from an administrator, with per-application conditions at ALE layers; callout drivers are only needed for inspection and modification. Mullvad's `wfp` crate (0.3.0, 2026-11-02, MIT/Apache) wraps this. This gives per-process network blocking with no driver of ours. https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- **Portmaster** (GPL-3.0, v2.2.8). `windows_kext/` is a Rust WFP callout driver with its own `wdk` crate, amd64 only. Best public example; licence prevents reuse in Apache code.
- **Fort** (GPL-3.0, v3.20.9): README tells users to disable HVCI. **Sandboxie** (GPL-3.0 classic, custom Plus licence). **WinDivert** (LGPLv3/GPLv2, v2.2.2 from 2022-09-21, no commits since 2023-03). Learn only or avoid.
- **eBPF for Windows** (MIT, v1.7.0). Program types: XDP, BIND, CGROUP_SOCK_ADDR, SOCK_OPS, NETEVENT, PROCESS. `ntosebpfext` (MIT) wraps `PsSetCreateProcessNotifyRoutineEx` to "monitor and control" process creation and its docs assume a test-signed machine. No file or registry hooks. Watch, do not depend.
- **Fibratus** (Apache-2.0, v3.1.1, Go): ETW-based detection with rules and YARA. Data source and rule reference.
- **JonMon** (MIT; repo now `jonny-jhnson/JonMon`): self-described research project, last push 2025-06. **Sealighter**: no licence, last push 2022-11. Learn only.
- **OpenEDR**: "Comodo Available Source License" since 2020, includes arbitration terms; last release 2022-09. Not open source. Do not use, and keep AI coding agents away from its code.

### 5. Detection engines and content

- **rsigma** (timescale, MIT, v0.26.0, 2026-11-02): parser, evaluator, correlation, linter, OTLP input, pySigma-compatible pipelines, MCP and LSP servers. `rsigma-eval` is the library. Reuse. **sigma-rust** (Apache-2.0, 0.7.0, 2025-11) is the smaller alternative.
- **YARA-X** (BSD-3, v1.23.0, 2026-11-05). Reuse.
- **cel** crate (cel-rust, MIT, 0.15.0, 2026-10-06, 5.8M downloads). Reuse for policy; aligns with Santa and Tetragon.
- **Hayabusa** (AGPL-3.0, v4.3.1) and **Chainsaw** (GPL-3.0, v2.17.1): offline EVTX hunting. Run as tools, do not link. Sigma rule content carries the Detection Rule License (not re-verified); Elastic `protections-artifacts` is Elastic License 2.0 and bars offering as a managed service.

### 6. Fleet, pipeline, update and packaging

- **osquery** 5.24.1 and **Fleet** 4.94.1 (MIT outside `ee/`). Orbit is an osquery installer and auto-updater. Consume osquery where present; ship an osquery extension exposing agent-inventory tables.
- **Wazuh** v4.14.10: agent GPL-2.0-only, engine AGPL-3.0. **Velociraptor** v0.77.3: AGPL-3.0. Integrate over their APIs and ship artifacts or decoders as content.
- **OpAMP**: spec status Beta. Packages, connection-settings offers and commands are Beta; custom messages, CSR flow and heartbeats are Development. WebSocket and HTTP transports, 16-byte `instance_uid` (UUIDv7 recommended). `opamp-go` v0.25.0 is the reference. https://opentelemetry.io/docs/specs/opamp/
- **OTel Collector** v0.165.0 (Apache-2.0, Go), **Vector** v0.61.0 (MPL-2.0, Rust), **Fluent Bit** v5.2.0 (Apache-2.0, C). Rust-native OTLP options: `rotel` (Apache-2.0) and `otel-arrow` dataflow engine (Apache-2.0). Emit OTLP and let users choose the collector.
- **TUF**: `tough` 0.24.0 (MIT/Apache, 2.9M downloads) is the maintained Rust client; `rust-tuf` is at 0.3.0-beta9; `go-tuf` v2.4.2 for the server side. **sigstore-rs** 0.15.0 (2026-11-05).
- **dist** (formerly cargo-dist) v0.34.0, active. **WiX** v7.0.1 (MS-RL). **nfpm** v2.48.0 (MIT). **SignPath Foundation** signs OSS Windows binaries for free with the Foundation as publisher; terms require an OSI licence with no commercial dual-licensing and exclude hacking tools while permitting breach and malware detection. It does not cover kernel drivers. https://signpath.org/terms

## Matrix

| Block | Licence | Latest (date) | OS | Blocks? | Embedding | Gate inherited | Verdict |
|---|---|---|---|---|---|---|---|
| aya | MIT/Apache | 0.16.0 (2026-10) | Linux | Yes, via LSM programs | Rust crate | root or CAP_BPF; BPF LSM enabled | Reuse |
| libbpf-rs | LGPL-2.1 or BSD-2 | 0.27.2 (2026-09) | Linux | Yes | Rust crate | Same | Reuse as fallback |
| bombini | Apache-2.0 | 1.2.0 (2026-11) | Linux 6.2+ | Yes | Binary; vendor code | BPF LSM | Learn, maybe vendor |
| Kunai | GPL-3.0 | 0.6.2 (2025-11) | Linux | No | Binary | none | Learn only |
| Pulsar | Apache + GPL-2 probes | 0.10.1 (2026-09) | Linux 5.5+ | No | Binary, modules | none | Learn |
| Tetragon | Apache-2.0 | 1.8.0 (2026-10) | Linux; Windows preview | Yes | gRPC, JSON | none | Data source |
| Falco + libs | Apache-2.0 | 0.45.2 (2026-10) | Linux | No | Plugin C ABI, alerts | none | Data source |
| Tracee | Apache-2.0 | 0.24.1 (2025-11) | Linux | Limited | Binary | none | Data source, at risk |
| KubeArmor | Apache-2.0 | 1.7.7-rc1 | Linux | Yes | Daemon, CRDs | LSM present | Data source |
| endpoint-sec | MIT/Apache | 0.6.2 (2026-09) | macOS | Yes (AUTH events) | Rust crate | Apple ES entitlement | Reuse |
| Santa | Apache-2.0 | 2026.9 (2026-10) | macOS | Yes | Sync protocol, protobuf logs | NPS-signed, or own entitlement | Data source, model |
| Mac Monitor | BSD-3 | 3.0.0 (2026-11) | macOS | No | App | ES entitlement | Learn |
| LuLu, BlockBlock | GPL-3.0 | 4.5.7 | macOS | Yes | App | NE and ES entitlements | Learn only |
| windows-rs | MIT/Apache | 0.62.2 | Windows | n/a | Rust crate | none | Reuse |
| ferrisetw | MIT/Apache | 1.2.0 (2024-06) | Windows | No | Rust crate | admin; PPL for TI | Reuse, plan fork |
| wfp (Mullvad) | MIT/Apache | 0.3.0 (2026-11) | Windows | Yes (network) | Rust crate | admin | Reuse |
| windows-drivers-rs | MIT/Apache | wdk 0.5.0 | Windows | Yes | Rust crates | EV cert, HLK or attestation | Prototype only |
| Built-in Sysmon | Windows feature | 2026 | Win 11, Server 2025 | No | Event log | none | Data source |
| WESP | Windows preview | build 29661 | Windows Insider | Not yet | `espclient.dll` | PPL plus token attribute | Design for, wait |
| eBPF for Windows | MIT | 1.7.0 pre-release | Win 11, Server 2022+ | Process, network | libbpf API | signed native `.sys` | Watch |
| Portmaster kext | GPL-3.0 | 2.2.8 | Windows | Yes (network) | Driver | driver signing | Learn only |
| WinDivert | LGPLv3/GPLv2 | 2.2.2 (2022) | Windows | Yes | DLL + driver | signed by author | Avoid |
| Fibratus | Apache-2.0 | 3.1.1 | Windows | Kill only | Binary | admin | Data source |
| OpenEDR | Comodo CASL | 2.5.1 (2022) | Windows | Yes | n/a | n/a | Avoid |
| osquery | Apache or GPL-2 | 5.24.1 | All | No | Extension socket | FDA on macOS | Data source |
| Wazuh agent | GPL-2.0-only | 4.14.10 | All | Active response | Agent, API | none | Data source |
| Velociraptor | AGPL-3.0 | 0.77.3 | All | Response actions | Artifacts, API | none | Data source |
| rsigma-eval | MIT | 0.26.0 | All | n/a | Rust crate | none | Reuse |
| YARA-X | BSD-3 | 1.23.0 | All | n/a | Rust crate | none | Reuse |
| cel | MIT | 0.15.0 | All | n/a | Rust crate | none | Reuse |
| tough | MIT/Apache | 0.24.0 | All | n/a | Rust crate | none | Reuse |
| sigstore-rs | Apache-2.0 | 0.15.0 | All | n/a | Rust crate | none | Reuse |
| opamp-go | Apache-2.0 | 0.25.0 | All | n/a | Go library | none | Server side, reference |
| dist, WiX, nfpm | Apache, MS-RL, MIT | 0.34.0, 7.0.1, 2.48.0 | Build | n/a | Tools | signing certs | Reuse |

## Weak points, gaps and risks

- **Platform gatekeeping conflicts with "everything is open source".** A self-built macOS sensor cannot load without an Apple entitlement. A self-built Windows driver cannot load outside test mode. Reproducible source is not enough; we need an official signed distribution and a degraded no-gate mode.
- **Windows Server blocking needs HLK-certified drivers.** Attestation-signed filter drivers are not accepted on Server 2016+, and attestation is framed as test-only.
- **WESP may be closed to non-MVI projects.** Reverse engineering shows a token attribute and PPL check. Whether an open-source project can qualify is unknown.
- **Rust kernel driver tooling is immature.** Microsoft's own README says so. A C or C++ minifilter with a Rust user-mode service is the lower-risk path if we ever ship a driver.
- **ferrisetw maintenance.** Critical Windows dependency with no crate release since mid-2024.
- **ETW cannot block and can be blinded** by an administrator; Rustinel documents truncated command lines, deferred hashes and missing process-access and injection events.
- **Linux fragmentation.** BPF LSM needs kernel support and `bpf` in the active LSM list; bombini requires 6.2+. Enterprise kernels and locked-down containers will need the fanotify or observe-only tier.
- **Tetragon's own docs admit kill races.** Signal-based enforcement does not undo an in-flight write.
- **Tracee and Kunai release cadence** has slowed; neither has shipped a tagged release in 2026.
- **AI-written code and licence contamination.** With coding agents implementing the product, GPL, ELv2 and CASL repositories must be on an explicit do-not-read list.

## Implications for our design

1. **Licence**: Apache-2.0 for sensor userland and SDK; eBPF programs declared `Dual MIT/GPL`; no GPL or AGPL linked in process. Keep GPL tools behind process boundaries.
2. **Three capability tiers per OS**, reported honestly in the UI: (a) no-gate observe (ETW and event logs, eslogger, eBPF tracing), (b) gate-free enforce (WFP user-mode filters and App Control policy on Windows, BPF LSM and fanotify on Linux, in-agent hooks and gateways everywhere), (c) signed enforce (ES AUTH on macOS, optional Windows driver, later WESP).
3. **Sensor backend trait.** One normalised event model with pluggable sources so WESP, eBPF for Windows or a vendor's own EDR driver can be swapped in. This is also the embedding seam for EDR vendors: they feed their kernel telemetry in and take our agent attribution and policy decisions out.
4. **Adopt Rustinel's proven stack** and check whether contributing or building on it beats starting clean: aya, endpoint-sec, ferrisetw, windows, rsigma, yara-x, with capture and replay for rule tests.
5. **Policy language is CEL** (cel crate), with Santa-style split between cacheable identity fields and non-cacheable context fields, and Santa-style rule types for file access (data-centric and process-centric).
6. **Consume before collecting.** Adapters for built-in Sysmon, Santa logs, osquery, Falco, Tetragon, KubeArmor and Wazuh. On a machine that already has these, our sensor adds agent attribution and policy, not duplicate hooks.
7. **Write our own OpAMP client in Rust** from the spec protobufs; use `opamp-go` in the control plane. Use Beta features only; put agent-specific control in custom messages behind a version flag.
8. **Updates**: TUF metadata via `tough`, artefact signatures via sigstore, OpAMP only as the offer channel. Build with dist, WiX and nfpm. Windows user-mode binaries through SignPath Foundation or our own certificate.
9. **Start the Apple entitlement request and Microsoft hardware program registration now.** Both are lead-time items outside engineering control.

### Recommended bill of materials

| Layer | Linux | macOS | Windows |
|---|---|---|---|
| Collect | aya + own eBPF programs (tracepoints, LSM, cgroup sock) | endpoint-sec in a system extension; eslogger fallback | ferrisetw or own ETW layer on `windows`; built-in Sysmon channel |
| Enforce | BPF LSM; fanotify `FAN_OPEN_EXEC_PERM` fallback; landlock for wrapped agents | ES AUTH events; NE content filter | `wfp` user-mode filters; App Control policy; optional signed driver later |
| Detect | rsigma-eval, yara-x, cel | same | same |
| Manage | own OpAMP client, tough, sigstore | same | same |
| Emit | OTLP (logs), optional Falco plugin, osquery extension | OTLP, osquery extension | OTLP, Windows event channel |
| Package | nfpm deb and rpm, systemd unit | notarised app bundle with system extension | WiX MSI, signed service |

**We must write ourselves**: the normalised event model and process-lineage cache; agent-versus-human attribution; AI-agent discovery inventory; all eBPF programs; the macOS system-extension host and NE filter; the Windows ETW session manager and any driver; the Rust OpAMP client; the embedding SDK (C ABI plus gRPC); source adapters; tamper resistance; and installers with clean uninstall.

## Ideas worth stealing and whitespace

- **Santa's step-up approval** (`REQUIRE_TOUCHID` with cooldown) applied to agent actions: a human-presence check is a direct answer to agent-versus-human attribution on shared credentials. Nobody does this on Windows or Linux.
- **Santa's data-centric file rules** fit secrets protection: "only these signed processes may read `~/.aws`, `~/.ssh`, agent credential stores".
- **bombini's rules-compiled-to-maps** for in-kernel filtering, and Tetragon's persistent LSM enforcement after agent exit.
- **Rustinel's capture and cross-platform replay**, plus `sigma doctor` explaining which rules can never fire on a host.
- **rsigma's MCP server**: detection tooling exposed to coding agents. Our sensor could expose its own policy test harness the same way.
- **Whitespace**: no open-source project offers one Apache-licensed Rust sensor that enforces on all three OSes; none attributes events to an AI agent session; none ships a Rust OpAMP client; none provides an embeddable SDK for EDR vendors; none has an open path onto WESP.

## Could not verify / open questions

- Web search budget was exhausted early; the following were not re-verified against 2026 primary sources: eslogger behaviour, Network Extension entitlement process, Sigma rule licence text, Fleet Orbit's TUF usage, WiX maintenance-fee terms, Tetragon and Falco BPF-side licence strings, bombini's BPF licence string.
- Whether built-in Sysmon is generally available on all Windows 11 and Server 2025 channels, and its exact GA update. The Learn page exists and is dated 2026-02-24.
- Whether Microsoft will admit open-source projects to MVI and WESP, and whether WESP will gain authorisation events.
- macOS version in which each ES event appeared, and events added in the latest macOS release (Apple's page was truncated).
- How Rustinel obtains and distributes its ES entitlement.
- Whether Apple will grant an ES entitlement to an open-source project whose users rebuild from source.
- Mac Monitor's move to a personal repository and BSD-3 licence was seen only through API metadata.
- Not reached: `falco.org/docs/plugins/` (redirect returned no body on first attempt), `docs.ebpf.io/linux/concepts/licensing/` (404).

## Sources

All accessed 2026-11-09.

- https://docs.kernel.org/bpf/bpf_licensing.html — BPF licensing (kernel docs)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings — Driver Signing Options (2026-03-23)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation — Attestation Sign Windows Drivers (2025-07-15, updated 2026-04-14)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later- — Kernel-Mode Code Signing Requirements
- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services- — Protecting anti-malware services
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview — Built-in Sysmon overview (2026-02-24, updated 2026-10-08)
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112 — Native Sysmon announcement (2025-11-18)
- https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform — About Windows Filtering Platform
- https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp — What wesp.sys reveals about WESP (2026-10-26)
- https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/ — First look inside WESP (2026-09-11)
- https://github.com/microsoft/ebpf-for-windows and https://github.com/microsoft/ntosebpfext — README, releases, `ebpf_structs.h`
- https://github.com/microsoft/windows-drivers-rs — README
- https://github.com/safing/portmaster/tree/master/windows_kext — Rust kext README
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client — ES client entitlement
- https://developer.apple.com/documentation/endpointsecurity/es_event_type_t — ES event types
- https://northpole.dev/features/binary-authorization/ and https://northpole.dev/features/faa/ — Santa docs (2026.9)
- https://github.com/HarfangLab/endpoint-sec — endpoint-sec README
- https://osquery.readthedocs.io/en/stable/deployment/process-auditing/ — osquery process auditing
- https://tetragon.io/docs/concepts/enforcement/ and https://github.com/cilium/tetragon/releases/tag/v1.8.0 — Tetragon enforcement, v1.8.0 notes
- https://falco.org/docs/concepts/plugins/ — Falco plugins
- https://man7.org/linux/man-pages/man7/fanotify.7.html — fanotify(7)
- https://opentelemetry.io/docs/specs/opamp/ and https://github.com/open-telemetry/opamp-spec — OpAMP specification (Beta)
- https://signpath.org/terms — SignPath Foundation conditions
- https://github.com/Karib0u/rustinel and https://docs.rustinel.io/limitations/ — Rustinel v1.11.0
- https://github.com/timescale/rsigma — rsigma v0.26.0
- https://github.com/bombinisecurity/bombini — bombini v1.2.0
- https://github.com/ComodoSecurity/openedr/blob/main/LICENSE.md — Comodo Available Source License
- GitHub API metadata for every repository named above; crates.io API for crate versions and licences

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: primary docs fetched directly, GitHub and crates.io APIs (read-only), kernel and project source, and read-only inspection of WESP binaries on a Windows 11 26H2 machine. The shared web-search budget was already exhausted, so no search-engine queries were run; WESP has no independent third-party write-up beyond the two posts already cited._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | LSM and struct_ops BPF programs must be GPL-compatible; GPL BPF programs may be packaged with proprietary userspace | Confirmed | Kernel doc text matches. Enforced in code: `bpf_lsm_verify_prog` rejects with "LSM programs must have a GPL compatible license". The doc's reason for allowing joint packaging is that they are "separate executable processes", and it tells readers to consult a lawyer. | https://raw.githubusercontent.com/torvalds/linux/master/Documentation/bpf/bpf_licensing.rst ; https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/bpf_lsm.c |
| 2 | ES client entitlement must be requested from Apple; without it `es_new_client` fails with `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` | Confirmed | Apple's entitlement page says both, verbatim ("You must request this entitlement from Apple"). | https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client.json |
| 3 | Attestation signing is "for testing purposes only", needs an EV certificate, cannot produce ELAM levels; Server 2016+ loads only HLK-passed dashboard-signed drivers | Confirmed | All four points are verbatim on the page (ms.date 2026-03-23). The separate attestation how-to repeats the EV and testing-scenario wording. Additional: attestation works only on Windows 10 desktop and later, and the page now lists a "preproduction signing" option that supports ELAM attributes but loads only on explicitly provisioned test devices. | https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings ; https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation |
| 4 | Antimalware PPL service requires an ELAM driver embedding the service's signing-certificate hashes | Confirmed | "the anti-malware vendor must have an ELAM driver installed"; hashes go in a `MicrosoftElamCertificateInfo` resource. `InstallELAMCertificateInfo` only avoids the reboot, not the driver. Context: MVI entry criteria require a commercially available real-time protection product with yearly independent-lab certification. | https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services- ; https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria |
| 5 | WESP (`wesp.sys`, `espclient.dll`) is present only in Insider builds, gated by `WESP://Permission` and Antimalware PPL, with no user-mode veto path | Corrected | Not Insider-only. Both binaries are on disk on a machine running GA Windows 11 26H2 build 26300.9818 (26H2 GA 2026-09-29; flighting registry values empty): file version 0.1.0.x, signed "Microsoft Windows", `wesp` registered as a boot-start `FSFilter Anti-Virus` driver at altitude 329500, state Stopped. Same binaries: `WESP://Permission` and `\EspFilterPort` strings present in `wesp.sys`; `espclient.dll` imports `FilterGetMessage` and `FilterSendMessage` but not `FilterReplyMessage`; none of its 125 `Esp*` names suggests a verdict API. So the gating and no-veto parts hold. PPL is conditional: Johnson reports one permission value needs no PPL and another needs Antimalware PPL. Single machine observed; no public SDK found. | Local inspection of `C:\Windows\System32\drivers\wesp.sys` and `espclient.dll`; https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information ; https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp |
| 6 | Built-in Sysmon is an optional feature on Windows 11 and Server 2025, serviced via Windows Update, cannot coexist with standalone Sysmon, telemetry only | Confirmed | All four points are on the Learn page (updated 2026-10-08): "Standalone Sysmon must be uninstalled before enabling built-in Sysmon"; "raw telemetry rather than active prevention". The page gives no minimum build or GA update; that open question stands. | https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview |
| 7 | eBPF for Windows v1.7.0 (2026-10-16) is pre-release and work-in-progress; HVCI needs signed native drivers; program types are XDP, bind, sock_addr, sock_ops, netevent, process | Confirmed | Releases API: v1.7.0 published 2026-10-16, `prerelease=true` on every release, and `/releases/latest` returns 404. README says "work-in-progress" and that neither JIT nor interpreter works on an HVCI production system. `ebpf_structs.h` enum matches; `BPF_PROG_TYPE_BIND` is marked deprecated. The platform is extensible, but new hooks mean writing and signing a kernel extension driver. | https://github.com/microsoft/ebpf-for-windows (README, `include/ebpf_structs.h`, releases API) ; https://github.com/microsoft/ntosebpfext |
| 8 | windows-drivers-rs (wdk 0.5.0, 2026-10-26) says early stage, not recommended for production | Confirmed | README line: "still in early stages of development and is not yet recommended for production use". wdk 0.5.0 published 2026-10-26 on crates.io and GitHub; crates.io builds support KMDF 1.33 only. | https://github.com/microsoft/windows-drivers-rs ; https://crates.io/crates/wdk |
| 9 | Santa (Apache-2.0, 2026.9) supports CEL rules over exec context, Touch ID or security-key step-up, and file-access authorisation with four rule types | Confirmed | Licence, release date (2026-10-27), CEL fields and the four `RuleType` values verified in the docs source. Caveats: the 2026.9 release notes tag the FIDO2 security-key option "[Workshop customers]"; `ancestors`, the time helpers and annotations are Workshop-only; the docs warn step-up proves presence only, not identity. | https://github.com/northpolesec/santa/releases/tag/2026.9 ; `docs/docs/features/binary-authorization.mdx` and `faa.mdx` in that repo |
| 10 | OpAMP is Beta; packages, connection-settings offers and commands Beta; custom messages and heartbeats Development; no Rust client under an open-source licence | Corrected | Spec statuses hold (spec v0.20.0, 2026-08-12). New Relic's licence is proprietary as stated ("New Relic Software License v1.0": New Relic service only, no modification). But open-licence Rust implementations do exist: `otel-opamp-rs` (Apache-2.0 repo, 0.0.14 published 2025-10-01), the OpAMP extension inside `open-telemetry/otel-arrow` (`rust/otap-dataflow/crates/controller/src/extension/opamp`), `neteye-platform/classis` `opamp` crate (MIT OR Apache-2.0, created 2026-10-19), and `oxtel-opamp` 0.0.1. Right statement: none is mature or widely adopted. Evaluate them before writing from scratch. | https://github.com/open-telemetry/opamp-spec/blob/main/specification.md ; https://github.com/newrelic/newrelic-opamp-rs/blob/main/LICENSE.md ; https://crates.io/crates/otel-opamp-rs ; https://github.com/neteye-platform/classis |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Findings 4: user-mode WFP filters give "per-process network blocking with no driver of ours" | Corrected | The granularity is per application path, user SID and package SID. `FWPM_CONDITION_ALE_APP_ID` is the executable's device path; no condition matches a PID or process instance. Two instances of the same `node.exe` or `python.exe` (agent-driven and human-driven) cannot be told apart by BFE filters alone. | https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers- |
| TL;DR: Apache userland plus dual-licensed eBPF is "the only combination a proprietary EDR vendor can embed" | Corrected (overstated) | The kernel doc cited for claim 1 allows GPL-only BPF programs to be packaged with proprietary userspace. Dual licensing is a convenience for code reuse, not a precondition for embedding. | https://raw.githubusercontent.com/torvalds/linux/master/Documentation/bpf/bpf_licensing.rst |
| Risks: neither Tracee nor Kunai "has shipped a tagged release in 2026" | Corrected (minor) | Kunai tagged v0.7.0-rc.1 (pre-release) on 2026-03-11; no stable release in 2026. Tracee holds: last tag v0.24.1 on 2025-11-19. | GitHub releases API for `kunai-project/kunai` and `aquasecurity/tracee` |

Also spot-checked and found accurate: versions, dates and licences for aya, endpoint-sec, ferrisetw, wfp, cel, tough, sigstore, rsigma-eval, yara-x, landlock, libbpf-rs and windows on crates.io; release metadata for Tetragon v1.8.0, Rustinel v1.11.0, bombini v1.2.0 and opamp-go v0.25.0.
