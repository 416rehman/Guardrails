# G05: Coexisting with incumbent EDR, DLP and ZTNA agents, and the cross-platform verification lab

_Researched 2026-11-09_

Method note: the shared web-search budget for this run was already exhausted, so this brief rests on direct fetches of primary documentation (Microsoft Learn, Apple developer JSON, kernel source, vendor docs, GitHub via `gh`). Each claim is tagged **[V]** (verified in a primary source today) or **[K]** (prior knowledge, cutoff mid-2026, not re-verified today). Vendor-gated portals (CrowdStrike, SentinelOne, Cortex, Zscaler) were not reachable.

## TL;DR

- **Windows production kernel code now means HLK/WHCP, not attestation.** Microsoft's signing page (2026-03-23) describes attestation signing as "for testing purposes only"; Windows Server 2016+ never loads attested filter drivers, and ELAM binaries must go through `.hlkx` [V].
- **ELAM, antimalware-PPL and Security Center registration are gated by MVI**, which requires a commercially available real-time antimalware product certified yearly by an independent lab, an NDA and Trusted Signing [V]. An open-source AIDR cannot assume it will get them, so it cannot assume kernel-grade tamper protection on Windows.
- **No Windows or macOS slot is strictly single-owner, but every shared slot is "deny wins, slowest wins".** WFP: block overrides permit across sublayers [V]. Endpoint Security: a missed deadline kills the client, and repeated misses get new connections refused [V]. fanotify: order within a class is undefined [V].
- **Truly single-consumer slots to avoid:** the Linux audit netlink socket (osquery tells you to stop auditd) [V]; macOS PF rules ("PF is not API", TN3165) [V]; the system VPN and DNS-proxy configurations on macOS [K].
- **Linux eBPF is the friendliest substrate, with hard limits:** at most 36 (x86-64) or 37 (arm64) BPF trampoline links per attach point, shared by every vendor's fentry/fexit/LSM programs [V]; BPF LSM programs chain and see the previous program's return value [V]; kill-by-signal does not guarantee the operation was blocked [V].
- **Incumbents are leaving auditd.** Defender for Endpoint on Linux dropped AuditD as a provider from 101.2408.0000 and falls back to Netlink (process events only) where eBPF is unavailable [V]. Its docs list kernel panics on specific kernels, which is the argument for a kernel matrix.
- **TLS interception chaining is a first-order problem.** Netskope states that developer tools often ignore the system store and must be bypassed or scripted [V]. Claude Code trusts the OS store by default, supports `HTTPS_PROXY` but not SOCKS, and documents a gzip incompatibility with some inspection proxies [V].
- **Hosted CI covers more than expected:** GitHub has standard `windows-11-arm`, `ubuntu-24.04-arm` and arm64 macOS runners; Linux x64 runners expose KVM; macOS arm64 runners have no nested virtualization [V].
- **macOS VM testing is licence-bounded:** two additional macOS instances per Apple-branded host, for development and testing; leasing has a 24-hour minimum [V]. Fleet size is therefore a hardware count.
- **Tart changed hands and licence:** the repository now resolves to `openai/tart` with an FSL-1.1-ALv2 licence file, while tart.run still advertises Fair Source tiers [V]. Treat it as a replaceable tool.
- **Kernel-matrix tooling is mature and Apache-2.0:** `cilium/little-vm-helper` (OCI kernel images) and `danobi/vmtest` (Rust, one-liner per kernel) [V].
- **Microsoft's Hardware Dev Center has a real API** (Entra client-credentials), including preproduction signing that keeps Secure Boot on [V]. Altitude allocation is the opposite: email only, 30 business days, public products only [V].

## Findings

### 1. Which of our techniques look like malware, and what relief exists

| Our technique | What incumbents see | Relief |
|---|---|---|
| Kernel driver install (minifilter, WFP callout) | New kernel driver. ASR rule `56a863a9-875e-4185-98a7-b882c64b5ce5` blocks writing known-vulnerable signed drivers [V]; WDAC or HVCI policy may require WHCP-level signing [V] | WHCP signing; publisher or certificate allow rules; documented driver names and altitude |
| Process injection, API hooking, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` | Classic injection behaviour; ASR `75668c1f-…` shows vendors treat injection as having no legitimate use [V] | Do not do it. Use vendor hook surfaces and configuration instead |
| Local TLS proxy plus root CA install | Root-store modification, a loopback listener and browser or agent traffic re-signed by an unknown CA [K] | MDM-delivered CA; prefer explicit `HTTPS_PROXY`/gateway base URL over transparent interception |
| Rewriting agent config (`settings.json`, MCP config, shell rc files) | Persistence and tampering heuristics; DLP file-write monitoring [K] | Use managed-settings channels (MDM, managed settings) rather than editing user files |
| eBPF load, BPF LSM, `bpf_override_return` | "BPF program loaded" detections; possible flagging of unknown programs [K] | Pinned, named programs and maps; published program inventory |
| Endpoint Security client and Network Extension | Legitimate, but a visible new system extension and TCC grant | MDM payloads for system extension, PPPC and content filter |
| Service that spawns shells or scripts | ASR `d1e49aac-…` (PSExec/WMI process creation), `5beb7efe-…` (obfuscated scripts), `c0033c00-…` (copied or impersonated system tools, which can block executables in non-default install paths) [V] | Signed binaries in default paths; no WMI or PsExec; no encoded PowerShell |

Vendor programmes and exclusion mechanics:

- **Microsoft Virus Initiative** (page updated 2026-10-06): requires a commercial real-time protection product, NDA, programme licence, Trusted Signing and yearly certification by AV-Comparatives, AV-TEST, SE Labs, MRG Effitas, VB100 or similar. Applications are reviewed monthly [V]. MVI 3.0 (2025-06-26) adds safe-deployment obligations: rings, monitoring and incident-response testing [V]. Microsoft's own post says MVI participants get access to ELAM and Protected Processes [V].
- **Windows endpoint security platform** (user-mode security outside the kernel): private preview to selected MVI partners planned for July 2025 [V]. I found no public developer documentation in MicrosoftDocs repositories today, so its current status is an open question.
- **Defender coexistence** (2026-08-21): on Windows clients Defender AV auto-disables when another AV registers with Security Center, or goes passive when onboarded to MDE. On Server it does not, and needs `ForceDefenderPassiveMode=1` set before onboarding. ASR, network protection and controlled folder access are inactive in passive mode. Tamper protection lets Defender switch to active but not back to passive [V]. Since we will not register as an AV, Defender stays active alongside us and its ASR rules apply to us.
- **Elastic Defend** documents the reciprocal pattern: allowlist by signer and process rather than by path, in both products, and it lists exact driver, ELAM and executable paths per OS [V]. We should publish the same.
- **Apple**: the Endpoint Security entitlement must be granted by Apple [K]. Content filter, DNS proxy and transparent proxy system extensions can ship with Developer ID outside the App Store [V, TN3134].
- CrowdStrike, SentinelOne and Cortex interoperability guidance sits behind customer portals. Not reached.

### 2. Behaviour of shared OS slots with several vendors present

**Minifilter altitudes (Windows).** Each filter needs a unique altitude. Microsoft assigns one integer altitude per company per load-order group, and vendors may add fractional altitudes themselves [V]. Requests go by ASCII email to `fsfcomm@microsoft.com`, take up to 30 business days, cannot be expedited, and are only processed for publicly shipping products. Test builds may use any value [V]. The allocated list (2026-10-29) shows the neighbourhood: `csagent.sys` 321410, `CyvrFsfd.sys` 321234 and `WdFilter.sys` 328010 in Anti-Virus; `SentinelMonitor.sys` 389040, `mssecflt.sys` 385600, `CarbonBlackK.sys` 386720, `mfeaskm.sys` 386610, `zdpinfrastructure.sys` 363040.5 and `fpepflt.sys` 362930 in Activity Monitor; Netskope `stadrv6x64.sys` 401350.5 and Digital Guardian 401400/401410 in FSFilter Top [V, extracted from a 110k-character page; spot-check before relying on a single value]. A read-only AIDR filter belongs in FSFilter Activity Monitor (360000–389999). Any altitude there sits above the AV group, so we see I/O before AV filters do and see their post-operation results.

**WFP (Windows).** Sublayers are evaluated from highest to lowest weight, and all of them are evaluated even after a block. Block overrides permit. A callout block is soft by default and a filter block is hard. A hard permit can still be vetoed. There is no cross-layer arbitration [V]. Consequences: we can always add a block; we can never force a permit past another vendor; and a ZTNA client and our callout can both act on the same flow. For connect-redirect (the layer ZTNA clients and local proxies both use) WFP exposes redirect state so a callout can detect an earlier redirect by another provider and avoid loops [K]. Our proxy redirect must check this and yield.

**Endpoint Security (macOS).** Several clients coexist. `es_new_client` can fail with `ERR_TOO_MANY_CLIENTS` (the number is not published), `ERR_NOT_ENTITLED`, `ERR_NOT_PERMITTED` (TCC) or `ERR_NOT_PRIVILEGED` (not root) [V]. Missing an AUTH deadline may terminate the client, and repeat offenders may be refused [V]. With several clients every AUTH event waits for all subscribers and any deny wins [K], so our latency adds to Falcon's, SentinelOne's and Defender's. Clients should mute each other's processes to prevent feedback loops [K].

**Network Extension (macOS).** Content filter, packet filter and DNS proxy are system-extension-only on macOS; transparent proxy may be either an app or system extension [V]. Apple's documentation does not describe ordering or verdict combination across several filters [V, absence confirmed on three pages]. Field behaviour is that several content filters can be active and a flow needs every filter's allow, while the system VPN slot and DNS proxy are effectively exclusive [K]. PF must not be used [V].

**Linux.** BPF LSM programs on one hook run in sequence and receive the previous return value [V]. All trampoline-based programs on one function share 36 or 37 slots [V]. fanotify permission listeners are ordered PRE_CONTENT, then CONTENT, then NOTIF, with undefined order inside a class, and need `CAP_SYS_ADMIN` [V]. The audit netlink socket has one consumer, and osquery's `--audit_persist` actively retakes it [V]. Tetragon documents that SIGKILL does not guarantee the triggering operation was stopped and must be paired with return override [V]. TCX multi-program attach (kernel 6.6+) replaces fragile `tc` priority conventions [K].

### 3. TLS interception chaining

- Netskope bypasses predefined certificate-pinned apps by default. For developer tools (AWS CLI, Azure CLI, gcloud, Python, Composer) it recommends a custom app entry with "steer and decrypt", because those tools ignore the system store [V].
- Claude Code (current docs): trusts the bundled Mozilla set plus the OS store (`CLAUDE_CODE_CERT_STORE=bundled,system`; npm installs need Node 22.15+); honours `HTTPS_PROXY`/`NO_PROXY`; has no SOCKS support; supports `NODE_EXTRA_CA_CERTS` and mTLS client certificates. If an inspection proxy mishandles gzip request bodies, `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` is the workaround. Background agents take network settings from settings files, not the shell. A `processWrapper` setting exists for corporate launchers [V].
- Inference: with Zscaler or Netskope present, a second local MITM yields a three-hop trust chain (agent → our CA → ZTNA CA → origin) and two parties rewriting streaming bodies. The durable design is a non-intercepting explicit gateway: set the agent's base URL or `HTTPS_PROXY` to our loopback listener, then originate upstream through the system proxy/PAC and trust the OS store so the ZTNA CA validates. Transparent redirection is a fallback for agents with no proxy setting.
- Zscaler forwarding-profile documentation returned empty (JavaScript-only). Tunnel versus local-proxy/PAC behaviour is not verified.

### 4. Performance budgets

Published vendor budgets are scarce. Verified data points: Datadog's agent publishes about 0.08% CPU and 130 MB RSS on a c5.xlarge, with stated conditions [V], which is the disclosure format to copy. Apple's ES deadline is the only OS-enforced hard budget [V]. Defender on Linux ships `mdatp diagnostic ebpf-statistics` to attribute load to paths, initiators and syscall IDs [V]. Independent labs (AV-Comparatives and AV-TEST performance tests) measure file copy, archive, install, application launch and browsing slowdown [K].

Proposed budgets (ours, not sourced): steady-state at most 1% of one core and 150 MB RSS; AUTH decision p99 at most 1 ms on cache hit, with fail-open well inside the ES deadline; developer-workload wall-time regression (`cargo build`, `npm ci`, `git status` on a large repository, kernel compile) at most 3% alone and at most 2% incremental on top of each incumbent; proxy added time-to-first-byte under 5 ms on streaming LLM responses.

### 5. Lab components

- **Linux kernel matrix:** `little-vm-helper` pulls prebuilt kernel and rootfs images from `quay.io/lvh-images` (for example `kind:5.15-…`) and can cross-build for arm64. `vmtest` maps the host userspace into the guest and runs one command per kernel. `libbpf/ci` provides reusable Actions [V]. GitHub Linux x64 runners expose `/dev/kvm` after a udev rule [V]; KVM on hosted arm64 runners is unverified.
- **Windows:** the Hardware API authenticates with an Entra application holding the Driver Submitter role. Preproduction signing (`PUT …/hardware/preprod/packages/`, poll `signingStatus`, download `SignedFilesZip`) supports ELAM and PETrust attributes on devices provisioned to trust it, with Secure Boot and HVCI on [V]. HLK needs a controller plus client machines and produces `.hlkx` [K]. Driver Verifier, CodeQL driver queries and kernel-debugger crash triage are scriptable [K]. `microsoft/windows-drivers-rs` (Apache-2.0) enables Rust drivers. `ebpf-for-windows` (MIT) needs native-mode `.sys` programs under HVCI, so each program is a signed driver [V].
- **macOS:** system extensions load from any path only with SIP disabled and `systemextensionsctl developer on`; entitlements and signature are still required [V]. Hosted macOS runners cannot nest VMs [V]. The licence allows two macOS guests per Mac [V]. AWS EC2 Mac is bare metal on Dedicated Hosts with a 24-hour minimum and configurable SIP, with types up to `mac-m4pro.metal` [V].
- **Fuzzing, fault injection, soak:** `cargo-fuzz` and `syzkaller` are Apache-2.0 [V].

## Matrix

Interference by OS and incumbent (C = coexists, R = risk, X = avoid):

| Our mechanism | Defender/MDE | Falcon | SentinelOne | Cortex XDR | DLP (Purview, Forcepoint, Digital Guardian) | ZTNA (Zscaler, Netskope) |
|---|---|---|---|---|---|---|
| Win minifilter (Activity Monitor) | C; WdFilter 328010 below us | C; csagent 321410 below | C; 389040 above most | C; 321234 below | R: FSFilter Top filters at 401xxx see I/O first | R: Zscaler DLP filter 363040.5 |
| Win WFP callout, own sublayer | C; their block wins | C | C | C | C | R: redirect contention at connect-redirect |
| Win local TLS proxy + CA | R: root-store alert | R | R | R | R: DLP may itself inspect | X as transparent MITM; chain explicitly |
| Win injection or hooking | X (ASR, PPL) | X | X | X | X | X |
| macOS ES client (AUTH) | C; additive latency | C | C | C | C | n/a |
| macOS content filter | C [K] | C [K] | C [K] | C [K] | R | R: several filters and proxies on one flow |
| macOS DNS proxy or VPN slot | R | n/a | n/a | n/a | n/a | X: slot usually owned |
| Linux eBPF tracing | C; MDE is eBPF-only now | C [K] | C [K] | C [K] | n/a | C |
| Linux BPF LSM / override | C; chain, deny wins | C | C | C | n/a | n/a |
| Linux audit netlink | X | X | X | X | X | n/a |
| Linux fanotify permission | R: MDE uses fanotify [K] | R | R | R | R | n/a |
| Linux nftables redirect | n/a | n/a | n/a | n/a | n/a | X; use cgroup connect hooks |

Where tests run:

| Test class | Hosted CI | Owned or dedicated |
|---|---|---|
| Unit, lint, parser fuzz smoke, user-mode builds for 3 OS × 2 arch | Yes | |
| eBPF CO-RE load and behaviour, x64 kernel matrix | Yes (KVM) | |
| eBPF arm64 kernel matrix | Unverified (emulation is slow) | Arm64 bare metal |
| Windows driver load, Driver Verifier, bugcheck triage | No | VMs with test-signing or preprod trust |
| HLK runs to WHCP submission | No | Controller plus clients (x64 and arm64) |
| macOS system extension, ES and NE functional | No | Apple silicon hosts, SIP-off VMs |
| macOS real approval path (MDM, SIP on) | No | Physical Mac or MDM-enrolled VM |
| Coexistence with licensed incumbents | No | Golden images, partner licences |
| 72-hour soak, upgrade/downgrade, fault injection | No | Yes |

## Weak points, gaps and risks

- **Tamper protection gap on Windows.** Without MVI there is no PPL service, no ELAM and no PPL-gated ETW providers. An agent running as the user's admin can stop us. Mitigation must be architectural: an out-of-band heartbeat, and the incumbent EDR watching our service.
- **Attestation is closing.** Any Windows kernel component commits us to HLK infrastructure, an EV certificate and a Partner Center organisation, a heavy lift for an open-source project.
- **Fail-open versus fail-closed is forced on us.** ES deadlines and WFP semantics mean a stalled policy engine either blocks the machine or allows the action. It must be explicit per rule.
- **Additive latency is blamed on the newest agent.** We will be the last installed and first uninstalled.
- **Undocumented caps:** the ES client limit and Network Extension multi-filter ordering are not specified by Apple.
- **Incumbent licences** often restrict testing or benchmarking; coexistence testing of CrowdStrike, SentinelOne, Cortex, Zscaler and Netskope requires partner agreements.
- **Kernel panics happen to the best-funded vendors** (MDE's documented RHEL 8.1/SAP and Oracle UEK 5.15.0-0.30.20 issues [V]; CrowdStrike Channel File 291 on 2024-07-19 [V for date and impact, K for the 21-versus-20 input-field root cause]).

## Implications for our design

1. **Make kernel code optional and tiny.** Ship a complete product at Tier 0 (in-agent hooks, managed settings, explicit gateway) and Tier 1 (unprivileged or observe-only OS telemetry). Kernel enforcement (minifilter, WFP, ES AUTH, BPF LSM) is an add-on capability with its own release train.
2. **Build a slot broker.** At start, probe each slot (ES client creation result, redirect state, `lsm=` list, trampoline attach errors, audit ownership, active NE configurations), record owner and outcome, and pick the next rung: enforce, then observe, then ingest incumbent telemetry and delegate response to the incumbent's API. Report the chosen rung per capability as product state, not as an error.
3. **Never take exclusive slots:** no audit netlink, no PF, no system VPN, no DNS-proxy slot, no legacy `tc` priorities, no injection.
4. **Prefer explicit proxying to MITM.** Configure agents through their own proxy and base-URL settings and managed configuration; originate upstream via system proxy/PAC with the OS trust store; reserve transparent redirect for agents that cannot be configured, and check WFP redirect state first.
5. **Publish a coexistence pack per release:** signer identities, Team ID, driver names and altitudes, BPF program names, process paths, loopback ports, plus ready-made exclusion snippets for Defender (including per-rule ASR), Falcon, SentinelOne, Cortex, Elastic, Zscaler and Netskope, and MDM profiles for macOS.
6. **Design the core as an embeddable library with a narrow event-in, verdict-out ABI.** An EDR vendor that owns ELAM, PPL and an ES client can host it, which is the only route to kernel-grade tamper resistance.
7. **Adopt MVI 3.0-style safe deployment regardless of membership:** content updates validated by the same parser fuzzers, ringed rollout, customer-controlled rings, and boot-loop detection that disables kernel components after repeated early crashes.
8. **Start the long-lead human tasks now:** Apple ES entitlement request, Partner Center hardware registration and EV certificate, minifilter altitude request once the filter design is stable (30 business days), and partner programme applications.

### Costed lab (estimates unless marked [V])

| Item | Purpose | Cost |
|---|---|---|
| GitHub-hosted standard runners, public repository | Tier A on every PR | Per-minute list rates if private: Linux $0.006, Windows $0.010, macOS $0.062 [V]; standard runners are free for public repositories [K] |
| Larger Linux runner, 16-core | Wider kernel matrix | $0.042/min [V] |
| 3 × Mac mini (Apple silicon) | 6 macOS guests plus Windows-on-Arm VMs | About $2–3k one-off |
| 1 × x64 virtualization host, 128 GB | Windows VMs, HLK controller and clients, incumbent golden images, Linux soak | About $3–4k |
| 1 × Windows-on-Arm device or cloud Arm VM | Arm64 driver and HLK client | About $1–1.5k, or hourly cloud |
| 1 × arm64 Linux bare metal | Arm64 kernel matrix with KVM | About $100–200/month rented |
| Apple Developer Program | Developer ID, notarization | $99/year [K] |
| EV code-signing certificate and Partner Center | Driver submission | About $300–700/year; registration free [K] |
| Incumbent licences | Coexistence matrix | Defender is built in; Elastic, Wazuh, osquery, Sysmon and Santa are free; the rest via partner programmes |

Agent operability: every step has a CLI or API (lvh, vmtest, a VM CLI, Hyper-V PowerShell, Hardware API, notarization CLI, kernel debugger scripting). Human gates are limited to legal agreements, the entitlement request, the altitude email, and hardware-token signing, which should be replaced by a cloud signing service.

## Ideas worth stealing and whitespace

- **Defender's passive mode** as a product concept: an explicit, visible "observe-only because another product owns enforcement" state.
- **`mdatp diagnostic ebpf-statistics`**: built-in self-attribution of overhead by path, initiator and syscall.
- **Datadog's overhead disclosure**: publish instance type, conditions and numbers per release.
- **Elastic's two-sided allowlist page**, generated per release from the build.
- **Whitespace 1:** nobody publishes an open, reproducible coexistence matrix (product × OS × version, with detections raised, health and performance delta). EDR-Telemetry compares telemetry only and is CC BY-NC [V].
- **Whitespace 2:** an "interference oracle" in CI that queries each incumbent's detection API after our install, upgrade and uninstall and fails the build on any alert.
- **Whitespace 3:** a vendor-neutral slot registry for eBPF and Network Extension (program names, priorities, redirect markers) comparable to Microsoft's altitude list.
- **Whitespace 4:** agent-aware TLS chaining guidance. Agent vendors document their side and ZTNA vendors theirs; nobody documents the three-party case.

## Could not verify / open questions

- Current public status and API surface of the Windows endpoint security platform after the July 2025 private preview.
- Numeric Endpoint Security client cap; Apple's rules for several content filters and transparent proxies on one flow.
- CrowdStrike, SentinelOne and Cortex interoperability and exclusion documents (gated); Zscaler forwarding-profile mechanics (page rendered empty).
- Whether GitHub-hosted arm64 Linux runners expose KVM; whether hosted macOS runners can approve system extensions.
- Whether macOS guests can be MDM-enrolled reliably enough to test the SIP-on approval path.
- Tart's effective licence terms after the move to `openai/tart` (repository licence file and website disagree); Anka pricing.
- HLK playlist contents and run time for file-system filter and WFP callout drivers; HLK on arm64 clients.
- AWS EC2 Mac hourly prices; published CPU and memory budgets from CrowdStrike, SentinelOne and Cortex.
- Elastic's minifilter altitude (extraction reported 260350.5 in Content Screener; confirm).

## Sources

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers — Load order groups and altitudes (2025-04-24)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request — Request a filter altitude (2026-10-07)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes — Allocated filter altitudes (2026-10-29)
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration — WFP filter arbitration (updated 2025-03-11)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings — Driver signing options (2026-03-23)
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation — Attestation signing (2025-07-15)
- https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/dashboard/manage-preprod-submissions.md — Preproduction submissions API
- https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/dashboard/dashboard-api.md — Hardware dashboard API
- https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria — Microsoft Virus Initiative (updated 2026-10-06)
- https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ — Windows Resiliency Initiative, MVI 3.0 (2025-06-26)
- https://www.microsoft.com/en-us/security/blog/2024/07/27/windows-security-best-practices-for-integrating-and-managing-security-tools/ — Kernel driver best practices (2024-07-27)
- https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility — Defender AV compatibility (2026-08-21)
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference — ASR rules reference (2026-09-09)
- https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf — MDE Linux eBPF sensor (2026-07-02)
- https://developer.apple.com/documentation/endpointsecurity/es_new_client_result_t — ES client creation results
- https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline — ES deadline
- https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment — TN3134
- https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api — TN3165 (2024-02-27)
- https://developer.apple.com/documentation/networkextension/content-filter-providers — Content filter providers
- https://developer.apple.com/documentation/driverkit/debugging-and-testing-system-extensions — System extension developer mode
- https://www.apple.com/legal/sla/docs/macOSTahoe.pdf — macOS Tahoe 26 licence, sections 2B(iii) and 3
- https://docs.kernel.org/bpf/prog_lsm.html — LSM BPF programs
- https://github.com/torvalds/linux/blob/master/include/linux/bpf.h — `BPF_MAX_TRAMP_LINKS`
- https://man7.org/linux/man-pages/man2/fanotify_init.2.html — fanotify_init(2)
- https://osquery.readthedocs.io/en/stable/deployment/process-auditing/ — osquery process auditing
- https://tetragon.io/docs/concepts/enforcement/ — Tetragon enforcement
- https://github.com/cilium/little-vm-helper, https://github.com/cilium/little-vm-helper-images, https://github.com/danobi/vmtest, https://github.com/libbpf/ci — kernel matrix tooling
- https://github.com/openai/tart and https://tart.run/licensing/ — Tart repository and licensing page
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners — hosted runner reference
- https://docs.github.com/en/billing/reference/actions-runner-pricing — runner pricing
- https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/ — KVM on Linux runners (2024-04-02)
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-mac-instances.html — EC2 Mac instances
- https://code.claude.com/docs/en/network-config — Claude Code enterprise network configuration
- https://docs.netskope.com/en/certificate-pinned-applications/ — Netskope certificate-pinned applications
- https://github.com/elastic/docs-content/blob/main/solutions/security/manage-elastic-defend/allowlist-elastic-endpoint-in-third-party-antivirus-apps.md — Elastic allowlisting
- https://docs.datadoghq.com/agent/basic_agent_usage/ — Datadog agent overhead
- https://www.crowdstrike.com/en-us/blog/channel-file-291-rca-available/ — Channel File 291 RCA announcement (2024-08-06)
- https://github.com/microsoft/ebpf-for-windows, https://github.com/microsoft/windows-drivers-rs, https://github.com/tsale/EDR-Telemetry — related projects

## Independent verification

_Checked 2026-11-09 by a second reviewer. The shared web-search budget was exhausted, so checks used direct fetches of primary documents, Apple documentation JSON, the licence PDF text and `gh` against source repositories. Where no independent source was reachable, the cited primary page was re-read in full._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Attestation signing is "for testing purposes only"; no retail Windows Update; Server 2016+ does not load attested device/filter drivers; ELAM needs `.hlkx` | Confirmed | All four statements are in the doc source (ms.date 2026-03-23). Nuance: the same page's table still lists attestation as loadable on Windows 10+ client, so "testing only" is policy, not a client load-time block. Preproduction signing does support ELAM. | https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/dashboard/driver-signing-offerings.md |
| 2 | MVI needs a commercially available real-time antimalware product, NDA, Trusted Signing, yearly independent-lab certification; members get ELAM and Protected Processes | Confirmed | Eight requirements, including a programme licence and industry reputation; eight accepted labs (also AVLab, SKD Labs, West Coast Labs). The ELAM/Protected Processes wording is in the 2024-07-27 Microsoft Security blog, not the criteria page. | https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria ; https://www.microsoft.com/en-us/security/blog/2024/07/27/windows-security-best-practices-for-integrating-and-managing-security-tools/ |
| 3 | WFP: all sublayers evaluated, block overrides permit, callout block soft and filter block hard by default, hard permit can be vetoed, no cross-layer arbitration | Confirmed | Design caveat the brief understates: because a callout block is soft by default, "we can always add a block" is only true if the callout clears `FWPS_RIGHT_ACTION_WRITE` (hard block); a soft block can be permitted by a lower-priority sublayer. | https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration |
| 4 | ES may terminate a client that misses an AUTH deadline and may refuse new connections after repeated misses; `ERR_TOO_MANY_CLIENTS` exists with no published cap | Confirmed | Apple's wording is "may terminate the client process, or restart the process if it's a system extension". The TL;DR phrase "kills the client" is stronger than the doc. No numeric cap in the enum documentation. | https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline ; https://developer.apple.com/documentation/endpointsecurity/es_new_client_result_t |
| 5 | Altitudes by email to fsfcomm@microsoft.com, 30 business days, no expedite, public products only, any altitude for test builds | Confirmed | Doc source (ms.date 2026-10-07) matches. It also advises waiting until the filter's load-order group is stable before requesting. | https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/ifs/minifilter-altitude-request.md |
| 6 | Trampoline links per attach point capped at 36 (x86-64), 37 (arm64), 27 (s390x/ppc64), shared by fentry/fexit/fmod_ret/LSM | Corrected | True only for Linux v7.3 (2026-10-18) and later, after commit 17637e1a581a. v6.12, v6.18, v7.0, v7.1 and v7.2 define 38 for every architecture except s390x (27); ppc64 is 27 only from v7.3. The commit carries a `Fixes:` tag, so stable backports may lower older trees too. The count is summed over all kinds (`kernel/bpf/trampoline.c`), and an fsession program counts twice. Probe at run time; do not hard-code. | https://github.com/torvalds/linux/blob/v7.2/include/linux/bpf.h ; https://github.com/torvalds/linux/commit/17637e1a581a |
| 7 | macOS Tahoe licence: two additional VM instances per Apple-branded computer for development and testing; 24-hour minimum lease | Confirmed | Section 2B(iii) also permits macOS Server and personal non-commercial use, and requires the host to be already running the Apple Software. The 24-hour minimum is Section 3A(ii), for "Permitted Developer Services" (CI); Section 3D limits who may virtualize under a lease. | https://www.apple.com/legal/sla/docs/macOSTahoe.pdf |
| 8 | Standard hosted runners for `windows-11-arm`, `ubuntu-24.04-arm`, arm64 macOS; no nested virtualization on arm64 macOS; KVM on Linux x64 | Confirmed | Arm labels now appear in both the public and private repository tables. The no-nesting statement covers arm64 macOS only; Intel labels (`macos-15-intel`, `macos-26-intel`) still exist. KVM on 2-vCPU Linux runners is stated in the 2024-04-02 changelog; the reference page itself only says "hardware acceleration for Android SDK tools". | https://docs.github.com/en/actions/reference/runners/github-hosted-runners ; https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/ |
| 9 | MDE on Linux dropped AuditD from 101.2408.0000, falls back to Netlink (process events only), documents kernel panics on RHEL 8.1/SAP and Oracle UEK kernels | Confirmed | The Oracle case is Oracle Linux 8.8 with UEK 5.15.0-0.30.20(.1).el8uek; a third known issue is a hang on Oracle Linux 7.9 with ksplice. The matrix cell "MDE is eBPF-only now" overstates this, since Netlink remains the fallback. | https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf |
| 10 | Several ES clients or NE content filters: all must allow, any deny wins; Apple does not specify this | Corrected | Apple does document ordering between content filters: `FilterGrade` / `NEFilterManager.grade` puts `firewall` filters before `inspector` filters and leaves order within a grade undefined. Apple's ES header also documents that the result cache is shared by all clients and is cleared when a new client is created. The "any deny wins" combination rule is not stated in any Apple page or header checked, so that part remains field knowledge and should be proven in the lab. | https://developer.apple.com/documentation/devicemanagement/webcontentfilter ; https://developer.apple.com/documentation/networkextension/nefiltermanager/grade-swift.property |

Further statements checked in the brief:

| Statement in brief | Verdict | Note | Source |
|---|---|---|---|
| "Apple's documentation does not describe ordering or verdict combination across several filters [V, absence confirmed on three pages]" | Corrected | Ordering is documented (see claim 10): firewall grade sees traffic before inspector grade, order within a grade is undefined, default grade is firewall. Only verdict combination is undocumented. The slot broker should read and set the grade. | https://developer.apple.com/documentation/devicemanagement/webcontentfilter |
| Matrix: SentinelOne minifilter at 389040, "above most" (Activity Monitor) | Corrected | The allocated-altitudes list (2026-10-29) marks `SentinelMonitor.sys` 389040 as "retired - new altitude allocated"; the current entry is 329355.5 in FSFilter Anti-Virus, which sits below any Activity Monitor filter. The other altitudes quoted (csagent 321410, CyvrFsfd 321234, WdFilter 328010, mssecflt 385600, CarbonBlackK 386720, mfeaskm 386610, zdpinfrastructure 363040.5, fpepflt 362930, stadrv6x64 401350.5, ElasticEndpoint 260350.5) match. | https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/ifs/allocated-altitudes.md |
| Tart now resolves to `openai/tart` with an FSL-1.1-ALv2 licence file | Confirmed | `cirruslabs/tart` redirects to `openai/tart`; LICENSE is "Functional Source License, Version 1.1, ALv2 Future License", copyright 2022-2026 OpenAI; GitHub reports no SPDX match. | https://github.com/openai/tart/blob/main/LICENSE |
