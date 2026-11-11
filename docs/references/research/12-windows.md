# Windows: observing and blocking agent activity (WESP, drivers, no-driver options)
_Researched 2026-11-09_

Legend: **[V]** verified in a primary source this session; **[S]** secondary source only; **[I]** my inference; **[K]** background knowledge not re-verified today (pre-mid-2026).

## TL;DR

- **WESP is not available to us.** The Windows Endpoint Security Platform is still preview-only, undocumented, and gated: production clients need a `WESP://Permission` token attribute and Antimalware-PPL (level 0x31), which in turn needs an ELAM driver, which needs Microsoft Virus Initiative (MVI) membership. First public binaries (`wesp.sys`, `espclient.dll`) appeared in Insider build 29661 in Sept 2026; no SDK, no GA as of 26 Oct 2026. [V]
- **MVI is closed to a new open-source project.** Criteria (page updated 2026-10-06) require an organisation with a *commercially available* real-time anti-malware product, industry reputation, NDA + programme licence agreement, yearly certification by a test lab (AV-Comparatives, AV-Test, SE Labs, etc.), and MVI 3.0 safe-deployment practices. [V]
- **Kernel drivers are still possible but the door is narrowing.** April 2026 removed trust in cross-signed drivers (24H2/25H2/26H1/Server 2025). Microsoft now documents attestation signing as "for testing scenarios", and says the signing bar will rise with "many new certification tests". [V]
- **Shipping any driver requires a legal entity**: EV code-signing certificate, Microsoft Entra tenant, legal signatory, Hardware Developer Program agreements, business questionnaire. Azure Artifact Signing does not issue EV certs and does not do kernel signing. [V]
- **Microsoft account risk is real**: in April 2026 Microsoft suspended the Partner Center accounts of WireGuard, VeraCrypt and Windscribe, blocking their driver updates until public outcry. [S]
- **A lot is possible with no driver**: ETW kernel providers, built-in Sysmon (now an optional Windows feature), user-mode WFP filters keyed on app path/user SID/AppContainer SID, AMSI provider, restricted tokens/AppContainer/job objects, ProjFS, WSL plug-in API. OpenAI Codex already ships a no-driver Windows sandbox built from WFP + tokens + ACLs. [V/K]
- **Windows now has native agent primitives we should hook, not rebuild**: Agent Workspace (separate session + per-agent local account), On-device Agent Registry (`odr.exe`), MCP proxy with consent/audit, agent connectors. All still preview. Agent accounts give a clean SID for human-versus-agent attribution. [V]
- **Rust for drivers is not production-blessed**: `windows-drivers-rs` 0.5.0 (2026-10-26) README still says "not yet recommended for production use". Safing Portmaster ships a production Rust WFP driver with its own bindings anyway. [V]
- **WSL2 is coverable without Microsoft's blessing**: the WSL plug-in API (signed DLL + one registry value) lets any vendor run a Linux binary in the utility VM root namespace. Microsoft's own Defender plug-in is visibility-only, x64-only, no custom kernels. [V]
- **Recommended**: ship driverless first (Phase 0), add an optional minimal attestation-signed driver once a legal entity exists (Phase 1), get WHCP/HLK for Server and durability (Phase 2), and reach WESP/PPL through EDR-vendor embedding rather than by joining MVI ourselves (Phase 3).

## Findings

### 1. WESP and the Windows Resiliency Initiative

- Timeline: WESES summit Sept 2024; MVI 3.0 announced June 2025 with private preview of WESP to "a set of MVI partners" in July 2025; Ignite (18 Nov 2025) restated private preview and that it "shifts AV enforcement from the kernel to user mode". [V] [blog 2025-06-26](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/), [blog 2025-11-18](https://blogs.windows.com/windowsexperience/2025/11/18/preparing-for-whats-next-windows-security-and-resiliency-innovations-help-organizations-mitigate-risks-recover-faster-and-prepare-for-the-era-of-ai/). Ignite 2025 Book of News reportedly targeted GA "in 2026" [S]; not GA as of the Elastic article dated 2026-10-26. Ignite 2026 has not happened yet; status may change within weeks.
- Architecture (reverse-engineered, no Microsoft docs): `wesp.sys` is a Microsoft minifilter at altitude 329500; `espclient.dll` exports ~120 `Esp*` functions (`EspRegisterClient`, `EspConnectClient`, `EspCreateEventQueue`, `EspCreateRule`, `EspUpdateRules`, `EspArmEventNotification`, `EspCompleteEventNotification`). Transport is filter port `\EspFilterPort` (max 512 connections). Rules are evaluated in-kernel (`RuleEngine::process_event<ProcessCreate>`), compiled to BDDs with NFA/trie string matching; events queue to user mode. Callbacks registered for process, thread, image, file, registry, object-manager (handle) and boot events. **Network is not mentioned anywhere.** [V] [Jonathan Johnson 2026-09-11](https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/), [Elastic 2026-10-26](https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp), [xusheng6 research](https://github.com/xusheng6/windows-wesp-research).
- Blocking: process creation can be vetoed in-driver via `PS_CREATE_NOTIFY_INFO.CreationStatus` by rule; object-manager rules can strip rights such as `PROCESS_TERMINATE`. No `FilterReplyMessage` path was found, so a synchronous "ask user mode, then decide" verdict appears absent in this build. Analysts disagree; treat as unsettled. [V]
- Access: port ACL is Administrators/SYSTEM; `wesp::server::connect` checks token attribute `WESP://Permission` and Antimalware PPL. A "delegated permission route" exists but is unexplored. Elevated admin connects only with test-signing on. [V]
- **MVI criteria**: organisation developing anti-malware; commercially available real-time protection; responsible for updates; positive industry reputation; NDA; programme licence agreement; "use of Trusted Signing"; certification in the last 12 months by one of eight labs. "Not all applicants are accepted." [V] [MVI criteria](https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria). MVI 3.0 (effective 1 Apr 2025): tested incident response, safe deployment practices, gradual ring-based updates with monitoring; required to keep signing rights for AV drivers. [V]
- Verdict: an AIDR project is not an anti-malware product by MVI's definition and has no lab certification. **Open-source status is not itself a bar; lack of a commercial AV product, an organisation and lab certification is.** [I]

### 2. Kernel drivers: what they give, what signing demands

- Capabilities [K]: minifilter (pre-create/read/write veto, per-process file policy), `PsSetCreateProcessNotifyRoutineEx2` (veto process start), `PsSetLoadImageNotifyRoutine` (observe only), `ObRegisterCallbacks` (strip handle rights: self-protection; image must be linked `/INTEGRITYCHECK`), `CmRegisterCallbackEx` (registry veto), WFP callouts (per-flow inspect, block, redirect to a local proxy).
- **Cross-signed trust removal**: from the April 2026 update on Windows 11 24H2/25H2/26H1 and Server 2025; evaluation mode, enforcement after 250 system hours and 3 boots (2 on Server) with no failing driver; a small Microsoft allow list; enterprises can allow custom kernel signers only with an App Control policy signed by the device's Secure Boot PK/KEK. [V] [Tech Community, 2026-03-26, updated 2026-10-22](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818)
- **Signing options today** [V] [Driver signing options, 2026-03-23](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings):
  - *WHCP (HLK-tested, dashboard-signed)*: works everywhere including Server; required for Windows Update retail distribution and for ELAM.
  - *Attestation*: now titled "for testing scenarios"; no HLK; Windows 10+ desktop only; docs state Server 2016+ "doesn't accept attested device and filter driver signing submissions"; cannot yield ELAM signature level; needs EV cert to submit. The doc table still lists attestation as loadable on Windows 10+ desktop. Portmaster's release procedure today is exactly this (CAB → Partner Center → Microsoft-signed). [V] I infer the April 2026 policy does not block attestation-signed drivers, but Microsoft's wording gives no long-term guarantee. [I]
  - *Preproduction signing*: only on specially provisioned devices.
- **Hardware Developer Program registration** (page dated 2026-08-11): EV certificate (only to register), Entra global admin, legal contact "with the authority to sign agreements on behalf of your organization", company lookup/D-U-N-S, Code Signing Agreement + WHCP agreement + Marks licence + Analytics agreement, then a business questionnaire. [V] [register](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register)
- **Azure Artifact Signing (ex Trusted Signing)**: user-mode only ("Signing with the Partner Center is kernel-mode signing (no change)"); "doesn't issue EV certificates... no plan"; needs paid Azure subscription; certificates live 3 days; anti-malware user-mode binaries for PPL must be signed with it (EKU prefix `1.3.6.1.4.1.311.97.*`). [V] [FAQ, updated 2026-10-27](https://learn.microsoft.com/en-us/azure/artifact-signing/faq). Eligibility: organisations in US, CA, EU, UK, AU, NZ, JP, KR, SG, CH, NO, IL; individuals only US/CA; about $9.99/month. [S]
- **Raising bar**: Ignite 2025 promised "mandatory compiler safeguards", "driver isolation", DMA remapping and more certification tests, with no dates. [V]
- **Cost and lead time (estimates)** [I/K]: EV cert roughly $300–700/year on hardware token or cloud HSM, 1–3 weeks validation for a new entity; Partner Center approval days to weeks; attestation turnaround minutes to hours per submission; HLK needs a controller (Windows Server) plus client machines per architecture and typically 1–3 weeks for first pass.

### 3. How open-source projects ship drivers

| Project | Driver | Signing / status | Lesson |
|---|---|---|---|
| Safing Portmaster (GPL-3, v2.2.8 2026-10-21) | Rust WFP callout kext, own `wdk` bindings, amd64 only | CAB submitted to Partner Center for Microsoft signing, no HLK step, then optionally co-signed "with company certificate" [V](https://github.com/safing/portmaster/tree/master/windows_kext/release); account held by the company behind the project [K] | Company behind the project owns the account; Rust kext is viable |
| WireGuard (wireguard-nt), VeraCrypt | NDIS / disk drivers | Partner Center accounts suspended April 2026 over identity re-verification; reinstated after press coverage [S](https://www.heise.de/en/news/VeraCrypt-and-WireGuard-Driver-Signing-Troubles-Solution-in-Sight-11250034.html) | Single account is a single point of failure |
| Fort Firewall (GPL-3, v3.20.9) | WFP driver that maps executable+writable memory | Requires HVCI off; attestation attempt failed [V](https://github.com/tnodir/fort/wiki/HVCI) | Anti-pattern; HVCI compatibility is mandatory |
| WinDivert | WFP callout, user-mode packet API | Last release 2.2.2, Sept 2022; repo idle since 2023 [V] | Do not depend on it |
| eBPF for Windows (MIT, v1.7.0 2026-10-16) | Core + per-program native `.sys` | Every release still flagged pre-release; JIT unusable under HVCI; native mode means each eBPF program is its own driver to sign; `ntosebpfext` has process create/delete hooks; file-system hook is still a proposal [V](https://github.com/microsoft/ebpf-for-windows) | Not a signing shortcut for third parties yet |
| Sandboxie-Plus (GPL-3, v1.18.8) | Sandbox driver | Signing arrangements not verified today | — |

### 4. Rust for drivers

`microsoft/windows-drivers-rs`: crates `wdk`, `wdk-sys`, `wdk-build`, `wdk-alloc`, `wdk-panic` at 0.5.0 (2026-10-26), Apache-2.0, WDM/KMDF/UMDF; crates.io builds only KMDF 1.33; README: "still in early stages of development and is not yet recommended for production use"; needs eWDK, LLVM/bindgen, cargo-make. [V] [repo](https://github.com/microsoft/windows-drivers-rs). Minifilter (`FltMgr`) and WFP safe wrappers are not provided [I]; expect to write `unsafe` FFI as Portmaster did.

### 5. No-driver toolbox

| Mechanism | Observe | Block | Notes |
|---|---|---|---|
| ETW `Microsoft-Windows-Kernel-Process/File/Network/Registry`, `DNS-Client`, `Microsoft-Windows-WFP` | Yes, near real time, admin only | No | Lossy under load; attacker with admin can stop sessions; file reads are high volume [K] |
| ETW `Threat-Intelligence` | Injection, memory ops | No | Consumer must be Antimalware-PPL, so MVI-gated [K] |
| **Built-in Sysmon** | Process create with command line and hashes, network connect, image load, raw disk, process GUID and logon-session GUID | No | Optional feature on Windows 11 and Server 2025, `sysmon -i`, serviced via Windows Update, cannot coexist with standalone Sysmon, "provides raw telemetry rather than active prevention" [V](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview) |
| Security auditing (4688, 4663, 5156/5157) | Yes | No | Needs audit policy and SACLs [K] |
| **User-mode WFP** (`FwpmFilterAdd0` at ALE connect/accept layers with `ALE_APP_ID`, `ALE_USER_ID`, `ALE_PACKAGE_ID`) | Via net events | **Yes**, per exe path, per user SID, per AppContainer SID | No payload inspection or redirect without a callout driver; app-path match is defeated by copying the binary, so prefer SID-based rules [K] |
| Restricted tokens, low-integrity, AppContainer/LPAC, job objects | — | Yes, for processes we launch | Basis of a launcher sandbox. Codex ships `windows-sandbox-rs` with `wfp.rs`, `token.rs`, `deny_read_acl.rs`, `dpapi.rs`, `identity.rs` [V](https://github.com/openai/codex/tree/main/codex-rs/windows-sandbox-rs) |
| Win32 app isolation | — | Yes, for MSIX-packaged apps | Release notes unchanged since Nov 2024; still preview by all signs [V](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-release-notes) |
| AMSI provider (in-proc COM DLL) | PowerShell, WSH, VBA, .NET loads | Yes (`AMSI_RESULT_DETECTED`) | Sees script content plus host process; signed DLL needed when AMSI signing enforcement is on [K] |
| ProjFS / Cloud Files provider | Reads of virtualised files with triggering PID and image | Yes, by failing hydration | Usable as a per-process secrets broker for `.env`, `~/.ssh`, `~/.aws` [K/I] |
| App Control for Business (WDAC) | Audit events | Yes, exe/DLL/script allow-listing | Admin policy; coarse; can also be the customer-side way to allow our driver [V/K] |
| Controlled Folder Access | Events | Writes only | Defender must be the active AV; no read protection [K] |
| Windows Sandbox, Dev Drive | — | Isolation by VM / per-volume filter policy | Dev Drive restricts which minifilters attach; our minifilter would need admin allow-listing [K] |

### 6. Tamper protection

PPL for services (`SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`) requires an ELAM driver whose resource section lists our signing certificate hashes; ELAM needs WHCP signing (attestation cannot produce it) and, in practice, MVI. PPL processes cannot have UI. [V] [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-). Without PPL: SYSTEM service with hardened DACLs, watchdog pair, signed config, and server-side heartbeat for tamper *detection*; with our own driver, `ObRegisterCallbacks` plus minifilter and registry self-protection [K].

### 7. Windows-native agent features

- **Agent Workspace** (preview; "Experimental agentic features" toggle, off by default, admin-only, device-wide): each agent runs in a separate Windows session under its own local agent account; access limited to six known folders with per-agent Allow always / Ask / Never; builds 26100.7344+ and 26220.7262+. Stated principles include non-repudiation and a "tamper-evident audit log" but no log location is documented. A listed known issue (leftover Intune profiles for agent accounts with names ending in `$`) suggests agent accounts are real local principals [I]. [V] [support page, updated 2025-12-05](https://support.microsoft.com/en-us/windows/ai/ai-features/experimental-agentic-features)
- **MCP on Windows / ODR**: `odr.exe mcp list|add|remove|configure|run`; servers register via MSIX package identity, MSIX with external location, `.mcpb` bundle, or manually (local or remote). MSIX-identity servers run contained in the agent session; `.mcpb` servers cannot be contained and are hidden unless the user enables "Reduce protections for agent connectors". Manifests must declare `static_responses` and `tools/list` that match runtime output exactly (anti tool-poisoning). File consent is per host, not per server. An MCP proxy handles consent, governance, auditing; Intune/Entra/Group Policy controls are in public preview. Docs still carry the prerelease banner (overview updated 2026-06-04). [V] [overview](https://learn.microsoft.com/en-us/windows/ai/mcp/overview), [containment](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment)
- **Agent Launchers**: agents registered in ODR through App Actions manifests. [V]
- **Agent 365** GA 1 May 2026, per-user licence, registry + Entra + Purview + Defender; Entra Agent ID GA. Cloud control plane, no documented local sensor API. [V] [overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview)
- **What a vendor can hook**: enumerate ODR; register our own MCP gateway as an ODR server; read agent-account SIDs and session IDs for attribution; apply WFP and ACL policy to agent SIDs. No documented callback or filter API into the MCP proxy. [I]
- Claude Code, Cursor, Codex and custom agents do **not** use Agent Workspace; they run as the human user. [I]

### 8. WSL2, containers, ARM, VDI

- **WSL plug-in API**: registry value under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins` pointing at an Authenticode-signed DLL; loaded into `wslservice`; hooks are synchronous and errors are fatal to distro start; `ExecuteBinary()` runs a Linux process in the VM root namespace. A plug-in crash crashes the WSL service. [V] [WSL plugins](https://learn.microsoft.com/en-us/windows/wsl/wsl-plugins). WSL is MIT-licensed, v3.0.5 (2026-11-03). [V]
- **Defender plug-in for WSL** (doc 2026-09-15): file/process/network visibility only, no response actions; unsupported on ARM64, multi-session Windows and custom kernels; now also covers WSL containers (WSLc, needs WSL 2.9.12+); each distro appears as a separate Linux device linked by `HostDeviceId`. [V] [doc](https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl)
- Docker Desktop and Dev Containers run in the same WSL2 utility VM (or Hyper-V), so a root-namespace eBPF sensor started by our plug-in sees them; the Windows host sees only `vmmem`/`wslhost`. [I/K]
- **Windows on ARM**: x64 drivers do not load; need native ARM64 builds and signing. WESP ships an ARM64 client. Portmaster's kext is amd64-only. [V/K]
- **VDI / Windows 365**: multi-session needs per-session attribution; Windows 365 for Agents provides Intune-managed Cloud PC pools that agents check out and in, so our sensor ships in the image or through Intune. [V] [doc 2026-07-23](https://learn.microsoft.com/en-us/windows-365/agents/introduction-windows-365-for-agents)

## Matrix

| Capability | No driver | Own signed driver | Microsoft platform |
|---|---|---|---|
| Process start | Observe: ETW Kernel-Process, built-in Sysmon ID 1, 4688. Block: only what we launch (job, token) or via WDAC. Effort low; kill-after-start is racy | `PsSetCreateProcessNotifyRoutineEx2` veto with user-mode verdict. Effort medium; BSOD risk; needs entity + EV + Partner Center | WESP ProcessCreate rule veto (preview; MVI + PPL) |
| File read/write of secrets | Observe: ETW Kernel-File (noisy), 4663 with SACLs. Block: ACL deny against sandbox user/AppContainer; ProjFS broker; CFA (writes only). Effort medium | Minifilter pre-create/pre-read per process tree. Highest effort (altitude request, Dev Drive, AV interop) | WESP file events exist, verdict path unclear; Agent Workspace folder consent for workspace agents only |
| Network egress per process | Observe: Sysmon ID 3, ETW Kernel-Network, WFP net events. Block: user-mode WFP by app ID/user SID/AppContainer SID. No TLS/SNI inspection or redirect. Effort low-medium | WFP callout: redirect to local LLM/MCP proxy, SNI inspection, per-PID verdicts. Effort medium (Portmaster precedent) | None in WESP today; Hyper-V firewall for WSL |
| DNS | Observe: ETW DNS-Client (misses DoH inside apps). Block: local resolver + WFP rule forcing port 53/853 to it | Callout at datagram layers; redirect | ZTDNS (status not verified) |
| Registry | Observe: ETW Kernel-Registry, Sysmon 12–14, 4657. Block: ACLs only | `CmRegisterCallbackEx` veto | WESP registry events |
| Module load | Observe: Sysmon ID 7, ETW image load. Block: WDAC | Image-load notify (observe); block via minifilter on section create | WESP image events; WDAC |
| Self-protection | DACLs, watchdog, heartbeat-based tamper detection. Admin can kill us | `ObRegisterCallbacks`, minifilter and registry protection of our own assets | PPL via ELAM (MVI only); WESP handle-rights rules |
| Human vs agent attribution | Process ancestry from known agent binaries; in-agent hook events carrying PID/tool-call ID; Sysmon ProcessGuid + LogonGuid; run agent children under a dedicated SID/AppContainer; Agent Workspace account SID | Same signals, tamper-resistant, with per-thread and handle context | Agent accounts + agent session; Entra Agent ID for cloud calls |

## Weak points, gaps and risks

- Attestation signing has no stated future; a policy flip to WHCP-only would strand a Phase 1 driver on desktop as it already does (per docs) on Server.
- Partner Center account suspension can freeze driver updates with no SLA.
- Driverless blocking is strong only for processes we launch or SIDs we assign; an agent running as the human user with the user's token is observable but not reliably blockable before the action completes.
- ETW and Sysmon are stoppable by local admin; without PPL we detect tampering rather than prevent it.
- WESP has no network events and no confirmed synchronous user-mode verdict; even MVI vendors will keep WFP callout drivers.
- Agent Workspace and ODR are preview with undocumented audit surfaces; APIs may change.
- `windows-drivers-rs` is not production-endorsed; AI-written kernel code raises the review bar (Driver Verifier, HLK, fuzzing mandatory).
- WSL plug-in runs in-process with `wslservice`; our bug breaks WSL for the user.

## Implications for our design

1. **Define one sensor trait with pluggable back ends**: `etw`, `sysmon-builtin`, `own-driver`, `wesp`, `host-edr`. Policy and detection never depend on which back end is present; each event carries a provenance and tamper-resistance grade.
2. **Phase 0 (no entity needed beyond user-mode signing)**: Rust SYSTEM service; ETW + built-in Sysmon ingestion (ship a Sysmon config, detect and reuse standalone Sysmon); user-mode WFP provider/sublayer with SID-keyed filters; AMSI provider; ODR inventory via `odr.exe mcp list`; agent-account and session enumeration; in-agent hooks and local MCP/LLM gateway as the primary pre-action enforcement point.
3. **Attribution by construction**: a launcher/shim that starts agents (or their tool subprocesses) under a dedicated local sandbox user or AppContainer inside a job object, as Codex does. That SID then drives WFP rules, deny-read ACLs on secret paths and unambiguous agent-versus-human labelling.
4. **Secrets broker**: ProjFS-backed virtual files for credentials so the provider sees the reading process and can refuse or substitute short-lived tokens.
5. **Phase 1 (legal entity + EV cert + Hardware Developer Program)**: one small, optional, HVCI-compatible driver for x64 and ARM64: process-create veto, minifilter limited to a configured secret-path set, WFP callout for redirect-to-gateway, `ObRegisterCallbacks` for self-protection. All policy in user mode; fail-open with a kernel-side timeout; MVI-3.0-style ringed rollout even though we are not members.
6. **Phase 2**: WHCP/HLK certification for Server and to survive an attestation clamp-down; second account admin and documented recovery path for Partner Center.
7. **Phase 3**: reach WESP and PPL through embedding. Ship the core as a library with a C ABI that an EDR vendor loads inside its own Antimalware-PPL process (requires our DLL be signed with, or catalogued under, the vendor's certificate) and feeds from its WESP queue.
8. **WSL**: signed plug-in DLL that drops a static eBPF sensor into the VM root namespace; keep the DLL trivial and crash-proof; also support ARM64 and custom kernels where Defender does not.
9. **Self-hosted enterprises**: document WDAC/App Control supplemental policy for our binaries and driver.

**Requires a legal entity, certificate or programme**: EV code-signing certificate (entity); Hardware Developer Program account (entity, Entra tenant, legal signatory, agreements); WHCP/HLK submission; Azure Artifact Signing Public Trust (entity in listed country, or US/CA individual); MVI (organisation, commercial AV product, NDA, lab certification) which gates ELAM, PPL, WESP, ETW Threat-Intelligence and Windows Security Center registration; App Control custom kernel signers (customer's Secure Boot PK/KEK). **Requires none**: ETW, Sysmon, user-mode WFP, AMSI provider, tokens/AppContainer/jobs, ProjFS, WSL plug-in (any trusted Authenticode signature), ODR registration.

## Ideas worth stealing and whitespace

- Codex's driverless sandbox recipe (dedicated users + WFP + deny-read ACLs + DPAPI) generalised to any agent.
- ODR's `static_responses` rule: pin an MCP server's declared tool list and reject runtime drift; apply this in our gateway on every OS.
- Agent Workspace's per-agent account model; offer the same for non-Microsoft agents today.
- WESP's rule model (typed predicates compiled to BDDs, evaluated in kernel, events queued to user mode) is a good shape for our own driver protocol and makes a later WESP back end a thin adapter.
- Whitespace: nobody covers WSL on ARM64 or custom kernels; nobody offers pre-action blocking for agents running as the human user without a driver; no vendor exposes MCP-proxy audit data from Windows in an open schema; no open-source project offers an embeddable, PPL-hostable AIDR core.

## Could not verify / open questions

- WebSearch quota ran out late in the session; items below were not re-checked.
- Whether attestation-signed drivers are explicitly in scope of "trusted" under the April 2026 Windows Driver Policy (inferred yes from the signing-options table and Portmaster practice).
- WESP GA date, SDK licence terms, whether non-AV vendors or delegated clients will be admitted, and whether network events are planned.
- Built-in Sysmon exact GA build/KB and optional-feature name; whether it is on Windows 10.
- Agent Workspace GA status, audit log location, policy CSP names, and whether agent accounts are visible to `LsaEnumerateAccounts`/4688 with distinguishable SIDs.
- ZTDNS status; Hyper-V firewall behaviour for WSL mirrored networking in 2026.
- Sandboxie-Plus current signing path; WireGuard account status after April 2026.
- HLK test set applicable to a software-only minifilter + WFP callout; real EV and HLK costs.
- ETW Threat-Intelligence PPL requirement and AMSI provider signing rules are from background knowledge.

## Sources

- https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ — Windows Resiliency Initiative, 2025-06-26
- https://blogs.windows.com/windowsexperience/2025/11/18/preparing-for-whats-next-windows-security-and-resiliency-innovations-help-organizations-mitigate-risks-recover-faster-and-prepare-for-the-era-of-ai/ — Ignite security and resiliency post, 2025-11-18
- https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp — Elastic, inside wesp.sys, 2026-10-26
- https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/ — Jonathan Johnson, 2026-09-11
- https://github.com/xusheng6/windows-wesp-research — WESP reverse engineering, 2026
- https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria — MVI criteria, updated 2026-10-06
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818 — cross-signed trust removal, 2026-03-26, updated 2026-10-22
- https://www.magicsword.io/blog/microsoft-is-killing-cross-signed-drivers — analysis, 2026-03-30
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings — Driver signing options, 2026-03-23
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation — Attestation signing, updated 2026-04-14
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register — Hardware Developer Program registration, 2026-08-11
- https://learn.microsoft.com/en-us/azure/artifact-signing/faq — Artifact Signing FAQ, updated 2026-10-27
- https://www.heise.de/en/news/VeraCrypt-and-WireGuard-Driver-Signing-Troubles-Solution-in-Sight-11250034.html — account suspensions, April 2026
- https://community.osr.com/t/microsoft-ignite-windows-driver-development-news/59923 — OSR discussion, Nov 2025
- https://github.com/microsoft/windows-drivers-rs — v0.5.0, 2026-10-26
- https://github.com/safing/portmaster/tree/master/windows_kext — Rust kext and release procedure, 2026
- https://github.com/tnodir/fort/wiki/HVCI — Fort Firewall HVCI note, 2026-01-24
- https://github.com/basil00/WinDivert — last release 2022-09
- https://github.com/microsoft/ebpf-for-windows and https://github.com/microsoft/ntosebpfext — v1.7.0 pre-release, 2026-10-16
- https://github.com/openai/codex/tree/main/codex-rs/windows-sandbox-rs — Codex Windows sandbox sources, 2026-11
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview — Built-in Sysmon, 2026-02-24, updated 2026-10-08
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112 — 2025-11-18
- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services- — ELAM and PPL, updated 2025-03-11
- https://support.microsoft.com/en-us/windows/ai/ai-features/experimental-agentic-features — Agent Workspace, updated 2025-12-05
- https://learn.microsoft.com/en-us/windows/ai/mcp/overview — MCP on Windows, updated 2026-06-04
- https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment — MCP containment, 2025-11-11
- https://github.com/MicrosoftDocs/windows-ai-docs (docs/mcp, docs/agent-launchers) — odr.exe, mcpb, agent launchers
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Agent 365, updated 2026-10-23
- https://learn.microsoft.com/en-us/windows/wsl/wsl-plugins — WSL plugins, updated 2026-06-02
- https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl — Defender plug-in for WSL, 2026-09-15
- https://github.com/microsoft/WSL — v3.0.5, 2026-11-03
- https://learn.microsoft.com/en-us/windows-365/agents/introduction-windows-365-for-agents — Windows 365 for Agents, 2026-07-23
- https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-release-notes — Win32 app isolation release notes, last entry 2024-11-21

## Independent verification

_Checked 2026-11-09 by a second reviewer. Method: direct fetch of primary Microsoft pages, read-only `gh` queries against source repositories, and one read-only Code Integrity inspection on a Windows 11 Pro build 26300 host. The web search quota was exhausted for this run, so no search-engine discovery of contrary sources was possible; verdicts rest on primary documents and source code only._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | WESP production clients need the `WESP://Permission` token attribute and Antimalware PPL (0x31); elevated admin connects only with test-signing; no public SDK | Confirmed, with one nuance | Independent RE report agrees: attribute value 1,000,000,000 takes the AM-PPL path (`0x31`); ordinary admin got `0x80070005` in production config and was admitted after Test Signing was enabled. Nuance: a second attribute value (10,000,000) selects a delegated route that **skips the PPL check**; issuer and constraints unknown. So "must be AM-PPL" holds for the normal partner route only. Elastic says only "likely need to run as PPL" and "not publicly documented". Microsoft's Artifact Signing quickstart now has a certificate-profile "Program Type" for those "enrolled in the Windows endpoint security platform" programme, which confirms enrolment-gated signing identity. | [xusheng6 REPORT.md](https://github.com/xusheng6/windows-wesp-research/blob/main/REPORT.md), [Elastic](https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp), [Artifact Signing quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) |
| 2 | MVI needs an organisation with a commercially available real-time anti-malware product, NDA, programme licence agreement, Trusted Signing, yearly lab certification; not all applicants accepted | Confirmed | All eight requirements and the eight-lab table read verbatim on the page (ms.date 2024-12-02, updated 2026-10-06). Applications are reviewed monthly. | [MVI criteria](https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria) |
| 3 | Hardware Developer Program registration needs an EV certificate, an Entra global admin account and a legal contact with signing authority | Confirmed | Verbatim in prerequisites. EV cert is needed only to register, not to sign the driver; an Entra directory can be created free during registration; a business questionnaire follows the certificate upload. Individual submissions may be signed with a registered non-EV Authenticode cert, but the account must hold at least one valid EV cert. | [register](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register), [code-signing-reqs](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs) |
| 4 | Attestation signing is documented as testing-only, Windows 10+ desktop, not accepted on Server 2016+, no ELAM level; WHCP needs HLK | Confirmed | Section title "Attestation signed drivers for testing scenarios"; "For testing purposes only"; "only works on Windows 10 Desktop and later"; no ELAM or Windows Hello PE level; Server 2016+ "only loads dashboard signed drivers that successfully pass the HLK tests". Also not publishable to Windows Update for retail. The older Driver Signing Policy page (2024) already said attestation is "for testing on Windows 10 client only systems". | [driver-signing-offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [kernel-mode code signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-) |
| 5 | Attestation-signed drivers still load on retail Windows 11 after the April 2026 cross-signed trust removal (inference) | Confirmed as an inference; one supporting argument is invalid | Microsoft still does not say it. The blog's literal wording is stricter than the claim: default trust is for drivers that WHCP "have passed and been signed", and ecosystem drivers "must be WHCP certified". Attestation is not mentioned. Supporting evidence found: (a) signing-options page, updated 2026-04-14 after the change, still says an attestation signature "indicates that Windows trusts the driver" and refers to "retail and attestation trusted configurations"; (b) the Code Integrity mechanism is WHQL enforcement (event 3084, registry key `CI\WhqlOnlyEvaluation`) and attested drivers are Microsoft-signed, not cross-signed; (c) on a Windows 11 build 26300 host on 2026-11-09, 13 running kernel drivers carry the attested EKU `1.3.6.1.4.1.311.10.3.5.1` (enforcement state on that host not established; event 3084 shows "Exemption 1"); (d) a Portmaster issue reports the official signed kext loading on Windows 11 Home build 28000.2956 in Sept 2026. **Correction**: the Portmaster release README is not evidence of post-April behaviour; it was last edited 2025-06-20 and still targets "Windows 11 Client, version 22H2". Treat attestation as working today but unguaranteed; plan WHCP/HLK earlier than Phase 2 if the driver is load-bearing. | [Tech Community post](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818), [driver-signing-offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [safing/portmaster#2271](https://github.com/safing/portmaster/issues/2271), [kext release README](https://github.com/safing/portmaster/tree/master/windows_kext/release) |
| 6 | Azure Artifact Signing issues no EV certificates and does no kernel-mode signing | Confirmed | FAQ verbatim: "doesn't issue Extended Validation (EV) certificates. There's no plan"; "Signing with the Partner Center is kernel-mode signing (no change...)". Needs a paid Azure subscription. Eligibility list (12 regions for organisations, US/CA for individuals) is confirmed in the quickstart, so the brief's [S] tag on it can be upgraded. | [FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq), [quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) |
| 7 | Antimalware-PPL service needs an ELAM driver whose resource section lists the signing certificate hashes | Confirmed; the MVI link is stronger than the brief states | Doc: vendor "must have an ELAM driver installed" with an embedded resource section of certificate info. The brief says ELAM needs MVI "in practice"; it is a documented hard gate: "Your submission will fail if you are not an MVI member." Since 2022 the user-mode AM binaries must also be signed by Artifact Signing with the vendor EKU (`1.3.6.1.4.1.311.97.*`) listed in the ELAM resource. | [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-), [ELAM prerequisites](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites), [FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq) |
| 8 | Built-in Sysmon is an optional feature on Windows 11 and Server 2025, serviced by Windows Update, telemetry-only, no coexistence with standalone Sysmon | Confirmed | All four points verbatim. Extra design-relevant detail: rendered event messages are localised in built-in Sysmon (standalone is not); only the XML event data is stable, so ingest XML, never message text. Standalone Sysmon must be uninstalled first; if it is present, built-in stays disabled. | [Sysmon overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview) |
| 9 | MCP servers with package identity run contained in a separate agent session and account; `.mcpb` cannot be contained; still prerelease | Confirmed | Verbatim. Containment also requires a binary (.exe) server and a manifest with `static_responses` and `tools/list`. Contained servers can still reach the internet and run executables in the agent session, so containment is not egress control. Consent to user files is per host app, not per server. Prerelease banner still present in the docs repo; last substantive MCP docs commit 2026-06-04. | [containment](https://learn.microsoft.com/en-us/windows/ai/mcp/servers/mcp-containment), [MicrosoftDocs/windows-ai-docs](https://github.com/MicrosoftDocs/windows-ai-docs) (`docs/mcp`) |
| 10 | Any vendor can load a WSL plug-in via an Authenticode-signed DLL under `HKLM\...\Lxss\Plugins`; runs in wslservice; can run Linux binaries in the VM root namespace | Confirmed in source | `PluginManager.cpp` reads that key, calls `ValidateFileSignature` (plain `WinVerifyTrust` generic verify, official builds only), then `LoadLibrary` in the service. No Microsoft allow list; any chain to a trusted root passes. Caveats: writing the key needs admin; the source carries TODOs "Once plugins are out of proc", so in-process loading may change; WSL 3.x adds WSLC plug-in calls (root-namespace process, folder mounts). Latest stable release 3.0.5 (2026-11-03). | [PluginManager.cpp](https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/PluginManager.cpp), [WSL plugins](https://learn.microsoft.com/en-us/windows/wsl/wsl-plugins) |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| "Portmaster's release procedure today is exactly this" used as evidence that attestation still works after April 2026 (section 2) | Corrected | The procedure document predates the policy (last commit 2025-06-20). Use the September 2026 field report instead; see claim 5. | [commits](https://github.com/safing/portmaster/commits/master/windows_kext/release) |
| ELAM needs WHCP signing "and, in practice, MVI" (section 6) | Corrected (understated) | MVI membership is an explicit documented requirement checked at submission, not a practical convention. | [ELAM prerequisites](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites) |
| Agent Workspace status and build numbers (section 7), sourced from a page last updated 2025-12-05 | Confirmed, but stale | Page content matches the brief and has not changed in eleven months. It does not say agent accounts are local accounts; the brief's [I] tag on that is correct. Re-check after Ignite 2026 before designing against it. | [support page](https://support.microsoft.com/en-us/windows/ai/ai-features/experimental-agentic-features) |

Spot checks that held without change: `windows-drivers-rs` wdk 0.5.0 on 2026-10-26 with the "not yet recommended for production use" note; eBPF for Windows v1.7.0 (2026-10-16) and every recent release flagged pre-release; WinDivert last release v2.2.2 (2022-09-21), last push 2023-03; Portmaster v2.2.8 (2026-10-21); Codex `windows-sandbox-rs` contains `wfp.rs`, `token.rs`, `deny_read_acl.rs`, `dpapi.rs`, `identity.rs`; Agent 365 GA 1 May 2026, per-user licence; Defender WSL plug-in unsupported on ARM64, multi-session and custom kernels, visibility only; cross-signed policy thresholds 250 hours and 3 restarts (2 on Server 2025), raised from 100 hours with the 9 June 2026 release.
