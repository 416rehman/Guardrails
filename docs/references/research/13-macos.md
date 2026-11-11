# macOS: observing and blocking AI-agent activity (Endpoint Security, Network Extension, Seatbelt)

_Researched 2026-11-09_

Method note: primary sources were Apple docs/headers (macOS 26.5 SDK headers read directly; macOS 27.0 header diff read from HarfangLab issue #169), Santa/LuLu/Codex/Gemini CLI source via GitHub, and vendor docs. The shared web-search budget ran out part-way, so Network Extension TLS/QUIC/ECH limits and Docker Desktop internals rest on background knowledge and are marked **[inferred]**.

## TL;DR

- **Endpoint Security (ES) is the only supported way to block exec/file/IPC on macOS, and it is gated by an Apple-approved entitlement** (`com.apple.developer.endpoint-security.client`). Without it `es_new_client` returns `ERR_NOT_ENTITLED`; self-builds only load with SIP disabled. Santa's docs say this explicitly.
- **Network Extension (NE) entitlements are not on Apple's "must request" list** (only ES, DriverKit and "let other developers use your system extension" are). LuLu ships an open-source Developer ID content filter with `content-filter-provider-systemextension`. NE is the first kernel-enforced control we can ship without waiting on Apple.
- **macOS 27 (Golden Gate, Sept 2026) changed the ES picture**: `es_new_descendants_client` (AUTH+NOTIFY for the caller's process subtree only, no root, no TCC/Full Disk Access, configurable deadline floors), `es_set_deadline_miss_mode` (KILL / FAIL_CLOSED / FAIL_OPEN), `AUTH_XPC_CONNECT`, `AUTH/NOTIFY_BOOTSTRAP_CHECK_IN` and `_LOOK_UP`, `es_exec_entitlements`, `cdhash_full`. It still needs the entitlement; Apple DTS said the intent is a self-add entitlement later.
- **Watching only agent process trees is a solved pattern**: Santa's process-scoped file-access client uses inverted process muting, adds children on `NOTIFY_FORK`, re-keys on `NOTIFY_EXEC`, removes on `NOTIFY_EXIT`. Muting is per audit token and is not inherited.
- **ES has undocumented network AUTH/NOTIFY events since macOS 26.4** (`ES_EVENT_TYPE_RESERVED_5/6`, reverse-engineered by Patrick Wardle). They are still named `RESERVED_*` in the 27.0 SDK. Do not build on them.
- **Every major coding agent uses Seatbelt on macOS** (Claude Code, Codex, Cursor, Gemini CLI), all through `/usr/bin/sandbox-exec` or `sandbox_init`, and all only for shell commands. MCP servers, hooks and built-in file tools run outside. `sandbox-exec` is marked deprecated with no replacement.
- **Agents in VMs are invisible to host ES.** Anthropic shipped (beta, 2026-11-05) a programme to run an approved vendor's EDR sensor inside the Cowork VM, detection-only, MDM-deployed, vendor list controlled by Anthropic.
- **Full Disk Access is about to tighten.** Apple's 2026-10-02 notice says FDA will require "very explicit action", citing AI agents. No date, no detail on MDM-granted FDA. ES clients need FDA today.
- **Santa is open core now.** The ES daemon is Apache-2.0; network extension (`santanetd`), sandbox-profile rules, CEL fallback, EDR signals and EPM are Workshop-only, and the NE source is not in the public tree.
- **Rust is viable for the core, not for the whole extension.** `endpoint-sec` (HarfangLab, Apache-2.0/MIT, MSRV 1.88) wraps ES but has open issues for macOS 26 and 27 support. NE providers are Objective-C classes; `objc2-network-extension` and `objc2-system-extensions` exist, but a thin Swift shell around a Rust static library is lower risk.

## Findings

### 1. Endpoint Security: events that matter for agents

Verified from the macOS 26.5 SDK `ESTypes.h` (158 enum entries including `LAST`) and the 27.0 diff (five new, `LAST` = 162).

| Need | Events | Since | AUTH? |
|---|---|---|---|
| Process lifecycle, lineage | `EXEC`, `FORK`, `EXIT` | 10.15 | EXEC only |
| Credential/secret file reads, repo writes | `OPEN`, `CREATE`, `RENAME`, `UNLINK`, `TRUNCATE`, `LINK`, `CLONE`, `COPYFILE` (12), `EXCHANGEDATA`, `READDIR`, `WRITE`/`CLOSE` (notify) | 10.15 to 12 | yes for most |
| Code injection, debugging | `MMAP`, `MPROTECT`, `GET_TASK`, `GET_TASK_READ` (11.3), `REMOTE_THREAD_CREATE`, `TRACE`, `PROC_CHECK`, `PROC_SUSPEND_RESUME`, `SIGNAL`, `CS_INVALIDATED` | 10.15 to 11.3 | mixed |
| Unix sockets (docker.sock, ssh-agent, password-manager sockets) | `UIPC_BIND`, `UIPC_CONNECT` | 10.15.1 | yes |
| Persistence | `BTM_LAUNCH_ITEM_ADD/REMOVE`, `PROFILE_ADD/REMOVE` (14) | 13 / 14 | notify only |
| Privilege | `SUDO`, `SU`, `AUTHORIZATION_PETITION/JUDGEMENT`, `SETUID` family, `AUTHENTICATION` | 12 to 14 | notify only |
| Sessions | `PTY_GRANT`, `LW_SESSION_*`, `OPENSSH_LOGIN`, `SCREENSHARING_ATTACH` | 10.15.4 / 13 | notify only |
| IPC | `XPC_CONNECT` (notify 14, **AUTH 27**), `BOOTSTRAP_CHECK_IN`, `BOOTSTRAP_LOOK_UP` (**27**, look-up AUTH only for descendants clients) | 14 / 27 | 27 |
| Consent | `GATEKEEPER_USER_OVERRIDE` (15), `TCC_MODIFY` (15.4) | 15 / 15.4 | notify only |
| Network | `RESERVED_5` (auth) / `RESERVED_6` (notify), undocumented | 26.4 | undocumented |

Sources: [macOS 26.5 SDK headers](https://github.com/alexey-lysiuk/macos-sdk/tree/main/MacOSX26.5.sdk/usr/include/EndpointSecurity), [HarfangLab #169, macOS 27 diff, 2026-09-15](https://github.com/HarfangLab/endpoint-sec/issues/169), [Wardle, 2026-03-26](https://objective-see.org/blog/blog_0x86.html).

**Deadlines.** Header: each AUTH message carries its own `deadline` (Mach absolute time), deadlines "can vary substantially", and a client that misses one is killed. Wardle measured 15 s on the 26.4 network AUTH event. macOS 27 adds `es_set_deadline_miss_mode` (`KILL` default, `FAIL_CLOSED`, `FAIL_OPEN`); under `FAIL_CLOSED` a queue-full drop becomes DENY instead of ALLOW. `es_set_deadline_max_milliseconds` can only shorten; `es_set_deadline_min_milliseconds` can extend beyond the system default but only for descendants clients.

**Caching.** `es_respond_auth_result(..., cache)`: cache key is "generally the involved files", modification invalidates, a cache hit suppresses the AUTH event but NOTIFY still fires. `es_clear_cache` is global across all ES clients and rate-limited. Creating any new client clears all caches. For flags events (`AUTH_OPEN`), pass `UINT32_MAX` when caching, never the event's own flags. Santa never lets ES cache a DENY, and only caches ALLOW for targets nobody can modify; its 2026.7 to 2026.9 releases fixed several cached-decision reuse and universal-binary bugs ([releases](https://github.com/northpolesec/santa/releases)), which is a warning about caching on anything weaker than content identity.

**Muting.** Three dimensions (process, path, target path), each invertible with `es_invert_muting` (macOS 13+). Dimensions combine with OR and inversion applies first, so a path mute still suppresses a selected process. New clients start with a default mute set for system-critical paths (most AUTH variants muted). Muting is by audit token and is not inherited: Apple's forum answer on inherited mute defers to another thread, and Santa's source shows the working pattern ([SNTEndpointSecurityProcessFileAccessAuthorizer.mm](https://github.com/northpolesec/santa/blob/main/Source/santad/EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.mm)): invert process muting, subscribe to file AUTH events plus `NOTIFY_EXEC/FORK/EXIT`, "start watching" (un-mute) a child on FORK, clean the old pid+pidversion on EXEC because no EXIT arrives for it.

**Build storms.** The design answer is scope, not speed: one client with inverted process muting sees nothing from a non-agent `cargo build`. Inside an agent tree, keep AUTH to `EXEC` plus a second client with inverted target-path muting over a small secrets set (`~/.ssh`, `~/.aws`, keychains, browser profiles, agent config), and take everything else as NOTIFY. Use `seq_num` gaps to detect kernel drops. Handlers run strictly serially per client; respond out of order with `es_retain_message`.

**Descendants client (macOS 27).** `es_new_descendants_client`: notify events for the caller, AUTH+NOTIFY for its entire subtree including existing descendants; cannot see anything else; no root; no TCC approval; still entitled. Apple DTS (Sept 2026 forum thread from a developer building an AI-development-tool daemon) said it was designed for exactly this use, can block in `exec` until a user consents, that restrictions vanish if the client dies (no fail-closed on client loss), that `AUTH_XPC_CONNECT` probably covers only named connections, and that the plan is a self-add entitlement; the developer filed FB24830531. Source: [forum thread 845644](https://developer.apple.com/forums/thread/845644).

### 2. The ES entitlement and open source

- Apple: "You must request this entitlement from Apple" ([entitlement doc](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)). The [System Extensions page](https://developer.apple.com/system-extensions/) lists three things needing a request: DriverKit, the ES API, and allowing other developers to use your system extension. While waiting you test with SIP off.
- Forum reports of two- and four-month waits with no response exist ([698942](https://developer.apple.com/forums/thread/698942), [743263](https://developer.apple.com/forums/thread/743263)); they are old. I found no 2025 to 2026 account from an open-source project.
- Precedents that hold it: Santa (North Pole Security, Team ID `ZMCG7MLDV9`, Apache-2.0, v2026.9 on 2026-10-27), BlockBlock (Objective-See, GPL-3.0, entitlement in `Daemon/Daemon/BlockBlock.entitlements`), Mac Monitor (BSD-3). All are organisations with a signing identity; the entitlement binds to their Team ID and bundle ID, not to the source code.
- Santa's build doc: an "adhoc" build with the entitlement self-asserted loads only with SIP disabled ([building.md](https://github.com/northpolesec/santa/blob/main/docs/docs/development/building.md)). So a community self-build cannot run ES on a normal Mac.
- `eslogger` (Apple-shipped, macOS 13+, root plus FDA for the invoking app) exposes NOTIFY events as JSON without our own entitlement. Its man page says it is not API **[recalled, not re-read]**. Useful only as an opt-in telemetry fallback.

### 3. Distribution, MDM, Full Disk Access

- Chain: Apple Developer Program organisation membership, Developer ID Application/Installer certificates, provisioning profile carrying the restricted entitlements, notarisation, `OSSystemExtensionRequest` from a containing app in `/Applications`, user approval in Login Items & Extensions or MDM.
- MDM payload `com.apple.system-extension-policy` (device channel, requires user-approved MDM): `AllowedSystemExtensions`, `AllowedSystemExtensionTypes`, `RemovableSystemExtensions`, `NonRemovableSystemExtensions`, `NonRemovableFromUISystemExtensions`; since 11.3 removing the payload deactivates the extension ([doc](https://developer.apple.com/documentation/devicemanagement/systemextensions)).
- ES clients must be granted FDA (`SystemPolicyAllFiles`) or `es_new_client` fails; Santa documents the PPPC profile with a code requirement pinned to its Team ID. NE needs its own content-filter and DNS-proxy configuration profiles.
- Activating a network extension tears down all existing connections; Santa installs it lazily on reboot or wake for that reason ([network-extension.md](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/network-extension.md)).
- Apple, 2026-10-02, "Updates to Full Disk Access in macOS": FDA will need very explicit user action, motivated by agent risk; no timeline; silent on security software and MDM ([notice](https://developer.apple.com/news/?id=p6zjojqw)). Secondary reports say macOS 27 also removed direct app access to the TCC database and added `tccutil list` (unverified).

### 4. Network Extension

- Provider matrix ([TN3134, rev. 2025-08-19](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)): on macOS, content filter and DNS proxy are system-extension only (10.15+); transparent proxy and app proxy can be system extensions with Developer ID; the URL filter (26.0) is app-extension only.
- Attribution: `NEFilterFlow.sourceAppAuditToken` (the "source application") and `sourceProcessAuditToken` (macOS 13+, "the process that created the flow"). LuLu's source treats them as different when a system delegate such as the resolver opens the socket on an app's behalf, and uses the app token for policy ([FilterDataProvider.m](https://github.com/objective-see/LuLu/blob/master/LuLu/Extension/FilterDataProvider.m)). Join either token to the ES process tree by pid+pidversion.
- Content filter: allow, drop, pause, or peek N bytes per flow. Transparent proxy (`NETransparentProxyProvider`, macOS 11+): returning false from `handleNewFlow` lets the flow go direct; claimed flows can be relayed to a local gateway. This is the mechanism for forcing a specific process's LLM and MCP traffic through our gateway without relying on proxy environment variables.
- Limits **[inferred unless noted]**: payload is TLS ciphertext unless we terminate with a trusted CA, which breaks pinned clients; QUIC arrives as UDP flows, so the practical control is dropping UDP/443 for governed processes to force TCP; ECH removes SNI, leaving the connect-by-name hostname and DNS-proxy correlation; in-app DoH bypasses a DNS proxy. Claude Code's own sandbox proxy does not terminate TLS by default and blocks UDP/QUIC/ICMP outright (verified, [docs](https://code.claude.com/docs/en/sandboxing)).
- ES network events (26.4): PID, path, resolved address, hostname up to 256 bytes; undocumented; Wardle's verdict is that they suit simple monitoring but not proxying or content inspection.

### 5. Seatbelt and how agents use it

| Agent | Mechanism (macOS) | Default | Scope | Network | Outside the sandbox |
|---|---|---|---|---|---|
| Claude Code | Seatbelt via `@anthropic-ai/sandbox-runtime` (Apache-2.0) | Off | Bash and children | Local proxy, `allowedDomains` empty by default | Read/Edit/Write tools, MCP servers, hooks; `dangerouslyDisableSandbox` retry unless `allowUnsandboxedCommands:false` |
| Codex CLI | `/usr/bin/sandbox-exec` hard-coded, `.sbpl` policies in `codex-rs/sandboxing` | On | `read-only` / `workspace-write` / `danger-full-access` | Managed network proxy, unix-socket allowlist | Escalated commands |
| Cursor | Seatbelt via `sandbox-exec`, generated profile for the subprocess tree | On in Auto-review | Shell commands | `sandbox.json` allowlist plus defaults | MCP and Fetch calls; re-runs after sandbox failure |
| Gemini CLI | `sandbox-exec`, six profiles, default `permissive-open` | Off (`-s`) | Whole CLI re-exec | Open or proxied by profile | Nothing, or Docker/Podman instead |
| Santa (Workshop, beta 2026.5) | `santactl sandbox`: `sandbox_init_with_parameters` then exec, verified at `AUTH_EXEC` | Per rule | The ruled binary | Per profile | n/a |

Sources: [Claude Code](https://code.claude.com/docs/en/sandboxing), [Codex seatbelt.rs](https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt.rs), [Cursor run modes](https://cursor.com/docs/agent/security/run-modes), [Gemini CLI sandbox.md](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md), [Santa SNTCommandSandbox.mm](https://github.com/northpolesec/santa/blob/main/Source/santactl/Commands/SNTCommandSandbox.mm).

Seatbelt needs no entitlement and no root, applies to the whole subtree, and cannot be removed by the confined process. It is also a discovery signal: an exec of `/usr/bin/sandbox-exec` with a `-p`/`-f` profile under a `node`, `codex` or Cursor helper parent identifies an agent and its posture.

### 6. Identity and attribution

- `es_process_t` gives `audit_token` (pid, pidversion, uid, audit session), `ppid`, `original_ppid`, `session_id`, `tty`, `start_time`, `signing_id`, `team_id`, `cdhash` (20 bytes), `codesigning_flags`, `is_platform_binary`, `parent_audit_token`, `responsible_audit_token`, plus `cs_validation_category` (macOS 26, message v10) and `cdhash_full` (macOS 27, v11). `es_exec_entitlements` (27) returns the exec target's entitlements. Apple's caveat: `CS_VALID` at exec means only what has been validated so far; pages are checked lazily ([es_process_t](https://developer.apple.com/documentation/endpointsecurity/es_process_t)).
- Fingerprint order: Team ID + signing ID for signed native agents; `cdhash` for exact build; for Node-hosted agents the signer is Node or Homebrew, so identity must come from argv, script path and package metadata **[inferred]**.
- Where lineage breaks: GUI apps are children of launchd via `xpcproxy` (use the responsible token); anything started in Terminal, iTerm or an IDE terminal has the terminal as responsible process, and TCC attributes to it (Wardle's 15.4 test saw Terminal, not the malware binary); daemonised children reparent to launchd (`original_ppid` survives); work handed to launchd jobs, XPC services, `osascript`, tmux servers or Docker's daemon leaves the tree entirely. The 27.0 bootstrap and XPC events are the first supported view of those hand-offs.
- Human and agent share uid and audit session in a GUI login, so the audit session separates SSH from console but not agent from human. The discriminator is ancestry rooted at an agent binary, plus TTY presence and correlation with in-agent hook events.

### 7. TCC as a computer-use signal

`NOTIFY_TCC_MODIFY` (15.4): service string (`Accessibility`, `ScreenCapture`, `SystemPolicyAllFiles`, ...), identity and type, create/modify/delete, right, reason, instigator and optional responsible process. Notify only; fires on grant or revoke, not on use; silent for entitled binaries and prompt-less denials; attribution often lands on the terminal ([Wardle, 2025-03-27](https://objective-see.org/blog/blog_0x7F.html)). An Apple forum report says direct sqlite edits of TCC.db produce no event. There is no ES event for synthetic input or screen capture in use.

### 8. Agents in VMs and containers

- **Claude Cowork**: Virtualization.framework Linux guest (Ubuntu 22.04 arm64 per January 2026 reverse engineering), bundle at `~/Library/Application Support/Claude/vm_bundles/claudevm.bundle/`, VirtioFS shares, bubblewrap+seccomp per session, egress through a host-side allowlist proxy in Claude.app reached over Unix sockets ([pvieito, 2026-01-26](https://pvieito.com/2026/01/inside-claude-cowork)). Host ES sees `com.apple.Virtualization.VirtualMachine`, Claude.app, and file events on shared folders.
- **EDR in the Cowork VM** (Anthropic, [2026-11-05](https://claude.com/resources/articles/claude-enterprise-security-updates)): beta on macOS and Windows for Team/Enterprise; MDM-configured; signature-checked vendor package installed at each VM start; detection only; local VM only. Secondary coverage names CrowdStrike, SentinelOne, Palo Alto Networks, Tanium and others as approved.
- **apple/container** (Apache-2.0, 1.7.1 on 2026-11-06): one lightweight VM per container, vmnet networking, `container-apiserver` launch agent with XPC helpers ([technical overview](https://github.com/apple/container/blob/main/docs/technical-overview.md)).
- **Docker Sandboxes**: microVM per agent, all outbound TCP through a host proxy that enforces policy and swaps sentinel credentials for real ones; stdio MCP servers run on the host ([architecture](https://docs.docker.com/ai/sandboxes/architecture/)).
- Coverage options: an in-guest Linux sensor (same code as our Linux agent); host-side observation of the VM process, its shares and its proxy; and the vendor's own proxy/hook surface.

### 9. Santa's architecture (closest precedent)

Bazel-built Objective-C++; one ES system extension (`com.northpolesec.santa.daemon`) hosting several `es_client_t` instances by concern: `Authorizer` (AUTH_EXEC with a local `AuthResultCache`), `DataFileAccessAuthorizer` (paths protected from processes), `ProcessFileAccessAuthorizer` (processes confined to paths, inverted process muting), `Recorder` (NOTIFY telemetry), `DeviceManager` (mounts), `TamperResistance`, and a `TreeAwareClient` base over a shared `process_tree`. Around it: `santactl`, a GUI, a sync service, a metrics service and a bundle service over XPC; CEL policies; protobuf spool telemetry; a separate `santanetd` system extension (content filter plus DNS proxy) that is Workshop-only and absent from the public tree. Known limits per its docs: exec only, scripts ignored, no dylib control.

### 10. Rust and Swift interop

- `endpoint-sec` / `endpoint-sec-sys` (HarfangLab): safe wrappers, dual Apache-2.0/MIT, MSRV 1.88; issues #166 (macOS 26) and #169 (macOS 27) both open as of 2026-09-15, so new APIs need our own `-sys` additions.
- `objc2` ships `objc2-network-extension`, `objc2-system-extensions`, `objc2-virtualization`, `objc2-service-management`. NE providers must be Objective-C subclasses named in `Info.plist`; system-extension activation is an app-side delegate flow.
- ES handlers are C blocks; Rust needs the `block2` crate or a C shim. Recommendation below.

## Matrix

| Capability | Mechanism | Requirements | Risks | Effort |
|---|---|---|---|---|
| Discover agents (installed, running) | Userspace scan: libproc, SecCode signature, config/MCP file discovery | None; FDA for some paths | Node-hosted agents lack a useful signer | S |
| Live process telemetry | ES NOTIFY in system extension | **Apple ES entitlement**, org Developer ID, notarisation, FDA, sysext approval | Approval delay; FDA policy change | L |
| Same, no entitlement | `eslogger` subprocess | root, FDA | Not API; notify only | S |
| Block exec | ES `AUTH_EXEC` | as ES | Deadline kill pre-27; cache bugs | L |
| Protect secrets from agent tree | ES file AUTH with inverted process + target-path muting | as ES | AUTH_OPEN volume; glob staleness | L |
| Supervise agents we launch | `es_new_descendants_client` | **macOS 27, ES entitlement**; no root, no FDA | Dies open with client; only our subtree | M |
| Confine agent without entitlement | Seatbelt launcher (`sandbox_init_with_parameters`) | None | `sandbox-exec` deprecated; SBPL undocumented; nested sandbox conflicts with agents' own | M |
| Per-process network allow/deny | NE content filter + DNS proxy | Org Developer ID, NE capability in profile, notarisation, user or MDM approval | Activation drops connections; coexistence with other filters | M |
| Force traffic through LLM/MCP gateway | NE transparent proxy to local gateway | as above, plus trusted CA for inspection | Pinning, QUIC, ECH | L |
| IPC hand-off visibility | `XPC_CONNECT`, `BOOTSTRAP_*` | ES; AUTH needs 27 | Named connections only (unconfirmed) | M |
| Computer-use grants | `TCC_MODIFY` | ES, 15.4+ | Notify only; weak attribution | S |
| Agents in VMs | In-guest Linux sensor; Anthropic EDR-in-VM | **Anthropic vendor approval** for Cowork | Detection only; vendor-gated | M |
| Enforce agent's own sandbox | Managed settings (Claude Code, Cursor team modes, Codex requirements) | MDM or admin console | Per-vendor drift | S |
| Embedding in an EDR | Rust core as a library inside the vendor's entitled extension | Vendor's entitlement | ABI stability | M |

## Weak points, gaps and risks

- The ES entitlement is a single external dependency with no SLA, bound to one Team ID. Forks and self-builders cannot inherit it.
- No fail-closed on ES client death, including descendants clients. A crash is an open window.
- FDA tightening is announced but unspecified; a design that hard-requires FDA on unmanaged Macs may get a much worse install flow.
- Agent sandboxes cover shell only; MCP servers and built-in tools run unsandboxed, so "sandbox on" is not containment.
- Process lineage is lossy by design on macOS. Any attribution model that is tree-only will misattribute launchd/XPC hand-offs.
- VM-hosted agents are opaque to host ES and probably to socket-level NE filtering **[inferred]**; Anthropic controls who may run inside Cowork's VM.
- Undocumented surfaces (`RESERVED_*` events, SBPL, `sandbox_init_with_parameters`) can change in any point release.
- Santa's 2026 advisories show ES authorisers are a real local attack surface (TOCTOU on exec targets, fat-binary confusion, daemon crash).

## Implications for our design

1. **Three tiers with one policy engine.** Tier A (no Apple approval): userspace discovery, in-agent hooks, managed-settings enforcement, local gateway, Seatbelt launcher, optional `eslogger`. Tier B (org Developer ID): NE system extension. Tier C (ES entitlement): ES system extension. The product must be useful at Tier A, because that is all a self-builder gets.
2. **Apply for the ES entitlement on day one**, as an organisation, describing an AIDR use case; build and test with SIP off meanwhile. File feedback supporting the self-add descendants entitlement.
3. **Copy Santa's client-per-concern layout**: exec authoriser, agent-tree watcher (inverted process muting, fork/exec/exit bookkeeping), secrets guard (inverted target-path muting), recorder, tamper client. Key every cache on cdhash/content, never cache DENY in ES.
4. **Ship an "agent launcher" on macOS 27** using `es_new_descendants_client`: no root, no FDA, deadline floor so a policy prompt can block an exec. Pair it with a watchdog that kills the subtree if the client exits.
5. **Rust core, Swift shell.** Rust static library with a C ABI (event in, verdict out, no Apple types) holds process tree, policy and telemetry. A small Swift target owns `es_new_client`, NE provider classes, sysext activation and XPC. The same library is what EDR vendors embed in their own entitled extension; Apple requires a separate approval to let other developers host our extension.
6. **Process identity record**: `{pid, pidversion, start_time, cdhash(_full), team_id, signing_id, cs_validation_category, tty, session_id, original_ppid, parent token, responsible token}` plus an "agent root" pointer and a list of hand-off edges (XPC/bootstrap/launch-item) with confidence.
7. **NE as content filter + DNS proxy first**, transparent proxy second and opt-in. Install lazily, like Santa. Drop UDP/443 only for governed processes.
8. **Treat `sandbox-exec` execs and agent managed-settings files as first-class telemetry**, and offer policy packs that turn on each agent's sandbox with escape hatches disabled.
9. **VMs**: reuse the Linux sensor as a guest package; pursue Anthropic's approved-vendor route; on the host, model the VM process as an agent container and attribute shared-folder file events to it.

Phasing: P0 Tier A (weeks). P1 NE extension plus signed, notarised installer and MDM profiles. P2 ES extension once entitled (macOS 14 baseline; 15.4 for TCC; 26 for `cs_validation_category`). P3 macOS 27 descendants supervisor and XPC/bootstrap AUTH. P4 VM guests and vendor embedding SDK.

**Needs an Apple developer organisation account**: Developer Program enrolment (legal entity), Developer ID Application and Installer certificates, provisioning profiles, notarisation, NE system-extension entitlements, system-extension install entitlement. **Needs explicit Apple approval**: ES client entitlement; the entitlement to let other developers use our system extension; DriverKit (not needed). **Needs someone else's approval**: Anthropic's EDR-in-Cowork vendor list; customers' user-approved MDM for silent sysext, FDA and filter approval.

## Ideas worth stealing and whitespace

- Santa's `SandboxExpectations`: register (dev, inode, cdhash, sha256) for a pid, then verify at `AUTH_EXEC` that the sandboxed launcher really exec'd the expected binary.
- Santa's lazy NE install on wake/reboot, and a "lite" package without the NE for users who object to its presence.
- Docker Sandboxes' sentinel-credential swap at the host proxy: the agent never holds the real secret.
- Codex's hard-coded `/usr/bin/sandbox-exec` path and deny rules for ancestor-directory unlink around protected sockets.
- Whitespace: nobody ships an open, user-level agent supervisor on the descendants client; nobody records launchd/XPC hand-off edges as attribution evidence; nobody unifies host and in-VM agent telemetry under one process-tree model; no open-source NE that routes by agent identity to an MCP/LLM gateway (Santa's is closed).

## Could not verify / open questions

- Current ES entitlement turnaround and whether Apple grants it to open-source organisations for AI-agent use.
- Whether NE Developer ID entitlements still need no manual approval (inferred from Apple's page and LuLu).
- NE visibility of traffic from Virtualization.framework/vmnet guests.
- Exact scope of `AUTH_XPC_CONNECT` (named services only?) and semantics of `RESERVED_0..8`.
- Final shape and date of the FDA changes; effect on MDM PPPC grants and system extensions.
- Team IDs and signing IDs of current agent binaries (must be collected empirically).
- macOS 27.2 additions (notify-only exception-port, `map_anon`, `sigaction` types inferred by calif.io from iOS 27.2 beta).
- `eslogger` man-page wording; Cowork approved-vendor list from Anthropic's Help Center.
- Blocked: x.com post by rad9800 (HTTP 402); several Apple doc pages returned only stubs.

## Sources

- https://github.com/HarfangLab/endpoint-sec/issues/169 - Support macOS 27 changes (header diff), 2026-09-15
- https://github.com/HarfangLab/endpoint-sec/issues/166 - Support macOS 26 changes, 2026-09-14
- https://github.com/alexey-lysiuk/macos-sdk - macOS 26.5 SDK EndpointSecurity headers
- https://developer.apple.com/forums/thread/845644 - Descendants client discussion with Apple DTS, Sept 2026
- https://objective-see.org/blog/blog_0x86.html - Undocumented ES network events, 2026-03-26
- https://objective-see.org/blog/blog_0x7F.html - TCC events in ES, 2025-03-27
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client - ES entitlement
- https://developer.apple.com/system-extensions/ - System Extensions and DriverKit
- https://developer.apple.com/documentation/endpointsecurity/es_process_t - es_process_t
- https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment - TN3134, rev. 2025-08-19
- https://developer.apple.com/documentation/networkextension/nefilterflow - NEFilterFlow
- https://developer.apple.com/documentation/networkextension/netransparentproxyprovider - NETransparentProxyProvider
- https://developer.apple.com/documentation/devicemanagement/systemextensions - SystemExtensions payload
- https://developer.apple.com/news/?id=p6zjojqw - Updates to Full Disk Access in macOS, 2026-10-02
- https://github.com/northpolesec/santa - Santa source, docs, releases (v2026.9, 2026-10-27)
- https://github.com/objective-see/LuLu - LuLu source (v4.5.7, 2026-11-02)
- https://github.com/objective-see/BlockBlock - BlockBlock source
- https://code.claude.com/docs/en/sandboxing - Claude Code sandboxing
- https://github.com/anthropic-experimental/sandbox-runtime - sandbox-runtime
- https://github.com/openai/codex/tree/main/codex-rs/sandboxing - Codex Seatbelt policies
- https://cursor.com/docs/agent/security/run-modes - Cursor run modes
- https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md - Gemini CLI sandboxing
- https://claude.com/resources/articles/claude-enterprise-security-updates - EDR in Cowork, 2026-11-05
- https://pvieito.com/2026/01/inside-claude-cowork - Cowork VM internals, 2026-01-26
- https://github.com/apple/container - apple/container 1.7.1, 2026-11-06
- https://docs.docker.com/ai/sandboxes/architecture/ - Docker Sandboxes architecture
- https://calif.io/research/ios-endpoint-security - ES in iOS 27.2 beta, 2026-09-18
- https://github.com/madsmtm/objc2 - objc2 framework crates

## Independent verification

_Checked 2026-11-09 by a second reviewer. Method: Apple documentation read through the developer.apple.com JSON endpoints, source and issue text read through the GitHub API, vendor pages fetched directly. The shared web-search budget was already exhausted, so no search-engine queries were possible; claims 4, 9 and 10 could only be re-read at the researcher's own source URL, not corroborated by a second source._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | ES client entitlement must be requested from Apple; without it `es_new_client` fails with `ERR_NOT_ENTITLED`; System Extensions page lists only DriverKit, ES and "let other developers use your system extension" | confirmed | Entitlement page says "You must request this entitlement from Apple" and names `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`. System Extensions page lists exactly those three and says nothing about Network Extension needing a request. | https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client ; https://developer.apple.com/system-extensions/ |
| 2 | Ad-hoc Santa build with the ES entitlement loads only with SIP disabled | confirmed | Santa's building.md says an "adhoc" build can be reloaded "only if you disable SIP". Apple's own page says to test with SIP off while the request is in review. `systemextensionsctl developer on` only relaxes the install-location check, not entitlement validation. A self-builder with their own Apple-granted entitlement is the only exception. | https://github.com/northpolesec/santa/blob/main/docs/docs/development/building.md ; https://developer.apple.com/documentation/driverkit/debugging-and-testing-system-extensions |
| 3 | macOS 27.0 adds `es_new_descendants_client` (notify for caller, AUTH+NOTIFY for subtree, entitlement required, no root, no TCC, settable deadline floors) | confirmed, with two caveats the brief omits | Apple's published doc (macOS 27.0) matches. Caveat 1: "The caller and its descendants can't execute setuid/setgid binaries unless the caller has an effective uid of 0"; blocked execs are killed with no exec event. A non-root supervisor therefore breaks `sudo`/`su` (and any other setuid tool) inside the agent subtree. Caveat 2: the deadline floor cannot be set for `AUTH_BOOTSTRAP_CHECK_IN` / `AUTH_BOOTSTRAP_LOOK_UP`, and a floor within 10 s of `UINT32_MAX` ms is refused. | https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:) ; https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_min_milliseconds(_:_:_:_:) |
| 4 | Apple DTS: descendants client designed for supervising AI dev tools; restrictions removed if client disconnects; intent is a self-add entitlement; none exists yet | confirmed (wording softer than the claim) | DTS engineer said the poster's scenario (an AI-assisted development coordinator controlling its workers) "is one of the primary use cases" it was designed for, not that it was built for AI tools specifically. "If the client goes away, all the restrictions it applied are removed." On the entitlement he said he did not know where things stand and that it will "probably" be a self-add entitlement, then asked for a bug (FB24830531). Apple's current doc still requires the full ES client entitlement. Treat the self-add entitlement as unscheduled. | https://developer.apple.com/forums/thread/845644 |
| 5 | NE content filter and DNS proxy are system-extension only on macOS (10.15+); transparent proxy can be a Developer ID system extension; LuLu ships open source with `content-filter-provider-systemextension` | confirmed | TN3134 tables read directly: content filter and DNS proxy list only "system extension, 10.15" for macOS; transparent proxy system extension row has no "App Store only" restriction. LuLu (GPL-3.0, v4.5.7, 2026-11-02) carries the entitlement in both `App.entitlements` and `Extension.entitlements`. Apple's NE entitlement page describes enabling the capability for a Developer ID app in the portal with no request step. | https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment ; https://github.com/objective-see/LuLu/blob/master/LuLu/Extension/Extension.entitlements ; https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension |
| 6 | ES muting is per audit token, not inherited; Santa watches process trees via inverted process muting, un-muting children on FORK, re-keying on EXEC, cleanup on EXIT | corrected | Inverted process muting, FORK propagation and EXIT cleanup are as described. EXEC is not re-keyed: on `NOTIFY_EXEC` Santa only deletes the old pid+pidversion entry. The new image is watched only if it independently matches a policy in the exec probe (`probeInterest` -> `findPolicyForProcess(exec.target)`); otherwise the next event finds no policy and `stopWatching` is called. Santa's client is binary-scoped with fork inheritance, not a tree follower across exec. An agent-tree watcher must itself select the exec target's audit token and carry the agent-root pointer through every exec. | https://github.com/northpolesec/santa/blob/main/Source/santad/EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.mm ; https://github.com/northpolesec/santa/blob/main/Source/common/es/SNTEndpointSecurityClient.mm |
| 7 | macOS 27.0 adds `es_set_deadline_miss_mode` (KILL default, FAIL_CLOSED, FAIL_OPEN); earlier a missed deadline kills the client; `AUTH_XPC_CONNECT` and AUTH/NOTIFY bootstrap check-in/look-up are new in 27.0 | confirmed | Apple docs list the function at macOS 27.0 with those three modes and KILL as default; the event enum now includes the five new types. Pre-27 wording in Apple's doc is that ES "may terminate the client process" and may refuse new connections after repeated misses. `AUTH_BOOTSTRAP_LOOK_UP` is unavailable to non-descendants clients. | https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:) ; https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline ; https://github.com/HarfangLab/endpoint-sec/issues/169 |
| 8 | Claude Code, Codex CLI, Cursor and Gemini CLI all use Seatbelt and apply it to shell commands only; in Claude Code and Cursor MCP servers and built-in tools run outside; Claude Code's sandbox is off by default | corrected | Seatbelt on macOS: true for all four. "Shell commands only" holds for Claude Code ("The sandbox covers shell commands only"; off by default; hooks, local MCP servers, Read/Edit/Write outside) and Cursor (shell commands; MCP and Fetch outside). It does not hold for Gemini CLI: its default Seatbelt mode re-executes the whole CLI under `sandbox-exec`, and the optional `security.toolSandboxing` (default false) isolates individual tools including `write_file`. Codex's docs say the sandbox "applies to spawned commands, not just to built-in file operations", so file edits are covered too. Section 5's table already has Gemini right; the TL;DR bullet and the "weak points" bullet overgeneralise. | https://code.claude.com/docs/en/sandboxing ; https://cursor.com/docs/agent/security/run-modes ; https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md ; https://learn.chatgpt.com/docs/sandboxing |
| 9 | Anthropic beta (2026-11-05): Team/Enterprise admins run a supported vendor's EDR sensor in the local Cowork VM on macOS and Windows, MDM-deployed, signature-checked each VM start, detection only | confirmed (single source) | Article dated 2026-11-05 states beta on macOS and Windows, set up "through device management", signature verified "each time the virtual machine starts", sensors "report activity ... and don't block it", local VM only (not cloud sessions). The article names no vendors; the list is in the Help Center, which I could not reach. | https://claude.com/resources/articles/claude-enterprise-security-updates |
| 10 | Apple, 2026-10-02: Full Disk Access will require very explicit user action, citing AI-agent risk, no timeline, silent on security software and MDM; ES clients currently require FDA | confirmed | Post dated October 2, 2026 uses "very explicit user action" and refers to AI agents becoming more capable and autonomous; no version, date, ES, EDR or MDM/PPPC mention. Apple's `es_new_client` doc requires TCC approval via Full Disk Access. The macOS 27 descendants client is the exception (no TCC approval). | https://developer.apple.com/news/?id=p6zjojqw ; https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:) |

Further statements checked:

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Implication 4 and the matrix row "Supervise agents we launch": descendants client needs "no root" and works as a general agent launcher | overstated | True that root is not required, but a non-root descendants client makes the whole subtree unable to exec setuid/setgid binaries (see claim 3). An agent that needs `sudo` or other setuid tools must be launched by a root-owned supervisor, which reintroduces a privileged helper. Design the launcher with both modes and test on macOS 27 which common tools are affected. | https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:) |
| Santa's network extension source "is not in the public tree" | confirmed | The public repo contains only `stubs/santanetd`, described as a stub that lets Santa build "without requiring access to the private `santanetd` repository". The NE docs state it needs a Workshop subscription. | https://github.com/northpolesec/santa/blob/main/stubs/santanetd/README.md ; https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/network-extension.md |
| Event enum: 27.0 adds five events, `RESERVED_0..8` exist, `LAST` = 162 | outdated as a description of the current SDK | Correct for the 27.0 header diff, but Apple's current `es_event_type_t` documentation lists `ES_EVENT_TYPE_RESERVED_0` through `RESERVED_18`, so a later 27.x SDK has added ten more reserved slots. Never hard-code `ES_EVENT_TYPE_LAST` or enum counts; size tables at runtime and ignore unknown types. | https://developer.apple.com/documentation/endpointsecurity/es_event_type_t |

Also spot-checked and found accurate: macOS 27 is named Golden Gate (apple.com/macos); `endpoint-sec` 0.6.2 is MIT OR Apache-2.0 with `rust-version = "1.88"` and issues #166/#169 are open; apple/container 1.7.1 was published 2026-11-06 under Apache-2.0; Santa 2026.9 was published 2026-10-27; Wardle's 2026-03-26 post identifies `RESERVED_5` (AUTH) and `RESERVED_6` (NOTIFY) in macOS 26.4 with a 15 s deadline.
