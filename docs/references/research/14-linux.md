# Linux: observing and blocking AI-agent activity (eBPF, BPF LSM, fanotify, seccomp, Landlock)

_Researched 2026-11-09_

Legend: **[V]** verified today against a primary source (linked). **[K]** from prior kernel knowledge, not re-verified today. **[I]** my inference. The shared web-search budget ran out part-way; later facts come from direct fetches of docs, man pages and source via `gh`.

## TL;DR

- **BPF LSM is the only synchronous, system-wide, cgroup-scopable deny on Linux, and it is still off on stock Ubuntu.** Ubuntu builds `CONFIG_BPF_LSM=y` but leaves `bpf` out of `CONFIG_LSM`; Launchpad #2054810 is still "Triaged" (last comment 2026-03-21) and 26.04 cloud images (kernel 7.0) are reported the same. Debian, RHEL/CentOS Stream 9, Bottlerocket, Talos and (since 2026-10-06) WSL2 have it active. [V]
- **WSL2 changed last month.** `linux-msft-wsl-6.18.54.1` (2026-10-06) says "Bpf LSM is enabled by default"; the config now ends `...,tomoyo,bpf`. Before that no WSL2 kernel had both halves on. The WSL2 kernel still has no `CONFIG_FUNCTION_ERROR_INJECTION` and no `CONFIG_FPROBE`, so Tetragon-style `Override` and kprobe-multi do not work there. [V]
- **Kill is not block.** Tetragon's own docs say SIGKILL "does not always stop the operation" (a `write()` may land) and must be paired with `Override`, which needs `CONFIG_BPF_KPROBE_OVERRIDE`. LSM return codes are the race-free path. [V]
- **BPF LSM programs must be GPL-compatible** (kernel doc: LSM and struct_ops programs "implicitly" call GPL-only functions), but the same doc says non-GPL applications and GPL BPF programs "can be packaged together" as separate executables. Tetragon ships BPF as `GPL-2.0-only OR BSD-2-Clause` beside Apache-2.0 userspace; Falco's driver is MIT/GPL2. Copy that layout. [V]
- **Landlock moved fast: ABI 12 is in 7.4-rc.** Verified from kernel tags: ABI 6 = 6.12, 7 = 6.15 (audit), 8 = 7.0 (TSYNC), 9 = 7.1 (pathname UNIX sockets), 10 = 7.2 (UDP + quiet rules), 11 = 7.3 (NO_NEW_PRIVS flag), 12 = 7.4-rc (capability and namespace rules). [V]
- **Codex and Anthropic's sandbox-runtime both use bubblewrap + seccomp, not Landlock.** Codex rejects its legacy Landlock path "because it cannot isolate app-server Unix sockets" (fixed in the kernel only from ABI 9 / 7.1). Both seccomp filters block `io_uring`. Both break under Ubuntu 24.04+'s `apparmor_restrict_unprivileged_userns`. [V]
- **Claude Code's sandbox covers Bash only.** Read/Edit/Write/WebFetch, hooks, local MCP servers, LSP servers and `!` commands run with full user access; reads are not denied by default (`~/.ssh` readable). A system-wide sensor is therefore not redundant. [V]
- **TLS uprobes do not work on the agents that matter.** Claude Code is a ~213 MB stripped Bun binary with static BoringSSL; AgentSight had to byte-pattern-match offsets from a matching Bun profile build, per version. Plan on hooks/gateway/proxy for content, uprobes as an opportunistic extra. [V]
- **fanotify permission events plus cgroup-v2 BPF are the no-reboot fallback.** `FAN_OPEN_PERM`/`FAN_OPEN_EXEC_PERM`/`FAN_ACCESS_PERM`, `FAN_DENY_ERRNO` (6.13), `FAN_PRE_ACCESS` and `FAN_MARK_MNTNS` (6.14) need only root; they can also *hold* a syscall while userspace decides, which BPF LSM cannot. [V]/[K]
- **Commercial "AI agent security" has no Linux endpoint story.** BeyondTrust's docs state Windows 11/Server 2022+ x64 and macOS 14/15/26 only. Open-source work (AgentSight, ActPlane, nono) is research-grade or launch-time only. Linux system-wide agent enforcement is open whitespace. [V]
- **Syscall-tracepoint sensors are blind to io_uring**; ARMO's "Curing" (2025-04-24) evaded Falco and default Tetragon. Hook LSM/VFS/socket layers, not `sys_enter_*`. [V]

## Findings

### 1. eBPF tracing and BPF LSM

**Availability (verified from configs/release notes this session):**

| Platform | `CONFIG_BPF_LSM` | `bpf` in active LSM list | Source |
|---|---|---|---|
| Debian (kernel-team `debian/latest`) | y | yes: `landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,selinux,smack,tomoyo,bpf,ipe` | salsa config |
| CentOS Stream 9 / RHEL 9 | y | yes: `landlock,lockdown,yama,integrity,selinux,bpf` | gitlab centos-stream-9 |
| Ubuntu 22.04 / 24.04 / 26.04 | y | **no**; needs `lsm=...,bpf` on the kernel command line + reboot | LP #2054810; 2026-07 stable thread (secondary) |
| Bottlerocket (6.18 kit) | y | yes | bottlerocket-kernel-kit |
| Talos | y | yes (`yama,selinux,safesetid,integrity,bpf,apparmor,lockdown,landlock`) | siderolabs/pkgs |
| WSL2 >= 6.18.54.1 (2026-10-06) | y | yes | WSL2-Linux-Kernel release notes + config |
| WSL2 6.6.y and 6.18 < .54.1 | y | no | microsoft/WSL #41612 (closed 2026-10-09) |
| GKE COS, AL2 (>=5.8), AL2023, RHEL >= 8.5, SUSE, OKE UEK7 | — | enforcement via BPF LSM per KubeArmor matrix | KubeArmor support matrix |
| EKS Ubuntu, AKS Ubuntu, Graviton Ubuntu | — | AppArmor path | KubeArmor support matrix |

RHEL 10 and Fedora are very likely the same as Stream 9 [I]; the Stream 10 config URL returned 404.

**Requirements.** Kernel >= 5.7 for `BPF_PROG_TYPE_LSM` (aya book, Tetragon docs) [V]; BTF (`CONFIG_DEBUG_INFO_BTF`, `/sys/kernel/btf/vmlinux`) for CO-RE [V]; lockdown must not be `confidentiality` (BPF load returns EPERM; Tetragon FAQ) [V]. On ARM64, LSM/fentry attach needs `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` or attach fails `ENOTSUP` (Tracee docs) [V]; KubeArmor lists AL2 on Graviton and Oracle Ampere as no-blocking [V].

**Verifier and policy limits.** 512-byte stack, 1M processed instructions, bounded loops only [K]. Path matching in-kernel is the pain point: Tetragon 1.8 rejects Postfix values over 87 chars on kernels without large-program support, caps `matchPIDs` at 4 and `followChildren` at 64 sections, and only in 1.8.0 (2026-10-30) added "an eBPF-based glob library" and "stateful tracing policies" [V]. Design for inode/cgroup-keyed maps populated by userspace, not string globs in BPF [I].

**Signed BPF.** Merged in 6.18 (KP Singh): the kernel verifies a signature on a libbpf-generated loader, which embeds a hash of the real program and maps. Microsoft's alternative (verification finished before the LSM hook) was refused by BPF maintainers; LWN 2025-10-27 calls the dispute unresolved. A May 2026 "Signed BPF + IPE Policies" series exists; merge status not verified. Treat signing as hardening on >= 6.18, not as a trust anchor. [V]

**BPF token.** Kernel 6.9: a privileged process sets `delegate_cmds/maps/progs/attachs` on a bpffs instance; the token is bound to the user namespace that created it. systemd 258 exposes this as `PrivateBPF=` and `BPFDelegate*=`. It lets a privileged installer delegate narrow BPF rights to an unprivileged per-user daemon; it does not remove the need for a privileged install step. [V]

**Licence.** Kernel `bpf_licensing` doc: programs may be proprietary only if they avoid GPL-only helpers; LSM, struct_ops and kfunc users must be GPL-compatible; packaging with non-GPL userspace is fine [V]. Observed practice: Tetragon `bpf/` = `(GPL-2.0-only OR BSD-2-Clause)` with Apache-2.0 agent; Falco `libs/driver` ships `GPL2.txt` + `MIT.txt`; KubeArmor enforcer = GPL-2.0; Tracee's BPF file is "licenced differently from the rest of the project"; **Kunai is GPL-3.0 as a whole**, so it is reference-only for an Apache-2.0 codebase [V].

### 2. Enforcement races: kill vs override vs LSM deny

- `Sigkill` runs in BPF but the in-flight syscall may complete; Tetragon says combine with `Override` [V].
- `Override` needs `CONFIG_BPF_KPROBE_OVERRIDE` and functions tagged `ALLOW_ERROR_INJECTION` (syscalls; `security_*` from 5.7). fentry supports neither Override nor Signal [V]. Absent on stock WSL2 [V].
- Syscall-entry hooks reading user pointers are TOCTOU-prone; Tetragon recommends hooking later `security_*` functions that see kernel-resident data [V].
- Tetragon 1.8 "Keep LSM enforcement active after agent exit" — pinned links give fail-closed behaviour when the daemon dies [V].
- BPF LSM cannot wait for a human. For "ask" verdicts use fanotify permission events or seccomp user-notification, which block the caller until userspace answers [I].

### 3. fanotify

Permission events: `FAN_OPEN_PERM`, `FAN_ACCESS_PERM`, `FAN_OPEN_EXEC_PERM` (5.0; fires only for direct execve, not interpreter reads), `FAN_PRE_ACCESS` (6.14; `FAN_CLASS_PRE_CONTENT`; carries offset/count range). `FAN_DENY_ERRNO` since 6.13 (EPERM, EIO, EBUSY, ETXTBSY, EAGAIN, ENOSPC, EDQUOT). `FAN_MARK_FILESYSTEM` (4.20) and `FAN_MARK_MOUNT` need CAP_SYS_ADMIN; `FAN_MARK_MNTNS` (6.14). `FAN_REPORT_PIDFD` gives a pidfd, created at read time. [V]

Gaps: no permission events for unlink, rename, create, chmod or write content; mmap access not reported; bind-mount paths can bypass mount marks; queue overflow drops notifications; closing the group **allows** all pending events (fail-open) [V]. A stalled listener stalls every opener on the marked filesystem, so the daemon needs its own exemption and a watchdog [K]. Filesystem opt-in list for pre-content events not verified.

### 4. seccomp user notification

`SECCOMP_RET_USER_NOTIF` and `NEW_LISTENER` (5.0), `FLAG_CONTINUE` (5.5), `ADDFD` (5.9), atomic `ADDFD_FLAG_SEND` (5.14), `WAIT_KILLABLE_RECV` (5.19) [V]. The man page states it is "explicitly not intended as a method implementing security policy": the target can rewrite pointer arguments while blocked, so `CONTINUE` is unsafe unless another layer also enforces; memory read via `/proc/TID/mem` must be bracketed by `NOTIF_ID_VALID`; signals silently cancel notifications and `SA_RESTART` re-delivers them; only one listener per thread; a higher-precedence filter installed by the target can bypass it [V]. Safe pattern: never `CONTINUE` on pointer-bearing calls; the supervisor performs `openat`/`connect` itself and injects the fd with `ADDFD` [I]. Go's signal-based preemption makes `WAIT_KILLABLE_RECV` mandatory [K].

### 5. Landlock by ABI (verified against `include/uapi/linux/landlock.h` at each tag)

| ABI | Kernel | Adds |
|---|---|---|
| 1–3 | 5.13 / 5.19 / 6.2 [K] | FS rights; REFER; TRUNCATE |
| 4 | 6.7 [K] | TCP bind/connect by port |
| 5 | 6.10 [K] | `IOCTL_DEV` |
| 6 | 6.12 [V] | scopes: abstract UNIX sockets, signals |
| 7 | 6.15 [V] | audit logging + `RESTRICT_SELF_LOG_*` |
| 8 | 7.0 [V] | `RESTRICT_SELF_TSYNC` (all threads) |
| 9 | 7.1 [V] | `ACCESS_FS_RESOLVE_UNIX` (pathname UNIX sockets) |
| 10 | 7.2 [V] | UDP bind / connect-send; `ADD_RULE_QUIET` |
| 11 | 7.3 [V] | `RESTRICT_SELF_NO_NEW_PRIVS` |
| 12 | 7.4-rc2 [V] | capability and namespace permission rules |

Distro reality [I from kernel versions]: Ubuntu 24.04 (6.8) = ABI 4; Debian 13 and RHEL 10 (6.12) = 6; WSL2 6.18 = 7; Ubuntu 26.04 (7.0) = 8. Standing limits: allow-list only (cannot carve `~/.ssh` out of an allowed `$HOME`), no control of `stat/chmod/chown/chdir`, no hostname-level network rules, 16 stacked layers, inherited fds unaffected, before ABI 8 only the calling thread is restricted [V].

### 6. cgroup v2 BPF for per-session network and DNS

Hooks: `cgroup/connect4|6`, `sendmsg4|6`, `bind4|6`, `sock_create`, `cgroup_skb/egress`, `sockops`, and `lsm_cgroup` (6.0) [K]. systemd already wraps them: `IPAddressAllow/Deny=` (235), `BPFProgram=` (249), `SocketBindAllow/Deny=` (249), `RestrictNetworkInterfaces=` (250), `RestrictFileSystems=` (250, needs BPF LSM) [V]. Works with BPF LSM inactive, so it is the default network enforcement tier. DNS: rewrite port-53 connects in `connect4/sendmsg4` to a local resolver that records name-to-IP, then allow by IP map [K]; DoH/DoT/QUIC need the proxy tier.

### 7. AppArmor / SELinux profile generation (KubeArmor)

KubeArmor (Apache-2.0, v1.7.x) maps one policy to BPF LSM, AppArmor or SELinux and falls back to audit-only when none is usable; SELinux-only rows are "no blocking" [V]. AppArmor cannot enforce ICMP rules and symlinked binary paths do not match [V]. Its FAQ still says WSL2 has no enforcement (securityfs); likely stale after 6.18.54.1 [I]. AppArmor generation is the realistic Ubuntu fallback but is per-binary, not per-cgroup.

### 8. io_uring

ARMO's Curing rootkit did C2 and command execution purely via io_uring; Falco was blind, Tetragon needed non-default kprobe/LSM policies, Defender for Endpoint on Linux missed it; Falco said it was building an LSM-hook plugin [V]. Falco 0.44/0.45 release notes (2026) show no io_uring/LSM item; 0.44.0 dropped the legacy BPF probe, gRPC and **gVisor engine** [V]. Mitigations: hook LSM/VFS layers [K]; `kernel.io_uring_disabled` = 0/1/2 with `io_uring_group` [V]; seccomp-deny `io_uring_setup/enter/register` in launch sandboxes, as Codex and sandbox-runtime do [V].

### 9. Plaintext LLM traffic

AgentSight (MIT, v1.0.35) attaches uprobes to `SSL_read/SSL_write`; on Claude Code 2.1.39 symbol lookup failed and offsets had to be recovered by prologue byte-matching against the matching `bun-...-baseline-profile` build, valid for that build only; traffic was HTTP/1.1 + SSE and included bearer tokens [V]. Go binaries need `ecapture gotls --elfpath`; static OpenSSL needs explicit paths/offsets; rustls is not covered [V]/[K]. Tetragon 1.8 added uprobe **binary digest verification** — the right guard for per-build offsets [V]. sandbox-runtime offers the proxy alternative: `network.tlsTerminate` with an injected trust bundle, `filterRequest`, credential masking [V]. BeyondTrust's product also requires trusting a tenant root certificate for HTTPS inspection [V].

### 10. Attribution and lineage escapes

Anchors: cgroup id (survives double-fork, `setsid`, `nohup`, sudo) [K]; pidfd (`pidfd_open` 5.3, `PIDFD_THREAD` 6.9) for race-free handles [V]; audit `loginuid`/`sessionid` (identical for a human and the agent in the same terminal, so only useful for spotting *new* sessions) [K]; BPF task-local storage copied at fork [K].

| Escape | Why lineage breaks | How to follow [I] |
|---|---|---|
| double fork / setsid / nohup | re-parents to init | cgroup membership; task-storage tag copied on fork |
| `systemd-run`, user timers, D-Bus activation | systemd/dbus-broker spawns in a new unit | LSM hook on UNIX connect to the manager socket from a tagged task; tag the unit created next; watch unit-file writes |
| cron / at / shell rc / git hooks | deferred execution by another parent | tag files written by tagged tasks (inode map or xattr); propagate on later exec/open |
| tmux / screen server | pre-existing server forks the command | UNIX-socket peer edge; treat server children after a tagged client attach as tainted |
| Docker / Podman socket | daemon and shim create the process | broker or deny the socket by default (sandbox-runtime does); map container cgroup to the requesting peer |
| ssh to localhost | sshd child, new audit session | correlate loopback 4-tuple from tagged connect to sshd accept |
| `kubectl exec` | process appears on another node | Kubernetes audit log + CRI exec correlation; credential-level attribution |

Agent env markers and process names are forgeable hints, never proof [I].

### 11. Containers, Kubernetes, immutable distros, ARM64

- Rootless and nested: bubblewrap needs capability-bearing user namespaces; Ubuntu 24.04+ strips them by default; in unprivileged containers `/proc` cannot be mounted (`enableWeakerNestedSandbox`); a root caller needs `CAP_SETFCAP` [V].
- Kubernetes: privileged or explicit-capability DaemonSet with host PID and BTF; Tetragon 1.8 Helm "run[s] the agent unprivileged with explicit capabilities" and maps cgroup to pod sandbox [V]. Falco least-privilege set: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_PTRACE`; modern probe needs >= 5.8, ring buffer, BTF [V].
- gVisor/Kata/Firecracker agent sandboxes hide guest syscalls from a host sensor; Falco removed its gVisor engine in 0.44 [V]. Needs an in-guest sensor or runtime integration [I].
- Immutable hosts (Bottlerocket, Talos, COS, Fedora CoreOS): BPF LSM generally on; delivery only as container/DaemonSet or sysext; no kernel modules [V]/[I].
- ARM64: Tetragon needs >= 5.10 for full function; sandbox-runtime seccomp filters are prebuilt for x64 and arm64; Tetragon added a 64K ring-buffer placeholder for non-4K pages [V].

### 12. Overhead

| Tool | Number | Setup | Quality |
|---|---|---|---|
| Tetragon | 1.68% (2.46% with JSON export); TCP_CRR −5.88% | kernel 6.1 build, ~2.6K exec events/s | vendor, 2023-10, stale |
| Falco / Tracee / Tetragon | CPU ~100% of a core / >300% / >300% (up to 415%); memory ~145 / ~260 / ~320 KB as reported; max throughput 21.7 / 13.98 / 12.40 Gbps | all syscalls traced, kernel 5.15, OSBench, K8s 1.29 | peer-reviewed (Sensors, 2025-10); worst case; tool versions not given |
| AgentSight | 2.9% average (0.4–4.9%) | Claude Code tasks, kernel 6.14 | arXiv 2025-08 |
| ActPlane | 1.9–8.4% end to end | coding-agent benchmarks | arXiv 2026-06 |
| Kunai | none published; CI covers LTS 5.4–6.6 only | — | docs |

Blog figures (Falco 1–5%, Tracee 3–7%) had no methodology and are not used.

### 13. Rust eBPF with aya

aya is `MIT OR Apache-2.0`; `aya-ebpf` 0.3.0 (2026-10-29), workspace MSRV 1.98; LSM programs via `#[lsm(hook = "...")]` + `LsmContext`, deny by returning a negative errno, BTF from `Btf::from_sys_fs()`, types via `aya-tool generate` [V]. The aya book example carries no licence declaration, but the kernel requires one for LSM programs [V]. Kunai shows a single static musl binary embedding aya probes is viable on x86_64 and aarch64 [V]. Depth of Rust-side CO-RE relocation and `lsm_cgroup`/sleepable support was not verified.

### 14. Launch-time sandboxes vs system-wide sensors

| | bwrap + seccomp (Codex, sandbox-runtime) | Landlock (+ seccomp) | System sensor (BPF LSM / fanotify / cgroup BPF) |
|---|---|---|---|
| Privilege | none, but needs unprivileged userns | none, no userns | root install |
| Covers unregistered agents | no | no | yes |
| Hides files / deny-within-allow | yes (bind mounts) | no | yes |
| Network | netns removed + host proxy over UDS | ports only (TCP ABI 4, UDP ABI 10) | cgroup hooks, IP/port/DNS |
| Breaks | Chromium/Electron sandbox, rootless podman, Docker, Ubuntu AppArmor userns rule | little | nothing in the workload |
| Tamper resistance vs the agent | high while inside | high, irrevocable | highest |

Codex: bwrap default, bundled fallback, `--unshare-user/pid/net`, protected `.git`/`.codex`, WSL1 rejected [V]. sandbox-runtime v0.0.82 (2026-11-09, Apache-2.0): bwrap + socat + seccomp, nested user+PID+mount namespace, denies `unshare/clone(NEWUSER|NEWNS)/setns/mount/pivot_root`, `clone3` → ENOSYS, cannot filter UNIX sockets by path [V]. nono (Apache-2.0, v0.81.0, Rust) adds credential-proxy injection, signed audit and rollback [V].

## Matrix

| Capability | Preferred | Fallbacks (in order) | Kernel / distro needs | Main risk | Effort |
|---|---|---|---|---|---|
| Discover agents | exec/exit tracepoints + BTF | proc scan + netlink proc connector | >= 5.8, BTF | interpreters hide script identity | M |
| Session attribution | cgroup-v2 scope per session + task storage | pidfd tree; audit session id | cgroup v2, systemd | IPC lineage escapes | L |
| Block file open/exec | BPF LSM `file_open`, `bprm_check_security` | fanotify perm events; AppArmor profile; Landlock at launch | `bpf` in LSM list | Ubuntu default off | L |
| Block write/unlink/rename | BPF LSM `inode_*`, `path_*` | Landlock / bwrap at launch; AppArmor | as above | fanotify cannot | L |
| Block network | cgroup `connect4/6`, `sendmsg`, skb egress | BPF LSM `socket_connect`; netns + proxy; Landlock ports | cgroup v2 | DoH/QUIC, loopback daemons | M |
| Hold for approval | fanotify perm; seccomp-unotify + ADDFD | cgroup freeze then decide | root / launch control | fail-open on listener death | M |
| LLM content | in-agent hooks, gateway | TLS-terminating proxy; uprobe offset packs | none / CA trust / per-build | pinned certs, token exposure | M–L |
| Tamper resistance | pinned LSM links, signed loader | systemd hardening | 6.18 for signing | root agent | M |
| io_uring | LSM-layer hooks | sysctl; seccomp deny | 6.6 for sysctl | breaks apps using it | S |
| Kubernetes | DaemonSet + cgroup/CRI enrichment | sidecar; admission-applied seccomp/AppArmor | BTF on nodes | gVisor/Kata blind | L |

## Weak points, gaps and risks

- Ubuntu, the largest developer and cloud population, needs a reboot to get BPF LSM; many cloud images cannot edit GRUB.
- CVE-2026-64192 (kernel panic with `CONFIG_BPF_LSM=y` but LSM inactive, reported for WSL2) — secondary sources only; verify before shipping a probe that loads LSM programs speculatively.
- BPF path matching is weak; string policies in-kernel will hit verifier limits. Symlink and hard-link aliasing affects every path-based tier.
- fanotify is fail-open on listener exit and can deadlock the host if the daemon touches a marked filesystem while deciding.
- seccomp-unotify is documented as unsafe for policy when used with `CONTINUE`.
- Unprivileged sandboxes cover only what the agent chooses to wrap.
- Uprobe offsets are per-build, and captured plaintext contains credentials.
- Overhead data is thin, old or worst-case. We need our own benchmark.
- gVisor/microVM agent sandboxes defeat host sensors.

## Implications for our design

**Phase 0 — capability probe.** One binary that reports: BTF, `bpf` in `/sys/kernel/security/lsm`, lockdown mode, cgroup v2, `CONFIG_BPF_KPROBE_OVERRIDE`, fanotify permissions, Landlock ABI, unprivileged userns state (incl. the AppArmor sysctl), `io_uring_disabled`, arch and page size. Every later tier keys off it.

**Phase 1 — observe and attribute (no enforcement).** aya-based sensor: exec/fork/exit, LSM-layer file/socket hooks in monitor mode where available, raw tracepoints otherwise. One cgroup-v2 scope per agent session, created by the launcher or by in-agent hooks handing the sensor a pidfd. IPC-edge tracking for the escape table above.

**Phase 2 — no-reboot enforcement.** cgroup BPF network policy + DNS interposition per session scope; fanotify permission events for read/exec deny and for "ask"; `cgroup.kill`/freeze as last resort.

**Phase 3 — BPF LSM.** Synchronous deny scoped by cgroup id; pinned links so enforcement outlives the daemon; guided enablement (`lsm=` via grubby/GRUB, WSL kernel update).

**Phase 4 — launch-time sandbox.** Ship our own Landlock + seccomp launcher (no userns dependency) and detect/compose with Codex and sandbox-runtime rather than replace them. Use ABI-gated features; treat ABI >= 9 as the point where Landlock alone is sufficient.

**Fallback ladder when BPF LSM is unavailable:** (1) kprobe/fmod_ret override on `security_*` if error injection is built; (2) fanotify + cgroup BPF; (3) generated AppArmor profile (Ubuntu) or SELinux module; (4) launch-time Landlock/seccomp/bwrap; (5) seccomp-unotify broker for launched trees; (6) detect + kill/freeze; (7) observe only, with the gap stated in the UI.

**Licensing layout:** `bpf/` crate dual `GPL-2.0-only OR BSD-2-Clause`, licence string `Dual BSD/GPL` in the object, everything else Apache-2.0. Do not copy from Kunai (GPL-3.0) or KubeArmor's enforcer (GPL-2.0 only).

**Avoid:** syscall-entry enforcement, kill-only "blocking", in-kernel string globs, depending on TLS uprobes, assuming userns works.

## Ideas worth stealing and whitespace

- Tetragon: pinned LSM enforcement after agent exit; uprobe binary-digest gating; `followChildren`; cgroup-to-pod-sandbox map.
- sandbox-runtime: model-facing deny reasons in the violation line; credential masking with proxy re-injection; per-command network lists.
- BeyondTrust: replaying recorded activity against a draft policy before enabling it.
- KubeArmor: one policy compiled to whichever enforcer the node has, with honest "audit only" status.
- Whitespace: (a) any open, system-wide agent sensor for Linux; (b) lineage-escape tracking across IPC; (c) hybrid verdicts — BPF LSM for static deny, fanotify/unotify for human approval; (d) signed, community-maintained uprobe offset packs per agent build; (e) Landlock/AppArmor policy generated from observed sessions; (f) in-guest sensor for gVisor/microVM agent sandboxes.

## Could not verify / open questions

- Web search budget exhausted mid-run: no search-based confirmation of Falco's LSM/io_uring plugin status, CVE-2026-64192 details, Cursor's Linux sandbox internals, or Fedora/RHEL 10/Amazon Linux/Flatcar/Azure Linux LSM lists.
- Ubuntu 26.04 state rests on the Launchpad bug (no fix recorded) plus a secondary report; not checked on a live image.
- Which filesystems accept fanotify pre-content events; whether a permission-event watchdog exists upstream.
- aya support for `lsm_cgroup`, sleepable LSM and Rust-side CO-RE.
- Whether `security.bpf.*` xattr kfuncs are usable for file tainting on target kernels.
- nono's exact Linux mechanism (README does not name it).
- Kunai: last tagged release v0.6.2 (2025-11-12) although the repo is active.
- Microsoft Agent 365 overview page describes registry, Entra, Purview and Defender integration; it says nothing about a Linux endpoint sensor.

## Sources

- https://docs.kernel.org/userspace-api/landlock.html — Landlock userspace API (Oct 2026, 7.4-rc2)
- https://github.com/torvalds/linux — `include/uapi/linux/landlock.h` at v6.12…v7.4-rc2 (read via API, 2026-11-09)
- https://docs.kernel.org/bpf/bpf_licensing.html — BPF licensing
- https://docs.kernel.org/bpf/prog_lsm.html — LSM BPF programs
- https://docs.kernel.org/admin-guide/sysctl/kernel.html — `io_uring_disabled`, `unprivileged_bpf_disabled`
- https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2054810 — Ubuntu: add bpf to CONFIG_LSM (open; last comment 2026-03-21)
- https://salsa.debian.org/kernel-team/linux/-/raw/debian/latest/debian/config/config — Debian kernel config
- https://gitlab.com/redhat/centos-stream/src/kernel/centos-stream-9/-/raw/main/redhat/configs/common/generic/CONFIG_LSM — Stream 9 LSM list
- https://github.com/microsoft/WSL2-Linux-Kernel/releases — 6.18.54.1 (2026-10-06), 6.18.58.1 (2026-10-27)
- https://github.com/microsoft/WSL/issues/41612 — bpf missing from WSL CONFIG_LSM (2026-09-15, closed 2026-10-09)
- https://tetragon.io/docs/concepts/enforcement/ ; https://tetragon.io/docs/concepts/tracing-policy/selectors/ ; https://tetragon.io/docs/concepts/tracing-policy/hooks/ ; https://tetragon.io/docs/installation/faq/
- https://github.com/cilium/tetragon/releases/tag/v1.8.0 — 2026-10-30
- https://isovalent.com/blog/post/tetragon-release-10/ — overhead figures (2023-10-31)
- https://pmc.ncbi.nlm.nih.gov/articles/PMC12608121/ — Aquila, Sensors 25(21):6511 (2025-10-22)
- https://falco.org/docs/concepts/event-sources/kernel/ ; https://github.com/falcosecurity/falco/releases (0.44.0 2026-05-26, 0.45.2 2026-10-29)
- https://aquasecurity.github.io/tracee/dev/docs/install/lsm-support/
- https://docs.kubearmor.io/kubearmor/quick-links/support_matrix.md ; https://github.com/kubearmor/KubeArmor/blob/main/getting-started/FAQ.md
- https://man7.org/linux/man-pages/man7/fanotify.7.html ; https://man7.org/linux/man-pages/man2/fanotify_mark.2.html ; https://lwn.net/Articles/1015987 (2025-03-30)
- https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html ; https://man7.org/linux/man-pages/man2/seccomp.2.html ; https://man7.org/linux/man-pages/man2/pidfd_open.2.html
- https://lwn.net/Articles/1042625/ — BPF signing dispute (2025-10-27)
- https://docs.ebpf.io/linux/concepts/token/ — BPF token (6.9)
- https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html ; https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- https://github.com/anthropics/sandbox-runtime — README, v0.0.82 (2026-11-09)
- https://code.claude.com/docs/en/sandboxing — Claude Code sandbox scope and limits
- https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md
- https://github.com/nolabs-ai/nono — v0.81.0 (2026-10-29)
- https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/ — 2025-04-24
- https://dev.to/yunwei37/reverse-engineering-claude-codes-ssl-traffic-with-ebpf-5bod ; https://arxiv.org/abs/2508.02736 (AgentSight) ; https://arxiv.org/abs/2606.25189 (ActPlane, 2026-06) ; https://arxiv.org/abs/2609.13930 (BPFence, CCS '26)
- https://github.com/gojue/ecapture — v2.10.0 (2026-11-07)
- https://aya-rs.dev/book/programs/lsm/ ; https://github.com/aya-rs/aya ; https://github.com/kunai-project/kunai ; https://why.kunai.rocks/docs/compatibility
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security ; https://learn.microsoft.com/en-us/microsoft-agent-365/overview (updated 2026-10-23)

## Independent verification

_Checked 2026-11-09 by a second reviewer against kernel and project source (read through `gh` and the Launchpad API), not the pages cited above where an alternative existed. Web search was unavailable (shared budget exhausted), so every check is a direct read of source, config or a primary doc page. Two claims need correcting (1 and 9); the rest held._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Ubuntu 22.04 / 24.04 / 26.04 build `CONFIG_BPF_LSM=y` without `bpf` in `CONFIG_LSM`; LP #2054810 open, no fix recorded | **Corrected** | True for 22.04 (5.15) and 24.04 GA (6.8), and for 25.10 (6.17): `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"` on their `master-next` branches; #2054810 is still Triaged for Jammy and Noble. **Outdated for 26.04**: a separate bug, LP #2166235 "append bpf to CONFIG_LSM" (filed 2026-09-03), landed in `Ubuntu-7.0.0-39.39`. The first build carrying it in `resolute-updates` was 7.0.0-42.42 (2026-10-28; security pocket 2026-11-02); 7.0.0-43.43 is current in updates. The 7.0.0-38.38 tag does not have it. The Resolute bug task still reads "Fix Committed", and cloud flavours plus the 24.04 HWE 7.0 kernels (azure, gcp, oracle, gke) were in `-proposed` verification on 2026-10-30/31, so those may lag. An updated 26.04 host needs no `lsm=` parameter. | Launchpad API `bugs/2054810`, `bugs/2166235`; `git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute` `debian.master/config/annotations` at tags 38.38 to 44.44; archive `getPublishedSources` |
| 2 | WSL2 6.18.54.1 (2026-10-06) is the first with BPF LSM on by default; no `FUNCTION_ERROR_INJECTION`, no `FPROBE`, so no kprobe return override | Confirmed | `Microsoft/config-wsl` at 6.18.54.1 ends `...,tomoyo,bpf`; 6.18.40.1, 6.18.26.3, 6.18.20.1, 6.6.114.1, 6.6.87.2 and 6.6.36.3 do not; 5.15 and 6.1 listed `bpf` but had `BPF_LSM` unset. Nuance: the arm64 config has `CONFIG_FUNCTION_ERROR_INJECTION=y` but `CONFIG_BPF_KPROBE_OVERRIDE` unset, so override is unavailable on both arches for different reasons. `FPROBE` is unset on both. | `microsoft/WSL2-Linux-Kernel` release notes and `Microsoft/config-wsl{,-arm64}` at each tag; `kernel/trace/Kconfig` |
| 3 | Tetragon: SIGKILL does not always stop the operation; pair with Override, which needs `CONFIG_BPF_KPROBE_OVERRIDE` and error-injectable functions | Confirmed | Wording matches the docs source in the repo; `security_*` override from 5.7 also stated there. | `cilium/tetragon` `docs/content/en/docs/concepts/enforcement/_index.md`, `.../tracing-policy/selectors.md` |
| 4 | LSM BPF must be GPL-compatible; separate packaging with non-GPL userspace is fine; Tetragon BPF is `GPL-2.0-only OR BSD-2-Clause` | Confirmed | Kernel doc text read at v7.4-rc2. Tetragon `bpf/COPYING` and SPDX headers confirm dual licence for `bpf/` only; repo licence Apache-2.0. | `torvalds/linux` `Documentation/bpf/bpf_licensing.rst`; `cilium/tetragon` `bpf/COPYING` |
| 5 | Landlock ABI 6=6.12, 7=6.15, 8=7.0, 9=7.1, 10=7.2, 11=7.3, 12=7.4-rc | Confirmed | `landlock_abi_version` in `security/landlock/syscalls.c` reads 6, 7, 8, 9, 10, 11, 12 at v6.12, v6.15, v7.0, v7.1, v7.2, v7.3, v7.4-rc1/rc2. Feature labels match `landlock.rst` at v7.4-rc2. ABI 12 is not in a released kernel yet. | `torvalds/linux` at each tag |
| 6 | Codex: bubblewrap + seccomp by default; legacy Landlock rejected (app-server Unix sockets); seccomp blocks io_uring | Confirmed | Rejection applies to filesystem-restricted policies; the Landlock code is retained. `seccomp.rs` denies `io_uring_setup/enter/register` in all filter modes. | `openai/codex` `codex-rs/linux-sandbox/README.md`, `src/seccomp.rs` |
| 7 | Claude Code sandbox covers Bash-type commands only; file/web tools, hooks, local MCP and LSP servers run outside; `~/.ssh` readable by default | Confirmed | Docs say the limits apply to "Bash, PowerShell, and Monitor commands and the processes they start". Also: the sandbox is off by default, and the seccomp filter is described as optional (adds Unix-socket blocking). | https://code.claude.com/docs/en/sandboxing |
| 8 | Claude Code is a stripped Bun binary with static BoringSSL; SSL uprobe offsets must be recovered per build by byte-pattern matching | Confirmed, with caveats | Single origin (the AgentSight author), observed on 2.1.39 / Bun 1.3.9-canary only; not reproduced here. "Stripped" means SSL symbols are absent; 556 exported `BUN_1.2` functions remain. AgentSight's `sslsniff` now auto-detects the functions by byte pattern at attach time, so the work is automated but still breaks when Bun, BoringSSL or compiler output changes. | `eunomia-bpf/agentsight` `docs/experiment/claude-code-analysis.md`, README FAQ |
| 9 | fanotify: permission events for open/read/exec; `FAN_PRE_ACCESS` and `FAN_MARK_MNTNS` since 6.14, `FAN_DENY_ERRNO` since 6.13; none for unlink/rename/create; pending events allowed on close | **Corrected** | Two version numbers are one release early (the man pages carry the same error). In the UAPI header, `FAN_DENY_ERRNO` is absent at v6.13 and present at **v6.14**; `FAN_MARK_MNTNS` is absent at v6.14 and present at **v6.15**. `FAN_PRE_ACCESS` = 6.14 is right. Everything else holds: the only permission-class events at v7.4-rc2 are `OPEN_PERM`, `ACCESS_PERM`, `OPEN_EXEC_PERM`, `PRE_ACCESS`; `fanotify_release()` replies `FAN_ALLOW` to every queued permission event. | `torvalds/linux` `include/uapi/linux/fanotify.h` at v6.12 to v6.15 and v7.4-rc2; `fs/notify/fanotify/fanotify_user.c` |
| 10 | BeyondTrust AI Agent Security: Windows and macOS endpoints only | Confirmed | Page states "AI Agent Security supports Windows and macOS endpoints only"; Windows 11 / Server 2022+ on x64 (no Arm), macOS 14, 15, 26. Linux is not mentioned. Only the vendor page was available to check. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |

### Further statements checked in the brief

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Fallback ladder (1): "kprobe/fmod_ret override on `security_*` if error injection is built" | Corrected | Only kprobe override needs error injection. `check_attach_modify_return()` accepts any `security_`-prefixed function in both the `CONFIG_FUNCTION_ERROR_INJECTION` and the non-error-injection branch, so `fmod_ret` on `security_*` needs a BPF trampoline (x86-64; arm64 with `DYNAMIC_FTRACE_WITH_DIRECT_CALLS`), not error injection. Ubuntu 24.04 and 26.04 also build `CONFIG_BPF_KPROBE_OVERRIDE=y` and `CONFIG_FUNCTION_ERROR_INJECTION=y`, so a synchronous deny on `security_*` is available on Ubuntu without a reboot. This weakens the "Ubuntu needs a reboot" risk. Read from source; not run on a live kernel. | `torvalds/linux` `kernel/bpf/verifier.c` at v7.3; Ubuntu `annotations` (noble, resolute) |
| Open question: "whether a permission-event watchdog exists upstream" | Answered | It exists since v6.18 (absent at v6.17): sysctl `fs.fanotify.watchdog_timeout`, default 0 (off). It only logs "PID ... failed to respond to fanotify queue"; it does not auto-reply, so a stalled listener still blocks callers. | `torvalds/linux` `fs/notify/fanotify/fanotify_user.c` at v6.17, v6.18 |
| Tetragon 1.8.0 (2026-10-30) items, fentry limits, Falco 0.44.0 removals, sandbox-runtime v0.0.82 seccomp behaviour, Debian LSM list | Confirmed | Release notes list the glob library, stateful policies, uprobe digest verification and "Keep LSM enforcement active after agent exit"; hooks doc says fentry supports neither `Override` nor `Signal`. Falco 0.44.0 dropped gRPC, gVisor and the legacy BPF probe. sandbox-runtime README confirms `clone3` to `ENOSYS`, namespace-call denial and io_uring blocking. Debian `CONFIG_LSM` ends `...,tomoyo,bpf,ipe`. | `cilium/tetragon` v1.8.0 notes and `hooks.md`; `falcosecurity/falco` 0.44.0 notes; `anthropics/sandbox-runtime` README; salsa `debian/config/config` |

**What changes for the architecture:** treat Ubuntu 26.04 (updated) as BPF-LSM-active and keep the `lsm=` guidance for 22.04/24.04 only; probe `/sys/kernel/security/lsm` at runtime instead of keying on distro version. Add `fmod_ret`/kprobe-override on `security_*` as a real no-reboot deny tier for Ubuntu 22.04/24.04. Gate `FAN_DENY_ERRNO` on 6.14 and `FAN_MARK_MNTNS` on 6.15.
