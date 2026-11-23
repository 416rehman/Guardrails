# ADR-0045: Every OS call needing unsafe and every raw OS binding crate lives in a layer 3 OS adapter crate

- Status: proposed
- Date: 2026-11-23
- Decided by: chief architect
- Spine: D-20, D-63, P5, P17; R-50
- Requires: #1749 (`grdr-os-service` and `grdr-peer-os` scaffold, `architecture.toml`, `.claude/owners.toml`, `security/trust-core.paths`), #1750 (`windows-sys` and `libc` admission), #419 (`rustix` admission for Linux and macOS kqueue), #1751 (`ARCH-027` and `ARCH-004` privileged-program coverage check), #1757 (RFC 0003 for `grdr-wire`'s peer-reader trait), #1671 (`docs/design/03` sections 2, 10 and 11 update)
- RFC: not required: preserves `docs/design/03` section 10 without exception, adds only internal layer 3 OS adapter crates with no same-layer edge, and routes the one public layer 2 trait through #1757 (RFC 0003)
- Work items: #1743, #1671; follow-ups #1749, #1750, #1751, #1752, #1757; endpoint items #1724, #1725, #1745, #683, #684, #680, #689, #427, #430; security and adapter items #375, #1549, #555, #516, #374, #1606

## Context

[`docs/design/03-system-architecture-and-modularity.md`](../design/03-system-architecture-and-modularity.md) section 10 forbids `unsafe_code` across workspace crates except in layer 3 OS adapter crates (the optional Windows driver included) and the FFI crates `grdr-ffi` and `grdr-fastpath-ffi`. [`Cargo.toml`](../../Cargo.toml) enforces that rule through `[workspace.lints.rust] unsafe_code = "forbid"`, inherited by `grdr-daemon`, `grdr-hook`, `grdr`, `grdr-wire` and every non-adapter crate via `[lints] workspace = true`.

Endpoint slice-0 items require raw OS and FFI calls that the standard library does not expose safely:

- Service-manager integration and socket activation for `grdr-daemon` on Windows (`StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`, `#1724`), Linux (`LISTEN_FDS` descriptor adoption via `OwnedFd::from_raw_fd`, `sd_notify`, signals, `#1745`) and macOS (`launch_activate_socket`, signals, `#1725`, `#683`).
- Named-pipe listener creation with explicit DACLs (`CreateNamedPipeW`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, `#684`) and child-process handle supervision and exit watching (`pidfd`, kqueue `EVFILT_PROC`, Windows job completion ports and `TerminateProcess`, `#680`, `#427`).
- Bidirectional IPC peer authentication in `grdr-wire` (`peer_auth`) and `grdr-hook` on Linux (`SO_PEERCRED`, `SO_PEERPIDFD`, `pidfd_open`, `#375`), macOS (`LOCAL_PEERTOKEN` and `libbsm` audit-token readers, `#1549`, `#516`) and Windows (`GetNamedPipeClientProcessId`, `GetNamedPipeServerProcessId`, `OpenProcess`, `OpenProcessToken`, `GetTokenInformation`, `QueryFullProcessImageNameW`, `#555`, `#516`), raised in `#1671`.
- Engine sandboxing on Windows (`AppContainer`, job objects, `#689`).
- A requested systemd D-Bus client for Linux per-session transient cgroup-v2 scopes ([`docs/design/10-sensor-linux-containers-ci.md`](../design/10-sensor-linux-containers-ci.md) section 8, `#419`, `#430`).

`docs/design/03` section 2 (`ARCH-002`) forbids dependency edges between layer 3 crates, `R-50` assigns IPC peer authentication to the `security` squad while endpoint hosting belongs to `endpoint`, and `D-63` ([`docs/design/02-threat-model.md`](../design/02-threat-model.md) Interfaces) keeps the privileged core and IPC peer-authentication OS adapters inside [`security/trust-core.paths`](../../security/trust-core.paths). Spine section 5 splits a unit into a crate when it gains a second consumer (`grdr-os-service` serves `grdr-daemon` and user-session services; `grdr-peer-os` serves `grdr-daemon`, `grdr-hook` and `grdr`).

## Decision

### 1. Layer 3 OS adapter crates and `unsafe_code` scope

`docs/design/03` section 10 stands with no exception. Every OS call needing `unsafe` and every raw OS binding crate lives in a layer 3 OS adapter crate carrying the OS-adapter lints table (`unsafe_code = "deny"`, a reasoned `#[allow(unsafe_code)]` on each unsafe item, a `// SAFETY:` comment on every `unsafe` block, and `#![deny(clippy::arithmetic_side_effects)]` where `privilege = "privileged"`). Layer 4 programs (`grdr-daemon`, `grdr-hook`, `grdr`) and layer 2 crates (`grdr-wire`) keep `[lints] workspace = true` (`unsafe_code = "forbid"`).

Two internal (`surface = "internal"`, `renders = "none"`) layer 3 crates join `grdr-sandbox-engine`:

| Crate | Layer | Squad | `privilege` | Trust core (`security/trust-core.paths`) | Holds |
|---|---|---|---|---|---|
| `grdr-os-service` | 3 | `endpoint` | `privileged` | Yes, privileged core (beside `grdr-sandbox-engine`) | Service-manager seam (Windows SCM dispatcher, control handler and `SetServiceStatus`; Linux `LISTEN_FDS` adoption and `sd_notify`; macOS `launch_activate_socket`); shared Unix signals; named-pipe instances with explicit DACLs, first-instance and remote-client rejection; child process handles and exit watching |
| `grdr-peer-os` | 3 | `security` (`R-50`) | `privileged` | Yes, OS adapters of IPC peer authentication | `SO_PEERCRED`, `SO_PEERPIDFD`, `pidfd_open`; `LOCAL_PEERTOKEN` and audit-token readers; `GetNamedPipeClientProcessId`, `GetNamedPipeServerProcessId`, `OpenProcess`, `OpenProcessToken`, `GetTokenInformation`, `QueryFullProcessImageNameW`; peer executable path, start time and parent chain |
| `grdr-sandbox-engine` (exists) | 3 | `endpoint` | `privileged` | Yes, privileged core | Unchanged: engine launch and sandbox confinement on Linux, macOS and Windows |

`grdr-os-clock` (layer 3, `privilege = "none"`, squad `core`, outside `security/trust-core.paths`) remains separate for system clock reads under the one-crate-per-seam rule (`#1927`, `#1933`).

The layer 3 adapter crates have no dependency edge to each other (`ARCH-002`). They exchange standard-library descriptor and handle types (`OwnedFd`, `BorrowedFd`, `OwnedHandle`, `BorrowedHandle`) and async-runtime stream types, joined in layer 4 programs. `grdr-peer-os` depends on `grdr-wire` (layer 3 to layer 2) to implement `grdr-wire`'s peer-reader trait and depends on no other workspace crate.

### 2. Placement per call group (R1)

- **Windows service entry (`#1724`):** SCM dispatcher, control handler, `SetServiceStatus` and User-profile session-end sources live in `crates/grdr-os-service/src/windows/service*` over `windows-sys`. `ServiceHost` implementations and status/control state mappings stay in `programs/grdr-daemon/src/platform/windows/service*`.
- **Linux service entry (`#1745`):** `LISTEN_FDS` descriptor adoption (`OwnedFd::from_raw_fd` and socket checks over `rustix`) lives in `crates/grdr-os-service/src/linux/activation.rs`; `sd_notify` writes datagrams over std's `UnixDatagram` in `crates/grdr-os-service/src/linux/notify.rs`; shared Unix signal handling lives in `crates/grdr-os-service/src/unix/signal.rs`. Directory ownership checks (`#148`), configuration name matching and the `Systemd` `ServiceHost` stay in `programs/grdr-daemon/src/platform/linux/service*`.
- **macOS service entry (`#1725`, `#683`):** `launch_activate_socket` is declared in `crates/grdr-os-service/src/macos/activation.rs` inside the crate's own `extern "C"` block (no Rust binding crate exposes it), freeing the returned array with `libc::free`; signal handling reuses `crates/grdr-os-service/src/unix/signal.rs`. Foreground entry, directory checks and the launchd `ServiceHost` stay in `programs/grdr-daemon/src/platform/macos/`.
- **Endpoint listeners (`#683`, `#684`):** `grdr-os-service` adopts (`launch_activate_socket`, `LISTEN_FDS`) or creates (`CreateNamedPipeW` in `crates/grdr-os-service/src/windows/pipe*`) listeners and returns std `UnixListener` or runtime stream types; `grdr-wire` frames on them (`#374`, `#1606`). Endpoint wiring, profile DACL choice and instance pool management stay in `grdr-daemon`.
- **Child supervision (`#680`, `#427`):** `socketpair` and pidfd helpers (Linux), kqueue `EVFILT_PROC` watch, reap and kill (macOS), and process-handle wait, `TerminateProcess`, job completion-port notifications and SCM service-pid query (Windows) live in `crates/grdr-os-service/src/{linux,macos,windows}/child*`. `EngineSupervision`, `ChildHandle` mapping and deadline logic stay in `grdr-daemon`.
- **Engine sandbox (`#689`, `#421`, `#688`):** Unchanged in `crates/grdr-sandbox-engine`. `#689` keeps its existing write set and uses `windows-sys` admitted on `crates/grdr-sandbox-engine/Cargo.toml` by `#1750`.
- **IPC peer authentication (`#375`, `#1549`, `#555`, `#516`):** Fact readers in both directions live in `crates/grdr-peer-os/src/{linux,macos,windows}/**` (`rustix` on Linux; `libc` for `LOCAL_PEERTOKEN` and crate-local `extern "C"` blocks for `libbsm` audit-token calls on macOS; `windows-sys` on Windows). Platform-neutral verification (`peer_auth/model*`, `Refusal`, `PeerVerifier`, `EndpointVerifier`) stays in `crates/grdr-wire/src/peer_auth/**` with no `unsafe` and reads facts through a reader trait introduced by RFC 0003 (`#1757`). `grdr-hook` (`#516`) stays `unsafe`-free and calls `grdr-peer-os` through that seam.

### 3. Raw OS dependencies and licences (R1)

No service-manager wrapper crate (`windows-service`, `sd-notify`, `listenfd`, `libsystemd`) is admitted. OS adapter crates link raw bindings only:

- `#1750` admits `windows-sys` (Windows-only target dependency on `grdr-os-service`, `grdr-peer-os` and `grdr-sandbox-engine`, restricted to needed API features) and `libc` (target dependency on the same crates for calls `rustix` lacks, such as `LOCAL_PEERTOKEN` and `free`). Both are dual-licensed `MIT OR Apache-2.0`, in the `permissive` class of [`supply-chain/licences.toml`](../../supply-chain/licences.toml) and allowed in [`deny.toml`](../../deny.toml).
- `#419` decides `rustix` (Linux and macOS kqueue/process calls) and the Linux seccomp builder on OS adapter crates only.
- Unbound C entry points (`launch_activate_socket`, `libbsm` audit-token readers) are declared directly in the owning adapter crate's `extern "C"` block with `// SAFETY:` comments rather than adding extra wrapper crates.

### 4. No D-Bus client in `grdr-daemon` (R3)

A D-Bus client decodes messages sent by other bus peers, so it is a content parser under [ADR-0010](ADR-0010-no-content-parser-in-a-privileged-closure.md) (`ARCH-004`) and remains excluded from `grdr-daemon` and every other `privilege = "privileged"` program. The transient cgroup-v2 scope request ([`docs/design/10-sensor-linux-containers-ci.md`](../design/10-sensor-linux-containers-ci.md) section 8, `#430`) moves to an unprivileged program running as the user on the user's bus (`grdr-run` is the first candidate, passing the root process by pidfd; `#419` and `docs/design/10` section 8 settle placement before a D-Bus crate is chosen). `grdr-daemon` keeps only the `Delegated` cgroupfs path (`mkdirat` through `grdr-os-service`) and scope state tracking. By contrast, `sd_notify` only writes datagrams over std's `UnixDatagram` and `LISTEN_FDS` reads integers set by the service manager, so neither is a content parser.

### 5. Follow-up work items and write-set disposition (R2)

Filed follow-ups and their dependency links:

- `#1749`: scaffold `crates/grdr-os-service/**` and `crates/grdr-peer-os/**` with empty OS module roots, add their layer 3 rows to [`architecture.toml`](../../architecture.toml), add squad routes (`endpoint` and `security`) to `.claude/owners.toml`, add both to `security/trust-core.paths`, add `grdr-wire` as a path dependency of `grdr-peer-os`, and note the three OS adapter crates in `programs/grdr-daemon/AGENTS.md`. Blocked by `#2` (closed), `#1550` (closed) and `#1580`; blocks `#1750`, `#1724`, `#1725`, `#1745`, `#683`, `#684`, `#680`, `#375`, `#1549`, `#555` and `#427`.
- `#1750`: admit `windows-sys` and `libc` on `grdr-os-service`, `grdr-peer-os` and `grdr-sandbox-engine`. Blocked by `#1749` and `#6`; blocks `#1724`, `#1725`, `#683`, `#684`, `#680`, `#1549`, `#555` and `#689` (as well as `#1927` and `#1933`). `#1745` (Linux) takes its raw-syscall dependency from `#419`, which already blocks `#1745`, `#680`, `#375`, `#427`, `#421` and `#430`.
- `#1751`: implement `ARCH-027` (`os-adapter-only`) and `ARCH-004`'s privileged-program coverage check in `grdr-archlint`. Blocked by `#1580`.
- `#1757`: RFC 0003 for `grdr-wire`'s slice-0 public surface including the peer-reader trait. Blocked by `#1743` and `#1671`; blocks `#374`, `#375`, `#1549` and `#555`.
- `#1752`: trust-core coverage ADR (ruling on `#1580`) and `docs/design/02` Interfaces list update. Blocked by `#1671`.
- `#1671`: update `docs/design/03` sections 2 (two crate rows and `ARCH-027`), 10 (OS adapter crates by name) and 11 (owners). Blocks `#374`, `#1549`, `#555`, `#1752` and `#1757`.

Write-set disposition for affected issues:

- `#1724`, `#1725`, `#1745`, `#683`, `#684`, `#680`: re-planned so raw OS calls move to `crates/grdr-os-service/**` while `grdr-daemon` keeps `ServiceHost`, endpoint wiring, `ChildHandle` and state types.
- `#689`: write set unchanged (`crates/grdr-sandbox-engine/src/windows*` and `tests/windows_*.rs`), now blocked by `#1750` for `windows-sys`.
- `#375`, `#1549`, `#555`: re-planned so fact readers move to `crates/grdr-peer-os/**` while decision logic stays in `crates/grdr-wire/src/peer_auth/**`.
- `#516`: calls `grdr-peer-os` through `grdr-wire`'s verifier/reader seam and keeps `programs/grdr-hook/**` free of `unsafe`.
- `#1606`: unchanged in `grdr-wire`; pipe instance creation stays in `#684` (`grdr-os-service`).
- `#427`: to be re-planned onto `crates/grdr-os-service/src/linux/child*` for pidfd and `socketpair` calls before readying (already blocked by `#1749` and `#419`).
- `#430`: to be re-planned once `docs/design/10` section 8 and `#419` move the D-Bus transient-scope request out of `grdr-daemon`.

## Enforced by

- `[workspace.lints.rust] unsafe_code = "forbid"` in `Cargo.toml`, inherited via `[lints] workspace = true` by `programs/grdr-daemon/Cargo.toml`, `programs/grdr-hook/Cargo.toml`, `programs/grdr/Cargo.toml` and `crates/grdr-wire/Cargo.toml`, verified by `cargo clippy --workspace --locked --all-targets -- -D warnings`. OS adapter crates run with `unsafe_code = "deny"` and `-D clippy::undocumented_unsafe_blocks`.
- `ARCH-027` (`os-adapter-only`, `#1751`) in `grdr-archlint`: fails any workspace crate whose `[lints]` is not `workspace = true` or that depends directly on `windows-sys`, `windows`, `libc`, `rustix` or `nix` unless `architecture.toml` lists it as an OS adapter or FFI crate.
- `ARCH-002` (`#1580`): fails any dependency edge between layer 3 crates.
- `ARCH-004` (`#1580`, `#1751`, `#1752`): fails any content parser (including any D-Bus decoder) in the dependency closure of `grdr-daemon` or any `privilege = "privileged"` program, and fails any `privilege = "privileged"` layer 4 program outside `security/trust-core.paths`.
- `cargo deny check` against `deny.toml` and `supply-chain/licences.toml`, plus `cargo vet` (`#1750`, `#419`, `#6`).
- `security/trust-core.paths` coverage for `crates/grdr-os-service/**` and `crates/grdr-peer-os/**` (`#1749`), holding both crates on the two-model `eval-review` and `eval-security` lane ([ADR-0043](ADR-0043-lean-token-optimised-agent-team.md), `D-63`).
- Until `#1749`, `#1750`, `#1751` and `#1671` land, the split holds by evaluator review against `.claude/risk-tiers.toml` and `docs/design/03` section 10.

## Consequences

- `docs/design/03` section 10 requires no exception; `grdr-daemon`, `grdr-hook`, `grdr` and `grdr-wire` keep `unsafe_code` forbidden and stay free of raw OS binding crates.
- Endpoint and peer-authentication OS `unsafe` is confined to three layer 3 trust-core crates split along squad boundaries (`endpoint` for `grdr-os-service` and `grdr-sandbox-engine`; `security` for `grdr-peer-os`).
- `grdr-wire` remains a portable, `unsafe`-free layer 2 public crate suitable for any embedding host (`P5`, `D-60`).
- `grdr-daemon` stays free of D-Bus decoding (`ADR-0010`), placing systemd transient-scope requests (`#430`) in an unprivileged user program.
- Crates pass `OwnedFd`, `OwnedHandle` and stream types across layer 3 boundaries instead of calling raw bindings inside `grdr-daemon`, and endpoint/security issues sharing `src/lib.rs` and `src/<os>/mod.rs` sequence cleanly after `#1749`.

## Alternatives rejected

- **Allow `unsafe` in `grdr-daemon` or in `crates/grdr-wire/src/peer_auth/{macos,windows}` as a documented exception (`#1743` option 1 variant, `#1671` option A):** puts raw OS bindings and `unsafe` into a layer 4 program and a public layer 2 crate linked by every host (`P5`, `D-61`), and breaks `docs/design/03` section 10.
- **Vetted service-manager and peer-auth wrapper crates (`#1743` option 2, `#1671` option C):** no maintained crate offers a safe API for `launch_activate_socket`, `libbsm` audit-token inspection, or Windows named-pipe peer verification (`GetNamedPipeClientProcessId` and token inspection), leaving `unsafe` with us anyway; for systemd and SCM, wrapper crates pull third-party `unsafe` and extra dependencies into the privileged closure for small, fixed protocols.
- **Place service-manager calls in `grdr-wire`'s OS back ends (`#1743` option 3):** mixes `endpoint` service hosting into a layer 2 transport crate (`core` and `security`) and pulls service-manager bindings into `grdr-hook` and `grdr`.
- **Combine `grdr-os-service` and `grdr-peer-os` into one crate:** violates `R-50` (`security` owns IPC peer authentication; `endpoint` owns daemon service hosting) and forces `grdr-hook` and `grdr` to link service-manager code solely to verify an endpoint owner.
- **Admit a D-Bus client inside `grdr-daemon` (`#419`):** violates `ADR-0010` (`ARCH-004`) by adding a multi-peer message decoder to a privileged program's dependency closure.

## Revisit when

- A service-manager or peer-authentication operation requires direct access to daemon internals that cannot cross an `OwnedFd`, `OwnedHandle` or stream boundary within `limits.toml` latency or memory budgets.
- `rustix` or `libc` adds audited, parser-free safe or raw bindings for `launch_activate_socket` or macOS `libbsm` audit-token calls, letting `grdr-os-service` or `grdr-peer-os` drop its crate-local `extern "C"` block.
- `grdr-os-service` or `grdr-peer-os` requires an RFC-governed public API (`surface = "public"`), moving that surface to layer 2 through an RFC (`D-61`).
