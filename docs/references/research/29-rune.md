# Rune UI framework deep-dive for the desktop app

_Researched 2026-11-09_

Read at `dev` rev `0fba24cd` (2026-11-10 04:58 UTC) through the GitHub API: README, `crates/rune/README.md` (206 KB), `crates/rune-kit/README.md`, PLAN.md, WEB.md, AGENTS.md, Cargo manifests, selected sources, the full tree (2,667 paths) and all 211 issues. "Verified" means read in the repo or a vendor doc today. "Inferred" is marked. Web search was unavailable (budget exhausted), so there is no third-party commentary in this brief.

## TL;DR

- Rune is 19 days old (created 2026-10-22), version `0.0.1`, MIT, no tags, no releases, not on crates.io. About 1,805 commits, 84% by one author. Apps pin a git rev of `dev`, which is fast-forward-only.
- The programming model is Elm-like with direct mutation: `fn view(&State, &mut Cx) -> El`, handler closures get `&mut State`, `poll` runs before each frame, background threads use `AppHandle::update` or a `Waker`. It maps cleanly onto a view-model boundary.
- Rendering needs a GPU API: Metal on Apple, DX12 or Vulkan on Windows, Vulkan only on Linux. There is no GL backend and no CPU renderer. Without a GPU it runs on WARP or lavapipe, and a full-window frame on WARP costs 0.67 to 0.82 CPU-seconds (about 2 fps on 2 vCPUs). VDI and RDP users are a real problem.
- Accessibility is real: AccessKit adapters for UI Automation, NSAccessibility and AT-SPI are a default feature. The same tree is dumped by `--tree`.
- That accessibility tree is also an attack surface for us: an AccessKit `Click` runs the element's `on_press` with no pointer event. Rune has no notion of input provenance. An approval button drawn in Rune can be pressed by any same-user process.
- Every Rune binary, release builds included, accepts `--script`, `--tree` and `--snap` on argv and runs the app headlessly. Ship with `.args(Vec::new())`, or an agent can drive our UI binary without a window.
- Tray exists on Windows and Linux only (macOS open, #141). Notifications exist on macOS and Windows only (Linux open, #334). There is no start-at-login, no packaging, no signing and no updater.
- rune-kit covers most of what we need: virtualised Table (100,000 rows at 0.4 ms p50), Tree, Diff, streaming Markdown, forms, toasts, dialogs and an app shell. There are no charts, no slider, no date picker and no code editor with a gutter.
- Long-running risk is concrete: open reports of an idle window using 100% of a core on Windows DX12 (#218), the same on Wayland when covered (#139), a per-cycle surface leak on macOS (#162) and a 180 MB private-memory floor on Windows (#430).
- Maintainers take issues only. 198 of 211 issues are open and 5 have a maintainer reply. Upstream CI runs on macOS only, and the documented test command failed 16 tests on `dev` (#260).
- Headless mode is the strongest part: same renderer, virtual clock, PNG, element and accessibility tree JSON, scripted input, and an in-process `headless_runtime` for `cargo test`.

## Findings

### Programming model

- View: plain Rust builders (`row()`, `col()`, `el()`, `text()`), keyed nodes, layout by Taffy 0.15 (flexbox, grid, block). Hover and press never re-run the view. ([core README](https://github.com/anomalyco/rune/blob/dev/crates/rune/README.md), 2026-11-10)
- State and messages: handlers such as `.on_press(|s: &mut S| ..)` are queued and run between frames, then the view re-runs and is diffed. There is no message enum unless we add one.
- Async and background work: `AppSpec::setup` hands out a `Waker`. `poll(state, clock, tx)` runs before each frame and must return true only when visible state changed. `tx.wake_after` schedules timers without a thread. `AppHandle<S>` is `Clone + Send + Sync`, and `handle.update(|s, tx| ..)` runs on the UI thread even with no window. `rune::Latest<T>` runs latest-wins requests on up to four workers with debounce.
- `rune::machine` gives explicit state machines (`enum State`, `step` returning effects, `Attempt` tokens that fence stale answers). AGENTS.md makes this mandatory inside Rune. ([AGENTS.md](https://github.com/anomalyco/rune/blob/dev/AGENTS.md))
- Animation is evaluated on the main thread at frame time. PLAN.md's render thread is not built (#263).

### Layout, text, input, IME, RTL, i18n

- Text: Parley 0.12 and swash, embedded Inter 4.1, ICU4X segmentation for CJK and Thai. Rasterisation modes: CoreText-matched on macOS, `Windfoil` (Rune's own) elsewhere, `DirectWrite` optional.
- Text fields: caret, selection, undo capped at 128 edits or 1 MiB, secure fields with wipe-on-drop, `tx.copy_secret(text, ttl)` with clipboard-history exclusion.
- IME goes through winit 0.30 (`Ime::Preedit`, `Ime::Commit`). PLAN.md calls winit's IME incomplete and lists native TSF, `NSTextInputClient` and `text-input-v3` as future work. Wayland layer-shell overlays have no input method (#322).
- RTL: bidi shaping works with first-strong detection. There is no API to set base direction (#244) and a caret bug in mixed runs (#243). An RTL scroll bar landed 2026-11-10. Layout mirroring was not verified.
- `rune-i18n` (2026-11-08): JSON catalogs compiled at build time, compile-time key checks, CLDR plurals and numbers, OS language negotiation. rune-kit still has fixed English strings (#396).
- Keyboard navigation is thorough: Tab order, roving focus groups, modal focus traps, default button, `Chord::parse("mod+shift+t")` for cross-platform shortcuts.

### Rendering stack and behaviour without a GPU

- wgpu `~30.0.1`. Non-Apple targets enable only `vulkan` and `dx12`; Apple uses Rune's own Metal backend by default; web uses WebGPU. ([Cargo.toml](https://github.com/anomalyco/rune/blob/dev/crates/rune/Cargo.toml))
- Adapter choice: compositor GPU on Wayland, the GPU driving the primary display on Windows, else lowest power, with software adapters ranked last. `force_fallback_adapter` is false. Overrides: `WGPU_ADAPTER_NAME`, `WGPU_POWER_PREF`, `RUNE_GPU_LOG=1`. A remote or indirect display has no PCI GPU and falls through to lowest power. ([gpu/pick.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/gpu/pick.rs))
- Linux without a GPU needs `mesa-vulkan-drivers` (lavapipe). A GL backend is an open request (#23).
- WARP cost, measured by users on a 2-vCPU Windows Server 2025 VM: 0.667 CPU-s per present for a 380 × 1080 panel; a second report shows 92% CPU at 2.1 fps while typing, 550 ms key-to-screen. A community fork with damage-limited redraw cut scrolling from 0.82 to 0.04 CPU-s per frame. PLAN.md deliberately skips partial present. ([#296](https://github.com/anomalyco/rune/issues/296), 2026-11-08)
- A window that cannot be created leaves a windowless process (#293). `AppHandle::window_error()` and `App::try_run` exist.
- A windowless Windows app touches no GPU at launch (changelog 2026-11-07), which suits a tray process.

### Windowing and platform shell

- Multiple windows with different state types (`run_windows`, `App::window`), click-through overlays, always-on-top, borderless, spring-animated resize, `fit_content_height`.
- App lifetime: `windowless()`, `keep_running()`, `accessory()` (macOS, no Dock icon), `release_gpu_when_closed()`.
- Global shortcuts: Carbon, `RegisterHotKey`, X11 grabs, Wayland portal. The portal fails for unsandboxed apps (#140). ([shortcuts README](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/shortcuts/README.md))
- Deep links: `App::on_open_url` on macOS; on Windows links arrive as arguments and `rune::single_instance(id)` forwards them over a per-user named pipe. Linux has neither (#22).
- Native popup and context menus on macOS and Windows; elsewhere the app needs an in-app fallback.
- File dialogs behind `native-file-dialog` (rfd, XDG portal on Linux), one file at a time (#367).
- Drag and drop: file drops on macOS, Windows and X11, not Wayland (#424). Drag-out is macOS only.
- Capture exclusion: macOS windows and Windows overlays. Ordinary Windows windows are not covered (#437), but calling `SetWindowDisplayAffinity` on the raw handle works.
- Windows overlays never take the keyboard (#325).

### Accessibility

Verified as real. Roles, labels, values, states, live regions, virtual-list row counts, text caret and selection are exposed. The tree is built lazily when an assistive client asks. rune-kit has per-component accessibility goldens. Caveats: the "Differences from PLAN.md" section of the same README still says there is no AccessKit (stale, #263); a macOS reentrancy abort is open (#150); WCAG audit issues are open as goals (#109 to #111).

### rune-kit components

Button (10 variants), IconButton, Switch, Checkbox, Radio, TextInput, TextArea, Field, Select, Combobox, Popover, Menu, Tooltip, HoverCard, Toast, Card, List, Accordion, Badge, Progress, SegmentedControl, Dialog, ShortcutRecorder, and `shell` (SplitView, Sidebar, Toolbar, Page). Table and Tree are virtualised. Markdown (CommonMark and GFM tables, streaming, 80 lexers including YAML and JSON, Mermaid subset). Diff (unified and split, annotations, 50,000-line diff in about 40 ms). Tokens live in a `Kit` struct filled from theme data; `Kit::from_palette` derives a theme from three colours. ([kit README](https://github.com/anomalyco/rune/blob/dev/crates/rune-kit/README.md))

Missing: charts, slider (#149), date and time pickers, a code editor with line numbers, folding or find, and drawn scrollbars in some components.

### Performance, memory, size, start-up

- Frame CPU 0.13 ms mean on Apple silicon; binary 10.9 MB (9.3 MB stripped); first content about 300 ms on macOS. These are the README's own numbers and may be stale.
- Windows, from user reports: `hello` first frame 1.34 s and 217 MB private (#218); 180 MB private on AMD DX12, 100 MB on WARP (#430); DX12 probe about 215 ms (#99).
- PLAN.md's target is 50 MiB idle RSS on Mac; the README's measured settings window sits at 70 to 77 MB.
- `procwatch` (libc only) reports the app's own footprint and CPU and can serve them as loopback JSON.

### Headless mode

Flags on any binary: `--snap out.png`, `--tree tree.json` (elements plus an `"accessibility"` subtree), `--script file.json` (tap by key, type, key, drag, wheel, `drop_files`, `menu-pick`, `file-dialog`, marks), `--video`, `--trace`, `--scene`, `--theme`, `--size`, `--scale`, `--window KEY`. The clock is virtual, so runs are deterministic. In `cargo test`: `App::headless_runtime(size, env)`, `rt.frame(dt)`, `rt.find`, `Runtime::accessibility_json`, `Runtime::accessibility_action`, `Runtime::resolve_file_dialog`. `--snap` needs no display but does need a GPU adapter (lavapipe works). ([tooling/args.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/tooling/args.rs))

### Web target

Experimental. WebGPU only; the `webgl` feature does not compile (#115). Main thread, no SharedArrayBuffer, no system fonts, no file dialogs, a DOM accessibility mirror, and `--html` static export. ([WEB.md](https://github.com/anomalyco/rune/blob/dev/WEB.md))

### Packaging, stability, issue handling

- "Rune doesn't bundle apps." `scripts/mac-app` is a development relauncher. Nothing for MSI, MSIX, pkg, deb, rpm, signing, notarisation or updates.
- Stability policy: pin a rev; `dev` is never rewritten; changes that move output or break builds need a changelog fragment; literal-built structs get builder methods instead of new public fields. CHANGELOG.md is one `## dev` section with 435 entries. Toolchain is pinned to Rust 1.99.1, edition 2024.
- The crates.io question (#108) is unanswered; the name `rune` is taken there.
- Issues: 211 filed in 19 days, 160 of them in the last four days. 13 closed (median 2.5 hours for those). 198 open. 5 have a maintainer comment. In the same period the core team merged 205 of its own PRs. Several reporters attach fix commits on forks because PRs are refused.
- The docs site at `anoma.ly/team/rune` sits behind Cloudflare Access; the READMEs are the public documentation. ([site README](https://github.com/anomalyco/rune/blob/dev/site/README.md))

## Matrix

| Need | Rune today | Gap | Workaround |
|---|---|---|---|
| Tray or menu-bar item | Windows (`Shell_NotifyIcon`), Linux (StatusNotifierItem) | macOS (#141); icon cannot change at runtime (#305); GNOME needs an extension | `tray-icon` 0.26 on macOS (needs main thread and a running loop), or own `NSStatusItem` via objc2 inside `AppHandle::update`; recreate `Tray` to change the icon |
| Notifications | macOS (bundled apps), Windows toasts | Linux no-op (#334); silent; no action buttons | zbus `org.freedesktop.Notifications` on Linux; click opens the app through a deep link |
| Approval prompt | Modal, always-on-top window, default button | No input provenance; accessibility click presses buttons; headless flags | See architecture below |
| Session timeline | `virtual_rows`, Table, Tree, sticky headers, streaming Markdown | Row-count changes copy every key (#203) | Page the timeline in the view-model; cap mounted rows |
| Policy editor | TextArea with syntax spans, DiffView for review | No gutter, folding, find; undo cap | Form-first editor, YAML pane as secondary, Diff for "review changes" |
| Settings, onboarding | `examples/settings`, `shell::Page`, animated resize | None material | — |
| Start at login | None | All platforms | Own code: `SMAppService`, HKCU Run key or scheduled task, XDG autostart |
| Single instance | Windows only | macOS (Launch Services does it), Linux | Lock on our own IPC socket |
| Deep links | macOS, Windows | Linux | Parse argv, forward over our socket |
| Packaging, signing, updates | None | All | Separate toolchain (Velopack lists Rust support; cargo-packager; native installers) |
| Software rendering | WARP or lavapipe, very slow | No damage redraw | "Lite" mode, small windows, alternative front-end |

## Weak points, gaps and risks

1. **Approval integrity.** A same-user agent can press Rune buttons through UI Automation or AT-SPI ([a11y/actions.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/a11y/actions.rs)), through synthetic input, or by launching our binary with `--script`.
2. **No-GPU environments.** VDI, RDP and server VMs get software rasterisation of the whole window every frame.
3. **Months-long uptime.** Idle CPU spin (#218, #139), hide/show leak (#162), hidden windows holding GPU memory (#161, #142), high memory floor (#430).
4. **Windows and Linux are second-class in testing.** Upstream CI is macOS only ([workflow](https://github.com/anomalyco/rune/blob/dev/.github/workflows/macos-tests.yml)); the precompiled Windows shader was unused because of a CRLF hash (#182).
5. **Governance.** No PRs, one dominant author, issue backlog growing faster than it closes, docs behind the code.
6. **Supply.** Git-only dependency with roughly 95 commits a day and no semver.
7. **Embedding.** Hosting Rune inside another app's GPU device or window is not supported (#230, #420).

## Implications for our design

**Process architecture**

- *Sensor service* (privileged, no UI dependency).
- *Session agent* (unprivileged, per user, always running): owns tray, notifications, autostart, single instance, deep links and the IPC connection. Build it so it never creates a GPU device. It may use Rune's `Tray` and `rune-notify`, but put them behind our own `Shell` trait so macOS and Linux gaps are filled by other crates.
- *Console window process* (Rune): timeline, policy editor, settings, onboarding. Spawn on demand and exit on close. This sidesteps every hidden-window leak and idle-spin report and returns 100 to 200 MB to the user.
- *Approval prompt*: do not treat a click in a same-privilege Rune window as authorisation.
  - Windows: have the service launch the prompt at a higher integrity level than the agent. Microsoft documents that a medium-integrity process without UIAccess "cannot access elevated … process UI", and that only the UAC desktop under SYSTEM is closed to everything. Restrict the answer pipe to that process identity.
  - macOS and Linux: there is no equivalent boundary (inference from general platform knowledge, not re-verified today). Use an OS authentication step for high-risk approvals (Touch ID or password sheet; polkit) and an out-of-band approval (phone or web console) as the strong tier.
  - In all cases: `.args(Vec::new())`, capture exclusion on the prompt window, a minimum display time before buttons arm, and a log of how each approval arrived. On Windows, subclass the window through `WindowHandle::with_raw_handle` and check `GetCurrentInputMessageSource` for injected input as a detection signal, not a control.

**View-model boundary**

- `ui-core` crate with no Rune dependency: view-model structs, `enum Intent`, `fn reduce(&mut Vm, Intent) -> Vec<Effect>`, IPC client, paging stores, token data as JSON.
- `ui-rune` crate: views and handler closures that only dispatch intents. IPC thread holds the `Waker`; `poll` drains a channel and returns true only when a visible view-model changed.
- Do not import `rune::machine` or `rune::Latest` into `ui-core`; copy the patterns.
- Treat a second front-end as a planned deliverable for no-GPU fleets, not a hypothetical.

**UI test strategy**

1. View-model unit tests without Rune.
2. `headless_runtime` tests per screen: dispatch, `rt.frame`, assert on `rt.find` and `accessibility_json`.
3. Scene goldens: `--tree` JSON on Windows, macOS and Linux; `--snap` PNG on one reference renderer (Linux lavapipe), because text rasterisation differs by platform.
4. Scripted flows with marks; attach `--video` on failure.
5. Accessibility goldens in rune-kit's style, plus one real UI Automation smoke test on Windows.
6. A 48-hour real-window soak on each OS per rev bump, with `procwatch` gauges and open/close cycles; fail on rising memory or non-zero idle CPU.
7. A negative security test: prove that an accessibility click and a `--script` run cannot produce an approval.

**Dependency handling**

Mirror the repo, pin a rev, bump on a schedule through the full gate, keep a small patch queue, and file issues with fix commits attached.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Agent approves its own action through the UI | High | Critical | Privilege-separated prompt, OS authentication, out-of-band tier, disabled headless flags |
| Unusable on VDI or RDP | High | High | Lite mode, on-demand window, second front-end behind the view-model |
| CPU spin or leak over weeks | Medium | High | Short-lived window process, soak gate, watchdog restart by the session agent |
| Breaking change on rev bump | High | Medium | Pin, mirror, scheduled bumps, changelog diff review, golden tests |
| Upstream stalls or changes licence terms | Low to medium | High | MIT fork is possible; view-model boundary keeps a toolkit swap to the view crate |
| Windows or Linux regressions upstream misses | High | Medium | Our own three-OS CI on every bump |
| macOS tray, Linux notifications never land | Medium | Low | Already behind our `Shell` trait |
| Accessibility defects block enterprise procurement | Medium | Medium | Accessibility goldens, manual screen-reader pass per release |

## Ideas worth stealing and whitespace

- One tree for accessibility, tests and agent inspection, with a virtual clock.
- A readiness file (`RUNE_READY_DIR`) for launch supervision.
- `copy_secret` with expiry and history exclusion.
- Repository rules written for coding agents: file-size caps, changelog fragments, a pre-commit grep for private paths.
- Whitespace: no toolkit exposes per-event input provenance or a "trusted press only" element. A small hardened-prompt crate for agent-security products does not exist. Rune's headless tree is also a ready-made detection signal: we can recognise other Rune apps being driven headlessly by their argv.

## Could not verify / open questions

- Whether Rune renders correctly at high integrity or on the Windows secure desktop.
- Whether fixes land on `dev` without the matching issue being closed (would make the 6% close rate misleading).
- Layout mirroring for RTL; real IME behaviour on Windows and Wayland.
- Binary size and start-up on Windows and Linux from our own builds.
- macOS and Linux approval-hardening details; Velopack licence and delta-update support.
- Third-party reviews of Rune: web search was unavailable in this session.
- The private docs site ("Launch fast", "Fast apps") could not be read.

## Sources

- https://github.com/anomalyco/rune — README, 2026-11-10
- https://github.com/anomalyco/rune/blob/dev/crates/rune/README.md — core docs, 2026-11-10
- https://github.com/anomalyco/rune/blob/dev/crates/rune-kit/README.md — components, 2026-11-10
- https://github.com/anomalyco/rune/blob/dev/PLAN.md — plan, targets, risks
- https://github.com/anomalyco/rune/blob/dev/WEB.md — web target
- https://github.com/anomalyco/rune/blob/dev/AGENTS.md — repository rules
- https://github.com/anomalyco/rune/blob/dev/crates/rune/Cargo.toml — features and dependencies
- https://github.com/anomalyco/rune/blob/dev/crates/rune/src/gpu/pick.rs — adapter selection
- https://github.com/anomalyco/rune/blob/dev/crates/rune/src/tray.rs — tray platforms
- https://github.com/anomalyco/rune/blob/dev/crates/rune-notify/README.md — notifications
- https://github.com/anomalyco/rune/blob/dev/crates/rune/src/shortcuts/README.md — global shortcuts
- https://github.com/anomalyco/rune/blob/dev/crates/rune/src/tooling/args.rs — headless flags
- https://github.com/anomalyco/rune/blob/dev/crates/rune/src/a11y/actions.rs — accessibility actions
- https://github.com/anomalyco/rune/blob/dev/.github/workflows/macos-tests.yml — CI
- https://github.com/anomalyco/rune/issues — #23, #80, #108, #139, #141, #162, #218, #244, #260, #263, #293, #296, #325, #334, #430, #437 (2026-10-24 to 2026-11-10)
- https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-securityoverview — Security Considerations for Assistive Technologies, updated 2026-02-18
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getcurrentinputmessagesource — GetCurrentInputMessageSource
- https://docs.rs/tray-icon/latest/tray_icon/ — tray-icon 0.26.1
- https://docs.velopack.io/ — Velopack overview

## Independent verification

Checked 2026-11-10 UTC against `dev` at `2fcb32db` (1,806 commits) through the GitHub REST and GraphQL APIs, the AccessKit adapter sources, crates.io and Microsoft and Apple documentation. Web search was unavailable (budget exhausted), so every check is against a primary source fetched directly.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | AccessKit `Click` on a pressable element runs `on_press` with no hit test or pointer event; any same-user UIA or AT-SPI client can press a Rune button | Confirmed | `a11y_action` maps `(Click, None) if pressable` to `Action::Press(path, Primary)`; the dispatcher calls `handlers.on_press` directly. AccessKit maps UIA `Invoke` and AT-SPI `DoAction` to `Action::Click`. Two limits: `allowed(i)` refuses `El::inert` nodes and nodes behind a modal, and on Windows UIPI blocks clients at a lower integrity level. | [a11y/actions.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/a11y/actions.rs), [runtime/input/action.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/runtime/input/action.rs), [runtime/input/focus.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/runtime/input/focus.rs), [accesskit windows node.rs](https://github.com/AccessKit/accesskit/blob/main/adapters/windows/src/node.rs) |
| 2 | Headless flags are parsed from process argv in all builds; only hot-reload flags are feature-gated; `App::args(Vec::new())` replaces argv | Confirmed | `try_run` uses `Args::parse()` (`std::env::args`) unless `App::args` set `argv`. Only `--hot`, `--snap-on-patch`, `--hot-control` are behind `feature = "hot"`. Not covered by `App::args`: `rune::tooling::is_headless()` always reads process argv, and environment switches (`RUNE_GPU_BACKEND`, `WGPU_ADAPTER_NAME`, `WGPU_POWER_PREF`) still apply. | [tooling/args.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/tooling/args.rs), [app.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/app.rs) |
| 3 | Non-Apple native builds enable only wgpu `vulkan` and `dx12`; software adapters ranked last; no forced fallback adapter | Confirmed | Base features `std, parking_lot, metal, wgsl`; non-Apple non-wasm adds `vulkan, dx12`. No `gles` anywhere; `webgl` is an opt-in wasm feature. `power_rank` puts `DeviceType::Cpu` last; `force_fallback_adapter: false`. No CPU renderer in the tree. | [Cargo.toml](https://github.com/anomalyco/rune/blob/dev/crates/rune/Cargo.toml), [gpu/pick.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/gpu/pick.rs) |
| 4 | WARP: 0.667 CPU-s per frame for a 380 x 1080 panel; second report 92% CPU at 2.1 fps while typing; no damage-limited redraw upstream | Corrected | The 0.667 figure is exact (2-vCPU Windows Server 2025 VM). The second measurement is a comment on the same issue from a different setup: Windows 11 with WARP forced by `WGPU_ADAPTER_NAME` and the process pinned to 2 logical cores, window 1642 x 1091, 92% of 2 cores at 2.1 fps, about 0.82 CPU-s per frame. It is not a 2-vCPU VM and not the 380 x 1080 panel. No damage or dirty-rect code exists in the `dev` tree. Both are single user reports. | [#296](https://github.com/anomalyco/rune/issues/296) and its comment of 2026-11-08 |
| 5 | `rune::Tray` supports Windows and Linux only; macOS returns `Unsupported` | Confirmed | Linux also needs the default `dbus` feature; without it `Tray::new` returns `Unsupported` there too. | [tray.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/tray.rs) |
| 6 | rune-notify posts on macOS (bundled) and Windows (registered AUMID); Linux no-op; silent; id, title, body, user info only | Confirmed | `available()` is false and `post` does nothing off macOS and Windows. No sound, no action buttons. | [rune-notify README](https://github.com/anomalyco/rune/blob/dev/crates/rune-notify/README.md), [lib.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune-notify/src/lib.rs) |
| 7 | Real platform accessibility tree through AccessKit as a default feature, built lazily | Confirmed | `default` includes `accessibility` (accesskit_windows 0.35.2, accesskit_macos 0.27.2, accesskit_unix 0.24.1). "Until a client asks, the runtime builds nothing." No adapter on iOS; the web uses a DOM mirror. | [Cargo.toml](https://github.com/anomalyco/rune/blob/dev/crates/rune/Cargo.toml), [a11y/mod.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/a11y/mod.rs) |
| 8 | v0.0.1, no tags or releases, pin a rev of `dev`, no PRs; 211 issues, 198 open, 5 with a maintainer comment | Confirmed | GraphQL: 0 tags, 0 releases, 198 open and 13 closed issues. README: "We don't take pull requests." Maintainer comments are on #2, #19, #44, #45 and #72. 6 outside PRs are open and 27 were closed unmerged. | [README](https://github.com/anomalyco/rune/blob/dev/README.md), [issues](https://github.com/anomalyco/rune/issues) |
| 9 | Unchanged `examples/hello` holds one core at 100% idle on Windows 11, DX12, AMD integrated GPU; 180 to 217 MB private memory | Confirmed | 100% and 217 MB are from #218 (Ryzen 5 7535HS, `x86_64-pc-windows-gnu` build). The 180 MB figure is a separate report, #430, on a discrete AMD Radeon R7 370. Neither has a maintainer reply or an independent reproduction. | [#218](https://github.com/anomalyco/rune/issues/218), [#430](https://github.com/anomalyco/rune/issues/430) |
| 10 | Medium-integrity process without UIAccess cannot access elevated UI; only UI on the UAC desktop under SYSTEM is closed to all listed scenarios | Corrected | First half is as documented. Second half: Microsoft says none of the scenarios reach UI running at system integrity level; that needs a process launched on the UAC desktop under SYSTEM. High-integrity UI is reachable by a UIAccess process launched by an administrator, and by any other high-integrity process (an agent in an elevated terminal). A prompt that is only "higher than the agent" at high integrity is not closed to those. | [Security Considerations for Assistive Technologies](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-securityoverview) (ms.date 2026-02-18) |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| "211 filed in 19 days, 160 of them in the last four days" | Corrected | 189 of the 211 were filed from 2026-11-06 00:00 UTC onward (51, 30, 59, 46 and 3 per day); only 22 were filed before that. | GraphQL issue list, [issues](https://github.com/anomalyco/rune/issues) |
| "macOS and Linux: there is no equivalent boundary" for the approval prompt | Corrected for macOS | macOS gates accessibility control of other apps behind a per-app user grant in Privacy & Security, Accessibility (TCC). It is a per-client permission, not an integrity level, and an agent host that already holds the grant passes it. The statement stands for Linux AT-SPI as an inference; it was not verified here. | [Apple: Allow accessibility apps to access your Mac](https://support.apple.com/guide/mac-help/allow-accessibility-apps-to-access-your-mac-mh43185/mac) |
| "`tray-icon` 0.26" and "the name `rune` is taken" on crates.io | Confirmed | tray-icon 0.26.1 (2026-10-07); `rune` 0.14.2 is the rune-rs scripting language; wgpu 30.0.1 is current. | [crates.io tray-icon](https://crates.io/crates/tray-icon), [crates.io rune](https://crates.io/crates/rune) |
