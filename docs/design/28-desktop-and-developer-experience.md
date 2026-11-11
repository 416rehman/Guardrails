# 28. Desktop apps in Rune and the developer experience

_Status: draft 5 against spine version 4 as amended on 2026-11-11 (principles P14 to P17, decisions D-69 to D-71), rulings R-03, R-11, R-21, R-33, the owner's answers (`_review/02-owner-answers.md`: no schedule, zero budget) and the owner instructions in `_review/04-owner-kit-instructions.md` (no human gates). Date: 2026-11-11. Owning squad: Interfaces (`desktop/`, the CLI shell, `grdr-approve` screens). Specifies D-43, the developer half of D-44, the desktop parts of D-48 and D-31, and the desktop part of D-69. Read with: `00-decisions.md`; 02 (SR-03, 04, 07, 18 to 23, 36, 49); 03 (layers, processes); 07 (verdict interface, `reason` fields, `doctor hooks`); 11 (`grdr.local.v1alpha1`, health codes, doctor, local listeners); 12 (modes, grants, `@message` and `@steer`); 18 (approval flow, grades, prompt anatomy, prompt budget); 22 (enrolment); 23 (CLI grammar, `--json` and exit codes); 24 (build, signing, packaging); 27 (web console, the interface system, the token source); 34 (references, the language-token workflow)._

## Summary

The developer meets Guardrails ADR through four local surfaces: the `grdr` command line, the approval helper `grdr-approve`, a per-user tray, and a six-screen desktop app in Rune. The full console exists once, as the web app (27). Key choices:

1. **One view-model crate, three renderers.** `grdr-ui-model` holds every desktop screen as data, with no Rune dependency. It drives the local web console, the Rune app and the terminal, and is the exit ramp if Rune stalls.
2. **Rune is a pinned, patched, sandboxed leaf**: a mirror pinned by commit, a capped patch queue that removes the headless tooling flags, a 48-hour soak on three operating systems per bump, and an on-demand window process.
3. **Three render tiers**: Full, Lite, and Web (software adapter or remote session: the tray opens the local console instead of Rune).
4. **Approvals never touch Rune.** `grdr-approve` uses OS-native dialogs and authenticators; every widening from any other local surface is a proposal, and mutations from inside an agent session are refused (D-31).
5. **Value before change.** First run is a read-only scan with no account and no elevation; the setup list opens with three of six steps ticked.
6. **The agent is steered, not just stopped**: every denial carries a fixed-shape message naming the one acceptable next step, so the next call is a retry, not a pivot.
7. **Notifications are budgeted and carry no content.**
8. **The command line is first-class**, with a typed `--json` envelope and agent-caller rules.
9. **Joining a team is re-labelling, not migration**: the local organisation id becomes an alias and history stays local.

## Requirements

| # | Requirement | Trace |
|---|---|---|
| R1 | Desktop app in Rune, six screens: First run, Home, My activity, Rules (Simple), Privacy, Settings | Owner request; D-43 |
| R2 | The local web console renders the same six screens, needing only the daemon; the tray opens it on software renderers and remote sessions | D-43; c7 F4; l06 F9 |
| R3 | View-models live in a crate with no Rune dependency; Rune is pinned, mirrored, patched, soak-tested and sandboxed | D-43; brief 29 |
| R4 | Approvals never use Rune; the tray has no Rune or GPU dependency | D-43; brief 29 verification rows 1, 2, 3 |
| R5 | Every widening from a local surface is a proposal that needs a step-up; narrowing applies and is staged; every mutation from inside an agent session is refused | D-31, D-11; SR-04, 23 |
| R6 | First value within five minutes, no account, no elevation; setup list opens with completed steps ticked | D-44, D-48; spine section 6 first-value target; c7 F8 |
| R7 | A block names the component, the rule and the route to an exception within 1 s; Ask names its approver; the agent gets a reason it can act on; no dead ends | D-44; h08 acceptance table |
| R8 | Prompts: median 3 or fewer, p95 8 or fewer per developer-day, reported per rule and per group | Spine section 6; D-51; 18 section 4 |
| R9 | The disclosure surface (Privacy screen, tray status) is reachable in two clicks and cannot be hidden in any shape or brand | D-51; SR-49; l07 F10 |
| R10 | CLI `status`, `why`, `run`, `doctor`, `policy test`, all with `--json` | Brief; 33 |
| R11 | Standalone to team without migration; join shows capture level, readers and locked rules first | D-48; l06 F7 |
| R12 | WCAG 2.2 AA on desktop with its own conformance report; keyboard path everywhere; modes never by colour alone | D-42; c7 F9; 33 |
| R13 | Language tokens on every surface (D-69): one MF2 source, generated typed accessors, CLDR formatting; `en-XA`, `ar-XB` and `ja-XC` in CI | D-42; D-69; c7 F9 |
| R14 | Autostart, single instance, deep links, packaging per platform | Brief 29 matrix; D-59 |
| R15 | Theme generated from the shared DTCG tokens; exponential spacing; Lucide icons | D-42; brief 30; owner UI rules |
| R16 | Text written by agents, tools or models is rendered inert | SR-36 |

## Design

### 1. The desktop pieces

| Piece | Binary | What it is for | Never does | Requires |
|---|---|---|---|---|
| Command line | `grdr` | Every task, scripted or by hand; the only surface on servers, CI and remote shells | Widen without a step-up; mutate from inside an agent session | The daemon (`status` and `doctor` also work with it down) |
| Approval helper | `grdr-approve` (trust core, D-63) | Render one approval, Exception request, widening confirmation or join confirmation from the canonical action, and collect the grade proof (18) | Render agent-supplied text as anything but inert text; use Rune | The daemon |
| Local console | `grdr console serve` plus the web app | The full local console (27) and the six desktop screens as web pages; an unprivileged per-logon-session process started on demand, reading through the daemon's local API (D-42, R-03) | Bind anything but loopback (SR-03); the daemon itself binds no TCP port | The daemon's local API |
| Tray | `grdr-tray` | Per-user session agent: status icon, native menu, notifications, deep links, autostart, launching the desktop app or console | Link Rune, wgpu or winit; render a window | The daemon's local API |
| Desktop app | `grdr-desktop` | The six screens with native feel for people who keep a window open | Hold state the daemon does not hold; approve | The view-model crate and a passing S-19 |

Block text does not depend on the tray. The person-facing block text travels in the dialect's user-message field where one exists (Cursor's `user_message`, brief 15) and otherwise inside the agent's own transcript, and appears within 1 s on the local console's Home route and in `grdr why --last`; where the tray runs, a toast also carries it (section 8). Approval dialogs need no tray: the daemon launches `grdr-approve` in the person's logon session. Toasts require the tray.

### 2. Depending on Rune [requires S-19]

Facts (brief 29, verification section): MIT, created 2026-10-22, `0.0.1`, git-only with a fast-forward-only `dev`, no outside pull requests, Rust 1.99.1 pinned; Metal, DX12 or Vulkan only, no CPU renderer; every binary parses `--script`, `--tree`, `--snap`, and `is_headless()` reads process argv even after `App::args`; an AccessKit `Click` runs `on_press`; tray on Windows and Linux only, notifications on macOS and Windows only; user reports of a full idle core on Windows DX12 (#218) and a 180 to 217 MB private-memory floor (#218, #430).

**Pinning and mirror.** A mirror repository of `anomalyco/rune` sits beside the main repository under the same account, created when DX-10 starts (team/06 section 2.2). `desktop/rune.lock.toml` records the upstream commit, the mirror branch `grdr/<upstream-sha>` (upstream plus our patch queue) and its tree hash. `grdr-desktop` depends on the mirror by full commit SHA; release builds run `--locked --offline` against a vendored source archive stored with the release inputs (24). `grdr-desktop` is not a default workspace member and sits behind the `rune-desktop` feature, so ARCH-011 holds (03).

**Patch queue.** `desktop/rune-patches/` is an ordered series. Each patch has a header naming the upstream issue, the reason, a test, and the date it was filed upstream as an issue with the fix commit attached (upstream takes no pull requests). The queue is capped at 10 patches and 1,500 changed lines. This design fixes three of them:

1. Compile out argv tooling flags and make `is_headless()` return false unless a `test-util` feature is on. The in-process `App::headless_runtime` stays available to `cargo test` only.
2. Expose the selected adapter's device type before the first window, if upstream does not (unverified; the S-19 spike checks), so the app can exit to the Web tier without drawing.
3. Ignore `RUNE_GPU_BACKEND`, `WGPU_ADAPTER_NAME`, `WGPU_POWER_PREF` and `RUNE_GPU_LOG` unless set by our launcher. The launcher also scrubs the environment to an allow-list.

Community fixes for #218 and #162 enter the queue only with a reproduction in our soak rig.

**Bumps.** A scheduled job proposes a bump every four weeks; a security-relevant upstream fix triggers one out of band under D-62's seven-day target. A bump passes the full gate: `eval-security` reading the upstream diff in a clean context, three-OS build, headless and accessibility goldens, the negative security tests, the 48-hour soak, and an `eval-ux` verdict on the `--snap` and `--tree` golden diffs. The changelog diff (upstream keeps changelog fragments) is posted on the bump's issue. An agent that prepares a bump runs within a usage cap per run on the owner's Claude subscription (D-47).

**Soak (the S-19 oracle and the bump gate).** On each OS (Windows 11 x64 on AMD and Intel integrated GPUs, macOS arm64, Ubuntu x64 on Wayland and X11), the release build runs for 48 hours with a scripted cycle every 10 minutes: open, visit all six screens, scroll a 10,000-row session, minimise, restore, close. Gauges come from the OS (Windows performance counters, `proc_pid_rusage`, `/proc/<pid>/stat`), never from Rune's own `procwatch`. Pass: idle CPU under 1% of one core with the window open and unfocused; private memory growth under 5% between hour 2 and hour 48; no crash; Web-tier fallback within 2 s when the adapter is forced to WARP or lavapipe and under RDP (c7 spike 2). Two consecutive failed gates switch the shipped configuration to Web tier everywhere (D-43); the soak reruns on each new Rune release. There is no money for lab hardware (D-64): the forced-WARP, lavapipe and remote-session fallback checks run on free hosted CI runners, the repository being public from its first push, while the GPU cells and the 48-hour runs need real GPUs and longer jobs than hosted runners allow, so they run on tier B self-hosted runners (D-64). A cell nobody has a machine for (for example one of the two Windows GPU vendors) is marked "requires hardware" and the gate reports it untested, never passed.

**Window lifetime.** The Rune process is spawned on demand and exits when its window closes (brief 29: this sidesteps the hide/show leak and hidden-window GPU retention). The tray samples the window process; above 5% CPU for five minutes while unfocused, or above its memory budget, it records the health condition `desktop-budget-exceeded` and relaunches the window on the same route when it next loses focus. The window has its own budget, 200 MB private on Windows and 120 MB elsewhere (targets until S-19 measures them; the reported Windows floor of 180 to 217 MB, single user reports, may force the Windows figure up), outside the steady-state endpoint budget (spine section 6 excludes the on-demand Rune window).

**Headless tests.** Patch 1 keeps the tooling only behind `test-util`, so tests use test builds, never the release binary. Per screen: `App::headless_runtime` tests that dispatch an `Intent`, step `rt.frame` and assert on `rt.find` and `accessibility_json`; `--tree` JSON goldens on all three systems; `--snap` PNG goldens on one reference renderer (Linux lavapipe), because text rasterisation differs by platform; scripted flows with marks, with `--video` attached on failure (brief 29, UI test strategy). The release binary gets only the negative test (flags ignored, Test section).

**Render tiers.**

| Tier | Chosen when | Behaviour |
|---|---|---|
| Full | Hardware adapter, local session | All motion (respecting the OS reduced-motion setting) |
| Lite | User choice; on battery saver; after one `desktop-budget-exceeded` in a day | No animation, no translucency, frames only on view-model change, smaller default window |
| Web | Software adapter (patch 2), window creation fails (`App::try_run` error, #293), remote session detected by the tray (Windows remote-session metric; macOS and Linux heuristics to be found in S-19), the gate fallback, or a right-to-left UI locale while Rune #244 is open (DX-23) | Rune never starts; the tray opens the same route in the local console |

The adapter result is cached per display configuration for 24 hours so the decision costs nothing on the next open.

**Sandbox.** The window process is launched by the tray through 11's sandbox launcher with 11's desktop profile (R-59): no network, read-only file access except its own state directory, IPC only to the daemon's `local` endpoint. On Windows the target is an AppContainer whose SID the `local` pipe DACL admits; if DX12 or DirectWrite fail inside it (spike DX-S2), a low-integrity restricted token is the fallback. Reason: a new, pre-1.0 renderer that draws strings written by agents is untrusted code (SR-36).

**Exit ramp.** Triggers: two failed soak gates (automatic, D-43); no upstream commit for 60 days; a licence change away from OSI; the patch queue over its cap; an upstream security fix unavailable within seven days. The non-automatic triggers become an issue for `lead-interfaces`; the chief architect decides and records the evidence in a decision record, because the owner asked for Rune. Response: Web tier everywhere, `grdr-desktop` kept as a launcher for the local console, and a replacement toolkit evaluated against the same view-models. Views only dispatch intents, so a swap rewrites `grdr-desktop` alone; MIT permits a hard fork meanwhile.

### 3. The view-model crate

`grdr-ui-model` is a layer 3 crate with `privilege = "untrusted"`. It depends only on layers 0 to 2 and never on `rune`, `wgpu`, `winit` or any I/O runtime. Archlint rule ARCH-016 `rune-leaf` (03's register, R-21) enforces that `rune` and `wgpu` appear only in the closure of `grdr-desktop`, and that `grdr-tray` and `grdr-approve` link neither.

Contents: one struct per screen (`FirstRunVm`, `HomeVm`, `ActivityVm`, `SessionVm`, `RulesVm`, `PrivacyVm`, `SettingsVm`), each carrying one `ViewState` of `grdr.ui.v1alpha1` (27 section 4); `TrayVm` for the tray menu and `NotificationVm` for toasts; `Preferences` (theme, render tier, `ui.locale`, `ui.time_zone`, UTC display, "Show technical detail"), shared with the local console; `enum Intent`; `fn reduce(&mut AppVm, Intent) -> Vec<Effect>`; `Effect` (a `grdr.local` request, open a route, launch `grdr-approve` for a request id, copy text); a paging store that holds at most 500 mounted rows per list and pages in 200-row slices (Rune #203 copies every key on a row-count change); language-token references (`MessageRef`: an id and typed arguments) in place of formatted strings, so Rune and the terminal format through `grdr-messages` and the web through `@grdr/i18n`, each in its own locale (section 13). Lifecycles are explicit enums with one transition function, per 03's convention; we copy the `rune::machine` pattern and import nothing from it.

Three renderers consume it:

- **Rune** (`grdr-desktop`): `fn view(&Vm, &mut Cx) -> El`, composed only from `grdr-desktop/src/kit/`, which implements each registered pattern a desktop screen uses, on rune-kit's typed `Kit` filled by the token outputs (section 15); screen code never calls a Rune or rune-kit element constructor (UX2). Handlers only dispatch `Intent`s. `SessionVm` carries 23's timeline page messages unchanged, so My activity and 27 section 4.9 render the same `SessionTimeline` pattern from the same rows. An IPC thread holds the `Waker`; `poll` drains the channel and returns true only when a visible view-model changed.
- **Web**: `grdr console serve` links the crate and serves each view-model as JSON (`grdr.ui.v1alpha1`, generated JSON Schema) at `/vm/<route>` with server-sent events for changes, behind the one-time launch token. 27 renders those routes with `@grdr/kit`. Intents arrive as `POST /vm/intent` and pass through the same `reduce`.
- **Terminal** (`grdr`'s `term` module): `grdr status`, `grdr why`, `grdr privacy show` and `grdr doctor` render `HomeVm`, the block card, `PrivacyVm` and the Health section as text.

One crate means the three renderers cannot disagree about what a screen says, and a parity test (section "Test and evaluation") holds them to it.

### 4. Interface rules applied to every screen

Every desktop screen is built from 27 section 10's tokens, patterns, presentation registry and language tokens, and 27 section 9's confirmation classes, through the desktop kit `grdr-desktop/src/kit/` (section 3). This document adds no visual or copy rule of its own. Rune cannot render Astryx, so the desktop kit and the tray take Astryx's component names, anatomy, variants and states and the same tokens, and a dialog, a table or a mode control looks and behaves as it does in the console; `grdr-approve` keeps OS styling with the same content, order and labels (section 7). Desktop additions: the OS reduced-motion and high-contrast settings select the token modes (section 15), and agent-written text renders through the kit's `Quoted` from 23 section 10's untrusted envelope (SR-36). Budgets, caps, intervals and timeouts in this document are `limits.toml` defaults, hosts and names come from configuration and the brand manifest, and no desktop binary holds them as literals (check S7, ARCH-021, UX1, UX3). An agent editing `desktop/`, `programs/grdr-tray/` or `programs/grdr-approve/` loads `ui-architect`, then `grdr-interface`, as `.agents/kit/path-skills.toml` lists; the web rendering of these screens lives under `web/` and also takes `frontend-design` and `modern-web-guidance` (27 section 11). *Applying: Safety (one system), Exponential Scaling, Optical Corrections.*

### 5. Screens and their states (web routes and Rune)

Every screen renders one `ViewState` of 27 section 4 through the desktop kit; `unreachable` is the daemon not responding (one sentence, the last known status with its age, and "Check health"). Registered banner patterns add 11's surface states **Degraded**, **Safe mode** and the **Stale** flag (with the condition code and the fix command); **managed** (enrolled: a "Managed by <organisation>" line, locked items with the lock icon and the layer that set them); and **agent caller** (opened from inside an agent session: read-only, mutations hidden). In the **User profile** every control is labelled "request", never "boundary", and 11's surface state `Protected` reads "On (requests only)" (SR-07). A screen with no data shows the `empty` state with a pre-filled suggestion, never a blank.

**First run.** Covered in section 9.

**Home.** The answer to "is it working, and does anything need me".
- Summary sentence: "Protected. 3 agents, 2 sessions running. 1 approval waiting." In the User profile the word is "On (requests only)" with a link to why; before protection is turned on it is "Scan only, not protecting". "Protected" is reserved for the Protected profile with every Tier 1 agent at AL2 or above (D-48: a control the agent can remove is not called protection); otherwise the sentence names the gap ("Protected, except Codex: hook not yet proven").
- Waiting approvals first, each opening `grdr-approve` for that request. *Applying: Prioritize Intent (pending decisions before status detail).*
- **Agents on this device** (the local inventory, 05): agent, version and whether it is in a tested range, assurance level with icon and label, 07's hook health state in words (for example `configured-not-effective` reads "Set up, but not firing", with its fix command), last session. Unknown programs appear as triage cards with three choices: "This is an agent", "Not an agent", "Decide later" (05 owns the triage semantics).
- Two tiles, each a sentence with a number, a comparison and one action (D-44): Blind spots ("Guardrails could not look at 1 agent today, 1 more than yesterday: Codex hooks are shadowed. Fix") and Prompt health ("Agents asked you 4 times today, 2 fewer than yesterday. Review rules"). Prompt figures are the person's own and shown only to them (D-51). *Applying: Meaningful Highlights.*
- Commands applied to this device (freeze, end session, kill) with issuer role, reason and expiry (18).

**My activity.** What my agents did.
- Session list grouped by day, filter chips Blocked, Asked, Would-be (Watch).
- Session detail: 18's timeline (phases collapsed, verdicts, provenance claimed or observed, gaps as "could not look"), with a table view of the session graph.
- **Why**, the `BlockCard` pattern shared with 27 section 4.10 and `grdr why`, titled by verdict from the presentation registry ("Why this was blocked", "Why this needs approval", "Why this was changed", "Why this was delayed"): who blocked (section 11), what (plain words, literal call one click away), rule name and pack, the rule's `@message`, what the agent was told, and one primary action chosen by the rule's mode (12 section 4):
  - Ask: names the approver in the presentation registry's words ("You", "Your team's sponsor", "An administrator", "Two approvers"); for self, "Review" opens `grdr-approve`; for anyone else the card shows the request state and the route timer (18);
  - Block, non-final, enrolled: "Request exception", which opens `grdr-approve` with the rule, the pattern and the session task summary pre-filled; the summary leaves the device only if the requester keeps it (18 section 11);
  - Block, non-final, standalone: "Allow this pattern", an Exception at the class's minimum grade in `grdr-approve`; in the User profile the disclosed D-31 time lock (default 10 minutes) stands in for G1 for the user's own local policy (R-11);
  - Block, final (`@final`): "Change mode", a widening proposal;
  - another component blocked: no exception button; a link explains where that component's setting lives.
  *Applying: Prioritize Intent (one next step, never a dead end); Ethical Friction on the widening routes.*
- Over 30 days of history or a free-text search: "Open in console".

**Rules (Simple only; 12).** Mode and lists, nothing else.
- Three presets: **Recommended** (selected by default: Essentials as shipped, every other pack in Watch, D-53), **Stricter** (destructive, secrets and egress packs at Ask), **Watch only** (lowers Essentials, so it is a widening proposal; the confirmation states what stops: "Guardrails will stop blocking writes to your agents' settings"). *Applying: Smart Defaults; Loss Aversion on the widening path.*
- Pack rows with the four-step mode control. Beside each mode the effective outcome for this device: boundary, request, or not enforceable, per action class (D-44).
- Promotion cards after seven days: "This would have asked you 4 times last week" with Promote and Not now (12 section 11).
- Active approvals and exceptions with expiry and Revoke (narrowing, no step-up). Snooze prompts (narrowing).
- "Add pack from git" pins a digest in the user layer (12 section 10); adding a forbid-only pack narrows.
- "Edit as code" opens the pack directory, or the web console's Code view (read-only here; the Advanced builder and editable Code belong to 27, section 4.13 and WEB-22).

**Privacy.** What is collected and who can read it; two clicks from the tray (R9).
- Capture level and, per data class, a live sample of this person's own most recent record (rendered inert).
- Where it goes: standalone "Nowhere. Only anonymous update checks to <the configured update sources> leave this device", naming each entry of `updates.sources` (or "Nothing leaves this device" when updates are off), followed by the `grdr egress` list; enrolled: the organisation, the roles that can read metadata and content, retention per class (D-51 defaults).
- Who looked: content views, evidence pulls and re-identifications of this person (`audit.access`, 18 section 7), with purpose and incident reference.
- Exclusions in force (paths, repositories). The screen cannot be removed by any layer, brand manifest or provider profile (SR-49). *Applying: Safety Principle (the monitored person can always check).*

**Settings.**
- Profile: Protected or User, with "Switch" (User to Protected needs one elevation; Protected to User is widening).
- Approvals: available grades on this device and authenticator enrolment, pre-selecting the platform authenticator the probe found (18). In the User profile this shows "G0 only", the classes of the person's own local policy where the time lock stands in for G1, and the rule classes that therefore block instead of asking (SR-07, D-31).
- Notifications: quiet hours, snooze, which toasts appear.
- Updates: on or off, update authority and the update sources (`updates.sources`: the project origin, a site mirror or any static file server; 22).
- Team: join, leave (section 12).
- Health (the target of "Check health" in the tray and in every `unreachable` state; the same report as `grdr doctor`): the rendered `grdr doctor --json` (11) and `grdr doctor hooks` (07), each condition with its code, severity, first-seen time and fix command, with a "Copy command" action; fixes that narrow or repair run from the screen, fixes that widen become proposals.
- Appearance and detail: theme (system, light, dark, high contrast), render tier, and "Show technical detail" (27 section 8). Language and region: language (shown in its own language, no flags, pre-selected from the OS); under More, regional formats, digits, 12- or 24-hour clock, time zone and UTC display, each defaulting to the OS. These are `grdr.ui.v1alpha1` `Preferences` and the user-layer settings `ui.locale` and `ui.time_zone`, which the tray, CLI, local console, `grdr-approve` and the browser extension all read.
- About: versions, Rune commit, "Open-source notices" (the same list as `grdr notices show`), the support-bundle preview.

### 6. Tray

`grdr-tray` implements our own `Shell` trait with three adapters: Windows `Shell_NotifyIcon` through the `windows` crate; macOS `NSStatusItem` through `objc2` on the main thread; Linux StatusNotifierItem over D-Bus through `zbus`. Menus are native. It holds one connection to the daemon's `local` endpoint and a `Subscribe` stream (11), and stays within 20 MB (03).

Icon states are the presentation registry's device states, each with its tray glyph: Protected, On (requests only), Scan only, Degraded, Safe mode, Stale, approval waiting (badge), Snoozed; each state differs by shape as well as colour; macOS template images, Windows light and dark taskbar variants, Linux icon names with pixmap fallback. Menu, top to bottom: status sentence (disabled item); "2 approvals waiting" with one item per request, each opening `grdr-approve` (the tray menu itself never approves, so the canonical action and arming delay are always shown); Open {short_name} (the brand manifest's short name; desktop app or console, by tier); My activity; Privacy; Snooze prompts (15 minutes, 30 minutes, 1 hour; 18 caps snooze at 60 minutes); Pause protection (widening, proposal); Check health; Quit tray, labelled "protection keeps running". The menu is `TrayVm` in `grdr-ui-model`: labels, order and targets come from the route table and the language tokens. In a right-to-left locale the tray sets each OS's right-to-left menu flag (D-69). *Applying: Safety Principle (conventional tray), Prioritize Intent (pending decisions first).*

On a Linux desktop with no StatusNotifierItem host (stock GNOME, brief 29), the tray runs without an icon, keeps notifications and deep links working, and installs a launcher entry; first run says so.

### 7. Approval helper screens

18 fixes content, grades and scope choices; this section fixes the surfaces.

| OS | G0 surface | G1 proof | G2 |
|---|---|---|---|
| Windows | Native task dialog | Windows Hello or FIDO2 key over the request digest | Protected profile only: the service launches the helper under SYSTEM on a separate desktop it creates and switches to, answer pipe restricted to that process, plus G1 (18). A helper merely at high integrity is not G2: an agent in an elevated terminal or a UIAccess process reaches high-integrity UI (brief 29, verification row 10). If S-16 fails, Windows G2 means a separate principal only |
| macOS | AppKit panel from the app bundle | Touch ID on a key that requires user presence, or FIDO2. A Secure Enclave key likely needs a signed app with keychain entitlements (unverified); in the build that ships without Apple's Developer Program (not platform-signed, D-18), G1 is FIDO2 only until that is checked | Not claimed locally: an agent host that already holds the Accessibility (TCC) grant can drive any same-user window (brief 29) |
| Linux | GTK 4 dialog (system library, dynamically linked; licence checked before adoption); terminal `grdr approvals` where GTK 4 is absent | polkit through the privileged helper on Wayland; FIDO2; X11 stays G0 | Not claimed locally |

In the User profile every row is G0, whatever the dialog collects, because the grant-signing key shares the agent's uid (SR-07); a rule class whose minimum is above G0 blocks there instead of asking, except that in the person's own local policy a disclosed time lock (default 10 minutes) stands in for G1 (D-31, R-11); a class needing G2 or G3 still blocks.

Rules: every approval surface (these dialogs, the terminal fallback, 27's approval card) renders one `ApprovalPrompt` value from `grdr-model`, built from the canonical action, with the same blocks in the same order (who; what, with the literal call one click away; why; what is new; choices) and the same labels (Deny, Allow once, Allow for this session, Allow for one hour); native dialogs keep OS styling and button placement, and content, order, labels, focus and keys never vary. Built with no Rune; capture exclusion on the window where the OS offers it; buttons arm after `approval-arm-default` (1 s) or `approval-arm-irreversible` (2 s); Deny has default focus and Escape is Deny; the window is shown without taking focus unless the requesting session's host is the foreground application. *Applying: Ethical Friction where stakes are high.* States: armed delay; grade proof in progress; superseded (a repeat raised `dedup_count`); expired (retry token lapsed); session ended; minimum grade unavailable (the dialog turns into the Exception route, never a dead end). Dialogs follow `ui.locale` and its direction (Windows `TDF_RTL_LAYOUT`, AppKit layout direction, GTK default direction); the canonical action always renders left-to-right in a monospace block with control and bidirectional characters visible.

Other dialogs: **Exception request** (rule, pattern, "this would have lifted N requests in the last 7 days", justification pre-filled from the session task); **widening confirmation** (the canonical diff, then the class's minimum grade proof; in the User profile, for the person's own local policy, the D-31 time lock countdown, default 10 minutes, cancellable from tray, CLI and console); **join confirmation** (server address and deployment-root fingerprint, SR-23).

### 8. Notifications and the prompt budget (the count needs only the daemon; toasts need the tray)

Toasts: Windows through WinRT toasts with the AUMID set by the installer's Start menu entry; macOS through `UNUserNotificationCenter` from the bundled tray app; Linux through `org.freedesktop.Notifications`. All live in `grdr-tray`. Classes are rows of `interface/notifications.toml` (18 section 10); this table is its device view, generated from it, and the approval prompt and the waiting toast are the device renderings of the class `approval.request`. Every toast renders one `NotificationVm`.

| Class | Counts against the budget | Rule |
|---|---|---|
| Approval prompt (`grdr-approve` shown for self) | Yes: 18's interruptive prompt | One per (rule, pattern, session); repeats raise a counter |
| Approval waiting toast (prompt not shown because the host is not in front) | No; the prompt counts when opened | One action, "Review", which opens `grdr-approve`. A toast never approves: it cannot show the canonical action or arm a delay |
| Block toast | No | Block-mode denials only; one per (rule, session) per 10 minutes; summary of repeats in the tray |
| Health | No | Degraded, `configured-not-effective`, Stale; once per condition per day |
| Promotion and digest | No | Never a toast; cards in Rules and Home |

Content rule: no command, path, host or prompt text in any notification, because notifications reach lock screens and notification history ("Claude Code was blocked from reading a credential file", not the path); toast text is a `notify.*` language token, and the compiler rejects any argument of data class `content` (D-69). Quiet hours and the OS focus mode suppress everything except approvals for a session the person is actively driving. Snooze (up to 60 minutes, 18) shows no new prompts; new requests are denied back to the agent with the `snoozed` message (section 11). After three prompts of the same shape in a session, the prompt marks "Allow for this session" as the suggested choice (Deny keeps default focus) and Rules shows a draft narrowing (18 section 4). *Applying: Chunking; Ethical Friction only where it protects.*

### 9. The first five minutes, no account

1. **Install**: a user archive with no elevation, or a system package whose installer is the one elevation (24). Signing follows 24 and D-18: every artefact carries a Sigstore keyless signature and SLSA provenance. Authenticode on Windows and notarisation on macOS need a vendor programme account in Loonaro's name; until one exists the release manifest marks those artefacts not platform-signed, Windows SmartScreen may warn once, and Gatekeeper asks the person to allow the app once, as the archive's instructions say. Either way the daemon starts in `scan-only` and nothing outside our own state directory changes (D-48).
2. **Scan** (`grdr init` or the First run screen): a read-only, unelevated scan of agents, MCP configuration and existing transcripts (D-24 passes 1 and 2) lists agents within 10 s and back-fills up to 30 days of sessions within 120 s (targets). Results stream in as skeleton rows that fill; the list is never empty while the scan runs.
3. **Show value**: agents found, last week's sessions, up to three things worth a look, and "Essentials would have blocked 2 actions and asked about 5 in the last 30 days", labelled as computed from the agents' own logs (claims, P3).
4. **Setup list** opens with Installed, Agents found and Last 30 days reviewed ticked: 3 of 6, so progress starts at 50%. Remaining: Turn on protection, Prove it works, Set up approvals. *Applying: Goal Gradient; Reciprocity before any change.*
5. **Turn on protection**: two choices, Protected pre-selected ("your agents cannot switch it off"; with "one administrator prompt" shown only when installed from a user archive, where `grdr protect` fetches the system package from the configured update source or takes `--from <bundle directory>`, 24) and User ("no administrator prompt; agents can remove it, so it only asks"). Choosing User first lists the rule classes whose minimum grade is above G0 and will therefore block instead of asking, or wait on the time lock in the person's own local policy (02, "Behaviour by deployment shape"; D-31). Before writing, a list of each file that will change, each expandable to its diff (l06 F8).
6. **Prove it works**: the next agent session's canary passes (07), which ticks the step and moves the agent to AL2 (labelled a request in the User profile).
7. **Set up approvals**: Protected: enrol the platform authenticator found by the probe, pre-selected. User: the step reads "Approvals here are clicks (G0)" and links to the classes that block; it is ticked on viewing.

Acceptance is the spine's first-value target (section 6): inventory, a session timeline and a deterministic block within five minutes on a clean machine, measured by the harness.

**The first `claude` session after protection is on.** The owner asked what happens after installing Guardrails and starting `claude`; this is the full answer, and `PLAN.md` section 3 carries the short version.

Read with 07 sections 6 and 15, the containment sections of 08 (5), 09 (4) and 10 (7), and DX-26.

**The short answer.** You install one package, click "Turn on protection" once, and then type `claude` as you always do. There is no new command and nothing else to install. Behind the scenes, Guardrails checks each tool call through the hook, runs shell commands inside a sandbox where Claude Code is cleared for it on your OS (step 5), and watches what really happens.

1. **Install one package.** The system package (MSI, pkg, deb or rpm) gives the Protected install, which asks for administrator rights once. The user archive gives the User install, with no administrator prompt. Guardrails' sandbox is inside that package and uses features the operating system already has, so there is nothing more to install for it. On a Mac without Apple's Developer Program the package and the user archive are not notarised, so macOS blocks the first start and you allow it once in System Settings; on Windows, until a signing programme signs the MSI, SmartScreen may warn once. On Linux, Claude Code's own sandbox needs two small system tools, bubblewrap and socat, and the deb and rpm packages pull them in as recommended packages (24). Ubuntu 24.04 and later also restrict a feature bubblewrap needs; where Claude Code's own sandbox cannot run, Guardrails uses its own sandbox for each shell command instead (step 5).
2. **First run changes nothing.** A read-only scan lists the agents it found and recent sessions.
3. **"Turn on protection"** offers Protected (pre-selected) or User, and shows each file it will change before writing. After the system package there is no further administrator prompt. If you installed the user archive and choose Protected, `grdr protect` installs the system package behind one administrator prompt. In the Protected install it then writes Claude Code's machine-wide settings file: our hooks, the blocks Claude Code can enforce itself, and safety switches such as bypass mode off. If your company manages Claude Code's settings centrally (MDM or server-managed policy), Guardrails gives that owner a settings fragment instead. In the User install it adds our entries to your own `~/.claude/settings.json`, which the agent can edit. Essentials, the small pack that blocks from the start (D-53), is on from here. The hooks count as working only once Guardrails sees them fire in your next session.
4. **You start a new `claude` session as usual.** Each hooked tool call goes through the hook. The sensor watches what really happens: on Linux through eBPF, on Windows through kernel ETW, and in the User install through less detailed polling. On macOS without Endpoint Security it cannot see programs start, so programs and files stay `claimed` and the agent's transcript is the cross-check. A session that was already running when you turned protection on is tracked, but stays at request level until you restart it.
5. **Shell commands run in a sandbox, with no new command.** This applies where Claude Code is cleared for the sandbox on your OS. For each agent and OS the sandbox is a switch, and it becomes the default once a set of everyday developer tasks passes inside it (Windows also needs spike S-10). On macOS and Linux, Guardrails switches on Claude Code's own sandbox and locks it, so commands cannot run outside it (`allowUnsandboxedCommands: false`). Linux checks that each command really is inside it; macOS below tier 3 takes Claude Code's word for it. On macOS and Linux, spike S-11 settles whether Claude Code keeps this mode (step 6). On Windows, in the Protected install only, the hook rewrites each shell command to run through `grdr-run`, in our sandbox inside the session's job. On a Linux host where Claude Code's own sandbox cannot run, the hook rewrites each shell command into our Landlock sandbox instead, which needs no extra tool, no user namespace and no administrator rights; on a host where user namespaces are blocked its network fence holds only once the `cgroup_sock` program has passed its review, and otherwise network rules for those commands are requests (10 section 7). Each session is checked first. If the sandbox cannot start, commands run unsandboxed at request level, and Guardrails shows why. Claude Code's Read, Edit and Write tools, local MCP servers, hooks and language servers (LSP) run outside either sandbox. The hook checks them (and the MCP broker, where a server entry is wrapped), as does a kernel tier where one is enforcing, but they are not sandboxed.
6. **The whole agent in the sandbox.** Running the whole agent in our sandbox also covers its file tools and MCP servers. It is for agents with no sandbox of their own, and for agents whose own sandbox still works inside ours, which spike S-11 checks (D-21). `grdr run --contain -- claude` asks for it. On macOS and Linux, Claude Code keeps its own locked sandbox for shell commands (step 5) unless S-11 shows that sandbox works inside ours. On Windows Claude Code has no sandbox of its own, but its default there is the per-command sandbox of step 5 (D-17, 08 section 5), so the whole agent goes in our sandbox only when you start it with `grdr run --contain`. Where the agent is cleared for the sandbox on your OS and whole-agent containment is its mode there, turning on protection in the Protected install does it for you, and you can reverse that per agent (`PLAN.md` section 13). Guardrails then puts a link to our launcher, named after the agent's command, early on the system `PATH`. For Claude Code on macOS and Linux it also sets Claude Code's own launcher setting (`processWrapper`), so its background sessions start in the sandbox too; Claude Code ignores that setting on Windows. A start that misses the link runs without whole-agent containment (its shell commands are still sandboxed per command where step 5 applies) and raises `launcher-bypassed`. That happens when an IDE chat panel starts its own copy, when a full path is typed, or when a shell profile puts the agent's folder first. `grdr doctor` names the cause and prints a line you can add to your shell profile; Guardrails never edits it.
7. **Agents started from an IDE** get the same hooks and settings, so their shell commands are sandboxed the same way where step 5 applies. An IDE mixes your actions and the agent's in one program. Guardrails counts an action as the agent's only when it can tie it to a specific tool call. Actions it cannot tie are `undetermined`: agent rules do not block them at the OS, and they are not called tampering. `grdr run --contain` cannot wrap these sessions. Typing `claude` in an IDE's built-in terminal is an ordinary terminal start.
8. **Only a layer that covers the whole OS reaches every start**, however the agent was launched. That is a kernel tier (Linux after review, macOS tier 3, the Windows driver), the macOS content filter for network (tier 2), or a gateway that is the only way out. Each is on only once its precondition is met: once Linux kernel enforcement has passed its review, the probe selects it in the Protected install; macOS tier 2 needs Apple's Developer Program and your approval, and tier 3 also the entitlement; the Windows driver is optional and ships separately; a gateway as the only way out is opt-in.

### 10. The command line

Conventions are 23 section 11's (grammar, `--json`, the error object, exit codes), generated from `interface/cli.toml`; this document adds none. `NO_COLOR` and `--plain` are honoured and colour never carries meaning alone. Human-readable output follows `--lang`, `GRDR_LANG`, `ui.locale`, `LC_ALL`, `LC_MESSAGES`, `LANG`, then English (`C` and `POSIX` mean English); `--json`, exit codes, codes, ids, paths and commands never change with the locale, and with `meta.agentCaller` set all output is English. Columns align by display width (`unicode-width`) and wrap at ICU4X grapheme and line-break boundaries. A command, path or id the person may copy is a separate token with no bidi control characters. In a right-to-left locale, localised text prints only where the terminal implements bidi (VTE 0.58 or later, mintty, or `GRDR_TERMINAL_BIDI=1`), and English otherwise.

| Command | Does | Notes |
|---|---|---|
| `grdr init` | Section 9 in the terminal | `grdr scan` is the read-only half (05) |
| `grdr protect [--package <file> \| --from <bundle directory>]` | Installs the system package (from the configured update source, a file or an air-gap bundle directory) behind one administrator prompt and switches to the Protected profile | 24; the OS installer raises the one elevation prompt |
| `grdr status [--assurance]` | One summary line, then one line per agent | Reads the spool when the daemon is down (07) |
| `grdr why [--last \| <reference> \| --session <reference>]` | Explains one decision: component, rule, reason, what the agent was told, the next command; the same receipt view as the block card and 27 section 4.10 | From inside an agent session it returns only the agent-facing message for that session |
| `grdr run [--contain] -- <command>` | Launches into a session container; `--contain` per D-21 | Front end for `grdr-run` (03); requires the launcher |
| `grdr doctor [hooks\|perf]` | 11's doctor | Works with the daemon down |
| `grdr policy test\|check\|fmt\|replay\|diff\|explain\|apply` | 12's semantics; `apply` stages a narrowing change and turns a widening one (by 12's semantic diff, a timeout counting as widening) into a proposal | Inside an agent session: `test`, `check` and `fmt` work only on pack directories under the session workspace, never on the installed bundle; `replay` is refused (D-38) |
| `grdr mode set <pack> <Off\|Watch\|Ask\|Block>` | Quick Mode change; the CLI takes the English Mode identifiers in every locale | Up is applied and staged; down is a proposal |
| `grdr approvals list\|show\|approve\|deny`, `grdr exceptions list\|show\|request\|revoke` | `approve` records G0 from outside agent lineage (18) where the rule's minimum is G0; otherwise it opens `grdr-approve` for the grade proof | Refused from agent lineage |
| `grdr prompts snooze <duration>`, `grdr protection pause <duration>` | Snooze (at most 60 minutes) narrows; pause is a widening proposal | |
| `grdr sessions list\|show`, `grdr actions tail` | Local history | |
| `grdr privacy show\|log` | The Privacy screen as text | Cannot be disabled |
| `grdr console open` | Starts `grdr console serve` on demand and opens the local console with a one-time launch token | |
| `grdr join\|leave\|uninstall` | Section 12; D-48 | Step-ups (SR-23) |
| `grdr egress`, `grdr support-bundle --preview`, `grdr audit verify` | 11 and D-39 | |
| `grdr operator config export\|apply`, `grdr operator status` | The operator plane's configuration as code and health, against a server's operator listener (23 section 15, D-70) | An operator account, never a console session |

Example:

```text
$ grdr why --last
Held for approval 14:02:11 BST by Guardrails ADR (local policy), ref 7Q2MK-X4D9PJ
Agent    claude-code 2.1.319, session 8F2KQ-M41TZW, repository web-app
Approver You
Action   file.read  ~/.aws/credentials
Rule     essentials.cred-store.read  (pack grdr.essentials, Mode Ask)
Reason   Reading credential stores and private keys needs your approval.
Told     Approval requested; retry the identical call after approval.
Next     grdr approvals list    (approve with Touch ID, G1)
```

The product name comes from the brand manifest, references use 34 section 7's form, and every label and sentence is a language token.

### 11. What the agent is told

07 carries the message in `reason`; 12 supplies `@message` and `@steer`. This section fixes the shape. Every agent-facing message is English, plain text, at most 600 characters, with no Markdown, links, policy text, grant state or exception routes (D-38), and has three lines:

```text
<product name> <blocked|held|changed|delayed> this <action class> [<code>; rule <rule id>; ref <reference>].
Reason: <the rule's @message>.
Next: <one sentence chosen by next-step kind>.
```

The product name comes from the brand manifest (D-66, ARCH-009). Every sentence of this section is an `agent.*` language token: English, never translated, typed and capped like every other token (D-69). The engine renders it once into the `BlockNotice` (the shim's fail-safe text is rendered when the table is compiled), so every control point (hook translators, proxy, MCP broker, gateway, extension) passes the same text; the same decision's person-facing text is `person_text`, rendered in the person's `ui.locale` (34 section 7). Each kind is registered against the verdict that produces it, so every verdict in the spine's set has a defined message:

| Next-step kind | Verdict | Sentence |
|---|---|---|
| `retry-after-approval` | `STEP_UP` | "Approval was requested from <approver>. Do not try a different command, path or tool to reach the same result. When you are told it was approved, retry the identical call once." |
| `use-alternative` | `DENY` | The rule's `@steer` text, for example "If you need a token, use the configured credential helper." |
| `blocked` | `DENY` | "This is not allowed here. Do not retry or work around it. Tell the user what you were trying to do." |
| `snoozed` | `STEP_UP` executed as deny | "The user has paused approval requests until <time>. Continue with other work, or stop and tell the user." |
| `frozen` | `DENY` | "This session is frozen after repeated refused requests. Stop and tell the user." |
| `offline-rule` | `DENY` from the shim's fail-safe table | "<product name> is using its offline rule set. Tell the user to run grdr doctor." |
| `retry-later` | `DEFER` | "Retry in <n> seconds." |
| `modified` | `MODIFY` | "This call was changed before it ran: <the rule's @message>. Do not resend the original." |

`ALLOW` sends nothing. `<approver>` is the presentation registry's English word for the agent audience, so the agent and the person name the same approver.

The approval outcome reaches the agent at its next hook event through `additionalContext` where the dialect supports it (Claude Code and Codex; 18 step 6): "<product name>: request <ref> was approved. Retry the identical call once." (the grant's scope and expiry are never told, D-38) or "...was declined. Do not retry." Watch-mode would-be verdicts are never shown to the agent. The person-facing text names the component that blocked: ours (brand manifest name); the agent's own permission system or classifier when its telemetry says so (for example Claude Code's `tool_decision` source); or another security product only when the slot broker found one installed and the evidence matches, phrased "possibly" unless that product's telemetry confirms it. Software that is not installed is never blamed (h08).

### 12. From one user to a team, without migration

Standalone already writes everything a server needs: a random organisation id, device-side pseudonyms from an install-time key (after joining, the server re-pseudonymises at ingest with a key the device never holds, D-51), and the `local` (device) and `user` policy layers (04, 12). `grdr join` (requires the server; standalone needs nothing beyond the alias seam) then:

1. Opens Settings, Team, with the server address pre-filled from an invite deep link (`grdr://open/settings/team?server=<address>`, which only navigates and fills that one field). The join code is pasted, never carried in a link.
2. Shows **What changes**: capture level, the roles that will read metadata and content, the rules that become locked (by pack, with mode), retention, and "History from before today stays on this device". Back-fill is an explicit choice, off by default.
3. Runs the join step-up in `grdr-approve` with the server address and deployment-root fingerprint (SR-23).
4. Records the local organisation id as an alias, so chains and receipts verify unchanged (D-48). Local settings become the user layer under the organisation's layers.

Afterwards screens show "Managed by <organisation>", Rules shows locks, Privacy lists the readers; `grdr leave` restores standalone after the leave step-up at the minimum grade the organisation set (SR-23). A team without a server shares a pack by git URL pinned to a digest. Single-user, IT-managed and provider-managed devices run the same screens. A provider branding profile may change accent and logo, never mode and status colours, vocabulary or the Privacy screen (SR-49). *Applying: Safety; one meaning across brands.*

### 13. Accessibility and internationalisation

Accessibility. Target WCAG 2.2 AA on desktop with a separate VPAT 2.5Rev INT report per release line (brief 30). Rune exposes AccessKit trees on all three systems by default (brief 29). Requirements: full keyboard path including every dialog; visible focus never obscured; 32 by 32 px minimum targets (27's product minimum, above WCAG 2.5.8's 24); 4.5:1 text contrast; no drag-only interaction; graphs always with a table equivalent; OS reduced motion and high contrast honoured, with a generated high-contrast theme because Rune's forced-colours support is unverified. Native approval dialogs inherit the platform's own accessibility. Known risk: a macOS AccessKit reentrancy abort is open upstream (#150). The accessibility tree also lets same-user processes press desktop buttons (brief 29, verification row 1); that is acceptable only because a pressed button can at most narrow or raise a proposal whose proof is collected in `grdr-approve`, which Rune never draws (SR-04).

Internationalisation. D-69 is the system and 34 section 15a the workflow; this is the desktop's part. `grdr-ui-model`, the tray, the CLI and `grdr-approve` link `grdr-messages` and format through `grdr-strings` (ICU4X 2.4 with baked data for the shipped locales); none parses a catalogue at run time, and none uses `rune-i18n`'s format, because a second format would split the source. `grdr-desktop` uses only rune-kit components whose text the app sets, because rune-kit's own strings are fixed English (#396). `en-XA` and `ja-XC` run on every screen headless; `ar-XB` runs to prove placeholders stay isolated. Until Rune #244 closes, a right-to-left UI locale selects the Web tier (section 2), so a right-to-left reader always gets a mirrored window; the tray and `grdr-approve` mirror through the OS. Codes, rule ids, Cedar identifiers and CLI tokens are never translated; Mode labels are translated in the interface and the CLI takes the English identifiers. Agent-facing messages stay English. Desktop text uses 27 section 10's script token sets; endpoint packages embed Inter and JetBrains Mono only, other scripts use OS fonts, and a missing script font raises the health condition `font-missing`, scoped to the script, with its fix.

### 14. Autostart, single instance, deep links, packaging

| | Windows | macOS | Linux |
|---|---|---|---|
| Package (24 builds and signs) | MSI features `Tray` and `Desktop` (24), Sigstore-signed and Authenticode-signed once a free signing programme account exists (until then marked not platform-signed); optional components are off by default there, so an interactive install offers both pre-ticked in the UI sequence while silent installs take them only by property | Universal pkg with one app bundle (`/Applications/<brand>.app`): the tray as a menu-bar agent app, the Rune window binary inside it as a pkg choice; Sigstore-signed, and signed and notarised only with Apple's Developer Program, otherwise not platform-signed (D-18) | Tray in the main deb and rpm; `grdr-desktop` as its own package recommending `mesa-vulkan-drivers` |
| User archive (User profile, 24) | Tray and desktop binaries included; autostart written by `grdr init` only after the person turns protection on | Same | Same |
| Tray autostart | Machine Run key (Protected) or per-user Run key (User) | LaunchAgent in `/Library/LaunchAgents` limited to GUI sessions (Protected); login item through `SMAppService` (User; whether it registers an unsigned app is unverified, and the fallback is a LaunchAgent in `~/Library/LaunchAgents`) | `/etc/xdg/autostart` (Protected) or `~/.config/autostart` (User) |
| Single instance | Named mutex per logon session; a second launch forwards its arguments over a per-user named pipe owned by the tray | Launch Services | Lock file and forwarding socket in the per-user runtime directory |
| Deep links `grdr://` (the `grdr` technical namespace, which D-66 keeps) | URL protocol registered by the MSI | URL type in the bundle | `x-scheme-handler` in the desktop entry |

Installer dialogs take their text from the language tokens (generated `.wxl` files for the MSI and localised strings for the pkg) and their artwork from the token outputs.

Deep links only navigate: `grdr://open/<route>[/<id>]`, with one permitted parameter (`server`, the join pre-fill of section 12), and `grdr://approval/<request id>`, which opens `grdr-approve` for an existing request. A deep link never decides, widens or carries a credential or join code. A user who disables tray autostart has made their own choice; the daemon records `tray-absent` and the CLI and console still disclose everything (SR-49 binds operators and brands, not the person). Flatpak and Snap are not offered (their sandboxes block the daemon socket); trigger to revisit: a distribution partner asks. Uninstall removes autostart entries, URL handlers and the desktop entry, and the residue report lists them (11).

### 15. Theming from the shared tokens

27 owns the DTCG token source in `interface/tokens/` (primitive, semantic, component; light, dark, high contrast; script sets; brand overrides in `brand/tokens/`). This document owns the desktop emitters, run by Style Dictionary in CI:

1. Rune theme JSON (keys `name`, `blend`, `palette`, `light`, `dark`, `numbers`, read by `Theme::from_json`; colours as `#rrggbbaa`) and a generated Rust module filling rune-kit's typed `Kit` (palette, elevation, type, radius, motion, glyphs), because rune-kit components read `Kit`, not the JSON (brief 30, verification row 10). The value semantics of `blend` are read from the pinned commit's `theme.rs` when the emitter is written.
2. Spacing, radius and type constants for `grdr-ui-model`, including the per-script token sets of 27 section 10, selected by the UI locale's script.
3. Tray icon rasters and template images per status.
4. Motion intents as Rune springs whose settle time equals the intent's duration token, with a zero-motion variant for Lite.
5. Behaviour constants for `grdr-approve` (`approval-arm-default`, `approval-arm-irreversible`, minimum target size).

Conversions: rem to logical px at a 16 px root; colours to 8-digit sRGB hex. The emitter is versioned against the pinned Rune commit. A runtime tenant theme (accent, neutrals, radius, logo) is a signed configuration item that 27 section 10's theme validator rejects unless its contrast pairs pass AA and it overrides no locked token (brief 30). Native dialogs (`grdr-approve`) use OS styling only, so the approval surface always looks like the operating system. *Applying: Safety Principle.*

## Interfaces and contracts

| Interface | Shape | Other party |
|---|---|---|
| `grdr.local.v1alpha1` `Status`, `Explain`, `Propose`, `Query`, `Subscribe` | Consumed as defined | 11 |
| `grdr.ui.v1alpha1` view-models | `ViewState`, `Preferences`, `TrayVm`, `NotificationVm` and one view-model per screen; generated JSON Schema; `/vm/<route>`, `/vm/intent`, SSE stream, behind the launch token | 27 renders it |
| Agent message template and next-step kinds | Section 11; `agent.*` language tokens (D-69); codes registered in `grdr-schema` | 07 translators, 12 annotations |
| Approval dialogs | Request rendering from the canonical action; grade proof returned to the daemon | 18, 12 |
| CLI grammar, JSON envelope and exit codes | 23 section 11, generated from `interface/cli.toml` | Every CLI-owning document (05, 07, 11, 12, 18, 24) |
| Health codes added | `desktop-budget-exceeded`, `tray-absent`, `render-tier-web`, `font-missing` (scoped to a script); and the finding `launcher-bypassed`, a coverage gap raised at agent start when the agent's mode is wrap-agent and the launcher is not in its ancestry (DX-26, D-21) | 11's registry; 07 section 9 for `launcher-bypassed` |
| Deep-link scheme | Section 14 | 24 registers it |
| Token emitter outputs | Section 15 | 27 owns the source |
| Archlint ARCH-016 `rune-leaf` (R-21) | `rune` and `wgpu` only under `grdr-desktop` | 03 |
| `desktop/rune.lock.toml`, `desktop/rune-patches/` | Pin and patch queue | 24 (release inputs), D-63 gate |

## Behaviour by deployment shape

- **Standalone.** All surfaces as described; Exceptions take the self route at the class's minimum grade, with the time lock standing in for G1 only in the User profile (D-31); Privacy says only anonymous update checks to the configured update sources leave the device, or nothing when updates are off.
- **Platform, self-hosted or hosted.** Same binaries. Approvals for sponsor, admin or quorum route to the server (18); the local "Request exception" goes there. Locked rules show their layer. Hosted and provider deployments add an organisation-signature requirement for widening (D-31), which the desktop shows as "Needs your organisation's approval". Self-hosting is the default way to run the platform; the hosted service requires its own preconditions, including infrastructure funded by revenue, sponsorship or donated cloud credits (D-63), and the desktop behaves the same against either.
- **Embedded.** A host vendor ships its own interface; the CLI and `grdr-approve` are optional components. Conformance marks still require a disclosure surface equivalent to Privacy (SR-49). A co-branded build changes names and accent through the brand manifest only.

## Extension points

- **Translations**: language-token files in the main repository, written by `impl-l10n` and corrected by anyone through pull requests; D-69's gates decide (placeholders, plural categories, glossary, length, back-translation by `eval-l10n`, pseudo-locale and screenshot runs), with no required human review (34 section 15a).
- **Renderers**: any process holding a launch token can read `grdr.ui.v1alpha1` through the local console, for example an IDE panel; it inherits the propose-only rule and the refusal from session containers (SR-03).
- **Brands and tenant themes**: token documents, validated by 27 section 10's theme validator (contrast, locked tokens); never code.
- **CLI output**: `--json` is the integration surface; there are no CLI plugins, because a plugin would be third-party code in a security tool's trusted path.

## Security and privacy

- The CLI, local console, tray and desktop app are untrusted (D-20): widening only as proposals, every mutation refused from session containers (SR-04, oracle S-17). `grdr-approve` is trust core (D-63) and the only local surface that returns a grade proof. Rune is patched, environment-scrubbed, sandboxed and never shows an approval (brief 29, rows 1 and 2).
- Agent-written text is inert everywhere (SR-36); notifications carry no content; no surface reads the clipboard. The view-model endpoint shares the console's launch-token, Host and Origin checks (SR-03).
- A person's own prompt figures are shown only to that person; nothing ranks or compares people (D-51). The disclosure floor holds in every brand and layer (SR-49).

## Test and evaluation strategy

| Property | Test | Oracle |
|---|---|---|
| First value in five minutes | Clean VM per OS with seeded transcripts; scripted person through the platform accessibility API | Harness clock; expected agents and sessions from the fixture |
| Block explanation within 1 s | Harness-driven deny at Block and STEP_UP | Receipt timestamp against the agent's received message and the local console's Home update, and, where the tray runs, the toast-posted time from the OS notification log |
| Disclosure floor | Brand manifest, provider profile and every layer setting that touches Privacy, applied in turn | Privacy route and tray item still reachable in two clicks; `grdr privacy show` still answers |
| Prompt budget | Benign corpus replay per pack preset | Count of `grdr-approve` prompts against 18's definition: median 3 or fewer and p95 8 or fewer per developer-day (target) for Recommended |
| No widening from local surfaces | S-17 with real agents using CLI, tray, deep links, loopback and accessibility actions | Effective-policy diff computed outside the product: zero |
| Approval surfaces | S-16 | Grants minted against the scripted person's approvals: zero excess |
| Headless flags gone | Release build launched with `--script`, `--tree`, `--snap` | No file written, no input replayed, process behaves as plain launch |
| Rune soak | Section 2, on tier B self-hosted runners; cells without a machine marked "requires hardware" | OS performance counters, not Rune's |
| Render-tier fallback | Forced WARP, lavapipe, RDP | Console open within 2 s, no Rune window created |
| Renderer parity | Same view-model golden rendered by the Rune headless runtime, the web route and `term` | Same accessible names and roles per element id; the same words per field in the terminal |
| View-models | Unit tests of `reduce` | Expected effects per intent |
| Accessibility | AccessKit goldens; keyboard-only scripted flows; Guidepup journeys driving NVDA on hosted Windows runners and VoiceOver on hosted macOS runners (U09); a person's Narrator or Orca pass adds evidence when someone is available and never gates | Accessibility Insights, Accessibility Inspector, Accerciser findings: zero AA failures |
| Localisation | Every screen in `en-XA`, `ja-XC`, `ar-XB` and each shipped locale, headless and on the web route; the U11 parity corpus | No truncation flags; no shipped-locale token without a current translation; placeholders isolated in `ar-XB`; parity differences only those in `parity-allow.toml` |
| Agent steering | Model-driven efficacy scenarios: denial with our message against a bare deny, run on the owner's Claude subscription within a usage cap per run (D-47) | Pivot-after-denial detection rate and identical-retry rate (D-45 harness) |
| CLI contract | Golden envelopes, schema validation, exit codes | Generated schemas |
| Protect from a bundle | 24-29 in a VM with no route out | `grdr protect --from <bundle directory>` reaches the Protected profile; an MSI absent from the bundle's targets is refused |
| Uninstall | Install, use, uninstall on each OS | Zero residue: autostart, URL handler, desktop entry |

## Work breakdown

**E1 View-models and the web contract**
- DX-01 `grdr-ui-model` with the six screens, intents, paging store. *Accept:* builds for `wasm32` and native with no `rune` in its closure; ARCH-016 `rune-leaf` passes; `reduce` unit tests cover every intent; every screen's view-model carries exactly one `ViewState`.
- DX-02 `grdr.ui.v1alpha1` served by `grdr console serve`. *Requires:* DX-01. *Accept:* JSON Schema generated; SSE updates within 500 ms of a daemon state change; SR-03 tests green.

**E2 Command line**
- DX-03 Envelope, exit codes, agent-caller rules. *Accept:* every command's `--json` validates; mutation from a session container exits 4 and writes `audit.admin`, except `grdr policy apply` and `grdr exceptions request`, which propose and exit 3 (23 section 11).
- DX-04 `status`, `why`, `doctor` rendering, `policy test` workspace restriction. *Accept:* `why` from agent lineage returns only the agent message; `policy test` against the installed bundle from agent lineage exits 4.
- DX-05 `grdr run` front end. *Requires:* the launcher (`grdr-run`, 03). *Accept:* a session container is created and named in `grdr status`; with `--contain`, an agent whose probe fails runs at request level and the command prints the probe's stated reason (D-21).
- DX-26 Terminal starts contained without typing `grdr run`: a link to `grdr-run` named after the agent's command, in our own directory early on the system `PATH`, plus the agent's own process-wrapper setting where one exists. *Requires:* DX-05; the install channel (07 section 6, D-49); a catalogue entry that makes wrap-agent the agent's mode on that OS, with containment on for it there (S-11; on Windows also S-10). *Accept:* in the Protected profile, after "Turn on protection", typing the agent's command in a new bash, zsh, fish, PowerShell or cmd terminal, and a script that calls it by name, each start a session that `grdr status` shows as launched and contained; where the agent has a process-wrapper setting (Claude Code's `processWrapper` on macOS and Linux), it is written through 07's owner-aware installer and the agent's background sessions also start contained; argv, working directory and inherited environment reach the agent unchanged, nothing is written to the terminal before it starts, its exec happens inside the deadline its adapter declares (about 3 s for Claude Code, which may run the launcher three times in series), and its exit code reaches the caller; the link skips its own directory when it resolves the agent, and a start from inside a contained session stays in that session with no second container; when the daemon does not answer, the probe fails or the agent version is outside the tested range, the agent still starts, uncontained, with the reason recorded (D-21); a start of the agent seen without the launcher in its ancestry raises `launcher-bypassed`, and `grdr doctor` names the cause (for example a `PATH` entry ahead of ours) and prints the line the person may add to their own shell profile, which we never write (D-27); an agent-start failure after any of these writes rolls back from the journal and halts the ring; turning the link and the setting off for an agent is a widening change under D-31; nothing changes before "Turn on protection" (DX-08); the link and the setting stay valid across our own updates and rollbacks; after `grdr uninstall` the agent starts from the terminal and from its own background service, with a zero byte diff on an untouched machine (D-48).

**E3 Approval helper**
- DX-06 Native dialogs per OS, armed delay, focus rule, states. *Accept:* S-16 vectors produce no grant, including an agent in an elevated terminal and a UIAccess process against the Windows G2 helper; buttons inert for 1 s and 2 s; a canonical call with bidi characters shows them; every User-profile grant records G0.
- DX-07 Exception, widening countdown and join dialogs. *Accept:* countdown cancellable from three surfaces; join shows the fingerprint.

**E4 First run**
- DX-08 `grdr init` and First run route. *Accept:* first value (spine section 6) in five minutes on clean Linux and macOS from both artefact families; setup list starts at 3 of 6; no file outside our own state directory changes before "Turn on protection" (byte diff); choosing User lists every class above G0 that will block.

**E5 Rune dependency**
- DX-09 S-19 spike. *Accept:* section 2 soak numbers on three OS, on tier B machines, with any cell lacking a machine reported as "requires hardware"; adapter type readable or patch 2 written.
- DX-10 Mirror, lock file, patch queue with patches 1 to 3. *Accept:* headless-flag negative test green; environment switches ignored; queue-cap check fails CI above 10 patches or 1,500 lines.
- DX-11 Bump job, soak rig and headless suite. *Requires:* DX-10; tier B self-hosted runners for the soak rig (D-64). *Accept:* a bump without a green 48-hour soak, green `--tree` goldens on three systems, green lavapipe `--snap` goldens, a passing `eval-security` review of the upstream diff and an `eval-ux` verdict cannot merge.

**E6 Desktop app**
- DX-12 Six screens in Rune at Full and Lite. *Requires:* DX-01, DX-10 and a passing S-19 (DX-09). *Accept:* parity test green; window budget met; relaunch on `desktop-budget-exceeded` preserves route.
- DX-13 Desktop sandbox profile per OS. *Accept:* window process cannot open a socket other than the daemon endpoint or write outside its state directory.

**E7 Tray and notifications**
- DX-14 `Shell` adapters for three OS, menu, icon states. *Accept:* no `rune`, `wgpu`, `winit` in closure; under 20 MB; Privacy reachable in two clicks.
- DX-15 Toasts and budget rules. *Requires:* DX-14. *Accept:* block toasts collapse per rule and session; no content string in any notification payload (canary strings test).

**E8 Accessibility and localisation**
- DX-16 Desktop use of the language tokens: `grdr-messages` in `grdr-ui-model`, the tray, the CLI and `grdr-approve`; pseudo-locale runs headless. *Requires:* WI-0041. *Accept:* a call to a missing token, a missing argument or a wrongly typed argument fails `cargo check`; `en-XA` and `ja-XC` pass on every screen headless; `ar-XB` proves placeholders isolated.
- DX-17 Desktop VPAT evidence. *Requires:* DX-12. *Accept:* zero AA failures in the AccessKit goldens and the U09 journeys; report published.

**E9 Packaging**
- DX-18 Autostart, single instance and deep links per OS. *Accept:* deep link to an approval opens the dialog and decides nothing; uninstall residue zero.

**E10 Team growth**
- DX-19 Alias seam and "What changes" view-model. *Accept:* local receipts verify after a simulated join.
- DX-20 Join and leave screens against the server. *Requires:* the server's enrolment (22) and DX-19. *Accept:* back-fill off by default; locked rules shown before the step-up.

**E11 Agent steering**
- DX-21 Message template and next-step kinds in the translators. *Accept:* every non-ALLOW receipt has a kind matching its verdict; messages under 600 characters; no product name outside the brand manifest; harness pivot rate lower than the bare-deny control with significance reported; the comparison runs within a usage cap per run and pauses rather than fails at a subscription usage limit (D-47).

**E12 Theming**
- DX-24 Token emitter for `grdr-ui-model` constants and the generated high-contrast theme. *Accept:* a spacing value outside 27 section 10's scale fails the build; every text and icon pair passes 4.5:1 in light, dark and high contrast.
- DX-25 Rune theme JSON, `Kit` module and tray rasters. *Requires:* DX-10 (the pinned commit). *Accept:* emitter output loads in `Theme::from_json` at the pinned commit; a tenant theme failing AA is rejected; mode and status tokens cannot be overridden.

**E13 Brands and text direction**
- DX-22 Provider branding profile on desktop. *Requires:* the provider tier (D-35). Seam: locked mode and status tokens. *Accept:* a profile that changes a mode or status token, vocabulary or the Privacy route is rejected.
- DX-23 Right-to-left in the Rune app. *Requires:* Rune #244 closed upstream (external precondition). Seam: the generated locale direction table; until then the Web tier serves right-to-left locales (section 2). *Accept:* every screen passes a mirrored-layout golden in `ar-XB` and `ar`; the Web-tier rule for right-to-left locales is removed.

## Risks, open questions and spikes

| Item | Response |
|---|---|
| Rune idle CPU and memory on Windows (#218, #430) fail the soak | Lite tier, relaunch watchdog; two failures trigger Web tier (D-43) |
| Remote-session detection on macOS and Linux is unreliable | DX-S1: test screen-sharing and VNC sessions; until solved, the first window probe decides |
| AppContainer breaks DX12 for the window | DX-S2: run the app in AppContainer on two GPU vendors; fallback restricted token |
| Rune renders Lucide glyphs badly or has no vector path | DX-S3: render all used icons at 1x and 2x in the headless runtime; fallback rasters from the emitter |
| GNOME without a StatusNotifierItem host hides tray status | Launcher entry and notifications; first run states it |
| GTK 4 dependency on minimal Linux desktops | Terminal fallback; measure share on tier B machines and the hosted Linux runners |
| Does the steer text change agent behaviour? | DX-21's controlled comparison settles it |
| Open: should the desktop app be offered at all in User profile installs, given request-level controls? | Default yes; revisit with S-19 usage data |

## Deviations from the spine and objections

1. **Ordering of D-43.** Resolved by R-33 and spine v4: the Rune app requires the view-model crate and S-19; the local console and tray require only the daemon's local API, as this document already had.
2. **Endpoint footprint target.** Resolved in spine v3: the section 6 footprint row excludes the on-demand Rune window, which keeps its own budget (section 2).
3. **Self Exception in standalone.** Resolved by R-11: D-31 accepts the disclosed time lock in place of G1 for the user's own local policy in the User profile only; in the Protected profile the route uses the class's minimum grade.

Not a deviation: 18 lists a tray click as G0. The spine defines G0 as a same-user click in `grdr-approve` (or a command run outside any agent session), and the agent's own prompt is never an approval; every tray approval item opens `grdr-approve`, so the canonical action and the arming delay are always shown.

## Sources

Research briefs: `research/29-rune.md`, `research/33-ux-personas.md`, `research/30-web-stack.md`, `research/15-coding-agent-surfaces.md`, `research/36-response-operations.md`, `research/35-data-secrets.md`, `research/h08-practitioner-voice.md`. Review notes: `design/_review/c7-interfaces-ux.md`, `l06-solo-developer.md`, `l07-privacy-works-council.md`, `l04-it-endpoint-engineer.md`, `00-resolution.md`.

Primary URLs: https://github.com/anomalyco/rune (README, `crates/rune/README.md`, `tooling/args.rs`, `a11y/actions.rs`, `gpu/pick.rs`, `tray.rs`, `theme.rs`; issues #150, #162, #203, #218, #244, #293, #296, #305, #334, #396, #430); https://github.com/anomalyco/rune/blob/dev/crates/rune-kit/README.md; https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-securityoverview; https://support.apple.com/guide/mac-help/allow-accessibility-apps-to-access-your-mac-mh43185/mac; https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/; https://www.itic.org/policy/accessibility/vpat; https://www.designtokens.org/tr/drafts/format/; https://code.claude.com/docs/en/hooks; https://raw.githubusercontent.com/lucide-icons/lucide/main/LICENSE (read 2026-11-10: ISC, with MIT for Feather-derived icons).
