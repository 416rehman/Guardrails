# Review C7: interfaces and experience (D-31, D-42, D-43, D-44, P8)

Reviewed 2026-11-10 under the ui-architect contract (evaluation, violations, fixes, principle cited). Rune re-checked today with `gh`: 0 tags, 0 releases, 204 open issues; #141, #162, #218, #244, #296, #334 and #430 still open.

## Evaluation

The ingredients are right, but three decisions cannot be built as written. D-31 promises unforgeable approvals while M1 ships a single user-level daemon with no privileged helper and no out-of-band channel. D-44 starts every pack in Watch while D-28 promises protection by default. D-43 names the web console as the M1 fallback while section 7 delivers it in M2. The change that matters most: replace "unforgeable" with an approval grade recorded on every grant, as P1 already requires of controls.

## Findings

### 1. Blocker, wrong: D-31 cannot hold in standalone, and three agent-reachable approval paths are open

**Problem.** D-20 runs M1 as one user-level daemon. There is no privileged helper and no server for push. The CLI in brief 33 has `approvals approve` and `exceptions grant`, which an agent with a shell can run. The localhost console (D-43) is reachable by any same-user process. On Windows a high-integrity prompt is still drivable by an elevated agent; Linux has no boundary at all.
**Evidence.** 29-rune verification rows 1, 2 and 10; 33 "Command line"; 36 "Approval system" item 2 ("policy maps risk tier to minimum channel", dropped by the spine).
**Amendment.** Add to D-31: "Every grant records an approval grade: G0 same-user click or CLI; G1 OS authenticator (Windows Hello, Touch ID, polkit) over the action digest; G2 privileged helper on the secure desktop or a separate principal; G3 out-of-band device. Policy sets a minimum grade per action class. Only G2 and G3 are called unforgeable. The CLI and local API refuse approval calls from a process inside any agent session container. Where the minimum grade is unavailable, Ask becomes Block." *Applying: Ethical Friction, Safety.*

### 2. Major, missing: the ladder does not say who is asked, whether the action waits, or how strong Block is

**Problem.** Brief 33 gives self-approval at Ask; brief 36 says the requester never approves their own request. The spine picks neither. Hold time is unstated: Copilot hooks time out at 30 s, Endpoint Security events near 15 s, while the admin answer target is a 15-minute median. "Block" on an AL2 device is a request, not a boundary, yet the mode control shows one word.
**Evidence.** 33 TL;DR and acceptance table; 36 section 3 and line 152; 15 timeouts; 13 "Deadlines"; P1.
**Amendment.** Add to D-44: "Ask carries an approver: self, sponsor, admin or quorum. Destructive and credential classes never allow self. The default mechanism is deny now, grant, retry (Run now); an action is held only for a self approver and within 80% of the control point's timeout. Every mode control shows its effective outcome for the selected scope: boundary, request, or not enforceable, with device counts." *Applying: Prioritize Intent, Zen of Clarity.*

### 3. Major, wrong: "new packs start in Watch" contradicts D-28 and D-15 and copies a rival's weakness

**Problem.** A fresh install enforces nothing, the gap brief 02 records against BeyondTrust.
**Evidence.** 02 surprises ("a default deployment enforces nothing"); 33 design review; 33 section 2 (LuLu's install defaults).
**Amendment.** Replace with: "One Essentials pack ships in Block: credential stores, agent control files, environment scrubbing. A rule enters it only with zero block-induced task failures on the efficacy corpus. Every other pack starts in Watch and after seven days proposes a move with 'this would have asked you N times'." *Applying: Smart Defaults.*

### 4. Major, risky: D-43 builds two consoles and M1 depends on the weaker one

**Problem.** "Rune console" is unscoped, so authors will rebuild the web console in Rune. The fallback web console is M2 but VDI and RDP users need it in M1. "Tray uses no GPU" is verified only for a windowless Windows process; Rune has no macOS tray, and a drawn popover needs a GPU device. D-43 has no revisit trigger.
**Evidence.** 29 matrix, verification rows 3 to 5 and 9; 33 "Desktop app" (five screens).
**Amendment.** Replace the D-43 body: "The Rune app is the developer's desktop app, six screens only: first run, Now, My activity, Rules (Simple), Privacy, Settings. The full console exists once, as the web app, served on localhost from M1. The tray uses native menus, has no Rune or wgpu dependency (lint-enforced) and opens the web console when a software adapter or remote session is detected. Revisit: if the soak gate fails on two consecutive revision bumps, ship web-only desktop until it passes." Move "local web console" to M1 in section 7. *Applying: Safety.*

### 5. Major, missing: no authentication model for the localhost console, no step-up for widening changes

**Problem.** D-42's OIDC backend-for-frontend does not exist in standalone. Browser agents ride the user's session and can click "Off" in either console; synthetic-input signals miss UI Automation.
**Evidence.** g09 implication 8; 30 section 3 (RFC 10017 covers hosted only).
**Amendment.** New decision: "The local console binds loopback on a random port with a one-time launch token from `grd console`, strict Host and Origin checks and no CORS. In every console, a widening change (posture down, grant, exception, capture level up, kill-switch release) needs the D-31 confirmation at that class's minimum grade; hosted uses WebAuthn user verification with the change digest as challenge." *Applying: Ethical Friction.*

### 6. Major, wrong: prompt metrics per developer break P8

**Problem.** Section 6 budgets prompts "per developer per day"; briefs 33 and 36 flag individual approvers by decision time. That scores employee behaviour. P8 also leaves the transparency floor open and "capture levels" (D-46) undefined.
**Evidence.** 34 lines 11, 92 ("no per-person scoring") and 107; 33 risks ("decide the floor now").
**Amendment.** Add to P8: "Prompt and approval health is reported per rule and per group of five or more; a person's own figures appear only in their own panel. The disclosure screen and tray status cannot be hidden in any shape, white-label included; this is a conformance-mark requirement. Capture levels are defined in section 3: metadata, redacted arguments, redacted content, full content." *Applying: Safety, Reciprocity.*

### 7. Major, risky: the Astryx wrapper will not isolate Astryx, and the OEM kit inherits it

**Problem.** A wrapper that re-exports Astryx components leaks its props, so a swap touches every screen. The published React kit (30, implication 8) would carry React 19, a StyleX runtime peer and a 269 KB global stylesheet into partner hosts. Astryx supplies none of our differentiating composites. The strongest alternative is React Aria Components 1.22 directly: stable 1.x, Apache-2.0.
**Evidence.** 30 verification rows 3, 4 and 6; 30 "Weak points".
**Amendment.** Add to D-42: "`ui` defines its own prop contracts. Composites (session timeline, session tree, policy editor, mode control, approval card) are built on headless primitives and tokens with no Astryx import, and form the embeddable kit. Astryx is first-party chrome only. Revisit when an upgrade costs more than one agent-day or the swap test fails."

### 8. Major, missing: first run hits an elevation wall before value

**Problem.** D-14 installs hooks only in admin-owned settings, so the first screen is a sudo or UAC prompt.
**Evidence.** 33 acceptance table (5 minutes, no account); 15 on-disk transcripts.
**Amendment.** Add to D-44: "First run performs a read-only scan with no elevation and shows agents found and last week's sessions from existing transcripts, with two or three things worth a look. Only then does it offer 'Turn on protection'. The setup list opens with completed steps ticked. Team enrolment imports local history so the first hosted screen is never empty." *Applying: Reciprocity, Goal Gradient, No Onboarding.*

### 9. Minor, missing: internationalisation and desktop accessibility have no decision

**Problem.** Three catalogue formats are in play (rune-i18n JSON, Fluent in 33, ICU in 30). Rune cannot set base direction (#244) and rune-kit strings are English-only (#396). D-42's WCAG target covers web only.
**Amendment.** New decision: "One ICU MessageFormat catalogue generates the web and Rune catalogues. M1 ships English plus a pseudo-locale; right-to-left is not claimed on desktop until #244 closes. Desktop targets WCAG 2.2 AA with its own VPAT. Deny reasons sent to agents are English with stable codes. Modes never rely on colour: Lucide icon plus label. Approval confirmation uses the OS authenticator sheet, which carries the platform's own accessibility."

### 10. Minor, missing: dashboards, pricing and provider rules

**Amendment.** Add to D-44: "Every tile is a sentence with a number, a comparison and one action; no chart without a claim and a table equivalent. Named metrics: Coverage (share of agents at target assurance level), Blind spots (could not look), Prompt health. Provider views always show the tenant and an 'acting as' banner. The pricing page shows two plans, Self-hosted (free, every feature) and Hosted (per active endpoint, shown per day); Provider, OEM and paid support sit behind 'View all plans'. Plans differ by operator, retention and response time, never by feature. 'Cancel anytime, export everything'." Evidence: g10 (free tier only on customer keys; measure telemetry before pricing). *Applying: Meaningful Highlights, Chunking, two-tier rule, Anchoring.*

## Screens and acceptance criteria

| Milestone | Screens | Acceptance |
|---|---|---|
| M1 | First-run scan; tray menu; approval prompt; block explanation (agent reply, toast, tray); Now; My activity with session detail; Rules (Simple); Privacy; Settings and Doctor; local web console | First agent and session in 5 minutes with no account and no elevation. Block reason visible within 1 s. Negative tests: accessibility click, `--script`, CLI from agent lineage and local API cannot mint a grant. Median 3, 95th percentile 8 interruptive prompts per day. Console usable over RDP. Keyboard and screen-reader pass on three systems. |
| M2 | Enrolment and setup list; Today; Inventory with unknown-agent triage; Sessions; Review queue; Policies (Simple, Advanced, Code) with Simulator; Approvals and Exceptions; Packs and rings; Roles; Deployment health | Tenant to first inventory in 30 minutes. Finding to evidence 1 click; action to draft rule 3; Watch to Block with replay 5. Builder round-trip 100%. Decision at endpoint in 30 s. SOC role sees no content. Zero AA failures. |
| M3 | Provider home, cross-tenant queue, pack library with per-customer diff; Identities and grants; Incidents and Cases; Kill switch; Data-flow declassification; Compliance evidence; Integrations; Usage and Pricing | Cross-tenant approval in 2 clicks, audited and visible to the customer. At most 2% of sessions need a person. Fleet kill needs two authenticators verified on the endpoint. No per-person metric in works-council mode. Two published VPATs. |

## Spikes

1. **Approval forgery.** Attack the helper and OS authenticator with UI Automation, AT-SPI, synthetic input, `--script`, CLI, local API and overlay windows on three systems. Pass: zero grants in 1,000 attempts per vector.
2. **Rune soak and no-GPU.** Six-screen app, 48 hours of open and close cycles, plus WARP, RDP and lavapipe. Pass: idle CPU under 1% of a core, memory growth under 5%, redirect to the web console within 2 s on software adapters.
3. **Astryx swap.** Implement eight `ui` primitives on Astryx 0.7.11 and React Aria Components; build Review queue and Session detail on both; run the 0.6 to 0.7 upgrade. Pass: zero application diff, upgrade within one agent-day, embed kit free of Astryx.
4. **Hold budget.** Measure hold-before-fail-open and deny, grant, retry on the four M1 agents. Pass: auto-resume within 5 s on three of four, zero fail-open in 1,000 stalled approvals.

## Agreed

- Approvals never rely on a Rune click; headless flags disabled.
- Grants scoped to the exact pattern, agent and window, centrally revocable.
- View-models and IPC in a crate without Rune; console spawned on demand.
- Static React app behind a backend-for-frontend for hosted.
- TanStack Table and Virtual for grids (Astryx stable has no windowing).
- One DTCG token source, if the generator also emits the Rust `Kit` mapping.
- Replay before enforce; three-bucket session review queue.
- Metadata-only capture by default; content gated separately.
