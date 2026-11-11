# Review C9: delivery, team and targets (D-47, sections 6, 7 and 8)

Decision challenger, 2026-11-10. References are to `research/NN-*.md`.

## Summary

D-47's operating model matches the evidence. The delivery outline is not yet a plan: milestones have no exit gates, three contradict section 4, the first usable release is undefined, and nothing is budgeted, least of all the owner's hours. The change that matters most is to budget human capacity and gate the hosted service on a second on-call human, not on a milestone.

## Findings

**F1. Blocker, missing. D-47 and Q3: every human-only duty lands on one unbudgeted person.**
D-47 gives the owner eight duties; section 7 adds a hosted beta at M3 and SOC 2. Evidence: 31 "Weak points" (OpenAI's bottleneck was human QA with three to seven people; "We have one"); g10 section 8 ("On-call needs at least two humans per rotation"); 28 verification row 3 (a free sensor tied to a paid hosted service makes us a CRA manufacturer; 24-hour reporting is live).
Amendment, new D-48: "Human capacity is budgeted. Owner review is capped at 10 hours a week; the planner cuts writer concurrency when the queue exceeds it. Approvals follow risk tiers (h09): low merges with no human, medium is sampled weekly, high needs the owner plus a cross-model review, bound to one commit. No hosted tenant, beta included, exists until two humans share on-call, the legal entity exists and a CRA reporting process is written." Q3 becomes this precondition.

**F2. Major, wrong. Section 7 contradicts D-17, D-40 and P12.**
M2 promises "sandbox launcher (AL3) everywhere", but D-17 reaches AL3 on Windows through user-mode WFP filters keyed on a sandbox SID, and "Windows WFP" is in M3. D-40 says importers "ship first", yet integrations are M3. P12 requires working beside and inside an EDR, yet every rung of D-41 waits for M4, although L0 and L1 need no kernel code. M5 ties self-hosted general availability to SOC 2 Type II, which concerns only the hosted service.
Amendment: adopt the revised table below.

**F3. Major, over-built. M1 is breadth-first and the first usable release is undefined.**
M1 spans three operating systems, four agents, a tray and a "local console". D-43 makes the localhost web console the Rune fallback, so M1 needs two front ends. Evidence: 29 TL;DR (Rune is 19 days old, has no macOS tray, and an idle window holds a core on Windows); 31 "Weak points" (no public agent effort built signed installers); 25 "Could not verify" (Cursor and Copilot hook paths).
Amendment: define release R1 as the M1 exit: "On a clean machine with no account, a signed package installs, finds Claude Code and Codex, installs managed hooks, and within five minutes shows inventory, a session timeline and a deterministic block of a protected-path read. It reports assurance level and Degraded state truthfully and uninstalls cleanly." R1's UI is the CLI and a localhost console subset. Rune moves to M2 behind spike S3. Lost: a native console in the first release.

**F4. Major, missing. The efficacy harness arrives at M4; the agent team needs it at M0.**
Evidence: 31 section 1 (parallel agents worked only with a strong oracle; "a security product has few clean oracles"); g08 "Weak points" ("Any corpus visible to build agents will be fitted"); h09 section 7 (the visible versus held-out gap grows 28 points per tenfold code size).
Amendment to M0: "Efficacy harness v0 (product absent, monitor, enforce; headless drivers for Claude Code and Codex; canary oracle; hook and daemon fault injection) and the held-out evaluator service returning category counts only. A scorecard is produced at every milestone exit." M4's item becomes a third-party rerun.

**F5. Major, missing. The lead-time list is incomplete and D-18's week-one action is impossible.**
D-18 says apply for the entitlement in week one; Q1 says the legal entity is undecided. The entitlement binds to one Team ID and enrolment needs a legal entity (13 "Weak points" and "Needs an Apple developer organisation account"). Signed binaries for R1 need the same entity: Artifact Signing rejects trial subscriptions and individuals outside the US and Canada (25 verification row 8). Also absent: the altitude request (30 business days) and incumbent test licences (g05), SOC 2 windows (34).
Amendment: add a lead-time register. Week one: incorporate, D-U-N-S, Apple organisation enrolment, Azure signing identity, trademark search, lab hardware order, model-provider accounts, first conversation with one MVI-member EDR vendor. Entitlement request the day the Team ID exists. EV certificate and Partner Center with two admins at M3 entry. Q1 and Q2 answered is an M0 exit gate.

**F6. Major, missing. No lab decision.**
Evidence: g05 "Where tests run" and "Costed lab"; 31 verification (hosted Linux x64 has KVM; hosted arm64 macOS cannot nest); g05 verification row 7 (two macOS guests per Mac).
Amendment, new D-49: "Tier A, hosted and free, from M0: builds for three operating systems and two architectures, x64 kernel matrix, Defender-active Windows runs. Tier B, owned, by M1 exit: three Mac minis (six guests, one physical SIP-on path), one 128 GB x64 host with snapshot-revert Windows VMs and free incumbents (Defender, Elastic, Wazuh), rented arm64 bare metal; about $7,000 to $9,000 once and $300 a month. Tier C at the driver milestone: HLK controller and clients, licensed incumbents. Self-hosted runners execute merge-queue commits only, never fork pull requests. One `matrix-run` tool returns ten lines and a log path."

**F7. Major, missing. Human review covers only the kernel driver.**
D-47 omits eBPF, the macOS system extension, updater, cryptography, tenant isolation, policy semantics and specification statements. Linux AL4 ships at M2 with no human gate. Evidence: h09 "Human checkpoints" items 3 and 4 and section 6 (the BPF verifier is where agents "give up"; "humans audited the theorem statements"); g05 "Weak points" (kernel panics at Microsoft and CrowdStrike).
Amendment to D-47: "Tier-0 paths are `grd-sensor-linux-bpf`, `grd-driver-windows`, the macOS extension shell, `grd-update`, `grd-crypto`, `grd-policy` semantics, tenancy, `unsafe` in `grd-ffi`, and gate configuration. A Tier-0 change needs a reference model with differential tests, matrix and 72-hour soak evidence, cross-model review and owner approval bound to the commit. Each Tier-0 component gets an external specialist audit before leaving the internal ring. `grd-crypto` composes vetted libraries only. A human approves every property and specification statement. With no qualified reviewer contracted at milestone entry, the component is cut."

**F8. Major, missing. DCO has no mechanism when agents write every commit.**
A merge queue that adds the owner's `Signed-off-by` is an agent signing, which the kernel policy we cite forbids; signing each commit by hand stops the queue. Evidence: 28 sections 3 and 6 and "Weak points" (without "a defensible human-accountability chain ... embedders' lawyers will object").
Amendment to D-02 and D-47: "Workers commit on agent branches under a bot identity with `Assisted-by: <harness>:<model>` and no sign-off. The merge queue squashes. The owner's `Signed-off-by` is added only by the owner's hardware-key approval of a queue batch digest: daily for low and medium tiers, per change for high. `AI_POLICY.md` states that sign-off certifies provenance and the right to submit, not line review. Counsel's opinion on copyright in agent-written code is obtained before R1."

**F9. Major, missing. No budget, kill criteria or risk register.**
Q2 asks the owner for a budget without proposing one. Evidence: 31 section 7 ($20,000 per 100,000 lines with a clean oracle).
Amendment: add the token column and risk table below as sections 9 and 10.

**F10. Minor, risky. Section 6 targets lack a measurement point and a gate.**
The hook target does not say whether it includes spawning the shim with Defender active (g05 section 1). g08 proposes p99 under 50 ms; g05, 1 ms on cache hit. g08's efficacy targets and D-34's storage targets are absent.
Amendment: split the hook target into engine evaluation, daemon round trip and end-to-end wall time per operating system, alone and with Defender. Add g08's discovery, attribution, block-reliability and overfit-margin targets, zero incumbent alerts on install, zero kernel crashes in soak, and a "gates milestone" column.

## Revised milestone table

Token figures are the reviewer's estimate, to be replaced by S2's measurement: about $200 per thousand lines with a clean oracle (31 section 7), tripled for evaluators, cross-model review and gardeners.

| Milestone | Scope | Exit gate | Tokens |
|---|---|---|---|
| M0 Foundations | Entity and accounts; agent kit, `verify`, merge queue; schemas; sans-IO core; efficacy harness v0, held-out evaluator; Tier A lab; spikes | Q1, Q2 answered; signed test binary on three operating systems; cost baseline | $10k to $20k |
| M1 Standalone (R1) | Claude Code and Codex on Linux and macOS, Windows if S1 passes; hook broker, local policy, history, catalogue discovery, config integrity, protected paths, CLI, localhost console; development fleet dogfoods | R1 definition; zero silent fail-open; block reliability 99.9%; zero Defender alerts | $30k to $50k |
| M2 Breadth and containment | Cursor, Copilot CLI; Windows user-mode WFP; MCP broker; explicit proxy; AL3 launcher everywhere; behavioural discovery; importers, L0, L1; tray; Rune console if S3 passes; Tier B lab | Coexistence pack; held-out discovery recall 85% | $50k to $80k |
| M3 Team | Single-node server, enrolment, rings, web console, roles and SSO; Linux AL4 after audit; macOS Network Extension; penetration test | Self-hosted 1.0 | $60k to $100k |
| M4 Enterprise | HA, provider tier, credential broker, labels, Endpoint Security if entitled, AMSI, Kubernetes and CI, LLM review, compliance evidence, L2 and L3 SDK | Storage targets met | $80k to $140k |
| H Hosted (parallel, gated by D-48) | Beta, SOC 2 Type I, then Type II | Two on-call humans | $10k to $20k |
| M5 Ecosystem | White-label, connectors, browser extension, reputation service, optional driver (Tier C), third-party scorecard, foundation trigger | Conformance listings | $60k to $100k |

Quotes still needed: penetration test and eBPF audit (M3), SOC 2 audit and hosting (H), driver audit (M5).

## Risk register and kill criteria

| Risk | Kill criterion or trigger | Owner |
|---|---|---|
| Owner queue saturates | Over 20 items or oldest over 48 hours: writers cut to three | Chief planner |
| Agent kernel code crashes hosts | Any panic in matrix or soak: component stays in the internal ring | Platform planner, contracted reviewer |
| Rune unfit | S3 fails at M2 entry: localhost console is the desktop UI; retest quarterly | Desktop planner |
| Entitlement not granted | By M4 entry: Endpoint Security only through an embedding partner | Owner |
| Test fitting | Overfit margin above 5 points: release blocked | Release evaluator |
| Spend runaway | Cost per accepted item above twice baseline for two weeks: feature freeze | Owner |
| Signing account suspended (12) | Second admin; documented re-sign path | Owner |
| Injection into build agents | Read-only agent jobs; the fleet's guard runs the last signed release, never the working tree | Security reviewer |

## Spikes

1. **S1, Windows hook latency.** Signed no-op shim to daemon over a named pipe, 10,000 Claude Code hook calls on Windows 11 x64 and ARM64 with Defender real-time protection on. Pass: end-to-end p99 at or under 50 ms; zero Defender or ASR alerts.
2. **S2, team calibration.** Build the shell canonicaliser, its reference model and fuzz target through the full pipeline with three writers for one week. Pass: owner time at or under ten minutes per merged item; visible minus held-out gap under 5 points; cost within twice $200 per thousand lines.
3. **S3, Rune soak.** Pinned revision, 100,000-row table, 48 hours on Windows DX12 integrated graphics, macOS, Wayland and RDP. Pass: idle CPU under 1% of a core, flat memory, and an accessibility click cannot approve.
4. **S4, agent-written eBPF.** Agents write a cgroup connect hook, a fanotify permission handler and one BPF LSM program with a user-space model. Pass: loads on every BTF kernel from 5.10 in the hosted matrix; zero mismatches over one million events; 72-hour soak beside Tetragon with no panic; under eight human hours.

## Agreed

- Single writer per work item, non-coding planners, deterministic merge queue.
- CI as the real gate behind one `verify` command.
- Acceptance tests outside worker reach.
- Driverless Windows first, optional driver last.
- Standalone before server.
- Lead times, not code, set the calendar.
- Zero silent fail-open as a target.
- Signing keys and releases stay human-only.
