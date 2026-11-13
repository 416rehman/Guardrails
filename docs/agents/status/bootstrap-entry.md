# Bootstrap entry review

Written by the chief architect in the seed session (docs/team/06 section 14, steps 5 and 6), for the `[WI-0000]` issue #1. It records where the project stands when the agent team starts: what waits on something outside the team, which work items are trust core, which spikes can start, and where the documents disagree. Statuses are "not started" unless docs/design/_review/04-owner-kit-instructions.md records otherwise. Nothing here is scheduled; order is stated only as prerequisites.

## 1. Work items filed

Every row of docs/team/06 section 10 is an issue in the repository `.agents/harness.toml [github] repository` names, filed in table order.

| Work item | Issue | Agent | Status at hand-off |
|---|---|---|---|
| WI-0000 | #1 | chief-architect | proposed; `kit handoff` moves it into review |
| WI-0001 | #2 | lead-agent-kit | ready |
| WI-0042 | #3 | lead-agent-kit | ready |
| WI-0002 | #4 | lead-agent-kit | ready |
| WI-0003 | #5 | lead-agent-kit | ready |
| WI-0004 | #6 | lead-agent-kit | ready |
| WI-0005 | #7 | lead-agent-kit | ready |
| WI-0006 | #8 | lead-agent-kit | ready |
| WI-0007 | #9 | lead-agent-kit | ready |
| WI-0008 | #10 | lead-agent-kit | ready |
| WI-0009 | #11 | lead-agent-kit | ready |
| WI-0010, WI-0011, WI-0043, WI-0012, WI-0013 | #12 to #16 | lead-agent-kit | proposed |
| WI-0014 to WI-0025 | #17 to #28 | impl-rust (WI-0023: impl-kernel) | proposed |
| WI-0041 | #29 | impl-web | proposed |
| WI-0026 to WI-0031 | #30 to #35 | impl-rust | proposed |
| WI-0032 | #36 | lead-agent-kit | proposed |
| WI-0033 | #37 | chief-architect | proposed |
| WI-0034 to WI-0038 | #38 to #42 | impl-rust (WI-0037: impl-content) | proposed |
| WI-0039 | #43 | impl-apple | proposed |
| WI-0040 | #44 | impl-web | proposed |
| WI-0044 to WI-0053 | #45 to #54 | lead-agent-kit | proposed |

Sub-issues and mechanisms the table has no row for:

| Issue | What | Why it exists | Agent | Status |
|---|---|---|---|---|
| #55 | RFC template and RFC 0001 (sub-issue of #10) | `rfcs/` is the chief architect's path; the rest of WI-0008 is gate configuration | chief-architect | proposed; `lead-security` readies it |
| #56 | Interface gate halves and the Astryx exception registry (sub-issue of #29) | Protected paths inside WI-0041 | lead-agent-kit | proposed; `lead-interfaces` readies it |
| #57 | The planning pass never hands an issue to its own agent for readying | Conflict 6 below; without it no later agent-kit protected change can be readied | lead-agent-kit | ready |
| #58 | `verify` fails a parser with no differential fuzz target | The mechanism ADR-0009 names | lead-agent-kit | proposed |
| #59 | `surfaces.toml` and `support.toml` gates | The mechanisms ADR-0019 and ADR-0020 name | lead-agent-kit | proposed |
| #60 | The recorded D-66 registry and trademark search | The evidence ADR-0003 names | chief-architect | proposed |

ADR-0001 to ADR-0028 cite work items by their reserved id, `[WI-NNNN]`, which every issue title carries. The fleet-guard check ADR-0027 names is requirement R5 of WI-0006 (#8).

Priority labels: `priority:p0` on WI-0001, WI-0042, WI-0002, WI-0003, WI-0004, WI-0005, WI-0009 and WI-0008 (docs/team/06 section 13 step 7), and on #55 and #57, which those depend on to finish or to be followed; `p1` on the remaining gate items and the core slice through WI-0023; `p2` on the rest of the slice; `p3` on the kit repairs WI-0045 to WI-0053.

## 2. External preconditions (spine section 7)

Each is a third party's account, programme or money. None gates daily work; the artefact that needs it waits and everything else proceeds.

| Precondition | Needed by | Status |
|---|---|---|
| Each agent's hook interface | Hook shim and broker (D-14) | exists for Claude Code and Codex; adapter canaries watch for change |
| A free open-source signing programme accepting Loonaro | Authenticode on Windows user-mode binaries (D-17, D-59) | not started; artefacts ship `not platform-signed` |
| EV certificate and Microsoft's hardware programme, paid for by a sponsor or partner | Optional Windows driver (D-17) | not started; Windows stays driverless |
| An antivirus-programme partner that embeds us | Windows endpoint security platform adapter (D-17) | not started |
| Apple's Developer Program for Loonaro (D-U-N-S number, Team ID, Developer ID) | macOS tier 2, notarisation, behavioural discovery on macOS, the Safari extension (D-18) | not started; waits on owner question 8 |
| The Endpoint Security entitlement | macOS tier 3 (D-18) | not started; needs the Team ID first |
| Access to an incumbent's API | Importers from incumbent inventories (D-24) | not started |
| Rune #244 closed upstream | Right-to-left in the Rune app (D-43, D-69) | not started |
| A customer with access to the vendor compliance APIs | Read-only SaaS connectors (D-40) | not started |
| The organisation's chosen judge back end and capture level | Review stage and model tiers (D-29) | not started; a deployment-time choice |
| A store account per browser | Browser extension for unmanaged installs (D-13) | not started; managed fleets need none |
| A third-party host vendor | L2 opened to third parties (D-41) | not started |
| An MVI-member EDR or MDR design partner | L3 sidecar pilot, L4 connector, stable public surfaces (D-41, D-60) | not started |
| An embedding partner | L6 rebuilt white-label (D-41) | not started |
| Incumbent EDR licences through design partners or free vendor programmes | Coexistence pack and ceiling matrix (D-23); the Falcon cells of S-04 | not started; Defender cells need none |
| Data from many organisations | Own reputation scanning (D-32) | not started |
| A witness outside the operator's control | Tile log, inclusion proofs, receipts (D-39) | not started |
| Revenue, sponsorship or donated cloud credits | Hosted service, beta included (D-63) | not started; self-hosting needs none |
| Revenue or a sponsor | Paid certifications for the hosted service (D-46) | not started |
| Legal help, free foundation legal programmes first | Paid offers (D-04, D-46) | not started |
| Donated capacity for the cell load test | S-24 beyond its `ha` arm; self-hosted multi-cell installations | not started |
| A machine that can host the three-OS VM lab | Air-gap conformance beyond tier A (P16, D-64) | not started |
| An independent party | Third-party rerun of the scorecard (D-45) | not started |
| A foundation's acceptance | Foundation transfer (D-03) | not started |
| A free external audit | Adds to trust-core review when granted (D-62) | not started; nothing waits for one |

## 3. One-time steps (docs/team/06 section 11)

| # | Step | Status |
|---|---|---|
| 1 | Record Loonaro's registration details in the private decision log | not started |
| 2 | D-U-N-S number for Loonaro, if owner question 8 is yes | not started |
| 3 | Decide owner question 8; enrol in Apple's Developer Program or record the decision | not started |
| 4 | Optional: apply to a free open-source signing programme for Windows | not started |
| 5 | DNS for the project domain, then the brand values move to their `on_domain` values through a protected change | not started (owner instruction 25 lists it as remaining) |
| 6 | Repository settings | recorded by owner instruction 28 as applied at setup: visibility, Actions permissions, Dependabot alerts and security updates, private vulnerability reporting, and secret scanning with push protection. Not verified in this session: `cargo xtask github check`, which reads them, is outside the seed shell. The branch rules on `main` are not started: they wait on WI-0010 (#12) to write `.github/rulesets/main.json` |
| 7 | Optional: a licence on the owner's public plugin repository | not started |
| 8 | Optional hardening: a token for hosted agent runs, the three GitHub Apps, a Semgrep sign-in | not started |
| 9 | Pre-push public gate on the seed commit | recorded by owner instruction 28 as run by the setup session before the first push; not verified in this session, and the repository holds no evidence file for that run |
| 10 | Ask a free legal programme for the four notes | not started |
| 11 | Optional: apply to free audit programmes | not started |
| 12 | Optional: register a self-hosted runner; request incumbent EDR evaluation licences | not started |
| 13 | First conversation with one MVI-member EDR vendor or MDR | not started |
| 14 | Accept Claude Code's workspace trust dialog in the repository folder | done (docs/team/06 section 11 item 14); the untrusted-workspace preflight enforces it |

Also recorded by agents, not started: the subscription's published usage limits and terms (docs/team/06 section 11), and the D-66 search (#60).

## 4. Trust-core work items

Every change under `security/trust-core.paths` takes the `full` lane: `eval-security` and `eval-adversarial` in clean contexts, cross-model review by the model that did not write the change, and two passing evaluators on different models (owner instruction 7, D-63). The issues carry the `trust-core` label.

Components that ship to endpoints (the rows marked TC). Each also needs a reference model with differential tests, matrix and soak evidence, and leaves the internal ring only through the review D-62 names:

| Work item | Issue | Trust-core part |
|---|---|---|
| WI-0016 | #19 | `unsafe` in `grdr-ffi` |
| WI-0018 | #21 | Policy evaluator semantics |
| WI-0021 | #24 | IPC peer authentication |
| WI-0022 | #25 | Privileged core |
| WI-0023 | #26 | eBPF programs |
| WI-0036 | #40 | Privileged core |

`platform/macos/**` is on the trust-core list, so WI-0039 (#43) carries the label too, although its row is not marked TC.

Gate, CI and release configuration: WI-0001 to WI-0013 (#2 to #16), WI-0042 to WI-0053 (#3, #14, #45 to #54), WI-0032 (#36), and #56 to #59. These paths never leave ring 0, so the clause on leaving the internal ring has nothing to gate (the reading of docs/team/06, Deviations). Each is also a protected-change item, implemented by `lead-agent-kit` under `GRDR_SCOPE=protected`.

Protected changes that are not trust core, landed after `eval-security` and one more evaluator on the other model: WI-0033 (#37), #55 and #60, all the chief architect's.

## 5. Spikes whose prerequisites exist

A spike can run once what it needs exists (spine section 8). With only the seed and the hosted runners, these can start:

| Spike | Why it can start | Owner | Issue |
|---|---|---|---|
| S-20 Team calibration | The dispatcher, the review workflow and the merge queue are in the seed; it measures the first landed items | `programme-manager`, with `lead-agent-kit` for the report | WI-0019 (#22) is the calibration item; WI-0032 (#36) is the report |
| S-22 Outsider build | `verify` exists; the criteria on hosted runners are in WI-0002 | `lead-agent-kit` | #4; the run by a stranger is evidence when one arrives (conflict 3) |
| S-26 Free origins and TUF through caches | Its first step is a written terms record per origin, which needs nothing built | `lead-release` | none yet; `lead-release` files it |
| S-02 Storage | A prototype over the candidate table formats needs only a runner; the server requires its result | `lead-server` | none yet; `lead-server` files it |
| S-03 Bus | As S-02 | `lead-server` | none yet |
| S-05 Hook delivery | Needs only the catalogued agents installed on runners and a probe | `lead-adapters` | none yet |
| S-12 Linux no-reboot deny | Needs only stock kernels on hosted runners; kernel enforcement requires its result | `lead-linux` | none yet |

Every other spike waits on a component: S-01 on WI-0015 (in WI-0029, #33); S-04 on WI-0015 (in WI-0030, #34); S-06 on WI-0021 (in WI-0034); S-07 on WI-0023 and WI-0024 (in WI-0038); S-13 on WI-0022 (in WI-0023); S-14 on WI-0019; S-15 on WI-0014 (in WI-0018); S-17 on WI-0022 (in WI-0036 and WI-0040); S-21 on WI-0017; S-08 and S-09 on an OS sensor; S-10 and S-11 on the launcher and a sandbox back end; S-16 on the approval helper; S-18, S-23, S-25 and S-27 on the uplink scheduler and the updater; S-19 on the view-model crate; S-24 and S-28 to S-31 on the server.

## Conflicts

Each is a disagreement between documents, or between a document and the kit, with the resolution the seed session applied. None is fixed by editing docs/design/ or docs/team/ here; those changes are protected-change items, and a change to the spine is an RFC (D-61).

1. **Number of initial crates.** The spine's section 5 says about twenty, docs/design/03 section 2 and A1 say twenty-four, ADR-0005 follows that, and docs/team/06 section 10 (WI-0001) and section 13 step 7 say 22. The two extra are `grdr-strings` and `grdr-messages`, which WI-0041 creates. Resolution: WI-0001 creates the 22 and lists all 24 in `architecture.toml`, WI-0041 creates the two; docs/team/06 should say "22 of the 24".
2. **Archlint rule range.** docs/design/03 work item A2 says rules 001 to 025; its own table and docs/team/06 go to ARCH-026. Resolution: 026, as WI-0003 states.
3. **S-22 needs a person.** The spine's S-22 and the WI-0002 row ask for a run by a stranger outside the team; owner instruction 7 allows no person as a step. Resolution: WI-0002's criteria measure a clean clone on the hosted runners; a stranger's run is added as evidence when one happens and never gates. The spine's S-22 wording needs an RFC to match.
4. **Label check command.** docs/team/06 section 7.2 and the WI-0009 row write `labels sync --check`; section 13 step 6 and the kit have `labels check`. Resolution: the kit's `cargo xtask labels check`; ADR-0024's "Enforced by" line means that command.
5. **Claude Code version for the schema check.** docs/team/06 (WI-0005, ADR-0013's row) names 2.1.322; `.agents/harness.toml` pins 2.1.319 and adopts 2.1.322 once V18 and `kit check` pass on it. Resolution: the criteria read the version from the harness file.
6. **Who readies an agent-kit protected change.** docs/team/06 section 13 step 7 has `lead-agent-kit`'s planning pass ready WI-0042, which `lead-agent-kit` implements. docs/team/01 section 5 says the agent that readies an item never implements it, `kit ready` enforces that, and the planning pass routes a squad's issues to its own lead. So no session after the seed could ready an agent-kit item. Resolution: the seed session readied WI-0042 (#3), and #57 changes the routing so such an issue goes to the programme manager.
7. **The trust-core label.** The seed prompt says to label trust core where the row says TC; docs/team/06 section 10 says the gate-configuration paths are trust core too, and `kit ready` adds the label from `security/trust-core.paths`. Resolution: the label follows the paths file on every issue.
8. **WI-0008 spans two protected-change agents.** Its governance files and the `rfc-required` check are gate configuration (`lead-agent-kit`); `rfcs/` is the chief architect's. One issue has one agent, and the chief architect could not ready an item it implements. Resolution: #10 for `lead-agent-kit`, sub-issue #55 for the chief architect.
9. **Evidence pull-request template.** The WI-0009 row and docs/design/30 work item 30-12 list a pull-request template; docs/team/01 section 3 says there is no `.github/PULL_REQUEST_TEMPLATE.md` because `kit handoff` builds the body. Resolution: docs/team/01; WI-0009 proves the built body.
10. **Kind labels.** docs/team/06 section 7.2 lists fifteen `kind:` labels; `.github/labels.toml` also holds `kind:gardening`, `kind:proposal` and `kind:rfc`, and `proposal.yml` applies `kind:feature` as section 7.1 gives it verbatim. Resolution: the files stay as they are; section 7.2's list should gain the three.
11. **The Plan field.** docs/team/06 section 7.1 lists a plan field in the form; the seed prompt's heading list omits it and forbids an execution-plan template. Resolution: the form keeps the field, the readied issues carry a `### Plan` section, and the others leave it to their lead.
12. **A `blocked:` reason label.** `.agents/skills/grdr-write-spec/references/issue-work-item.md` says `status:blocked` comes with a `blocked:` reason label; `labels.toml` has none and docs/team/06 section 7.2 says the issue names what it waits on. Resolution: the labels file; the skill reference is corrected in WI-0005.
13. **Creating a crate inside an ordinary item.** `**/AGENTS.md`, `Cargo.toml` and `architecture.toml` are protected, so an implementer cannot add a crate, while the `grdr-scaffold-crate` skill is preloaded for implementers. Resolution: a new crate's manifest entry, `AGENTS.md` and layer row are a protected-change sub-issue of the item that needs it (noted in #17 and #56); the skill should say so.
14. **Spine version in ADR-0002's row.** docs/team/06 section 9 says spine v4; the repository holds version 5. Resolution: ADR-0002 adopts version 5.
15. **People in the review and merge path.** docs/design/_review/02 (the buddy as trust-core reviewer, the owner's review queue) and _review/03 (the merge queue lands on a signature; the dispatcher reads a work graph in the repository; gardeners on scheduled tasks) predate owner instructions 5 to 7 and 23. Resolution: _review/04 and spine version 5 override them, as _review/04 states; no edit.
16. **Where the repository lives.** _review/02 answer 1 puts the GitHub account with Loonaro; owner instruction 5 puts the one repository on the owner's personal account. Resolution: instruction 5, as _review/04 records; GitHub can transfer it later.
17. **Item size.** Several rows of section 10 are larger than size M (WI-0041 above all), while an issue is at most M. Resolution: each is filed at M as a ceiling and its lead splits it into sub-issues before readying.

## What the seed session did not read in full

For context budget this session read in full the spine, docs/design/_review/04, docs/team/06 sections 6.4 to 14, docs/team/01 sections 3 to 6 and docs/design/03 section 2, and the parts of docs/design/_review/02 and 03, docs/design/30, docs/team/03 and docs/team/05 that the work items of WI-0001 to WI-0009 cite. It did not read docs/design/_review/00 and 01, docs/team/02 and 04, or docs/design/02, 24, 07, 12 and 04 beyond those citations. The specs of WI-0010 onward therefore carry the row text of section 10 and leave the criteria to their leads, who read the design documents the rows cite.
