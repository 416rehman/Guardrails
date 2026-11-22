# ADR-0040: Clock, Entropy, Monotonic and the retry executor are the surface RFC 0008 states, built under the constraints of its decision

- Status: accepted
- Date: 2026-11-22
- Decided by: chief architect
- Spine: D-05, D-15, D-60, D-61, D-62, D-63, P1, P5, P6, P8, P9, P14, P15, P17
- Requires: #1928 (RFC 0008 on `main` in State: Review); the review of RFC 0008 on #1924 by the nine persona council seats, `eval-architecture`, `eval-api`, `eval-security` and `eval-adversarial`
- RFC: 0008 ([`rfcs/0008-clock-entropy-and-the-retry-executor.md`](../../rfcs/0008-clock-entropy-and-the-retry-executor.md)), accepted on #1924
- Work items: #1964; #281, #282, #283, #1238, #1580, #1582, #1688, #1741, #1850, #1927, #1933; the owners its constraints bind; #1963 and #1959; #1966 to #1972, filed on acceptance; #1974, filed in the record's review

## Context
#281 (the Clock and Entropy ports, the deterministic adapters and the conformance runner) and #283 (the retry executor) are the first code in `grdr-ports` and `grdr-ports-testkit`, and the first runnable path needs them. RFC 0002 sections 3 and 4 stated this surface, but share no mechanism with that RFC's tenant boundary, so RFC 0008 took them on its own route ([RFC 0008, Motivation](../../rfcs/0008-clock-entropy-and-the-retry-executor.md#motivation)). Both crates are public in layer 2, so their surface changes only by RFC (D-61).

RFC 0008 went through eight revisions on #1924. Rounds 5 and 6 moved the machinery for outside callers, many principals and the decide path to #1959, and narrowed the executor to two callers. The decided text is RFC file blob `b338780823870d0f81c92e1a6f9cd2a5ec472eb8`, written against the spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9`. On that blob every evaluator the review calls for passed, each naming that blob and the base, with minors and no blocker or major:
- `eval-architecture` (Sonnet, the other model from the RFC's metadata), https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081614067;
- `eval-api` (Opus), https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081689414;
- `eval-adversarial` (Opus), https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081761732, with one minor held back under D-62;
- `eval-security` (Opus), https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081862512.

The nine seats reviewed the same blob. All nine support it with changes and none names a broken spine floor. The orchestrating session makes the owner's decisions (#1828). Its exit rule decides an RFC after the first round with no blocker or major and writes that round's minors, and the seats' changes, into the decision as constraints (https://github.com/416rehman/Guardrails/issues/1828#issuecomment-7074036273). Its rulings on the deciding round and on the seats are https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081876721 and https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081922479. The RFC's [Decision section](../../rfcs/0008-clock-entropy-and-the-retry-executor.md#decision) quotes the rulings it relies on as text.

## Decision
**Accepted.** The slice-0 surface of `grdr-ports` (`clock`, `entropy`, `retry`), `grdr-ports-testkit` (`ManualClock`, `ClockError`, `SeededEntropy`, `block_on`, `Stalled`, the conformance runner, the Clock suite and the `Health` double) and `grdr-model`'s `Monotonic` is RFC 0008 at RFC file blob `b338780823870d0f81c92e1a6f9cd2a5ec472eb8`, with the spine pin above as its base ([RFC 0008, Design](../../rfcs/0008-clock-entropy-and-the-retry-executor.md#design)). In outline:
- Layers 0 and 1 read no clock or randomness and take `now` and an `Entropy`. Only `grdr-os-clock` implements `Clock` and only `grdr-crypto`'s `random` module implements `Entropy` in product code, and the kit reaches no program's normal closure (R1, R3, R4).
- There is one retry executor. Until #1959 is decided it has two callers: the calls the uplink's own tasks start, and an adapter's connection set-up inside its constructor, which drops the state and keeps a copied, labelled `ClassReading`. No instance a request handler reaches builds a state, and no call a request starts, local or remote, runs through one (R9, R11).
- Each class has its own policy, budget, attempt counter, breaker and health call on its own route. A failure counts against the peer only by its registered code or its cutoff, the breaker opens only when the health call agrees, a call-probe turn ends within one cap, and a probe with no verdict at its deadline counts as no answer (R12, R13, section 4).
- Degraded is raised while `refuted` is above 0, at the cap, or above the failure-share row `uplink.degraded-failure-share`, and always carries a code: `GRDR-RETRY-0001` after a cutoff (R12, section 4).
- ARCH-018's four lists, by layer, module and function, hold who may call the executor, with review behind the scan (R11, section 8).

**No pin and no evidence.** RFC 0008 decides no pinned path, so its Decision section holds no decision line, `rfcs/pins.toml` is unchanged, and nothing is added under `rfcs/evidence/` ([RFC 0001, "RFC states"](../../rfcs/0001-adopt-the-spine.md#design); [ADR-0036](ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md), "Evidence added in route"). The decided RFC file differs from `b338780` only in `State:`, `Decision record:` and the Decision section, as the RFC's Review section allows.

**Constraints.** The decision binds the constraints of the RFC's Decision section, each on the issues it names, and each was posted on those issues. Where a constraint and the RFC text differ, the constraint wins for those issues. In outline:
1. The round 8 minors: who may call a start-up module and how the lists are shaped (#1967, #1582, #1688, #1534); the area rows (#1968); the share as `Permille`, counted over recent attempts (#1966); `ClassReading`'s fields (#283); a set-up state carried out of its constructor (#1582, #1966); the held-back m4, by component only (#1582, #1238, #1967); coupling inside one class, Degraded through `refuted`, the STEP_UP ApprovalRequest, denied with `approver-unreachable` until #1974 builds its own path, and Enrol's one connection and slot (#215, #1974, #1238, #1286); and RFC 0002's composition root (#1967, #1688).
2. The seats' changes: standalone builds nothing before join but the update fetches' own class, with Enrol sent once outside the executor, and bounded local set-up (seat 1, #1238, #1688, #30); the never-connected cap, and the offline state and the wait after a suspend by amendment (seat 2, #1238, #1966), with the operator probe declined; replay by outcome and the coverage-gap state (seat 3, #281, #1582, #1972); join's exit codes and Degraded as fleet metadata (seat 4, #1238, #1286); the embedded closure, the timer route and the promotion rule (seat 5, #1580, #1927, #1969); the counter file and the messages (seat 6, #1238, #283, #215); a reproducible bench, lint diagnostics and documented tools (seat 7, #283, #1582, #1580, #1741); `MessageRef`, bidi escaping and translated code pages (seat 9, #1238, #281, #1968).
3. Seat 8's cuts as the session ruled: one Degraded in the Simple view, the three triggers kept as mechanisms, one generated `KIT` page; the rest declined (#1238, #1688, #1968).
4. The amendments and moved work: #1963 (amendment 1, `taken`), #1966 (amendment 2, after #1963) and #1959 (seats 4 and 6). An amendment is a new RFC that names RFC 0008.
5. The minors of this record's review: #283's blockers, the owner of `CheckIn`'s new fields, #1967's `entry_points` field with #1582 after it, and the `KIT` page's anchors (#283, #1238, #1967, #1582, #1968).

**What this acceptance binds.** What RFC 0008 states changes only by an amendment of RFC 0008, a new RFC that names it (section 8). Every other later change takes the lane of the table below. The lanes stack: a change that matches more than one row takes each of them, so an amendment that also touches a trust-core path takes the trust-core lane too. The baseline is what RFC 0008 states together with the forms its constraints set, such as the array module fields of 1b and the `entry_points` field of 5c, so a change to one of those forms is a row 5 change. #1963 and #1966 are amendments already open, and #1959's decision will be another.

## Lanes for later changes
| Change | Lane |
|---|---|
| An `architecture.toml` entry that the path conventions of section 8 already cover: a layer 3 crate's `src/setup.rs::connect`, `grdr-uplink`'s `src/origin/*.rs`, a layer 4 program's start-up modules | No change: the existing entry covers it. `eval-architecture`'s duties of #1971 apply to the code that uses it. A new item in an entry's `entry_points` is the next row |
| Any other ARCH-018 list entry, any `run_until_caller` entry, any new `entry_points` item, and any other change to the entries #1967 adds | A protected change on `architecture.toml`, a trust-core path, worked by lead-agent-kit or the chief architect: `eval-security`, `eval-adversarial` and two passing evaluators on different models |
| A `limits.toml` row, or a change to a row's value or range, such as #1238's lead setting `uplink.degraded-failure-share`'s `min` and `max` within 1 to 999 | Trust core, on the full lane, as RFC 0007 section 6 has every row |
| The code areas of #1968 and the rows of #1969 | As #1967: `eval-security`, `eval-adversarial` and two passing evaluators on different models |
| A change to what RFC 0008 states or to a form its constraints set: a signature, a semantic, a variant, a suite case, a list's form, the `fixed` scope of `uplink.degraded-failure-share` or a range beyond 1 to 999, and the promotion of `grdr-ports` or `grdr-ports-testkit` out of `experimental` (constraint 2e) | An amendment, a new RFC that names RFC 0008, reviewed by the persona council once, `eval-architecture`, `eval-api`, `eval-security` and `eval-adversarial`, with one evaluator on the other model. A range change on `uplink.degraded-failure-share` beyond 1 to 999, and a promotion's `surfaces.toml` row, also take the trust-core lane of their file |
| A constraint of the Decision section | Checked by the evaluators of the item it binds, on that item's pull request |

## Where each item is built
Seat 7 asked for one map from each public item to its building issue (constraint 2g). The write sets are the issues'.

| Item | Built by |
|---|---|
| `Monotonic`, `RetryPolicy`, `RetryStep`, `RetryBudget`, `Breaker`, `ProbeKind`, `AttemptCounter`, `GiveUp` | #1850 states them, #282 builds them |
| `Clock`, `pub use Entropy` | #281 |
| `ManualClock`, `ClockError`, `SeededEntropy`, `block_on`, `Stalled`, `clock::suite`, `params.rs` | #281 |
| `Case`, `Suite`, `Outcome`, `CaseResult`, `Failure`, `Report` | #281; RFC 0002 amends them (#1688) |
| `ScriptedHealth`, `Scripted`, `ScriptedFault` | #281 |
| `Health` and its `Arc` impl, `run`, `run_until`, `faults_peer`, `RetryState`, `HealthReading`, `HealthAnswer`, `ClassReading`, `Attempt`, `RetryError` | #283, after #1963 and #1966 |
| `OsClock`, the programs' `Entropy` | #1927, in `grdr-os-clock` (#1933) |
| The `KIT` and `RETRY` codes | #1968, after #278 |
| `architecture.toml` entries | #1967 |
| `surfaces.toml` rows | #1969 |
| ARCH-001 closure rules and fixtures | #1580 |
| ARCH-003, ARCH-017, ARCH-018 and ARCH-019 clauses and fixtures | #1582 |
| The uplink's state, classes, health calls, Degraded and the row `uplink.degraded-failure-share` | #1238 |
| The device's remote ApprovalRequest path | #1974 |
| The construction cases of each storage suite | RFC 0002's amendment (#1688) and its storage items |
| Design texts | #1970 |

## Enforced by
- RFC 0008 section 7, one mechanism per decision, each built by the item it names: the `+ Send` bounds and compile-time tests (#283); ARCH-001's closure rules (#1580); ARCH-003's implementor lists, ARCH-017's exemptions, ARCH-018's clause and ARCH-019's exemption (#1582, reading #1967's entries); `faults_peer`'s table test over 80 pairings (#283); the construction cases (#1688 and the storage items); the reset test on `grdr-server`, the daemon and `grdr-uplink` (#1534, #1744, #1238).
- `eval-architecture`'s two review duties (#1971), so the scan has review behind it.
- ADR-0020's stability gate over #1969's rows, with `cargo public-api` and `cargo semver-checks` (#1741).
- Each constraint by the issue it binds: its lead writes it into the item before readying it, and the item's evaluators check it on its pull request. Until each item lands, a constraint holds by review only.

## Consequences
- #281 and #283 have one decided surface to build against and name RFC 0008 as their route; #283 waits for #1963 and #1966, and for #282's types, not for RFC 0002.
- A device that has never checked in takes a control cap of 10 minutes or more, so a containment command can take up to that cap to reach it, not 122 s.
- `grdr doctor` reads each class's state and moves nothing, so after an administrator fixes a blocked route a class recovers at its next probe, up to its cap.
- Until #1959 is decided, every port a request handler reaches, the endpoint's local stores and the spool return their errors unretried, and so do the uplink calls a local request starts. Their callers see each error once.
- A dead origin costs about 87 calls an hour per device, against 58 to 71 with one breaker per origin; design/22's sentence changes with #1970.
- The free retry every 10 s applies to each class, so two classes may make two every 10 s.
- An adapter shows no live breaker after its set-up; its set-up reading says only how the set-up went.
- Until #1966 is decided, Degraded from the failure share can turn off and on under a steady failure rate; the design residual records it (#1970).

## Alternatives rejected
- Those of [RFC 0008, Alternatives](../../rfcs/0008-clock-entropy-and-the-retry-executor.md#alternatives).
- A pin record and evidence files for this decision: RFC 0008 decides no pinned path, and evidence without a decision line is out of route (ADR-0036).
- Writing the constraints into the RFC's Design text: the exit rule makes them constraints, and the decided file may differ from the reviewed blob only in its state, its decision record and its Decision section.
- Making the round 8 changes to `grdr_ports::retry`'s surface and semantics (`Permille`, the share's window, a scoped set-up, the offline state and the wait after a suspend) as constraints: they change what the RFC states, so they go by amendment (#1966), as seats 3 and 9's `taken` does (#1963).
- Seat 2's operator-started probe for `grdr doctor` and `grdr join`: declined for slice 0 (https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7082538803, D2-1). A probe a local request starts would move a class's breaker, against R11, SR-new-0008-I and SR-04.
- Seat 8's cuts 2 and 4, and cut 5's `for_class` and `resume`: the session declined them (https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7081922479), because the construction cases read the set-up reading after the state is dropped, a route can fail its health call while its calls would succeed, the uplink's two classes are slice 0's, and design/22 needs the counter to survive a restart.
- Making `uplink.degraded-failure-share` tunable by a partner's settings revision, as seat 5 asked: declined for slice 0 by the session (https://github.com/416rehman/Guardrails/issues/1924#issuecomment-7082447861). The row stays `fixed`, a partner changes it through a release on the full lane, and the revisit is when the embedding settings surface exists, in the embed item or #1959.

## Revisit when
- A verdict by an evaluator of RFC 0008's review fails `b338780`, or a later comment shows a defect in the accepted text; either opens an amendment of RFC 0008 (`docs/design/30` section 3).
- #1963, #1966 or #1959 is decided, each as an amendment of RFC 0008.
- The embedding settings surface exists, which reopens seat 5's settable Degraded row.
- RFC 0002 is decided without the construction-case changes of section 8 and constraints 1b and 1m.
- #1850 is decided with types or uses other than section 8 lists.
