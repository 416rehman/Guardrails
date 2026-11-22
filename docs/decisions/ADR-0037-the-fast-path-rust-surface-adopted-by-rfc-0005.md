# ADR-0037: The fast-path Rust surface is the one RFC 0005 states, built under the constraints of its decision

- Status: accepted
- Date: 2026-11-22
- Decided by: chief architect
- Spine: D-05, D-10, D-15, D-20, D-22, D-41, D-60, D-61, D-63, D-71, P5, P8, P9, P14, P17
- Requires: #1866 (RFC 0005 on `main` in State: Review); the review of RFC 0005 on #405 by the nine persona council seats, `eval-security`, `eval-adversarial`, `eval-architecture` and `eval-api`
- RFC: 0005 ([`rfcs/0005-fastpath-rust-surface.md`](../../rfcs/0005-fastpath-rust-surface.md)), accepted on #405
- Work items: #1913; #20, #71, #245, #246, #388, #409, #410, #412, #414, #418, #427, #1538, #1582, #1768, #1769, #1778; the owners its constraints bind; #1914 to #1921, filed on acceptance; #1925, #1926 and #1930, filed in its review

## Context
WI-0017 (#20), its sub-issues #409, #410, #412 and #414, and EM-2 (#418) build against a Rust surface no document stated, and their specs already disagreed on the compiler's return value and on an action class outside the table's vocabulary ([RFC 0005, Motivation](../../rfcs/0005-fastpath-rust-surface.md#motivation)). `grdr-fastpath` and `grdr-core` are public crates in layer 1, so their surface changes only by RFC (D-61).

RFC 0005 went through six revisions on #405. The decided text is RFC file blob `f6f1eadbff5d189d9966cea2dd3b044f901df7cb` (`git rev-parse 1bb2998:rfcs/0005-fastpath-rust-surface.md`), written against the spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9`, `tables.md` blob `8339bea85bb2ee563dd0dfe38befee871a5b7d12` (`issue/245` at `115ec8b`), and `c-abi.md` blob `b147c9dbd81068cd0d95cad4813bfee5e702fe30` and `status-codes.toml` blob `abcaa9704974359cdf7fac76712263b7b6f6f74b` (`issue/246` at `ca039ed`). On that blob every evaluator the review calls for passed, each naming the RFC file blob, the base and the three contract blobs, with minors and no blocker or major:
- `eval-architecture` (Sonnet), on the delta from revision 4 and the whole blob, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075428051;
- `eval-api` (Sonnet), on the same delta, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075407504;
- `eval-security` (Opus), https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075013043;
- `eval-adversarial` (Sonnet), https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074929458.

All nine seats supported with changes, and no verdict on #405 fails that blob. The decision rests on the `eval-architecture` pass, as the RFC's Review section asks, and every required evaluator passed the decided blob, as the exit rule on #1828 asks.

The orchestrating session makes the owner's decisions (#1828). It ruled that revisions 5 and 6 are reviewed as deltas, and that the RFC is decided after the first round with no blocker or major (https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074036733, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074638064). Its decision, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075095292, accepts the RFC on `f6f1ead` and binds eleven groups of constraints, each on the issue that builds the surface. Its correction, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075382924, withdrew the decision's reliance on the round 4 passes of `eval-architecture` and `eval-api`, which named blob `1d591bb`, and held the decision until both passed `f6f1ead`. They have, so no earlier pass is part of this decision. The RFC's [Decision section](../../rfcs/0005-fastpath-rust-surface.md#decision) quotes these rulings as text.

## Decision
**Accepted.** The fast-path Rust surface is RFC 0005 at RFC file blob `f6f1eadbff5d189d9966cea2dd3b044f901df7cb`, with the contract blobs and spine pin above as its base ([RFC 0005, Design](../../rfcs/0005-fastpath-rust-surface.md#design)). In outline:
- `grdr-fastpath` is `no_std`, with no `alloc`, no dependency and no `unsafe`. It takes a safe borrowed `Input` whose three resource inputs are each `Absent`, `Unresolved` or `Resolved`, and returns a `Verdict` whose variants carry their own scope. An `Unresolved` value meets every row it could meet and is never a cacheable `pass` (R1, R2.3b).
- `Tables<B, A>` is generic over who owns the blob and the arena. Custody of both, and of each input during its call, is a host obligation. A call makes the closed list of re-checks RC1 to RC6 at the first read of what each guards, and a failed one gives the sticky `Changed`, the new status `GRDR_E_CHANGED` in C (sections 1 and 2).
- After `Changed` the host retires the handle and its cache generation, and reloads under a bounded policy with episodes and probation. While the floor cannot answer, the action classes in the header's `loss_closed_classes` deny for processes inside session containers, and every other action goes on as after a floor `pass` (section 2a).
- The `#[repr(C)]` structs live in `grdr-fastpath-ffi` (section 5). `grdr_fastpath::layout` is the one definition of the blob layout, and of `grdr-core` only `compile::fastpath` imports it (section 3). `compile_fastpath` returns the blob with its floor report (section 4).
- Error variants bind to registered codes one leaf at a time, and the cap, the path bound and the two expiries travel in the blob header, written from `limits.toml` (sections 6 and 7).
- The three crates are `experimental` in a new `[[crate]]` row kind of `surfaces.toml`. No dependency, edge, wire format or Cedar schema changes (sections 8 and 9).

**No pin and no evidence.** RFC 0005 decides no pinned path, so its Decision section holds no decision line, `rfcs/pins.toml` is unchanged, and nothing is added under `rfcs/evidence/` ([RFC 0001, "RFC states"](../../rfcs/0001-adopt-the-spine.md#design); [ADR-0036](ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md), "Evidence added in route"). The decided RFC file differs from `f6f1ead` only in `State:`, `Decision record:` and the Decision section, as the RFC's Review section allows.

**Constraints.** The decision binds these constraints, each on the issues the RFC's Decision section names for it. Where a constraint and the RFC text differ, the constraint wins for those issues. Where a constraint changes what a host does, the contract text of #245 or #246 takes the same rule, so a partner host and our daemon answer one way (P17).
1. Cold start: with no tables since start, deny-all applies only to processes inside session containers, and the RFC places and #1538's AC-2 that say otherwise are replaced; the daemon persists the last adopted bundle and re-verifies it at start through the adoption checks, the generation floor included, and a fresh compile, never a kept blob; hooks are enabled only after the first adoption, and a hook request before it is answered by the shim's fail-safe table (D-14); a `limits.toml` row bounds that window, and when it elapses the device stays without tables, Degraded with a code, enabling nothing and changing no answer (#427, #1538, #245, #1917, #1925, #1921).
2. Recovery: an audited re-adoption request is an activation, names no bundle, path or table, is accepted only from a peer authenticated as every privileged-side request is (SR-01, SR-04) and counts against a `limits.toml` rate row, and #1930 owns its command and handler (#1930, #427, #1538, #1917); a bounded background re-adoption follows a cooldown after a repeat, and the cooldown covers the requests too (#427, #1538, #1917); an incumbent-EDR coexistence case with its runbook joins the coexistence pack (#641, #727, #575, #1734).
3. Person-facing reasons: the floor-missing denial, the daemon's state codes and a deny over an `Unresolved` input each have a presentation row and language tokens with rule, reason and route (D-44), an LTR isolate for identifiers and `risk = safety` (#1384, #1537, #1853, #1925).
4. Evidence: every answer carries `basis`, action class and episode id; inputs carry their resolution state, and a deny over an `Unresolved` input is a coverage gap (#427, #429); tamper findings are grouped by bundle digest and compiler version, and each `FASTPATH` code's routing class is its existing `class` key, with the values the RFC's Decision section gives per code: `retryable`, `fatal` or `internal` (#278, #427). Seat 3's request that `Changed` carry the failed re-check contradicts R1.5 and R4, so it is not a constraint; it is the amendment item #1926.
5. Fleet: floor state, tamper findings and per-rule outcome counts go up as metadata (#706, #1302), and a pack promotion preview shows the classes it adds to the closed set (#760, #1357).
6. Privacy: an unresolved executable digest only for processes attributed to a session or `undetermined`; no serialiser or `LogSafe` for `Blob`, `DeviceFacts` and the input types, with a canary test; a memory-only, bounded verdict cache cleared on retirement; tamper findings name device and bundle only and read "cause not determined" (#412, #414, #427, #1769).
7. International: uncased non-ASCII literals compile on case-insensitive volumes; NFD, mark-order and the listed code-point vectors join `fastpath_path_form`; a name that cannot be normalised is `Unresolved` (#412, #414, #418, #427, #1769).
8. Contributors: a table of every section 12 change in the first of #245 and #246 to land, the review lane of each item, a fixed `tests/` path for each oracle, a "Where things are" table in `grdr-fastpath`'s `AGENTS.md`, and the rulings quoted as text (#245, #246, #409, #410, #412, #414, #418, #427).
9. Slice-0 build order: the C handle record, its check word and the C compile entry wait for the embedding slice, as do `ScopeEnd`, `narrow` on expiries and `Facts::Relay`; the ARCH-017 entries keep `status` as the one copy of the leaf-to-status mapping (P17), which `status_per_variant` reads, and the parent-swap check of R4.2 stays as a test in #418; RC2 to RC6, the reload state machine and the `Arg` call made again stay (#414, #418, #427, #1914, #1918, #1919, #410, #412).
10. C interface for the embedding slice: arena writability or a host-supplied flag word, layout asserts for every target with a zeroing initialiser, `grdr_fp_blob_info`, a host conformance kit, and the host's MUSTs and defaults (#246, #418, #1769).
11. Evaluator minors MN9 to MN14, F9, C2 to C4 and round 6 `eval-adversarial` m1 to m3, m1 in its strict reading: a `Pass` from the call made again on `State`, for a process inside a session container in a closed class, is answered as the closed answer (D-20) (#414, #418, #427, #1538, #1769, #245, #246, #1917, #1921). With them, the minors of the passes on `f6f1ead`:
    - `eval-architecture` minor 1: a host pre-checks a path or name only for what the library cannot see, and for the library's forms may pass the value as `Resolved` and rely on the call made again (#245, #427);
    - `eval-architecture` minor 2: the host's copy of `loss_closed_classes` belongs to the serving and floor-missing variants of the floor state type, not an `Option` (#427);
    - `eval-api` O1: `tables.md` line 49 is among the sites where the header's 224 bytes become 232 (#245).

    And from `eval-security`'s pass on this decision: SR-new-W (cold-start scope), SR-new-X (re-adoption request) and SR-new-Y (persisted bundle) join #1921, whose rows for the FFI's rules and handle record are marked as oracled in the embedding slice (#1921); and MN9's fold test uses a cased non-ASCII literal on an `Unknown` volume (#414).

**What this acceptance binds.** The surface of the RFC text and these constraints change only by an amendment of RFC 0005, which R6.4 already requires for a break of any of the three crates. The items #1914 to #1921 carry the changes of the RFC's section 12 that are not yet anyone's item, #1925 the interface text of constraint 3, and #1930 the re-adoption command of constraint 2a, each blocked by #1913.

## Enforced by
- RFC 0005 section 11, one mechanism per decision, each built by the item it names: `#![forbid(unsafe_code)]`, `#![no_std]` and `clippy::as_conversions` (#409, #418); the re-check, sticky-flag, reload and unresolved-value tests (#410, #412, #427); the C differential (#418); `fastpath_loss_classes`, `fastpath_compile_interest` and `fastpath_expiry_source` (#414); the Miri job (#1475).
- ARCH-013 and ARCH-017 (#1582) over the edge keys and code entries of #1914. Until #1582 lands, `eval-architecture` checks every change to `crates/grdr-core/src/**` (RFC 0005 section 11).
- ADR-0020's stability gate over the `[[crate]]` rows of #1915, with `cargo public-api` and `cargo semver-checks`.
- The `limits.toml` rows of #1917 and #1768, read through `grdr-schema`'s generated module, and ARCH-019.
- The fuzz target of #1920 (SD-04) and the requirements of #1921.
- Each constraint by the issue it binds: its lead writes it into the item before readying it, and the item's evaluators check it on its pull request, in the lane the RFC's Decision section gives (constraint 8b). Until each item lands, a constraint holds by review only.

## Consequences
- #409, #410, #412, #414, #418, #427 and #1538 have one stated surface to specify against, and the questions their specs disagreed on are settled.
- Every cost RFC 0005's Drawbacks lists, plus MN14's: a `State` stops every floor row that reads a label, for contained processes too, and an honest engine whose projection comes from the other bundle during an activation causes it as a compromised one does. Constraint 11's MN14 rows make it visible as Degraded past a bound.
- Under m1's strict reading, a process inside a session container in a closed class is denied on a stale label projection while the engine is down, where revision 6 as written would have waited on the engine.
- #245 and #246 are not merged. If either lands with text that differs in a way RFC 0005's Unresolved question 1 or 2 lists, RFC 0005 needs an amendment.
- The C work of #418 moves after slice 0, so the Rust daemon is the only fast-path host until the embedding slice.

## Alternatives rejected
- Those of [RFC 0005, Alternatives](../../rfcs/0005-fastpath-rust-surface.md#alternatives).
- A pin record and evidence files for this decision: RFC 0005 decides no pinned path, and evidence without a decision line is out of route (ADR-0036).
- Writing the constraints into the RFC's Design text: the session made them constraints, not RFC text, and the decided file may differ from the reviewed blob only in its state, its decision record and its Decision section.
- Binding host constraints only on our daemon: our daemon and the host contract would answer one case two ways (P17), so 1a, MN13, m1 and m2 also bind #245, and m3 binds #246.

## Revisit when
- A verdict by an evaluator of RFC 0005's review fails `f6f1ead`, or a later comment shows a defect in the accepted text; either opens an amendment of RFC 0005 (`docs/design/30` section 3).
- #245 or #246 lands with a change that RFC 0005's Unresolved question 1 or 2 lists.
- RFC 0007 or RFC 0002 is accepted with other row names, keys or entry forms than RFC 0005 assumes (Unresolved questions 3 and 4).
- #418 starts the C handle record, which constraint 9 holds back until the embedding slice.
