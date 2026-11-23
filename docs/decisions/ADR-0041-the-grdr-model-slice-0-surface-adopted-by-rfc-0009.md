# ADR-0041: The slice-0 surface of grdr-model is the one RFC 0009 states, built under the constraints of its decision

- Status: accepted
- Date: 2026-11-22
- Decided by: chief architect
- Spine: D-05, D-06, D-15, D-36, D-48, D-51, D-60, D-61, D-63, P1, P5, P8, P9, P14, P15, P17
- Requires: #1979 (RFC 0009 on `main` in State: Review); RFC 0007 accepted on `main` (#1850 R5); the review of RFC 0009 on #1850 by the nine persona council seats, `eval-architecture`, `eval-api`, `eval-security` and `eval-adversarial`
- RFC: 0009 ([`rfcs/0009-grdr-model-slice-0-surface.md`](../../rfcs/0009-grdr-model-slice-0-surface.md)), accepted on #1850
- Work items: #1982 (superseded on pull request #1991 by #2004); #383, #18, #282 (with #1995 to #1997), #284, #279, #281, #283, #246, #386, #388, #1690, #1853, #1966, #1994; the owners its constraints bind; #1984 to #1990, filed on acceptance; #1998 and #2001, filed in this record's revisions 2 and 3

## Context
#383 (time, `Entropy` and ids), #18 (the envelope's lane, epoch and sequence), #282 (the retry state types) and #284 (`LogSafe` and the log record) add the first public items to `grdr-model`, and RFC 0002, RFC 0003, RFC 0007 and RFC 0008 already use them. No RFC stated their signatures, and the texts disagreed: four lanes against five, `HolderId` in two crates, two names for the give-up reason, an `Entropy::fill` that could not report a failure, every id loggable against design/21's two, and a remote call able to read a `local` retry table ([RFC 0009, Motivation](../../rfcs/0009-grdr-model-slice-0-surface.md#motivation)). `grdr-model` is public in layer 1, so its surface changes only by RFC (D-61).

RFC 0009 went through three revisions on #1850. Round 1 failed on the breaker's representable states and a window literal; round 2 failed on the turn bound of a dropped call probe. The reviewed text is RFC file blob `e1f4f50307ec78e6610008cbe53343e7951ce837`, written against the spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9`, and the accepted file is blob `4f36df6f0b2ce122d3b09d8109e83fb4720b1c68`, which differs from it only in `State:`, `Decision record:` and the Decision section. On the reviewed blob every evaluator the review calls for passed, each naming that blob and the base, with no blocker or major:
- `eval-api` (Sonnet, the other model from the RFC's metadata), https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085494964, no findings;
- `eval-architecture` (Sonnet), https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085509746, one minor;
- `eval-security` (Sonnet), https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085582842, three minors, with a disclosed deviation the RFC's Decision section weighs;
- `eval-adversarial` (Opus), https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085612435, three minors.

The nine seats reviewed the same blob. All nine support it with changes and none names a broken spine floor. The orchestrating session makes the owner's decisions (#1828). Its exit rule decides an RFC after the first round with no blocker or major and writes that round's minors, and the seats' changes, into the decision as constraints (https://github.com/416rehman/Guardrails/issues/1828#issuecomment-7074036273). Its rulings S1 to S7 on the seats are https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085697482, its rulings D1 to D5 on this record's round 1 are quoted in the comment "Decision record revision 2" on #1850, its rulings E1 to E5 on round 2 are quoted in "Decision record revision 3", and #2004 gives the session's text for constraint 1a's controls and residual and carries round 3's minors as constraints. The RFC's [Decision section](../../rfcs/0009-grdr-model-slice-0-surface.md#decision) relies on all of them.

## Decision
**Accepted.** The slice-0 surface of `grdr-model` is RFC 0009 as reviewed at RFC file blob `e1f4f50307ec78e6610008cbe53343e7951ce837` and accepted as file blob `4f36df6f0b2ce122d3b09d8109e83fb4720b1c68`, with the spine pin above as its base ([RFC 0009, Design](../../rfcs/0009-grdr-model-slice-0-surface.md#design)), and so are its amendments of RFC 0007 sections 5 and 6 and RFC 0008 section 8 changes 4 and 5 (section 16). In outline:
- `grdr-model` depends on `grdr-schema` only, with `grdr-proto` as a dev-dependency; it does no I/O, reads no clock or randomness, and puts every public item at its root (R1 to R3).
- `Entropy::fill` returns `Result<(), EntropyError>`. A failed source is `GRDR-MODEL-0003`, `fatal` with `failed_precondition`, never bytes the source did not produce and never a peer's fault (section 3).
- Ids come from one macro list, `IdKind`, with three mint routes; `DelegationSnapshotId` is `dls_` on UUIDv7, `HolderId` is `hld_` in this crate and the capability `Holder` stays in `grdr-ports` (section 4).
- `Lane` is `Uploaded(UploadedLane)` or `Local`; the server and the device's upload path take `UploadedLane`, and `lane_wire` holds `Lane` to the protobuf enum by walking the descriptor (section 5).
- `RetryPolicy::from_limits(table, access)` is the one constructor, with `PeerAccess::retry_peer` as the one classifier and a consistency check; `Breaker` is four states with `OpenPhase` and `HalfOpenPhase` and RFC 0008's turn timing; the failure share counts over the registered key `budget_share_attempts` (section 6, section 16).
- A log line carries only `LogValue`s: names fixed at build time, no integer type, and only `OrgId` and `DelegationSnapshotId` among the ids (section 7).
- `InstallProfile` and `Tamper` are at the crate root (section 8), and the crate enters `surfaces.toml` as `experimental` (section 13).

**No pin and no evidence.** RFC 0009 decides no pinned path, so its Decision section holds no decision line, `rfcs/pins.toml` is unchanged, and nothing is added under `rfcs/evidence/` ([RFC 0001, "RFC states"](../../rfcs/0001-adopt-the-spine.md#design); [ADR-0036](ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md), "Evidence added in route").

**Constraints.** The decision binds the constraints of the RFC's Decision section, each on the issues it names, and each was posted on those issues. Where a constraint and the RFC text differ, the constraint wins for those issues. A constraint narrows, orders, tests or refuses within what the RFC states; by session rulings, constraint 3c makes one required key optional with a registered default (S1) and constraint 5 moves the `MODEL` tokens from the registering items to #1853 (D5); a new id row is content; any other change to a public item, variant or signature, a change to an existing type's shape or meaning, and a new loggable kind are amendments. In outline:
1. The round 3 minors:
   - the log-gate scan (#1989). Where the scan resolves its type, an operand loggable by type (`bool`, a wire enum or `Lane`, `Code` and this crate's error enums, `OrgId`, `DelegationSnapshotId`), and `<x>.log_value()` or `LogValue::Bool`, `Enum` or `Code` over one in `LogRecord::new`, passes with no marker. An operand of a type of 1c's set, a `LogValue`, an opaque `impl LogSafe` or a type the scan cannot determine fails unless every leaf traces to a literal, a `limits` constant, a length or count of a resolved standard collection or a `Clock` reading, joined by the listed operators and 1c's constructors (`Duration`'s in `architecture.toml` included), over plain `let` bindings never borrowed `&mut` whose every assignment traces, or its line carries a marker with a stable id that states the value's origin and that it is not an identifier (and callers on a parameter site). A value through a parameter, a struct field, a trait object, a closure, a helper, an alias, a function value, a `&mut`-borrowed or non-plain pattern binding, or a workspace macro, a custom `impl LogSafe` outside `grdr-model`, and `Duration::new` on untraced arguments fail unless marked. The scan lists, in changed lines, calls and function-value references resolved by name (over-approximating) to a function with a marked parameter site and new constructors or uses of a marked impl's type, and `eval-security` also reads the scan's marker report when its count or ids change. The scan is a tripwire against accident for the forms it names. Its controls are separate:
     - The `LogSafe` type gate bounds what a log field can be: a typed value. It cannot tell a count from a wrapped identifier.
     - The scan fails the named forms, and it lists the named calls and uses in the lines a pull request adds or changes.
     - `eval-security` reads every marker, every listed call or use, and every changed line in a function that holds a marked site (#1990).

     Every other way an identifier's value can reach a log has no dedicated control and rests on `eval-security`'s ordinary reading of the diff. That includes, among others:
     - a value that reaches a marked site from code outside the function that holds it, such as a field writer, a helper body, an impl, or a call the scan cannot resolve;
     - a mixed expression;
     - a carrier collection;
     - an unseen closure or macro.

     Building such a carrier on purpose is outside "accident". Binds #1989, #1990, #1988, #2001 and #284;
   - the name macros take `$l:literal`, and a hand-written `LiteralText` takes literals only (#284, #1989);
   - the scan's set is derived from `LogValue`'s payloads and this crate's `LogSafe` impls (#1989);
   - a failed draw in `Engine::step` is a typed failure on every input (#1537, #1536);
   - `BudgetShareBelowBreaker` follows `BreakerFailuresAboveCeiling`, and `narrow` compares fields first (#279);
   - `OwnFile` is shown from the opened handle: `f_type` on Linux and `f_fstypename` on macOS against one local allow-list, with remote-backed block devices a stated residual (#301, #1542, #30).
2. The seats' changes:
   - Seat 1: an undecided install profile, a default state directory that is never refused, with the UNC first-run test, and a record lookup in `grdr` and the desktop (#1987, #1610, #1286, #669, #1379).
   - Seat 2: health codes and skew counting; presentation words; the breaker's state word, deferred to #1289's amendment.
   - Seat 3: a coverage-gap record after a failed draw, failures named in health and audit records, replay by outcome, and stable record words (#476, #760, #763).
   - Seat 4: the rollout correlation id by #757's amendment, and one retry state per cell.
   - Seat 5: the seeded generator of the embedding interfaces by an amendment that #388 brings, sharing one algorithm with the kit's `SeededEntropy` and stating the algorithm's 256-bit expansion strength (or that no minted id is a secret), whether the kit's SplitMix64 vector stays as `from_seed(u64)`, what equal seeds means across `u64` and `[u8; 32]`, whether any consumer keys on a minted id across calls, and how a reused seed is detected or that it is not; what an embedder may rely on; `Tamper` from a host; no partner id kinds (#388, #281, #246, #242).
   - Seat 6: the per-field layer note. The field registry names the pseudonym layer of every principal-id field at each place it is stored or sent; device-side sinks, standalone export, the archive (with its backup marker) and the bundle carry it; the archive (with its `backup --to` and `migrate --to ha` copies) is device-layer by design, written by `store` (re-framed by compaction and rewritten in batch contents only by archive reduction), read by `lake rebuild`, `restore`, chain verification, `restore --verify`, the bundle and #1307's archive-reading export (which gets organisation-layer values from the existing key holder and holds no key itself, or declares any extra holder in design/21's key table), with operator and owner roles named; #1690's test walks every `PrincipalId` field by descriptor (#386, #1690, #1302, #1332, #1547, #1222, #1307).
   - Seat 7: evidence in the repository; diagnostics, whose messages `eval-api` reads; gate tools and contributor paths (#1741, #10).
   - Seat 9: labels, tokens with typed arguments, the id alphabet and one time type (#1618, #1612).
3. Seat 8 as the session ruled: only the id kinds slice 0 uses, with `ost`, `acc`, `sup`, `exp`, `grp` and `opr` named to their items (#1596, #306, #483, #442, #755, #1584). The floor row is kept and `budget_share_attempts` gets a registered default that is applied only after the rules pass on the keys as written (#279, #1966). One name type, fewer `LogValue` variants and crate-private breaker states are declined.
4. Amendments and other RFCs, each brought by its item before it is readied:
   - the breaker's state word (#1289);
   - the rollout correlation id (#757);
   - the seeded `Entropy` implementor, amending RFC 0008 and RFC 0009 (#388);
   - two principal types, if a field needs them (#1690);
   - an `Output` member by its own RFC, if the embed path needs one (#246);
   - the RFC 0007 section 4 sentence, filed as #1998 and merged to `main` in `State: Review` as RFC 0010 (pull request #2000, awaiting its decision).
5. The `MODEL` codes' tokens are written by #1853, not by the items that register the codes (#383, #1986, #1994, #1995; `lead-core` cleans the parent #282's body to match), which are blocked by #1998, not by the token tree #1614. RFC 0010 orders the merges (its R5) and gives the exit if #1853 lands first. If RFC 0010 is declined, the session's fallback is that #1853 is blocked by the registering items; that conflicts with RFC 0007 section 4 as it stands, so the declining decision states the order it keeps and updates the four items' blocker links so a declined #1998 does not keep blocking them.

**What this acceptance binds.** What RFC 0009 states changes only by an amendment of RFC 0009, a new RFC that names it (section 13), and so do its amendments of RFC 0007 and RFC 0008, which an amendment names beside RFC 0009. The baseline is what RFC 0009 states together with the forms its constraints set, such as constraint 1a's rule, its accepted sources, its joins, its listing and the marker form #1989 fixes, and constraint 3c's registered default. Every other later change takes the lane of the table below. The lanes stack: a change that matches more than one row takes each of them.

## Lanes for later changes
| Change | Lane |
|---|---|
| A new row of the id table, not loggable, under section 4's rules and constraint 3a | Content under RFC 0009: the item that first uses the kind adds the row, its pull request names RFC 0009 for `rfc-required`, and `eval-api` reads the prefix against section 4's table. High tier through `crates/grdr-model/**`. A row that changes an existing type's shape or meaning, such as splitting `PrincipalId` by pseudonym layer, takes the amendment row |
| A new code in the `MODEL` area | Content under RFC 0007 and RFC 0009: the item that first constructs it registers it in `schema/codes/model.toml`, and its tokens come by RFC 0007 section 4's route as constraint 5 sets it |
| A change to what RFC 0009 states or to a form its constraints set: a signature, a semantic, a variant, a grammar, a code's class, the loggable kinds, the access classification, the lane mapping, the default of constraint 3c, and the promotion of `grdr-model` out of `experimental` | An amendment, a new RFC that names RFC 0009, reviewed by the persona council once and the evaluators of the `[kinds] rfc` row of `.claude/risk-tiers.toml` on its base (RFC 0001), with `eval-api`, `eval-security` and `eval-adversarial` always, as ADR-0040's row has them, and one evaluator on the other model. An amendment that also changes RFC 0007's retry rules or RFC 0008's breaker names those RFCs too |
| A change to the log-gate scan of #1989: its reach, the sources and joins it accepts, what it lists, the source of its derived set, its exempt paths, its fixtures, the `LiteralText` allow list or the marker form (constraints 1a to 1c) | The amendment row, and the `architecture.toml` row below for the entries the scan reads. The scan's module and fixtures are trust-core paths once #2001 lands, so every change to them, one that keeps all of these included, takes `eval-security`, `eval-adversarial` and two passing evaluators on different models |
| An allow marker on a log line, a custom `impl LogSafe` outside `grdr-model` with its marker, and any pull request the scan lists a call or a use for | The lane of the pull request. `eval-security` reads every marker it adds or changes, a touched marked line included, every listed call or use, every changed line in a function that holds a marked site, and the scan's marker report when its count or ids change, and refuses a marker that does not state an origin that is not an identifier or a read site whose value is an identifier (#1990) |
| An `architecture.toml` entry: an ARCH-003 implementor, an ARCH-018 list, an ARCH-019 or ARCH-021 entry, and the log-gate scan's accepted sources (leaves, standard-collection list and clock methods), joins, `Duration` constructors, source of its derived set and exempt paths | A protected change on a trust-core path, worked by lead-agent-kit or the chief architect: `eval-security`, `eval-adversarial` and two passing evaluators on different models. An ARCH-003 implementor that RFC 0008 R3 and RFC 0009 section 3 do not state, such as #388's seeded generator, is also an amendment of both |
| A further edge of `grdr-model`, or a change to #1984's | A protected change on `Cargo.lock` and `architecture.toml`, trust-core paths: `eval-security`, `eval-adversarial` and two passing evaluators on different models. A new dependency is also an amendment (R1) |
| The `[[crate]]` row of #1985 | Trust core: `eval-security`, `eval-adversarial` and two passing evaluators on different models |
| Any `limits.toml` row or range change, a `[retry.<name>]` table's `budget_share_attempts` and the rows `retry-bounds.share-attempts-ceiling` and `retry-bounds.share-multiple-floor` included | A protected change on a trust-core path, on the full lane: `eval-security`, `eval-adversarial` and two passing evaluators on different models, as RFC 0007 section 6 has every row. A change to what the rows mean also takes the amendment row |
| A constraint of the Decision section | Checked by the evaluators of the item it binds, on that item's pull request |

## What an embedder may rely on
Seat 5 asked for this list (constraint 2e). The class is the crate's; the wire forms are stable from the first release whatever the class (RFC 0009 section 13; RFC 0007 section 11; D-06).

| Part | Rust API | Wire form |
|---|---|---|
| Id text and prefixes | `experimental` | Stable |
| Lane words and numbers | `experimental` | Stable |
| `MODEL` codes: area, number, reason, class, Connect code | `experimental` | Stable |
| Words of `Tamper` and `InstallProfile` in stored or exported records | `experimental` | Stable, through their protobuf twins |
| Every other item of sections 2 to 8 | `experimental` | None until a stored or exported record carries it; from then on its words are stable (constraint 2c) |
| Principal ids in a record | `experimental` | The pseudonym layer of each place is named in the field registry, and every device-side output, the archive and the bundle also state it in their output or metadata (constraint 2f) |

The C ABI, the `wasm32` binding and the host contract keep their own classes (design/26 section 3). A partner holds no id kind of its own (constraint 2e).

## Where each item is built
| Item | Built by |
|---|---|
| `Timestamp`, `TimeError`, `Entropy`, `EntropyError`, `IdKind`, `MintRoute`, `IdError`, the typed ids; codes 0001 to 0005 registered | #383, after #278, #1984 and #1998 |
| `Epoch`, `Seq`, the epoch and sequence variants of `OrderError`; codes 0010 and 0011 registered | #1994, after #278, #383, #1984 and #1998 |
| `Lane`, `UploadedLane`, the lane variants of `OrderError`, `lane_wire`; codes 0007 to 0009 registered | #1986, after #394, #17, #284, #1994, #1984 and #1998 |
| `RetryPolicy`, `RetryPolicyError`, `PeerAccess`, `AttemptCounter`, `RetryStep`, `GiveUp`; code 0006 registered | #1995 (part of #282), after #278, #279, #284, #383, #1984 and #1998 |
| `RetryBudget`, `AttemptOutcome` | #1996 (part of #282), after #279, #281, #284 and #1995 |
| `Breaker` and its state structs and phases, `Permit`, `ProbeKind`, `CheckOutcome` | #1997 (part of #282), after #281, #284 and #1995 |
| The tokens of every `MODEL` code | #1853 (constraint 5) |
| `LogSafe`, `LogValue`, `IdRef`, `LiteralText`, the name types, `LogLevel`, `LogRecord`, the macros, the impls for RFC 0007's types | #284 |
| `InstallProfile`, `Tamper` | #1987, after #284 |
| `budget_share_attempts`, the three rules, the two rows and the default | #279 |
| The edges of R1 | #1984 |
| The `[[crate]]` row | #1985, after #1817 and #1915 |
| The log-gate scan | #1989, after #1582, #284 and #2001 |
| The scan's paths on `security/trust-core.paths` | #2001 |
| The pseudonym layer of each principal-id field | #386, with #1302, #1332, #1547 and #1222 stating the device layer in their output or metadata and #1307 re-deriving the organisation layer |
| The review duties | #1990 |
| Design texts | #1988 |

## Enforced by
- RFC 0009 section 12, one mechanism per decision, each built by the item it names, with the row constraint 1d adds: private source modules and `cargo public-api` (#383, #284, #1741); the wasm32 check and ARCH-003 (#1582); the failing-source fixture (#383, #1995, #283, #1537); `lane_wire` (#1986); the compile-fail doctests of the gate, the names and the breaker (#284, #1997); the turn and share tests (#1997, #1996, #279).
- The log-gate scan of #1989, a tripwire against accident for the forms it names, with the failing, passing and listed fixtures of constraints 1a to 1c, on the trust-core paths of #2001. Its controls are separate: the `LogSafe` type gate of section 7 bounds what a log field can be (a typed value; it cannot tell a count from a wrapped identifier); the scan fails the named forms, and it lists the named calls and uses in the lines a pull request adds or changes; and `eval-security` reads every marker, every listed call or use, and every changed line in a function that holds a marked site, plus the marker report when its count or ids change (#1990). Every other way an identifier's value can reach a log has no dedicated control and rests on `eval-security`'s ordinary reading of the diff.
- #1690's descriptor-walk test (and #1307's archive-export test) for the lake, the relational rows and the server's outputs, #386's field registry for the layer every place carries, and the output or metadata statements on device-side outputs, the archive (with its backup marker) and the bundle.
- ADR-0020's stability gate over #1985's row, with `cargo public-api` and `cargo semver-checks` (#1741).
- Each constraint by the issue it binds: its lead writes it into the item before readying it, and the item's evaluators check it on its pull request. Until each item lands, a constraint holds by review only.

## Consequences
- #383, the parts of #282, #284, #1986 and #1994 have one decided surface and name RFC 0009 as their route; none of them can start before #1984 adds the edges, and #383, #1994 and #1995 wait on #1998, not on the token tree.
- RFC 0002 and RFC 0003 are not decided before they carry section 14's changes: `UploadedLane` on the server, `Holder`, the contexts' data class, `PeerAccess` in each adapter's set-up, and the root paths of `InstallProfile` and `Tamper`.
- Every function that draws can fail, so minting, `Engine::step`, the daemon's decision ids and `Setup::holder` each carry a failure that, with AWS-LC, the programs never see returned.
- A diagnostic points at a record by `(epoch, lane, seq)`, and a person can look a record up by it in `grdr` and the desktop (constraint 2a).
- A log field of a type in the scan's set whose value the scan cannot trace to a literal, a `limits` constant, a length or count of a standard collection or a clock reading (joined by the listed operators and constructors) carries a marker that states its origin, and so do most fields that log a parameter, a retry reading, an epoch, a sequence number or a value from a helper. Fields loggable by type need none where the scan resolves their type.
- The scan is a tripwire against accident for the forms it names. Its controls are separate: the `LogSafe` type gate bounds what a log field can be (a typed value; it cannot tell a count from a wrapped identifier); the scan fails the named forms, and it lists the named calls and uses in the lines a pull request adds or changes; and `eval-security` reads every marker, every listed call or use, and every changed line in a function that holds a marked site (#1990). Every other way an identifier's value can reach a log has no dedicated control and rests on `eval-security`'s ordinary reading of the diff. That includes, among others, a value that reaches a marked site from code outside the function that holds it (such as a field writer, a helper body, an impl, or a call the scan cannot resolve), a mixed expression, a carrier collection, and an unseen closure or macro; building such a carrier on purpose is outside "accident".
- The archive (with its backup and migration copies) and the organisation bundle hold device-layer pseudonyms by design; every device-side output, the archive and the bundle say which layer they hold, and the field registry names the layer for every place, server exports and `/mcp` included.
- A `MODEL` code registered before #1853 lands has no token until #1853 writes it; nothing renders a code's token before then.
- Every retry table may omit `budget_share_attempts` and gets the floor multiple of its `breaker_failures`, applied after the rules pass on what the table writes.
- `grdr doctor` cannot show a breaker's state word until #1289's amendment, a rollout's jobs are not correlated in log lines until #757's, and the embedding interfaces' seeded generator waits on #388's.

## Alternatives rejected
- Those of [RFC 0009, Alternatives](../../rfcs/0009-grdr-model-slice-0-surface.md#alternatives).
- A pin record and evidence files: RFC 0009 decides no pinned path, and evidence without a decision line is out of route (ADR-0036).
- Writing the constraints into the RFC's Design text: the accepted file may differ from the reviewed blob only in its state, its decision record and its Decision section.
- Keeping the log-gate scan as a list for review: a wrapped identifier would reach a log whenever review missed it (seat 6, `eval-security` m1; ruling S4).
- A scan that passes the values it cannot trace, as this record's first revision had it: a uid carried in by a parameter, a field or a trait object reached a log with no marker and no reader (`eval-diff` on Opus and `eval-security`, round 1 of this record; ruling D3).
- A deny list of four macros for `LiteralText`, or name macros on an `expr` fragment: a named constant, `include!` or `wire_name!(env!(..))` passes them (`eval-security` m2, `eval-adversarial`; this record's round 1).
- Seat 8's single name type, `Position` and `Instant` variants and crate-private breaker states: declined for the reasons constraints 3b, 3d and 3e give.
- Seat 2's per-install backoff offset: a second randomness source in layer 1, and needless where AWS-LC aborts and #1966 R5 spreads the restart (constraint 2b).
- A seeded `Entropy` crate for replay, as seat 3 asked: RFC 0008's decision compares outcomes and keeps the kit's generator out of every program (constraint 2c).
- A field of the `[[crate]]` row for the wire-stable parts, as seat 5 asked: RFC 0005 R6.1 fixes the row's keys, and the table above holds the list.
- A reserved prefix range for partners: a partner kind would be a fork, and `native_*` fields carry partner ids (constraint 2e).
- #1690's single ingest test in place of seat 6's per-field layer note, as this record's revision 2 had it: device-side sinks, standalone export, the archive and the bundle carry the device layer, so ingest is not the one way a principal id reaches a reader (`eval-diff` on Opus and three other lanes, round 2 of this record; ruling E2).
- A scan that claims to leave no unreviewed residual, as this record's revision 2 had it, or that claims the `LogSafe` type gate and #1990's reading hold the residual and nothing else does, as revision 3 had it: a static scan reads one function and one pull request at a time, the type gate passes any wrapped number, and neither the scan nor #1990's targeted reading reaches a carrier collection, a mixed expression, an unseen closure or macro, or a feeder outside the marked function that the listing does not resolve (`eval-adversarial`, `eval-architecture` and `eval-diff` on Opus, rounds 2 and 3 of this record; #2004).
- Leaving the `MODEL` tokens with the registering items, or moving them to #1853 under RFC 0007 section 4 as it stands: either keeps #383 behind #1613 and the token tree (constraint 5).

## Revisit when
- A verdict by an evaluator of RFC 0009's review fails `e1f4f50`, or a later comment shows a defect in the accepted text; either opens an amendment of RFC 0009 (`docs/design/30` section 3).
- #1289, #757, #388, #1690 or #246 brings the amendment or RFC constraint 4 names, or RFC 0010 (#1998) is decided or declined.
- #1966 decides a share other than over recent attempts with a registered window (RFC 0009, unresolved question 1).
- RFC 0002 or RFC 0003 is decided without section 14's changes.
- The item that adds the `srv_` row decides the server's emitter type (RFC 0009, unresolved question 2).
