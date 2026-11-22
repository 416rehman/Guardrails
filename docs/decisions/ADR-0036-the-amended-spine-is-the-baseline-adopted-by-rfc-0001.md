# ADR-0036: The amended spine is the baseline, adopted by RFC 0001

- Status: accepted
- Date: 2026-11-21
- Decided by: chief architect
- Spine: D-47, D-61, D-62, D-63, P2
- Requires: #1818 (on `main`); the review of RFC 0001 on #1711 by the nine persona council seats and `eval-architecture`, on the decided text
- RFC: 0001 ([`rfcs/0001-adopt-the-spine.md`](../../rfcs/0001-adopt-the-spine.md)), accepted on #1711
- Work items: #77, [WI-0008] (#10)

Supersedes [ADR-0002](ADR-0002-the-spine-is-the-baseline-adopted-by-rfc-0001.md), whose Decision names the spine as the seed commit `daf8765` imported it.

## Context
ADR-0002 recorded the plan to adopt the spine through RFC 0001, naming the seed text. ADR-0029 and ADR-0035 have since amended that text by owner instruction, so ADR-0002 names a text `main` no longer holds, and a record is superseded, never edited (ADR-0001). RFC 0001 went through six revisions on #1711 and #55 ([Review](../../rfcs/0001-adopt-the-spine.md#review)). The decided text is RFC file blob `b3eacc9fa915434ba22e75f481f99a42a28fb910`. The nine seats commented on that blob and raised no blocker; every note has a disposition at https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7070812061. On #55, `eval-security` (https://github.com/416rehman/Guardrails/issues/55#issuecomment-7070000776) and `eval-diff` (https://github.com/416rehman/Guardrails/issues/55#issuecomment-7069733212), on two models, passed blob `0b91b7f`, which differs from `b3eacc9` by one Review link line. Their minor findings that bear on this commit are recorded below. `eval-adversarial` ran no open attack search on revisions 5 and 6 of the RFC text. Its revision 5 pass (https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7069342495) was a bounded re-run of the round 4 seeds, and revision 6, which added the state table and the committed evidence, had no `eval-adversarial` run (https://github.com/416rehman/Guardrails/issues/55#issuecomment-7069540489). #77's own `eval-adversarial` replay covers the forms this commit lands (https://github.com/416rehman/Guardrails/issues/77#issuecomment-7071309945). The route's rules as a whole are first attacked when #1741 builds them.

## Decision
**Baseline.** The baseline is `docs/design/00-decisions.md` at commit `6d42c3d687e4597da5e6212aa78f1f28e65df496`: blob `a80859235e7a2a4444648d6fa8d389d78dde6be9`, SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`, version 5 as amended by ADR-0029 and ADR-0035 ([RFC 0001, "Baseline"](../../rfcs/0001-adopt-the-spine.md#design)). From this decision on, the spine changes only by an accepted RFC, an owner instruction included ("After adoption" and "Owner instructions"), and it wins every conflict with another document.

**Registry and decision lines.** `rfcs/pins.toml` holds one `[[pin]]` record with the keys `path`, `blob`, `sha256` and `rfc`: the spine at the blob and SHA-256 above, put in force by RFC 0001 ([RFC 0001, "The pin registry"](../../rfcs/0001-adopt-the-spine.md#design)). Decision lines and their states, Open, Applied and Withdrawn, are those of [RFC 0001, "Decision lines"](../../rfcs/0001-adopt-the-spine.md#design). A decision line stands alone on its line in its RFC's `Decision` section, outside any fence or HTML comment, with single spaces and this key order:

`decision rfc=<NNNN> path=<path> proposed=<blob> proposed-sha256=<hex> base=<blob> rfc-file=<blob> pass=<comment id> pass-sha256=<hex>`

A withdrawal line is `withdraw` followed by the same fields, in the same order, of the line it names. These are the forms #1741 parses and #1819 writes into the template. RFC 0001's own adoption line is in [its Decision section](../../rfcs/0001-adopt-the-spine.md#decision).

**The route.** Adopted as RFC 0001 states them: committed evidence under `rfcs/evidence/` ("Review binds the decision"), the table of "RFC states", the three rules of "In route", the limit that a pinned file is never renamed or deleted ("The pin registry"), the route for owner instructions ("Owner instructions") and "What holds the rule" ([RFC 0001, Design](../../rfcs/0001-adopt-the-spine.md#design)).

**Review.** The decision rests on the `eval-architecture` pass https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7069489546. Its role lines are RFC file `b3eacc9`, and proposed text and base `a808592` with the SHA-256 above, and no verdict on those blobs fails ([RFC 0001, "Review binds the decision"](../../rfcs/0001-adopt-the-spine.md#design)). Its body is `rfcs/evidence/7069489546.md`, the only verdict on #1711 that names all three blobs.

**Where review binding is checked** (`eval-security` minor 1, https://github.com/416rehman/Guardrails/issues/77#issuecomment-7071222037). The decision line names `rfc-file=b3eacc9fa915434ba22e75f481f99a42a28fb910`, a blob reachable only from `issue/55`, not from `main`, because #55 landed as a squash commit. That the decided RFC file differs from the reviewed blob only where "Review binds the decision" allows is checked once, at landing. For this line #77's evaluators made that check (AC-8 and the R9 comparison). The replay judges only from objects in `main`'s history, as that section's replay bullet lists them, and never diffs against the reviewed blob again ([RFC 0001, "Review binds the decision"](../../rfcs/0001-adopt-the-spine.md#design)).

**What this acceptance binds** (seat 8, note 1, taken in part). Only a later accepted RFC changes these:
1. the pin;
2. `rfcs/pins.toml`, its four keys, and the rule that a record is added only by an adoption, changes only by an apply and never leaves;
3. the decision line and withdrawal line forms, and the rule that a line or evidence file added in route is never edited or removed;
4. the property the route holds: on `main` the text of a pinned path changes only in a commit that applies an open decision line of an `Accepted` RFC, decided on blobs its review named, and every other change to a pinned path, its record, or a line or evidence file added in route is out of route and is reverted.

The other mechanisms of RFC 0001's Design (the state table, the replay that finds the pin in force, path equivalence, how evidence is committed and read, the evaluator set, detection and the role lines) are the design that #1741, #1759, #1798, #1819 and #1821 build. A later change to one of them that keeps items 1 to 4 and every outcome RFC 0001 makes fail closed, and that leaves the replay's verdict on every commit already on `main` unchanged, shown by a fixture that replays `main` before and after the change, is a protected change (D-63) that names this record and writes the new rule into `docs/design/30` section 3, which from then on wins over RFC 0001's Design for that mechanism. It is not an RFC amending RFC 0001. A change that loosens items 1 to 4, or makes an outcome that fails closed pass, is an RFC. Any other change to one of them is an RFC.

**Verdict content** (seat 6, note 2). Evidence is public and permanent. A verdict or seat comment on an RFC's design issue cites fields, files, screens, commands and blob ids, and never quotes captured content, a real person's data or a secret. One that does is deleted and posted again without it before its line lands, and a pass deleted before landing is replaced by a new pass and new evidence ("Review binds the decision"). The chief architect reads every evidence body for this before it decides.

**Unicode version** (seat 9, note 3). The checker fixes the Unicode version of its path equivalence ([RFC 0001, "The pin registry"](../../rfcs/0001-adopt-the-spine.md#design)): its job pins the Python version, and it compares `unicodedata.unidata_version` with a value in its data and fails closed with its own code when they differ.

**Coverage reading** (`eval-diff` minor 1, https://github.com/416rehman/Guardrails/issues/55#issuecomment-7069733212). This commit creates the registry before `governance/rfc-required.toml` exists. The checker reads which paths that file covers from the head it judges toward (the pull request's base, or `main`'s head), never from each commit in the replay, so the replay does not fail closed on this commit ([RFC 0001, "The pin registry"](../../rfcs/0001-adopt-the-spine.md#design)). #1741 owns the fixture.

**Evidence added in route** (`eval-diff` minor 2, same source). Rule 1 of "In route" protects only lines and evidence files added in route. An evidence file is added in route only in the commit that adds a decision line it covers. Any other addition under `rfcs/evidence/` is out of route, so the revert of [RFC 0001, "A spine outside the route"](../../rfcs/0001-adopt-the-spine.md#design) may remove it and still meet rule 1.

**Line endings.** Until #1741 adds `rfcs/evidence/** -text` to `.gitattributes`, the evidence of this commit holds no CR byte, so `* text=auto eol=lf` leaves it unchanged ([RFC 0001, "Review binds the decision"](../../rfcs/0001-adopt-the-spine.md#design)).

## Enforced by
The mechanisms of [RFC 0001, "What holds the rule"](../../rfcs/0001-adopt-the-spine.md#design), with what exists on `main` when this record lands:
- The ruleset on `main` (#1719): active, with an empty bypass list, a squash-merged pull request for every change and required status checks. #1719 stays open until `rfc-required` and the write-set job join its required checks.
- The registry and `rfcs/evidence/` in the trust core (#1818): on `main`, both listed in `security/trust-core.paths`.
- The one checker and `rfc-required` (#1741): open, not built. Its golden cases replay this commit first and judge it in route by rule 3, and its fixtures hold items 1 to 4 above, the Unicode version and the two readings of `eval-diff`. Its scope also takes the review-binding reading above: `rfc-required` diffs the decided RFC file against the reviewed blob on the pull request that adds a line, and the replay reads no object outside `main`'s history, so its golden case passes on a single-branch clone of `main`.
- Detection (#1759): open, not built.
- Role lines in verdicts and seat comments (#1798): open. It also carries the verdict content rule above.
- The `Withdrawn` state, the state table and the line forms in `docs/design/30` section 3 and the template (#1819): open.
- The high evaluator set for the spine, RFCs and decision records (#1758): open.
- `eval-security` and `eval-adversarial` in the `[kinds] rfc` row (#1821): open.
- The write-set job, with the protected-path list read from the base (#1668): open.

Until #1741 lands no mechanical check reads the registry or a decision line, and the rule holds by review: the evaluators read every diff against its issue's write set and the protected-path list of `team/06` section 2.1 (ADR-0035), and D-63's protected change carries `eval-security` and an evaluator on the other model for every change to the spine, `rfcs/**` and `docs/decisions/**`. Whether a change to a mechanism keeps items 1 to 4 is judged by review only: `eval-security` and `eval-architecture`, on every pull request that changes `docs/design/30` section 3, the checker, the registry or `rfcs/evidence/`. #1758 maps `docs/design/30-open-source-governance-and-community.md` to the high set beside the spine, so that review does not rest on an issue's label.

No detection runs until #1759 lands. Neither agent's file tells it to run the check, and nothing runs between reviews ([RFC 0001, "Detection"](../../rfcs/0001-adopt-the-spine.md#design); `eval-security` F2).

## Consequences
- Every later spine change is an RFC that amends this recorded text, decided by a line naming its blobs. The first amending RFC has a pin to start from.
- The checker, its fixtures and `docs/design/30` section 3 can change by protected change while they keep what this acceptance binds, without an RFC amending RFC 0001.
- After a revert, only the CI job's push-time issue records the window in which an out-of-route text was in force, and a drift reverted before any detector runs leaves no record. A change to a workflow, the checker or the registry is caught only by evaluator review ([RFC 0001, "Detection" and "What the single login leaves open"](../../rfcs/0001-adopt-the-spine.md#design); `eval-security` F3).
- The record conflict stops two applies from one pin. It does not stop an apply racing the withdrawal of its own line, because the ruleset's `strict_required_status_checks_policy` is false. Such an apply is judged out of route only after it lands ([RFC 0001, "After adoption" and "What holds the rule"](../../rfcs/0001-adopt-the-spine.md#design); `eval-security` G6 (i)).
- After #1741 lands and before `rfc-required` is a required check of the `main` ruleset (#1719), a pull request can merge with `rfc-required` red. Nothing then diffs that decision against its reviewed blob again: the replay never does, and the push-time detector makes only the API read ([RFC 0001, "Detection"](../../rfcs/0001-adopt-the-spine.md#design)). A decided RFC file that changed after review would be judged in route for good. The window is closed by adding `rfc-required` to the ruleset's required checks in the same change that lands #1741 (`eval-diff` round 2, https://github.com/416rehman/Guardrails/issues/77#issuecomment-7071534082).
- Evidence bodies are committed verbatim and are never removed in route. An RFC decided in a private fork under D-62 lands only through the by-hand landing comparison, and its evidence bodies become public as written, so they are reviewed for disclosure before they land ([RFC 0001, "After adoption" and "Review binds the decision"](../../rfcs/0001-adopt-the-spine.md#design); `eval-security` G6 (iv), https://github.com/416rehman/Guardrails/issues/55#issuecomment-7070000776).
- The single owner login is residual risk. No check can tell a verdict an evaluator posted from one a session wrote, so the route makes the decided text the text a pass names and does not make the pass genuine ([RFC 0001, "What the single login leaves open"](../../rfcs/0001-adopt-the-spine.md#design); ADR-0035).
- Adoption records the text; it does not claim that any target or commitment in it is built or met ([RFC 0001, "What adoption does not claim"](../../rfcs/0001-adopt-the-spine.md#design)).

## Alternatives rejected
- Those of [RFC 0001, Alternatives](../../rfcs/0001-adopt-the-spine.md#alternatives).
- Binding the pin and the registry only, leaving the line forms and the property changeable without an RFC (seat 8, note 1 as written): every replay reads the line forms of every landed line, so changing them rewrites history, and the property is what D-61 asks the route to hold.
- Binding every mechanism of the Design text: a defect #1741 finds while building the checker, or a simpler mechanism with the same result, would cost an RFC amending an RFC, and the route would live in two documents once #1819 lands.
- Dropping the evidence folder, pinning by SHA-256 only, deferring case folding, or replacing the replay by rule (seat 8, notes 2 to 5): the reasons are in the dispositions on #1711 linked under Context.

## Revisit when
- #1741's replay does not judge this commit in route by rule 3.
- #1741 or #1759 is closed without landing, which leaves the route held by review alone.
- A comment that shows a defect in what this acceptance binds arrives after the decision; it opens a new RFC (`docs/design/30` section 3).
- The repository moves to SHA-256 object ids; the RFC for that move restates the blob ids ("Baseline").
