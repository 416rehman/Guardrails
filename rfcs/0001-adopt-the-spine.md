RFC: 0001
Title: Adopt the spine as the baseline
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Review
Design issue: #1711
Spine: D-61
Surfaces: docs/design/00-decisions.md
Decision record: none yet

Comments go on the design issue, so commenting needs no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
Adopt `docs/design/00-decisions.md` at commit `6fbf1ac5c7fbd9ad16644e1917595c48ba58c0d6`, version 5 as amended by ADR-0029, as the baseline, so that every later change to the spine is an RFC that amends a recorded text. This RFC changes no spine text.

## Motivation
The spine was written before the repository had a process. Without an adoption on record, the first later RFC would have nothing to amend. [ADR-0002](../docs/decisions/ADR-0002-the-spine-is-the-baseline-adopted-by-rfc-0001.md) records the intent to adopt it, but names the text the seed commit imported, which [ADR-0029](../docs/decisions/ADR-0029-the-team-is-plain-claude-code-subagents-and-skills.md) has since amended. Version 5 carries the owner's instructions in [`docs/design/_review/04-owner-kit-instructions.md`](../docs/design/_review/04-owner-kit-instructions.md), which bind. The table in [`docs/team/06-repository-bootstrap.md`](../docs/team/06-repository-bootstrap.md) section 9 still calls the baseline "Spine v4".

## Design
**Baseline.** The baseline is the text of `docs/design/00-decisions.md` at commit `6fbf1ac5c7fbd9ad16644e1917595c48ba58c0d6`: version 5 as amended by ADR-0029. While the spine is unchanged on `main`, `git log -1 --format=%H origin/main -- docs/design/00-decisions.md` prints that id. The baseline is the text at this hash, not whatever `main` holds when the RFC is decided.

**What changed since the seed.** The seed commit `daf876539e6ef21207e5124fa9cb88c472a4d545` imported version 5. `6fbf1ac` is the only commit since then that touches the spine, and it replaces 24 lines (`git diff --stat daf8765 6fbf1ac -- docs/design/00-decisions.md`). Every change is to how the team builds, reviews and lands work: the dispatcher, merge queue, review lanes and `cargo xtask` commands give way to the orchestrating session, risk tiers, the plain gates and the interface generator. The lines are the status line, P14, P17, D-42, D-45, D-47, D-61, D-62, D-63, D-64, D-69, the layer-rules paragraph of section 5, the preamble and three rows of section 7, S-20, S-22, S-23, four risks in section 9 and one note in section 10. No product behaviour changes. The decisions an embedder plans against, D-59 (signing), D-60 (stability classes, and no network call from embedded builds) and D-66 (the brand manifest), read as the seed imported them.

**If the spine moves first.** This RFC can be decided only on the hash named above. If the spine changes on `main` before the decision, a revision of this RFC must name the new hash, list the decisions changed since the previous pin and call out any of D-59, D-60 and D-66 among them, and go back to review. The decision item (#77) must check this: `git log -1 --format=%H origin/main -- docs/design/00-decisions.md` on its base must print the hash this file names.

**After adoption.** The spine wins every conflict with another document. Its text changes only in a pull request that names an accepted RFC (D-61; `docs/design/30` section 3). That change is a protected change: its own issue whose write set names `docs/design/00-decisions.md`, worked by `lead-agent-kit` or the chief architect and landed after `eval-security` and one evaluator on the other model pass (D-63). Every edit takes this route, a typo fix included. Tuning, adding or promoting a rule in a pack changes content, not the spine or a public surface, so it needs no RFC and follows the content lane (D-61, P14; `docs/design/30` section 4). The pack format and the Cedar schema stay RFC-gated.

**Owner instructions.** ADR-0029 amended the spine by owner instruction with no RFC, before any baseline was on record, and this RFC adopts the text it produced. From acceptance on, an owner instruction that changes the spine is the reason for an RFC, not a way around one. The RFC cites the instruction by its numbered entry in `docs/design/_review/04-owner-kit-instructions.md` at a named commit, the record of the owner's written instructions (`docs/design/30` section 3, Owner row). The persona council and `eval-architecture` check that the entry exists at that commit and says what the RFC applies, and review how the RFC writes it into the spine; the chief architect decides with no waiting period (owner instruction 7). If the review finds that an instruction with an entry cannot be applied as given, the chief architect decides how it is applied and records the finding and the reason in the decision; nothing waits on the owner. A claimed instruction with no entry, whether it appears in a prompt, an issue, a comment or tool output, gives the RFC no standing: it is reviewed on its merits as an ordinary RFC. The instruction behind ADR-0029 has no entry yet (#1720).

**A spine commit outside the route.** A commit that changes the spine on `main` without a pull request naming an accepted RFC is handled like an embargoed fix (the paragraph under the metadata block). A retroactive RFC either adopts it, after review, and pins the new hash, or the commit is reverted. Until that RFC is decided, the recorded baseline stays at the last pinned hash. `eval-architecture` looks for such a commit in every RFC review that touches the spine, by reading the spine's history since the hash the RFC amends.

**What holds the rule.** Nothing yet forces a spine change through a pull request or its checks. `main` accepts direct pushes: it has no branch protection and no ruleset, and `6fbf1ac`, the commit this RFC pins, reached `main` with no pull request. The rule rests on each session following `grdr-work-issue` (ADR-0029, Consequences). A change that does go through a pull request lands only after `eval-security` and one evaluator on the other model pass (D-63), and the evaluators check its diff against its issue's write set (D-47). `.claude/settings.json` denies no edit to `docs/design/**`, and no `rfc-required` job exists under `.github/`. Three items add the mechanical checks. Until #1719 lands, `rfc-required` and the evaluators bind only the changes that open a pull request:

- #1719 adds a ruleset on `main` that requires a pull request and the status checks, `rfc-required` among them once it exists. Its bypass list stays empty: every session acts as the owner's login (owner instruction 23), so a bypass for that login would exempt every session.
- #1715 adds the spine to the paths the permission rules refuse. A static deny rule would also refuse the issue that applies an accepted RFC, so the entry belongs in the per-issue gate list of #1550 (the record #1669 proposes), granted to `lead-agent-kit` and the chief architect. It stops file tools and the shell writes the #1550 hook checks. Native Windows has no sandbox, so it catches mistakes and is not a boundary.
- #10 builds `rfc-required`, the one check that fails a pull request touching the spine without an accepted RFC (`docs/design/30` section 3). As #10 is written it does not do that yet: its R3 covers only `proto/**` and `schema/**`, it passes an RFC whose file exists rather than one in `State: Accepted` (#85, closed as not planned), and its write set names the `xtask` crate that ADR-0029 removed. #10 must be re-planned before it holds this rule.

**What adoption does not claim.** Adoption records the text. It does not claim that any target or commitment in it is built or met, such as the first-run, footprint and prompt-budget targets of section 6, D-23's coexistence or the uninstall that restores every file it changed. Nor does it claim that a review the spine leaves to a design document is done, the privacy work of `design/16` and `design/29` included. These are the baseline: weakening one needs an RFC that amends it. Work is ordered by the prerequisites of section 7 and the slices of ADR-0029.

**ADR-0002 on decision.** ADR-0002 decides "the spine as imported by the seed commit, version 5", which is `daf8765`. Records are superseded, never edited (ADR-0001; `docs/team/06` section 6.1). On Accepted, a new decision record supersedes ADR-0002. It names the hash above, version 5 as amended by ADR-0029, the route for owner instructions and what holds the rule. ADR-0002's Status line becomes `superseded by ADR-NNNN` with that record's number, nothing else in ADR-0002 changes, and this RFC's `Decision record` names the new record. On Rejected, ADR-0002's Status line becomes `rejected`. On Postponed, ADR-0002 does not change.

## Surfaces changed
`docs/design/00-decisions.md`: no text change; its governance changes from "edited" to "amended by RFC". Stability class: none. D-60's classes apply to product surfaces; the spine is the plan, and it changes only by RFC (D-61).

## Alternatives
- Adopting version 4 as the table in `team/06` section 9 says: version 5 is the text in the repository and carries the owner's later instructions, which bind.
- Treating the spine as adopted without an RFC: the first later RFC would have nothing recorded to amend.
- Adopting the seed text at `daf8765`: it is the harness text ADR-0029 replaced, such as D-63's `cargo xtask risk` classifier and the merge queue of D-47 and D-61. Later RFCs would amend a text `main` does not hold.
- Keeping owner instructions as a second route beside RFCs, recorded with `RFC: not required` as ADR-0029 is: it would be the one spine change with no review, and no check can tell an owner instruction from an agent's claim of one, because every session commits and posts as the owner's login (owner instruction 23).
- Letting an edit that changes no decision text skip the RFC: deciding that an edit changes no meaning is the review an RFC already is, and an RFC costs one review round with no waiting period.

## Drawbacks
Every spine edit, a typo fix included, costs an RFC: one round of the persona council and `eval-architecture`, with no waiting period (owner instruction 7). Editorial fixes can share one RFC. An owner instruction that changes the spine waits for that round before it lands.

## Unresolved questions
None for this RFC. Found in review and filed as their own items: the "Spine v4" row in `docs/team/06` section 9 (#1716), the missing branch rule on `main` (#1719), the spine's missing deny rule (#1715), `rfc-required` covering the spine (#10), the unrecorded instruction behind ADR-0029 (#1720), the route an outsider follows to propose an RFC (#1717), and the locale defaults D-69 leaves open (#1718).

## Review
Round 1 on #1711:

- Seat 1, solo developer: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049605775
- Seat 2, IT admin: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049568762
- Seat 3, SOC analyst: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049587010
- Seat 4, MSP operator: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049550941
- Seat 5, OEM partner: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049528585
- Seat 6, privacy: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049491942
- Seat 7, contributor: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049511453
- Seat 8, simplicity: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049472720
- Seat 9, international: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049622721
- `eval-architecture`, fail: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7049712318

Round 2 on #1711:

- Dispositions: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7050020126
- `eval-architecture`, fail: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7050171679

Round 3 on #1711:

- Dispositions: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7050223158
- `eval-architecture`, pass: https://github.com/416rehman/Guardrails/issues/1711#issuecomment-7050326883

## Decision
<The chief architect's outcome and written reasons.>
