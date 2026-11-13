RFC: 0001
Title: Adopt the spine as the baseline
Author: chief-architect
Harness: Claude Code
Model: claude-sonnet-5-5
State: Review
Design issue: #<open: the `kind:rfc` issue titled "RFC 0001: adopt the spine as the baseline" is not filed yet>
Spine: D-61
Surfaces: docs/design/00-decisions.md
Decision record: none yet

Comments go on the design issue, so commenting needs no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
Adopt `docs/design/00-decisions.md` at version 5 unchanged as the baseline, so that every later change to the spine is an RFC that amends a recorded text.

## Motivation
The spine was written before the repository had a process. Without an adoption on record, the first later RFC would have nothing to amend. `docs/team/06` section 9 still says "Spine v4"; ADR-0002 records that version 5 is the text in the repository.

## Design
The baseline is `docs/design/00-decisions.md` at version 5, identified by the last commit that changed it on the merge base: `daf876539e6ef21207e5124fa9cb88c472a4d545` (`git log -1 --format=%H origin/main -- docs/design/00-decisions.md`). From acceptance on, the spine changes only by RFC and wins every conflict with another document (ADR-0002). If the spine changes on the main branch before this RFC is decided, the decision is made on the text named here or on a revision of this RFC that names the new commit.

## Surfaces changed
`docs/design/00-decisions.md`: no text change; its governance changes from "edited" to "amended by RFC".

## Alternatives
- Adopting version 4 as the table in `team/06` section 9 says: version 5 is the text in the repository and carries the owner's later instructions, which bind.
- Treating the spine as adopted without an RFC: the first later RFC would have nothing recorded to amend.

## Drawbacks
Every spine edit, however small, costs an RFC.

## Unresolved questions
None. The "Spine v4" wording in `docs/team/06` section 9 is fixed by its own item.

## Review
<Links to each persona council seat comment and to the `eval-architecture` verdict on the design issue.>

## Decision
<The chief architect's outcome and written reasons.>
