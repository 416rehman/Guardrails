# ADR-0002: The spine is the baseline, adopted by RFC 0001

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-61
- Requires: RFC 0001 reviewed by the persona council and `eval-architecture`
- RFC: 0001
- Work items: [WI-0008]

## Context
`docs/design/00-decisions.md` was written before the repository had a process. It is at version 5: version 4 applied the owner's answers, and version 5 the owner's kit instructions (P14 to P17, D-69 to D-71, S-23 to S-31). `docs/team/06` section 9 still says "Spine v4". Every later change to the spine is an RFC, so the starting text needs one adoption on record.

## Decision
The spine as imported by the seed commit, version 5, is the baseline. RFC 0001 adopts it unchanged. From then on the spine changes only through an RFC, and it wins every conflict with another document.

## Enforced by
`docs/design/**` is a protected path: gate V05, and the read-only mount once the fleet container exists ([WI-0006]), reject a change outside a protected-change lease held by the chief architect. RFC 0001 is opened as a `kind:rfc` design issue by [WI-0008].

## Consequences
Design documents that disagree with the spine are wrong until an RFC changes the spine. Known disagreements are listed in the bootstrap entry review.

## Alternatives rejected
- Adopting version 4 as the table in `team/06` section 9 says: version 5 is the text in the repository and carries the owner's later instructions, which bind.
- Treating the spine as adopted without an RFC: the first later RFC would have nothing recorded to amend.

## Revisit when
Never; later RFCs amend the spine and each has its own record.
