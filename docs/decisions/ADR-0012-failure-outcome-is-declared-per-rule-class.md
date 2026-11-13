# ADR-0012: The failure outcome is declared per rule class, with zero silent fail-open

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-15, P9
- Requires: nothing
- RFC: not required: restates D-15 and P9 as repository mechanism
- Work items: [WI-0027], [WI-0036]

## Context
Hooks fail open by default, and silent downgrades were shown as healthy in the products reviewed (briefs 04, 06, 25, g04, h02; reviews c3, l11). A failure the product does not report is indistinguishable from "nothing found".

## Decision
Loss-of-sensor behaviour is declared per pack and group. The default is allow with a loud Degraded state, and deny for the fail-closed classes in the shim's fail-safe table. Each adapter publishes the failure mode it can achieve per agent version; where closed is not achievable the class is backed by a boundary or the assurance record says `on_failure: open`. "Could not look" is reported apart from "nothing found". Every specification has a failure-modes table of failure, declared outcome and where it is visible.

## Enforced by
The fault-injection suite in `lab/`: harness track in [WI-0027], both install profiles in [WI-0036]. The release gate of spine section 6 is zero silent fail-open in every Tier 1 cell. The specification template requires the failure-modes table.

## Consequences
Every component has a declared answer to "what happens when this breaks". A feature without a fault-injection case is not complete.

## Alternatives rejected
- Fail closed everywhere: a sensor fault would stop developers, against P4.
- Fail open everywhere with logging: a log line is not a visible state.

## Revisit when
S-06 shows the shim cannot hold its two-second bound or the fail-safe table denies outside its classes.
