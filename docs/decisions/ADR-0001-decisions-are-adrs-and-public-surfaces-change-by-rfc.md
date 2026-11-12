# ADR-0001: Decisions are recorded as ADRs, and public surfaces change by RFC

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-61
- Requires: nothing
- RFC: not required: this record adopts the process D-61 already states
- Work items: [WI-0008]

## Context
The spine holds seventy-one decisions and the design documents specify them. Decisions made after it need one place and one form, and a change to what outsiders build against (the spine, a public crate, a wire format, the pack format, the Cedar schema) needs review before code exists. The stakeholder reviews found that undocumented decisions were re-argued in every design document (`design/_review/00-resolution.md`; brief 28).

## Decision
A decision that outlives a work item is a record at `docs/decisions/ADR-NNNN-<slug>.md` in the form of `docs/agents/templates/decision-record.md`. A record is superseded by a later record and never edited. A change to the spine, a public crate (layers 0 to 2, `grdr-ffi`, `grdr-wasm`), a wire format, the pack format or the Cedar schema is drafted as `rfcs/NNNN-title.md` and discussed on its own `kind:rfc` design issue. The persona council and `eval-architecture` review it, the chief architect decides with no waiting period, and the decision record states the outcome.

## Enforced by
The `rfc-required` CI check fails a pull request that changes `proto/` or `schema/` when its body has no `RFC: <nnnn>` line; it is a path rule until [WI-0014] adds the `buf breaking` input, and public-crate API changes join it with the `semver-checks` gate of ADR-0020. `docs/decisions/**` and `rfcs/**` are protected paths, so gate V05 rejects a change to them outside a protected-change lease. Appending instead of editing is review only: `eval-architecture` reads every protected change under `docs/decisions/`.

## Consequences
Every surface change has a public design record before it lands. A small API fix in a public crate costs an RFC, which is the price of D-60's stability classes.

## Alternatives rejected
- Decisions kept only in issue comments: they are not versioned with the code they bind.
- A comment period before every decision: owner instruction 7 removed every wait on a person.

## Revisit when
The steering group forms at the second external maintainer (D-61).
