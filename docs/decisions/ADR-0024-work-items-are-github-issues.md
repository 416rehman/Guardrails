# ADR-0024: Work items are GitHub issues in one repository, labels are their state, and agents drive the queue

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-47, D-61
- Requires: nothing
- RFC: not required: restates D-47 as owner instructions 5 and 6 word it
- Work items: [WI-0009], [WI-0011], [WI-0005]

## Context
The owner ruled that the only place for work items is GitHub issues, with no local tooling, no organisation and no GitHub Project, and that agents, not a person, put work in the queue (owner instructions 5 and 6).

## Decision
A work item is a GitHub issue in the one repository `.agents/harness.toml [github] repository` names, on the owner's personal account, and nothing else. There are no work-item files, no organisation, no GitHub Project and no milestones. The issue number is the id: branch `agent/<n>/a<attempt>`, `GRDR_WORK_ITEM=<n>`, `Closes #<n>` in the pull request body. Labels in `.github/labels.toml` are the status and the fields (status, priority, tier, squad, kind, size, agent), with the valid status transitions listed there. Dependencies are "blocked by" links and decomposition is sub-issues. Acceptance criteria are a section of the issue held by the SHA-256 in a `ready.v1` comment. Hand-offs, leases, verdicts, escalations and council seats are issue comments. Any agent files what it finds as `status:proposed`; a lead, the product lead or the programme manager readies it, and the agent that readies an item never implements it.

## Enforced by
`cargo xtask labels sync --check` in CI; the dispatcher's work-item check before a lease; gate Q01, which fails a pull request whose issue no longer matches its `ready.v1` digest; `guard-command`, which holds each role to its `gh` calls and refuses any status change outside the listed transitions; `kit ready`, which refuses a readier that is the item's agent.

## Consequences
All state survives the loss of a machine or an account. Every agent posts as the owner's login, so records name the agent and tampering is found by digest, not by author.

## Alternatives rejected
- Work-item files in the repository: a second source that drifts from the issues.
- A GitHub Project or an organisation: owner instruction 5 rules both out.

## Revisit when
The optional GitHub Apps give each role its own identity; the records stay, and authorship becomes a second check.
