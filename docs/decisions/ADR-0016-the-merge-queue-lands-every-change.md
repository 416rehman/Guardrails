# ADR-0016: The merge queue lands every change, commits are one line, and no agent or person votes

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-61, D-63
- Requires: nothing
- RFC: not required: restates D-61 as amended by owner instructions 7 and 27
- Work items: [WI-0010], [WI-0043], [WI-0007]

## Context
An integrator agent became the bottleneck in the teams studied, and human sign-off was removed by owner instruction 7. release-please reads squash subjects, and the owner's `cleanup` gate refuses multi-line messages (owner instruction 27).

## Decision
Only the merge queue, deterministic software, lands a change on `main`. It squashes the pull request onto the current base tip, runs the full verify there, and squash-merges as `<title> (#<pr>)` once the lane's evaluators passed, CI is green where it runs and at most three review rounds were used. Every commit message is one Conventional Commit line of at most 72 characters with no body, trailer or credit line. No agent identity holds a code-owner entry or a vote, evaluators publish check runs and never approvals, and no person is a step.

## Enforced by
`cargo xtask queue` and the dispatcher's landing pass; gate V24 on every commit since the base; `guard-command`, which refuses any other commit form and any merge by an agent; `cargo xtask governance-sync`, which rejects a bot handle in `CODEOWNERS` or `MAINTAINERS.md`.

## Consequences
A change lands when software says it may, at any hour. A pull request with an invalid title or no `Closes #<n>` returns to its worker with the reason.

## Alternatives rejected
- GitHub's native merge queue: it needs branch protection approvals from a person or an App.
- An integrator agent: a model in the landing path.

## Revisit when
The optional GitHub Apps exist and can post check runs; the queue's inputs change, not its role.
