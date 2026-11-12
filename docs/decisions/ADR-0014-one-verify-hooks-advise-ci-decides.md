# ADR-0014: One `verify`; hooks advise, and the merge queue and CI decide

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-47, D-64
- Requires: nothing
- RFC: not required: restates D-47 as repository mechanism
- Work items: [WI-0002], [WI-0005], [WI-0006]

## Context
Edit hooks are bypassed through the shell, and a crashed Stop hook fails open (brief h09). A gate that differs between a hook, a harness and CI is three gates.

## Decision
`cargo xtask verify` is the only gate. Hooks, every harness, the merge queue and CI call it. Hooks give early feedback and enforce nothing. The merge queue's full verify on the squashed tree, run with the kit binary built from the base, is the primary gate, and hosted CI is the backstop. Protected paths are held by read-only mounts in the fleet container and by gate V05 on the diff.

## Enforced by
The `hooks-selftest` gate (V18) proves each hook handler on three systems. The CI `protected-paths` job and gate V05 reject a diff that touches a protected path outside a protected-change lease. The kit binary is built from the merge base, so a change cannot alter the gates that judge it.

## Consequences
A check that matters is a `verify` gate with a message naming the fix. On native Windows, which has no sandbox, hooks and permission rules are the only local boundary until the fleet container exists.

## Alternatives rejected
- Separate hook-only checks: they are skipped by any route the hook does not see.
- CI as the only gate: feedback after a push costs a review round.

## Revisit when
A gate cannot run inside `verify` within its time bound; it then becomes a merge-queue job with the same evidence format.
