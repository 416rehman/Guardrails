---
name: grdr-fix-bug
description: Fix a reported defect. Use for any work item of kind bug, any regression, and any failing test you did not intend to break.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: K4
  closes-by: test
---

# Fix a bug with a three-arm proof

1. Reproduce before reading the fix area. Write the failing test first, in the crate's normal test location.
   Run `cargo xtask prove --arm before --test <path::name>`. It must fail. If it passes, the report is wrong
   or your test is: stop and record this in the hand-off.
2. Find the cause, not the symptom. Name the state or input that makes it reachable. If the bug is one
   instance of a class (swallowed error, missing timeout, unscoped tenant key), fix the class at its
   authoritative boundary and list other instances in the hand-off's `next` field for the lead.
3. Fix. Do not edit the test after step 1 except to make it compile.
4. `cargo xtask prove --arm after` must pass; `cargo xtask prove --arm revert` reverts your non-test changes
   in a scratch worktree and must fail. The three results land in `.agent/evidence/prove.json` and the
   hand-off's `three_arm` field points at them.
5. Regression hunt: list every caller of what you changed up to a public interface and state, per caller,
   whether behaviour changed. Unstated behaviour changes are a defect.
6. `cargo xtask verify --fast`, then hand off with `grdr-handoff`.

Never weaken, skip or delete an assertion to make the proof pass. If the test and the specification
conflict, change neither: hand off with status `impossible` and a one-line reason.

`cargo xtask prove` and `cargo xtask verify` arrive with WI-0002. Until then, run the three arms as
`references/three-arm-by-hand.md` says and the verify steps as skill `grdr-verify` says.
