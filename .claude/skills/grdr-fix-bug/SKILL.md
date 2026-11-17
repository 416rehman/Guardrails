---
name: grdr-fix-bug
description: Fix a reported defect. Use for any issue of kind bug, any regression, and any failing test you did not intend to break.
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
  closes-by: test
---

# Fix a bug with a three-arm proof

1. Reproduce before reading the fix area. Write the failing test first, in the crate's normal test location.
   Run it on the code before your fix (arm 1 of `references/three-arm-by-hand.md`). It must fail. If it
   passes, the report is wrong or your test is: stop and say so in your report.
2. Find the cause, not the symptom. Name the state or input that makes it reachable. If the bug is one
   instance of a class (swallowed error, missing timeout, unscoped tenant key), fix the class at its
   authoritative boundary and list other instances in your report's `Next` for the lead.
3. Fix. Do not edit the test after step 1 except to make it compile.
4. Arm 2: the test passes with the fix. Arm 3: with every non-test change reverted in a scratch worktree,
   it fails again. The three commands and exit codes go in your report's three-arm line.
5. Regression hunt: list every caller of what you changed up to a public interface and state, per caller,
   whether behaviour changed. Unstated behaviour changes are a defect.
6. Run the gates of `grdr-verify`, then finish with `grdr-handoff`.

Never weaken, skip or delete an assertion to make the proof pass. If the test and the specification
conflict, change neither: report `impossible` with a one-line reason.
