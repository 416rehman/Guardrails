RFC: <four digits, the next unused number>
Title: <what the RFC changes, in a short phrase>
Author: <agent roster name or person>
Harness: <the harness that drafted it>
Model: <the model id that drafted it>
State: Draft
Design issue: #<n>
Spine: <the D-nn and Pn it touches, or none>
Surfaces: <each RFC-gated surface it changes, from the list in docs/design/30 section 3 "Required for">
Decision record: none yet

Copy this file to `rfcs/NNNN-title.md`, fill every key and every heading, and keep the order. Tools read `RFC` and `State` from the block above by key. Delete this paragraph and the notes in angle brackets.

`State` is exactly one of these, and each move needs what is written beside it:

- `Draft`: while the pull request is open.
- `Review`: once the persona council and `eval-architecture` are asked on the design issue.
- `Accepted`, `Rejected` or `Postponed`: when the chief architect decides, with written reasons.
- `Implemented`: when the linked work items are closed.

Comments go on the design issue, so commenting needs no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
<One paragraph: what changes and why.>

## Motivation
<The problem, who has it, and what happens if nothing changes.>

## Design
<The change in enough detail to build and to review.>

## Surfaces changed
<Every public surface touched and its stability class, or none.>

## Alternatives
<What else was considered and why it lost.>

## Drawbacks
<What the change costs.>

## Unresolved questions
<What is still open, or none.>

## Review
<Links to each persona council seat comment and to the `eval-architecture` verdict on the design issue.>

## Decision
<The chief architect's outcome and written reasons. A comment after the decision that shows a defect opens a new RFC; there is no waiting period (owner instruction 7).>
