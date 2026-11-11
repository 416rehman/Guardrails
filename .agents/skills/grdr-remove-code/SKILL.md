---
name: grdr-remove-code
description: Delete code, flags or features. Use for any removal or "replace X with Y" item.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: none
  closes-by: test
---

# Remove code with a survival test

A removal is finished when the target is gone, not when it can no longer run. In the h09 sample, 29%
of passing patches wrapped the target in a guard instead of deleting it. So a removal closes only with
a survival test, a test that fails while the target remains, and a diff that deletes rather than hides.

The item is issue `#<n>`, where `<n>` is `GRDR_WORK_ITEM`. Read it with `gh issue view <n> --comments`;
its write set and tier are in `.agent/state/item-<n>.json`, which `cargo xtask kit launch` wrote (skill
`grdr-start-item`).

## 1. Name the target

List every symbol, file, flag, configuration key, CLI command, error code, metric name, pack rule and
dependency the item removes. For "replace X with Y", X is the target and Y is what every caller uses
afterwards. If the item does not say what Y is, stop with status `impossible` and say so.

## 2. Find every reference before deleting anything

`rg` each name across the whole tree: code, tests, docs, `proto/`, `schema/`, gate files, packs and
CI files. Put each hit in one of three groups: deleted by this item, moved to Y, or outside the write
set.

- A hit on a protected path (`.agents/kit/protected-paths.toml`) goes into `protected_change_requests`.
- A hit outside the write set is another item's work. File it as a `status:proposed` issue with the
  `rg` output as evidence (skill `grdr-handoff`) and name that issue in `next`. Never edit it here.
- If the removal cannot be completed without either, hand off with status `blocked`.

## 3. Check whether the target is a public surface

Run `cargo xtask risk` on your diff once you have one; removing a public item raises the tier. A
target is a public surface when it is listed in `surfaces.toml`, belongs to a public crate (layers 0
to 2), is a protobuf field or package, is part of the Cedar schema or pack format, or is a CLI command,
configuration key or HTTP API.

- Public crates, wire formats and the Cedar schema change only through an accepted RFC (D-61).
- Every public surface needs a `deprecations.toml` entry whose `earliest_removal` has passed, plus its
  migration page, or CI fails the removal (design/34 section 10).
- If either is missing, hand off `blocked` with the escalation packet of `team/01` section 6 (skill
  `grdr-handoff`). Do not add the deprecation entry and remove the target in the same item.

## 4. Write the survival test first

Put it where the crate keeps its tests. It must fail now and pass once the target is gone. Test what
a caller observes:

- a removed flag or command: invoking it exits with the unknown-argument error;
- a removed configuration key: a file that sets it is reported as an unknown key;
- a removed public function or type: a compile-fail case that uses it;
- a replaced code path: the input that used to reach X now produces Y's output, asserted on the output;
- a removed dependency: the crate's dependency closure no longer contains it.

Prefer a behavioural test. If only a structural one can tell, record why in the hand-off `decisions`.

Run `cargo xtask prove --arm before --test <path::name>`. It must fail. If it passes, the test does not
see the target: fix the test, never the code under it.

## 5. Delete

Delete the target and everything that exists only for it: its tests, fixtures, docs, configuration
schema entries, feature flags and `limits.toml` keys. Retire its error codes, metric names and rule ids
in their registers; they are never reused (design/34 section 10).

These are not deletions, and the deletion audit (team/04 E04) fails them:

- a branch that cannot run: `if false`, an early return, a match arm that is never reached;
- a feature flag, configuration default or environment variable that switches the target off;
- `#[cfg(any())]`, commented-out code, or `#[allow(dead_code)]` on what should be gone;
- a `#[deprecated]` attribute on its own, or a renamed copy;
- a stub that returns success, `todo!()` or `unimplemented!()`;
- a fallback to X when Y fails.

For "replace X with Y", every caller moves to Y in this item. A shim that keeps X's name and calls Y
counts as keeping X, unless the spec asks for one.

A removal often leaves state behind: a boolean that once chose between X and Y, a `mode` field with
one value left, an `Option` that is now always set. Remove it or make the type say what remains
(skill `grdr-structure`, rules 3 and 5). Never keep it alive with a new guard or comment.

Tests that exercised only the target go with it. List each deleted test in `decisions` with the
reason: the test-diff ratchet and the evaluator read test deletions first. Never weaken a test that
stays. Tests on protected paths (`conformance/vectors/`, `tests/golden/`, `**/*.snap`) change only
through `protected_change_requests`.

## 6. Prove and audit your own diff

1. `cargo xtask prove --arm after` must pass, and `cargo xtask prove --arm revert` must fail. The
   results land in `.agent/evidence/prove.json`.
2. Read your diff as the evaluator will and answer E04's question: did this remove what the item says,
   or wrap it in a guard, fallback or flag?
3. `rg` every target name again. The only hits left are the survival test, the `deprecations.toml`
   entry and changelog entries of earlier releases.

## 7. Finish

- `cargo xtask verify --fast` (skill `grdr-verify`). The full form adds diff-scoped mutation testing,
  which shows whether the tests that remain still bite.
- The commit subject follows the repository's Conventional Commit form and marks a removed public
  surface as breaking with `!`. release-please builds the changelog entry and the version bump from
  that subject, so write it for the person who upgrades.
- Hand off with `grdr-handoff`. Put the survival test's runs in `evidence`, name the test in `summary`,
  and fill the pull-request section "Survival tests (removals)".

## Commands this skill names

A command that has not landed yet shows as an unknown subcommand.

| Command | Added by | Until it exists |
|---|---|---|
| `cargo xtask verify --fast` | WI-0002 (team/03 K4) | Follow `grdr-verify`, and list every gate that did not run under what was not verified |
| `cargo xtask prove` | WI-0002 (team/03 K4, team/05 QG-10) | Run the survival test with `cargo nextest run` before and after the deletion, attach both outputs with their exit codes, and list the revert arm as not verified; CI replays it |
| `cargo xtask risk` | WI-0007 | Compare your changed paths with `.agents/risk-tiers.toml` and `security/trust-core.paths`; if either is missing or you are unsure, take the higher tier. A model may raise a tier, never lower it |
