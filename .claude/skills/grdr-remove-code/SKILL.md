---
name: grdr-remove-code
description: Delete code, flags or features. Use for any removal or "replace X with Y" item.
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
  closes-by: test
---

# Remove code with a survival test

A removal is finished when the target is gone, not when it can no longer run. In the h09 sample, 29%
of passing patches wrapped the target in a guard instead of deleting it. So a removal closes only with
a survival test, a test that fails while the target remains, and a diff that deletes rather than hides.

The item is issue `#<n>`, named in your prompt. Read it with `gh issue view <n> --comments`; its
write set and tier are in its body and labels (skill `grdr-start-item`).

## 1. Name the target

List every symbol, file, flag, configuration key, CLI command, error code, metric name, pack rule and
dependency the item removes. For "replace X with Y", X is the target and Y is what every caller uses
afterwards. If the item does not say what Y is, stop with status `impossible` and say so.

## 2. Find every reference before deleting anything

`rg` each name across the whole tree: code, tests, docs, `proto/`, `schema/`, gate files, packs and
CI files. Put each hit in one of three groups: deleted by this item, moved to Y, or outside the write
set.

- A hit on gate configuration (AGENTS.md, "Rules") becomes its own issue, named in your report.
- A hit outside the write set is another item's work. File it as a new issue with the
  `rg` output as evidence (skill `grdr-handoff`) and name that issue in your report's `Next`. Never edit it here.
- If the removal cannot be completed without either, report `blocked`.

## 3. Check whether the target is a public surface

Compare your diff with `.claude/risk-tiers.toml` once you have one; removing a public item raises the tier. A
target is a public surface when it is listed in `surfaces.toml`, belongs to a public crate (layers 0
to 2), is a protobuf field or package, is part of the Cedar schema or pack format, or is a CLI command,
configuration key or HTTP API.

- Public crates, wire formats and the Cedar schema change only through an accepted RFC (D-61).
- Every public surface needs a `deprecations.toml` entry whose `earliest_removal` has passed, plus its
  migration page, or CI fails the removal (design/34 section 10).
- If either is missing, report `blocked` with the escalation packet of `team/01` section 6 (skill
  `grdr-handoff`). Do not add the deprecation entry and remove the target in the same item.

## 4. Write the survival test first

Put it where the crate keeps its tests. It must fail now and pass once the target is gone. Test what
a caller observes:

- a removed flag or command: invoking it exits with the unknown-argument error;
- a removed configuration key: a file that sets it is reported as an unknown key;
- a removed public function or type: a compile-fail case that uses it;
- a replaced code path: the input that used to reach X now produces Y's output, asserted on the output;
- a removed dependency: the crate's dependency closure no longer contains it.

Prefer a behavioural test. If only a structural one can tell, record why in your report's decisions.

Run it on the code before your deletion (arm 1 of `grdr-fix-bug/references/three-arm-by-hand.md`). It must fail. If it passes, the test does not
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

Tests that exercised only the target go with it. List each deleted test in your report's decisions with
the reason: the evaluators read test deletions first. Never weaken a test that
stays. Tests agents may not edit (`conformance/vectors/`, `tests/golden/`, `**/*.snap`) change only
through their own issue.

## 6. Prove and audit your own diff

1. Arms 2 and 3 of `grdr-fix-bug/references/three-arm-by-hand.md`: the survival test passes with the
   deletion and fails with the deletion reverted.
2. Read your diff as the evaluator will and answer E04's question: did this remove what the item says,
   or wrap it in a guard, fallback or flag?
3. `rg` every target name again. The only hits left are the survival test, the `deprecations.toml`
   entry and changelog entries of earlier releases.

## 7. Finish

- The gates of `grdr-verify`. Where `cargo mutants` is installed, run it on the touched crates to see
  whether the tests that remain still bite.
- The commit subject follows the repository's Conventional Commit form and marks a removed public
  surface as breaking with `!`. release-please builds the changelog entry and the version bump from
  that subject, so write it for the person who upgrades.
- Finish with `grdr-handoff`. Put the survival test's runs and exit codes in your report and name the
  test in its summary.
