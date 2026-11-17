# Three-arm proof

The arms prove that the test detects the bug: it fails on the code before the fix, passes with the fix, and fails again when only the fix is taken away. Everything else in `SKILL.md` still applies: test first, cause not symptom, no edits to the test after step 1, regression hunt, gates, report.

## Setup

```sh
base=$(git merge-base HEAD origin/main)
tests="crates/<crate>/tests/<file>.rs"       # every test path you added or changed, space separated
name="<test path::name>"                      # the one test that proves the bug
mkdir -p target/prove
```

`target/` is git-ignored, so the scratch worktrees below never show in `git status`. Commit the test and the fix on your branch before you start, so `HEAD` holds both.

## Arm 1: fails before

The base commit plus your test changes only.

```sh
git worktree add --detach target/prove/before "$base"
git diff "$base" HEAD -- $tests | git -C target/prove/before apply
(cd target/prove/before && cargo test -p <crate> -- "$name") > target/prove/before.log 2>&1; echo "exit $?"
```

It must fail. If it passes, the report is wrong or the test is: stop and say so (step 1 of `SKILL.md`).

## Arm 2: passes after

Your branch as committed.

```sh
cargo test -p <crate> -- "$name" > target/prove/after.log 2>&1; echo "exit $?"
```

It must pass.

## Arm 3: fails on revert

`HEAD` with every non-test change reverted.

```sh
git worktree add --detach target/prove/revert HEAD
git diff "$base" HEAD -- . $(printf ' :!%s' $tests) | git -C target/prove/revert apply -R
(cd target/prove/revert && cargo test -p <crate> -- "$name") > target/prove/revert.log 2>&1; echo "exit $?"
```

It must fail. If it passes, the test does not depend on your fix: the fix is not what makes it pass.

## Record and clean up

```sh
git worktree remove --force target/prove/before
git worktree remove --force target/prove/revert
```

Put the three commands with their exit codes in your report's three-arm line, and the log paths if anyone needs the output. Evaluators re-run the same three arms on the branch.
