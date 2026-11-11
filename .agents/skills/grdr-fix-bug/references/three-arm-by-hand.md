# Three-arm proof before `cargo xtask prove` exists

`cargo xtask prove` and `.agent/evidence/prove.json` are built by WI-0002 (team/03 K4, team/05 QG-10). If cargo reports no `xtask` command or `xtask` reports an unknown subcommand `prove`, run the same three arms by hand as below. Everything else in `SKILL.md` still applies: test first, cause not symptom, no edits to the test after step 1, regression hunt, verify, hand-off.

The arms prove that the test detects the bug: it fails on the code before the fix, passes with the fix, and fails again when only the fix is taken away.

## Setup

```sh
base=$(git merge-base HEAD main)
tests="crates/<crate>/tests/<file>.rs"       # every test path you added or changed, space separated
name="<test path::name>"                      # the one test that proves the bug
mkdir -p .agent/scratch .agent/logs
```

`.agent/` is git-ignored, so the scratch worktrees below never show in `git status`. Commit the test and the fix on your branch before you start, so `HEAD` holds both.

## Arm 1: fails before

The base commit plus your test changes only.

```sh
git worktree add --detach .agent/scratch/before "$base"
git diff "$base" HEAD -- $tests | git -C .agent/scratch/before apply
(cd .agent/scratch/before && cargo test -p <crate> -- "$name") > .agent/logs/prove-before.log 2>&1; echo "exit $?"
```

It must fail. If it passes, the report is wrong or the test is: stop and record that in the hand-off (step 1 of `SKILL.md`).

## Arm 2: passes after

Your branch as committed.

```sh
cargo test -p <crate> -- "$name" > .agent/logs/prove-after.log 2>&1; echo "exit $?"
```

It must pass.

## Arm 3: fails on revert

`HEAD` with every non-test change reverted.

```sh
git worktree add --detach .agent/scratch/revert HEAD
git diff "$base" HEAD -- . $(printf ' :!%s' $tests) | git -C .agent/scratch/revert apply -R
(cd .agent/scratch/revert && cargo test -p <crate> -- "$name") > .agent/logs/prove-revert.log 2>&1; echo "exit $?"
```

It must fail. If it passes, the test does not depend on your fix: the fix is not what makes it pass.

## Record and clean up

```sh
sha256sum .agent/logs/prove-before.log .agent/logs/prove-after.log .agent/logs/prove-revert.log
git worktree remove --force .agent/scratch/before
git worktree remove --force .agent/scratch/revert
```

Add three `evidence` entries to the hand-off (command, exit code, log path, SHA-256) and point `three_arm` at their indexes. Say in the hand-off's summary that the arms were run by hand because `prove` does not exist yet, so no `prove.json` exists. CI replays the three arms in the merge queue once WI-0002 and WI-0010 have landed (team/05 section 14).
