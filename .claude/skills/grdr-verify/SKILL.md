---
name: grdr-verify
description: Run the repository gates before claiming anything works. Use before a hand-off, after any edit, and whenever a hook or CI reports a failure.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: K4
  closes-by: evidence
---

# Run the gate and read its verdict

`cargo xtask verify` is the only gate (D-47). Hooks, every harness and CI run it, and CI decides. The command writes the facts: an evidence file in `.agent/evidence/` with the command, exit code, duration and the tree digest it ran against. A result you type without that file counts for nothing.

## Which form to run

| Form | Scope | When |
|---|---|---|
| `cargo xtask verify --fast` | Changed files, touched crates and their dependents, against the merge base with `origin/main` | After each batch of edits; before every hand-off; when a hook or CI reports a failure |
| `cargo xtask verify` | The whole workspace; the pull-request gate | Implementers run it once `--fast` is green, before the hand-off (team/02 section 5) |

Options: `--base <ref>` changes the comparison base; `--json <path>` also writes the result as JSON. The Stop hook runs `cargo xtask verify --fast --json .agent/state/verify.json`.

Exit codes: `0` every step passed; `2` a gate failed; anything else is an infrastructure error and counts as a failure.

## Read the output

The command prints at most ten lines and a log path. The first failing line is `ERROR <gate-id>: <reason>`.

1. Read the `ERROR` line. The gate id tells you which step failed; `references/gates.md` says what each step checks and where the fix usually is.
2. Open the log at the printed path for the detail. Do not paste the whole log into the conversation; quote the lines that matter.
3. Fix the cause in your write set, then run the same form again. A structure finding (`ERROR V20 S4: ...`, structure checks S1 to S7) is fixed by a design change: load skill `grdr-structure`. An interface finding (`ERROR V26 UX3: ...`) is fixed as skill `grdr-interface` says.
4. When it is green, note the evidence id (the file name under `.agent/evidence/`). Cite it in the hand-off and in your final message. The Stop hook's checker refuses a success claim that names no evidence id.

## Rules

1. Never edit a gate to make it pass. `xtask/src/gates/**`, `xtask/verify.toml`, lint configuration, ratchets, structure exemptions, snapshots and golden files are protected paths; hooks deny the edit and CI gate V05 rejects it. If you believe a gate is wrong, file a `status:proposed` issue with the evidence (skill `grdr-handoff`) and name it in `next`. The one exception is an item whose work is the gate, under a protected-change lease (`GRDR_SCOPE=protected`), whose write set's protected paths you change through `cargo xtask kit place` (owner instruction 7); its change is still judged by the base's gates and by `eval-security` and an evaluator on the other model, never by itself.
2. Never weaken, skip, ignore or delete a test or an assertion to get green. No new `#[allow`, `#[ignore]`, `@ts-ignore`, `todo!` or `unimplemented!` without a stated reason; the post-edit hook flags them and V06 ratchets them.
3. Snapshot acceptance is denied: no `cargo insta accept`, `cargo insta review`, `INSTA_UPDATE=always` or `vitest -u`.
4. If `--fast` is red before you change anything, stop and hand off with status `blocked`, citing the evidence id (AGENTS.md, start of every session).
5. A failure is never "pre-existing", "flaky" or "out of scope" without an evidence id or a filed item. The Stop hook's checker blocks those words when they stand alone.
6. Do not rerun hoping for a different answer. A test that fails and then passes on retry is flaky: report the test, its seed and the log path. Quarantine is the merge queue's job (team/05 section 17).
7. A usage limit is never a reason to skip a check. If a limit ends the session, the next session runs the gate again.

## When the gate and the specification disagree

If the only way to make a gate pass would contradict the spec or the issue's acceptance criteria, change neither. Hand off with status `impossible` and a one-line reason that names the clause and the gate or test id. That is a correct outcome, not a failure (team/05 section 18).

## The Stop hook

When you end a turn, the Stop hook runs `--fast` (internal deadline 540 s) and checks the definition of done: green on the current tree digest, a valid `handoff.v1`, the `cleanup` sign-off matching the diff, `prove.json` for bug items, a survival test for removals, no S1 to S4 structure finding, no unexplained suppression, and the hand-off's `decisions` list. It blocks with ten lines when anything fails. After three blocks on the same diff it lets the turn end and records a hand-off with `gate: failed`. At that point write your hand-off with the failing output and stop; do not keep retrying (CLAUDE.md).

## Before WI-0002 lands

`cargo xtask verify` and its evidence files are built by WI-0002 (team/03 K4); WI-0001 adds the `cargo xtask` alias and the workspace. If cargo reports no `xtask` command, or `xtask` reports an unknown subcommand, the gate does not exist yet. Then:

1. Run the steps the fast form would run, on the crates you touched:
   - `cargo fmt --all -- --check`
   - `cargo clippy -p <crate> --all-targets -- -D warnings`
   - `cargo test -p <crate>` (or `cargo nextest run -p <crate>` when nextest is installed)
2. Write each command's output to `.agent/logs/<step>-<timestamp>.log`. Record the command, exit code, log path and the log's SHA-256 as an `evidence` entry in the hand-off.
3. Say in the hand-off's summary that the gate did not run and no evidence file exists. Never write that verify passed.

If there is no workspace yet (WI-0001 has not landed), say that instead and run nothing.

The structure checks S1 to S7 run in the kit binary's hooks (WI-0005) as well as in V20. If neither ran, check your diff by hand as skill `grdr-structure` describes and say so.

Bug fixes before WI-0002 lands have no `cargo xtask prove` either: follow `.agents/skills/grdr-fix-bug/references/three-arm-by-hand.md`.
