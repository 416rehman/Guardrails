---
name: grdr-audit
description: Run one power prompt from the library. Use when a scheduled audit or a lead names an audit id.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: "team/04 work items 2 and 3 (the runner, cargo xtask audit run)"
  closes-by: ledger
---

# Run one audit through the runner

An audit is a read-only power prompt that asks one question about one scope, such as A01 "find all of the implicit state machines" (`docs/team/04`). You run it with one command and nothing else:

```sh
cargo xtask audit run <id> [--diff <base>] --commit <sha> [--arm power|control]
```

The runner does everything that makes the result trustworthy, so none of it is yours to do by hand:

- it checks out `<sha>` in a fresh read-only worktree with no network but the model endpoint and no credentials;
- it prepends the shared preamble of team/04 section 2 to the prompt's concept text, so the wording cannot drift between runs;
- it validates the finder's JSON and discards every evidence span that does not match the file at `<sha>` exactly;
- it sends each surviving result to the refuting verifier in a clean context on Opus 5.5, and a severity 1 result to a second one;
- it writes the run and its results to `.agent/audits/<run>/run.json`, keyed by fingerprint.

A result you produce yourself skips all five, which is why the skill allows no manual run. The prover and the ledger repositories are later team/04 work items; until then a result is upheld or refuted, never reproduced.

`cargo xtask audit run <id> --dry-run` prints the run it would make and the filled prompt, and exits 0 when the runner and the prompt exist.

## 1. Get the arguments right

- **Id**: the one the schedule or the lead named (A01, C03, M04, ...). Look it up in `audits/library.toml` to see its version, scope kind and closure kinds. Do not substitute a similar prompt.
- **Scope**: the whole repository with no option, or `--diff <base>` for the files changed since one base commit (never a range), as the trigger says. Pull-request runs take the diff against the pull request's base commit.
- **Commit**: a full SHA, never a branch name, so the run is reproducible.
- **Arm**: the scheduled job passes `--arm control` when `library.toml` pairs the run (team/04 section 6). Never pick the arm yourself.

## 2. Run it, and nothing else

- Do not open `.agents/skills/audit-<id>/SKILL.md` and follow its concept text yourself. The runner reads it.
- Do not edit, create or delete files, run `verify`, push, or open pull requests. An audit session is read-only.
- Do not fix what the run finds, however small. A repair is an ordinary work item with its own writer (team/04 section 3, step 4).
- The run has a usage cap per run from `library.toml`. At a subscription usage limit the runner pauses and resumes after the window resets; a paused run is never recorded as failed or as "found nothing" (P9).

## 3. Report what the runner wrote

The command prints at most ten lines and a log path. Your final message gives:

- run id, prompt id and version, arm, scope and commit;
- counts: results returned, after the span check, upheld, reproduced;
- the `checked_and_sound` list and every `skipped` entry, so "did not look" stays separate from "found nothing";
- fingerprints of upheld results with their severity and state.

Never restate a result as a fact beyond what the ledger says, and never paraphrase a security candidate. A result with `security_candidate: true` appears in public text only as its fingerprint and "held for private triage" (D-62).

Work items come from the runner, not from you. A reproduced result becomes a `status:proposed` repair issue that names its closure kind; prompts in their 14-day shadow create none, and audits create at most eight items a week (team/04 section 6). Filing audit results by hand would duplicate fingerprints, so do not. A repair item closes through `cargo xtask audit close <fingerprint> --by <kind>:<ref>` in that item's own session.

## Pull requests

Inside the `review` workflow, `eval-diff` runs the pull-request prompts that match the diff's paths (team/04 section 9: at most six power runs and one shared control, in the first round over the whole diff and in the final round over the change since the first), so audits add no review round. Two rules from owner instruction 4 apply on top:

- A01 also runs on every pull request whose diff adds or changes a type's fields, a status-like field, or a `match` on one.
- An A01 result that survives the refuting pass is a blocking review finding, severity `major`, closed only by a type change (`closes-by = "type"`): never by a comment, a guard or a test alone. Skill `grdr-structure` is the fix.

Pull requests from forks receive no secrets, so their audits run when the pull request enters the merge queue.

`garden-architecture` runs A01 over the whole tree weekly; each surviving finding becomes a repair issue that closes only by a type change.

## When the runner does not exist yet

The runner is team/04 work item 2 and the prompt skills are item 3; neither is among the reserved items WI-0001 to WI-0053, and `lead-agent-kit`, which owns the library, files them. If `cargo xtask audit` reports an unknown subcommand, or `audits/library.toml` does not exist:

1. Do not run the prompt by hand, in a subagent or otherwise.
2. Report "not run: the audit runner does not exist (team/04 work items 2 and 3)". Record it as skipped, never as an empty result.
3. Check for an open issue about the runner (`gh issue list --state open --search "audit runner in:title"`). If there is none, file one with `status:proposed` as skill `grdr-handoff` describes. File it once, not on every run.
4. In an `eval-diff` round, say in the verdict which audits did not run. Structure check S4 of `grdr-structure` still runs in `post-edit` and gate V20; it does not replace A01.
