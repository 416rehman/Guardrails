# A `workflow_dispatch` run as the oracle

The orchestrating session (skill `grdr-work-issue`) and every evaluator (skill `grdr-evaluate`) follow this procedure, so that on the same data both pick the same run for a criterion or give the same reason none counts. Steps marked **Session only** are the session's alone: starting and finding a run, after the additive workflow rule's conditions where they apply (step 6), and the landing re-check and closing check that `grdr-work-issue` section 5 runs with this file. An evaluator never takes a session-only step; where one is needed it returns `cannot-evaluate` with the finding the step names.

A pull request runs `verify.yml` on Linux only, so a macOS or Windows result exists only in a run dispatched on the branch. `<file>` is the workflow the criterion names (`verify.yml` for the gates). `<sha>` is the commit judged: `git rev-parse origin/issue/<n>` for the session, `git rev-parse HEAD` for an evaluator. Fetch both refs first with `git fetch origin main issue/<n>`.

## Terms

- **Runner label**: a value a workflow of `origin/main` gives `runs-on`, directly or through the matrix of its plan job.
- **Name stem**: a job's name with its last parenthesised part removed. A job with no `name:` is named by its key.
- **Own change** of a commit `<x>`: `git diff origin/main...<x>`, the change from its fork point with `origin/main` to `<x>`.
- **Counted job**: a job a criterion counts under the additive workflow rule, or a job the closing check of `grdr-work-issue` section 5 reads by name.

## States

- Selection, per criterion: `checking-config` (step 1) exits to `cannot-evaluate`, `rebase` or `listing`. `listing` (step 2) exits to `waiting`, `no-run`, `cannot-evaluate` (100 runs) or `classified`. `no-run` is the head with no run or only `ignored` ones: an evaluator returns `cannot-evaluate` with the finding "no run on head", and the session dispatches (step 6) and goes back to `listing`. `classified` (steps 3 to 5 and 7) exits to `fails` or `counts`.
- Run class, per listed run (step 3): `waiting` exits to another class, or to `cannot-evaluate` past the bound. `ignored`, `fails` and `green` are terminal.
- Landing, per item (`grdr-work-issue` section 5): `re-check` exits to `rebase` or `merge`. `closing`, for an item the additive workflow rule admitted, starts at the issue's `Closing check pending` comment and exits to `passed` (issue closed), `failed` (issue open, owner told) or `pending` (issue open, resumed by the next session).

Nothing counts as a pass by default (P9): every state above ends in a counted run, a failed criterion or `cannot-evaluate`.

## Bounds

- A list that returns 100 runs may hide older ones, so it is `cannot-evaluate`. This holds for every list below.
- The wait bound is the sum of the `timeout-minutes` of the jobs along the longest `needs` chain of `<file>` at `<sha>`, doubled to allow for queueing, counted from the run's `createdAt` (`gh run view <id> --json createdAt`).
- With no run URL printed, the session lists at most 6 times, at least 10 seconds apart (step 6).

## 1. Check what the run reads

A dispatch runs the files of the dispatched commit: `.github/` (workflows and actions), `.cargo/` and `rust-toolchain.toml`. A branch that edits them writes its own oracle: it can keep a job named for macOS and run it on Linux. Read each check from the files `git diff --name-only` prints, never from an exit code.

- If `git diff --name-only origin/main...<sha> -- .github/ .cargo/ rust-toolchain.toml` prints a file, the change itself edits those paths. A run on the branch counts only when the criterion names "the additive workflow rule" and every condition of that rule (below) holds; a failed condition takes that rule's route. A criterion that does not name the rule is `cannot-evaluate` and goes back to the spec author.
- Otherwise, if `git diff --name-only origin/main <sha> -- .github/ .cargo/ rust-toolchain.toml` prints a file, `main` changed those paths after the branch forked. The criterion is `cannot-evaluate` until the branch is rebased onto `origin/main`; say "rebase" in the finding.

These two checks stay as they are for every change the additive workflow rule does not admit.

## 2. List the runs on the head

`gh run list --workflow <file> --event workflow_dispatch --commit <sha> --limit 100 --json databaseId,headSha,attempt,status,conclusion`, filtered by GitHub, then keep only the runs whose `headSha` is `<sha>`. No run there, or only runs step 3 classes `ignored`, is `no-run`.

## 3. Class every run

Read every listed run with `gh run view <id> --json attempt,status,conclusion,jobs` and give it exactly one class. The rules apply in this order and the first that matches wins:

| Rule | The run | Class |
|---|---|---|
| 1 | `attempt` above 1: a re-run replaces the earlier attempt's result under the same id | `fails` |
| 2 | `status` anything but `completed`: `requested`, `queued`, `pending`, `waiting`, `in_progress`, or a status GitHub adds later | `waiting` |
| 3 | `conclusion` `cancelled` and no jobs: the concurrency group cancelled it before it started | `ignored` |
| 4 | `conclusion` anything but `success`, with or without jobs: `failure`, `timed_out`, `startup_failure`, `action_required`, `neutral`, `stale`, `skipped`, `cancelled` with jobs, or a conclusion GitHub adds later | `fails` |
| 5 | Any job concluded anything but `success` or `skipped` (a job past its `timeout-minutes` concludes `cancelled`) | `fails` |
| 6 | Otherwise | `green` |

Wait on a `waiting` run with `gh run watch <id>`, repeated until `gh run view <id> --json status` shows `completed`, because one call can outlast a tool call's time limit; then apply the table again. A run not completed within the wait bound makes the criterion `cannot-evaluate`, naming the run id.

The criterion fails if any run on the head is `fails`. Otherwise the newest `green` run (highest `databaseId`) is the candidate, and it counts only after steps 4, 5 and 7. No run is passed over without a class.

## 4. Carry failures across commits and events

A flake holds across commits and events: a run that fails and then passes with nothing fixed is flaky, not green (team/05 section 17). Before the candidate counts:

1. The branch's commits are `<sha>`, every commit `git log --format=%H origin/main..<sha>` prints, and every `headSha` that `gh run list --workflow <file> --branch issue/<n> --limit 100 --json headSha` prints, which adds the commits a rebase or force-push left behind.
2. For each commit `<c>`, list its runs from any branch and any event, with no `--branch` or `--event` filter: `gh run list --workflow <file> --commit <c> --limit 100 --json databaseId,headSha,headBranch,event,attempt,status,conclusion`. Keep each run whose jobs (`gh run view <id> --json jobs`) include one whose name stem equals the name stem of a job the criterion names. Class each kept run by step 3, waiting as rule 2 says.
3. For each kept run classed `fails`, run `git fetch origin <c>` first. If that or `git rev-parse <c>^{tree}` fails, the criterion fails. If `git rev-parse <c>^{tree}` equals `git rev-parse <sha>^{tree}`, the criterion fails. That includes every failing run on `<sha>` itself, such as its pull-request run.
4. Otherwise quote the failing line. In `gh run view <id> --json jobs` (with `--attempt <k>` for the first attempt that did not class `green`, when rule 1 classed the run), take each job that concluded `failure` and its first step that concluded `failure`. In `gh run view --job <job databaseId> --log-failed`, the failing line is the first line whose section is that step and whose text after the timestamp starts with `##[error]`. A line from any other step is never quoted, so an `::error::` line that a passing step printed is not evidence. A run with no jobs quotes the first annotation `gh run view <id>` prints.
5. Then name a hunk of the head's own change (`git diff origin/main...<sha>`) whose added lines are not in `<c>`'s own change (`git diff origin/main...<c>`) and that addresses the failing line. A hunk a rebase brought from `main` is in neither own change, so it never counts. With no such hunk, or no line to quote, the criterion fails.

## 5. Read the named jobs

In the run that counts, compare each job the criterion names (`fmt, clippy and tests (macos-26)`, for example) with its `expect`. The run's own `conclusion` is not evidence: a run concludes `success` with every Rust job skipped. A job that is missing, skipped, never expanded from its matrix (its name still shows `${{ matrix.os }}`) or did not conclude `success` fails the criterion. A repository made private plans only the Linux job, and that shows here.

## 6. Start a run (Session only)

When the head is `no-run` and `git rev-parse origin/issue/<n>` is `<sha>`, the session starts a run. For a change under the additive workflow rule, it runs that rule's conditions on the `<sha>` it has just fetched and dispatches at once, because a dispatch runs the new job with the token it asks for. `.claude/settings.json` lists the workflows a session may start.

1. `gh workflow run <file> --ref issue/<n>`, with the inputs (`-f`) the criterion's check names. A dispatch that exits non-zero makes the criterion `cannot-evaluate`.
2. Take the run id from the last line of the output that ends in `/actions/runs/<id>`. Confirm it with `gh run view <id> --json headSha,event,workflowName`: `headSha` is `<sha>`, `event` is `workflow_dispatch` and `workflowName` is the `name:` of `<file>`. `--ref` takes a branch, so a `headSha` other than `<sha>` means the branch moved between the check and the dispatch, and a workflow nobody checked may have run with its token. Any mismatch stops the item: nothing counts, and the session reports the run id to the owner.
3. When no line carries the URL, list as in step 2 at most 6 times, at least 10 seconds apart. Wait between lists with the Monitor tool or a background Bash command, never a foreground `sleep`. No matching run after the sixth list: the criterion is `cannot-evaluate`, and the session reports it.
4. Wait for the run as step 3 says, then class it.

Evaluators run in `dontAsk` with no command that waits between lists, so only the session can poll. An evaluator that returned "no run on head" runs once more on the same head after the dispatch; that run is not a new round.

## 7. Counted-job check

For each counted job all three of these hold, or the criterion fails, quoting the line or naming the step:

1. Image. In `gh run view --job <job databaseId> --log`, each line is the job name, the section and the text, separated by tabs, and the text starts with a timestamp. The first line whose text after the timestamp starts with `Image: ` lies in the section `Set up job` and comes before every line of every other section. Its value equals the runner label in the last parentheses of the job's displayed name, or starts with that label followed by `-` (`kit hooks (macos-26)` with `Image: macos-26-arm64` passes); that label is a runner label. The runner writes `Set up job` before any step runs, so no byte of the workflow writes the line that comes first.
2. Steps. In `gh run view <id> --json jobs`, the job concluded `success` and every entry of its `steps` concluded `success`. A step that concluded `skipped` (a step-level `if:`) or anything else fails, even when the job concluded `success`.
3. Count. The criterion's `expect` names the prefix of its test reporter's count line (`# tests ` for the Node test runner's TAP reporter). The count line is the last line of the job's log whose text after the timestamp starts with that prefix; quote it. No such line fails. A count of 0 fails unless the `expect` states that zero tests is the expected result. A criterion counted under the additive workflow rule that names no prefix is `cannot-evaluate` and goes back to the spec author.

## 8. What the verdict lists

Every verdict or session report that reads runs lists each run it read with its id, `headSha`, event and class; for step 4 the commits it listed and the runs carried against the head, each with its failing line and hunk or the reason the criterion fails; and for step 7 the `Image:` line, the step conclusions and the count line of each counted job. Write the expectation for each before the command (team/05 section 18).

## The additive workflow rule

A run on a branch whose three-dot list (step 1) prints a file counts only when the criterion names "the additive workflow rule" and every condition below holds, each checked with two dots against the current `origin/main`:

1. `git diff --name-only origin/main <sha> -- .github/ .cargo/ rust-toolchain.toml` lists only files under `.github/workflows/` that the issue's write set names.
2. In `git diff -U0 origin/main <sha> -- <file>` for each of them, every hunk is one of two kinds:
   - its removed and added lines all lie above the `jobs:` key, outside any block scalar, and each is a whole-line YAML comment;
   - it is a pure insertion (`@@ -L,0 +M,N @@`) of one new job: the first added line is a key at two spaces' indent that the `jobs:` of `origin/main` lacks, the other added lines are blank or indented four spaces or more, and line L+1 of `origin/main` is a job key at two spaces' indent, or L is its last line.
3. Each new job:
   - has a `runs-on` that is a runner label or its own matrix variable, and a matrix that comes from an output of a job of `origin/main`;
   - sets `timeout-minutes` and `defaults.run.shell: bash`, which GitHub runs as `bash --noprofile --norc -eo pipefail {0}` on every system, and no step of it sets `shell:` or `continue-on-error`;
   - has `steps:` and no job-level `uses:`, and sets none of `container`, `services`, `concurrency`, `environment` or `continue-on-error`;
   - has `permissions` absent or `contents: read` alone;
   - has no line that contains `secrets` in any letter case, which covers `secrets.<name>`, `secrets['<name>']`, `toJSON(secrets)` and `secrets: inherit`;
   - uses, in every `uses:`, a full commit SHA that a workflow of `origin/main` uses for the same action;
   - names no step `Set up job` or `Complete job`.

   No list of masking commands is checked: the counted-job check (step 7) is the evidence that the tests ran, and `eval-diff` judges the steps' script as code.
4. Each new job sets `name:`. `${{` appears in it only in a final part of the form `(${{ matrix.<key> }})`, where `<key>` is the matrix variable its `runs-on` uses. Its name stem differs from the name stem of every job of every workflow of `origin/main`. The verdict also checks that each job the new job produced shows that same stem in its displayed name in `gh run view <id> --json jobs`, never the YAML text alone.

Route on a failed condition: if `git diff --name-only <sha>...origin/main -- .github/ .cargo/ rust-toolchain.toml` prints a file, `main` changed those paths after the fork and the route is `rebase`. Otherwise the criterion is `cannot-evaluate` and goes back to the spec author, naming the condition. The session checks 1 to 4 before it dispatches (step 6) and does not dispatch when one fails. Each evaluator checks them again on the head it judges. The new job's steps are the subject of the change, so `eval-diff` judges them as code against the reference model the criterion names.

Under this rule the run counts for the new jobs only, and each is a counted job (step 7). A criterion on such a branch that names a job `origin/main` already has is `cannot-evaluate` before the merge; the closing check of `grdr-work-issue` section 5 reads every job of the run on `main`, those included.
