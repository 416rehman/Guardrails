# A `workflow_dispatch` run as the oracle

The orchestrating session (skill `grdr-work-issue`) and every evaluator (skill `grdr-evaluate`) follow this procedure, so that on the same data both pick the same run for a criterion or give the same reason none counts. Steps marked **Session only** are the session's alone: starting and finding a run, after the additive workflow rule's conditions where they apply (step 6), and the landing re-check and closing check that `grdr-work-issue` section 5 runs with this file. An evaluator never takes a session-only step; where one is needed it returns `cannot-evaluate` with the finding the step names.

A pull request runs `verify.yml` on Linux only, so a macOS or Windows result exists only in a run dispatched on the branch. `<file>` is the workflow the criterion names (`verify.yml` for the gates). `<sha>` is the commit judged: `git rev-parse origin/issue/<n>` for the session, `git rev-parse HEAD` for an evaluator. Fetch both refs first with `git fetch origin main issue/<n>`.

## States

- Selection, per criterion: `checking-config` (step 1) exits to `cannot-evaluate`, `rebase` or `listing`. `listing` (step 2) exits to `waiting`, `no-run`, `cannot-evaluate` (100 runs) or `classified`. `no-run` is the head with no run or only `ignored` ones: an evaluator returns `cannot-evaluate` with the finding "no run on head", and the session dispatches (step 6) and goes back to `listing`. `classified` (steps 3 to 5) exits to `fails` or `counts`.
- Run class, per listed run (step 3): `waiting` exits to another class, or to `cannot-evaluate` past the bound. `ignored`, `fails` and `green` are terminal.
- Landing, per item (`grdr-work-issue` section 5): `re-check` exits to `rebase` or `merge`; `closing`, for an item the additive workflow rule admitted, exits to `closed` or `reopened`.

Nothing counts as a pass by default (P9): every state above ends in a counted run, a failed criterion or `cannot-evaluate`.

## Bounds

- A list that returns 100 runs may hide older ones, so it is `cannot-evaluate`. This holds for every list below.
- The wait bound is the sum of the `timeout-minutes` of the jobs along the longest `needs` chain of `<file>` at `<sha>`, doubled to allow for queueing, counted from the run's `createdAt` (`gh run view <id> --json createdAt`).
- With no run URL printed, the session lists at most 6 times, at least 10 seconds apart (step 6).

## 1. Check what the run reads

A dispatch runs the files of the dispatched commit: `.github/` (workflows and actions), `.cargo/` and `rust-toolchain.toml`. A branch that edits them writes its own oracle: it can keep a job named for macOS and run it on Linux.

- If `git diff --quiet origin/main...<sha> -- .github/ .cargo/ rust-toolchain.toml` exits non-zero, the change itself edits them. A run on the branch counts only when the criterion names "the additive workflow rule" and every condition of that rule (below) holds. Otherwise no run on the branch counts: the criterion is `cannot-evaluate` and goes back to the spec author, naming the condition that failed.
- Otherwise, if `git diff --quiet origin/main <sha> -- .github/ .cargo/ rust-toolchain.toml` exits non-zero, `main` changed them after the branch forked. The criterion is `cannot-evaluate` until the branch is rebased onto `origin/main`; say "rebase" in the finding.

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

The criterion fails if any run on the head is `fails`. Otherwise the newest `green` run (highest `databaseId`) is the candidate, and it counts only after step 4. No run is passed over without a class.

## 4. Carry failures from earlier commits

A flake holds across commits: a run that fails and then passes with nothing fixed is flaky, not green (team/05 section 17). Before the candidate counts, list the branch's dispatch runs of the same workflow:

`gh run list --workflow <file> --event workflow_dispatch --branch issue/<n> --limit 100 --json databaseId,headSha,attempt,status,conclusion`

Class each run on another commit `<c>` by step 3, waiting on any that is `waiting`. For each that is `fails`:

- If `git rev-parse <c>^{tree}` equals `git rev-parse <sha>^{tree}`, it counts against the head and the criterion fails.
- Otherwise quote the first failing line of the failed job, from `gh run view <id> --log-failed` (with `--attempt <k>` for the attempt that failed, when rule 1 classed it), or the first annotation `gh run view <id>` prints when no job ran. Then name the hunk of `git diff <c> <sha>` that addresses that line. With no such hunk, no failing line to quote, or a `<c>` that `git rev-parse` cannot read, the criterion fails.

## 5. Read the named jobs

In the run that counts, compare each job the criterion names (`fmt, clippy and tests (macos-26)`, for example) with its `expect`. The run's own `conclusion` is not evidence: a run concludes `success` with every Rust job skipped. A job that is missing, skipped, never expanded from its matrix (its name still shows `${{ matrix.os }}`) or did not conclude `success` fails the criterion. A repository made private plans only the Linux job, and that shows here.

## 6. Start a run (Session only)

When the head is `no-run` and `git rev-parse origin/issue/<n>` is `<sha>`, the session starts a run; for a change under the additive workflow rule, only after every condition of that rule holds, because a dispatch runs the new job with the token it asks for. `.claude/settings.json` lists the workflows a session may start.

1. `gh workflow run <file> --ref issue/<n>`, with the inputs (`-f`) the criterion's check names. A dispatch that exits non-zero makes the criterion `cannot-evaluate`.
2. Take the run id from the last line of the output that ends in `/actions/runs/<id>`. Confirm it with `gh run view <id> --json headSha,event,workflowName`: `headSha` is `<sha>`, `event` is `workflow_dispatch` and `workflowName` is the `name:` of `<file>`. A mismatch stops the item, and the session reports it to the owner.
3. When no line carries the URL, list as in step 2 at most 6 times, at least 10 seconds apart. Wait between lists with the Monitor tool or a background Bash command, never a foreground `sleep`. No matching run after the sixth list: the criterion is `cannot-evaluate`, and the session reports it.
4. Wait for the run as step 3 says, then class it.

Evaluators run in `dontAsk` with no command that waits between lists, so only the session can poll. An evaluator that returned "no run on head" runs once more on the same head after the dispatch; that run is not a new round.

## 7. Runner-image check

For each job a criterion reads under the additive workflow rule, or that the closing check of `grdr-work-issue` section 5 reads, run `gh run view --job <job databaseId> --log`. Each line is the job name, the section and the text, separated by tabs, and the text starts with a timestamp.

- The first line whose text after the timestamp starts with `Image: ` must lie in the section `Set up job` and come before every line of every other section.
- Its value must equal the runner label in the last parentheses of the job's name, or start with that label followed by `-` (`kit hooks (macos-26)` with `Image: macos-26-arm64` passes).
- That label must be a runner label: a value a workflow of `origin/main` gives `runs-on`, directly or through the matrix of its plan job.

Otherwise the criterion fails, quoting the line. The runner writes `Set up job` before any step runs, so no byte of the workflow writes the line that comes first.

## 8. What the verdict lists

Every verdict or session report that reads runs lists each run it read with its id, `headSha` and class; the runs step 4 carried against the head, with the failing line and the hunk named or the reason the criterion fails; and for step 7 the `Image:` line of each job. Write the expectation for each before the command (team/05 section 18).

## The additive workflow rule

A run on a branch whose three-dot diff edits `.github/`, `.cargo/` or `rust-toolchain.toml` counts only when the criterion names "the additive workflow rule" and every condition below holds. Check each with two dots against the current `origin/main`, so that a `main` that moved since the fork fails it and means "rebase".

1. `git diff --name-only origin/main <sha> -- .github/ .cargo/ rust-toolchain.toml` lists only files under `.github/workflows/` that the issue's write set names.
2. In `git diff -U0 origin/main <sha> -- <file>` for each of them, every hunk is one of two kinds:
   - its removed and added lines all lie above the `jobs:` key, outside any block scalar, and each is a whole-line YAML comment;
   - it is a pure insertion (`@@ -L,0 +M,N @@`) of one new job: the first added line is a key at two spaces' indent that the `jobs:` of `origin/main` lacks, the other added lines are blank or indented four spaces or more, and line L+1 of `origin/main` is a job key at two spaces' indent, or L is its last line.
3. Each new job's `runs-on` is a runner label or its own matrix variable, and its matrix comes from an output of a job of `origin/main`. It sets none of `container`, `services`, `concurrency`, `environment` or `continue-on-error`. Its `permissions` is absent or `contents: read` alone. It references no `secrets.` context. Every `uses:` in it appears, with the same full commit SHA, in a workflow of `origin/main`. No step is named `Set up job` or `Complete job`, and no step masks a non-zero exit (`|| true`, `set +e`, `continue-on-error`).
4. Each new job's `name`, with its last parenthesised part removed, differs from the name of every job of `origin/main` with the same part removed.

The session checks 1 to 4 before it dispatches (step 6); when one fails it does not dispatch, and the criterion is `cannot-evaluate` and goes back to the spec author. Each evaluator checks them again on the head it judges.

Under this rule the run counts for the new jobs only, and each must pass the runner-image check (step 7). A criterion on such a branch that names a job `origin/main` already has is `cannot-evaluate`; the closing check of `grdr-work-issue` section 5 covers those jobs on `main`. The new job's steps are the subject of the change, so `eval-diff` judges them as code against the reference model the criterion names.
