---
name: grdr-build
description: Build the whole product by working the repository's issues one iteration at a time, slice by slice, through grdr-work-issue. Use when asked to build the product, keep building or work through the issues, and when a /loop run names this skill or building the product.
license: Apache-2.0
metadata:
  version: "3"
  owner: agent-kit
---

# Build the product

A wrapper on `grdr-work-issue`. Each run of this skill is one iteration: pick the next work, run it, write a two-line note, and stop. Under `/loop` with no interval the next iteration starts when this one ends.

State lives on GitHub only: issues, their labels and "blocked by" links, and pull requests. Read it fresh at the start of every iteration and never carry a plan in the session's memory, so a new iteration, a restart or a compacted context picks up where the last one stopped.

## Slices

The product is built in end-to-end slices, never one layer after another. The slices are defined on GitHub, not in the repository:

- Each slice is an epic issue labelled `epic` and `slice:N` (N = 0, 1, 2, ...). Its body states the end-to-end scenario the slice must make work on Windows, macOS and Linux at once, through every layer it names (endpoint, wire, server ingest and storage, API, console or CLI, docs), and lists the design documents it draws on.
- Every product issue carries the `slice:N` label of the slice it serves. An issue with no slice label gets one from its squad's lead before it is worked.
- The lowest open epic is the current slice. Find it with `gh issue list --label epic --state open --json number,title,labels,body`.

**Nothing in the plan is missed.** Every work item listed in a design document's "## Work breakdown" section (ids such as W-1.1, 04-21, EN-A1, P-1, 14.1.1, I2.1, E3.2) has a GitHub issue whose title or body names the item id and the document (`design/NN`). When a slice starts, its leads check this for every document the slice draws on and file each missing item (`gh issue list --state all --search "<id> design/NN"`). Before the loop reports the plan done, the leads check it for every design document. A design change that adds a work item files its issue in the same pull request.

Each layer an epic names has a lead: endpoint `lead-endpoint`, with `lead-windows`, `lead-macos`, `lead-linux` for the sensors and `lead-adapters` for agent hooks; wire `lead-core`; server ingest, storage and API `lead-server`; console `lead-interfaces`; CLI `lead-endpoint`; docs `product-lead`. Any other area takes its lead from `.claude/owners.toml`.

## One iteration

1. **Check the stop conditions** (below). If one holds, stop and report it. Then check the branches against the owner's rule, one issue, one branch `issue/<n>`, one pull request (`grdr-work-issue`, "Branches and pull requests"): run `node .claude/hooks/branch-check.mjs` and read it by its last line, as that section says. It is clean only with exit 0 and the summary `branch-check: <owner/repo>: ... findings: 0.` as the last line. It has findings only with exit 1 and the summary as the last line: repair each `finding:` line as that section's table says before picking new work. Its `info:` lines about fork pull requests need nothing and never stop the loop.
2. **Read GitHub.** The open epics, and the open issues with their labels: `gh issue list --state open --limit 500 --json number,title,labels,body`. For each candidate, its open blockers: `gh api repos/{owner}/{repo}/issues/<n>/dependencies/blocked_by --jq '[.[] | select(.state == "open")] | length'`. Leave out `good-first-issue`, `extractive` and issues already in progress (a branch `issue/<n>` or an open pull request on it).
3. **Start the slice.** A slice has started when the epic carries one comment per layer it names, `Layer <name> filed: #a, #b, ...`. Until it does, spawn the lead of each missing layer, in parallel. Each reads the epic and its design documents, then the existing issues for its layer (including one-line stubs that still need a spec), writes the spec into each stub with `grdr-write-spec`, checks that every Work breakdown item of those documents has an issue, files every issue the slice still needs in its layer with the work-item form and the `slice:N` label (spec citing the doc section, write set, acceptance criteria, "blocked by" links), gives unlabelled issues of its squad a slice, and posts the layer comment on the epic. No layer is left for later, and no implementer starts in the slice before it has started.
4. **Pick.** The highest-priority open issue labelled with the current slice whose blockers are closed; ties by oldest number.
   - It has a usable spec (spec, write set, acceptance criteria with a check and an oracle each): work it.
   - It has none: spawn its squad's lead to write one with `grdr-write-spec`, read it again, then work it.
   - Nothing in the current slice is workable: take issues of the next slice instead, starting it first as in step 3, so capacity is not idle. Never more than one slice ahead.
5. **Work it** with the `grdr-work-issue` flow, steps 1 to 5. Up to three issues may run at once, one subagent each in one message, when their write sets are disjoint and none blocks another. Never two writers on the same files.
6. **Close the slice.** When every issue of the current slice is closed, spawn `eval-acceptance` to drive the epic's scenario end to end on Windows, macOS and Linux. On a pass, comment its evidence on the epic and close it. On a fail, file the missing work as issues of that slice and keep going.
7. **Note.** End with two lines: what landed (pull requests merged, issues filed), and what is next.

## Stop

Stop the loop and say why when:

- no open epic is left, every Work breakdown item of every design document has an issue (the leads checked it this iteration), and every open issue is closed or waits on an outside precondition: list those preconditions (signing programmes, store and developer accounts, hardware, legal steps) with their issues, and say that the next slice needs an epic;
- the same issue failed three rounds in `grdr-work-issue`: report the issue, its branch and the open findings;
- CI on `main` is red: report the failing run and do not start new work. Judge it by each required workflow's latest `push` run on `main`, never by the newest runs of any kind, which scheduled runs crowd out:
  1. The required checks are the ruleset's, read page by page: `gh api repos/{owner}/{repo}/rules/branches/main --paginate --jq '.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context'`. If the call fails, the list is empty, or it is as long as `required_check_limit` in `.claude/hooks/ci-rules.json`, CI could not be judged: stop.
  2. For each workflow in `gh workflow list --limit <workflow_list_limit> --json id --jq '.[].id'` (could not judge when the list is as long as that limit), its latest push run is `gh run list --workflow <id> --branch main --event push --limit 1 --json databaseId,conclusion,status`. Empty output is not "no runs": it means could not judge. A workflow with no push run on `main` has nothing to judge. A run still in progress is polled with `gh run view <databaseId> --json status,conclusion` every `poll_interval_seconds`, at most `poll_limit` times; one still unfinished after that reads red.
  3. A workflow is required when one of its jobs is a required check. Read the jobs of that latest push run with `gh run view <databaseId> --json jobs --jq '.jobs[].name'`. A run that never started (`startup_failure`) has no jobs. For such a run, and for any run with no jobs, read the jobs of the workflow's last successful run of merged code instead: `gh run list --workflow <id> --branch main --event push --status success --limit 1 --json databaseId`. Never read them from a run of another branch or event: a pull request can rename its jobs, and its run would make a red `main` read green. If no such run exists, the workflow counts as red. Job names are read from runs, never from the workflow file, because a matrix names its jobs only when it runs.
  4. CI is red when a required workflow's latest push run concluded anything other than `success`, `startup_failure` included.
  5. If no workflow provides any of the required checks, CI could not be judged: stop.

  `node .claude/hooks/ci-stop.mjs` runs these five steps with these commands, tested offline by `node --test .claude/hooks/ci-stop.test.mjs`. It exits 0 green, 1 red and 2 could not judge, and its last line is `ci-stop: <green|red>: required workflows ...` only when it judged. Read it as the branch check is read: green only with exit 0 and the summary `ci-stop: green: ...` as the last line, red only with exit 1 and the summary `ci-stop: red: ...` as the last line. Exit 0 without the summary as the last line, exit 2, and any other status mean could not judge.

  `branch-check.yml` has no push trigger and no required check, so it never counts here. Its result reaches the loop only through the branch check of step 1;
- the branch check could not look (its last line is not the summary, whatever the status, or it exited 2 or any status other than 0 and 1), or a finding is one its table sends to the owner: report the output and do not start new work;
- the account's usage limit is reached.

Under `/loop`, a stop means you do not schedule another iteration.

## Never

- Keep a list of picked issues, progress or plans outside GitHub.
- Skip the evaluators, the three-round limit or CI to go faster.
- Work an issue whose blockers are open, one without acceptance criteria, or one with no `slice:` label.
- Work two slices ahead, or close an epic without its end-to-end `eval-acceptance` pass on all three systems.
