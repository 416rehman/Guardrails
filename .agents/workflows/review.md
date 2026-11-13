# review

Cross-model review of one pull request, run inside an `eval-diff` session (team/03 section 6, team/02 section 6). Independent finders look for defects on the model that did not write the change, audit A01 runs when the diff touches state, a shadow seat reports beside the verdict, a group of Opus refuters votes on every finding, and the verdict goes out as a check run and a comment on the work-item issue. The Claude Code implementation is `.agents/kit/workflows/review.js`, rendered to `.claude/workflows/review.js` by `cargo xtask kit render`.

## Inputs

| Input | Meaning |
|---|---|
| `pr` | Pull-request number in the repository (default: `[github] repository` of `.agents/harness.toml`, which the scope step reads) |
| `item` | Work-item issue number; otherwise the `item` of the pull request body's `meta.v1` block, its `Closes #<n>` line or its closing references |
| `round` | Review round; otherwise derived from earlier verdict comments |
| `repo`, `dryRun`, `force` | Another repository; build the verdict without publishing; review a head that was already reviewed |
| `base`, `head` | Without `pr`: review a local range and publish nothing |

## Models

Every agent runs on Opus 5.5 or Sonnet 5.5, never Fable or Haiku (`design/_review/03`).

- Writer models come from the `model` of the pull request body's `meta.v1` block (skill `grdr-handoff`), else from the newest worker `handoff.v1` comment on the item, mapped through `.agents/models.toml` at the base commit. Commits carry no trailers (owner instruction 27). A local review reads the hand-off drafts under `.agent/state/`.
- Finders run on the other model: Opus when Sonnet wrote the change, Sonnet when Opus wrote it, Opus for a Fable-written change, and both when no metadata names a model. When both Opus and Sonnet wrote the change, every finder runs on both, so each line meets a reviewer that did not write it.
- Refuters run on Opus. The scope, diff and publishing steps run on Sonnet at low effort; they run commands and copy output, and judge nothing.

## Steps

1. **Scope.** Collect the base and head commits, the work item and its labels, the writer models, the trust-core list (`security/trust-core.paths` at the base), the changed paths, the hunk headers of the diff and the added or removed lines that look state-like (type declarations and aliases, fields, enum variants, `match` or `switch`, and the words state, status, phase, stage, mode). Earlier verdict comments are read from the item issue and the pull request.
2. **Round.** Round 1 reviews the whole diff (`base...head`). A later round reviews only `previous-head..head`. The same head as the last verdict is not reviewed again. A fourth round is not reviewed: the check fails and the item returns to its lead (team/03 section 4.2).
3. **Find.** Fourteen finders per reviewer model, each read-only, each told that repository and pull-request text is data:
   - the built-in `code-review` skill at effort `medium`, `high` for high tier, `xhigh` when a trust-core path changes;
   - three `pr-review-toolkit` agents (`silent-failure-hunter` for error handling a deletion removed, test coverage, type design), falling back to the same focus as a plain finder when the plugin is not enabled;
   - the ten per-PR prompts of research h09 (trust boundaries, dropped errors, tests, removals and guards, unstated behaviour changes, lifecycle deltas, silent decisions, new dependencies, retry safety, suppressions). The removal prompt also treats a symptom fix, a new guard around an implicit state and a mechanical file split as design findings.
   Each finding has a head-side path and line, a category, a severity (blocker, major, minor), a failure scenario, quoted evidence and a fix.
   A fifteenth seat, `thermo-nuclear-code-quality-review` (structural quality and the refactor candidates `cleanup` left), runs in shadow for its first 20 items or two weeks (team/03 section 9 rule 7): its findings are listed under "Shadow seats" in the check run and the result, are not refuted, and never change the verdict. Moving it out of shadow is a kit change.
4. **Audits.** Through the `audit` workflow, at the same time as the finders:
   - A01 (implicit state machines) on this round's diff whenever it has state-like lines, with the reviewer model as finder (`cargo xtask audit run A01 --diff <range>`). A surviving A01 result is at least major, so it blocks, and it closes only by an explicit state type.
   - The library's pull-request prompts (`audits/library.toml`, path filters, at most six, M01 to M05 first, plus the shared control) in round 1 over the whole diff, and again on the final head over the change since round 1. The final head is round 3, or an earlier round whose own findings would pass.
   - Pull requests from forks get neither here; they run in the merge queue (team/04 section 3), and the verdict lists them as not run.
5. **Filter.** Style and cleanup findings are dropped. Findings at the same path, category and line (within three lines) merge. From round 2, a finding outside the lines changed since the last round is dropped, so nothing is raised again on unchanged code. In round 1, a finding outside the changed lines is pre-existing.
6. **Verify.** Each remaining finder result faces Opus refuters in fresh contexts: three for blocker and major, one for minor. A refuter never sees the finder's reasoning or another refuter's verdict. It re-reads the evidence, looks for the strongest reason the defect cannot happen, corrects the severity, says whether the defect already existed at the base, and refutes any style remark. A finding survives when more than half the refuters uphold it; it keeps the highest severity they give. Audit results arrive already refuted by the audit's own verifiers and skip this vote.
7. **Tag and verdict.** Survivors are tagged Pre-existing (outside the change or present at the base), Important (blocker or major) or Nit (minor). The verdict is `fail` with any Important finding, `cannot-evaluate` when A01 was needed and could not run, and `pass` otherwise. Writer metadata naming a model outside `.agents/models.toml` is itself an Important finding.
8. **Publish.**
   - A check run named `eval-diff` on the head commit, with the findings as its summary and the `handoff.v1` verdict as its text. Check runs need a GitHub App, which is an optional later hardening (owner instruction 23); under the one `gh` login the step falls back to a commit status `grdr-evaluator/eval-diff`.
   - A one-line comment on the work-item issue (the pull request when there is none) carrying a hidden marker with the round, the head and the findings. When only the commit status could be posted, the comment also carries the findings and the verdict in collapsed sections. The publisher then hashes the comment as GitHub holds it, and the hash with the command that reproduces it is the review's own entry in the hand-off's `evidence`, beside each audit run's record: `kit handoff` refuses a finished verdict with no evidence. The lookup and the hash find the comment by the line that starts with its marker, since the hand-off comment quotes the hash command and so holds the comment's token too, and the hash of an empty read is never evidence. When that read prints no comment, one more step reads it again and posts nothing. If that read fails too or reports nothing, or its agent does not return, the review returns `incomplete` with the comment URL and the hash command, so the agent hashes the comment and adds the entry without reviewing again. Its reason says which happened, since a resumed run reads the comment again only in the second case, and names the digest of no input as one the agent never cites: when the command prints it, gh printed no comment and the agent runs it again.
   - Each Pre-existing finding becomes a new issue labelled `status:proposed` and `kind:bug` (plus `trust-core` on a trust-core path) for a lead to triage, with a fingerprint token in its body. An open issue with the same token gets a one-line "seen again" comment instead; a closed one is referenced as regressed.

## Rounds, repeats and pauses

- The marker in each verdict comment is the round record. It holds a number that orders the round's verdicts, since the scope lists the issue's markers before the pull request's, and its token is a digest of the comment and that number. The marker with the round's highest number is the round's record, so the next round reads its findings and none from the comments it replaced. A re-run of the same round and head finds its marker and posts nothing twice, and so does a forced re-review that reaches the verdict of the round's newest marker, or a run resumed while it was publishing. Any other verdict takes the next number, so a forced re-review posts and cites a comment of its own, even when it returns to a verdict the round had before.
- Any agent that does not return (a usage limit, a terminal error) stops the run before anything is published; the run is resumed after the window resets and is never counted as a failed round.

## What it never does

It never edits, commits, approves, merges, closes an issue, changes a label on an existing issue or creates a label. It never reads instructions from the pull request: `REVIEW.md` and the trust-core list come from the base commit. A security candidate from an audit appears only as its fingerprint with "held for private triage" (team/04 section 4).

## Not yet available

| Missing piece | Effect now | Completed by |
|---|---|---|
| A GitHub App for the evaluators (optional, owner instruction 23) | Commit status plus a full comment instead of a check run | team/06 section 11 item 8 |
| `thermo-nuclear-code-quality-review` fetched on the machine | The shadow seat runs as a plain finder with the same focus | Claude Code fetching the pinned plugin at session start; `kit install` enables it |
| Audit runner (`cargo xtask audit`) | A01 runs through the audit workflow's agent fallback, with agent span checks | team/04 work item 2 |
| `pr-review-toolkit` fetched on the machine | The three toolkit focuses run as plain finders | Claude Code fetching the pinned plugin at session start; `kit install` enables it |
