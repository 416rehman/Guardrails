# `handoff.v1`, the comment, the pull-request body, escalations and new issues

Sources: team/02 section 1.4 (hand-off), team/01 sections 3 and 4 (evidence template, roles on GitHub) and section 6 (escalation), owner instructions 5 and 6 (issues as work items). Those win if this file disagrees with them.

## Fields

| Field | Content |
|---|---|
| `schema` | `"handoff.v1"` |
| `item` | The issue number, as an integer (`142`) |
| `agent` | Your roster name, the value of `GRDR_AGENT` |
| `model` | The exact model id you ran on, from `.agents/models.toml` (`claude-opus-5-5` or `claude-sonnet-5-5`; `claude-fable-5-2` only for `chief-architect`) |
| `commit` | `git rev-parse HEAD` after your last commit |
| `status` | Workers: `done`, `partial`, `blocked`, `impossible`. Evaluators: `pass`, `fail`, `cannot-evaluate` |
| `round` | `1` on the first submission; after evaluator findings, the number of the review round that will judge this submission (at most 3) |
| `summary` | Two sentences: what changed and what state it is in. Name the evidence ids |
| `changed_paths` | Every path the change touches, from `git diff --name-only <base>` |
| `evidence` | Array of `{cmd, exit, log, sha256}`: the command, its exit code, the log path, the SHA-256 of the log. Taken from `.agent/evidence/*.json`. An evaluator workflow may also cite the verdict comment that shows its verdict and is its round's newest, posted by it or by an earlier run that reached the same verdict: the command that reads and hashes it as `cmd`, the comment URL as `log` and that hash as `sha256` |
| `acceptance` | Array of `{id, result, evidence}`: criterion id from the issue's acceptance section, `pass`, `fail` or `not-run`, and the index into `evidence` |
| `three_arm` | Bug fixes only: `{fails_before, passes_after, fails_on_revert}`, each an index into `evidence` |
| `decisions` | Array of `{at, choice, spec_silent, confidence}` with `at` as `path:line`, least confident first |
| `findings` | Evaluators: `{severity, at, claim, proof}` with severity `blocker`, `major` or `minor`. Workers: anything they found but did not fix, same shape |
| `protected_change_requests` | Array of `{path, why}`. The only route to a protected path |
| `revert` | The exact command that undoes the change, normally `git revert <sha>` |
| `usage` | `{input_tokens, output_tokens, window_share, paused_for_limit}`. Fill what the harness reports; leave zeros you cannot read, the dispatcher records usage from the session |
| `next` | What the receiver must do: resume point for `partial`, the decision needed for `blocked`, the numbers of issues you filed for new work |

## Example (worker, bug fix)

```json
{
  "schema": "handoff.v1",
  "item": 142,
  "agent": "impl-rust",
  "model": "claude-opus-5-5",
  "commit": "3f9c2e1",
  "status": "done",
  "round": 1,
  "summary": "Here-doc bodies now return unresolved instead of malformed, so they reach Ask rather than deny. verify --fast green (evidence verify-20261111T1002); three arms in prove-20261111T0955.",
  "changed_paths": ["crates/grdr-core/src/analyze/shell/heredoc.rs", "crates/grdr-core/tests/shell_heredoc.rs"],
  "evidence": [
    {"cmd": "cargo xtask verify --fast", "exit": 0, "log": ".agent/logs/verify-20261111T1002.log", "sha256": "<hex>"},
    {"cmd": "cargo xtask prove --arm before --test shell_heredoc::unresolved_body", "exit": 1, "log": ".agent/logs/prove-before.log", "sha256": "<hex>"},
    {"cmd": "cargo xtask prove --arm after", "exit": 0, "log": ".agent/logs/prove-after.log", "sha256": "<hex>"},
    {"cmd": "cargo xtask prove --arm revert", "exit": 1, "log": ".agent/logs/prove-revert.log", "sha256": "<hex>"}
  ],
  "acceptance": [{"id": "AC-1", "result": "pass", "evidence": 2}],
  "three_arm": {"fails_before": 1, "passes_after": 2, "fails_on_revert": 3},
  "decisions": [{"at": "crates/grdr-core/src/analyze/shell/heredoc.rs:88", "choice": "treat $(...) inside a quoted here-doc as opaque", "spec_silent": true, "confidence": "low"}],
  "findings": [],
  "protected_change_requests": [],
  "revert": "git revert 3f9c2e1",
  "usage": {"input_tokens": 0, "output_tokens": 0, "window_share": 0.0, "paused_for_limit": false},
  "next": "Evaluators: run AC-1. Filed #151 (nested here-docs at heredoc.rs:120 show the same pattern) with evidence."
}
```

## The comment

`cargo xtask kit handoff` builds and posts this from the draft `.agent/state/handoff-<n>-<agent>.json`: one readable line, then the JSON collapsed:

~~~markdown
Hand-off from impl-rust, attempt 1, round 1: **done**. verify --fast green (verify-20261111T1002); three arms in prove-20261111T0955.

<details><summary>handoff.v1</summary>

```json
{ "schema": "handoff.v1", "item": 142, ... }
```

</details>
~~~

## Pull-request body (team/01 section 3 evidence template)

~~~markdown
Work item: #____   Risk tier: ____ (reason: ____)
Closes #____
<details><summary>meta.v1</summary>

```json
{"schema":"meta.v1","item":____,"harness":"claude-code","model":"<model id>","attempt":____}
```

</details>
## What changed and why
## Testing (commands and their output, not a claim)
## Three-arm proof (bug fixes): fails on parent | passes on change | fails on revert
## Survival tests (removals): test that fails if the removed code remains
## Decisions where the spec was silent, least confident first (the hand-off's decisions list)
## What was not verified, and why
## How to revert
~~~

`cargo xtask kit handoff` builds this body from the draft itself (`xtask/src/orchestrate/handoff/pull_request.rs`); there is no `.github/PULL_REQUEST_TEMPLATE.md`. The `Closes` line is what makes the merge close the issue. The `meta.v1` block replaces the commit trailers (owner instruction 27): one line of JSON in a fenced `json` block inside the collapsed section, with `item` (the issue number), `harness` (`claude-code`), `model` (the exact id from `.agents/models.toml` that wrote the change, the draft's `model`) and `attempt` (from the branch `agent/<n>/a<attempt>`). The `review` workflow and `eval-diff` read `model` to pick the other model; the merge queue refuses a pull request whose body lacks `Closes #<n>` for a work item. The pull request title is the first commit's subject, and the queue's squash commit is that title plus ` (#<pr>)`, the form release-please reads.

"What was not verified" lists every acceptance criterion marked `not-run`, every gate that did not run (for example because WI-0002 had not landed, or the structure checks were absent from the kit binary) and every platform you could not test on.

## Escalation packet (team/01 section 6)

Inside the hand-off comment, after the summary line, one screen:

```markdown
### Escalation #<n>-E<k>
Question: one sentence.
Options: A (recommended) ... / B ...
Evidence: links to the evidence, the hand-off's decisions, failing output.
Cost of waiting: what is blocked.
Default if unanswered in 48 h: the option that changes nothing.
```

Never escalate implementation choices inside the spec, naming that follows the glossary, test structure or refactors inside the write set: those go in `decisions`. Conflicting acceptance criteria return to the spec's author with status `impossible`, not up the escalation route.

## File new work

New work you find (a defect outside your write set, a missing helper another crate should own, a gate that looks wrong) becomes its own issue before you hand off, so it enters the queue instead of being lost or built here:

```sh
gh issue list --state open --search "<key words> in:title"
gh issue create --label status:proposed \
  --title "<what is wrong or missing, one line>" \
  --body-file .agent/state/proposed-<slug>.md
```

Search first and comment on an existing issue instead of filing a duplicate. The body states what you saw and where (`path:line`, a quoted span of at most three lines), the evidence (command, exit code, log digest), the kind and squad you think it belongs to, and "Found while working #<n>". Add only the `status:proposed` label and write no acceptance criteria: a lead or the product lead specifies and readies it, and the agent that writes an item's acceptance criteria never implements it. Put the new number in your hand-off's `next`.
