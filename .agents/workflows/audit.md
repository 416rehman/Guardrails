# audit

One run of the power-prompt library of team/04: discover, refute, prove, record (team/04 section 3, team/03 section 6). Gardeners and leads start it on the team/04 cadence or for a named prompt; the `review` workflow starts it for A01 and the pull-request prompts. The Claude Code implementation is `.agents/kit/workflows/audit.js`, rendered to `.claude/workflows/audit.js`.

## Inputs

| Input | Meaning |
|---|---|
| `prompts` | Explicit prompt ids, for example `["A01"]` |
| `select` or `trigger` | Without `prompts`: run every library prompt whose triggers include this value (`pr`, `nightly`, `weekly` and so on) |
| `scope`, `commit` | A crate, module, path or the whole repository, at a frozen commit (default `HEAD`) |
| `diff` | A range such as `base...head`; the scope becomes that diff and path filters apply |
| `arm` | `power`, `control` or `paired` (default): paired adds the control run the pairing rule asks for |
| `finderModel` | Overrides the library's finder model; the review workflow passes the model that did not write the change |
| `prove`, `record`, `fileIssues`, `maxIssues` | Defaults: prove on, record on, file issues unless the trigger is `pr`, eight issues a week |
| `repo`, `dryRun` | Target repository (default: `[github] repository` of `.agents/harness.toml`, which the plan step reads); build issues without filing them |

## Steps

1. **Plan.** Resolve the frozen commit, read `audits/library.toml` at that commit (defaults and entries), probe the runner, read the trust-core list, count earlier runs per prompt. Without the library, explicit ids take their name, theme, triggers and closure kinds from team/04 sections 7 and 8, and the model defaults of team/04 section 1 apply (finder Sonnet, security finder Opus, verifier Opus, second verifier Sonnet, prover Opus).
2. **Select.** Explicit ids run as given. Selection by trigger keeps entries whose path filters match the changed paths; for `pr` the S prompts come first and at most six run, the rest are recorded as skipped. A prompt whose finder model is not `opus` or `sonnet` is skipped under the model rule.
3. **Pair.** Q prompts are never paired. Prompts whose only triggers are W4, release or model upgrade pair every run; the rest pair their first eight runs and then one in four. One control run, concept "Find the bugs in {scope}.", serves every paired prompt with the same finder model, commit and scope.
4. **Find.** One finder per run, on the run's finder model, read-only. With the runner it prepares the worktree and prompt, the finder writes the output file, and the runner checks it (schema, evidence spans at the commit, fingerprints, suppression of refuted fingerprints). Without the runner the finder follows the team/04 section 2 preamble word for word with the skill's concept, in a detached worktree at the commit, and a separate Sonnet agent checks each evidence span against `git show <commit>:<path>`; a result with any unmatched span is dropped.
5. **Refute.** Each result goes to `audit-verify` in a fresh context on the library's verifier model (Opus); a severity 1 result also goes to the second verifier (Sonnet). No verifier sees the finder's transcript or another verdict. A result survives only when every verifier returns UPHELD or DOWNGRADED; it keeps the highest severity and the weakest label any verifier gives.
6. **Prove.** For surviving CONFIRMED and LIKELY results at severity 1 or 2, an Opus prover writes a reproducer (failing test, Quint trace, or `trybuild` compile-pass case) in a scratch worktree, changing only tests and fixtures, and names the command, whether the defect shows as the command failing or passing, and an output marker. A different agent executes it: through `cargo xtask audit prove` when the runner exists, otherwise by running the command and returning the exit code and output tail. The result is reproduced only when the exit code and the marker both match.
7. **Record.** With the runner, each verdict and each run is recorded (`cargo xtask audit verify`, `cargo xtask audit record`) in the ledger. Without it, the run record goes to `.agent/audit/<run>/run.json` only.
8. **File.** Security candidates (any severity 1, any S result, B results at severity 2) are never filed in public: only their fingerprints are returned, for the private ledger (D-62). Prompts in their 14-day shadow file nothing. The rest become issues labelled `status:proposed` and `kind:repair` (plus `trust-core` on a trust-core path), ranked by severity, then reproduction, then trust core, within eight a week counted over the last seven days (team/04 section 6). Every surviving A01 result is filed regardless of that cap and closes only by an explicit state type (owner instruction 4). An open issue with the same fingerprint token gets a "seen again" comment; a closed one is referenced as regressed.

## Runner contract

The workflow calls these subcommands of `cargo xtask audit` (team/04 work item 2). None of them calls a model; each prints at most ten lines plus a log path, and with `--json` one JSON object.

| Command | Must do and print |
|---|---|
| `run <id> (--scope <s> \| --diff <range>) --commit <sha> --arm power\|control --json` | Create the read-only worktree, write the prompt file (team/04 preamble plus the concept or the control concept, filled in) and name the output file; print `run_id`, `worktree`, `prompt`, `out` |
| `check <run_id> --json` | Validate `out` against `audit-finding.v1`, check every span by exact match at the commit, compute fingerprints, drop suppressed refuted ones; print the checked results |
| `verify <run_id> --fingerprint <fp> --verdict -` | Validate and store one verifier verdict read from stdin |
| `prove <run_id> --fingerprint <fp> --reproducer <dir> --json` | Execute the reproducer at the commit in the audit sandbox; print `reproduced` or `not-reproduced` |
| `record <run_id> --json` | Write the run record and findings to the ledger, security candidates to the private side; print the ledger path |
| `report --prompt <id> --json` | Report the prompt's run count and shadow state, used for pairing |

The plan step treats the runner as present only when `cargo xtask audit --help` names `run`, `check`, `verify`, `prove` and `record`.

## Pauses and limits

Any agent that does not return stops the run before anything is filed, and the run resumes after the usage window resets; a paused run is never recorded as failed or as "found nothing" (team/04 section 9). Per-run token caps of team/04 section 9 are enforced by the dispatcher and the runner, not by this workflow.

## Not yet available

| Missing piece | Effect now | Completed by |
|---|---|---|
| Audit runner | Agents prepare the worktree, check spans and execute reproducers; nothing reaches the ledger | team/04 work item 2 |
| `audits/library.toml` and the audit skills | Only explicit ids run, with team/04 text as the concept | team/04 work item 3 |
| `audit-ledger` repository and its private fork | Local run records only; security candidates stay in the run result | team/04 work item 1 |
