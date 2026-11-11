# Audit library

The power prompts of `docs/team/04-power-prompts.md`. Each prompt is a read-only audit that asks one question about one scope, cites its evidence as file and line spans, states each result as a claim a verifier can refute, and closes a result only through a type, a test, a lint or a decision record. Only `cargo xtask audit` runs them; an agent runs one through the `grdr-audit` skill and never by hand.

`audits/**` is gate configuration and trust core (D-63) and a protected path: an agent cannot edit it, and a change to it is a trust-core work item.

## Files

| Path | What it holds |
|---|---|
| `library.toml` | The registry: defaults, triggers, diff shapes, the nightly rotation, the ledger and issue settings, and one `[[prompt]]` per prompt |
| `preamble.md` | Section 2's shared preamble, word for word. It ends with the line `Concept:` |
| `verifier.md` | Section 3's verifier text, word for word, then the output form and the line `Result:` |
| `prompts/<id>.md` | One prompt per file, in the skill form of section 1: front matter, heading, `Concept:` and the exact wording, then `Looks in`, `Evidence`, `Claim`, `Class keys`, `Artefact` and `Closure guidance`. Q01 has `Procedure:` instead of `Concept:` |
| `schema/audit-finding.v1.json` | The finder's report, the verifier's report, and the ledger record (section 4) |
| `schema/audit-run.v1.json` | The run record (section 4); it refers to the finding schema by `$id`, so load both into one registry |
| `schema/fixtures/{valid,invalid}/` | Every file in `valid/` must pass and every file in `invalid/` must fail (team/04 work item 1) |

The ledger the runner writes lives in separate repositories (`[ledger]` in `library.toml`), never in this directory.

## What `cargo xtask audit run <id>` does

1. **Load.** Read `library.toml` and the prompt file from the base branch, never from the change under review, so a pull request cannot change its own audits. Merge the entry over `[defaults]`. Refuse to run when the front matter disagrees with the entry (`name` must be `audit-<id in lower case>-<name>`, and `metadata.version` and `metadata.closes-by` must equal `version` and `closes-by`), or when a model name is not in `[rules] allowed_models`. Resolve model names to ids through `.agents/models.toml`; no audit pass runs on `fable`.
2. **Select the scope.** The trigger's `scope` applies unless the entry's `scope` table overrides it for that trigger.
   - `diff`: a pull request. The prompt runs when the diff touches its `paths` (or the paths listed in the front matter of each `docs/state-machines/*.md` for `paths_from`) and, when `pr_shape` is set, a changed file in those paths matches one of the shapes. A shape matches through its ast-grep rule, or through its `line_regex` on added or removed lines, its `paths`, or its `text_regex` on the title, body and commit subjects. At most six power runs plus one shared control per pull request, `[trigger.pr] order` first, then library order; the rest are recorded as `skipped` with reason `max-power-runs`. A prompt with `pr_priority = "never-skip"` (A01) is outside the six and is funded first from the per-pull-request cap. Pull requests from forks are audited when they enter the merge queue.
   - `rotation`: the next `[[rotation]]` entry whose paths exist, so the cycle grows as crates arrive. One of `security_rotation` runs each night.
   - `repo`: the whole tree at the commit, or the five crates with the most churn when the tree does not fit the cap.
   - `machines`: for A03, each machine the A01 run of the same trigger upheld, passed as `{name}`.
   - `kit` (`.agents/`, `.claude/`, `audits/`, the marketplace manifest and the ledger), `bench` (`audit-bench`) and `release-head` (findings diffed against the previous release).
   - A w4 prompt runs in the week whose bucket is `((ISO week - 1) mod 4) + 1`. A scope that does not exist yet is recorded `skipped` with reason `scope-absent`, never as "found nothing" (P9). The run record states the scope as `crate`, `diff`, `path` or `repo`.
3. **Cap.** A run's token cap is the lower of the entry's `usage_cap_tokens` and the per-run cap of the trigger's `routine` in `.agents/kit/usage.toml`, which also holds the per-night, per-week, per-release and per-incident caps and the usage brake. A run that does not fit is recorded `skipped` with the cap it missed. A subscription usage limit (`.agents/harness.toml [limits]`) pauses the run and resumes it after the window resets; the pause is recorded in `paused_for_limit`, and a paused run is never failed or empty.
4. **Build the prompt.** Fill `{scope}`, `{commit}`, `{prompt_id}`, `{run_id}` and `{out}` in `preamble.md`, plus the entry's `params` (`{name}` for A03, `{ref}` for Y03 and Y04). Append everything in the prompt file after its `Concept:` line. The control arm appends `control_concept` instead; it runs on the same commit, scope, finder model, cap and verifier as the power runs it pairs with, under `control_pairing`. Q01 sends nothing of its own: it replays the prompts in `replay` with `--frozen`.
5. **Find.** Check out `<commit>` in a fresh worktree and start `claude -p` on the finder model at the entry's effort, with `--max-turns` from `finder_max_turns`, `--permission-mode dontAsk`, and only Read, Grep, Glob, and Write limited to `{out}` (`.agent/audits/<run_id>/finder.json`). No Bash, no network beyond the model endpoint, no credentials. The fleet container (WI-0006) adds the read-only mount and the egress block; until then the permission rules and the hooks are the only control. `cargo xtask dispatch` starts the audit routines of `.agents/kit/usage.toml` on their cadence, and the review pass runs A01 inside the `review` workflow.
6. **Check.** Validate `{out}` as `finder_report` against `schema/audit-finding.v1.json`. Reject a `class_key` that is neither on the prompt's `Class keys` line nor `injected-instruction`. Discard every span whose `quote` does not occur verbatim in the file at `<commit>` starting on the cited line, and every result left with no span. Resolve each span's enclosing item with ast-grep (the heading path in a document), then compute `snippet_sha256` (the quote), `item_sha256` (the item's text) and the fingerprint: SHA-256 of `prompt_id|prompt_major|class_key|crate|item`. A fingerprint the same prompt version refuted on an unchanged `item_sha256` is dropped.
7. **Refute.** Give each surviving result to a verifier in a new context: `preamble.md` filled for the same run, then `verifier.md`, then the result JSON with its fingerprint. The verifier never sees the finder's transcript or another verifier's output. It runs on `verifier_model` (Opus); a severity 1 result adds `second_verifier_model` (Sonnet). A result survives only if every verifier returns UPHELD or DOWNGRADED; the record keeps the higher severity.
8. **Prove.** For each upheld CONFIRMED or LIKELY result at severity 1 or 2, the prover (`prover_model`) writes a reproducer in a scratch worktree: a failing test, a Quint trace for `quint-connect`, or a `trybuild` case. The runner, not the agent, runs it against `<commit>` and records `reproduced` or `not-reproduced`.
9. **Record.** Write the `audit-run.v1` record with its results and update each `audit-finding.v1` record. A security candidate (`[embargo]`: any severity 1 result, any S-theme result, any B-theme result at severity 2 or worse) goes to the private ledger only, with a stub (fingerprint, prompt id, severity, state) in the public one. Until the ledger repositories exist, the runner writes to `[ledger] local` and prints the owner step that creates them.
10. **Hand over.**
    - On a pull request, `eval-diff` posts one comment through the runner with the results that are not security candidates. A security candidate fails the audit check with its fingerprint and "held for private triage", and the merge waits until `lead-security` has classified it in private triage (D-62, owner instruction 7). A surviving result of a prompt with `blocking` (A01) is a blocking review finding at that level.
    - On a schedule, the agent that ran the audit files each upheld result that is not a security candidate as an issue in `[issues] repository`: it searches for the fingerprint line first and comments on a match; otherwise it creates the issue with `[issues] labels`, `squad:<owner of the locus>` from `.agents/owners.toml`, the title form, the fingerprint and closure lines, the prompt id and version, severity, label, the evidence spans as code blocks, the claim, the verifier's reason and the proof artefact. Results are ranked by `rank`; at most `max_per_week` are filed a week and the rest stay in the ledger for the next week. A prompt with `always_file` (A01) files every upheld result regardless of the cap. A prompt in shadow (`shadow_days` from its first run of the current major version) files nothing and blocks nothing.
    - A repair pull request carries the issue's fingerprint and closure lines. The gate runs `cargo xtask audit close <fingerprint> --by <kind>:<ref>` and fails when the closure does not verify or its kind is not in the prompt's `closes-by`, so the issue closes only through a verified closure.

**Release gate.** A release is blocked by any result of a prompt with `release_gate = n` at severity `n` or worse in one of `[release_gate] blocking_states`: M01 to M05 at severity 1, F04 and F08 at severity 1 or 2.

## Other subcommands

- `verify` and `prove` re-run step 7 or 8 for one fingerprint.
- `close <fingerprint> --by <kind>:<ref>` checks a closure as team/04 section 5 says: a `trybuild` case that fails to compile for a type, the three-arm proof for a test, a fixture that fails the lint for a lint, a decision record that cites the fingerprint for a decision. S1 never closes by decision record, S5 only by type or test, A01 only by type.
- `diff --from <run|date|commit> --to <run|date|commit> [--prompt <id>] [--frozen]` sorts results into `new`, `persisting`, `closed`, `regressed` and `refuted-again`.
- `report` regenerates the metrics of section 6 from the ledger alone.
- `coverage`, part of `verify`, fails when a crate in `architecture.toml` is in no rotation entry and no prompt's `paths`.

## Changing the library

- A change to `preamble.md` bumps every prompt and starts a recalibration (team/04 section 6).
- A change that alters what a prompt looks for bumps its major version: new fingerprints, mapped forward where `class_key` is unchanged, and 14 days in shadow. A wording edit that keeps the concept bumps the minor version. The version is in three places that must agree: the entry, the front matter and the heading.
- A new crate joins `[[rotation]]` and the relevant `paths` in the pull request that adds it.
- Class keys are fixed per prompt, so ledger diffs are exact. Adding one is a minor bump; renaming one is a major bump.

## Names

The audit ids M01 to M05 are the security prompts of team/04 section 8, and Y01 to Y04 its calibration prompts, so that S1 to S7 and Q01 keep their owner-given meanings. The structure checks S1 to S7 of the `grdr-structure` skill (file size, declaration order, comments, implicit state machines, nesting, panic paths, hard-coded values) are a different set run by the kit's hooks and gate V-structure. A01 is the model audit behind the deterministic structure check S4, and E08 the one beside check S7: it finds the hard-coded behaviour a pattern match cannot see (P14).
