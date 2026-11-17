# Audit library

The power prompts of `docs/team/04-power-prompts.md`. Each prompt is a read-only audit that asks one question about one scope, cites its evidence as file and line spans, states each result as a claim a verifier can refute, and closes a result only through a type, a test, a lint or a decision record. A session or an agent runs one through skill `grdr-audit`, never by improvising its own wording.

`audits/**` is gate configuration and trust core (D-63): a change to it is a trust-core work item.

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

The ledger lives in separate repositories (`[ledger]` in `library.toml`), never in this directory. Until they exist a run keeps its records under `[ledger] local` and says so.

## How a run works

Skill `grdr-audit` gives the steps; this is what each one must hold to.

1. **Load.** Read `library.toml` and the prompt file from `main`, never from the change under review, so a pull request cannot change its own audits. Merge the entry over `[defaults]`. Refuse to run when the front matter disagrees with the entry (`name` must be `audit-<id in lower case>-<name>`, and `metadata.version` and `metadata.closes-by` must equal `version` and `closes-by`), or when a model is not in `[rules] allowed_models`. No audit pass runs on Fable.
2. **Select the scope.** The trigger's `scope` applies unless the entry's `scope` table overrides it for that trigger.
   - `diff`: a pull request. The prompt runs when the diff touches its `paths` (or the paths listed in the front matter of each `docs/state-machines/*.md` for `paths_from`) and, when `pr_shape` is set, a changed file in those paths matches one of the shapes (`line_regex` on added or removed lines, `paths`, or `text_regex` on the title, body and commit subjects). At most six power runs plus one shared control per pull request, `[trigger.pr] order` first, then library order; the rest are recorded as skipped. A prompt with `pr_priority = "never-skip"` (A01) is outside the six.
   - `rotation`: the next `[[rotation]]` entry whose paths exist, so the cycle grows as crates arrive.
   - `repo`: the whole tree at the commit, or the five crates with the most churn when the tree does not fit the cap.
   - `machines`: for A03, each machine the A01 run of the same trigger upheld, passed as `{name}`.
   - `kit` (`.claude/`, `audits/` and the ledger), `bench` (`audit-bench`) and `release-head` (findings diffed against the previous release).
   - A scope that does not exist yet is recorded as skipped, never as "found nothing" (P9).
3. **Build the prompt.** Fill `{scope}`, `{commit}`, `{prompt_id}`, `{run_id}` and `{out}` in `preamble.md`, plus the entry's `params` (`{name}` for A03, `{ref}` for Y03 and Y04). Append everything in the prompt file after its `Concept:` line. The control arm appends `control_concept` instead, on the same commit, scope, finder model and verifier as the power runs it pairs with, under `control_pairing`. Q01 sends nothing of its own: it replays the prompts in `replay`.
4. **Find.** A clean-context subagent on the finder model, in a worktree at `<commit>`, with only read tools and the one output file `{out}`. It never sees an earlier run.
5. **Check.** Validate `{out}` as `finder_report` against `schema/audit-finding.v1.json`. Reject a `class_key` that is neither on the prompt's `Class keys` line nor `injected-instruction`. Discard every span whose `quote` does not occur verbatim in the file at `<commit>` starting on the cited line, and every result left with no span. The fingerprint is the SHA-256 of `prompt_id|prompt_major|class_key|crate|item`. A fingerprint the same prompt version refuted on an unchanged item is dropped.
6. **Refute.** Each surviving result goes to a verifier subagent in a new context: `preamble.md` filled for the same run, then `verifier.md`, then the result JSON with its fingerprint. The verifier never sees the finder's output beyond that result, or another verifier's. It runs on `verifier_model` (Opus); a severity 1 result adds `second_verifier_model` (Sonnet). A result survives only if every verifier returns UPHELD or DOWNGRADED; the record keeps the higher severity.
7. **Prove.** For each upheld CONFIRMED or LIKELY result at severity 1 or 2, a prover subagent (`prover_model`) writes a reproducer in a scratch worktree (a failing test, a Quint trace, or a `trybuild` case) and runs it against `<commit>`: `reproduced` or `not-reproduced`.
8. **Record.** Write the `audit-run.v1` record with its results. A security candidate (`[embargo]`: any severity 1 result, any security-theme result, any boundaries-theme result at severity 2 or worse) never goes into public text: only its fingerprint and "held for private triage" (D-62).
9. **Hand over.**
   - In a review round, `eval-diff` puts the results that are not security candidates in its verdict. A surviving result of a prompt with `blocking` (A01) is a blocking finding at that level. A security candidate fails the review with its fingerprint and "held for private triage", and the change waits until `lead-security` has classified it.
   - Otherwise the agent that ran the audit files each upheld result that is not a security candidate as an issue: it searches for the fingerprint line first and comments on a match; otherwise it creates the issue with `[issues] labels`, `squad:<owner of the locus>` from `.claude/owners.toml`, the title form, the fingerprint and closure lines, the prompt id and version, severity, label, the evidence spans as code blocks, the claim, the verifier's reason and the proof. At most `max_per_week` a week, ranked by `rank`; a prompt with `always_file` (A01) files every upheld result. A prompt in shadow (`shadow_days` from its first run of the current major version) files nothing and blocks nothing.
   - A repair pull request carries the issue's fingerprint and closure lines, and its evaluators check the closure as team/04 section 5 says: a `trybuild` case that fails to compile for a type, the three-arm proof for a test, a fixture that fails the lint for a lint, a decision record that cites the fingerprint for a decision. S1 never closes by decision record, S5 only by type or test, A01 only by type.

**Release gate.** A release is blocked by any result of a prompt with `release_gate = n` at severity `n` or worse in one of `[release_gate] blocking_states`: M01 to M05 at severity 1, F04 and F08 at severity 1 or 2.

## Changing the library

- A change to `preamble.md` bumps every prompt and starts a recalibration (team/04 section 6).
- A change that alters what a prompt looks for bumps its major version: new fingerprints, mapped forward where `class_key` is unchanged, and 14 days in shadow. A wording edit that keeps the concept bumps the minor version. The version is in three places that must agree: the entry, the front matter and the heading.
- A new crate joins `[[rotation]]` and the relevant `paths` in the pull request that adds it.
- Class keys are fixed per prompt, so ledger diffs are exact. Adding one is a minor bump; renaming one is a major bump.

## Names

The audit ids M01 to M05 are the security prompts of team/04 section 8, and Y01 to Y04 its calibration prompts, so that S1 to S7 and Q01 keep their owner-given meanings. The structure checks S1 to S7 of the `grdr-structure` skill (file size, declaration order, comments, implicit state machines, nesting, panic paths, hard-coded values) are a different set, a review rubric. A01 is the model audit behind structure check S4, and E08 the one beside check S7: it finds the hard-coded behaviour a pattern match cannot see (P14).
