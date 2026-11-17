---
name: grdr-audit
description: Run one power prompt from the audit library. Use when a lead, an evaluator or the owner names an audit id (A01, C03, M04, ...), or asks for an audit of a scope.
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
  closes-by: ledger
---

# Run one audit

An audit is a read-only power prompt that asks one question about one scope, such as A01 "find all of the implicit state machines" (`docs/team/04`). The rules a run must hold to are in `audits/README.md`, "How a run works"; this skill is the order of steps. You orchestrate the run; you never answer the prompt yourself, because a result that skips the clean context, the span check and the refuting verifier is worth nothing.

## 1. Get the arguments right

- **Id**: the one you were given. Look it up in `audits/library.toml` for its version, models, scope kind and closure kinds. Do not substitute a similar prompt.
- **Scope**: the whole repository, a named crate or path, or the diff against one base commit (never a range), as the request says. A review round takes the diff against `origin/main`.
- **Commit**: a full SHA (`git rev-parse HEAD`), never a branch name, so the run is reproducible.
- **Arm**: the power wording, plus the control arm when `control_pairing` in `library.toml` pairs this run. Never pick the arm to suit the result.

Read the library, the preamble, the verifier text and the prompt from `main` (`git show origin/main:audits/...`), never from a branch under review.

## 2. Find

Spawn one clean-context subagent (`general-purpose`, on the prompt's `finder_model`, with `isolation: "worktree"`) whose whole prompt is `audits/preamble.md` with `{scope}`, `{commit}`, `{prompt_id}`, `{run_id}` and `{out}` filled, followed by everything in `audits/prompts/<id>.md` after its `Concept:` line. `{out}` is `target/audit/<run_id>/finder.json`. Tell it to check out `<commit>` and to edit nothing but `{out}`. Give it nothing else: no earlier results, no hint of what you expect.

## 3. Check

Validate the finder's JSON against `audits/schema/audit-finding.v1.json`. Drop every span whose quote is not verbatim at the cited line at `<commit>`, every result left with no span, and every `class_key` not on the prompt's `Class keys` line (except `injected-instruction`). Compute each fingerprint as `audits/README.md` says.

## 4. Refute

For each surviving result, spawn a new clean-context verifier subagent on `verifier_model` (Opus): the filled preamble, then `audits/verifier.md`, then that one result with its fingerprint. A severity 1 result also goes to a second verifier on `second_verifier_model`. A result survives only if every verifier returns UPHELD or DOWNGRADED. Verifiers never see the finder's transcript or each other's verdicts.

## 5. Report and file

Your final message gives:

- run id, prompt id and version, arm, scope and commit;
- counts: results returned, after the span check, upheld, reproduced;
- the `checked_and_sound` list and every skipped part of the scope, so "did not look" stays separate from "found nothing";
- fingerprints of upheld results with their severity.

Never restate a result as a fact beyond what the verifier upheld, and never paraphrase a security candidate. A result in `[embargo]` appears in public text only as its fingerprint and "held for private triage" (D-62); tell the owner privately and stop there.

Outside a review round, file each upheld result that is not a security candidate as an issue, as `audits/README.md` step 9 says: search for its fingerprint line first and comment on a match. A prompt in its shadow period files nothing. Do not fix what the run finds, however small: a repair is an ordinary issue with its own writer.

## In a review round

`eval-diff` runs the prompts whose paths and shapes match the diff (at most six power runs and one shared control), in the first round over the whole diff and in the final round over the change since the first. Two rules from owner instruction 4 apply on top:

- A01 also runs on every change whose diff adds or changes a type's fields, a status-like field, or a `match` on one.
- An A01 result that survives the refuting pass is a blocking finding, severity `major`, closed only by a type change (`closes-by = "type"`): never by a comment, a guard or a test alone. Skill `grdr-structure` is the fix.

`garden-architecture` runs A01 over the whole tree when the owner asks; each surviving finding becomes a repair issue that closes only by a type change.

## Rules

- An audit session is read-only: no edits outside `target/audit/`, no pushes, no pull requests.
- A usage limit that ends a run means the run did not happen; never record it as "found nothing" (P9).
- If `audits/library.toml` or the prompt file does not exist, report "not run" with the reason. Never run a prompt from memory.
