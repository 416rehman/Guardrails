# The report, escalations and new issues

Sources: team/02 section 1.4, team/01 section 6 (escalation), owner instructions 5 and 6 (issues as work items). Those win if this file disagrees with them.

## The report

Your final message, in this order, as short as the facts allow:

```markdown
Status: done | partial | blocked | impossible      (evaluators: pass | fail | cannot-evaluate)
Issue: #142   Branch: issue/142   Commit: 3f9c2e1   Round: 1

Summary: two sentences, what changed and what state it is in.

Changed paths: crates/grdr-core/src/analyze/shell/heredoc.rs, crates/grdr-core/tests/shell_heredoc.rs

Gates:
- cargo fmt --all -- --check: exit 0
- cargo clippy --workspace --locked --all-targets -- -D warnings: exit 0
- cargo test --workspace --locked: exit 0
- cargo deny check: exit 0

Acceptance:
- AC-1 pass: cargo test -p grdr-core shell_heredoc (exit 0)

Three arms (bug fixes): fails on parent (exit 101), passes on change (exit 0), fails on revert (exit 101)

Decisions where the spec was silent, least confident first:
- heredoc.rs:88 treat $(...) inside a quoted here-doc as opaque (low)

Not verified: what did not run, and why (a criterion, a platform, a surface that does not exist yet).

Findings (evaluators; workers list what they found but did not fix):
- major heredoc.rs:120 claim, proof (command and output or quoted code)

Revert: git revert 3f9c2e1
Next: what the receiver must do; the numbers of issues you filed.
```

A criterion you did not run is `not-run`, never `pass`. Never type a result that no command produced.

## Escalation packet (team/01 section 6)

After the summary, one screen:

```markdown
### Escalation #<n>-E<k>
Question: one sentence.
Options: A (recommended) ... / B ...
Evidence: the output, the decisions, the failing command.
Cost of waiting: what is blocked.
Default if unanswered: the option that changes nothing.
```

Never escalate implementation choices inside the spec, naming that follows the glossary, test structure or refactors inside the write set: those go in the decisions list. Conflicting acceptance criteria go back to the spec's author with status `impossible`, not up the escalation route.

## New work

New work you find (a defect outside your write set, a missing helper another crate should own, a gate that looks wrong) becomes its own issue before you report, so it is not lost or built here:

```sh
gh issue list --state open --search "<key words> in:title"
gh issue create --title "<what is wrong or missing, one line>" --body-file target/proposed-<slug>.md
```

Search first and comment on an existing issue instead of filing a duplicate. The body states what you saw and where (`path:line`, a quoted span of at most three lines), the evidence (command and exit code), the kind and squad you think it belongs to, and "Found while working #<n>". Add no labels and no acceptance criteria: a lead or the product lead specifies it, and the agent that writes an issue's acceptance criteria never implements it. Put the new number in your report's `Next`.
