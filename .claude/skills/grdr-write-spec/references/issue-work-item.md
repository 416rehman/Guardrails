# A work item as a GitHub issue

Sources: owner instructions 5 and 6 (`docs/design/_review/04-owner-kit-instructions.md`), team/01 sections 3 and 4, team/02 section 1.5. The form is `.github/ISSUE_TEMPLATE/work-item.yml` and the labels are `.github/labels.toml`; where those files and this one differ, the files win and this one is wrong.

## The body

The work-item form renders each field as a `### <label>` heading. A body written with `gh issue create --body-file target/proposed-<slug>.md` uses the same headings in the same order, so the orchestrating session and the evaluators find every section:

~~~markdown
### Kind
bug

### Squad
core

### Agent
impl-rust

### Size
S

### Write set
crates/grdr-core/src/analyze/shell/**
crates/grdr-core/tests/shell_*.rs

### Spec
Spine: D-10. Design: docs/design/12 section 9. Requires: #131.
#### Problem
...
#### Behaviour
R1 ...

### Plan
- [ ] 1. Failing test for a quoted here-doc body (crates/grdr-core/tests/shell_heredoc.rs) - verify: `cargo nextest run -p grdr-core shell_heredoc`

### Acceptance criteria
```json
{"schema": "grdr.agents.acceptance.v1", "item": 142, "criteria": [
  {"id": "AC-1",
   "check": "cargo nextest run -p grdr-core shell_heredoc::unresolved_body",
   "expect": "exit 0; the case returns Unresolved, not Malformed",
   "oracle": "bash under exec tracing (D-10)"}
]}
```

### Risk tier
high (fail_mode_change: malformed denies, D-10)

### Trust core
no
~~~

- **Spec**: team/06 section 6.2 from Problem to Open questions, with `####` subheadings so they stay inside the section. A spec too long for the body goes in a sub-issue (`gh issue create --parent <n>`), and the parent's spec section links it.
- **Plan**: the squad lead's tasks of minutes, each with exact paths and a verifying command. The lead ticks them at the compound step; implementers cannot edit the body, so their progress is in commits and reports.
- **Acceptance criteria**: the JSON block of team/06 section 6.4, one entry per criterion with `id`, `check` (the command), `expect` (the exact observable result) and `oracle` (independent of the code under test). It always stays in the parent's own section, because that is what the evaluators judge against. Held-out scenarios go to the held-out evaluator, never here.

## Labels

- There are no status labels. An issue is open until the merged pull request with `Closes #<n>` closes it; work in progress shows as the branch `issue/<n>` and its pull request.
- Fields: `squad:<id>`, `kind:<kind>`, `size:<class>`, `tier:low|medium|high`, `agent:<name>`, `trust-core`, and `priority:p0` to `priority:p3` from the programme manager.
- No milestones and no date labels.

Who moves what (team/01 section 4): leads, the product lead and the programme manager create and edit issues, sub-issues, dependencies and labels; the chief architect creates, edits and comments on issues; the orchestrating session opens, merges and so closes; implementers, evaluators, gardeners and auditors comment and create new issues. Every agent shares one GitHub login, so these are roles each agent keeps, not permissions GitHub enforces.

An edit to the acceptance section after work started is called out on the issue and in the pull request, and evaluators judge against the section as it stood when the implementer started. An edit by the item's implementer is a blocker finding.
