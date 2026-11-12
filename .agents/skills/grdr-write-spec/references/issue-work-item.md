# A work item as a GitHub issue

Sources: owner instructions 5 and 6 (`docs/design/_review/04-owner-kit-instructions.md`), team/01 sections 3 and 4, team/02 section 1.5. The form is `.github/ISSUE_TEMPLATE/work-item.yml` and the labels are `.github/labels.toml`; where those files and this one differ, the files win and this one is wrong.

## The body

The work-item form renders each field as a `### <label>` heading. A body written with `gh issue create --body-file` (a quoted here-document on `-`, or a draft at `.agent/state/proposed-<slug>.md`) uses the same headings in the same order, so the dispatcher, the hooks and the evaluators find every section:

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
- **Plan**: the squad lead's tasks of minutes, each with exact paths and a verifying command. The lead ticks them at the compound step; implementers cannot edit the body, so their progress is in commits and hand-offs.
- **Acceptance criteria**: the JSON block of team/06 section 6.4, one entry per criterion with `id`, `check` (the command), `expect` (the exact observable result) and `oracle` (independent of the code under test). It always stays in the parent's own section, because that is what the digest covers. Held-out scenarios go to the held-out evaluator, never here.

## Labels

- Exactly one `status:` label at a time: `status:proposed`, `status:ready`, `status:leased`, `status:in-review`, `status:blocked` (with a `blocked:` reason label), `status:escalated`. Done means the issue is closed by the merged pull request.
- Fields: `squad:<id>`, `kind:<kind>`, `size:<class>`, `tier:low|medium|high`, `agent:<name>`, `trust-core`, and `priority:p0` to `priority:p3` from the programme manager.
- No milestones and no date labels.

Who moves what (team/01 section 4): leads, the product lead and the programme manager create and edit issues, sub-issues, dependencies and labels, and post `ready.v1`; the chief architect creates, edits and comments on issues; the dispatcher and the merge queue swap `status:` labels, assign and post lease and state comments; implementers, evaluators, gardeners and auditors comment and create `status:proposed` issues. `guard-command` enforces this on `gh` calls, because every agent shares one GitHub login until the Apps exist.

## The acceptance digest

The digest is the lowercase hex SHA-256 of the acceptance-criteria section: the text after the `### Acceptance criteria` line and before the next line that starts with `### `, or the end of the body, with CRLF turned into LF and leading and trailing newlines removed, encoded as UTF-8.

```sh
gh issue view <n> --json body -q .body | python -c "import sys,re,hashlib; b=sys.stdin.buffer.read().decode('utf-8').replace('\r\n','\n'); m=re.search(r'^### Acceptance criteria\n(.*?)(?=^### |\Z)', b, re.M|re.S); print(hashlib.sha256(m.group(1).strip('\n').encode('utf-8')).hexdigest() if m else 'no acceptance section')"
```

The dispatcher (WI-0011), `kit launch`, gate Q01 `acceptance-digest` and the evaluators compute the same digest. `cargo xtask kit ready <n>` computes and posts it for the readying agent; anyone else checking a digest uses this command.

## The `ready.v1` and `lease.v1` comments

The agent that readies the item posts, after the body is final:

~~~markdown
Ready: acceptance criteria sha256 `<hex>`, readied by lead-core.

<details><summary>ready.v1</summary>

```json
{"schema": "ready.v1", "item": 142, "by": "lead-core", "acceptance_sha256": "<hex>", "write_set_sha256": "<hex>"}
```

</details>
~~~

`by` is the roster name of the readying agent. It must not be the agent named in the `agent:` label. `write_set_sha256` is the SHA-256 of the write set's globs, one per line, as `kit ready` reads them from the section. Then swap `status:proposed` for `status:ready`.

The dispatcher's lease comment carries `{"schema": "lease.v1", "item": 142, "attempt": 1, "agent": "impl-rust", "model": "claude-opus-5-5", "acceptance_sha256": "<hex>", "branch": "agent/142/a1"}`, and evaluators judge against that snapshot of the criteria. An edit to the section after readying drops the item back to `status:proposed` for a lead to ready again, and so does an edit of the write set before the lease; after the lease, gate Q01 fails it and a protected-change lease widens nothing. An edit by the item's implementer is a tamper finding.
