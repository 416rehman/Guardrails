# Compact handoff report

Keep the final message brief and factual (never claim a command result you did not run):

```markdown
Status: done | partial | blocked | impossible   (evaluators: pass | fail | cannot-evaluate)
Issue: #<n>   Branch: <branch>   Commit: <sha>   Round: <1|2>
Provider: <anthropic|google|openai>   Model: <exact-model-id>   # required for evaluators

Summary: 1 to 2 concise sentences on what changed and current state.
Changed paths: path1, path2
Checks: `<cmd>` (exit <code>); `<ci-note>`
Decisions: `file:line` brief choice where spec was silent (none if none)
Findings: `<blocker|major> file:line claim + proof` (evaluators only; omit if none)
Revert: git revert <sha>
Next: one line next action (or new issue #<id> if filed).
```

If escalating (`team/01`), add at most 5 lines (`Question`, `Options`, `Evidence`, `Cost`, `Default`). Put suspected D-62 security details only in this private message, never on GitHub.
