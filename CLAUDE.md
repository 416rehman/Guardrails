# CLAUDE.md

@AGENTS.md

## Claude Code specifics
- "Fix issue #n", "work issue #n" or "work the next issue": follow skill `grdr-work-issue`.
  This session is the orchestrator and spawns the team in `.claude/agents` with the Agent
  tool; it does not write the change itself. Independent issues can run in parallel
  subagents, one per issue.
- "Build the product", "keep building" or `/loop`: follow skill `grdr-build`, one iteration
  at a time, with all state on GitHub.
- Docs change with the code: follow "Docs (design/34)" in AGENTS.md. The PreToolUse hook
  `.claude/hooks/docs-check.mjs` holds `gh pr create` and `gh pr merge` until its checks pass.
- `.claude/agents/*.md` and `.claude/skills/` are the source of truth; edit them by hand.
- Agent sessions have no permission limits (ADR-0035). Start the orchestrating session with
  `claude --permission-mode bypassPermissions`: Claude Code ignores that mode in project
  settings, and subagents run in the session's mode. The repository ships no
  `PermissionRequest` hook; the owner's sessions answer requests from their gitignored local
  settings, and a clone keeps the mode its user chose.
- Implementers and evaluators run with `isolation: "worktree"` on `issue/<n>-<slug>`. Read
  `.agents/models.toml` (`[providers.anthropic]`) and `.claude/risk-tiers.toml` (ADR-0043): spawn 0
  evaluators for green docs/test-only PRs, `eval-review` alone (`standard`/`fast`) for medium changes,
  and `eval-review` + `eval-security` on 2 distinct models/providers for `tier:high` or `trust-core`
  (CI-first verification, max 2 rounds). Only `chief-architect` uses the `architect` tier.
- Commit with `git commit -m '<subject>'`: one `-m`, one line. The project settings leave
  `attribution.commit` and `attribution.pr` empty, so Claude Code adds no co-author line.
  Run `cleanup` on the staged diff before each commit.
- GitHub only through `gh` (`GH_REPO` is set); there is no GitHub MCP server.
- Use subagents for search, review and refutation. Never two subagents editing the
  same files.
- Sessions run on the owner's Claude subscription. A usage limit can end a session at any
  point; a limit is never a reason to skip a check.
- Skills to load by name: `grdr-work-issue`, `grdr-build`, `grdr-start-item`, `grdr-structure`,
  `grdr-verify`, `grdr-handoff`, `grdr-fix-bug`, `grdr-write-spec`, `grdr-scaffold-crate`,
  `grdr-threat-model-change`, `grdr-audit`, `grdr-vendor-research` (unclear requirements),
  `ui-architect` then `grdr-interface` (anything a person or an agent reads),
  `grdr-evaluate` (evaluators only), and `cleanup` before every commit.
- MCP servers: only those in project settings (Playwright once `web/` exists). Do not
  add any. `DISABLE_TELEMETRY=1` is set for every session.
- No auto memory: code, decisions and evidence live in the repository and work items in
  issues.
