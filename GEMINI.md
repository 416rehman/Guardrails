# GEMINI.md

@[AGENTS.md](AGENTS.md)

## Gemini and Antigravity specifics
- "Fix issue #n", "work issue #n" or "work the next issue": follow `.claude/skills/grdr-work-issue/SKILL.md`.
  This session is the orchestrator and runs agents from `.claude/agents/*.md` via `define_subagent` and
  `invoke_subagent`; it does not write product code itself unless directed. Independent issues with disjoint
  write sets run in parallel subagents.
- "Build the product" or "keep building": follow `.claude/skills/grdr-build/SKILL.md`, one iteration at a
  time, with all state on GitHub.
- Customizations and hooks:
  - `.agents/skills.json` mounts all skills from `.claude/skills/` directly (no duplicate skill files).
  - `.agents/hooks.json` runs `.agents/hooks/agy-pre-tool-use.mjs` on `PreToolUse` (`run_command`),
    enforcing the shared `.claude/hooks/docs-check.mjs` rules: no direct push to `main`, branches named
    `issue/<n>-<slug>`, every non-exempt PR targeting an issue with the issue name in branch and PR, one
    open PR per issue, `Docs:` line when code changes, and `[release_note]` when closing an issue.
- Model routing and lean review (ADR-0043): read `.agents/models.toml` (`[providers.google]`) and
  `.claude/risk-tiers.toml`:
  - `architect` (`chief-architect`): `Gemini 4 Neon` (`pro`).
  - `high` (`eval-security`, complex `trust-core`): `Gemini 4 Neon` (`pro`).
  - `standard` (normal implementation, `eval-review`): `Gemini 4 Carbon` (`inherit`); `fast`: `flash`.
  - Evaluators (`0 / 1 / 2` by tier, CI-first, max 2 rounds): skip for green docs/tests (`low`), spawn
    `eval-review` alone for `medium`, and spawn `eval-review` + `eval-security` on 2 distinct models or
    providers for `tier:high` / `trust-core` (`Provider:` and `Model:` in every verdict, D-63).
- Worktrees and environment:
  - Isolate each subagent writer or evaluator in its own git worktree under `.agent/worktrees/` (gitignored),
    never sharing a mutable working tree across concurrent writers and never editing `.claude/worktrees/`.
  - `run_command` runs each call in a fresh shell, so set `$env:GH_REPO = "416rehman/Guardrails"`,
    `$env:GH_PROMPT_DISABLED = "1"`, and `$env:CARGO_TERM_COLOR = "never"` in `gh` and `cargo` commands.
- Branches, commits and PRs:
  - Branch name: `issue/<n>-<slug>` (lowercase ASCII kebab-case from the issue title, 3 to 60 characters).
  - Commit with `git commit -m '<subject>'`: one `-m`, one Conventional Commit line (<= 72 characters), no
    body, no trailers, no AI credit line. Run `cleanup` on the staged diff before committing.
- Skills to load by name (`read_file` on `.claude/skills/<name>/SKILL.md`): `grdr-work-issue`, `grdr-build`,
  `grdr-start-item`, `grdr-structure`, `grdr-verify`, `grdr-handoff`, `grdr-fix-bug`, `grdr-write-spec`,
  `grdr-scaffold-crate`, `grdr-threat-model-change`, `grdr-audit`, `grdr-vendor-research`, `ui-architect`
  then `grdr-interface`, `grdr-evaluate` (evaluators only), and `cleanup`.
- No auto memory outside the repository and GitHub issues.
