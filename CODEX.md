# CODEX.md

OpenAI Codex and ChatGPT sessions read `AGENTS.md` automatically at repository start and use this overlay
for provider-specific execution rules.

## Codex and ChatGPT specifics
- Model routing and lean review (ADR-0043): read `.agents/models.toml` (`[providers.openai]`) and
  `.claude/risk-tiers.toml`:
  - `architect` and `high` (`eval-security`, complex `trust-core`): `gpt-5.4`.
  - `standard` and `fast` (`eval-review`, normal implementation): `gpt-5.4-mini`.
  - Evaluators (`0 / 1 / 2` by tier, CI-first, max 2 rounds): skip for green docs/tests (`low`), run
    `eval-review` alone for `medium`, and run `eval-review` + `eval-security` on 2 distinct models or
    providers for `tier:high` / `trust-core` (`Provider:` and `Model:` in every verdict, D-63).
- Skills and roles: read `.claude/agents/<role>.md` for role duties and `.claude/skills/<name>/SKILL.md`
  for procedures (`grdr-work-issue`, `grdr-build`, `grdr-start-item`, `grdr-structure`, `grdr-verify`,
  `grdr-handoff`, `grdr-evaluate`, `cleanup`).
- Gates and hooks (run directly before pushing or opening/merging a PR, since Codex CLI does not fire
  `.claude/settings.json` or `.agents/hooks.json` automatically):
  - Set `GH_REPO=416rehman/Guardrails`, `GH_PROMPT_DISABLED=1`, and `CARGO_TERM_COLOR=never`.
  - Run `node .claude/hooks/branch-check.mjs` before and after `gh pr create` / `gh pr merge`.
  - Run `node .claude/hooks/docs-check.mjs --ci` (or verify `Docs:` and `[release_note]` rules) before
    creating or editing a pull request.
  - Run `node --test .claude/hooks/branch-check.test.mjs .claude/hooks/ci-stop.test.mjs .agents/hooks/agy-pre-tool-use.test.mjs`
    when changing agent-kit files.
- Worktrees, branches and commits:
  - Work in a dedicated git worktree (such as `.agent/worktrees/wt-<n>`) on `issue/<n>-<slug>`.
  - Every non-exempt PR must target an issue (`Refs #<n>` / `Closes #<n>`), include the issue name in both
    its branch slug and its PR title or `Issue: #<n> <title>` header, and be the sole open PR for `#<n>`.
  - Commit with `git commit -m '<subject>'`: one Conventional Commit line (<= 72 characters), no body, no
    trailers, no AI credit line.
