# ADR-0042: Multi-provider agent kit and issue-named branches and pull requests

- Status: accepted
- Date: 2026-11-23
- Decided by: owner
- Spine: D-47, D-61, D-63, P14, P17; section 9 ("automation is bound to one account")
- Requires: nothing
- RFC: not required: an owner instruction amending ADR-0029 and triggering its revisit clause ("the owner adopts a second agent tool")
- Work items: #2005

## Context
ADR-0029 kept the agent kit bound to Claude Code alone (`.claude/settings.json`, Claude-only model names, and a Claude-only `PreToolUse` hook), while leaving "automation is bound to one account" as an explicit risk in spine section 9 and stating "Or the owner adopts a second agent tool" as ADR-0029's revisit trigger. In addition, the branch rule of #1875 (`issue/<n>`) did not carry the issue name in the branch or pull request, and `PreToolUse` hooks did not check branch/PR linkage locally before push or `gh pr create`.

## Decision
1. **Multi-provider agent kit (Claude, Gemini, Codex/ChatGPT).**
   - `.claude/agents/*.md` and `.claude/skills/` remain the single source of role definitions and procedures with zero duplication.
   - `.agents/models.toml` is the single data source (P14, P17) for model selection across `[providers.anthropic]`, `[providers.google]`, and `[providers.openai]`.
   - `GEMINI.md`, `.agents/skills.json`, and `.agents/hooks.json` (running `.agents/hooks/agy-pre-tool-use.mjs` over `.claude/hooks/docs-check.mjs`) configure Antigravity / Gemini sessions with parity to `.claude/settings.json`.
   - `CODEX.md` overlays `AGENTS.md` for OpenAI Codex / ChatGPT sessions.
   - Cross-model review (`D-63`, `distinct_models = 2`) may be satisfied across different providers (Claude, Gemini, Codex/ChatGPT) or across distinct model tiers within one provider; every evaluator verdict states `Provider:` and `Model:`.
2. **Issue-named branches and strict 1:1 issue-PR linkage.**
   - Every non-exempt work branch is named `issue/<n>-<slug>`, where `<n>` is the issue number and `<slug>` is a 3-to-60-character lowercase ASCII kebab-case slug of the issue title.
   - Every non-exempt pull request must target an open issue (`Refs #<n>` or `Closes #<n>`), include the issue name in its branch slug and in the pull request (`Issue: #<n> <title>` or matching title), and be the single open pull request for that issue.
   - Pre-existing open branches created before this rule (`legacy_pre_slug_branches` in `.claude/hooks/branch-rules.json`) are grandfathered only until they merge or close.

## Enforced by
`.claude/hooks/docs-check.mjs`, `.agents/hooks/agy-pre-tool-use.mjs`, `.claude/hooks/branch-check.mjs`, `.github/workflows/branch-check.yml` (on `schedule`, `workflow_dispatch`, and `pull_request`), and `.github/workflows/docs.yml`.

## Consequences
Sessions on Claude Code, Gemini / Antigravity, and Codex / ChatGPT share the same roles, skills, hooks, and gates without duplicating prompts or diverging on rules. Every new branch and pull request carries a readable issue name and links strictly one-to-one with its GitHub issue.

## Alternatives rejected
- Maintain separate agent and skill directories per provider: rejected under P17 because duplicated instructions drift.
- Allow unlinked or generic branches (`issue/<n>` without slug): rejected because concurrent work across issues becomes opaque in PR lists and worktrees.

## Revisit when
A fourth agent harness or provider is added, or all grandfathered entries in `legacy_pre_slug_branches` have closed so that list can be removed.
