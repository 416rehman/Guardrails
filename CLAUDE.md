# CLAUDE.md

@AGENTS.md

## Claude Code specifics
- Claude Code 2.1.319 or later (the fleet image moves to 2.1.322 once V18 and `kit check`
  pass on it). `onFailure: "block"` exists only on command and HTTP hooks and has no
  effect on Stop, SubagentStop, TaskCompleted, TeammateIdle or async hooks, so a crashed
  gate hook fails open and CI re-runs every gate.
- `.claude/` is rendered from `.agents/` (roster, templates, skills and kit data) by
  `cargo xtask kit render`. Edit the source in a kit work item; CI fails on any drift.
- Hooks run `.agent/kit/bin/xtask`, which `cargo xtask kit install` builds from the
  merge-base with `origin/main`, so your edits cannot change the hooks that judge them.
  Run it once per clone; without the binary every file and shell tool is blocked.
- Start an agent session with `cargo xtask kit launch` (`--item <n>` for issue #n). It sets
  `GRDR_AGENT` and `GRDR_WORK_ITEM`, writes the snapshot `.agent/state/item-<n>.json` from
  the issue and passes the agent's model and turn cap. Never start `claude --agent` by hand.
- The model gate (UserPromptSubmit and PreModelSwitch hooks) stops a session whose model
  is not the one `.agents/models.toml` binds to its agent. Sessions here default to
  `claude-sonnet-5-5`; only `chief-architect` may run on Fable.
- Hooks are early feedback, not enforcement. Edits made through Bash bypass Edit and
  Write matchers; the read-only mounts and the CI `protected-paths` job (WI-0006) are the
  boundary. Until they land `verify` gate V05 rejects any diff that touches a protected
  path outside a protected-change lease, and on native Windows, which has no sandbox,
  hooks and permission rules are all there is.
- After each edit `post-edit` runs the structure checks S1 to S7, and on interface paths the
  interface checks UX1 to UX8. When it blocks, load the skill its message names
  (`grdr-structure`, or `ui-architect` then `grdr-interface`) and change the design; never
  silence the finding. The first edit of a path in `.agents/kit/path-skills.toml` adds that
  path's skills, in order, to your context.
- Commit with `git commit -m '<subject>'`: one `-m`, one line, no newline, no `-F`, `--file`
  or `--template`. The project settings leave `attribution.commit` and `attribution.pr`
  empty, so Claude Code adds no co-author line; `guard-command` and gate V24 refuse anything
  but one Conventional Commit line.
- The Stop hook runs `cargo xtask verify --fast`. After three blocks it lets the turn end;
  hand off with the failing output instead of retrying.
- GitHub only through `gh` (`GH_REPO` is set); there is no GitHub MCP server. Per role,
  `guard-command` allows only that role's `gh` calls: an implementer comments and files
  `status:proposed` issues, and never edits an issue body or a `status:`, `tier:` or
  `priority:` label.
- Use subagents for search, review and refutation. Never two subagents editing the
  same files.
- Before compaction the PreCompact hook writes `.agent/state/<session>.md`; after a
  compaction, re-read it and your issue before acting.
- Sessions run on the owner's Claude subscription. A usage limit can end a session at any
  point; the dispatcher resumes it after the window resets and counts no attempt. A limit
  is never a reason to skip a check.
- Skills to load by name: `grdr-start-item`, `grdr-structure`, `grdr-verify`,
  `grdr-handoff`, `grdr-fix-bug`, `grdr-write-spec`, `grdr-scaffold-crate`,
  `grdr-threat-model-change`, `grdr-audit`, `grdr-vendor-research` (unclear requirements),
  `ui-architect` then `grdr-interface` (anything a person or an agent reads),
  `grdr-evaluate` (evaluator sessions only), and `cleanup` before every commit.
- MCP servers: only those in project settings (Playwright once `web/` exists). Do not
  add any. Modern Web Guidance comes as the pinned plugin, never through
  `npx modern-web-guidance`; `DISABLE_TELEMETRY=1` is set for every session.
- No auto memory: code, decisions and evidence live in the repository and work items in
  issues. No Claude Code scheduled tasks for project work; `cargo xtask dispatch` runs the
  recurring agents in `.agents/kit/usage.toml`.
