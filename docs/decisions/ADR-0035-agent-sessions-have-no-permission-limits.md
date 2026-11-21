# ADR-0035: Agent sessions have no permission limits; review and CI protect the gate paths

- Status: accepted
- Date: 2026-11-21
- Decided by: owner
- Spine: D-47, D-61, D-63
- Requires: nothing
- RFC: not required: an owner instruction, like owner instructions 7 and 27 and ADR-0029 before it, amending D-47 and D-63
- Work items: #1782

## Context
ADR-0029 held the protected paths with the permission rules and sandbox of `.claude/settings.json` and with the evaluators' check of each diff against its issue's write set. A deny rule refuses every session, the one implementer a protected change names included, so that implementer handed its change to the owner to apply. #1550 and the proposed ADR-0030 (#1669) designed a hook that would grant gate paths per issue to get around this.

The owner, on 2026-11-21: development is agent-driven with no person in the loop, and no agent-level permission limit may stop an agent or ask a person. CI, the evaluators, the docs-check hook and review stay.

## Decision
- Agent sessions run with no permission limits. In `.claude/settings.json`, `permissions.deny` is empty, `permissions.ask` and `permissions.disableBypassPermissionsMode` are gone, `permissions.defaultMode` is `bypassPermissions` and `sandbox.enabled` is `false`. No agent file sets `permissionMode`, so every subagent runs in the session's mode.
- Claude Code does not start a session in `bypassPermissions` from project settings, so the owner starts the orchestrating session with `claude --permission-mode bypassPermissions` (`CLAUDE.md`). The project value records the intended mode.
- The repository ships no `PermissionRequest` hook. The owner's own sessions answer permission requests from their local, gitignored settings, so a request that would still ask in bypass mode does not reach a person. A contributor's clone keeps the mode its user chose: a hook in a checked-in file would strip the prompts from everyone who clones this public repository. This is the answer to eval-security finding F3 on #1782.
- Gate paths are protected by the gates only. A protected change is still its own issue whose write set names the path, worked by `lead-agent-kit` or the chief architect and landed after `eval-security` and an evaluator on the other model pass (D-63). Every evaluator checks the diff against the issue's write set and fails a write outside it; CI judges the diff (`verify.yml`, `docs.yml`, and the write-set job of #1668 once it lands, which takes its checker and the protected-path list from the base commit and fails a change outside the closed issue's write set); the docs-check hook holds `gh pr create` and `gh pr merge`.
- The single list of protected paths is the protected-path list of `team/06` section 2.1, a fenced block of globs that the evaluators and #1668 read. No other file lists them.
- The rules agents follow (stay inside the write set, read no secrets, escalate a new dependency, leave signing and releases alone) are process rules in `AGENTS.md` and the skills, checked by review. No session refuses or asks on their behalf.
- The allow list, `env`, the hooks (the PreToolUse docs-check hook) and the model stay unchanged. In `bypassPermissions` the allow list neither refuses nor asks; its `WebFetch` entries remain the research domain list that `grdr-vendor-research` follows.
- No agent file sets `maxTurns`, so no agent stops at a turn limit; an agent reports `partial` when its context or usage window is nearly spent.
- Front-matter `tools` and `disallowedTools` stay. They define a role, such as an evaluator that does not write, and are not a permission limit.

## Enforced by
`.claude/settings.json` and the agent files in `.claude/agents/`. Review only: `eval-security` and an evaluator on the other model read every change to `.claude/settings.json` (high tier, trust core), and `eval-docs` and `garden-docs` treat text that says a session permission protects a path as stale.

## Consequences
The implementer a protected change names writes its write set directly, with no hand-off to the owner. The grant mechanism of #1550 (#1763 to #1767) and ADR-0030 are not needed, and #2 no longer waits for them. #1668 stays: it is re-specified with its own write-set parser and the protected-path list of `team/06` section 2.1, both read from the base commit, and #1550 is removed from its blockers before #1550 closes.

Residual risk, in general terms (D-62): nothing on the agent's side refuses or asks before an agent acts. An action that ends up in a diff is caught after the fact, by the evaluators and CI, before it merges. An action that leaves no diff (a command run, a read, a call to an outside service) is caught by nothing in the repository; only the process rules of `AGENTS.md` and the skills speak to it, and review sees only what an agent reports. That changes reach `main` only through a pull request that CI and the evaluators judge is today a process rule the orchestrating session follows, not a repository gate: `main` has no branch rule until #1719 makes it one. Agent hosts hold no signing key, and once a signed release exists the owner's machine runs it in front of the agents (D-47). Running sessions in an isolated environment is the owner's choice and is not a gate.

Two design controls no longer hold as written: SD-06 (`design/02` section 3.10) and SP-26 (`design/35`, #1493), which rest on session limits. #1493, #1494, #1719, #1786 (the orchestrating session checks its checkout against `origin/main`) and #1787 (releases, tags and publishing behind a repository gate) are the remaining gates, and #1783 brings the design text in line.

## Supersedes and amends
- Amends D-47: protected paths are held by review and CI, not by the permission rules and sandbox of `.claude/settings.json`; each agent's tools, not its permissions, are set in its agent file.
- Amends D-63: the rule that no agent changes a protected path inside an ordinary issue is held by review and CI, not by a session permission.
- Supersedes in part ADR-0029: its bullet that the permission rules and sandbox hold the protected paths, and its sentence that the docs-check hook is the one hook. The same reading applies to the notes in ADR-0001, ADR-0002 and ADR-0028 that call the protected paths the deny rules of `.claude/settings.json`.
- Supersedes ADR-0030 (#1669) before it was accepted.

## Alternatives rejected
- Grant gate paths per issue with a hook (#1550, ADR-0030): a second hook and a grant store, built to lift a limit the owner has removed.
- Keep deny rules for the paths no agent ever writes: still a session limit that can stop an agent, for a rule review and CI already hold.
- Keep the sandbox for its network limits: it stops an agent mid-task, and the owner's instruction removes it.

## Revisit when
A defect or incident lands that a session refusal would have stopped. The fix is a CI job or a review rule first, as ADR-0029 says for its former checks.
