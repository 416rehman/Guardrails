# 03. Skills, plugins and settings for the agent team

_Status: draft 6. Specifies D-47 for the tooling layer. Owning squad: `agent-kit` (SQ-17); everything under `.claude/` and `.github/` is gate configuration and trust core under D-63. Read with: [`00-decisions.md`](../design/00-decisions.md) (the spine, authoritative); [`_review/02-owner-answers.md`](../design/_review/02-owner-answers.md) (zero budget, the Claude subscription); [`_review/03-models-and-orchestration.md`](../design/_review/03-models-and-orchestration.md) (the model rule); [`_review/04-owner-kit-instructions.md`](../design/_review/04-owner-kit-instructions.md) (the owner's kit instructions, which override this document where they differ); `team/01` (how an issue is worked); `team/02` (agent names, the report); `team/04` (audit library); `team/05` (gates); `team/06` (paths and names)._

## Summary

The team uses plain Claude Code: subagents in `.claude/agents/`, skills in `.claude/skills/`, and the project settings in `.claude/settings.json`. There is no custom binary, no rendering step and no plugin catalogue in the repository.

1. **Three layers, each with one job.** Skills tell an agent how to do a task. The project settings and the sandbox limit what a session can run, read and reach. CI decides: it runs the gates and the security scans on every pull request, so nothing depends on an agent following a skill.
2. **The session is the orchestrator.** Skill `grdr-work-issue` turns "fix issue #n" into a lead, an implementer and evaluators spawned with the Agent tool (`team/01` section 1). Fan-out work (audits, the persona council, broad reviews) is the same: the session spawns subagents in parallel.
3. **The owner's installed skills each get a lane** (section 2), and project skills are prefixed `grdr-` so they never collide with the owner's or built-in skills (section 3).
4. **Plugins are the owner's user-scope installs.** The project enables none; agents use what the owner has installed (`cleanup`, `frontend-design` and the like). A third-party skill or plugin enters the project only by the rules of section 5.
5. **One Claude subscription and one GitHub login run the team** (owner instruction 23). Work is measured in share of the subscription's usage windows, not dollars.

## 1. Project settings

`.claude/settings.json` is edited by hand and judged like any other gate configuration (high tier, `squad:agent-kit`). Its keys:

| Key | Value |
|---|---|
| `attribution` | `commit` and `pr` empty, so Claude Code adds no co-author line (owner instruction 27) |
| `env` | `CARGO_TERM_COLOR=never`, `DISABLE_TELEMETRY=1`, `GH_REPO` (the repository issues live in), `GH_PROMPT_DISABLED`, `GH_NO_UPDATE_NOTIFIER`, the subagent concurrency cap, and `ANTHROPIC_DEFAULT_HAIKU_MODEL` set to the Sonnet id, so anything that names `haiku` runs on Sonnet |
| `model`, `availableModels` | `claude-sonnet-5-5` by default; the three ids of the model rule |
| `permissions.allow` | Build, test, lint, format and `cargo deny` commands, git reads and branch commands, `git add`, `git commit -m`, `git push`, the `gh issue`, `gh pr` and `gh run` calls agents make, the read-only contract, licence and mutation checks, `pnpm install --frozen-lockfile`, `mcp__playwright__*`, one `WebFetch(domain:...)` rule per research domain, and `WebSearch`. Agents run with `permissionMode: dontAsk`, so a command outside this list is refused, not asked |
| `permissions.ask` | `cargo add`, `cargo install`, `pnpm add` |
| `permissions.deny` | `Edit` of gate configuration and other protected paths (security, supply chain, lint and deny configuration, the Cargo workspace files, `.github/`, golden files and snapshots, governance files, `.claude/settings.json`); reads of credential and user settings files; force push, `reset --hard`, `--no-verify`, signed-off commits, the `gh release` writes, publishing, snapshot acceptance, and gh account, secret, repository and label administration |
| `hooks` | One PreToolUse hook on Bash and PowerShell, `.claude/hooks/docs-check.mjs`: a dependency-free Node script that holds `gh pr create` and `gh pr merge` until the design/34 docs rules a script can check pass (docs change with code or the body says `Docs: unchanged because <reason>`, the `[release_note]` block, page front matter, no third-party requests or `curl \| sh` on the site). It lets the command through on its own errors |
| `sandbox` | Enabled, no unsandboxed commands, credential directories unreadable, network to the crate, npm, GitHub and buf registries |
| `autoMemoryEnabled`, `disableAutoMode`, `disableBypassPermissionsMode` | `false`, `disable`, `disable` |

A deny rule blocks the file tools, not a shell redirect, so it is early feedback; evaluators and CI judge the diff regardless. An issue whose write set names a denied path is worked by `lead-agent-kit` or the chief architect, and the owner lifts the rule for that change.

## 2. The owner's installed skills

Each installed skill has one lane. Agent names are `team/02`'s.

| Skill | Source | When it runs | Who invokes it |
|---|---|---|---|
| `cleanup:cleanup` | Owner's own plugin (`416rehman/claude-mods`, subdirectory `cleanup`), user scope; its commit gate denies `git commit` until the skill signs off the staged diff, and denies a multi-line message or an AI credit line | Before every commit | Implementers, `lead-agent-kit`, `garden-deslop` |
| `simplify` | Built into Claude Code | The owner's own sessions only | The owner. Agents do not run it: `cleanup` applies its checks |
| `code-review` | Built in | Inside `eval-diff`'s review | `eval-diff`, in a clean context |
| `security-review` | Built in | Trust-core paths, parsers, IPC, pack verification, the shim, CI or agent files; every high-tier change | `eval-security` |
| `autopilot`, `auto-dev-via-github-issues` | Owner's own skills | Only when the owner runs a loop, under `docs/AUTOPILOT.md`, which takes item choice through "work the next issue" of `grdr-work-issue` and keeps one writer per issue | The owner |
| `ui-architect` | Owner's own skill | Before the first UI decision on any interface path (`web/`, `site/`, `interface/`, `desktop/`, the CLI, tray and approval programs, installers, translations), and always before `grdr-interface` (the owner's global rule, which also binds subagents) | `impl-web`, `impl-docs`, `eval-ux`, `eval-a11y`, `lead-interfaces`, the persona seats that review screens |
| `frontend-design` | `claude-plugins-official`, user scope, Apache-2.0 | After `ui-architect`, for new screens (owner instruction 18); output composes Astryx components through `@grdr/ui` and `@grdr/kit` and uses the DTCG tokens (D-42, owner instruction 21) | `impl-web` |
| `write-like-a-normal-staff-senior-developer` | Account skill | Any prose written into the repository: docs, ADRs, RFCs, pull request bodies, commit subjects, skill files | Every agent |
| `skill-creator` | Account skill (Anthropic) | Creating or changing any project skill, with its trigger evals | `impl-docs`, `lead-agent-kit` |

`cleanup`'s gate and the repository's commit form agree: one Conventional Commit line, no body, no trailer, no credit line (owner instruction 27). `ui-architect` includes pricing, paywall and conversion rules; the product has no paywall (P11), D-44 experience rules and the D-51 disclosure floor win wherever the manual differs, and approval surfaces follow D-31 (OS-native, no persuasion patterns).

## 3. Project skills

Format: one directory per skill under `.claude/skills/`, frontmatter `name`, `description` (the trigger), `license: Apache-2.0` and `metadata` (`version`, `owner`). Each skill stays under 200 lines; long references go in `references/` beside it. Each ships trigger evals in `evals/triggers.json` (ten prompts that should load it, ten that should not), made with `skill-creator`.

| Name | What it is for |
|---|---|
| `grdr-work-issue` | The orchestration: "fix, work or implement issue #n" and "work the next issue". The session reads the issue, spawns a lead for a missing spec, the implementer in a worktree and the evaluators by tier in parallel, runs at most three rounds, opens the pull request with `Closes #<n>`, waits for CI and squash-merges |
| `grdr-build` | "Build the product", "keep building", and `/loop`: one iteration reads GitHub, picks the next workable issue by priority and the build order it holds, runs `grdr-work-issue` on it (up to three independent issues in parallel), has a lead break the next design area into issues when nothing is workable, and stops when the plan is covered or something fails |
| `grdr-start-item` | How an implementer begins: the branch `issue/<n>`, what to read in which order, the write set, the baseline gates, search before writing, failing test first |
| `grdr-verify` | The gates: `cargo fmt --all -- --check`, `cargo clippy --workspace --locked --all-targets -- -D warnings`, `cargo test --workspace --locked`, `cargo deny check`; reading the output; never editing a gate to pass it; the `impossible` route |
| `grdr-handoff` | How every agent finishes: status, definition of done, the one-line commit, the push, the report returned to the session (`references/format.md`), escalation, new work as issues |
| `grdr-evaluate` | How an evaluator judges a change: clean context on the branch, instructions from `main`, expectations before each action, driving the artefact, proofs re-run, structure, findings with proof, three rounds, the verdict |
| `grdr-structure` | The owner's seven rules for code (owner instructions 4, 9, 15 and 26): structures before implementations; files of at most 500 code lines, split by responsibility; no implicit state machines; comments only for a reason the code cannot show; fix the core problem; readable code; find the mechanism first (P14). Checks S1 to S7 and their fixes, and which data source holds each kind of value |
| `grdr-interface` | The cohesion rules of P17 and D-69 for anything a person or an agent reads: registries first, Astryx through `@grdr/ui`, language tokens, `present()`, one `ViewState`, `useAction`, route ids; checks UX1 to UX8 |
| `grdr-vendor-research` | Owner instruction 14: the research briefs, then the vendors' current public documentation, then the horizon sweep over standards, conferences, papers and new projects; one comment separating what ships, what standards converge on and what is novel |
| `grdr-fix-bug` | Reproduce first; three-arm proof (fails on the parent, passes with the change, fails on revert); regression hunt through callers |
| `grdr-remove-code` | A survival test that fails while the target remains; no guard instead of a delete (29% of passing patches do this, h09); callers updated |
| `grdr-write-spec` | The spec, plan and acceptance sections of a work-item issue, decision records and RFCs; acceptance criteria with a named oracle; the mechanism the feature extends (P14); the RFC route |
| `grdr-scaffold-crate` | A new crate: `[package.metadata.grdr]`, workspace lints, error register entry, `limits.toml` entries, test layout, the split rule |
| `grdr-add-agent-adapter` | The steps of design/03 "Add an agent adapter"; tested version range; canary proof that the product's control point fired (D-49) |
| `grdr-author-detection` | Session rule versus Sigma detection (D-09); attack fixture and benign corpus; starts in Watch |
| `grdr-author-policy` | Pack anatomy; semantic diff; widening needs an approver; Essentials entry rule (D-53) |
| `grdr-add-integration` | Manifest first; golden files; destination is configuration (P7); two first-party members per family (D-40) |
| `grdr-add-port-adapter` | `grdr-ports-testkit`; crash points; tenant context; contrib versus profile adapter (P6) |
| `grdr-threat-model-change` | Map the change onto `design/02` adversaries and assets; trust boundaries; new security requirement ids; tests for each control |
| `grdr-matrix-run` | Testing on an operating system, architecture or kernel you are not on, through CI's hosted runners; a cell that needs hardware nobody has reports `requires hardware` |
| `grdr-audit` | Run one power prompt of `team/04`: the preamble, the find pass, the refuting verifier in a clean context, issues for upheld results |
| `grdr-cut-release` | Release gates of `team/05` section 16; release-please, keyless signing, SBOM and VEX (owner instructions 3, 7 and 23) |

**Skills by path.** Before editing a path, an agent loads the skills it needs, in this order:

| Paths | Skills, in order |
|---|---|
| `web/**`, `site/**` | `ui-architect`, `frontend-design:frontend-design`, `grdr-interface` |
| `interface/**`, `desktop/**`, `programs/grdr/**`, `programs/grdr-tray/**`, `programs/grdr-approve/**`, `platform/*/installer/**`, `interface/strings/tr/**`, `docs/i18n/**` | `ui-architect`, `grdr-interface` |
| `crates/**`, `programs/**`, `**/*.rs`, `**/*.ts`, `**/*.tsx` | `grdr-structure`, `cleanup:cleanup` |
| `docs/**` | `write-like-a-normal-staff-senior-developer` |

## 4. MCP servers

| Server | Use |
|---|---|
| `microsoft/playwright-mcp` | The only MCP server configured for implementers and evaluators; evaluators drive the local console with it once `grdr console serve` exists (D-42, D-43) |
| Our own MCP server (D-38) | Read-only for evaluators and content gardeners, once a signed release of it exists |

No GitHub MCP server: GitHub only through `gh`. No fetch-anything documentation server (an injection route into agents with write access); dependency docs are vendored as `docs/references/*-llms.txt`.

## 5. Adding third-party skills, plugins and MCP servers

1. **Pinned by commit.** A third-party skill or plugin the project depends on names its source and full commit SHA in the issue that adds it; a user-scope install is the owner's choice and is not a project dependency.
2. **Every file is read before it enters.** Skills, plugin scripts, MCP launch commands and assets, read in full by `eval-security` in a clean context. Reject precompiled binaries without reproducible source, archives that skills read instructions from, and files padded past what a reviewer reads (h09 section 2). Scanner verdicts are a signal, never approval.
3. **Licence allow-list.** OSI permissive licences may be vendored with a provenance file. CC-BY-SA skills are installed unmodified and never copied into the repository. GPL tools are development tools only. Custom or source-available licences stay out.
4. **Cooldown.** Three days from the upstream release before a pin moves, seven for a new major version; a security fix moves at once, after `eval-security` has read the diff (owner instruction 22).
5. **Least power.** A plugin that runs its own commands on Claude Code events or brings an MCP server is reviewed at high tier. Prefer one skill from a collection over the whole collection.
6. **No other vendor's model.** Any plugin or skill that calls another vendor's model stays out: the model rule allows none (`design/_review/03`).

## How this is kept current

`lead-agent-kit` re-reads this document when a skill is added or removed, when `.claude/settings.json` changes, and on a Claude Code version that changes the sub-agent, skill or settings fields this document relies on.

## Risks and open questions

| Item | Risk or question | Settled by |
|---|---|---|
| An agent skips a skill | A skill is guidance; an agent can ignore it | Evaluators check the diff against the same rules; CI runs the gates |
| Deny rules cover the file tools only | An agent can write a denied path through the shell | Evaluators flag any change outside the write set as a blocker; CI judges the diff |
| Owner skills' provenance | `cleanup`, `autopilot`, `ui-architect`, `auto-dev-via-github-issues` and `write-like-a-normal-staff-senior-developer` have no stated licence; the open kit cannot carry them until they do | Owner question 7 in the spine (licence them, or keep them private and optional) |
| `autopilot` drift | The skill says it never stops by itself; it may ignore the overlay | `grdr-work-issue` lands only through evaluators and CI |
| Plugins on the owner's machine | A user-scope plugin runs in every session the owner starts here | The owner's choice; nothing in the repository depends on one beyond `cleanup` and `frontend-design` |
| Power-prompt value | The one controlled pilot found the bare state-machine prompt weaker than "find the bugs" (h09 verification) | `team/04` retires prompts that lose to the control |

## Deviations from the spine and objections

No objections. Two readings, recorded so they can be overruled:

1. **D-47 says third-party skills come only from a marketplace pinned by commit.** The owner removed the repository's plugin catalogue; built-in skills ship inside Claude Code and are pinned through its version, and a project dependency on a third-party skill follows section 5.
2. **D-47 says one `verify` command gates every change.** The gates are now the plain commands of `grdr-verify`, run by every implementer and by CI.

## Sources

Research briefs (verification sections preferred): `research/32-agentdev-quality.md`, `research/31-agentdev-operating-model.md`, `research/h09-agentdev-practice-sweep.md`, `research/15-coding-agent-surfaces.md`. Review notes: `design/_review/c9-delivery-team.md`, `design/_review/00-resolution.md`. Design documents: 02, 03, 07, 12. Team documents 01, 02, 04, 05, 06.

Claude Code pages: https://code.claude.com/docs/en/sub-agents, https://code.claude.com/docs/en/settings, https://code.claude.com/docs/en/permissions, https://code.claude.com/docs/en/sandboxing.
