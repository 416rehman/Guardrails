# Pins

This directory is the plugin marketplace of team/03 section 9, the one place agent sessions in this repository load plugins from. `.claude-plugin/marketplace.json` lists every plugin and skill collection of team/03 section 5 and every de-slop skill the research adopts. Each git entry is pinned by full commit, and every entry is enabled in `.agents/kit/marketplace.toml` (owner instruction 2).

## How sessions load it

- `.claude/settings.json` names this directory as a `directory` marketplace at `./.agents/marketplace`. Claude Code resolves that path against the main checkout, so every clone works with no machine-specific path and every worktree loads the same catalogue. Until `kit render` writes the entry, `kit install` writes the catalogue's absolute path into the untracked `.claude/settings.local.json`.
- A vendored plugin (`./plugins/<name>`) loads in place from this directory. Claude Code clones a git entry into its plugin cache and checks out its `sha`, whatever `ref` names by then.
- Claude Code fetches a plugin with a git source only when local, user or managed settings enable it, so `kit install` enables each git entry in `.claude/settings.local.json`. It also turns off there any user-scope plugin that loads under the same name as an entry here, such as the owner's `cleanup@claude-mods`, because Claude Code registers one copy's hooks per name and both copies would carry a commit gate.
- `kit install` compares each installed plugin's recorded commit with its pin and prints every mismatch with the commands that fix it (team/03 section 9 rule 2).

## Changing an entry

- An addition, pin move or removal is a protected change (owner instruction 7): its own issue, implemented by `lead-agent-kit` under `GRDR_SCOPE=protected`, and landed after `eval-security` and one evaluator on the other model pass.
- The owner waived the file-by-file read for the pins below only. A new entry or a moved pin is read in full first (team/03 section 9 rule 3).
- A pin moves no earlier than three days after its upstream commit, or seven for a new major version. A security fix moves at once, after `eval-security` has read the diff (owner instruction 22).
- Nothing that calls another vendor's model enters. CC-BY-SA content is installed unmodified from upstream and never copied into this repository.
- The catalogue entry, its row below and, for a vendored plugin, its `PROVENANCE.md` change in the same commit. The catalogue check fails when an entry is not enabled, a git source has no full commit, a vendored plugin has no provenance, or this file does not record an entry with its commit.

## Entries

| Entry | Upstream and path | Commit | Licence | How it entered |
|---|---|---|---|---|
| `pr-review-toolkit` | `anthropics/claude-plugins-official`, `plugins/pr-review-toolkit` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `code-simplifier` | `anthropics/claude-plugins-official`, `plugins/code-simplifier` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `security-guidance` | `anthropics/claude-plugins-official`, `plugins/security-guidance` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `security-scan` | `anthropics/claude-plugins-official`, `plugins/claude-security` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `hookify` | `anthropics/claude-plugins-official`, `plugins/hookify` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `md-management` | `anthropics/claude-plugins-official`, `plugins/claude-md-management` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `rust-analyzer-lsp` | `anthropics/claude-plugins-official`, `plugins/rust-analyzer-lsp` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `typescript-lsp` | `anthropics/claude-plugins-official`, `plugins/typescript-lsp` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `frontend-design` | `anthropics/claude-plugins-official`, `plugins/frontend-design` | `43fd1f9db0941b2b83cb62268e35970d4a67c202` | Apache-2.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `mutation-testing` | `trailofbits/skills`, `plugins/mutation-testing` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `property-based-testing` | `trailofbits/skills`, `plugins/property-based-testing` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `rust-review` | `trailofbits/skills`, `plugins/rust-review` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `differential-review` | `trailofbits/skills`, `plugins/differential-review` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `regression-hunt` | `trailofbits/skills`, `plugins/regression-hunt` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `patching-bugs` | `trailofbits/skills`, `plugins/patching-bugs` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `insecure-defaults` | `trailofbits/skills`, `plugins/insecure-defaults` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `sharp-edges` | `trailofbits/skills`, `plugins/sharp-edges` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `spec-to-code-compliance` | `trailofbits/skills`, `plugins/spec-to-code-compliance` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `fp-check` | `trailofbits/skills`, `plugins/fp-check/skills`: `fp-check` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `supply-chain-risk-auditor` | `trailofbits/skills`, `plugins/supply-chain-risk-auditor` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `agentic-actions-auditor` | `trailofbits/skills`, `plugins/agentic-actions-auditor` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `writing-lean-proofs` | `trailofbits/skills`, `plugins/writing-lean-proofs` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC-BY-SA-4.0 | Enabled by owner instruction, 2026-11-11; not read file by file |
| `superpowers` | `obra/superpowers` v7.0.2, `skills/`: `test-driven-development`, `systematic-debugging`, `verification-before-completion` | `22f0b463e7a5e579904dd6211a520321035526f7` | MIT | Enabled by owner instruction, 2026-11-11; not read file by file |
| `dzhng-skills` | `dzhng/skills`, `skills/review/`: `find-state-machines`, `audit-tests`, `audit-decisions`, `find-overengineering`, `ratchet-files` | `873aba8d6331976f92052f54513076abd1ae629f` | MIT | Enabled by owner instruction, 2026-11-11; not read file by file |
| `cleanup` | `416rehman/claude-mods`, `cleanup/` | `489dd5a409814c9db337a4d53bce440aba75d21f` | None stated (the owner's own; team/03 proposes Apache-2.0) | Enabled by owner instruction, 2026-11-11; the hook and its gate read in full, the skill not read file by file |
| `ce-simplify-code` | `EveryInc/compound-engineering-plugin` v3.37.1, `skills/ce-simplify-code/`, vendored at `plugins/ce-simplify-code` | `dd9b7921c9c80498eba84994ff1b8e1e81dbc1db` | MIT | Enabled by owner instruction, 2026-11-11; vendored with edits, every copied file read (`PROVENANCE.md`) |
| `thermo-nuclear-code-quality-review` | `cursor/plugins`, `cursor-team-kit/skills/thermo-nuclear-code-quality-review/` | `5866df557357d005b3c0c9d3da0d9e739b4bdde3` | MIT | Enabled by owner instruction, 2026-11-11; not read file by file |
| `unslop` | `cursor/plugins`, `pstack/skills/unslop/SKILL.md`, vendored at `plugins/unslop` | `5866df557357d005b3c0c9d3da0d9e739b4bdde3` | MIT | Enabled by owner instruction, 2026-11-11; vendored with edits, read in full (`PROVENANCE.md`) |
| `semgrep` | `semgrep/mcp-marketplace`, `plugin/` | `5e0bb47111d96081e06194bad0fb7dc0caa52563` | No licence file at the pin | Enabled by owner instruction, 2026-11-11; not read file by file |
| `modern-web-guidance` | `GoogleChrome/modern-web-guidance` v1.0.0, repository root | `4dd968349e54ca45a05dd5c818fb035c9054b022` | Apache-2.0 for code; CC-BY-4.0 for the guides | Enabled by owner instructions 2 and 18, 2026-11-11; not read file by file |

Every pin is the newest stable commit or release on 2026-11-11 (owner instruction 22), except `modern-web-guidance`, which owner instruction 18 fixes at its v1.0.0 release commit.

## Notes on the pins

- **Official plugins.** The nine plugin directories at `43fd1f9db094` are identical, tree for tree, to the plan's `dceb15d50832`, and `frontend-design` to its `f8c5e7a1dcb7`. Each has a `version` in its `plugin.json`, so Claude Code keeps its cached copy until that string changes, and a moved pin can leave an old copy behind; `kit install`'s pin check reports it. Claude Code refuses a third-party entry name that starts with `claude-`, so `claude-security` and `claude-md-management` are listed as `security-scan` and `md-management`; their skills and agents keep the upstream names, which `[plugins.namespaces]` records. `security-guidance` has hooks only. Its pattern-based warnings on edits run; `ENABLE_CODE_SECURITY_REVIEW=0` in the settings `env` switches off its model reviews at stop, commit and push, and with them the unpinned Agent SDK install its `SessionStart` hook would make with pip (owner instruction 8). The plugins' agents name `opus`, `sonnet` or `inherit`.
- **Trail of Bits.** `e4dd0bb5b155` is still the newest commit. Only the thirteen plugins team/03 names are entries, never the collection of 47. The `fp-check` entry points at `plugins/fp-check/skills` and lists its one skill, so the plugin's `Stop` and `SubagentStop` prompt hooks do not load (owner instruction 8: no prompt hooks), and neither do its three analysis agents, which no roster agent could start, since none has the Agent tool. The `agents/openai.yaml` files are interface metadata for another harness; no plugin listed here calls another vendor's model.
- **superpowers.** The entry points at `skills/` and lists the three skills, so the plugin's `SessionStart` hook and its other skills do not load. The plan's "v7.0.2 (`bb92a777`)" mixed two releases: `bb92a777` is v7.0.0, and v7.0.2 is `22f0b463`.
- **dzhng/skills.** The five skills moved from `skills/engineering/` to `skills/review/` on 2026-11-10, so the newest commit is pinned with the new path. `ratchet-files` ships a script that installs git hooks; the kit's own ratchet is `quality/file-size.toml`.
- **cleanup.** `489dd5a` is the newest commit. Its gate denies a commit message of more than one line or with an AI credit, which is the commit form owner instruction 27 makes ours, so every valid one-line Conventional Commit subject passes it. The repository is public and states no licence.
- **thermo-nuclear-code-quality-review.** The skill file is unchanged since `6e3d2ea56d7d` and sets `disable-model-invocation: true`. The agent that runs it as a shadow seat in the `review` workflow is ours (research section 1.1).
- **semgrep.** Guardian 2.10.45, the newest `develop` commit. It needs a Semgrep account, which no agent creates (owner instruction 23), so it scans nothing until someone signs in, while its hooks still run on every write, shell command and stop. Signed in, it sends each file an agent writes to Semgrep's scanner. It runs precompiled hook binaries and replaces them at session start unless `SEMGREP_GUARDIAN_AUTO_UPDATE=0`, which would leave this pin behind; `DISABLE_TELEMETRY=1` turns its telemetry off.
- **modern-web-guidance.** The only licence file at the pin is `LICENSE` (Apache-2.0). The README licenses the guides under `skills/modern-web-guidance/guides/` as CC BY 4.0 and says parts derive from MDN Web Docs and W3C, WHATWG and IETF specifications. The plugin carries the `chrome-extensions` skill too. Its `modern-web-guidance` skill tells an agent to run `npx -y modern-web-guidance@latest`, the CLI that owner instruction 18 rules out; the 209 guides it would fetch are files inside the installed plugin.

## Attribution

- "Modern Web Guidance" by Google Chrome, from `GoogleChrome/modern-web-guidance` at `4dd968349e54ca45a05dd5c818fb035c9054b022`. Guides under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/), code under Apache-2.0. Installed unmodified.
- "Trail of Bits Skills" by Trail of Bits, from `trailofbits/skills` at `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff`, under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/). Installed unmodified; nothing is copied into this repository.
- `ce-simplify-code` by Every and `unslop` by Lauren Tan, under MIT. Each copy keeps its upstream `LICENSE` and lists its changes in `PROVENANCE.md`.

## Not marketplace entries

- Claude Code 2.1.322, the harness (team/06 section 12). This machine runs 2.1.319.
- `microsoft/playwright-mcp` v0.0.85, tag commit `4e0794dd0a0176519830a5ed27b491137cf9338f`, Apache-2.0. An MCP server configured directly in implementer and evaluator sessions as `playwright`, so its tools stay `mcp__playwright__*`, started with pnpm (owner instruction 24).
- `github/gh-aw`, a GitHub CLI extension for the public routines, pinned where those workflows run.
- Our own MCP server (D-38), which waits for a signed release.
- Cross-model review, a rule about models with nothing to install.
- The `ai-tells` Vale styles, vendored under `third_party/vale/` for `verify` (research section 1.1).
- The ideas `grdr-structure` restates in its own words from Cursor's `deslop`, the Karpathy guidelines and dzhng's `find-overengineering`.

## Kept out

- Anything that calls another vendor's model: the Codex plugins, Trail of Bits' `second-opinion`, the pstack plugin, whose subagents run on Grok, and the Compound Engineering plugin as a whole, whose `ce-optimize` runs `codex exec`. From those collections only the skills above enter.
- dzhng's `refactor-clean`, which team/03 gives as an example: the research rejects it, because it deletes compatibility paths that a hand-off must decide.
- The rest of the research's rejected list (section 1.4) and team/03 section 5's "Not installed" list.
