# ADR-0029: The team is plain Claude Code subagents and skills, with no custom harness

- Status: accepted
- Date: 2026-11-17
- Decided by: owner
- Spine: D-45, D-47, D-61, D-63, D-64, P14, P17; sections 4, 7, 8, 9 and 10
- Requires: nothing
- RFC: not required: an owner instruction, like owner instructions 7 and 27 before it, amending D-47, D-61 and D-63
- Work items: the slice epics (labels `epic`, `slice:0` to `slice:10`)

## Context
The team was to run on a custom harness: a dispatcher process that leased work items to headless sessions, a merge queue that landed every change, lease, hand-off and ready records on issues, `status:` labels with fixed transitions, `cargo xtask kit` commands that rendered `.claude/` from `.agents/`, 30 hooks, a fleet container for agents, and the `xtask` crate with `cargo xtask verify` and its gates. By 2026-11-17 it was 293 files and about 21,000 lines, built and repaired before any product code existed, and most of it repeated what Claude Code already does: subagents, worktree isolation, permission rules, a sandbox and skills. Every fault in it stopped all work at once.

## Decision
The owner removed the harness on 2026-11-17. The team is the agents in `.claude/agents/` and the skills in `.claude/skills/`, both edited by hand. The owner's Claude Code session orchestrates them:

- Skill `grdr-work-issue` works one issue: a lead writes a missing spec, one implementer writes the change in its own worktree on `issue/<n>`, the evaluators the issue's tier calls for judge it in clean contexts for at most three rounds, and the session opens the pull request with `Closes #<n>` and squash-merges it with one Conventional Commit line once CI is green.
- Skill `grdr-build` repeats that, slice by slice. The product is built in end-to-end slices: epic issues labelled `epic` and `slice:N` (0 to 10), each with a scenario that must work on Windows, macOS and Linux through every layer it names. Slice 0 is a walking skeleton through every layer. A slice closes when `eval-acceptance` drives its scenario on all three systems.
- Work items live only in GitHub issues. Their state is open or closed, their labels (`priority:`, `tier:`, `squad:`, `kind:`, `size:`, `agent:`, `slice:N`, `epic`), their "blocked by" links, and the `issue/<n>` branch and pull request. There are no status labels, leases, hand-off, ready or lease records, or attempts. Agents return their reports to the session (skill `grdr-handoff`).
- The gates are plain commands: `cargo fmt --all -- --check`, `cargo clippy --workspace --locked --all-targets -- -D warnings`, `cargo test --workspace --locked` and `cargo deny check`, run by each implementer (skill `grdr-verify`) and by CI in `verify.yml`, which decides. CI also runs the security scans and the `docs` job; `.claude/hooks/docs-check.mjs` is the one hook. A planned gate joins `verify.yml` as a plain command in the work item that builds it (`team/05`).
- An issue's `tier:` label and `.claude/risk-tiers.toml` pick its evaluators; `eval-tier` may raise the tier, and nothing lowers it. There are no review lanes and no classifier. Trust-core changes still need two passing evaluators on different models.
- Protected paths are held by the permission rules and sandbox in `.claude/settings.json` and by the evaluators' check of each diff against its issue's write set.
- There is no fleet container. Once a signed release exists, the owner's machine runs it in front of the agents.
- Product tools once placed under `xtask` (the architecture lint, the interface generator, the distribution build, the docs and release-notes generators, the fleet herd simulator, the name check) keep their requirements and are built by their own work items as ordinary crates or scripts. No `xtask` crate returns.

## Enforced by
The skills `grdr-work-issue` and `grdr-build`; `.claude/settings.json`; `.github/workflows/verify.yml`, `scan.yml` and `docs.yml`. Review only: `eval-docs` and `garden-docs` treat a document that tells an agent to build or run the removed machinery as stale.

## Consequences
The team needs no tooling of its own before product work starts, and anyone with Claude Code can run it from the repository. Landing now rests on the session following its skill rather than on software that refuses, and the checks the harness made mechanically (commit form V24, protected-path diff V05, acceptance digest Q01, the hook checks) are review until a CI job takes each over. Work moves only while a session runs, under `/loop` or by hand.

This record supersedes ADR-0013, ADR-0014, ADR-0016, ADR-0023 and ADR-0027; in part ADR-0015 (lanes and classifier), ADR-0017 (`cargo xtask verify` as the gate), ADR-0024 (status labels, records, leases, attempts, agent branches) and ADR-0028 (the kit's paths); and the `verify`, `kit check` and other `xtask` checks named under "Enforced by" in ADR-0001, ADR-0002, ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0009, ADR-0010, ADR-0018, ADR-0019, ADR-0022, ADR-0025 and ADR-0026, which now mean the CI job or review that keeps the same rule. The spine is amended to match.

## Alternatives rejected
- Keep the dispatcher and merge queue: tooling the size of a product component, built before the product, that duplicated Claude Code.
- GitHub's native merge queue: it needs approvals from a person or an App (ADR-0016).
- Keep `.agents/` as the source of the kit and render `.claude/` from it: a renderer kept for a second agent tool that never came (ADR-0023's revisit trigger).
- Build layer by layer from the schemas up: nothing works end to end until late, and cross-layer defects surface last.

## Revisit when
A defect lands that one of the former mechanical checks would have stopped; that check then becomes a CI job, not a harness. Or the owner adopts a second agent tool.
