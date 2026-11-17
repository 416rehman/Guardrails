# Guardrails ADR

Guardrails ADR is an open-source agent detection and response (ADR) platform, published by
Loonaro under Apache-2.0. It finds the AI agents running on a company's machines, including ones
nobody registered, works out which actions were the agent's, applies policy before an action
completes, protects credentials and data, and detects and stops misbehaviour. It runs on Windows,
macOS and Linux, from one laptop to ten million endpoints, and inside networks with no route to
the internet. The code namespace is `grdr`.

Nothing is released yet. The repository holds the plan and the agent team that builds the
product.

## The plan

- `docs/PLAN.md` is the entry point: the product on one page and a map of the documents.
- `docs/design/00-decisions.md` holds the binding decisions; every other file in `docs/design/`
  expands one part of it.
- `docs/team/` describes how the agent team works: operating model, roster, skills, audits,
  quality gates and the repository bootstrap.

## The agent environment

The product is built by a team of Claude Code agents, defined as plain subagents in
`.claude/agents/` with project skills in `.claude/skills/`. There is no separate harness: open
Claude Code in this folder and say "work issue #42" or "work the next issue". The session follows
skill `grdr-work-issue`. It reads the issue, has the squad's lead write a missing spec, spawns the
implementer in its own worktree, runs the evaluators the issue's risk tier calls for, sends their
findings back for at most three rounds, then opens the pull request and squash-merges it once CI
passes. Independent issues can be worked in parallel subagents. "Build the product", or `/loop` with
skill `grdr-build`, repeats this over the issues in the build order until the plan is done.

To start, install Rust with rustup (`rustup toolchain install` reads `rust-toolchain.toml`), the
GitHub CLI logged in with `gh auth login`, and Claude Code logged in to the subscription that runs
the agents. The gates are plain tools: `cargo fmt --all -- --check`,
`cargo clippy --workspace --locked --all-targets -- -D warnings`, `cargo test --workspace --locked`
and `cargo deny check`, which CI runs with the security scans in `.github/workflows/`.

`AGENTS.md` and `CLAUDE.md` are the map every agent session reads. `CONTRIBUTING.md` explains how
people contribute alongside the agents, and `SECURITY.md` how to report a vulnerability.
