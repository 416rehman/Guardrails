# Guardrails ADR

Guardrails ADR is an open-source agent detection and response (ADR) platform, published by
Loonaro under Apache-2.0. It finds the AI agents running on a company's machines, including ones
nobody registered, works out which actions were the agent's, applies policy before an action
completes, protects credentials and data, and detects and stops misbehaviour. It runs on Windows,
macOS and Linux, from one laptop to ten million endpoints, and inside networks with no route to
the internet. The code namespace is `grdr`.

Nothing is released yet. The repository holds the plan and the agent environment that builds the
product.

## The plan

- `docs/PLAN.md` is the entry point: the product on one page and a map of the documents.
- `docs/design/00-decisions.md` holds the binding decisions; every other file in `docs/design/`
  expands one part of it.
- `docs/team/` describes how the agent team works: operating model, roster, skills and hooks,
  audits, quality gates and the repository bootstrap.

## The agent environment

The product is built by a team of Claude Code agents. Work items are issues in this repository,
and `cargo xtask verify` is the one gate for agents, people and CI. To start:

1. Install Rust with rustup (`rustup toolchain install` reads `rust-toolchain.toml`), the GitHub
   CLI logged in with `gh auth login`, and Claude Code logged in to the subscription that runs the
   agents.
2. Run `claude` once in the repository folder and accept the workspace trust dialog. In print
   mode Claude Code ignores the project's permission rules in a folder it does not trust, so
   `cargo xtask kit launch` and `cargo xtask dispatch` check the trust first and stop with this
   instruction until the dialog is accepted.
3. `cargo xtask kit install` builds the kit binary the hooks run, from the merge base with
   `origin/main`, so a change cannot alter the hooks that judge it. `cargo xtask github check`
   confirms the login, the repository and its settings.
4. `cargo xtask labels sync` creates the labels of `.github/labels.toml` on the repository, which
   the seed session needs before it files its first issue.
5. `cargo xtask kit launch <agent> --item <n>` starts one agent on issue `#<n>` with the model and
   turn cap its role gets. The first session is the chief architect's seed session,
   `cargo xtask kit launch chief-architect --seed` (`docs/team/06-repository-bootstrap.md`
   section 14).
6. `cargo xtask dispatch` runs the loop: it leases ready issues to implementers, runs the
   evaluators and the recurring agents, and pauses on a usage limit without failing an item.

`AGENTS.md` and `CLAUDE.md` are the map every agent session reads. `CONTRIBUTING.md` explains how
people contribute alongside the agents, and `SECURITY.md` how to report a vulnerability.
