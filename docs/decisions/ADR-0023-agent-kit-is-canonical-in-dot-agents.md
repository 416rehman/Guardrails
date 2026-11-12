# ADR-0023: The agent kit is canonical in `.agents/`, and `.claude/` is rendered

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-47, D-61, P14
- Requires: nothing
- RFC: not required: restates D-47 and D-61 as repository mechanism
- Work items: [WI-0005]

## Context
The kit is part of the open project and must survive a change of harness (D-61; spine section 9, "automation is bound to one account"). Hand-edited harness configuration drifts from the roster and cannot be reviewed as data.

## Decision
Roles, hooks, gates, lanes, routines, skills, permissions and the plugin marketplace live as data under `.agents/`. `cargo xtask kit render` generates `.claude/` from it, and nobody edits `.claude/`. Everything specific to Claude Code stays in `CLAUDE.md` and the rendered tree; `AGENTS.md` is the map every harness reads. One agent, the chief architect, is bound to `fable`; the model names and ids live only in `.agents/models.toml`.

## Enforced by
`cargo xtask kit check` (gate V21): the rendered tree is byte-identical to a fresh render and valid against the pinned Claude Code settings schema; a second agent bound to `fable` is refused; a `chief-architect` definition without the ownership sentence fails; a path `AGENTS.md` names that does not exist fails. Gate V22 holds the model rule. `.agents/**` and `.claude/**` are protected, trust-core paths.

## Consequences
Another harness is a second renderer over the same data. A kit change is a protected-change item for `lead-agent-kit`.

## Alternatives rejected
- `.claude/` as the source: it binds the project to one harness.
- Roles written into `xtask` code: P14 forbids behaviour that data can carry.

## Revisit when
A second harness is adopted; its renderer and `kit check` rules are added then.
