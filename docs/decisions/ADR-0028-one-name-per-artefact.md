# ADR-0028: One name and one path per artefact, as `team/06` section 2.2 lists them

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: section 5, P17
- Requires: nothing
- RFC: not required: no spine change; the table binds the team and design documents
- Work items: [WI-0005]

## Context
The design and team documents named different paths and forms for the same things: the spine path, the RFC directory, the risk-tier file, the protected-path list, the merge-queue branch, bot identities, CLI exit codes and others. Agents follow whichever document they read last.

## Decision
`docs/team/06` section 2.2 is the single table of names. Among its rulings: the spine is `docs/design/00-decisions.md`; RFCs live in `rfcs/`; status records live in `docs/agents/status/`; a work item's id is its issue number; the risk-tier file is `.agents/risk-tiers.toml`; the protected-path list is `.agents/kit/protected-paths.toml`; the queue merges into `main`; the writer metadata block is `meta.v1`; lint ids are `ARCH-NNN`; CLI exit codes follow `design/23` section 11. Another document that disagrees conforms at its next edit. A change to the table is a protected-change item of the chief architect.

## Enforced by
`cargo xtask kit check` path references: a path named in `AGENTS.md`, `CLAUDE.md` or a kit file that does not exist fails. Review only for the design documents: leads cite section 2.2 when they review a specification, and `garden-docs` files a `status:proposed` issue for each variant it finds.

## Consequences
An agent that finds two names uses the table and files the other as a defect. The table grows when a new collision is found.

## Alternatives rejected
- Editing every document now: `docs/design/` and `docs/team/` are protected and the seed session does not change them.
- Letting each document keep its names: two words for one thing is the defect P17 names.

## Revisit when
`schema/vocabulary.toml` and the registries of [WI-0041] exist; names of product objects then move there and this table keeps repository artefacts only.
