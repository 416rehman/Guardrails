# ADR-0026: Captured vendor pages never enter a repository

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-02
- Requires: nothing
- RFC: not required: local to repository contents
- Work items: [WI-0004]

## Context
The research behind the plan captured vendor documentation pages into `research/_sources/`. They are third-party copyrighted text. The research briefs written from them are ours and are imported under `docs/references/research/`.

## Decision
No path containing `_sources/` is committed to this repository or any other project repository, in the tree or in history. Briefs cite their sources by URL. Agents fetch a vendor page when they need it (skill `grdr-vendor-research`) and never store it in the repository.

## Enforced by
An entry in `supply-chain/do-not-read.toml`; a path check in `verify` that fails on any tracked path containing `_sources/`; the pre-push public gate, which checks the whole history of the seed.

## Consequences
A brief must stand on its own summary and its links. A source that disappears from the web is lost to us.

## Alternatives rejected
- Committing the captures under a separate licence notice: we hold no right to redistribute them.
- A private repository for the captures: a second place for agents to read copyrighted text from.

## Revisit when
A vendor publishes its documentation under a licence on our allow-list; that vendor's pages may then be vendored under `third_party/` with provenance.
