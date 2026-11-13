# ADR-0020: Stability classes live in `surfaces.toml`, and every surface is experimental until one external embed pilot completes

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-60, D-71
- Requires: an embedding partner, before any surface becomes stable
- RFC: not required: restates D-60 as repository mechanism
- Work items: the `cargo public-api` and `cargo semver-checks` gate is a work item still to be filed; its first inputs come from [WI-0016]

## Context
Embedders build against our crates, wire packages and C ABI. A promise of stability made before anyone outside has embedded the engine is a promise about an untested interface (brief 27; reviews l08, c6).

## Decision
Every public surface (public crate, protobuf package, C ABI, pack format, Cedar schema, CLI `--json`) has a class in `surfaces.toml`: experimental, beta or stable. Stable means additive-only within a major with 12 months of overlap. Nothing is stable before one external embed pilot completes. A change that breaks a declared contract range fails unless it bumps that contract's major and adds the overlap its class requires.

## Enforced by
`cargo public-api` and `cargo semver-checks` against the class in `surfaces.toml`; `buf breaking` for wire packages; the C header diff for the ABI (D-71). `surfaces.toml` is a protected, trust-core path.

## Consequences
Until an embed pilot completes, we may break any surface with a major bump and no overlap. After it, a break costs a parallel version for 12 months.

## Alternatives rejected
- Declaring 1.0 surfaces stable at the first release: no outside consumer would have tested them.
- Stability per crate version alone: wire and ABI contracts cross crates.

## Revisit when
The first external embed pilot completes.
