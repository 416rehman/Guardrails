# ADR-0009: Normalisers return resolved, unresolved or malformed, and each has a differential fuzz target

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-10; `design/02` SD-04
- Requires: nothing
- RFC: not required: restates D-10 as repository mechanism
- Work items: [WI-0019]; the `verify` rule is a work item still to be filed

## Context
A normaliser that guesses is a bypass. The shell canonicaliser, the path resolver and the protocol parsers each stand between untrusted input and a verdict, and each has a real consumer that decides what the input means (briefs 09, 21, 32; reviews c2, c5, l06).

## Decision
Every normaliser returns `resolved`, `unresolved` or `malformed`. Malformed denies. Unresolved is the fact `exec.opaque`: at a boundary the OS judges the concrete action, and at request level an opaque command in a fail-closed class steps up. An unrecognised harness version never denies; its adapter drops that agent to Watch. Each normaliser has a reference model and a differential fuzz target against its real consumer: the shell under exec tracing, kernel path resolution, the agent's own parser, Cedar's Lean model.

## Enforced by
`verify` fails a crate marked as a parser in `[package.metadata.grdr]` that has no fuzz target. ClusterFuzzLite runs every target in CI (`fuzz.yml`). [WI-0019] delivers the first normaliser with its oracle.

## Consequences
No normaliser returns a best guess. Writing one costs a reference model and a fuzz target before it can land.

## Alternatives rejected
- Two results, parsed or error: it forces opaque input to be either allowed or denied outright.
- Unit tests as the oracle: they encode the author's reading, not the consumer's.

## Revisit when
S-14 finds more than 2% of benign commands opaque.
