# ADR-0003: The technical namespace is `grdr` and every name comes from one brand manifest

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-66, P14
- Requires: the recorded registry and trademark search, before the first release
- RFC: not required: no spine, public-crate, wire or schema change
- Work items: [WI-0003]; the D-66 search is a work item still to be filed

## Context
The owner named the product Guardrails ADR, published by Loonaro (owner instruction 25). The command `guardrails` belongs to another project and `grd` is taken on the package registries, so identifiers use `grdr`. A self-hosted, white-label or OEM build must change every name and host without a code change (D-41 L6).

## Decision
Identifiers use `grdr`: CLI `grdr`, binaries `grdr-*`, crates `grdr-`, protobuf packages `grdr.*`, Cedar namespace `Grdr`, environment prefix `GRDR_`. No wire or ABI identifier contains the company name. The product name, short name, domain, repository identity and every address and host live in `brand/brand.toml` and nowhere else. Agents run the package-registry and trademark search D-66 asks for and attach its result to the record that supersedes this one; if the search fails `grdr`, that record names the replacement before the first release.

## Enforced by
ARCH-009 fails a brand string or company name outside `brand/`. Structure check S7 reports a hard-coded product or vendor name. `brand/**` is a protected path.

## Consequences
A rename is a manifest change plus generated output. Until the search is recorded, the namespace is provisional and no release is cut.

## Alternatives rejected
- `guardrails` or `grd` as the namespace: both are taken.
- The company name in identifiers: it would survive a foundation transfer (D-03) and an OEM rebuild.

## Revisit when
The recorded search finds a conflict for `grdr` in a registry or trademark class the product uses.
