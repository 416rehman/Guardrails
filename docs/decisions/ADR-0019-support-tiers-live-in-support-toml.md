# ADR-0019: Support tiers live in `support.toml` and generate the release-blocking jobs

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-50, D-71
- Requires: nothing
- RFC: not required: restates D-50 as repository mechanism
- Work items: [WI-0013]; the generated-matrix check is a work item still to be filed

## Context
"Supported" meant different things in different design documents (reviews l10, l12). A tier written in prose is not what CI runs.

## Decision
Every agent adapter, host target, control point, integration and dialect has a tier in `support.toml`: Tier 1 first-party and release-blocking, Tier 2 community and conformance-gated, Tier 3 experimental and off by default. The release-blocking jobs, the conformance cells and the compatibility matrix of D-71 are generated from that file. A cell joins Tier 1 by a change to the file once it passes the conformance suite.

## Enforced by
`verify` regenerates the matrix from `support.toml` and fails on a difference from the committed workflow matrix. `support.toml` is a protected, trust-core path, so a tier change is its own protected-change item. `matrix-run` ([WI-0013]) runs the cells and reports `requires hardware` for a cell with no machine.

## Consequences
What blocks a release is one file anyone can read. Promoting a platform is a reviewed data change with conformance evidence.

## Alternatives rejected
- Tiers in documentation: they drift from the jobs.
- Hand-written workflow matrices: a cell can be dropped without anyone deciding to.

## Revisit when
S-04 passes or fails for Windows; the Windows cells then move in `support.toml` accordingly.
