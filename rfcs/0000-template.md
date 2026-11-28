# RFC-NNNN: Short Descriptive Title

- **Status:** Draft | Review | Accepted | Rejected | Postponed | Superseded
- **Author:** Name or Agent Role
- **Date:** YYYY-MM-DD
- **Governing Design Docs:** `docs/design/...` (`D-XX`, `PXX`)
- **Affected Surfaces:** List files/crates/contracts from `contracts/surfaces.toml`

## 1. Summary

One concise paragraph explaining the proposed change and why existing mechanisms cannot absorb it without changing a governed surface.

## 2. Motivation and Goals

- Problem statement and concrete failure mode today.
- Explicit non-goals.

## 3. Detailed Design

- Data structures, wire/schema additions, CLI/IPC flags, or policy semantics.
- Dynamic content-driven alignment (`P14`): confirm zero hardcoded domain lists or static enumerations.
- Upgrade, downgrade, and rollback impact (`lifecycle.toml` and `upgrade-path.json`).

## 4. Security, Privacy, and Tenancy Review

- Data classes touched (`P8`), trust-core paths affected (`security/trust-core.paths`), and fail-closed guarantees (`P13`).

## 5. Verification Plan

- Unit, differential, fuzz, architecture lint (`scripts/check-architecture.mjs`), and docs checks (`scripts/check-docs.mjs`).
