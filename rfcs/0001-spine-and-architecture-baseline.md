# RFC-0001: Architecture Spine, Layering, and Public Surfaces Baseline

- **Status:** Accepted
- **Author:** Guardrails Architecture Team
- **Date:** 2026-11-27
- **Governing Design Docs:** [docs/design/00-decisions.md](../docs/design/00-decisions.md) (`D-01`..`D-71`, `P1`..`P17`), [contracts/architecture.toml](../contracts/architecture.toml), [contracts/surfaces.toml](../contracts/surfaces.toml)
- **Affected Surfaces:** Workspace crate layering, `grdr.*` Connect/Protobuf contracts, OS peer-authenticated endpoint IPC, split Console/Operator bindings (`D-70`)

## 1. Summary

This RFC establishes the baseline governed surface boundary recorded across the repository ADR spine (`ADR-0001`..`ADR-0057`) and design documents `00` through `36`.

## 2. Baseline Invariants

1. **Layer Isolation (`contracts/architecture.toml`):** Dependencies strictly flow downward across layers `0` -> `1` -> `2` -> `3`, with zero unapproved same-layer edges and `grdr-crypto` remaining the sole workspace cryptography crate (`ARCH-006`).
2. **Split Plane Separation (`D-70`):** `grdr-server` requires distinct `--bind` (Connect Console/API plane) and `--operator-bind` (isolated Operator plane) socket addresses; `grdr-daemon` binds zero HTTP/TCP listeners and serves OS peer-authenticated IPC only.
3. **Dynamic Content-Driven Catalogue (`P14`):** Agent harnesses, detection fingerprints, compliance frameworks, and integrations live in signed packs and declarative manifests rather than hardcoded static Rust or TypeScript enumerations.
4. **Error Code Registration (`ARCH-017`):** Every workspace `GRDR-<AREA>-<NNNN>` error code is registered in [contracts/codes/registry.toml](../contracts/codes/registry.toml).
5. **Commercial Parity (`P11`):** [contracts/plans.toml](../contracts/plans.toml) guarantees security, SSO, and audit parity across free self-hosted and paid tiers.
