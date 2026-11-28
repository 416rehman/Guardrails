# Requests for Comments (RFCs)

Per [GOVERNANCE.md](../GOVERNANCE.md), an accepted RFC in `rfcs/` is required before merging breaking or architectural changes to any governed surface:

- [docs/design/00-decisions.md](../docs/design/00-decisions.md) (decision spine)
- Public crates (`grdr-schema`, `grdr-core`, `grdr-ports`, shared protocol and C/WASI bindings)
- Wire formats (Connect/Protobuf packages, signed pack format, provider protocol, host contract)
- The Cedar policy schema (`contracts/cedar/`)
- Stability classes in [contracts/surfaces.toml](../contracts/surfaces.toml) or same-layer dependency edges in [contracts/architecture.toml](../contracts/architecture.toml)
- Core governance, licence allow-list, release/support policy, or [security/supply-chain/do-not-read.toml](../security/supply-chain/do-not-read.toml)

## Filing a New RFC

1. Copy [0000-template.md](0000-template.md) to `rfcs/NNNN-short-title.md` using the next four-digit sequential number.
2. Fill in every required section, including author (agent or person), compatibility/migration plan, security considerations, and design-doc alignment.
3. Open a pull request. The review council and architecture evaluator review it, and the chief architect writes the final disposition (`accepted`, `rejected`, or `postponed`).
4. Implementation pull requests cite the accepted RFC number alongside their tracking GitHub issue (`Closes #<n>`).

## Index

| RFC | Title | Status |
| --- | --- | --- |
| [0000](0000-template.md) | Standard RFC Template | Template |
| [0001](0001-spine-and-architecture-baseline.md) | Architecture Spine, Layering, and Public Surfaces Baseline | Accepted |
