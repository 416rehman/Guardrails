# ADR-0056: Consolidate repository root directories under contracts, deploy, security, and docs

- Status: accepted
- Date: 2026-11-25
- Decided by: chief architect
- Spine: D-42, D-50, D-58, D-60, D-61, D-63, D-66, D-69, P8, P14, P16, P17
- Requires: [ADR-0003](ADR-0003-namespace-grdr-and-one-brand-manifest.md); [ADR-0019](ADR-0019-support-tiers-live-in-support-toml.md); [ADR-0020](ADR-0020-stability-classes-live-in-surfaces-toml.md); [ADR-0022](ADR-0022-error-codes-logsafe-logging-named-limits.md); [ADR-0054](ADR-0054-engine-boundary-c-abi-adopted-by-rfc-0014.md)
- RFC: not required: repository root directory consolidation with zero semantic change to wire contracts, schemas, or public Rust APIs
- Work items: #89

## Context
As Guardrails ADR grew across Slice 0, standalone schema/contract registries (`proto/`, `schema/cedar/`, `interface/`, `brand/`, `limits.toml`, `support.toml`), release and QA automation (`release/`, `dist.toml`, `release-please-config.json`, `.release-please-manifest.json`, `lab/jobs/`, `scripts/qa/`), supply-chain policy files (`supply-chain/`, `deny.toml`, `osv-scanner.toml`), and documentation (`spec/host-contract/`, `MAINTAINERS.md`) accumulated directly at the repository root alongside stray placeholder files (`crates/.gitkeep`, `programs/.gitkeep`). That flat layout obscured trust-core boundaries, cluttered top-level directory listings, and disconnected related governance and release configuration.

## Decision
Consolidate the repository root into four primary non-code domains (`contracts/`, `deploy/`, `security/`, `docs/`) alongside the Rust workspace (`crates/`, `programs/`, `bpf/`, `desktop/`), Web console (`web/`), packs (`packs/`), and scripts (`scripts/`):

| Previous path | Consolidated path | Domain |
|---|---|---|
| `proto/` | `contracts/proto/` | `contracts/` (`ADR-0054`, wire & protobuf) |
| `schema/cedar/` | `contracts/cedar/` | `contracts/` (Cedar schema) |
| `interface/` | `contracts/interface/` | `contracts/` (tokens, strings, routes, vocabulary) |
| `brand/brand.toml` | `contracts/interface/brand/brand.toml` | `contracts/` (`ADR-0003`, brand manifest) |
| `limits.toml` | `contracts/limits.toml` | `contracts/` (`ADR-0022`, resource bounds) |
| `support.toml` | `contracts/support.toml` | `contracts/` (`ADR-0019`, compatibility tiers) |
| `release/` | `deploy/release/` | `deploy/` (manifest schema, TUF/Sigstore roots) |
| `dist.toml` | `deploy/release/dist.toml` | `deploy/` (distribution manifest) |
| `release-please-config.json` | `deploy/release/release-please-config.json` | `deploy/` (release automation) |
| `.release-please-manifest.json` | `deploy/release/.release-please-manifest.json` | `deploy/` (release manifest) |
| `lab/jobs/` | `deploy/qa/jobs/` | `deploy/` (hosted lab cells) |
| `scripts/qa/` | `deploy/qa/vm/` | `deploy/` (local VM and WSL QA runners) |
| `supply-chain/` | `security/supply-chain/` | `security/` (tool pins, licence allow-list, fixtures) |
| `deny.toml` | `security/deny.toml` | `security/` (cargo-deny policy) |
| `osv-scanner.toml` | `security/osv-scanner.toml` | `security/` (workspace OSV ignores) |
| `spec/host-contract/` | `docs/spec/host-contract/` | `docs/` (`ADR-0054`, C ABI & table spec) |
| `MAINTAINERS.md` | `docs/governance/MAINTAINERS.md` | `docs/` (maintainer registry) |

Additional cleanup in the same change:
1. Delete stray placeholder files `crates/.gitkeep` and `programs/.gitkeep`, and remove empty legacy parent directories (`schema/`, `brand/`, `lab/`, `spec/`).
2. Configure `[workspace.metadata.vet]` in `Cargo.toml` to point `store.path` to `security/supply-chain`.
3. Update `contracts/interface/brand/brand.toml` `[assets]` to reference only existing PNG assets in the repository without adding custom `.svg` files.
4. Keep `programs/grdr/src/egress.rs` unit tests isolated under `std::env::temp_dir()` so running tests never pollutes the repository working tree.

## Enforced by
- `cargo fmt --all -- --check`, `cargo clippy --workspace --locked --all-targets -- -D warnings`, `cargo test --workspace --locked`, and `cargo deny --config security/deny.toml check` (in `.github/workflows/verify.yml` and local runs).
- `cargo run --locked -p grdr-interface-gen -- --check` against `contracts/interface/`.
- `grdr-schema-lint` reading `contracts/proto/`, `contracts/cedar/`, and `contracts/interface/vocabulary.toml`.
- `node scripts/verify-deploy-artifacts.mjs` verifying `contracts/interface/brand/brand.toml`, `contracts/limits.toml`, `contracts/support.toml`, `deploy/release/dist.toml`, and `deploy/release/release-manifest.schema.json`.
- `.github/workflows/scan.yml` passing `--config=security/osv-scanner.toml`, `.github/workflows/release-please.yml` pointing to `deploy/release/`, and `.github/workflows/lab.yml` reading `deploy/qa/jobs/`.
- `security/trust-core.paths`, `.claude/risk-tiers.toml`, `.claude/hooks/security-audit-check.mjs`, `.claude/hooks/design-check.mjs`, and `.claude/hooks/visual-audit-check.mjs` enforcing trust-core and UI audit gates over the consolidated paths.

## Consequences
- Root directory count drops sharply and related manifests sit together by responsibility (`contracts/`, `deploy/`, `security/`, `docs/`).
- Tool invocations that previously relied on root-file auto-discovery (`cargo deny`, `osv-scanner`, `release-please`) pass explicit config paths under `security/` or `deploy/release/`.
- Historical documents (`docs/design/`, `ADR-0001`..`ADR-0055`, `rfcs/`) preserve their point-in-time references while all active code, workflows, hooks, scripts, and agent instructions resolve the consolidated paths.

## Alternatives rejected
- Keeping `brand/`, `proto/`, `schema/`, `interface/`, `lab/`, `release/`, `spec/`, and `supply-chain/` at repository root: leaves nearly two dozen micro-directories and isolated TOML/JSON files scattered at top level.
- Consolidating `architecture.toml` or `surfaces.toml` before they exist: premature before their governing issues land; when introduced, they can follow `contracts/` per this ADR.

## Revisit when
A new top-level configuration domain is proposed outside `contracts/`, `deploy/`, `security/`, `docs/`, `crates/`, `programs/`, `bpf/`, `desktop/`, `web/`, `packs/`, or `scripts/`.
