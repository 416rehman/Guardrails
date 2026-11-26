# ADR-0057: Admit CDLA-Permissive-2.0 for rustls CA root certificate data

- Status: accepted
- Date: 2026-11-26
- Decided by: chief architect
- Spine: D-02, D-36, D-62, D-63, P10, P11, P16
- Requires: [ADR-0004](ADR-0004-apache-2-code-dual-licensed-ebpf-no-cla-no-sign-off.md); [ADR-0018](ADR-0018-supply-chain-latest-at-bootstrap-then-cooldowns.md); [ADR-0056](ADR-0056-repository-root-hierarchy.md)
- RFC: not required: admits a permissive data-only SPDX licence required by D-36 rustls transport dependencies without changing wire contracts, schemas, or public Rust APIs
- Work items: #125

## Context
[D-36](../design/00-decisions.md) (`docs/design/03-system-architecture-and-modularity.md` section 13, `docs/design/17-network-proxy-mcp-broker-gateway-browser.md` section 3) specifies TLS 1.3 via `rustls` with `aws-lc-rs` and `rustls-platform-verifier` for sensor transport and proxy upstream verification across connected and self-hosted deployments.

Enabling the `rustls` feature on workspace `reqwest` (`0.13` in `Cargo.toml` and `programs/grdr/Cargo.toml`) unconditionally pulls `rustls-platform-verifier` (`0.7.1`) and its transitive dependency `webpki-root-certs` (`1.0.12`). `webpki-root-certs` distributes Mozilla NSS CA root certificate trust-anchor data licensed under Linux Foundation `CDLA-Permissive-2.0` (Community Data License Agreement - Permissive 2.0).

Under [D-02](../design/00-decisions.md) and [`docs/design/30-open-source-governance-and-community.md`](../design/30-open-source-governance-and-community.md) section 1, Guardrails ADR requires permissive dependencies with zero copyleft propagation and zero attribution-in-UI obligations (`THIRD-PARTY-NOTICES` and CycloneDX SBOM generation handle source/binary notices). `CDLA-Permissive-2.0` is a purely permissive data license with no copyleft terms and no UI attribution duty; like `CC0-1.0` (already admitted for data), it applies to trust-anchor data rather than software source code. Because `security/supply-chain/licences.toml`, `security/deny.toml`, `security/deny.embedded.toml`, and `fuzz/deny.toml` are trust-core gate configuration (`D-63`), `#125` admits `CDLA-Permissive-2.0` in its own isolated change before any `Cargo.toml` or `Cargo.lock` change enables `reqwest/rustls`.

## Decision
1. Add `"CDLA-Permissive-2.0"` to the `permissive` class `licences` list in [`security/supply-chain/licences.toml`](../../security/supply-chain/licences.toml).
2. Add `"CDLA-Permissive-2.0"` to `[licenses] allow` in [`security/deny.toml`](../../security/deny.toml), [`security/deny.embedded.toml`](../../security/deny.embedded.toml), and [`fuzz/deny.toml`](../../fuzz/deny.toml) so workspace targets, layer 0-2 / embedded closures, and fuzz targets share one consistent permissive data allowance for CA root trust anchors.
3. Document `CDLA-Permissive-2.0` (root-cert data) beside `CC0-1.0` (data) in the `Permissive` / allow-list tables of [`docs/design/30-open-source-governance-and-community.md`](../design/30-open-source-governance-and-community.md) section 1, [`docs/design/36-legal-brand-and-commercial.md`](../design/36-legal-brand-and-commercial.md) section 6, and [`docs/design/24-deployment-and-packaging.md`](../design/24-deployment-and-packaging.md) section 12.
4. Keep `security/supply-chain/licence-headers.toml` unchanged: repository source files continue to carry `Apache-2.0` (and `GPL-2.0-only OR BSD-2-Clause` in `bpf/`), and `CDLA-Permissive-2.0` is limited to third-party root-certificate trust data.

## Enforced by
- `cargo deny --all-features --config security/deny.toml check` and `cargo deny --manifest-path fuzz/Cargo.toml --all-features --config fuzz/deny.toml check` in `.github/workflows/verify.yml`, plus `cargo deny --all-features --config security/deny.embedded.toml check`.
- `node scripts/licence-lint.mjs` enforcing `security/supply-chain/licences.toml` and SPDX file headers across the repository.
- `node scripts/check-architecture.mjs` and `python .github/actions/tree-paths/check_tree.py --rev HEAD`.
- `security/trust-core.paths` (`security/**`, `**/deny.toml`, `**/deny.*.toml`) and `.claude/hooks/security-audit-check.mjs` requiring independent security and licence audit verification before commit or PR creation.
- `Cargo.lock` dependency and licence review (`security/supply-chain/admissions.toml` and `eval-security` / `eval-licence` checks when `Cargo.lock` changes) auditing that only approved CA root-certificate trust-anchor crates (`webpki-root-certs`) resolve under `CDLA-Permissive-2.0` once `reqwest/rustls` lands, with `[licenses]` eligible to narrow to a crate-scoped `[[licenses.exceptions]]` allow-entry across the `deny*.toml` profiles.

## Consequences
- Follow-up work enabling `rustls` on `reqwest` (`D-36`) can resolve `rustls-platform-verifier` and `webpki-root-certs` across workspace, embedded-profile, and fuzz graphs without `cargo deny` licence rejection.
- Embedders and downstream redistributors retain a purely permissive closure (`D-02`) with zero copyleft or product-UI attribution duties, with `webpki-root-certs` tracked in generated SBOMs and `THIRD-PARTY-NOTICES`.
- No existing crate code, `Cargo.toml`, `Cargo.lock`, or source-header rule is altered by this admission.

## Alternatives rejected
- Disabling `rustls` or falling back to OpenSSL / platform-only TLS stacks without `rustls`: violates `D-36` ("TLS 1.3 through rustls with aws-lc-rs") and introduces OpenSSL build and air-gap portability hazards (`P16`).
- Adding a crate-only `[[licenses.exceptions]]` override solely in `security/deny.toml` without updating `security/supply-chain/licences.toml`, `docs/design/24-deployment-and-packaging.md`, `docs/design/30-open-source-governance-and-community.md`, `docs/design/36-legal-brand-and-commercial.md`, `security/deny.embedded.toml`, and `fuzz/deny.toml`: leaves the canonical policy and embedded/fuzz profiles inconsistent prior to `reqwest/rustls` enablement.

## Revisit when
- `reqwest/rustls` lands in `Cargo.lock`: audit `Cargo.lock` so only approved CA root-data crates (`webpki-root-certs`) carry `CDLA-Permissive-2.0`, and optionally narrow `[licenses]` from global `"CDLA-Permissive-2.0"` allowance to a crate-scoped `[[licenses.exceptions]]` entry (`name = "webpki-root-certs"`, `allow = ["CDLA-Permissive-2.0"]`) across `security/deny.toml`, `security/deny.embedded.toml`, and `fuzz/deny.toml`.
- `rustls-platform-verifier` or `reqwest` removes the `webpki-root-certs` dependency, or any dependency proposes using `CDLA-Permissive-2.0` for executable code rather than static trust-anchor data.
