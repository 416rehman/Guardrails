# ADR-0043: Lean token-optimised agent team and fast-track lane

- Status: accepted
- Date: 2026-11-23
- Decided by: owner
- Spine: D-47, D-61, D-63, P14, P17
- Requires: ADR-0042
- RFC: not required: owner instruction optimising the agent kit workflow to eliminate token waste and multi-day stalls on routine tasks
- Work items: #2005

## Context
Running 4 to 16 split evaluators (`eval-diff` twice, `eval-docs`, `eval-acceptance`, `eval-architecture`, `eval-security`, `eval-adversarial`, per-kind reviewers, plus a 9-seat persona council for RFCs) across up to 3 rounds burned massive AI tokens and stalled routine work. Treating `Cargo.toml`, `Cargo.lock`, `supply-chain/build-tools.toml`, `rust-toolchain.toml`, lint configs, and docs as `trust-core` also routed simple dependency/tool pins through 7+ evaluators, 20+ generated acceptance criteria, cross-lead sign-offs, and multi-day queues despite full automated CI verification (`cargo-deny`, `osv-scanner`, pin/checksum checks, `gitleaks`, `Semgrep`, `CodeQL`, `fmt/clippy/tests`).

## Decision
1. **Three clear workflow lanes in `.claude/risk-tiers.toml`:**
   - **Fast-Track (`[fast_track]` -> 0 LLM evaluators):** dependency/tool pins (`Cargo.toml`, `Cargo.lock`, `supply-chain/build-tools.toml`, `rust-toolchain.toml`), docs/markdown, tests-only changes, lint/format/release config, and small fixes under 50 lines with no `trust_core` or `high` path/trigger. Skip `grdr-write-spec`, implement directly, let deterministic CI verify, and squash-merge immediately once CI is green.
   - **Normal / Medium (`[medium]` -> 1 evaluator):** `eval-review` alone (`standard` tier), combining diff, docs (`design/34`), acceptance, and architecture/structure in one pass.
   - **High / Trust-Core (`[high]` & `[trust_core]` -> 2 evaluators on 2 distinct models/providers):** `eval-review` + `eval-security` (covering security, up to 3 adversarial abuse traces, dependency licences, and reference-model checks) per D-63 and `.agents/models.toml`, capped at **2 rounds** (`[limits].max_rounds = 2`).
   - Inline `[checklist_addons]` replace extra per-kind evaluator spawns and the 9-seat RFC persona council fan-out.
2. **Narrow `security/trust-core.paths` to actual security boundaries:** retain kernel/driver/daemon/sandbox/updater/crypto/policy/fastpath/tenant/FFI runtime paths, `limits.toml`, `security/**`, `.github/workflows/**`, `**/deny*.toml`, and `supply-chain/{licences,do-not-read}.toml`; remove routine tool/crate pin files, formatting/lint configs, release manifests, and agent/doc markdown.
3. **CI-first verification & minimal spec ceremony:** evaluators trust green `gh pr checks` on the exact head commit `<sha>` instead of re-running local tools, GraphQL history queries, or multi-prompt audits. `grdr-write-spec` skips routine work and caps complex-issue criteria at 2 to 5 concise checks.

## Consequences
Routine dependency pins, docs, and small fixes finish and merge in minutes with zero evaluator token burn, while `medium` changes take 1 evaluator and `high` / runtime `trust-core` paths preserve D-63 two-model independent review.

## Alternatives rejected
- Keeping `Cargo.lock`, `supply-chain/build-tools.toml`, and markdown inside `security/trust-core.paths`: rejected because CI already verifies digests, licences, and advisories deterministically while multi-day evaluator loops blocked downstream crates like `grdr-proto`.
- Keeping 6 to 16 evaluators across 3 rounds: rejected due to unsustainable token cost and latency.
