# Guardrails ADR Hook Broker Specification (L2)

Defines the declarative third-party `VerdictProvider` plug-in protocol, `providers.d/` manifest validation, strict deadline fan-out merge semantics, and fail-closed safety invariants (`docs/design/07`, `docs/design/26`).

## Core Invariants

1. **Conservative Most-Restrictive Merge:** Provider verdicts strictly combine via `DENY > STEP_UP > DEFER > MODIFY > ALLOW`. No provider can widen an existing engine `DENY` or `STEP_UP`.
2. **Bounded Evaluation Budget:** Default provider deadline is `150 ms` and maximum allowed deadline is `1000 ms`. Timeouts trigger the provider's configured `on_failure` policy.
3. **Model-Backed Safety Clamps:** Any provider with `trust_model: model_backed`:
   - Cannot emit `DENY` directly (`DENY` clamps to `STEP_UP`).
   - Cannot hold `may_modify: true` (`GRDR-BRK-0005`).
   - Defaults/forces `on_failure: ignore` to prevent probabilistic availability outages from bricking endpoints.
4. **Single-Writer Modify & Engine Re-Evaluation:** At most one active provider may hold `may_modify: true` (`GRDR-BRK-0006`). Every `MODIFY` rewrite must re-run through core policy evaluation before returning to the caller.
5. **Circuit Breaker Suspension:** Five consecutive failures or >5% failure rate across a 5-minute window (>=20 calls) transitions the provider into `Suspended` (`provider-suspend`).
6. **White-Label Brand Resolution:** Messages emitted by the broker read brand identity from `contracts/interface/brand/brand.toml` or caller-supplied `BrokerBrand` (`docs/design/26`), never hardcoded vendor strings.
7. **`command-hook` Re-Hosting & Capability Conformance:** Providers with `kind: command-hook` compile into `provider-index.tsv` (`<=64 KiB` stdout, `<=1000 ms` deadline) executed only by the unprivileged `grdr-hook` shim (the daemon never spawns child processes), and conformance results generate `capabilities.json` across the 18 canonical events.
