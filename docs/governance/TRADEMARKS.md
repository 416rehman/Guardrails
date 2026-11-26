# Guardrails ADR Trademark & Conformance Mark Policy

This policy governs use of the **Guardrails ADR** name, logos, and conformance marks
(`docs/design/30` section 8, `docs/design/36` section 1). Source code licensing is governed
separately by `LICENSE` (`Apache-2.0`).

## Ownership & Stewardship

"Guardrails ADR" and the conformance marks belong to the Guardrails ADR project (`contracts/interface/brand/brand.toml`),
currently held by Loonaro under the springing assignment escrow in `docs/governance/COVENANT.md`
(transferring upon D-03 trigger to the chosen foundation). "Loonaro" remains the house mark of
Loonaro.

## Permitted Use Without Permission

1. **Nominative use:** Truthful statements indicating compatibility such as "works with
   Guardrails ADR" or "integrates with Guardrails ADR".
2. **Factual attribution:** Unmodified or truthfully described references such as "built from
   Guardrails ADR source".

## Conformance Marks (Evidence-Gated)

Conformance marks indicate verified interoperability under published conformance kits and the
`D-51` no-covert-monitoring privacy floor:
- **"Runs Guardrails ADR content"**: L0 golden-vector verification pass.
- **"Guardrails ADR hook provider"**: L2 hook broker kit pass plus ACS signature/replay/skew
  verification (`D-14`).
- **"Embeds the Guardrails ADR engine"**: L3 golden vectors + scripted scenario pack with full
  disclosure of any "not evaluable" rules.
- **"Guardrails ADR platform"**: Full conformance suite pass on a rebuilt distribution (`L6`).

Rules:
- Every listing must publish reproducible verification evidence in the public conformance
  registry, state its embedding option and OS assurance level, identify the exact build digest,
  and expire upon the next conformance kit major version.
- Conformance testing services may be sold independently, but conformance marks are never sold.

## Restrictions & Forks

- Modified distributions, forks, or white-label rebuilds must NOT use "Guardrails ADR" or
  "Guardrails" as their product name and must replace Class B and Class C brand fields cleanly
  while preserving Class A technical wire namespaces (`grdr`, `grdr.*`, `Grdr`, `GRDR-`).
- "Passes AARM R1 to R9 test set" may be claimed directly; public CSA AARM conformance claims
  require satisfying AARM's external production and certification rules (`docs/design/36`).
