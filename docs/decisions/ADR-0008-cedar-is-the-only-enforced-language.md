# ADR-0008: Cedar is the only enforced authorisation language, and there is no third expression language

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-08, D-09
- Requires: nothing
- RFC: not required: restates D-08 and D-09 as repository mechanism
- Work items: [WI-0004], [WI-0018]

## Context
Each expression language in a security product is a parser, an evaluator and a set of semantics to keep sound. Cedar has a formal model and an analyser; Sigma is the detection community's format (brief 20; reviews c2, l10).

## Decision
Authorisation is Cedar 4.x over a published, fixed schema. Detections are Sigma-format rules behind a detection-engine trait. Session rules are small deterministic state machines. Manifests are match tables. Nothing else evaluates expressions: no CEL, Rego, Lua, JavaScript or embedded scripting in any layer.

## Enforced by
`cargo deny` bans in `deny.toml` on the crates of the do-not-use list (`cel` and the other expression and scripting engines). The Cedar reference differential of [WI-0018] holds evaluator semantics.

## Consequences
A request that needs logic beyond Cedar, Sigma or a match table becomes an analyser that emits facts, or an RFC. Dogwood syntax may be accepted only as an authoring front end that lowers to Cedar.

## Alternatives rejected
- CEL for manifests: a third language for what a match table expresses.
- OPA and Rego: no formal model, and a second policy evaluator beside Cedar.

## Revisit when
Policy evaluation exceeds 1 ms p99 at 1,000 policies including request construction (D-08): add slicing by action class, not a language.
