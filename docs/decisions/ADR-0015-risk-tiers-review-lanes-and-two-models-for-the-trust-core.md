# ADR-0015: Risk tiers come from paths, review lanes from the diff, and a trust-core change needs two models

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-63; `design/02` SD-13
- Requires: nothing
- RFC: not required: restates D-63 as repository mechanism
- Work items: [WI-0007]

## Context
Most changes are small or checkable without a model, and every evaluator pass spends the shared usage window (owner instruction 8). The trust core is where one missed defect harms hosts (reviews c9, l01).

## Decision
One deterministic classifier, `cargo xtask risk`, gives each diff a tier (low, medium, high) from its paths and triggers, and a lane (`static`, `light`, `standard`, `full`). A tier or lane may be raised by an agent and never lowered. High tier and trust-core changes take `full`: `eval-security` and `eval-adversarial` in clean contexts, cross-model review, and for the trust core two independent passing evaluators on different models. A protected change is its own work item and lands after `eval-security` and one more evaluator on the other model pass.

## Enforced by
`cargo xtask risk` reading `.agents/risk-tiers.toml` and `security/trust-core.paths` from the base commit; golden diffs with their expected tier and lane; the dispatcher's review pass and the merge queue, which follow the lane; `kit ready`, which refuses a protected write set for any agent but `lead-agent-kit` or the chief architect.

## Consequences
A comment fix lands on proofs alone and a daemon change costs the full set. The lane rules are data; changing them is a protected change.

## Alternatives rejected
- The same evaluator set on every change: it spends the usage window on typos.
- A model that picks the lane: P2 applied to our own process forbids a model lowering a control.

## Revisit when
A circuit breaker of `team/01` section 5 trips, or S-20 shows a lane's cost per accepted item above twice its baseline.
