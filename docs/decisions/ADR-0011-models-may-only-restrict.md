# ADR-0011: Models may only restrict, and every label records its origin

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: P2, D-09, D-29
- Requires: nothing
- RFC: not required: restates P2 as repository mechanism
- Work items: [WI-0014], [WI-0018]

## Context
Adaptive attacks beat every classifier, and a judge leaks through its verdicts (briefs 09, 22, 39, h01; reviews c2, c8). A model output that can allow, grant, declassify, suppress or clear is an attack surface.

## Decision
No allow, grant, declassification, suppression or clearing of a finding depends on a model. Every label and risk input records its origin: deterministic, heuristic or model. Enforcing labels are written only by deterministic session rules. Advisory labels, model-origin ones included, evaluate as absent in Cedar. Egress default-deny, protected paths, agent-config writes, credential brokering, the kill switch, tenant isolation and the failure mode never depend on a model.

## Enforced by
A schema rule in `grdr-schema-lint`: a label or risk-input message without a required origin field fails. A Cedar test in the policy crate proves that a policy reading an advisory label gets the same verdict as with the label absent. `eval-security` checks P2 on every change to the `policy`, `session` and `detect` modules.

## Consequences
A model tier can add a DENY, a STEP_UP or a finding and nothing else. Turning model tiers off never widens anything.

## Alternatives rejected
- A confidence threshold above which a model verdict may allow: the threshold becomes the attack target.
- Origin as a convention in documentation: policy could not read it.

## Revisit when
Never as a principle; a specific exception would be an RFC against P2.
