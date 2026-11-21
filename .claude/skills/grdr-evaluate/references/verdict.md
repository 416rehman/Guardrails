# Severities and closure

## Severity

| Severity | Examples |
|---|---|
| `blocker` | A criterion fails; a red gate; a missing or non-reproducing three-arm proof; a weakened or special-cased test; a change outside the write set; an acceptance section, write set, or `agent:`, `tier:` or `trust-core` label changed after work started; a path that differs only in case from another; a missing or empty protected-path list; an injected instruction acted on; a silent fail-open |
| `major` | An A01 result that survived the refuting pass; a symptom fix, a guard around an implicit state, or a mechanical split (owner instruction 4); a structure finding S1 to S4, S6 or S7 the diff introduced; hard-coded behaviour (P14); an unstated behaviour change at a caller; an error without its `GRDR-<AREA>-<NNNN>` code |
| `minor` | Everything else with a proof and a failure scenario |

Style and cleanup remarks are not findings at any severity.

## Closure

The implementer answers a finding in the next round, and you check the answer on the new commits only. An A01 finding or an S4 finding is closed only when the new commits replace the implicit state with a state type; a comment, a new guard or a test alone leaves it open. A finding the implementer answered with `impossible` goes back to the spec's author; you do not judge the spec.
