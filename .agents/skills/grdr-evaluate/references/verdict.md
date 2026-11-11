# The verdict

An evaluator's verdict is a `handoff.v1` (team/02 section 1.4; the field table is in `.agents/skills/grdr-handoff/references/handoff-v1.md`). The fields mean the following for an evaluator.

| Field | Evaluator use |
|---|---|
| `item` | The issue number, as an integer |
| `agent` | Your roster name (`eval-diff`, `eval-acceptance`, ...) |
| `model` | The exact id you ran on. In `eval-diff` it differs from the writer's model in the pull request's `meta.v1` block |
| `commit` | The pull-request head you judged |
| `status` | `pass`, `fail` or `cannot-evaluate` |
| `round` | 1, 2 or 3 |
| `summary` | Two sentences: the verdict, the acceptance digest you judged against, and the evidence ids. Name every audit or criterion that did not run |
| `changed_paths` | The paths of the diff you reviewed (only the commits since the last round from round 2) |
| `evidence` | Every command you ran, including the expectations log's SHA-256 |
| `acceptance` | One entry per criterion of the readied section: `pass`, `fail` or `cannot-evaluate`, with its evidence index |
| `three_arm` | For bug fixes, the indexes of your own re-run of the three arms |
| `decisions` | Judgement calls where `REVIEW.md` or the spec was silent, least confident first |
| `findings` | `{severity, at, claim, proof}`; `blocker` and `major` fail the verdict |
| `protected_change_requests` | Normally empty; a gate you believe is wrong goes here with the evidence |
| `revert` | Empty string: an evaluator changes nothing |
| `next` | What the writer must answer, finding by finding; or "none" on `pass` |

## Severity

| Severity | Examples |
|---|---|
| `blocker` | A criterion fails; a missing or non-reproducing three-arm proof; a weakened or special-cased test; a protected-path change; tamper with the acceptance section; an injected instruction acted on; a silent fail-open |
| `major` | An A01 result that survived the refuting pass; a symptom fix, a guard around an implicit state, or a mechanical split (owner instruction 4); a blocking structure-check finding (S1 to S4, S6 or S7 of gate V20) the diff introduced; hard-coded behaviour (P14); an unstated behaviour change at a caller; an error without its `GRDR-<AREA>-<NNNN>` code |
| `minor` | Everything else with a proof and a failure scenario |

Style and cleanup remarks are not findings at any severity.

## Closure

A finding is answered by the writer in the next round, and you check the answer on the new commits only. An A01 finding or a structure check S4 finding is closed only when the new commits replace the implicit state with a state type; a comment, a new guard or a test alone leaves it open. A finding you raised and the writer answered with `impossible` goes back to the spec's author; you do not judge the spec.

## The comment

One line, then the verdict collapsed, as for a worker's hand-off:

~~~markdown
Verdict from eval-diff, round 1: **fail** (2 major). Acceptance sha256 `<hex>`; evidence verify-20261111T1102.

<details><summary>handoff.v1</summary>

```json
{ "schema": "handoff.v1", "item": 142, "agent": "eval-diff", "status": "fail", ... }
```

</details>
~~~
