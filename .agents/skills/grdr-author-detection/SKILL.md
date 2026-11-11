---
name: grdr-author-detection
description: Write a detection or session rule with tests. Use for any item that adds or tunes detection content.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: grdr content test (design/03 G2)
  closes-by: test
---

# Write a detection or session rule

Detection content is signed data in the content repository (`grdr-content`), loaded by the production
interpreter in every supported engine (P7). It enters as `experimental`, in a pack at Watch, and moves
up only on evidence that a bot proposes and people approve. Your job is the rule, its fixtures and the
test evidence.

`grdr-content` is created under the same GitHub profile as the main repository when the first
content item starts. Until it exists only built-in rules in this repository can land; for any other
rule hand off `blocked` and name the missing repository. Creating it is the owner's step.

The item is issue `#<n>`, where `<n>` is `GRDR_WORK_ITEM`. Read it with `gh issue view <n> --comments`;
its write set and tier are in `.agent/state/item-<n>.json`, which `cargo xtask kit launch` wrote (skill
`grdr-start-item`).

## Pick the kind first (D-09)

| You need | Write | It produces |
|---|---|---|
| An enforcing label that an Ask or Block policy reads | A session rule in the policy pack's `session-rules.yaml` | A label or counter with a scope and decay, written synchronously |
| Anything else: a finding, risk, an advisory label, a response binding | A Sigma detection with an `x_grdr` block | A finding; never a block on its own |

A session rule reads only deterministic facts and classes. It never reads an advisory label or a
model-origin input (P2). A detection cannot cause a block: the compiler rejects any enforced rule that
reads detection output (design/13 section 1). If the item wants a detection to block, it needs a session
rule plus a policy rule: record that in `decisions` and use `grdr-author-policy` for the policy half.

## Write a Sigma detection (design/13 sections 2 to 5)

1. Write it fresh. Never copy SigmaHQ rules (DRL 1.1), Elastic rules (Elastic License 2.0) or
   malcontent's `third_party` YARA into the repository: our content is Apache-2.0 with no attribution
   duty (D-02).
2. Log source: `product: grdr`, `category` the event category, `service` the action class. Field names
   come from the log-source taxonomy (design/13 section 3), generated from the field registry. Use them
   exactly. If the field you need is missing, never invent one: file it as a `status:proposed` issue
   against the field registry (skill `grdr-handoff`) and name that issue in `next`.
3. Match only with `contains`, `startswith`, `endswith`, `re` (linear time), `cidr`, `exists` and
   `expand`. A correlation groups by `session.root` or `session.id` unless it declares device or
   organisation scope, and never by a key derived from a person (D-51). `value_sum`, `value_avg` and
   `value_percentile` run on the server only.
4. Fill the `x_grdr` block:
   - `rule_id`, and `version`, bumped on any logic change;
   - `finding_class` and `ceiling` (`record`, `notify`, `contain`, `remediate`); a rule whose
     determining input is heuristic or model origin binds at most `notify`;
   - at most one `risk` contribution, 1 to 250 points;
   - `requires`: the fields read, `min_provenance` and `placement`; reading a content-class field forces
     `placement: device` (P8);
   - `stage`, `mappings` to pinned releases, typed `tunables` with bounds, `tests`, `known_gaps`.
5. Declare every field and data class the rule reads. Declared reads must equal computed reads.
6. A `response` binding names verbs at or below the ceiling with a blast-radius block, and starts in
   `simulate` (design/13 section 14). Never write a binding that acts outside `simulate`.

## Write a session rule (design/13 section 6; design/12 section 9)

- One entry: `id`; `on` (action class, phase `decided-allow` or `observed`, deterministic classes or
  facts); then `set` (label, scope `session` or `lineage`, decay) or `count` (counter, window, threshold,
  label).
- A session has at most 64 enforcing labels and 32 counters. Cedar sees labels, never counters.
- The rule ships in a policy pack, so its pack's policy tests apply as well: run `grdr policy test`
  (see `grdr-author-policy`).

## Tests (design/13 section 12)

1. Write the fixtures first: one positive and one near-miss negative, as event JSON lines under
   `tests/<rule>/`. Fixtures are inert: no live credential, no runnable payload, nothing that harms a
   machine that replays it.
2. Every field the rule constrains has a concrete, non-wildcard value in some positive fixture.
3. Run `grdr content test`. It loads the rule in every supported engine (native and `wasm32`, each
   engine version from `min_engine` up), runs the fixtures and checks declared reads, mappings, cost
   (p99 50 µs on a matching event, 1 µs on a non-matching one), the version bump and the benign corpus.
4. Benign corpus: an `experimental` rule may hit at most 1 of every 1,000 corpus sessions. Tune the
   rule, never the corpus. Adding a sample to `corpora/goodlog/` or an entry to `known-fps.yaml` needs its own
   item that `eval-security` and an evaluator on the other model approve.

Attach each command, its exit code and its log path as evidence. A rule you could not load in every
engine is not done, whatever the fixtures say.

## Tuning an existing rule

- Any logic change bumps `version`.
- Keep the existing fixtures passing unless the item says the behaviour changes; then name each changed
  fixture and the reason in `decisions`.
- Tighten matching or add typed tunables. Never loosen a locked tunable, and never add a whole-rule
  suppression: it is refused, because disabling a rule is a Mode change (design/13 section 13).

## Status, Mode and approval

- New rules enter `experimental`, with the ceiling forced to `record`, and the pack ships at Watch.
  Never set a higher status or ceiling yourself; the promotion bot proposes it from evidence.
- First-party content lands when its evaluators pass in check runs. Community content needs two
  passing evaluators on different models. A ceiling of `contain` or above also needs `eval-security`
  and `eval-adversarial` to pass (owner instruction 7). You supply evidence; the approvals belong to
  evaluators, never to you.
- A rule bound for Essentials follows `grdr-author-policy` and D-53.

Finish with `grdr-handoff`. For a change in this repository (built-in rules, the `detect` module),
also run `cargo xtask verify --fast`.

## Commands this skill names

A command that has not landed yet shows as an unknown subcommand.

| Command | Added by | Until it exists |
|---|---|---|
| `grdr content test` | design/03 G2, with design/13 E5.1 for the CI checks; no reserved item, so `lead-content` files it as an issue | The rule cannot be verified, so the item cannot be done. Write nothing that claims a result; hand off `blocked`, naming G2 in `next` |
| `grdr policy test` | design/12 E4.1 | As above, for session rules |
| `cargo xtask verify --fast` | WI-0002 | Follow `grdr-verify` |
