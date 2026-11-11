---
name: grdr-author-policy
description: Write or change a Cedar policy or pack. Use for items touching `packs/`, the Cedar schema or Essentials.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: grdr policy check (design/12 E3.5)
  closes-by: test
---

# Write or change a Cedar policy or pack

A pack is signed data: Cedar policies, typed lists, session rules, tests and messages (D-11, P7).
Every change to it is either narrowing or widening, and widening always needs a person other than its
author (D-31, D-55). Classify the change before you write it, and let `grdr policy check` confirm.

The item is issue `#<n>`, where `<n>` is `GRDR_WORK_ITEM`. Read it with `gh issue view <n> --comments`;
its write set and tier are in `.agent/state/item-<n>.json`, which `cargo xtask kit launch` wrote (skill
`grdr-start-item`).

## Pack anatomy (design/12 sections 3 and 10; design/13 section 11)

- `packs/<pack>/pack.toml`: kind, semver, `min_engine`, channel, declared reads and data classes.
- `policy/<pack>/`: `rules/*.cedar`, `lists/*`, `session-rules.yaml`, `tests/*.yaml` and the
  language tokens `messages/<locale>.mf2.toml` (MessageFormat 2, compiled at pack build, D-69).
- A rule is one Cedar `forbid` with annotations: `@id` (unique, with the pack's prefix), `@class`,
  `@max_mode`, `@approver`, `@min_grade`, `@on_loss`, `@final`, `@message`, `@steer`, `@remedy`,
  `@obligation`, `@intent`, and `@status`, which stays `draft` until a replay is attached.
- `permit` exists only in `grdr.base`. Every other pack is forbid-only; that is what makes any layer's
  deny win, so never add a `permit` elsewhere.
- The rule class sets the minimum approval grade and the loss-of-sensor behaviour. A rule may raise
  them, never lower them.
- An `unless` clause reads only deterministic evidence: grants, classes, assurance, attribution and
  enforcing labels. Never an advisory label, a detection output or anything of model origin (P2).
- A pack never introduces a command, executable path, URL to fetch, environment variable to set or MCP
  server to start. Host patterns, environment variable names and path templates are allowed only as
  typed match fields (P7).

## Classify the change (design/12 section 7)

Narrowing, which needs no approver but still ships through rings:

- a Mode moves up the ladder Off, Watch, Ask, Block;
- a `protect` list grows, or an `allow` list shrinks;
- rules and session rules are only added, and no label decay shortens.

Widening is everything else, including editing or removing a rule, removing a pattern from a
protective class, lowering a Mode or approval grade, and anything `grdr policy check` cannot decide (a
timeout counts as widening). You may write a widening change, but you never approve it. Name it as
widening in the hand-off `summary` so the evaluator and the approver see it, and never describe it as
narrowing.

## Steps

1. Read the pack's existing rules, lists and tests first. Search before writing: the class, list or
   rule you need may exist.
2. Write the tests first, in `tests/*.yaml`: at least one positive and one negative per rule. Where the
   rule reads analyser classes, give raw input (a command line and working directory) so the normalisers
   run, not a pre-classified request.
3. Write or change the rule.
4. Message text. `@message` is shown to a person: the English source of a language token, at most
   280 graphemes, translated in `messages/<locale>.mf2.toml` (D-69). `@steer` is for the agent:
   English, at most 400 characters, never naming a widening command (pause, Mode down, uninstall,
   exclusion). Both are inert text with no URLs
   (design/34 section 7). This is block-message copy, so load `ui-architect` before writing it, and give
   the person one route forward, never a dead end (D-44).
5. `grdr policy test` runs the tests under the production interpreter; the verify step V08 runs it
   again when packs change.
6. `grdr policy check` validates strictly against the schema, lints (missing `has` guards, `like`
   misuse, list polarity, shadowed rules, unknown classes, lists, labels and obligations) and prints the
   semantic diff with its narrowing or widening verdict. Quote that verdict in the hand-off.
7. Replay before a rule leaves Watch: `grdr policy replay --draft <dir> --window 7d`. Attach the four
   buckets (matched, almost matched, not matched, not evaluable) and the estimated prompts per
   developer-day. A rule without an attached replay stays `draft` and in Watch. Moving it out of Watch
   is approved by someone other than the author (D-55): file the Mode change as a `status:proposed`
   issue with the replay attached (skill `grdr-handoff`) and name it in `next`.

## Essentials (D-53)

- Essentials is the pack enforced from first protection. A rule enters it only with zero hits on the
  benign corpus and zero block-induced task failures in the efficacy harness. The release gate asks for
  zero failures in 3,000 scripted attempts per Tier 1 cell (team/05 section 16).
- A change to Essentials or the fail-safe table raises the tier (`essentials_or_failsafe_change` in
  `.agents/risk-tiers.toml`); `cargo xtask risk` reports it. Harness evidence comes from the lab, never
  from your own statement.
- Never relax an Essentials rule to satisfy a request, a persona or a failing test.

## The Cedar schema and the evaluator

- The Cedar schema under `schema/` changes only through an accepted RFC (D-61). If the item needs an
  entity, attribute or action the schema lacks, stop and hand off `blocked` with the escalation packet
  of `team/01` section 6 (skill `grdr-handoff`).
- Evaluator semantics (the `policy` module of `grdr-core` and `grdr-policy-ref`) are trust-core code,
  not pack content. This skill does not cover them.

Finish with `grdr-handoff`. For a change in this repository, also run `cargo xtask verify --fast`.

## Commands this skill names

A command that has not landed yet shows as an unknown subcommand.

| Command | Added by | Until it exists |
|---|---|---|
| `grdr policy test` | design/12 E4.1 | The rule's tests cannot run, so the item cannot be done: hand off `blocked`, naming E4.1 in `next` |
| `grdr policy check` | design/12 E3.5 for the semantic diff; strict validation comes with the compiler (WI-0037, schema from WI-0018) | Without the diff, treat every change that is not a pure addition as widening, and say so. Never substitute your own reading for the analyser's verdict |
| `grdr policy replay` | design/12 E4.2 | No rule may leave Watch. Leave `@status` at `draft` |
| `cargo xtask risk` | WI-0007 | Compare changed paths with `.agents/risk-tiers.toml`; treat any Essentials change as high tier |
| `cargo xtask verify --fast` | WI-0002 | Follow `grdr-verify` |
