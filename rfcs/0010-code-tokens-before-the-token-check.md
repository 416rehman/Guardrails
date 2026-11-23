RFC: 0010
Title: RFC 0007 amendment 1: a code registered before the token check exists gets its tokens from #1853
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Accepted
Design issue: #1998
Spine: D-61, D-69, P17 (no spine text changes)
Surfaces: the public crate `grdr-schema` (layer 0), through one sentence of RFC 0007 section 4 ("Content, not surface"): when an item that registers an error code is blocked by the interfaces item that writes the code's tokens. No type, format, refusal, rendered form, token id, wire format, dependency, same-layer edge or Cedar schema changes
Decision record: docs/decisions/ADR-0044-code-tokens-before-the-token-check-adopted-by-rfc-0010.md

To comment, write on issue #1998 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This RFC amends RFC 0007 (`rfcs/0007-grdr-model-and-grdr-schema-slice-0-surface.md`, accepted, [ADR-0038](../docs/decisions/ADR-0038-the-grdr-model-and-grdr-schema-slice-0-surface-adopted-by-rfc-0007.md)) in one sentence of section 4. An accepted RFC never returns to `Review`, so an amendment is a new RFC that names RFC 0007 (RFC 0007 section 11; RFC 0001, "RFC states"), and the RFC 0007 file is not edited, as RFC 0008's constraint 4d has it for RFC 0008's amendments. This is amendment 1 of RFC 0007. #1851, #1852, #1858 and RFC 0009 section 16 also amend RFC 0007, each as part of an RFC with its own subject, and carry no number, as #1959 and RFC 0009 carry none among RFC 0008's.

## Summary
RFC 0007 section 4 lets an item that registers a code leave its two source-locale tokens to an interfaces item, and then blocks the registering item by that interfaces item so that the token check never fails on `main`. The token check is #1853 R2, which is not on `main` yet, so until it lands the blocking protects nothing and only holds the registering item behind the interfaces chain. This amendment applies the blocking once the check is on `main`. Before then, the item that adds the check writes the tokens of every code registered when it is worked. Nothing else in RFC 0007 changes.

## Motivation
RFC 0009's constraint 5 (#1982, from the session's ruling D5 on #1850, https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7086965082) has #1853 write the tokens of every `GRDR-MODEL` code, and #383, #1986, #1994 and #1995 register their codes and write none. Under RFC 0007 section 4 as decided, each of those items would be blocked by #1853. #1853 is blocked by #1613, which is blocked by #449 and #1612, behind the RFC on #448. #383 (p0), #1994 and #1995 would then wait on that chain, which is the wait they had through #1614 and which ruling D5 removed.

The blocking exists so that the token check never fails on `main`. That check is #1853's own R2, run in the gate of #1613 (#1853 R3). Until #1853 lands there is no check on `main` that a registered code with no tokens could fail, and nothing renders a code's token before #1613 and #1853 land either.

If nothing changes, the `MODEL` items either wait on the interfaces chain or land against the text of RFC 0007.

## Design
- R1. In RFC 0007 section 4, "Content, not surface", third bullet, the sentence

  > An item that does not write them is blocked by the interfaces item that does, so the token check never fails on `main`.

  becomes

  > Once the check that fails a registered code with no tokens is on `main` (#1853 R2), an item that does not write them is blocked by the interfaces item that does. Before then, the item that adds that check writes the tokens of every code registered when it is worked (#1853 R1), so the check never fails on `main`.

- R2. Nothing else in RFC 0007 changes. That includes the rest of the bullet, under which the registering item may write the tokens itself in `interface/strings/src/code.mf2.toml`, `eval-ux` judges them there and translations follow through `impl-l10n` (D-69); the registry and its formats; the token ids `code.<area>_<nnnn>.message` and `.fix`; section 11's stability table; and section 12's row for a code with no token.
- R3. #383, #1994 and #1995 are blocked by #1998, and by neither #1614 nor #1853. #1853 writes the `code.<code>.message` and `code.<code>.fix` tokens of every `MODEL` code registered when it is worked, with the text that RFC 0009's constraints 2a, 2b and 2h set, as RFC 0009's constraint 5 has it.
- R4. The `/codes/<code>` page rule of design/34 (F2) does not change: a registered code gets its page through #1636, as every code does.
- R5. #1853's pull request, and every pull request that registers a code and is open at any point while #1853's is open, merges only from a head that contains the tip of `main` at the time of the merge. The ruleset on `main` does not require a branch to be up to date before it merges (RFC 0001, "What holds the rule"). Without R5, a code registered after #1853's checks last ran, or a registering pull request whose checks last ran before #1853 landed, would put a registered code with no tokens on `main`, and the token check would then fail on `main` and on every pull request.

**What holds it.**
- Before #1853 lands, there is nothing to hold: no check exists to fail, and no surface reads a code's token.
- On #1853's own pull request, its check (R2 and R3 of #1853) walks `codes::ALL` of the merge with its base, so a code registered on that base with no token fails #1853 until #1853 writes it.
- R5 is held by the orchestrating session at each merge R5 names, before it squash-merges: `git fetch origin main` and then `git merge-base --is-ancestor origin/main <head>` must exit 0. Otherwise the branch is rebased onto `origin/main` and the gates run again on the new head. The decision posts R5 as a constraint on #1853 and on the open items that register a code.
- After #1853 lands, RFC 0007's rule holds as before: the lead of an item that registers a code and writes no token blocks it by the interfaces item that writes them, and the check fails a pull request that registers a code with no token.

**Failure modes.**

| Failure | Declared outcome | Visible as |
|---|---|---|
| A code is registered before #1853 lands | It has no token until #1853 writes it. Nothing reads a code's token before #1613 and #1853 land | #1853's check names the code on #1853's own pull request, which then writes its tokens |
| A code reaches `main` with no token despite R5 | The token check fails on `main` and on every pull request. The exit is an interfaces item that writes the tokens, at `priority:p0` | The check names the code and the locale (RFC 0007 section 12) |
| A code is registered after #1853 lands, with no token and no blocker | The check fails that pull request | The check's line naming the code |

Data classes: none, because no field is read or written. Assurance effect: none. No action class changes `visibility`, `control`, `on_failure` or `tamper`.

## Surfaces changed
- RFC 0007 section 4, one sentence (R1). It is a rule for content on the `grdr-schema` mechanism, not an item of its Rust API, so the crate's class, `experimental`, and section 11's table do not change.
- No spine text, type, format, refusal, rendered form, token id, protobuf package, Cedar schema, dependency or same-layer edge changes.

## Alternatives
- **Keep the sentence.** #383, #1994 and #1995 would wait on #1853's chain behind #448's RFC, the wait ruling D5 removed. Rejected.
- **The registering items write their own tokens**, as RFC 0009 sections 9 and 14 had it. `interface/**` belongs to the interfaces squad (#1853, Problem), and the token tree #1614 would block each of them. Rejected by ruling D5 and RFC 0009's constraint 5.
- **No blocking at all, with the check's first run naming the missing tokens.** After #1853 lands, a registered code with no token would fail every pull request until someone wrote it, which is what the blocking prevents. Rejected.
- **An amendments section inside the RFC 0007 file.** An accepted RFC never returns to `Review`, and its decided file differs from the reviewed blob only in `State:`, `Decision record:`, review links and the `Decision` section (RFC 0001, "Review binds the decision"; RFC 0008, constraint 4d). Rejected for a new RFC that names RFC 0007.
- **Every branch up to date before it merges.** RFC 0001 rejects it for the whole repository. R5 asks it only of the pull requests that can race with #1853. Rejected for R5.

## Drawbacks
- A code registered before #1853 lands has no token for that time. No surface renders it before #1613 and #1853 land.
- The RFC 0007 file still reads the old sentence. A reader finds this amendment through #1998, the items R3 names and this RFC's decision record.
- R5 costs a rebase and a gate run for a pull request in the window whose base `main` has moved past.

## Unresolved questions
None.

## Review
How review binds the decision (RFC 0001, "Review binds the decision"; ADR-0036):
- RFC 0010 decides no pinned path, so its decision adds no decision line and no file under `rfcs/evidence/`, and `rfcs/pins.toml` does not change.
- The lane is the one ADR-0038 gives a change to what RFC 0007 states: an amendment, a new RFC that names RFC 0007 (ADR-0038, "What this acceptance binds"; RFC 0007 section 11; `docs/design/30` section 3). It changes no file under `schema/codes/`, `crates/grdr-schema/` or `security/trust-core.paths`, so none of ADR-0038's other lanes applies.
- The review set is an amendment's, as ADR-0040 and ADR-0041 have it: the nine persona council seats once, on #1998; `eval-architecture`, from the `[kinds] rfc` row of `.claude/risk-tiers.toml` on the base; and `eval-api`, `eval-security` and `eval-adversarial`. At least one evaluator runs on the other model from the one in the metadata block (D-63, owner instruction 7).
- Each verdict and each seat comment gives the three role lines of RFC 0001 (#1798), as full 40-character ids:
  - `RFC file:` the blob of this file it read (`git rev-parse <commit>:rfcs/0010-code-tokens-before-the-token-check.md`), with the commit;
  - `Proposed text: none`, because no pinned path changes;
  - `Base:` the spine pin in force in `rfcs/pins.toml`, `a80859235e7a2a4444648d6fa8d389d78dde6be9`, SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`.
- RFC 0010 is decided only once #1982 has landed, because R3 reads RFC 0009's constraints 2a, 2b, 2h and 5, which #1982 commits in RFC 0009's Decision section.
- The decision rests on an `eval-architecture` pass on the blob it decides, with no fail by an evaluator of the set on that blob, and the chief architect checks that the seats commented on that blob. The file the decision commits differs from that blob only in `State:`, `Decision record:`, link lines under this section and the `Decision` section. It reaches `main` in `Review` before the commit that decides it (RFC 0001, "RFC states").

Verdicts and seat comments are linked below, one per line.
- `eval-api` (`claude-sonnet-5-5`, pass, three minors): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087252283
- `eval-architecture` (`claude-sonnet-5-5`, pass, five minors): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087264786
- `eval-adversarial` (`claude-opus-5-5`, pass, three minors): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087291118
- `eval-security` (`claude-opus-5-5`, pass, two minors): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087371885
- `persona-solo-dev` (seat 1, support): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087384235
- `persona-it-admin` (seat 2, support): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087384317
- `persona-soc-analyst` (seat 3, support): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087385145
- `persona-msp-operator` (seat 4, support): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087386717
- `persona-oem-partner` (seat 5, support): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087386468
- `persona-privacy-officer` (seat 6, support): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087387333
- `persona-contributor` (seat 7, support with changes): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087387093
- `persona-simplicity` (seat 8, support, one minor): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087388488
- `persona-intl` (seat 9, support, one condition): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087388753

## Decision
Accepted by the chief architect under D-61, on RFC file blob `74616992ad270de277a20272eeeffd5dc9858c91` (SHA-256 `6c1b9b809fddab5ebc67119d453aae0167cc57c8b2e2a7d04097e018eaa35ef5`), the reviewed text, with the spine pin in force (`rfcs/pins.toml`), blob `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`), as its base. [ADR-0044](../docs/decisions/ADR-0044-code-tokens-before-the-token-check-adopted-by-rfc-0010.md) records the decision.

This RFC decides no pinned path of `rfcs/pins.toml`, so this section holds no decision line, `rfcs/pins.toml` does not change, and no file is added under `rfcs/evidence/` (RFC 0001, "RFC states"; ADR-0036, "Evidence added in route"). `rfcs/0007-grdr-model-and-grdr-schema-slice-0-surface.md` is unchanged at blob `0c0a6745f04888bec8ef2e718352549f47181201`. The accepted file differs from `7461699` only in `State:`, `Decision record:`, the thirteen review link lines above and this `Decision` section.

### Reasons
1. **Unblocks slice-0 `MODEL` items without dropping token validation.** Amending one sentence of RFC 0007 section 4 ("Content, not surface", third bullet) applies the interfaces-item blocker only once `#1853`'s token check (R2) is on `main`. Before then, `#1853` R1 writes the tokens of every code registered when `#1853` is worked, so `#383`, `#1986`, `#1994` and `#1995` do not wait behind `#1613`, `#449`, `#1612` and `#448`'s RFC, while nothing renders code tokens before `#1613` and `#1853` land (RFC 0009 constraint 5; D-69, P17).
2. **Closes the non-strict ruleset race.** Because `main`'s ruleset (`strict_required_status_checks_policy: false`) does not require a branch to be up to date before merge (RFC 0001, "What holds the rule"), R5 orders `#1853`'s pull request and every open code-registering pull request during `#1853`'s open-PR window without imposing a repository-wide up-to-date-branch rule. R5 is a temporary operational rule binding the orchestrating session for that window, not a change to RFC 0007 or `grdr-schema` (explaining why Summary and Surfaces changed omitted it; Constraint 8).
3. **Keeps RFC 0007 immutable and scopes the amendment.** RFC 0007 stays accepted and unedited (RFC 0007 section 11; RFC 0001, "RFC states"). `grdr-schema` stays `experimental`, the token ids `code.<area>_<nnnn>.message` and `.fix`, `eval-ux` and `impl-l10n` review under D-69, and `/codes/<code>` pages through `#1636` all stay unchanged (R2, R4).
4. **Prerequisite met and round 1 review.** `#1982` (RFC 0009 and ADR-0041) landed on `main` (`0fde8bc`). On `7461699`, all four required evaluators passed in round 1 with no blocker and no major (with `eval-api` and `eval-architecture` on `claude-sonnet-5-5`, the other model from the metadata block's `claude-opus-5-5`), and all nine persona council seats supported (seat 7 with changes, seat 8 with one minor, seat 9 with one condition). Under the exit rule (`#1828`), those round-1 minor findings and seat changes become binding constraints below.

### Review it rests on
On blob `7461699`, on `#1998`, each verdict and seat comment naming that blob, `Proposed text: none` and the base above:
- `eval-api` (`claude-sonnet-5-5`, the other model), pass, minors 1 to 3: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087252283
- `eval-architecture` (`claude-sonnet-5-5`, the other model), pass, minors 1 to 5: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087264786
- `eval-adversarial` (`claude-opus-5-5`), pass, minors m1 to m3: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087291118
- `eval-security` (`claude-opus-5-5`), pass, minors 1 and 2: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087371885

All nine persona council seats reviewed `7461699`, with none reporting a broken spine floor (P8, D-51, D-31):
- seat 1 (`persona-solo-dev`), support (notes row 2 p0 exit): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087384235
- seat 2 (`persona-it-admin`), support: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087384317
- seat 3 (`persona-soc-analyst`), support: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087385145
- seat 4 (`persona-msp-operator`), support: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087386717
- seat 5 (`persona-oem-partner`), support: https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087386468
- seat 6 (`persona-privacy-officer`), support (notes P8 reliance after `#1853` lands): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087387333
- seat 7 (`persona-contributor`), support with changes (two changes): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087387093
- seat 8 (`persona-simplicity`), support (one minor on explicit R5 lapse): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087388488
- seat 9 (`persona-intl`), support (one condition on `max` and `risk` fields): https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7087388753

The decision rests on the `eval-architecture` pass above, with no verdict on `#1998` failing `7461699`.

### Session rulings it relies on
1. The exit rule, https://github.com/416rehman/Guardrails/issues/1828#issuecomment-7074036273:
   > An RFC is decided after the first round in which no evaluator reports a blocker or a major. Minor findings from that round, and changes asked by seats that support with changes, do not open another round. They are written into the decision as constraints, each tied to the issue that builds the surface, which must meet it. Every gate stays: each required evaluator must pass on the decided blob, and trust core still needs two models.
2. RFC 0009 constraint 5 (`#1982` / `#2004`, rulings D5 and E4; `#1998` comment `7095847020`, https://github.com/416rehman/Guardrails/issues/1998#issuecomment-7095847020):
   > `#383`, `#1986`, `#1994` and `#1995` are blocked by this item while RFC 0010 is in `State: Review` on `main`. When RFC 0010 is decided: if accepted, closing this item unblocks those four items under RFC 0010 R1 to R5 (and R3 covers `#1986` alongside `#383`, `#1994` and `#1995`).

### Constraints
Each constraint binds the issues or roles named after it. Where a constraint clarifies or narrows the reviewed text above (including extending R3 to `#1986` and supplying Failure mode row 3's exit), the constraint wins for the items it binds.

1. **R3 covers all four `MODEL`-registering items (`#1998` comment `7095847020`, `eval-architecture` minor 2, `eval-api` minor 1, `eval-adversarial` m2).** R3 applies to all four items: `#383` (`GRDR-MODEL-0001` to `0005`), `#1995` (`GRDR-MODEL-0006`), `#1986` (`GRDR-MODEL-0007` to `0009`), and `#1994` (`GRDR-MODEL-0010` and `0011`). None is blocked by `#1614` or `#1853`; closing `#1998` upon merge of its decision pull request unblocks all four items from `#1998` (they must not be unblocked before `#1998` merges). `#1853` R1 writes the `code.<code>.message` and `code.<code>.fix` tokens for every `GRDR-MODEL` code registered when `#1853` is worked, with the text of RFC 0009 constraints 2a, 2b and 2h and RFC 0007 constraint 2f, judged by `eval-ux` there. Binds `#383`, `#1986`, `#1994`, `#1995` and `#1853`.
2. **Exit for Failure mode row 3 when `#1853` lands before a registering item (`eval-api` minor 1, `eval-architecture` minor 1, `eval-adversarial` m2).** `#1853` is not linked as blocked by `#383`, `#1986`, `#1994` or `#1995`, because blocking `#1853` on `#1986` would stall `#1925` and `#427` behind `#1986`'s chain (`#17`, `#394`, `#284`). Instead, if `#1853` (and its R2 check) lands on `main` before any of `#383`, `#1986`, `#1994` or `#1995`, or for any later code registered after `#1853` lands without tokens (Failure modes row 3), RFC 0007 section 4 as amended by R1 applies: the lead of the first affected registering item whose pull request meets the landed check files an `interfaces` item (`squad:interfaces`, at the registering item's priority, `priority:p0` for slice-0 `MODEL` items) to write the missing `code.<code>.message` and `code.<code>.fix` tokens in `interface/strings/src/code.mf2.toml` (with RFC 0009 constraints 2a, 2b and 2h and RFC 0007 constraint 2f) and blocks the unlanded registering item(s) by it (or, where `lead-interfaces` accepts the write-set line under RFC 0007 section 4's first clause, the registering item writes its own tokens in the same pull request). Failure mode row 3 takes this exit. Binds `#1853`, `#383`, `#1986`, `#1994`, `#1995` and their leads.
3. **R5 path trigger, open items at decision time, and lapse condition (`eval-api` minor 3, `eval-architecture` minor 4, `eval-adversarial` m3, `eval-security` minor 1, `persona-simplicity` minor).**
   - While `#1853`'s pull request is open, "a pull request that registers a code" is defined by path diff against `origin/main`: `git diff --name-only origin/main...<head> -- schema/codes/` is non-empty (equivalently `git diff --quiet origin/main...<head> -- schema/codes/` exits 1). This path rule applies to every code area (`MODEL`, `FASTPATH`, `RETRY`, `KIT`, `GATE`, `SUPPLY`, `STORE`, `DAEMON`, `SANDBOX`, `LOCAL`, `REVIEW`, `HOOK`, `AGENT`, `CFG`, `LIMITS` and any item filed later).
   - At decision time, the open items naming `schema/codes` or slice-0 code registration in scope are `#383`, `#1986`, `#1994` and `#1995`, alongside `#278`, `#279`, `#370`, `#667`, `#1028`, `#1742`, `#1829`, `#1968` and `#1978` (plus `#1925` and `#427` if any pull request touches `schema/codes/`).
   - At `#1853`'s merge, the orchestrating session also inspects all still-open pull requests (`gh pr list --state open --json number,files`), posts the R5 constraint on any open pull request touching `schema/codes/` that does not yet carry it, and holds each to rebase onto `origin/main` and re-pass checks before merging.
   - R5 lapses permanently once `#1853`'s pull request has merged AND every pull request touching `schema/codes/` that was open during `#1853`'s open-PR window has either merged (on a head containing `#1853`'s merge commit) or closed; after that, no session runs R5's `merge-base` check. Binds `#1853`, the open code-registering items and the orchestrating session.
4. **R5 serial merge order, check timing, post-merge `main` check and row 2 causes (`eval-api` minor 2, `eval-architecture` minor 3, `eval-adversarial` m1, `eval-security` minor 2).**
   - While `#1853`'s pull request is open, `#1853`'s pull request and every pull request matching Constraint 3's `schema/codes/` diff test merge **one at a time**, never in parallel subagents or the same parallel batch (`grdr-work-issue`'s parallel-issues batching does not apply within this set during the window).
   - For each merge in the R5 set: (a) wait for `gh pr checks <pr> --watch` on `<sha>`; (b) as the last check immediately before `gh pr merge <pr> --squash --match-head-commit <sha>`, run `git fetch origin main` requiring exit 0, confirm `origin/main` matches the live server tip (`gh api repos/416rehman/Guardrails/git/ref/heads/main --jq .object.sha`), and run `git merge-base --is-ancestor origin/main <head>` requiring exit 0; (c) if `origin/main` is not an ancestor, rebase onto `origin/main`, re-run CI gates and the pull request's required evaluators on the new head (`grdr-work-issue` / ADR-0043: `schema/**` is high tier, so Drawbacks also includes re-running required evaluators, not only CI), and repeat; (d) after `gh pr merge` succeeds, inspect the `verify` push workflow run on `main` (`verify.yml`) before starting the next merge in the set, and if `main` fails the token check, halt merges in the set and open the `priority:p0` interfaces exit of Failure modes row 2.
   - Interleaved or parallel merges in the R5 set, a stale local `origin/main` from an unchecked fetch, or an out-of-session merge are recorded as causes of Failure modes row 2. Binds `#1853` and the orchestrating session.
5. **Temporary contributor notice in `CONTRIBUTING.md` while `#1853` is open (`persona-contributor` seat 7, change 1).** When `#1853`'s pull request opens, `lead-security` (owner of `CONTRIBUTING.md`, `.claude/owners.toml`) adds one line to `CONTRIBUTING.md` (naming `RFC: 0010` if `rfc-required` is active) explaining that while `#1853`'s pull request is open, a pull request changing `schema/codes/` may be asked to rebase onto `main` before merge under R5 because `main`'s ruleset does not require up-to-date branches, and removes that line once R5 lapses under Constraint 3. Binds `lead-security`.
6. **Contributor next-step options in `#1853` R2's check diagnostic (`persona-contributor` seat 7, change 2).** When `#1853` R2's `grdr-interface-gen` check fails on a registered active code with a missing `message` or `fix` token in a shipped locale, the check's message must name the code, the locale, and both contributor paths with the exact token file path: either add the two source-locale tokens in `interface/strings/src/code.mf2.toml` (as RFC 0007 section 4 allows, reviewed by `eval-ux`) or open/link an `interfaces` work item (`squad:interfaces`) to write them. Binds `#1853`.
7. **Length budgets and safety metadata on `#1853` R1 tokens (`persona-intl` seat 9 condition).** `#1853` R1 preserves `max` and `risk` (`risk = safety`, alongside `desc` per RFC 0007 constraint 2f and RFC 0009 constraint 2h) on every `code.<area>_<nnnn>.message` and `code.<area>_<nnnn>.fix` token written for every registered code (including `GRDR-MODEL-0001` to `0011`), keeping `en-XA`, `ar-XB` and `ja-XC` checks active from day one. Binds `#1853`.
8. **R5 scope relative to Summary and Surfaces changed (`eval-architecture` minor 5).** Summary and Surfaces changed remain identical to reviewed blob `7461699` and omit R5 because R5 adds no change to RFC 0007 or `grdr-schema`; R5's orchestrator merge-order obligation and lapse condition live in this Decision section and ADR-0044. Binds the orchestrating session and readers of this RFC.
