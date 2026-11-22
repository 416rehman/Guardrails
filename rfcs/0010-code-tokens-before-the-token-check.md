RFC: 0010
Title: RFC 0007 amendment 1: a code registered before the token check exists gets its tokens from #1853
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Review
Design issue: #1998
Spine: D-61, D-69, P17 (no spine text changes)
Surfaces: the public crate `grdr-schema` (layer 0), through one sentence of RFC 0007 section 4 ("Content, not surface"): when an item that registers an error code is blocked by the interfaces item that writes the code's tokens. No type, format, refusal, rendered form, token id, wire format, dependency, same-layer edge or Cedar schema changes
Decision record: none yet

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

## Decision
None yet.
