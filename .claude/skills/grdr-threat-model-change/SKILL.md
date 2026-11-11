---
name: grdr-threat-model-change
description: Threat-model a change. Use for high-tier items, trust-core paths, new IPC, new parsers, new network listeners and new privileges.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: none
  closes-by: test
---

# Threat-model a change

The register in design/02 is the threat model of the whole product. This skill maps one change onto it: which assets the change touches, who can reach it, which trust boundaries it crosses or adds, and which test proves each control. A threat model whose controls have no tests is a list of hopes.

Who uses it: a lead while specifying a high-tier or trust-core item (before it is readied), an implementer on such an item, and `eval-security` reviewing one. The item is GitHub issue `#<n>` (`GRDR_WORK_ITEM`); the threat model is posted on it as a comment (step 7). Evaluators put the same content in their verdict's `findings` and summary instead.

## 1. Scope

1. List the paths the change touches and the processes they run in (design/03 section 4).
2. Run `cargo xtask risk` on the diff (WI-0007) for the tier and its reasons. Until that command exists, classify by hand with `.agents/risk-tiers.toml` and `security/trust-core.paths`: the highest matching row wins, and say "classified by hand". A model may raise a tier, never lower it.
3. Note which of the triggers apply: high tier, a trust-core path, new IPC, a new parser or decoder, a new network listener, a new privilege.

## 2. Map onto design/02

- **Assets** (section 3.2, A1 to A9): which ones the change can read, change or make unavailable.
- **Adversaries** (section 3.3, ADV-1 to ADV-12): who can reach the changed code, starting from what. Always consider ADV-1 and ADV-2 (an over-eager or manipulated agent at user privilege) and ADV-4 (a local user).
- **Trust boundaries** (section 3.4, TB-1 to TB-15): which ones the change crosses, moves or adds. A new boundary needs its rule written the way the table writes them.

## 3. Walk every boundary crossing

For each crossing, answer with path and line:

1. **Untrusted input.** What enters, from whom, where it is validated, and the bound on its size and depth (`limits.toml`).
2. **Data that becomes instructions.** Any input that reaches a shell, a policy, a configuration writer, a model prompt or a log another tool parses.
3. **Parsed twice.** Any value two components parse separately. Two parsers can disagree, and the gap is a bypass: name the differential test that holds them together (SD-04).
4. **Where it is parsed.** No content parser in a privileged program or `grdr-hook` (ARCH-004); untrusted content is parsed in the sandboxed engine or the unprivileged proxy (SR-05).
5. **Who the peer is.** Peers are authenticated by kernel handle, never PID (SR-01). A local API lives in a privileged-owned location in the Protected profile (SR-02). Mutations from local surfaces are proposals (SR-04).
6. **Check, then use.** Anything checked and later used (a path, a hash, a digest, a PID, a peer) either re-checks at use or binds to a handle.

## 4. Failure behaviour

For each way the changed code can fail (error, timeout, panic, missing or expired configuration, unparseable input, unknown harness version, peer gone, resource limit, update in progress) state what the action receives: deny, allow or hold. Fail-open is a blocker unless the rule class declares `on_failure: open` (D-15), and an open outcome must raise Degraded and emit an event (P9). Silent fail-open is severity 1.

## 5. Privilege, secrets and models

- What can an unprivileged same-user process make the privileged side do?
- Can a secret or a content-class field reach a log, metric, crash report, support bundle or export? Logs take `LogSafe` values only; no secret on a command line (SD-11).
- Can any model or heuristic output allow, grant, declassify, suppress or clear anything (P2)? It may only restrict.

## 6. Requirements and tests

- List the existing SR and SD ids (design/02 sections 3.8 and 3.10) the change must keep.
- Propose new SR ids for controls the register lacks: wording, component, oracle and test id. `security/requirements.yaml` and `security/threats.yaml` are protected, so the proposal goes in the threat model and the hand-off's `protected_change_requests`.
- Name one test per control: a negative test from an unprivileged account, a fault-injection case, a differential fuzz target for a parser, a race test with injected delay for a check-then-use window. A control without a test id is listed under residual risks, not under controls.
- Trust-core changes also need a reference model with differential tests, matrix and soak evidence, and two passing evaluators on different models (owner instruction 7). Kernel components leave the internal ring only with the review D-62 sets.

The security power prompts M01 to M05 (team/04 section 8) cover fail-open paths, privilege crossings, untrusted parsing, check-then-use windows and model-verdict reach. Run them through `grdr-audit`; they check the code, they do not replace this model.

## 7. Write the output

Write it to `.agent/state/threat-model-<n>.md` and post it as a comment on the issue: `gh issue comment <n> --body-file .agent/state/threat-model-<n>.md`. A lead writing the spec links the comment from the spec section, so the item is readied with its threat model; an implementer links it from the hand-off's summary. A later revision is a new comment, never an edit of the old one. In this order:

```markdown
## Threat model #<n>: <change in one line>

- Tier: <tier> (<reasons>; classified by `cargo xtask risk` | by hand)
- Triggers: <high tier | trust core | new IPC | new parser | new listener | new privilege>
- Paths and processes: <list>

### Assets
### Adversaries
### Trust boundaries crossed or added
### Untrusted inputs
| Input | From | Validated at | Bound | Parsed where |
### Failure modes
| Failure | Outcome (deny, allow, hold) | Declared on_failure | Visible as |
### Privilege, secrets and model reach
### Security requirements
Kept: SR-nn, SD-nn. Proposed: wording, component, oracle, test id.
### Controls and their tests
| Control | Test id | Kind |
### Residual risks
### Reviews required
`eval-security` and `eval-adversarial` on Opus; cross-model review by the other of Opus and Sonnet; for trust core, two passing evaluators on different models (owner instruction 7).
```

Every claim cites `path:line` or a design section. Write "none" for an empty section rather than leaving it out, so a reader can tell "did not look" from "found nothing" (P9). A suspected vulnerability in existing code goes to private intake, never into this comment, the issue or any public text (D-62): hand off `blocked` as skill `grdr-handoff` describes.
