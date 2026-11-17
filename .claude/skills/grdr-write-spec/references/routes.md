# Routes for specifications, decisions and RFCs

Sources: spine D-61 and D-63; team/01 sections 5 and 6; team/06 sections 2 and 6; design/30 section 3 (the RFC process); owner instructions 5 and 6.

## When an RFC is required (D-61)

An RFC is required for a change to the following. The persona council and `eval-architecture` review it on its design issue and the chief architect decides; there is no waiting period (owner instruction 7):

- the spine, `docs/design/00-decisions.md`;
- a public crate: layers 0 to 2 (`grdr-proto`, `grdr-schema`, `grdr-model`, `grdr-core`, `grdr-fastpath`, `grdr-ffi`, `grdr-wasm`, `grdr-ports`, `grdr-crypto`, `grdr-wire` and the other layer 0 to 2 crates of design/03 section 2);
- a same-layer dependency edge in `architecture.toml`, at any layer (design/03 section 2);
- a wire format: `proto/grdr/**`, IPC framing;
- the Cedar schema under `schema/`.

The chief architect drafts it in `rfcs/NNNN-<title>.md` and is its author of record. An RFC always escalates (team/01 section 6). The item that implements it is not worked until the RFC is accepted: make it "blocked by" the RFC's issue.

## Files agents may not edit

The `deny` rules of `.claude/settings.json` keep agents from editing these. Post the proposed content as a comment on the item's issue, headed with the target path, and file the change as its own issue, named in your report.

| Target | Lands by |
|---|---|
| `docs/decisions/ADR-NNNN-<slug>.md` | The chief architect, through its own issue, after the decision it records is made |
| `specs/**` (Quint, Kani property statements) | its own issue for `lead-agent-kit` (gate configuration) or the chief architect (spine and plan), landed after `eval-security` and one evaluator on the other model pass (owner instruction 7); they approve every stated property |
| `spec/**`, `conformance/vectors/**`, `tests/golden/**` | its own issue for `lead-agent-kit` (gate configuration) or the chief architect (spine and plan), landed after `eval-security` and one evaluator on the other model pass (owner instruction 7); the item is high tier |
| `security/requirements.yaml`, `security/threats.yaml` (new SR or threat ids) | its own issue for `lead-agent-kit` (gate configuration) or the chief architect (spine and plan), landed after `eval-security` and one evaluator on the other model pass (owner instruction 7), from the threat model (skill `grdr-threat-model-change`) |
| `web/packages/ui/exceptions.toml` (an Astryx exception) | Its own item, landed after `eval-ux` and `lead-interfaces` both agree (skill `grdr-interface`) |
| `docs/design/**` | The RFC route |

## Decision records

- Status starts at `proposed`. Records are append-only: a changed decision is a new record that supersedes the old one, never an edit.
- Header fields (team/06 section 6.1): status, date, decided by (agents draft; the chief architect accepts), spine decisions, requires (components, work items, decisions or external preconditions, or "nothing"), RFC number or "not required" with the reason, work items as issue numbers.
- Sections: Context, Decision, Enforced by, Consequences, Alternatives rejected, Revisit when (a measurable trigger, not a date).

## Specifications in an issue

- The form's fields carry the header of team/06 section 6.2: squad, size (XS, S or M), risk tier, trust core, agent, write set. The spec section opens with requires (issues, components, decisions or external preconditions), spine decisions and design section, surfaces added with their stability class, and the RFC.
- Then: Problem (two sentences), Non-goals, Behaviour (R1, R2, ...), Interfaces (protobuf messages, CLI commands and output, files, configuration keys), Data classes, Failure modes table, Assurance effect, Write set notes, Open questions (each with the experiment that settles it).
- Acceptance criteria go in their own section, never inside the spec text, so evaluators judge exactly them.
- Held-out scenarios go to the held-out evaluator, never into the issue.

## Breaking an item down

- An item larger than size M becomes sub-issues, each a complete work item with its own write set and criteria. Order them with "blocked by", not with numbering in titles.
- Surprises an implementer finds come back as new issues, never as fixes inside the item. Specify them the same way.

## Who may write what

| Agent | Writes |
|---|---|
| `chief-architect` | `rfcs/`, decision-record drafts, issues and their labels; never code |
| `product-lead` | Product specs, item specs and acceptance criteria |
| `lead-<squad>` | Item specs, acceptance criteria, sub-issues, dependencies and labels; never code |
| `programme-manager` | Checks specs are complete and orders items (`priority:` labels) |

Leads never relax a spine floor (the P8 privacy floor, D-53 Essentials) to satisfy a persona, and every persona-council blocker gets a written disposition on the design issue.
