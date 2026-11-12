# <Capability>: specification for #<n>

- Squad: <id>   Size: XS | S | M   Risk floor: low | medium | high
- Requires: <#n, components, decisions or external preconditions | nothing>
- Spine: D-nn, Pn   Design: docs/design/<NN> section <k>
- Surfaces added: <none | name, stability class>   RFC: <nnnn | not required>

## Problem
Two sentences.

## Non-goals

## Behaviour
Normative statements, one per line, numbered R1, R2, ...

## Interfaces
Protobuf messages, CLI commands and output, files, configuration keys.

## Mechanism (P14)
The port, pack, manifest, configuration key, registry or plugin seam this extends, and the
product's own behaviour as default content or configuration on it. No host, name, bound or
string that is not data (owner instruction 26).

## Data classes (P8)
Fields read and written, with their data_class; capture level that applies.

## Failure modes (P9, D-15)
| Failure | Declared outcome | Visible as |

## Assurance effect (P1)
Changes to visibility, control, on_failure or tamper for which action classes; "none".

## Acceptance criteria
| ID | Given, when, then | Oracle (independent of the code under test) | Command |
These rows become the issue's acceptance-criteria section (section 6.4), which the
ready.v1 digest covers; held-out scenarios go to the evaluator.

## Write set
Exact path globs.

## Open questions
Each with the experiment that settles it.
