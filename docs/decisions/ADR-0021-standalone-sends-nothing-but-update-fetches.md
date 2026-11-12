# ADR-0021: Standalone sends nothing but update fetches

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-48, P8, P16
- Requires: nothing
- RFC: not required: restates D-48 as repository mechanism
- Work items: [WI-0036]

## Context
A developer who installs the product alone has no account and has agreed to send nothing. Air-gapped sites need the same guarantee for every shape (P16). A promise about network behaviour is only as good as the test that watches the wire (reviews l01, l06, c7).

## Decision
In the standalone shape the only outbound traffic is anonymous, mirrorable update fetches, which can be turned off. Reputation is matched on the device. `grdr egress` lists every destination the installation can contact, and `grdr server egress` does the same for the server. With `network.mode = "isolated"` every product process in every shape is held to the operator's allow-list and resolves no outside name. No endpoint has a compiled default: each is configuration behind a port.

## Enforced by
The `grdr egress` oracle: CI runs the standalone product in a network namespace that records every connection and DNS query and compares them with what `grdr egress` printed ([WI-0036]). ARCH-025 `one-dialer` fails a second outbound path. S-31 proves the isolated mode.

## Consequences
Any feature that would contact a service needs a port, a setting and a line in `grdr egress` before it can ship. Telemetry of our own is not possible in standalone.

## Alternatives rejected
- Opt-out usage telemetry: it breaks "nothing sent by default".
- A documented list of destinations with no test: documentation drifts.

## Revisit when
Never as a default; a new outbound destination is an RFC.
