# ADR-0027: Before the first signed release, the fleet guard is a tagged CI build in Watch

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-47
- Requires: [WI-0006] for the fleet image; the first signed release to end this arrangement
- RFC: not required: a reading of D-47 recorded in `team/06`, Deviations
- Work items: [WI-0006]

## Context
D-47 says the development fleet runs under the last signed release of the product. No release exists at bootstrap. The guard must never be the working tree, because an injected change could then weaken the guard that watches it (spine section 9, "injection into build agents").

## Decision
Until the first signed release exists, the fleet guard is a tagged CI build of the product, named by digest in the fleet image manifest and running in Watch. It observes and reports and enforces nothing. From the first signed release on, the fleet runs under the last signed release with the Essentials pack enforced, and this record is superseded.

## Enforced by
The fleet image manifest under `deploy/fleet/`, a protected path, which names the guard build by digest; `kit check` fails a manifest whose guard is not a tagged build or a signed release ([WI-0006]). Review only for the switch at the first signed release: `lead-release` files the protected-change item when release-please creates that release.

## Consequences
The fleet gets product findings on its own sessions early, with no risk of the guard blocking the team. Enforcement on the fleet waits for a release.

## Alternatives rejected
- No guard until a release: the product would not be used by its own builders.
- The working tree as the guard: the judged code would judge itself.

## Revisit when
release-please creates the first signed release.
