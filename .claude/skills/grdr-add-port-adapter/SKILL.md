---
name: grdr-add-port-adapter
description: Implement a store, bus, blob, sandbox or sensor back end behind a port. Use for any item that adds or changes a port adapter.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: grdr-ports-testkit (design/03 E1)
  closes-by: test
---

# Implement a port adapter

Every external dependency sits behind a port trait in `grdr-ports` (P6). An adapter implements one
trait in its own layer 3 crate, passes `grdr-ports-testkit` against the reference in-memory adapter, and
states the kit version it passed. The kit, not your own tests, decides whether the adapter is correct.

The item is issue `#<n>`, where `<n>` is `GRDR_WORK_ITEM`. Read it with `gh issue view <n> --comments`;
its write set and tier are in `.agent/state/item-<n>.json`, which `cargo xtask kit launch` wrote (skill
`grdr-start-item`).

## Profile adapter or contrib adapter (P6; design/03 section 6)

| | Profile adapter | Contrib adapter |
|---|---|---|
| Lives in | This repository; compiled into `grdr-server` or the sensor | The `grdr-contrib` repository: one directory with an `OWNER` file naming a person, the kit version it passed and a `dist.toml` snippet |
| Gates a release | Yes | Never. Tier 2; removed after two red releases |
| Limit | At most two release-gating adapters per port per profile; for endpoint ports, per operating system | None |

If the item would add a third release-gating adapter for a port in one profile, stop with status
`impossible`: the spine forbids it, and only an RFC can change that.

## The ports

- Server (design/20 section 3): Relational, Events (with `QueryIr`), Bus, Blobs, Jobs, Keys.
- Endpoint (design/03 section 6): `SensorBackend` (described by a `HostProfile`), `Actuator`,
  `SandboxBackend`, `KeyStore`, `UpdateTrust`, `Clock`, `Entropy`, `Meter`, `JudgeBackend`, `SecretStore`.

## Steps

1. A new adapter is a new crate: follow `grdr-scaffold-crate` (`cargo xtask new-crate`), at layer 3,
   with the privilege of the program that links it.
2. Read `crates/grdr-ports-testkit/AGENTS.md` and the trait first. Implement the trait exactly as
   `grdr-ports` defines it. If a method you need is missing, do not add a side channel or a downcast: a
   trait change is a change to a public crate (layer 2), an RFC and a new kit version (D-61). Stop,
   file the trait change as a `status:proposed` issue (skill `grdr-handoff`) and hand off `blocked`.
3. Keep to the architecture rules that `verify` checks (design/03 section 2):
   - the driver crate (database, bus, object store) appears only in this adapter crate (ARCH-005);
   - no dependency on another layer 3 crate (ARCH-002); a shared type moves to layer 2, by RFC;
   - every relational, lake, bus, blob and cache method takes the `TenantCtx` it is given, and no query
     or object key is built outside the adapter crate (ARCH-015). Never construct a `TenantCtx`: only the
     authentication middleware and the job runner mint one;
   - cryptography only through `grdr-crypto` (ARCH-006); time and randomness only through `Clock` and
     `Entropy`;
   - every queue, cache, batch and buffer has a bound in `limits.toml`. That file is protected, so new
     keys go in `protected_change_requests`;
   - errors carry `GRDR-<AREA>-<NNNN>` codes registered in `grdr-schema`. `unsafe` only in OS adapter
     crates, each block with a `// SAFETY:` comment;
   - a connection, lease, retry or migration life cycle is an explicit state type, never a set of
     flags or a status field (skill `grdr-structure`, check S4).
4. Run the kit from the adapter crate's tests (`cargo nextest run -p <crate>`), in the way the kit's
   `AGENTS.md` describes: semantics, crash points, tenant-context enforcement and differential runs
   against the reference adapter. Every case passes. A case the kit skipped is reported as not verified,
   never counted as a pass (P9).
5. Back-end specifics:
   - an Events adapter implements all six `QueryIr` node types (design/20 section 3);
   - a sandbox back end also passes the sandbox conformance suite (D-21);
   - a sensor back end describes what it observes in a `HostProfile` (event classes with provenance
     grade, session mechanism, actuator verbs) and runs the scenario pack. It never claims a provenance
     grade the OS does not give;
   - a back end for another operating system is tested through `grdr-matrix-run`, never approximated
     on the system you are on.
6. State the kit version the adapter passed in the hand-off `summary`, and for a contrib adapter in its
   directory beside `OWNER`.

## Changing an existing adapter

- The kit must still pass in full; a change that needs a kit case relaxed is a kit change, not an
  adapter change. Hand off `blocked`.
- A change in what a server adapter stores or how it keys objects needs a migration path for data
  already written (design/20). If the item does not describe one, hand off `blocked` with the question
  in `next`.

## Trust core and tier

Tenant context and row-level security are trust core (D-63), as are `grdr-sandbox-engine`,
`grdr-crypto` and every crate in the privileged daemon's closure. `cargo xtask risk` gives the tier. A
trust-core item needs a reference model with differential tests, matrix and soak evidence, and
two passing evaluators on different models (owner instruction 7). If the item does not provide for that, hand off `blocked`.

Finish with `cargo xtask verify --fast` and `grdr-handoff`.

## Commands this skill names

A command that has not landed yet shows as an unknown subcommand.

| Command | Added by | Until it exists |
|---|---|---|
| `grdr-ports-testkit` | design/03 E1 (reference adapters and kit); the empty crate comes with WI-0001 | No adapter can be accepted without the kit. Hand off `blocked`, naming E1 in `next`; do not write a stand-in conformance suite inside the adapter |
| `cargo xtask new-crate` | No work-item id reserved yet; see `grdr-scaffold-crate` | Follow `grdr-scaffold-crate` |
| `cargo xtask verify --fast` | WI-0002 | Follow `grdr-verify` |
| `cargo xtask risk` | WI-0007 | Compare changed paths with `security/trust-core.paths`; if unsure, treat the change as high tier |
