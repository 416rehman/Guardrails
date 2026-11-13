# ADR-0005: Five layers, the initial crates, and a module becomes a crate on its second consumer

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: section 5, P5, P6, P17
- Requires: nothing
- RFC: not required: restates section 5 as repository mechanism
- Work items: [WI-0001], [WI-0003]

## Context
One core has to run in the sensor, the proxy, the server and other vendors' products (P5), so dependency direction must hold mechanically. The simplicity review found that a crate per concept made the workspace unreadable (l10).

## Decision
The workspace has five layers: 0 schema, 1 core, 2 ports and shared libraries, 3 adapters, 4 programs. A unit depends only on lower layers and on the same-layer edges `architecture.toml` lists; adapters reach each other only through layer 2. `design/03` section 2 lists twenty-four initial crates. [WI-0001] creates twenty-two of them and [WI-0041] the other two, `grdr-strings` and `grdr-messages`, with the interface system. A module becomes its own crate when it gains a second consumer or a different licence. Layers 0 to 2 plus `grdr-ffi` and `grdr-wasm` are the public crates.

## Enforced by
`cargo xtask archlint` rules ARCH-001 to ARCH-026 over `architecture.toml` and `cargo metadata`, each with a fixture and a message that states the fix. `[package.metadata.grdr]` in each manifest carries layer, privilege, surface and squad, and `kit check` compares it with the crate's `AGENTS.md`.

## Consequences
A new dependency edge is a change to `architecture.toml`, a protected path, and so its own reviewed item. Splitting a crate early needs a reason the lint can read.

## Alternatives rejected
- One crate per concept from the start: about sixty crates before any had a consumer.
- Layering by convention and review: reviews miss transitive edges.

## Revisit when
The workspace passes forty crates, or a clean full verify exceeds its time bound because of crate count.
