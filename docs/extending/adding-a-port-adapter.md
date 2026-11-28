# Adding a Port Adapter

Storage, message bus, blob store, job journal, sandbox, and OS sensor backends implement stable traits declared in `crates/grdr-ports` (`Layer 2`) inside dedicated `Layer 3` crates.

## Requirements

1. Declare `[package.metadata.grdr]` (`layer = 3`, `privilege = "none"` or audited trust-core tier, `surface = "internal"`, `renders = "none"`) in the adapter `Cargo.toml`.
2. Register the crate in `contracts/architecture.toml` and all error codes (`GRDR-<AREA>-<NNNN>`) in `contracts/codes/registry.toml`.
3. Depend on `grdr-crypto` instead of adding external cryptographic crates.
4. Pass the full conformance suite exported by `crates/grdr-ports-testkit` (`assert_blob_port_contract`, `assert_job_port_contract`, `assert_events_port_contract`, `assert_bus_port_contract`, `assert_relational_store_contract`).
5. Validate SPDX licence headers (`scripts/licence-lint.mjs`), dependency allow-list (`cargo deny --config security/deny.toml check`), and architecture rules (`node scripts/check-architecture.mjs`).
