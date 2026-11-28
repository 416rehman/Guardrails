# Lab 2: Operator Split-Plane, Recovery Drills, and SaaS Cells

## Objectives

1. Launch `grdr-server` with split Console (`--bind 127.0.0.1:8787`) and Operator (`--operator-bind 127.0.0.1:8788`) bindings and verify startup rejects colliding sockets.
2. Run `cargo run -p grdr-daemon -- --self-test` and confirm OS peer IPC initialization with zero open TCP listeners.
3. Run `cargo run -p grdr -- server preflight --profile embedded --strict --json` and cross-check `upgrade-path.json` and `contracts/upgrade-path.json` against `lifecycle.toml`.
4. Inspect `crates/grdr-saas/tests/saas_ops_tests.rs` and run `cargo test -p grdr-saas --locked` to validate cell splitting (`[0, 4096)`), signed bundle roundtrips (`lake/` + `audit/`), and zero-variance billing reconciliation.
5. Walk through [FLEET-VERIFY.md](../runbooks/FLEET-VERIFY.md) and [RB-01](../runbooks/RB-01-cell-restore-and-dr.md).
