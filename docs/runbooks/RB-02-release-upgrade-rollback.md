---
id: RB-02
actor: release-manager
rto: 30m
rpo: 0m
---

# RB-02: Release Upgrade and Minor Rollback

## Diagnosis

1. Inspect `lifecycle.toml` and `upgrade-path.json` for approved hop paths (`max_upgrade_minor_hop = 2`, `rollback_window_minors = 1`).
2. Check active endpoint versions against sensor skew policy (`2` minors behind to `1` minor ahead per `contracts/support.toml`).

## Actions

1. Execute `grdr server preflight --profile ha --strict --json` on the target cluster.
2. When schema revision changes, execute `grdr server migrate --from-data-dir <PATH> --target-bucket-dir <PATH> --dry-run` followed by live cutover prior to shifting control-plane traffic.
3. Roll server deployments canary-first under `docs/ops/bounds.toml` concurrency caps (`1` region at a time), monitoring Connect RPC error rates.

## Verification

- Verify `grdr doctor` and `grdr server preflight --profile ha --strict` pass on upgraded nodes.
- Verify endpoint hooks continue enforcing the signed local floor cache without fallback disruptions.

## Rollback

If error rates or p99 decision latency exceed SLO thresholds, roll server binaries back within `1` minor version (`rollback_window_minors = 1`) after pausing irreversible migrations.

## Escalation

Escalate to Platform Architecture if a schema compatibility bump forces emergency protocol negotiation changes.
