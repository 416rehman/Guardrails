# Fleet Verification Checklist (`GRDR-VERIFY-<YYYY-MM-DD>`)

Execute all three verification tracks after any regional failover drill, storage migration, or minor release rollout. Save the completed record as `GRDR-VERIFY-YYYY-MM-DD` attached to the change ticket.

## Track 1: Control Planes and Storage Integrity

- [ ] `grdr server preflight --profile <embedded|ha|distributed> --strict` exits `0` against the target deployment profile.
- [ ] `--bind` (Console/API) and `--operator-bind` (Operator plane) resolve to distinct socket addresses.
- [ ] `OperatorService` RPCs on `--operator-bind` require separate `--operator-token` credentials and emit immutable impersonation receipts.
- [ ] Lake and relational checksums pass after backup restore within `RPO <= 5m` and `RTO < 4h`.

## Track 2: Endpoint IPC, Fastpath, and Receipts

- [ ] `grdr-daemon --self-test` exits `0` with zero TCP/HTTP listeners bound.
- [ ] `grdr doctor` reports healthy OS peer-authenticated IPC and signed floor cache verification.
- [ ] `grdr check --action file.write --target .claude/settings.json` fails closed (`Block`) within latency SLO.
- [ ] `grdr audit verify --json` verifies hash-chained JSONL receipts without continuity breaks.

## Track 3: SaaS Cells, Reconciliation, and Security Watchers

- [ ] Contiguous shard bucket ownership across all active regional cells covers `[0, 4096)` cleanly with zero overlap or utilization above 70%.
- [ ] Sample organisation migration bundle export/import roundtrip succeeds and preserves active revocation grants and `kill_switch_epoch`.
- [ ] Monthly billing statement reconciliation holds `0%` variance (`<= 10 bps` drift tolerance) across statement file, Stripe, and Kill Bill adapters.
- [ ] Change freeze and operational bounds (`<= 25%` blast radius, `1` concurrent region) verified cleanly.
