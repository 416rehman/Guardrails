---
id: server-profiles
type: how-to
personas:
  - operator
shapes:
  - self-hosted
covers:
  - embedded
  - ha
  - distributed
  - preflight
  - migrate
owner_squad: platform
stability: beta
title: Server Storage Profiles and Migrations
---

# Server Storage Profiles and Migrations

`grdr-server` supports three storage topologies (`--profile`):

| Profile | Relational Store | Event Bus Adapter | Object Store | Primary Use Case |
| --- | --- | --- | --- | --- |
| `embedded` | SQLite (`grdr-rel-sqlite`) | Relational WAL log (`grdr-bus-log` / `sqlite-log` in `contracts/support.toml`) | Local filesystem | Single-node self-hosted and developer setups |
| `ha` | PostgreSQL 18 (`grdr-rel-postgres`) | Relational WAL log (`grdr-bus-log` / `postgresql-log` in `contracts/support.toml`) | Local or S3-compatible object store | High-availability multi-replica team clusters |
| `distributed` | PostgreSQL 18 (`grdr-rel-postgres`) | NATS JetStream (`grdr-bus-nats` / `2.15.2`) | AWS S3, GCS, Azure Blob, SeaweedFS, or Ceph RGW | Large enterprise fleets and regional SaaS cells |

## Preflight Verification

Run preflight checks before starting or upgrading a deployment profile:

```powershell
cargo run -p grdr -- server preflight --profile ha --strict --json
```

Preflight validates disk headroom, PostgreSQL/NATS connectivity where configured, object-store readiness, and sensor skew constraints (`-2` / `+1` minor versions per `contracts/support.toml`).

## Schema Migrations

Preview and execute deterministic, lock-fenced schema and object migrations prior to rolling traffic:

```powershell
cargo run -p grdr -- server migrate --from-data-dir ./grdr-data --target-bucket-dir ./grdr-object-store --dry-run
cargo run -p grdr -- server migrate --from-data-dir ./grdr-data --target-bucket-dir ./grdr-object-store
```

Consult [RB-02 Upgrade and Rollback](../../runbooks/RB-02-release-upgrade-rollback.md) before hopping minor versions.
