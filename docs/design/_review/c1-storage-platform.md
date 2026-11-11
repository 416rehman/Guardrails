# C1 review: storage and platform (D-33, D-34, D-35, P6)

Reviewed 2026-11-10 against draft 1. Numbered references are `research/` briefs. Cloud prices are recalled list prices.

## Summary

The direction holds: a Parquet lake on object storage beats DuckDB plus ClickHouse on dependencies, Windows support and tenant isolation. But D-34 names an engine and leaves us owning an unnamed table format and an undefined hot tier, with no answer for erasure, key coverage, backup or the endpoint-local store. Its sizing basis contradicts brief 24 by a factor of 20, and its "three dependencies in HA" rests on a misreading of OpenObserve. The change that matters most: rewrite the Events and Bus rows to adopt an existing table format (DuckLake layout through DataFusion), make the bus the only write-ahead log, and gate both on a spike run at 5,000 and 100,000 events per endpoint per day.

## Findings

### F1 (blocker, missing). D-34 Events: no table format and no hot tier

**Problem.** DataFusion supplies query execution only. "Parquet segments with a Postgres catalogue" means we write the catalogue, commit protocol, flush, compaction, orphan collection, deletes, schema evolution and repair tooling. Nothing says how an event becomes queryable within 60 s (g10 section 3). Flushing per organisation each minute, for 10,000 ten-endpoint organisations, is 14.4 million PUTs a day (about $2,160 a month) against about $270 a month to store their data.

**Evidence.** 11 section 1 (DuckLake: SQL catalogue in SQLite or Postgres, inlining) and verification row 2. Checked today: `datafusion-contrib/datafusion-ducklake` (Apache-2.0, 0.9, alpha) reads and writes both catalogues; DuckLake documents compaction, snapshot expiry, file rewrite and per-file Parquet encryption keys.

**Amendment.** Replace the Events row: "DuckLake-layout tables (Parquet plus SQL catalogue: SQLite embedded, Postgres scaled), written and queried through DataFusion; DuckDB is a supported external reader. A bespoke catalogue is the fallback if S1 fails." Add: "`store` consumes the bus, holds an Arrow memtable per organisation, serves tail reads to `query`, flushes at 32 MB or 10 minutes, and compacts to at most 8 objects per organisation, class and day. The catalogue keeps per-file minimum and maximum session and device ids. Session summaries and artefact inventory (device by digest, first and last seen) live on the relational port, so list views and indicator retro-matching never scan the lake. User SQL runs with DDL disabled, per-query limits, and only the caller's organisation registered."

### F2 (blocker, wrong). D-34 revisit trigger and D-36: event volume is unreconciled

**Problem.** The spike targets assume 5,000 events per endpoint per day (g10's assumption). Brief 24, which D-34 cites, estimates about 100,000 (P95 250,000), most of it the OS events D-13 needs for cross-checking. At 10,000 endpoints the 30-day hunt is 1.5 billion rows on one basis and 30 billion on the other. A spike passed only at the lower figure proves little.

**Evidence.** 24 section 6 and verification row 10 ("plus or minus 3x until a pilot measures it"); g10 weak points (a two-week capture "should precede any pricing").

**Amendment.** D-36: "Target 5,000; storage and bus are designed and tested to 100,000 events per endpoint per day." D-34 revisit: "Targets must hold at both volumes: session timeline under 2 s at both; 30-day aggregation under 10 s at 5,000 and under 60 s at 100,000, rollups permitted." Run S0 before S1.

Cost per endpoint-month at 13-month retention: 117 MB and $0.003 of object storage at 5,000 a day; about 2 GB and $0.045 at 100,000. A cell floor of $1,500 to $3,000 a month (g10 section 1) is $1.50 to $3.00 per endpoint at 1,000 endpoints and $0.03 to $0.06 at 50,000. Cell fill sets cost per endpoint.

### F3 (major, missing). D-34, D-35, D-39, D-46: deletion, holds and key coverage

**Problem.** Day partitions handle time retention only. Not covered: per-class retention, subject erasure, scoped legal hold, and erasure against sensor hash chains. "Per-organisation keys" cannot mean a KMS key each (about $1 per key-month roughly doubles a free organisation's cost), so encryption is application-level, and D-35 does not say that Postgres rows, the bus, search indexes and backups sit outside a crypto-shred.

**Evidence.** 34 lines 85 and 93 (per-class retention; erasure with hold exceptions); 11 verification row 4 (NATS account stores share one server store); 23 tlog-tiles (pruning needs a published policy).

**Amendment, new D-35a.** "Partition by organisation, data class and day. Captured content is stored apart from event rows under a per-session key with its own retention. Human identifiers are pseudonymised at ingest through a relational map; erasure deletes the map entry and shreds content keys, with a rewrite job for free-text columns. File keys are wrapped by the organisation key. Integrity chains commit to salted per-event digests and the verifier accepts signed tombstones. Holds are catalogue pins checked by every delete path. A published table states which stores each key mode covers."

### F4 (major, wrong). D-34 Bus: NATS as a mandatory data bus in HA

**Problem.** D-34 cites OpenObserve, but OpenObserve uses NATS as a "cluster coordinator", not as the event log, and both cited briefs keep a broker-free middle size. At 10,000 endpoints the bus averages 0.6k to 12k events per second, which Postgres absorbs as coalesced batch rows. NATS adds a third stateful system with its own disaster recovery and a full-disk failure mode.

**Evidence.** OpenObserve HA guide (checked today); 11 reference stack (b) ("PostgreSQL outbox; NATS optional"); 24 sizing ("embedded or small broker"); g10 sections 4 and 5.

**Amendment.** Bus row: "Embedded and HA: an append-only log on the relational port (SQLite file or partitioned Postgres table) with consumer offsets. Distributed: NATS JetStream." Text: "The bus is the only write-ahead log; `store` checkpoints its offset at flush. HA needs Postgres and object storage only." Settled by S2.

### F5 (major, wrong). D-34 contradicts D-06

**Problem.** D-34 stores "OCSF-shaped Parquet". D-06 rejects "storing OCSF or OTel names internally". A customer-readable lake makes column names a public contract, tied to OCSF 1.9 while the 1.10 objects we need are unreleased.

**Evidence.** D-06; 23 design implications ("never store OCSF or OTel names as the internal schema").

**Amendment.** "Lake columns are the canonical model flattened, versioned `guardrails.v1`, additive within a major, with Parquet field ids. OCSF 1.9 is a generated view and export driven by the D-06 mapping files."

### F6 (major, risky). D-34 embedded Events on endpoints: use SQLite

**Problem.** Standalone history runs inside `guardrailsd` (150 MB resident target) at about 3 MB of events a day. A flush and compaction cycle plus DataFusion in the daemon is over-built there, weak on point lookups and range deletes, and writes many small files under EDR real-time scanning on Windows. SQLite is already linked.

**Evidence.** Spine section 6; 23 recommendation (the spool is append-only segments, not Parquet); 11 section 2 (SQLite "the only boring choice").

**Amendment.** "Endpoint-local history and the flight recorder use SQLite (indexed columns, zstd payload, FTS5) behind a reduced typed query subset, with Parquet export. The lake's embedded form is for `guardrails-server` only and is supported on Windows x64 and ARM64." Settled by S3.

### F7 (major, missing). No decision on backup, restore and disaster recovery

**Problem.** A catalogue restored to time T over a later bucket references files that compaction or retention has deleted. Erased data survives in backups. The spine states no recovery objectives and no tooling.

**Evidence.** g10 section 5 and implication 6 (`backup` and `restore --verify` in the first self-hosted release).

**Amendment, new D-34a.** "Physical deletion lags logical deletion by at least the catalogue point-in-time window (default 7 days), with bucket versioning. `store` writes a signed per-organisation manifest to the bucket hourly so the lake can be rebuilt without Postgres. `grd server backup` and `restore --verify` ship at M2 for every profile. Recovery point and time: relational 5 minutes and 1 hour; events 15 minutes and 4 hours. Backup retention is bounded by the erasure deadline."

### F8 (major, missing). P6 and D-33: supported profiles are undefined

**Problem.** Six ports with two adapters each allow 64 combinations. D-33 says "two shapes" while admitting a third in brackets, which has its own requirements. No path from embedded to scaled is stated.

**Evidence.** 24 verification row A (Loki HA Monolithic needs a singleton compactor and shared state).

**Amendment.** P6: "At most two adapters per port, selected only through three named profiles: `embedded` (one process), `ha` (N replicas of `all`), `distributed` (one target per process). Any other combination fails at start." D-33: "Compaction, retention, rollout timers and content signing are singletons held by lease on the Jobs port. `grd server migrate` moves embedded to HA by copying files and the catalogue."

### F9 (major, missing). D-35: global tier and cell rules

**Problem.** Brief 24's `router` target is absent from D-33's list. Undefined: what is global, how large a cell is, how a Provider spanning cells queries, how an organisation moves.

**Evidence.** 24 section 2 (Sentry control silo, AWS cells), reference architecture (`router`) and sizing ("capped near 250k endpoints or a tested TB/day limit").

**Amendment, new D-35b.** "A `router` target, hosted service only, holds the directory (organisation to cell, region, provider membership) and redirects; it never carries events. Intel, the content repository and billing roll-ups are global; everything else is cell-local. A cell is one identical profile instance capped at a load-tested size, initially 50,000 endpoints. Provider views fan out per cell and merge on `org_id`; no cross-cell joins. An organisation moves by prefix copy and catalogue export."

### F10 (minor, over-built). D-34 Search, scaled adapter

**Problem.** "Tantivy segments on blob storage" is Quickwit's product, not a Tantivy feature; no brief evaluates it. Index segments hold plaintext terms outside Parquet encryption, and P8 leaves little full text by default.

**Evidence.** 11 section 1 (Quickwit "slow-moving"); 11 matrix recommended ClickHouse's text index instead.

**Amendment.** Search row: "Entities: SQLite FTS5, or Postgres full-text and trigram. Events: scans through the lake. Opt-in captured content: Tantivy per organisation on local disk, rebuilt from the lake. Object-storage search is deferred until S1 shows scans miss the hunt target." Lost: sub-second free-text search over captured content at fleet scale.

## Spikes

| Id | Question | Method | Pass |
|---|---|---|---|
| S0 | What is the real volume? | Prototype sensor filter on at least 10 developer machines, three operating systems, two weeks. Record events per endpoint per day (p50, p95), bytes per event, compression ratio. | p95 at or below 20,000 and 5 MB compressed a day; otherwise restate D-36 and resize S1. |
| S1 | Does the lake meet its targets, and in which form? | Generator calibrated by S0 at 5,000 and 100,000 per day; one 10,000-endpoint organisation plus 2,000 five-endpoint organisations; 30 days. Arms: bespoke catalogue, DuckLake layout through DataFusion, ClickHouse baseline. Measure: acknowledgement p99 and loss on `kill -9`; freshness p99; timeline p95 for sessions aged 1 minute to 30 days; 30-day aggregation and substring scan; objects and PUTs per organisation-day; catalogue commit conflicts; one-subject erasure time; catalogue restore to an hour earlier; embedded profile on Windows x64 and ARM64 with Defender on; cost per endpoint-month. | Zero acknowledged loss; freshness at or below 60 s; F2's latency targets; at most 8 objects and 200 PUTs per organisation-day; no dangling references after restore; under $0.05 per endpoint-month excluding models. |
| S2 | Can Postgres carry the bus in HA? | 10,000 endpoints at four times peak, both volumes, three `all` replicas; fail the primary mid-run. | Acknowledgement p99 under 200 ms; detection lag p99 under 5 s; no acknowledged batch lost. |
| S3 | SQLite or lake on the endpoint? | One device-year at both volumes inside `guardrailsd` on Windows (Defender on), macOS, Linux. | Daemon under 150 MB resident; timeline p95 under 200 ms; range delete and full-text search work. |

## Agreed

- DataFusion as the embedded engine: pure Rust, builds on Windows; chDB ships no Windows artefact (11 verification row 1).
- Rejecting ClickHouse as a required HA dependency: two dialects, and row policies are not a tenant boundary (24 section 2).
- Object storage as the system of record: under five cents per endpoint-month at either volume.
- Real-time detection on the bus, never on the store; edge tables, no graph database.
- Organisation id from the device credential, with forced row-level security.
- Jobs as a step journal on the relational port, after evaluating apalis (11 verification row 6).
