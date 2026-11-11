# Open-source building blocks for the server platform

_Researched 2026-11-09_

Method note: licence, version, archive and activity facts come from the GitHub API and crates.io queried on 2026-11-09 (marked **[GH]**). Docs pages were fetched directly (marked **[doc]**). The shared web-search budget ran out part-way through, so items marked **[memory]** are from prior knowledge and were not re-verified today.

## TL;DR

- **Write the server in Rust as one binary with role flags, behind five ports**: relational store, event store, bus, durable workflow, object store. Two adapters per port cover all four sizes: SQLite/DuckDB/in-process for laptop, PostgreSQL/ClickHouse/NATS for scale.
- **ClickHouse cannot be the laptop engine.** chDB's Rust binding supports Linux and macOS only, and its binding repo calls itself an "FFI example". DuckDB 2.0.0 (LTS, 2026-10-21, MIT) is the embedded engine; ClickHouse 26.10 (Apache-2.0) is the HA/SaaS engine.
- **Licence traps are everywhere.** Not OSI: Restate, SurrealDB, Memgraph, Pathway, Redpanda (BSL); FalkorDB, Inngest (SSPL); Flipt v2 (Fair Core); CockroachDB; TimescaleDB `tsl/`; n8n. OSI but AGPL (blocks embedding by EDR vendors): OpenObserve, Parseable, Zitadel, Tracecat, Shuffle, Lago, Loki, Garage, Citus, ParadeDB, Unleash, Windmill.
- **Several seeds died or moved in 2026.** TensorZero archived 2026-06-12. MinIO archived 2026-04-25. Envoy AI Gateway became Agent Router under the Agentic AI Foundation (September 2026). Tansu became Nisshi under Solace. Fluvio moved to a community org with no release since July 2025.
- **Kuzu's successors are thin.** LadybugDB (MIT, v0.22.3) is the only live fork; RyuGraph is stalled and Bighorn is archived. PostgreSQL 19 reverted SQL/PGQ before release. Store provenance as edge tables, not in a graph database.
- **LiteLLM was compromised twice on PyPI in 2026** (1.82.7/1.82.8 in March, 1.107.0 in October). Integrate with AI gateways; do not depend on one.
- **Cedar (Rust, Apache-2.0, 4.14.1) is the one authorisation engine that embeds in every size** and can serve both platform RBAC and agent-action policy.
- **rsigma (MIT, 0.26.0) is a Rust Sigma evaluator with correlation**, embeddable in-process. It has one dominant maintainer, so vendor it behind our own trait.
- **No durable-workflow engine fits all four sizes.** Temporal needs a cluster; DBOS for Rust is 0.6 pre-production and Postgres-only. Build a small DBOS-style step journal on our own SQL port.
- **connect-rust became the official Connect implementation for Rust in 2026** (crate 0.9.1, pre-1.0). Use protobuf plus buf as the contract and tonic for sensor streams until it hits 1.0.
- **Pingora is Linux-first** ("Windows support is preliminary"). Use hyper/rustls for anything that must run on endpoints.

## Findings

### 1. Event storage and analytics

- **ClickHouse** — Apache-2.0, v26.10.2 (2026-10-24) [GH]. Multi-tenancy docs recommend a shared table with the tenant column in the primary key plus row policies, and say this can handle "potentially millions" of tenants; separate tables or databases "doesn't scale for 1000s of tenants" [doc]. Text index is GA from 26.2 with `hasAnyTokens`/`hasAllTokens` [doc]. An official operator exists (Apache-2.0, v0.0.8, 2026-09-25, young) next to the mature Altinity operator (0.27.4) [GH]. No Windows server.
- **chDB** — Apache-2.0, v4.4.0. chdb-rust lists Linux x86_64/aarch64 and macOS only and downloads `libchdb` at build time [GH]. Rejected for laptop mode.
- **DuckDB** — MIT, 2.0.0 LTS supported to at least October 2027 [doc]. New in 2.0: Quack client-server protocol (`quack_serve`, `ATTACH 'quack:host'`), async I/O for Parquet and object storage, PEG parser. Files written by 2.0 are unreadable by older versions. `duckdb-rs` crate 1.20000.1 [GH].
- **DuckLake** — MIT, 1.0 in April 2026, 1.1 with DuckDB 2.0 [doc]. Catalog lives in SQLite, PostgreSQL, MySQL or DuckDB; small writes are inlined in the catalog (100,000 inlined rows commit in 0.13 s on PostgreSQL). No indexes, primary keys or unique constraints; upsert only via `MERGE INTO` [doc]. Fits laptop (SQLite catalog) and small install (Postgres catalog) with identical code.
- **Iceberg** — Apache-2.0, 1.12.0; `iceberg-rust` 0.11.0 (2026-11-03) [GH]. Use as an export and interchange format, not the primary store.
- **PostgreSQL with row-level security** — the control-plane store. PostgreSQL 19 was at RC1 on 2026-10-15; release notes list no RLS changes and no `GRANT`-level tenancy features beyond `GRANTED BY` [doc]. SQL/PGQ was reverted in beta 4 (secondary sources, September 2026).
- **VictoriaLogs** — Apache-2.0, v1.53.0; single zero-config binary and open-source cluster mode. Tenant is an `(AccountID, ProjectID)` pair of 32-bit integers set by header; it performs no per-tenant authorisation and has no object-storage backend [doc]. Good optional log sink, weak as system of record.
- **GreptimeDB** — Apache-2.0, v1.3.0, Rust [GH]. Credible alternative; smaller ecosystem than ClickHouse.
- **Quickwit** — Apache-2.0, v0.9.3 (2026-10-22, security patch); README still advertises 0.8; commits continue under Datadog [GH]. Treat as slow-moving.
- **OpenObserve, Parseable** — both AGPL-3.0 [GH]. Run-alongside only.
- **TimescaleDB** — Apache core plus Timescale Licence in `tsl/` [GH]. Avoid.

### 2. Embedded stores (single-binary mode)

- **SQLite** via `rusqlite` 0.41.1 (bundled) — public domain, the only boring choice [GH].
- **Turso** (Rust rewrite) — MIT, v0.8.3, still beta; MVCC `BEGIN CONCURRENT` is experimental. **libSQL** server last released 2025-02 [GH]. Watch, do not adopt.
- **redb** — Apache-2.0/MIT, v4.5.0, pure Rust B-tree. **fjall** — Apache-2.0/MIT, 3.1.13, pure Rust LSM [GH]. Either works for hot state (correlation windows, dedupe); redb is the simpler default.
- **RocksDB** — now at `meta/rocksdb`, v11.13.2, C++ build cost [GH]. Not needed.
- **SlateDB** — Apache-2.0, 0.18.1, LSM on object storage [GH]. Useful later for stateless SaaS workers.
- **Tantivy** — MIT, crate 0.27.0 [GH]. Embedded full-text for laptop and small installs.

### 3. Streaming

- **NATS JetStream** — Apache-2.0, v2.15.2 (2026-10-26) [GH]. CNCF and Synadia settled on 2025-05-01: Apache-2.0 stays, trademarks go to the Linux Foundation, any proprietary fork ships under a new name [doc]. Accounts are isolated tenants with their own subject space and JetStream store [doc]. Go binary, so it cannot be linked into a Rust process; `async-nats` 0.52.0 is the client.
- **Kafka** — Apache-2.0; **AutoMQ** Apache-2.0 (1.7.x) [GH]. Support the Kafka protocol as an optional ingest and export edge, not as a core dependency.
- **Redpanda** — BSL plus RCL [GH]. Trap. **Redpanda Connect** mixes Apache-2.0 and RCL; **Bento** (MIT fork) is clean.
- **Apache Iggy** — Apache-2.0, server 0.10.0 (2026-11-07), Rust, io_uring thread-per-core, VSR clustering built in; latest checkout breaks wire and on-disk formats; Kafka gateway unreleased [GH]. Linux-centric and still unstable.
- **Fluvio** — moved to `fluvio-community`, last release v0.18.1 (2025-07) [GH]. Reject.
- **Nisshi (ex-Tansu)** — Apache-2.0, v0.8.2, stateless Kafka-API broker on PostgreSQL, libSQL or S3, now owned by Solace [GH]. Interesting for small installs that need Kafka clients.
- **S2 lite** — MIT, self-hostable stream store in Rust [GH]. Young.

### 4. Stream processing and detection

- **rsigma** — MIT, 0.26.0 (2026-11-02), repository `timescale/rsigma`, 186 stars. Parser, compiled evaluator, stateful correlation (sliding, tumbling, session windows), pySigma-compatible pipelines, OTLP input, linter, LSP [GH]. One contributor has 2,100 of roughly 2,400 commits.
- **sigma-rust** — Apache-2.0; upstream idle since 2025-11, Yamato-Security fork adds correlation (v0.7.2) [GH].
- **pySigma** — LGPL-2.1, v2.1.0 [GH]. Sigma rules are under Detection Rule License 1.1, which is a content licence requiring attribution, not an OSI software licence.
- **VRL** — MPL-2.0, crate 0.38.0 [GH]. Embeddable normalisation language.
- **Feldera** — MIT core, incremental SQL. Multi-node, fault tolerance and resource isolation are Enterprise-only [doc]. Single-node only in OSS.
- **RisingWave** — Apache-2.0, v3.1.1. Premium features (database isolation, resource groups, secret management, time travel, several sinks) need a licence key above 4 cores [doc].
- **Arroyo** — Apache-2.0, last release v0.15.0 (2025-12-01); commits continue, roadmap is Cloudflare's [GH].
- **Flink** — Apache-2.0, JVM cluster. Too heavy.
- **Tenzir** — BSD-3-Clause, v6.21.0, C++ [GH]. Good optional pipeline bridge; not embeddable.
- **Substation** — MIT, Go, 409 stars [GH]. Niche.

### 5. Workflow engines for response playbooks

- **Temporal** — MIT, v1.32.2 [GH]. Production needs a multi-service cluster plus PostgreSQL, MySQL or Cassandra; the CLI dev server is for development only [doc].
- **DBOS Transact** — MIT libraries. Go has a SQLite driver; **Rust SDK is 0.6 "pre-production" and Postgres-only** [GH].
- **Hatchet** — MIT, v0.114.2, Go, Postgres with optional RabbitMQ; "Hatchet Lite" single image for low throughput [doc].
- **Restate** — BSL [GH]. Trap. **Inngest** — SSPL [GH]. Trap. **Windmill** — AGPL plus proprietary compile flags [GH].
- **Tracecat** — AGPL-3.0, v1.4.0, runs on Temporal; multi-tenancy is Enterprise Edition [GH]. **Shuffle** — AGPL-3.0. **StackStorm** — Apache-2.0, v3.9.0, low activity [GH].
- **Absurd** — Apache-2.0, durable execution as Postgres stored procedures [GH]. The pattern is worth copying.

### 6. Identity and authorisation for the platform

- **Keycloak** — Apache-2.0, 26.8.2, JVM [GH]. **Dex** — Apache-2.0, v2.46.1, light federation broker. **Rauthy** — Apache-2.0, Rust, 0.37.2. **Kanidm** — MPL-2.0.
- **Zitadel** — AGPL-3.0, v4.20.2; strongest built-in multi-tenancy model (instances, organisations) [GH].
- **authentik** — MIT core, `enterprise/` directory under a separate licence [GH].
- **Ory** — Apache-2.0, but last release v26.2.0 (2026-03) and last push July 2026 [GH]. OSS cadence has slowed.
- **Cedar** — Apache-2.0, Rust, 4.14.1; `cedar-go` 1.9.0 [GH].
- **OpenFGA** — Apache-2.0, v1.22.1; datastores `memory`, `postgres`, `mysql`, `sqlite`; usable as a Go library [doc]. **SpiceDB** — Apache-2.0, v1.57.0. **OPA** — Apache-2.0, v1.22.2. **Cerbos** — Apache-2.0, v0.57.0. **Permify** — AGPL-3.0 [GH].

### 7. Secrets and PKI

- **OpenBao** — MPL-2.0, v2.7.2 [GH]. 2.6 added per-namespace sealing and external KMS plugins; 2.7 added read scaling on the PostgreSQL backend, external keys for PKI and Transit, ML-DSA in PKI, and moved PKCS#11 to a plugin (secondary summaries of release notes).
- **Infisical** — MIT core with `ee/` directories [GH]. Open-core caution.
- **step-ca** — Apache-2.0, v0.30.2. **SPIRE** — Apache-2.0, v1.16.0. **cert-manager** — Apache-2.0, v1.21.3 [GH].

### 8. API tooling

- **buf** — Apache-2.0, v1.75.0. **connect-rust** — Apache-2.0, crate `connectrpc` 0.9.1; accepted as the official Rust implementation on 2026-05-05, announced by Buf 2026-08-26; serves Connect, gRPC and gRPC-Web; depends on `buffa`; MSRV 1.88; pre-1.0.
- **tonic** — now at `grpc/grpc-rust`, MIT, 0.14.x [GH]. Mature.
- **OpenAPI** — `utoipa` (Apache-2.0/MIT) for a REST façade.

### 9. Proxy and gateway

- **agentgateway** — Apache-2.0, Rust, v1.7.0 (2026-10-27), Linux Foundation/AAIF. LLM, MCP (stdio, SSE, Streamable HTTP) and A2A; JWT, API key and MCP-auth; CEL-based RBAC; external authz; OpenTelemetry; standalone binary or Kubernetes [doc]. Internal crates include `cel-fork`, `policies`, `xds`, `llm` [GH].
- **Agent Router (ex Envoy AI Gateway)** — Apache-2.0, v1.2.1; moved to AAIF in September 2026; CRD and CLI names unchanged.
- **Pingora** — Apache-2.0, 0.9.1; Linux tier 1, Windows "preliminary" [GH]. **hyper** — MIT, 1.12.0.
- **hudsucker** — MIT/Apache-2.0, 0.25.0, MITM library on hyper, 386 stars. **rama** — MIT/Apache-2.0, 0.4.0, modular proxy framework [GH]. **mitmproxy** — MIT, 12.3.1, Python.
- **LiteLLM** — MIT plus `enterprise/`; two supply-chain compromises in 2026. **Portkey** — MIT, no push since 2026-05-25, 2.0 on a pre-release branch. **Bifrost** — Apache-2.0, Go, enterprise tags in the same repo. **Plano** — Apache-2.0. **TensorZero** — archived [GH].

### 10. Graph storage for provenance

- **LadybugDB** — MIT, v0.22.3 (2026-11-07), 1.9k stars, Rust crate `lbug`; commit history is mostly inherited from Kuzu authors [GH].
- **RyuGraph** — last push 2026-01. **Bighorn** — archived 2026-08 [GH].
- **Grafeo** — Apache-2.0, Rust, v0.6.2, 838 stars; GQL, Cypher, SQL/PGQ [GH]. Promising, unproven.
- **HelixDB** — Apache-2.0, Rust, v3.6.1. **Apache AGE** — Apache-2.0, PG18 support only at rc0 since July 2026. **DuckPGQ** — MIT community extension [GH].
- **FalkorDB** SSPL, **Memgraph** BSL, **SurrealDB** BSL, **Neo4j** GPL-3.0 [GH]. Traps or copyleft.

### 11. Metering, flags, notifications, operators, object storage

- **OpenMeter** — Apache-2.0, v1.0.0-beta.236; README says releases are beta [GH]. **Lago** — AGPL-3.0. **Kill Bill** — Apache-2.0. **Meteroid**, **Flexprice** — AGPL-3.0.
- **OpenFeature spec** and **flagd** (v0.19.2) — Apache-2.0. **go-feature-flag** — MIT. **Flipt v2** — Fair Core Licence (not OSI). **Unleash** — AGPL-3.0. **GrowthBook** — MIT plus enterprise directories [GH].
- **Apprise** — BSD-2-Clause, Python. **ntfy** — Apache-2.0. **Svix** — MIT, Rust, webhook delivery. **Novu** — MIT core plus enterprise licence [GH].
- **kube-rs** — Apache-2.0, 5.0.0. **CloudNativePG** — Apache-2.0, v1.30.1. **Altinity clickhouse-operator** — Apache-2.0 [GH].
- **Object storage**: MinIO archived; **SeaweedFS** Apache-2.0 (4.53), **RustFS** Apache-2.0 (1.0.4, young), **Garage** AGPL-3.0 [GH]. Code against S3 via the `object_store` crate (0.14.2).
- **Valkey** — BSD-3-Clause, 9.1.3 [GH]. Use instead of Redis.

## Matrix

| Area | Pick | Licence | Laptop | SaaS | Multi-tenancy | Rejected, with reason |
|---|---|---|---|---|---|---|
| Relational | SQLite → PostgreSQL | Public domain / PostgreSQL | SQLite file | CloudNativePG, replicas | RLS on `tenant_id`; schema-per-tenant tier | Turso (beta), CockroachDB (non-OSI), Citus (AGPL) |
| Events | DuckDB+DuckLake → ClickHouse | MIT / Apache-2.0 | Embedded, Parquet on disk | Replicated, S3 disks | Tenant first in sort key, row policies, quotas | chDB (no Windows), Timescale (TSL), OpenObserve/Parseable (AGPL), VictoriaLogs (no tenant authz) |
| Hot KV | redb | Apache-2.0/MIT | In-process | Local per worker | Key prefix | RocksDB (C++ build), Redis (licence churn) |
| Bus | In-process + SQL outbox → NATS JetStream | Apache-2.0 | No extra process | 3+ nodes, R3 | Account per tenant | Redpanda (BSL), Fluvio (stalled), Iggy (unstable formats), Kafka (weight) |
| Detection | rsigma + VRL + own correlation | MIT / MPL-2.0 | In-process | Same code in workers | Per-tenant rule sets | Flink (JVM), Feldera (HA is enterprise), RisingWave (premium gates), Arroyo (owner roadmap) |
| Workflow | Own step journal on SQL port | — | SQLite | PostgreSQL | Tenant column | Temporal (cluster), Restate (BSL), Inngest (SSPL), Tracecat/Shuffle (AGPL), DBOS Rust (pre-production) |
| AuthZ | Cedar | Apache-2.0 | Library | Library | Policy store per tenant | OPA (Go sidecar), SpiceDB/OpenFGA (service; keep as optional adapter) |
| AuthN | OIDC relying party; Dex or Keycloak optional | Apache-2.0 | Local account | Keycloak or customer IdP | Organisation per tenant | Zitadel (AGPL), Ory (slow OSS), authentik (open-core) |
| Secrets/PKI | OS keychain + rcgen → OpenBao, SPIRE, cert-manager | MPL-2.0 / Apache-2.0 | Keychain | OpenBao HA | Namespace per tenant | Infisical (open-core), Vault (BSL) |
| API | protobuf + buf; tonic now, connect-rust later | Apache-2.0 / MIT | Same | Same | Tenant in token claims | REST-only (no streaming contract) |
| Gateway | hyper/rustls core; agentgateway as reference and K8s option | MIT / Apache-2.0 | Endpoint proxy | Edge fleet | Per-tenant policy | Pingora (Linux-first), LiteLLM (supply chain, Python), TensorZero (archived) |
| Provenance graph | Edge tables + recursive CTEs + petgraph | — | SQLite/DuckDB | ClickHouse/Postgres | Tenant column | Kuzu (archived), FalkorDB (SSPL), Memgraph (BSL), AGE (lagging) |
| Search | Tantivy → ClickHouse text index | MIT / Apache-2.0 | Embedded | GA since 26.2 | Tenant filter | Quickwit (slow), Elasticsearch (licence history) |

## Weak points, gaps and risks

- **Two SQL dialects for events** (DuckDB and ClickHouse) is the largest shared-code cost. Raw SQL in product code will fork the codebase.
- **rsigma bus factor.** One maintainer; 186 stars. A vendor change of heart would leave us maintaining it.
- **DuckDB 2.0 is three weeks old** and changes the on-disk format. DuckLake conflict behaviour under concurrent writers was not documented on the pages read.
- **NATS is Go.** Laptop mode needs a second bus implementation, and behaviour must be kept equivalent by tests.
- **ClickHouse official operator is v0.0.8.** Altinity's is the safe choice today.
- **AI gateway projects churn fast.** Three of the eight seeded gateways were archived, renamed or went quiet within 2026.
- **AGPL in the shipped bundle** is OSI-compliant but will stop EDR vendors embedding us. The embeddable core must be Apache-2.0/MIT/MPL only.
- **OpenBao 2.7 moved auth methods and HSM support into plugins**; upgrade paths need testing.

## Implications for our design

1. Define five ports as Rust traits (`RelationalStore`, `EventStore`, `Bus`, `WorkflowJournal`, `BlobStore`) and ship exactly two adapters each. Forbid direct driver use outside adapters with a lint.
2. Never write backend SQL in feature code. Use a typed query IR that compiles to DuckDB SQL and ClickHouse SQL, with a conformance suite that runs every query against both on the same fixture data.
3. Use one event schema in Arrow/Parquet (OCSF-aligned) as the wire, spool and storage format. Sensors spool Parquet; laptop mode queries it in place; SaaS bulk-loads it.
4. Put `tenant_id` first in every key from day one, including laptop mode with a single constant tenant. Enforce with PostgreSQL RLS (`FORCE ROW LEVEL SECURITY`), ClickHouse row policies and NATS accounts, so isolation is defence in depth, not application logic alone.
5. Make Cedar the single policy language for platform access and for agent-action enforcement, so the same evaluator runs in hooks, gateways and the server.
6. Build the playbook engine as a step journal (workflow row, step-output rows, leases, idempotency keys) on the relational port. Offer a Temporal adapter for enterprises that already run it.
7. Keep the embeddable core free of AGPL, LGPL-static and open-core dependencies. Run `cargo-deny` with an allow-list of Apache-2.0, MIT, BSD, MPL-2.0, ISC, PostgreSQL, Unicode.
8. Ship an OIDC relying party and SCIM, not an identity provider. Document Dex (small) and Keycloak (large) as tested companions.
9. Treat AI gateways as integration targets through hooks, ext-authz and OpenTelemetry. Build our own enforcement proxy on hyper/rustls so it runs on Windows, macOS and Linux.
10. Pin and vendor every dependency, verify provenance, and delay adoption of new releases; the LiteLLM incidents show the release pipeline is the attack surface.

### Reference stacks

| | (a) Laptop, one binary | (b) Small self-hosted | (c) HA on Kubernetes | (d) Multi-tenant SaaS |
|---|---|---|---|---|
| Process | One Rust binary, all roles | Same binary + PostgreSQL | Same binary, one Deployment per role | As (c), in regional cells |
| Relational | SQLite (WAL) | PostgreSQL 17/18 | CloudNativePG, 3 instances | As (c) + RLS, schema-per-tenant tier |
| Events | DuckDB, DuckLake with SQLite catalog | DuckDB, DuckLake with Postgres catalog; ClickHouse single node optional | ClickHouse replicated + Keeper, S3 disks | Shared tables + row policies; dedicated database or cluster for large tenants |
| Bus | In-process + SQLite outbox | PostgreSQL outbox; NATS optional | NATS JetStream R3 | NATS accounts per tenant; Kafka-API edge optional |
| Detection | rsigma, VRL, Cedar in-process | Same | Same, in worker role | Same + ClickHouse materialised views |
| Workflow | Step journal on SQLite | Step journal on PostgreSQL | Same | Same; Temporal adapter optional |
| Search | Tantivy | Tantivy | ClickHouse text index | Same |
| Secrets/PKI | OS keychain, local CA (rcgen) | Key file or KMS envelope; OpenBao optional | OpenBao HA, cert-manager, SPIRE | OpenBao namespaces per tenant |
| AuthN | Local account, optional OIDC | OIDC; Dex bundled optionally | Customer IdP or Keycloak | Keycloak organisations or customer IdP |
| Blobs | Local directory | Local or S3 | S3-compatible (SeaweedFS or cloud) | Cloud object storage |
| Ops | Auto-update | Docker Compose | Helm + kube-rs operator | As (c) + metering, flagd |

Reasons: every row keeps the same trait and the same feature code; only the adapter changes. (a) has no Go, JVM or Python. (b) adds one container. (c) and (d) differ only in tenancy enforcement and cell topology.

## Ideas worth stealing and whitespace

- **DuckLake's data inlining**: small batches live in the catalog database and are flushed to Parquet later. It solves the small-file problem for trickle ingest from endpoints.
- **Absurd/DBOS**: durable execution as plain tables and leases in the database you already run.
- **OpenBao namespace sealing**: a tenant can seal its own keys. Strong story for MSPs.
- **NATS leaf nodes and accounts**: maps naturally to MSP → customer → site hierarchies.
- **rsigma's `rule tune` and `rule draft`**: propose filters from false positives and verify true positives still fire.
- **agentgateway's CEL policy plus external authz**: a ready extension point where our decision service can sit.
- **Whitespace**: nobody ships one OSI-licensed detection platform that runs identically from a laptop binary to multi-tenant SaaS. No embedded, permissive, actively maintained graph engine exists for Windows, macOS and Linux. No durable-workflow library in Rust is production-ready on both SQLite and PostgreSQL.

## Could not verify / open questions

- DuckLake conflict resolution semantics with many writers on a PostgreSQL catalog (page exists, not read).
- ClickHouse row-policy overhead at high tenant counts; per-tenant quota behaviour.
- Whether RisingWave premium code sits in the Apache-2.0 repository.
- OpenBao 2.7 details came from search summaries of release notes, one of which referenced a beta page.
- PostgreSQL 19 GA date (RC1 on 2026-10-15) and the SQL/PGQ revert (secondary sources only).
- Why TensorZero was archived; no first-party statement found.
- Kuzu acquisition by Apple (single aggregator source).
- [memory] Redis licence state, OpenMeter ownership, Keycloak Organizations maturity, ClickHouse recursive CTE support, `regorus` as a Rust Rego evaluator.
- Search budget ended before verifying: Iggy cluster maturity in practice, Tenzir edition limits, Portkey 2.0 licence, Bifrost enterprise boundary, Lakekeeper status, pySigma ClickHouse/DuckDB backends.

## Sources

- GitHub REST API, repository, licence, release and README endpoints for about 250 repositories, queried 2026-11-09 — https://api.github.com/repos/{owner}/{repo}
- crates.io API, queried 2026-11-09 — https://crates.io/api/v1/crates/{name}
- ClickHouse multi-tenancy — https://clickhouse.com/docs/cloud/bestpractices/multi-tenancy (read 2026-11-09)
- ClickHouse text indexes — https://clickhouse.com/docs/engines/table-engines/mergetree-family/textindexes (read 2026-11-09)
- Announcing DuckDB 2.0.0 — https://duckdb.org/2026/10/21/announcing-duckdb-200.html (2026-10-21)
- DuckLake 1.1 — https://ducklake.select/2026/10/21/ducklake-11/ (2026-10-21)
- DuckLake 1.0 — https://ducklake.select/2026/04/13/ducklake-10/ (2026-04-13)
- DuckLake FAQ — https://ducklake.select/faq ; unsupported features — https://ducklake.select/docs/stable/duckdb/unsupported_features
- PostgreSQL 19 release notes (RC1) — https://www.postgresql.org/docs/19/release-19.html (as of 2026-10-09)
- PostgreSQL 19 beta graph queries — https://www.infoq.com/news/2026/06/postgresql-19-graph-queries/ (2026-06)
- VictoriaLogs docs — https://docs.victoriametrics.com/victorialogs/
- NATS accounts — https://docs.nats.io/running-a-nats-service/configuration/securing_nats/accounts
- NATS 2.14 upgrade notes — https://docs.nats.io/release-notes/upgrade-to-2.14 (2026-04)
- CNCF and Synadia on NATS — https://www.cncf.io/announcements/2025/05/01/cncf-and-synadia-align-on-securing-the-future-of-the-nats-io-project/ (2025-05-01)
- agentgateway docs 1.7.x — https://agentgateway.dev/docs/standalone/latest/ ; v1.0 post — https://agentgateway.dev/blog/2026-03-12-agentgateway-v1.0/
- Agent Router joins AAIF — https://aaif.io/blog/agent-router-joins-aaif (2026-09-09) ; repo — https://github.com/theagentrouter/agent-router
- connect-rust joins Connect — https://buf.build/blog/connect-rust-joins-the-connect-project (2026-08-26) ; RFC 007 — https://connectrpc.com/docs/governance/rfc/007-rust-implementation/
- LiteLLM March incident — https://github.com/BerriAI/litellm/issues/24518 ; https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- LiteLLM October incident — https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/ (2026-10-23)
- TensorZero — https://github.com/tensorzero/tensorzero (archived 2026-06-12)
- Kuzu landscape — https://gdotv.com/blog/kuzu-legacy-embedded-graph-database-landscape/ ; LadybugDB — https://github.com/LadybugDB/ladybug
- rsigma — https://github.com/timescale/rsigma ; https://rsigma.io/
- Turso concurrent writes — https://turso.tech/blog/concurrent-writes-on-turso-cloud (2026-08)
- OpenBao 2.7 — https://openbao.org/blog/release-v2-7-0/ ; 2.6 — https://openbao.org/blog/release-v2-6-0/
- RisingWave premium features — https://docs.risingwave.com/get-started/premium-features
- Feldera enterprise — https://docs.feldera.com/get-started/enterprise
- Hatchet self-hosting — https://docs.hatchet.run/self-hosting
- Temporal deployment — https://docs.temporal.io/self-hosted-guide/deployment
- OpenFGA configuration — https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga
- DBOS Rust — https://github.com/dbos-inc/dbos-transact-rust ; DBOS June 2026 — https://www.dbos.dev/blog/new-in-dbos-june-2026
- Arroyo joins Cloudflare — https://www.arroyo.dev/blog/arroyo-is-joining-cloudflare/ (2025-04-10)
- Quickwit joins Datadog — https://quickwit.io/blog/quickwit-joins-datadog (2025-01)
- MinIO archive timeline (secondary) — https://ttlab.hopto.org/blog/2026-07-17-minio-archived-garage-seaweedfs-ceph-rgw?lang=en

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: GitHub REST and GraphQL API (licence files, release assets, `archivedAt`, source code), crates.io and PyPI indexes, and direct fetches of primary docs. The shared web-search budget was exhausted, so no search-engine queries were run; every verdict below rests on a primary source that was read directly._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | chDB Rust binding supports only Linux and macOS, so ClickHouse cannot be the embedded engine for a Windows laptop binary | Confirmed | README lists Linux x86_64/aarch64 and macOS x86_64/arm64 and calls the crate experimental. `build.rs` returns "Unsupported platform" for any other target. The upstream `chdb-core` v26.9.0 release ships no Windows `libchdb` artefact at all, so the gap is in the engine, not only the binding. | https://github.com/chdb-io/chdb-rust/blob/main/build.rs ; https://github.com/chdb-io/chdb-core/releases/tag/v26.9.0 |
| 2 | DuckDB 2.0.0 is LTS (2026-10-21, MIT, supported to at least October 2027); DuckLake 1.1 supports SQLite and PostgreSQL catalogs with data inlining | Confirmed, with a design caveat | Release calendar lists 2.0.0 LTS, released 2026-10-21, end of life 2027-10-22. DuckLake 1.1 docs list DuckDB, SQLite, PostgreSQL and MySQL catalogs (MySQL is "not recommended"). Inlining works on DuckDB, PostgreSQL, SQLite and Quack catalogs, not MySQL. **Inlining is on by default but the default row limit is 10**, so trickle ingest needs the limit raised explicitly. The SQLite catalog allows one writer at a time (DuckLake retries on lock). | https://duckdb.org/release_calendar ; https://ducklake.select/docs/stable/duckdb/advanced_features/data_inlining ; https://ducklake.select/docs/stable/duckdb/usage/choosing_a_catalog_database |
| 3 | ClickHouse docs recommend a shared table with tenant in the primary key plus row policies; separate tables or databases do not scale to thousands of tenants | Confirmed | The page recommends the shared-table model ("simplest to manage", "potentially millions" of tenants) and says of both separate tables and separate databases that the approach "doesn't scale for 1000s of tenants". It is a ClickHouse Cloud best-practice page; no contradicting primary doc was found. | https://clickhouse.com/docs/cloud/bestpractices/multi-tenancy |
| 4 | NATS remains Apache-2.0 under CNCF after the May 2025 settlement; accounts are isolated tenants with their own subject space and JetStream store | Confirmed, with two additions | Licence file is Apache-2.0 at v2.15.2. CNCF now lists NATS as **Graduated** (project page gives 2026-11-02; the CNCF landscape file also says `graduated`). In source, each account's JetStream store is a sub-directory of the server's single `store_dir` (`jsa.storeDir = filepath.Join(js.config.StoreDir, a.Name)`), so isolation is logical inside one process and disk, with per-account limits. JetStream is opt-in per account once an `accounts` block exists. | https://github.com/nats-io/nats-server/blob/main/server/jetstream.go ; https://www.cncf.io/projects/nats/ ; https://github.com/cncf/landscape/blob/master/landscape.yml |
| 5 | Restate, SurrealDB, Memgraph and Pathway are BSL; FalkorDB and Inngest are SSPL; Flipt v2 is Fair Core Licence; none OSI-approved | Confirmed | Licence files read directly. Restate BSL 1.1; SurrealDB BSL 1.1 (change date 2030-01-01, then Apache-2.0); Memgraph BSL 1.1 plus Memgraph Enterprise Licence; Pathway BSL 1.1 (free grant limited to one machine); FalkorDB SSPLv1; Inngest SSPL with a delayed Apache-2.0 grant; Flipt default branch `v2` is FCL-1.0-MIT. | https://github.com/surrealdb/surrealdb/blob/main/LICENSE ; https://github.com/memgraph/memgraph/blob/master/LICENSE ; https://github.com/pathwaycom/pathway/blob/main/LICENSE.txt ; https://github.com/FalkorDB/FalkorDB/blob/master/LICENSE ; https://github.com/inngest/inngest/blob/main/LICENSE.md ; https://github.com/flipt-io/flipt/blob/v2/LICENSE |
| 6 | DBOS Transact for Rust is 0.6, pre-production and PostgreSQL-only; no durable-workflow library covers both SQLite and PostgreSQL in Rust | **Corrected** | First half holds: crate `dbos` 0.6.0, README says "Pre-production release", `Cargo.toml` enables only `sqlx` `postgres` (SQLite is a planned second backend). Second half is wrong. **apalis 1.0.0** (MIT, 2026-10-12) ships `apalis-workflow` (sequential and DAG, "durable and resumable") on both `apalis-sqlite` and `apalis-postgres`. **microsoft/duroxide** (MIT, labelled Preview, crate 0.1.32) has a built-in SQLite provider and a PostgreSQL provider in `duroxide-pg`. Correct statement: no *production-proven* replay-style engine covers both; evaluate these two before building a step journal. | https://github.com/dbos-inc/dbos-transact-rust/blob/main/crates/dbos/Cargo.toml ; https://github.com/apalis-dev/apalis ; https://github.com/apalis-dev/apalis-sqlite ; https://github.com/microsoft/duroxide ; https://github.com/microsoft/duroxide-pg |
| 7 | rsigma (MIT, crate 0.26.0, 2026-11-02) is an embeddable Rust Sigma evaluator with stateful correlation; one contributor authored about 2,100 of 2,400 commits | Confirmed | crates.io: 0.26.0 published 2026-11-02, MIT. Contributors API: top author 2,100 commits, next 191, then a bot at 73; 2,379 commits in total. README documents the `rsigma-eval` library crate and sliding, tumbling and session correlation windows. Repository was created 2026-02-10. | https://crates.io/crates/rsigma ; https://api.github.com/repos/timescale/rsigma/contributors |
| 8 | LiteLLM was compromised on PyPI twice in 2026 (1.82.7/1.82.8 in March; 1.107.0 including Docker images in October); TensorZero archived 2026-06-12 | Confirmed | GitHub malware advisory GHSA-92x9-889m-jgmw lists exactly 1.82.7, 1.82.8 and 1.107.0. All three are gone from the PyPI index. Issue #47826 (2026-10-21) records that `latest`, `main-latest` and `main-stable` on GHCR and Docker Hub pointed at the 1.107.0 image until pulled. GraphQL `archivedAt` for TensorZero is 2026-06-12T03:36Z. | https://github.com/advisories/GHSA-92x9-889m-jgmw ; https://github.com/BerriAI/litellm/issues/47826 ; https://pypi.org/pypi/litellm/json |
| 9 | Kuzu is archived; LadybugDB (MIT, v0.22.3) is the only active fork, RyuGraph stalled, Bighorn archived; PostgreSQL 19 reverted SQL/PGQ before release | Confirmed | Kuzu `archivedAt` 2025-10-10. LadybugDB v0.22.3 released 2026-11-07, MIT. RyuGraph's last commit is 2025-12-06. Bighorn is archived. One more fork exists, Vela-Engineering/kuzu (MIT, 52 stars), but its last commit and release are 2026-06-14, so "only active fork" holds today. PostgreSQL: commit "Revert SQL Property Graph Queries (SQL/PGQ)" landed on `REL_19_STABLE` on 2026-09-07; the feature is present in the Beta 3 tag and absent from Beta 4 and RC1. No `REL_19_0` tag exists yet. | https://github.com/postgres/postgres/commit/2b9e1aff4d ; https://github.com/LadybugDB/ladybug/releases/tag/v0.22.3 ; https://github.com/Vela-Engineering/kuzu |
| 10 | Pingora: Linux tier 1, Windows preliminary community best effort; agentgateway (Apache-2.0, Rust, v1.7.0) covers LLM, MCP and A2A with CEL RBAC and external authz | Confirmed | Pingora README: "Linux is our tier 1 environment" and "Windows support is preliminary by community's best effort only"; crate 0.9.1. agentgateway v1.7.0 released 2026-10-27, Apache-2.0, README lists LLM, MCP and A2A gateways and "RBAC with CEL policy engine"; ext-authz policy exists in code and examples. Worth knowing: the release **ships `agentgateway-windows-amd64.exe`**, and the repository is about two-thirds Rust with a Go controller. | https://github.com/cloudflare/pingora/blob/main/README.md ; https://github.com/agentgateway/agentgateway/releases/tag/v1.7.0 |

### Further statements checked in this brief

| Statement in the brief | Verdict | Note | Source |
|---|---|---|---|
| Whitespace: "No embedded, permissive, actively maintained graph engine exists for Windows, macOS and Linux." | **Refuted as written** | It contradicts section 10. LadybugDB is MIT, released v0.22.3 on 2026-11-07, and that release ships `liblbug` (shared and static) for Windows x86_64/arm64, macOS and Linux, with about 100 commits from nine authors since 2026-10-01. Grafeo (Apache-2.0, Rust) is also active. The defensible statement is that none is mature or proven; edge tables remain a reasonable default, but not because nothing exists. | https://github.com/LadybugDB/ladybug/releases/tag/v0.22.3 |
| Section 10: "Bighorn — archived 2026-08" | Corrected | 2026-08-10 is the last push. GraphQL `archivedAt` is 2026-10-23. | https://github.com/Kineviz/bighorn |
| Repository moves: tonic at `grpc/grpc-rust`, RocksDB at `meta/rocksdb`, Envoy AI Gateway now Agent Router, Tansu now Nisshi under Solace; MinIO archived 2026-04-25 | Confirmed | The old GitHub paths redirect to `grpc/grpc-rust` (MIT), `meta/rocksdb`, `theagentrouter/agent-router` (Apache-2.0) and `nisshi-io/solace-nisshi` (Apache-2.0). MinIO `archivedAt` is 2026-04-25. | https://github.com/grpc/grpc-rust ; https://github.com/theagentrouter/agent-router ; https://github.com/nisshi-io/solace-nisshi |
