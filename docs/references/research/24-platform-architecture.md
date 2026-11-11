# Server architecture: single binary to multi-tenant SaaS and MSP

_Researched 2026-11-09_

Method note: web search quota was exhausted early in this run, so findings come from direct fetches of vendor docs, specs and GitHub (via `gh`). Claims marked **[V]** were read in the primary source today; **[I]** are my inference or arithmetic.

## TL;DR

- **Ship one binary with exactly two shapes**: `--target=all` and one-target-per-process. Grafana tried a third "middle" shape twice and killed it twice: Loki's Simple Scalable mode is deprecated and removed in Loki 4.0; Mimir removed read-write mode in 3.0. [V]
- **The closest prior art for our stack is OpenObserve** (Rust, single binary, SQLite + local disk on one node; Postgres + NATS + object storage + Parquet in HA). Copy the storage shape, not the AGPL code. [V]
- **Self-hosted stacks that need Kafka + ClickHouse + Postgres + Redis die of support cost.** PostHog dropped Kubernetes self-hosting (3.5% of users, outsized support load); Sentry self-hosted is ~15 services, needs 16 GB RAM + 16 GB swap, and offers no HA. [V]
- **Tenancy must be in the data path from day one.** Wazuh's "multi-tenancy" is dashboard saved-object tenants; Velociraptor calls its orgs "soft separation" and shares one CA across orgs. Neither is safe for an MSP with untrusted tenant admins. [V]
- **Fleet control planes at 100k endpoints are modest; the telemetry store is not.** Fleet: 25 x (1 vCPU / 4 GB) tasks + Aurora db.r6g.2xlarge for 100k hosts. Elastic: Fleet Server 16 GB / 16 vCPU, but a 512 GB RAM / 128 vCPU Elasticsearch hot tier. [V]
- **Use OpAMP (beta) semantics for sensor management** (config hash, `RemoteConfigStatus` APPLIED/FAILED, capability bitmask, package offers) rather than inventing a protocol. Wazuh is replacing its bespoke agent protocol end to end with HTTPS + JWT enrolment tokens in 5.0 (rc2, 2026-10-30). [V]
- **Policy and detection content are code and must ride the same rings as binaries.** CrowdStrike's RCA finding 6: content "should have staged deployment"; Microsoft MVI 3.0 now requires gradual rollout, rings and monitoring. Teleport's managed updates still halt only manually and ship unsigned binaries. [V]
- **MCP became stateless on 2026-07-28** (no `initialize`, no `Mcp-Session-Id`), so an MCP endpoint is now just another horizontally scaled API surface. [V]
- **Accept OTLP natively.** Microsoft deprecated the Agent 365 Observability SDK (doc dated 2026-10-01) for a Microsoft OpenTelemetry Distro that can dual-export to any OTLP endpoint. In-house agents instrumented for Agent 365 can feed us with a config change. [V]
- **Storage is nearly free; ingest, detection and query compute are the bill.** A heavy agent-using workstation is roughly 100k events/day, about 60 MB raw, about 5 MB compressed. 100k such endpoints is about 6 TB/day raw. [I]
- **Whitespace**: customer-held policy signing (Tailnet Lock applied to policy push), endpoint-side sealing of prompts so the operator cannot read them, and policy replay against history as a rollout gate.

## Findings

### 1. One codebase from single binary to scaled-out services

- **Loki** (v3.7.9, 2026-10-20, AGPL-3.0): `-target=all` monolith "up to approximately 20GB per day"; SSD (`read`/`write`/`backend`) "close to a TB of logs per day" and "is being deprecated and will be removed with the Loki 4.0 release"; microservices for larger. [V] https://grafana.com/docs/loki/latest/get-started/deployment-modes/
- **Mimir** (3.2.4, 2026-10-30, AGPL-3.0): monolithic and microservices only. Monolith scales by running several `-target=all` replicas. 3.0 removed read-write mode, made the Mimir Query Engine default (up to 92% lower peak memory), and added Kafka-based "ingest storage" that decouples read and write paths; classic architecture still supported. [V] https://grafana.com/docs/mimir/latest/references/architecture/deployment-modes/ , https://grafana.com/docs/mimir/latest/release-notes/v3.0/
- **OpenObserve** (v1.2.0-rc1, AGPL-3.0, Rust): single node uses SQLite and local disk or object storage, about 31 MB/s ingest on an M2 (about 2.6 TB/day). HA requires Kubernetes, object storage, Postgres (orgs, users, schemas, file list) and NATS (coordination). Roles: router, ingester (WAL, memtable, Parquet), querier, compactor, scheduler. [V] https://openobserve.ai/docs/architecture/
- **SigNoz** (v0.149.0, MIT + `ee/`): consolidated into one binary (frontend, API, OpAMP server, ruler, alertmanager) but still needs ClickHouse and its own collector. [V] https://signoz.io/docs/architecture/
- **Tailscale control plane**: JSON file, then etcd with hand-written indexes, then SQLite + Litestream to S3, chosen because the full test suite runs hermetically and nobody wanted to operate replicated Postgres. [V] https://tailscale.com/blog/database-for-2022 (2022; later history not checked)
- **Sentry self-hosted** (26.10.1, FSL-1.1-Apache-2.0): Kafka, ClickHouse, Snuba, Relay, Symbolicator, Postgres, pgbouncer, Redis, Memcached, SeaweedFS, Vroom, Taskbroker, nginx, web, worker. Minimum 4 cores, 16 GB RAM + 16 GB swap. All single-node "including Kafka"; no scaling guidance. [V] https://develop.sentry.dev/self-hosted/
- **PostHog**: "New deployments ... using Kubernetes are no longer supported"; hobby Docker Compose only; no tagged releases, ships from `master`; paid features cloud-only. Reasons (2023-02-08): about 3.5% of users, failures spread across Kafka, ClickHouse, Postgres, Redis; a full disk took deployments down "for hours or days". [V] https://posthog.com/docs/self-host , https://posthog.com/blog/sunsetting-helm-support-posthog
- **Supabase** self-hosted is a single project: no multiple orgs or projects, no branching, no PITR, no Management API. [V] https://supabase.com/docs/guides/self-hosting

### 2. Tenant isolation, MSP hierarchy, cross-tenant views

- **AWS SaaS guidance**: authentication and authorisation are not isolation; isolation must use tenant context to scope every resource access. Silo, pool and bridge models. [V] https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/tenant-isolation.html (marked historical)
- **Loki/Mimir**: tenant is an `X-Scope-OrgID` header; with auth off everything lands in tenant `fake`. Cross-tenant query is `A|B` in the header (off by default) and yields a synthetic `__tenant_id__` label; writes with multiple tenants are rejected. [V] https://grafana.com/docs/loki/latest/operations/multi-tenancy/
- **Mimir shuffle sharding**: each tenant gets a subset of partitions/ingesters/queriers/store-gateways/rulers/compactors. With 50 partitions and 4 per tenant, two tenants share nothing 71% of the time and fully overlap 0.0004%. Runtime override keys such as `max_queriers_per_tenant`. [V] https://grafana.com/docs/mimir/latest/configure/configure-shuffle-sharding/
- **Velociraptor orgs** (0.77.3, AGPL-3.0): per-org datastore subdirectory, users, ACLs and audit log; root-org artifacts visible to all children; client-to-org mapping is only `Client.nonce`, same CA for all orgs; docs call it "soft separation" and advise against GUI access for untrusted users. [V] https://docs.velociraptor.app/docs/deployment/orgs/
- **Wazuh 4.x**: documented multi-tenancy is OpenSearch dashboard tenants (Global, Private, custom) holding index patterns and dashboards, enabled by hand-editing `opensearch_dashboards.yml`. [V] https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/multi-tenancy.html
- **Microsoft Defender multitenant management** (doc 2026-05-27): cross-tenant incidents, alerts, cases, KQL advanced hunting, custom detection rules, and named **tenant groups**; secondary workspaces in other tenants still need Azure Lighthouse. This is the MSSP feature bar. [V] https://learn.microsoft.com/en-us/defender-xdr/mto-overview
- **Sentry multi-region**: a control silo resolves org to region and proxies; responses carry `X-Sentry-Proxy-Url` so clients go direct; integration credentials and inbound webhooks are centralised to avoid token-refresh races; requests via the global domain do not meet residency. [V] https://develop.sentry.dev/application-architecture/multi-region-deployment/control-silo/
- **Cells** (AWS, 2023-09-20): cap cell size, keep cells identical, test a cell at full scale, deploy cell by cell in waves with rollback. [V] https://docs.aws.amazon.com/wellarchitected/latest/reducing-scope-of-impact-with-cell-based-architecture/cell-sizing.html
- **ClickHouse row policies** do not hide row counts in metadata, are bypassable by anyone with write access, and must be defined on underlying tables of Distributed tables. Not a sufficient sole boundary. [V] https://clickhouse.com/docs/operations/access-rights

### 3. Keys, customer-held secrets, residency

- **Tailnet Lock**: nodes verify signatures from customer-held keys, so a compromised coordination server cannot add nodes. Max 20 signing nodes, 10 disablement secrets, lose them all and the tailnet is unrecoverable. [V] https://tailscale.com/kb/1226/tailnet-lock
- **Teleport Cloud**: six AWS regions; External Audit Storage puts audit logs and recordings in the customer's own AWS account; SLA 99.9% (99.99% with multi-region). [V] https://goteleport.com/docs/reference/architecture/teleport-cloud-architecture/
- Infisical's KMS overview page did not expose its key hierarchy; not verified. Infisical is MIT + `ee/`.

### 4. Fleet management at 100k+

- **Fleet** (v4.94.1, MIT + `ee/`): MySQL (single writer) + Redis. AWS reference: 100k hosts = 25 Fargate tasks (1 vCPU / 4 GB), Aurora db.r6g.2xlarge x3, Redis r6g.large x3; 300k = 70 tasks, db.r6g.8xlarge. Per-fleet enrol secrets (Premium). TPM 2.0 host identity certificates (Linux only, Premium) with HTTP message signatures on every request, P-384, about 50% more server CPU. fleetd updates via TUF with channels. [V] https://fleetdm.com/docs/deploy/reference-architectures , https://fleetdm.com/guides/enroll-hosts
- **Elastic Fleet Server** (Elastic License 2.0): agent-initiated HTTPS long poll (`checkin_long_poll` 5 m); offline after 5 min; default rate limits about 10 enrolments/s and 10 artifact rollouts/s; each check-in triggers an Elasticsearch auth request above 10k agents, so the API-key cache must be 2x agents. [V] https://www.elastic.co/docs/reference/fleet/fleet-server-scalability
- **Velociraptor**: one server handles about 10k-15k endpoints; multi-frontend is "experimental", needs NFS/EFS (40-60 ms per operation) and a single master that owns metadata. [V] https://docs.velociraptor.app/docs/deployment/server/multifrontend/
- **Wazuh 5.0** (rc2 2026-10-30; 4.14.10 stable): new HTTPS agent transport and control plane "replacing the legacy MQ/DGRAM-based agent-manager protocol end to end"; cluster-by-default; enrolment tokens as JWTs with TTL, use cap and CA pinning replacing the shared enrolment password; a `cluster:read_secrets` RBAC action with logged disclosures; engine relicensed AGPLv3. [V] https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/CHANGELOG.md
- **OpAMP** (beta): WebSocket or HTTP polling (30 s default); `AgentToServer` carries instance UID (UUID v7), capabilities, health, effective config, `RemoteConfigStatus`, package statuses; `ServerToAgent` carries remote config, connection settings (credential rotation), package offers, commands; spec warns remote config is a code-execution-grade capability. [V] https://opentelemetry.io/docs/specs/opamp/
- **Teleport Managed Updates v2**: groups with `start_hour`/`days`, `halt-on-error` or `time-based`, `canary_count` 0-5, `wait_hours`, a group is done at 90% on target; updater reverts if the agent is unhealthy. Gaps: "automatic error detection is planned", halting is manual, binaries "aren't currently signed" (shasum over TLS). Skew rule: agent never newer than server, at most one major behind. [V] https://goteleport.com/docs/reference/deployment/managed-updates-v2/ , https://goteleport.com/docs/reference/architecture/agent-update-management/
- **CrowdStrike RCA (2024-08-06)**: template type declared 21 fields, sensor supplied 20; validator trusted the declaration; interpreter had no bounds check; tests used wildcards for field 21; content had no staged rollout. Mitigations: compile-time arity check, runtime bounds check, test every content instance in the real interpreter, rings with bake time and rollback, customer control over content rollout. [V] https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf
- **Microsoft**: MVI 3.0 partners must test incident response and "updates must be gradual, leverage deployment rings and leverage monitoring"; endpoint security platform lets products run outside the kernel (2025-06-26). Azure DevOps SDP: five tiers, 24 h bake including a business-hours peak, Sev 1 hotfixes still pass tier 0. [V] https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ , https://learn.microsoft.com/en-us/devops/operate/safe-deployment-practices

### 5. API, MCP, query language, ecosystem seeds

- **MCP 2026-07-28**: stateless; per-request protocol version in `_meta`; mandatory `server/discover`; `subscriptions/listen` replaces GET stream; tasks moved to an extension; `Mcp-Method`/`Mcp-Name` headers required; `ttlMs`/`cacheScope` on list results; Dynamic Client Registration deprecated for Client ID Metadata Documents; Roots, Sampling, Logging deprecated; 12-month deprecation window. [V] https://modelcontextprotocol.io/specification/2026-07-28/changelog
- **Query languages**: Defender cross-tenant hunting is KQL; ClickHouse's KQL dialect is Beta (`enable_kusto_dialect`), PRQL experimental. [V] https://clickhouse.com/docs/guides/developer/alternative-query-languages . OCSF schema is at 1.9.0 (2026-08-03). [V] https://github.com/ocsf/ocsf-schema/releases
- **Microsoft Agent 365**: GA 2026-05-01, per-user licence, registry in the M365 admin centre, Entra/Purview/Defender for control. Its Observability SDK is deprecated in favour of `microsoft-opentelemetry` / `@microsoft/opentelemetry` / `Microsoft.OpenTelemetry`, exporting to Agent 365, Azure Monitor and any OTLP endpoint simultaneously. [V] https://learn.microsoft.com/en-us/microsoft-agent-365/overview , https://learn.microsoft.com/en-us/microsoft-agent-365/developer/microsoft-opentelemetry
- **BeyondTrust AI Agent Security**: a "Pathfinder" endpoint agent, kernel and network enforcement plus hooks, SaaS console only, Windows 11 / Server 2022+ x64 and macOS 14/15/26, no Linux, tenant root CA for HTTPS inspection, and **policy replay** against recorded activity before enforcing. [V] https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security

### 6. Scale and cost arithmetic [I]

Assumptions for a developer workstation with heavy agent use (8 active hours, 2-3 concurrent agents):

| Stream | Events/day | Avg raw size | Raw/day |
|---|---|---|---|
| Agent hook events (pre/post tool call, verdicts, session, MCP calls) | 10k-20k | 700 B | 7-14 MB |
| LLM request/response metadata (no content) | 2k-5k | 500 B | 1-3 MB |
| OS sensor events attributed to agent process trees, after endpoint-side aggregation | 60k-150k | 450 B | 27-68 MB |
| **Total, metadata only** | **about 100k (P95 250k)** | | **about 60 MB** |
| Optional prompt/tool content capture | 15k bodies | 4 KB | +60 MB |

- Columnar + zstd at 10-15x on metadata gives 4-6 MB/day, about **150 MB/endpoint/month**; content compresses 4-5x, adding about 400 MB/month.
- Object storage at about $0.023/GB-month (list price, not re-verified today): 30-day metadata retention costs under **$0.01/endpoint/month**; with content about $0.015. Storage is not the constraint.
- 100k endpoints: 10^10 events/day, 116k events/s average, about 350k/s peak, 6 TB/day raw. That is beyond Loki's stated monolith (20 GB/day) and SSD (about 1 TB/day) envelopes, so it is microservices mode on a partitioned log.
- Free tier (5 endpoints, 7-day retention): about 300 MB/day raw, about 0.2 GB stored. Marginal cost is dominated by fixed per-tenant overhead, so the free tier is only cheap if tenants are pooled with zero per-tenant infrastructure (no per-tenant database, index, topic or pod).

## Matrix

| Project | Licence | Single binary? | Scale-out needs | Tenancy | Main pain |
|---|---|---|---|---|---|
| Loki / Mimir | AGPL-3.0 | Yes, `-target` | Object store, (Kafka in Mimir ingest storage), rings | Header tenant ID, per-tenant limits, shuffle sharding | Third mode abandoned; no built-in authN |
| OpenObserve | AGPL-3.0 | Yes (Rust) | K8s + Postgres + NATS + S3 | Orgs and streams | HA only on Kubernetes |
| SigNoz | MIT + ee | App yes, needs ClickHouse | ClickHouse cluster | Orgs | External DB always |
| Sentry self-hosted | FSL | No, ~15 services | Not supported | Orgs; SaaS uses control + region silos | 16 GB floor, no HA |
| PostHog | MIT + ee | No | Dropped | Cloud only | K8s self-host sunset |
| Wazuh 4.x / 5.0 | GPLv2 / AGPLv3 engine | No (server, indexer, dashboard) | Server cluster + OpenSearch | Dashboard tenants only | Bespoke protocol being replaced |
| Fleet | MIT + ee | Yes + MySQL + Redis | More replicas, bigger Aurora | Fleets/teams (Premium) | Single-writer MySQL; tenancy and TPM identity paywalled |
| Velociraptor | AGPL-3.0 | Yes, file datastore | Shared NFS/EFS, experimental | Orgs, "soft separation" | 10-15k per server |
| Elastic Fleet Server | ELv2 | Subprocess of agent | Stateless, behind LB | Spaces / clusters | Elasticsearch hot tier and auth load |
| Teleport | AGPL-3.0 | Yes | DynamoDB/S3 etc. | One cluster per tenant; trusted clusters | Manual rollout halt, unsigned binaries |
| Headscale | BSD-3 | Yes | None | Single tailnet by design | No multi-tenant |
| NetBird | BSD-3 client, AGPL server | Several services | Mgmt, signal, relay | Accounts | Split licence |
| Supabase | Apache-2.0 | No | Compose | Single project self-hosted | Platform features absent |

## Weak points, gaps and risks

- No studied open-source project delivers hard multi-tenant isolation plus an MSP hierarchy with inheritance. Fleet and Velociraptor come closest, and both are single-level.
- OpAMP is still beta; package signing and the CSR flow are "Development". We would be an early production user and must own a compatibility shim.
- Two storage engines doubles the test matrix. Choosing embedded Parquet over ClickHouse costs mature SQL features; choosing ClickHouse costs the single binary.
- Endpoint-sealed content removes server-side content detection and full-text search for that tenant; this must be an explicit, visible trade.
- AI-agent implementers will happily add per-tenant infrastructure and cross-tenant joins unless the framework makes them impossible.
- The sizing arithmetic rests on assumed event rates. Instrument a pilot before fixing quotas or price.

## Implications for our design

### Reference architecture (one Rust binary, `--target=<list>`; `all` is default)

| Service | Responsibility | State |
|---|---|---|
| `router` (SaaS only, global) | Resolve org to region/cell, redirect sensors and API clients to the cell URL, hold nothing else | Global directory (org id, cell, region) |
| `gateway` | Sensor-facing: enrolment, device identity verification, OpAMP-style check-in stream, config/content/package offers, command dispatch, edge rate limits | Stateless |
| `ingest` | Authenticate, apply per-org quota, validate schema (OCSF 1.9 + OTel GenAI attributes), accept OTLP, append to log, ack | Stateless |
| `log` | Durable partitioned log. Embedded WAL in `all`; Kafka-protocol broker or NATS JetStream when scaled; tenants shuffle-sharded onto partitions | Disk / broker |
| `detect` | Streaming rules (Sigma-compatible plus agent-session correlation), emits findings | Checkpoints |
| `store` | Build Parquet per org/day/stream, compaction, retention, crypto-shredding | Object storage or local disk |
| `query` | Query frontend with per-org queues and concurrency caps, queriers (DataFusion), federated fan-out across orgs | Cache only |
| `control` | Org tree, policy, RBAC bindings, SSO/SCIM, audit log, alerts/incidents/cases, API tokens | SQLite (`all`) or Postgres |
| `rollout` | Rings, canaries, bake timers, health gates, automatic halt and revert for binaries, policy and content | In `control` DB |
| `content` | Compile, validate and sign policy and detection bundles; TUF repository | Object storage |
| `keys` | Envelope encryption, per-org KEK, external KMS adapters, key-broker protocol | KMS |
| `notify` | Webhooks, SIEM/EDR export, event stream out | Outbox |
| `api` | ConnectRPC (gRPC + JSON/REST from one proto), OpenAPI, MCP endpoint, console assets | Stateless |

**Event flow**: sensor signs and batches; `gateway`/`ingest` verifies device identity, derives `org_id` from the credential (never from the payload), checks quota, appends to the org's shard and acks; `detect` consumes and emits findings; `store` writes Parquet under `org/<id>/...` encrypted with the org DEK; `control` groups findings into alerts and incidents; `notify` drains an outbox. Enforcement decisions happen on the endpoint, so server latency never blocks an agent action.

**Policy change flow**: admin edits at any tree node; `control` writes an audited draft; `content` compiles the effective policy per device group (inheritance resolved server-side), runs the validator and the real sensor interpreter in a sandbox, optionally replays against N days of that org's history, then signs (operator key, plus tenant key in locked mode); `rollout` offers the new hash to ring 0; sensors verify, apply, report `APPLIED`/`FAILED` and health; gates promote or halt; sensors keep last-known-good and revert locally on crash loop.

### Tenancy model

- Tree: **Provider (MSP) > Organisation > Group > Device > Agent**. The **Organisation is the hard boundary**: its own keys, object prefix, region, quotas and audit log. Everything above is policy and access; everything below is grouping.
- Inheritance: a node sets a value as *default* (child may override) or *locked* (child may not). Compile to a flat effective policy and show provenance per setting.
- Delegated admin: role bindings of (principal, role, node). Provider staff get access to a customer only through an explicit, time-boxed, audited binding that the customer can see and revoke.
- Cross-tenant views are federated queries over orgs the caller is bound to, returning an `org_id` column, with tenant groups. Never a shared table without `org_id`.
- Isolation: pooled by default, with tenant context injected by the framework (Postgres RLS plus mandatory `org_id` key prefix; object-store credentials scoped per request). Offer a dedicated cell as the silo tier.
- Residency: a region is a set of cells; an org is pinned at creation; only the directory is global.

### Keys

1. Default: per-org DEK wrapped by operator KMS.
2. Customer-managed: KEK in the customer's KMS; revocation makes data unreadable (crypto-shred).
3. Customer-held ("sealed") mode: sensor encrypts sensitive fields with HPKE to an org public key whose private key lives in a customer-run key broker or analyst devices; server stores ciphertext, cleartext envelope metadata and keyed blind-index tokens for exact match.
4. Policy lock: sensors accept policy only if co-signed by a customer-held key.

### Fleet

- Enrolment: short-lived, use-capped JWT tokens that pin the server CA; per-device key pair, hardware-backed where available (TPM 2.0, Secure Enclave); renewal by proof of possession; request signing with HTTP message signatures. All in the open core.
- Rings for everything: internal, canary (few devices per org), early, broad; bake at least 24 h for binaries, shorter for content but never zero; **automatic** halt on crash-free rate, check-in loss, CPU, and block-rate anomalies. Orgs choose N, N-1 or pinned for content.
- Signed artifacts via TUF; never shasum-over-TLS alone.
- Skew contract: server is always at least as new as sensors; support sensors one major behind; capability negotiation instead of version checks.

### API, auth, query, cases

- Proto-first with generated REST, OpenAPI and SDKs; outbox-backed signed webhooks; OCSF event stream out; OTLP in.
- MCP endpoint on the same authz path, stateless per 2026-07-28, with read tools default-on, response tools behind approval, and per-call row, time and cost limits.
- SSO (OIDC, SAML), SCIM, roles and audit in the open-source build. Log secret reads, not only writes.
- Canonical engine is SQL over OCSF tables; add a KQL-style pipe front end and Sigma import, because that is what SOC analysts already write.
- Model: finding > alert > incident (correlated by agent session, device, identity) > case; all org-scoped, with provider-level rollups.

### Sizing [I, anchored to Fleet/Elastic/OpenObserve numbers above]

| Tier | Endpoints | Raw/day | Shape | Indicative resources |
|---|---|---|---|---|
| Laptop | 1-25 | up to 1.5 GB | `all`, SQLite, local disk | 2 vCPU, 2-4 GB |
| Team | up to 500 | 30 GB | `all`, SQLite or Postgres, disk or S3 | 4-8 vCPU, 16 GB |
| Enterprise | 5k-10k | 0.3-0.6 TB | 3 x `all` behind LB, Postgres HA, S3, embedded or small broker | 3 x 16 vCPU / 32 GB |
| Large | 100k | 6 TB | Per-target: about 6 gateway, 12-20 ingest, 3-5 brokers, 8-12 detect, 6-10 store, 6+ query | About 300-500 vCPU total |
| SaaS / MSP | Millions | Many cells | Cells capped near 250k endpoints or a tested TB/day limit, global router | Per cell as "Large" |

SLOs to publish: ingest ack p99, policy propagation p99 (target under 60 s to connected sensors), sensor check-in success, detection latency p95, query p95, percentage of fleet on target version, crash-free sensor rate.

### Anti-patterns and who paid for them

| Anti-pattern | Project |
|---|---|
| A third "simple scalable" deployment shape | Loki (removed in 4.0), Mimir (removed in 3.0) |
| Self-hosting that requires Kafka + ClickHouse + Postgres + Redis | Sentry self-hosted, PostHog |
| No tagged releases for self-hosters | PostHog |
| Tenancy added at the dashboard layer | Wazuh 4.x |
| Tenant separation by shared secret under one CA | Velociraptor |
| Shared network filesystem as the scale-out datastore | Velociraptor multi-frontend |
| Datastore authentication on every agent check-in | Elastic Fleet Server |
| Single-writer SQL as the fleet bottleneck | Fleet |
| Bespoke agent protocol and shared enrolment password | Wazuh 4.x (rewritten in 5.0) |
| Hand-rolled indexes on a KV store | Tailscale on etcd |
| Single-tenant by design, platform features missing when self-hosted | Headscale, Supabase |
| Isolation, SSO or device attestation behind a paid directory | Fleet, Infisical, SigNoz |
| Content updates outside staged rollout; validator and interpreter disagree | CrowdStrike, July 2024 |
| Manual rollout halt, unsigned update binaries | Teleport |
| Row filters as the only tenant boundary | ClickHouse row policies |

## Ideas worth stealing and whitespace

- Policy replay before enforce (BeyondTrust), wired in as a mandatory rollout gate.
- Tailnet Lock applied to policy and content: the operator cannot push policy the customer did not sign. Nobody in endpoint security offers this.
- `X-Sentry-Proxy-Url`-style direct-to-cell hints, so the global router is not on the hot path.
- Shuffle sharding for tenants on log partitions and queriers.
- Audit of secret reads (Wazuh 5.0).
- Teleport-style external storage: tenant data in the customer's own bucket, with our compute.
- Whitespace: an open, hard-isolated MSP hierarchy with inheritance and provenance; customer-held content keys with blind-index search; automatic health-gated content rings exposed to customers; an embeddable server library so an EDR vendor can host `gateway` + `detect` inside its own cloud.

## Could not verify / open questions

- Web search was unavailable; I could not survey 2026 write-ups on cell-based SaaS (Slack, DoorDash, and others) or confirm current S3/ClickHouse Cloud prices.
- Infisical key hierarchy and external-KMS details; Fleet server-configuration page (404); Velociraptor performance page (404); Sentry cross-region RPC and replication pages.
- Teleport's GitHub "latest" is v18.10.0 (2026-07-09), which looks stale against a repo pushed 2026-11-06; release channel may have moved.
- CrowdStrike Flight Control and SentinelOne account/site hierarchies are behind logins; not read.
- Whether DataFusion + Parquet meets sub-second hunting at 6 TB/day without a secondary index needs a prototype.
- Real events/endpoint/day for agent-heavy workstations: all figures in section 6 are assumptions.
- OpAMP stabilisation timeline and package-signing design.

## Sources

- https://grafana.com/docs/loki/latest/get-started/deployment-modes/ - Loki deployment modes (docs for 3.7, fetched 2026-11-09)
- https://grafana.com/docs/loki/latest/operations/multi-tenancy/ - Loki multi-tenancy
- https://grafana.com/docs/mimir/latest/references/architecture/deployment-modes/ - Mimir deployment modes
- https://grafana.com/docs/mimir/latest/release-notes/v3.0/ - Mimir 3.0 release notes
- https://grafana.com/docs/mimir/latest/configure/configure-shuffle-sharding/ - Mimir shuffle sharding
- https://openobserve.ai/docs/architecture/ - OpenObserve architecture; https://github.com/openobserve/openobserve (README)
- https://signoz.io/docs/architecture/ - SigNoz architecture
- https://develop.sentry.dev/self-hosted/ - Sentry self-hosted
- https://develop.sentry.dev/application-architecture/multi-region-deployment/control-silo/ - Sentry control silo
- https://posthog.com/docs/self-host - PostHog self-host; https://posthog.com/blog/sunsetting-helm-support-posthog (2023-02-08)
- https://supabase.com/docs/guides/self-hosting - Supabase self-hosting
- https://documentation.wazuh.com/current/getting-started/architecture.html - Wazuh architecture
- https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/multi-tenancy.html - Wazuh multi-tenancy
- https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/CHANGELOG.md - Wazuh 5.0.0 changelog (rc2, 2026-10-30)
- https://fleetdm.com/docs/deploy/reference-architectures - Fleet reference architectures
- https://fleetdm.com/guides/enroll-hosts - Fleet enrolment and host identity
- https://docs.velociraptor.app/docs/deployment/orgs/ - Velociraptor orgs
- https://docs.velociraptor.app/docs/deployment/server/multifrontend/ - Velociraptor multi-frontend
- https://www.elastic.co/docs/reference/fleet/fleet-server-scalability - Fleet Server scalability
- https://www.elastic.co/docs/reference/fleet/fleet-server - Fleet Server
- https://goteleport.com/docs/reference/architecture/teleport-cloud-architecture/ - Teleport Cloud architecture
- https://goteleport.com/docs/reference/architecture/agent-update-management/ - Teleport agent updates
- https://goteleport.com/docs/reference/deployment/managed-updates-v2/ - Managed Updates v2 reference
- https://tailscale.com/kb/1226/tailnet-lock - Tailnet Lock
- https://tailscale.com/blog/database-for-2022 - Tailscale control-plane database (2022)
- https://github.com/juanfont/headscale - Headscale README (v0.29.7)
- https://docs.netbird.io/about-netbird/how-netbird-works - NetBird; https://github.com/netbirdio/netbird (LICENSE)
- https://opentelemetry.io/docs/specs/opamp/ - OpAMP specification (beta)
- https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf - CrowdStrike RCA (2024-08-06)
- https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ - Windows Resiliency Initiative, MVI 3.0 (2025-06-26)
- https://learn.microsoft.com/en-us/devops/operate/safe-deployment-practices - Microsoft safe deployment practices
- https://docs.aws.amazon.com/wellarchitected/latest/reducing-scope-of-impact-with-cell-based-architecture/cell-sizing.html and .../cell-deployment.html - AWS cell-based architecture (2023-09-20)
- https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/tenant-isolation.html - AWS SaaS tenant isolation
- https://modelcontextprotocol.io/specification/2026-07-28/changelog - MCP 2026-07-28 changes
- https://clickhouse.com/docs/guides/developer/alternative-query-languages - ClickHouse KQL/PRQL; https://clickhouse.com/docs/operations/access-rights - row policies
- https://github.com/ocsf/ocsf-schema/releases - OCSF 1.9.0 (2026-08-03)
- https://learn.microsoft.com/en-us/defender-xdr/mto-overview - Defender multitenant management (2026-05-27)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview - Agent 365 overview (2026-08-19)
- https://learn.microsoft.com/en-us/microsoft-agent-365/developer/microsoft-opentelemetry - Microsoft OpenTelemetry Distro (2026-10-22)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security - BeyondTrust AI Agent Security

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Method: doc sources and changelogs read from the upstream GitHub repositories with `gh` (read-only), plus direct fetches of vendor pages. Web search was unavailable (quota exhausted), so no third-party write-ups were consulted._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Loki SSD is deprecated and removed in Loki 4.0; monolithic about 20 GB/day, SSD close to 1 TB/day | Confirmed | Exact wording is in the 3.7.x docs. Loki 4.0 is not GA yet (v4.0.0-rc.3, 2026-11-07); its upgrade guide removes the `read`/`write`/`backend` targets and Loki fails to start if they are used. The 4.0 docs replace SSD with a new documented "HA Monolithic" mode: 3+ replicas of `-target=all`, shared object store, memberlist, replication factor 3, one designated main compactor, load balancer. | https://github.com/grafana/loki/blob/main/docs/sources/setup/upgrade/_index.md ; https://github.com/grafana/loki/blob/release-3.7.x/docs/sources/get-started/deployment-modes.md |
| 2 | Mimir 3.0 removed read-write mode, leaving monolithic and microservices, and introduced Kafka-based ingest storage | Confirmed | CHANGELOG 3.0.0: "Remove support for the experimental read-write deployment mode" (#12584). Two nuances: read-write mode was only ever experimental, and ingest storage existed as an experimental feature in 2.x; 3.0 is where it became the headline architecture. Classic architecture remains supported. | https://github.com/grafana/mimir/blob/main/CHANGELOG.md |
| 3 | OpenObserve single node uses SQLite with local disk or object storage; HA requires Kubernetes, Postgres, NATS, object storage, Parquet | Corrected | Single-node part and Parquet/NATS/object storage hold. Kubernetes is the only officially packaged path (Helm), not a hard requirement: the HA guide says HA "can run ... on bare metal servers, VMs, and other platforms". The metadata store may be PostgreSQL or MySQL (Postgres is the chart default). Local disk is not supported in HA. | https://github.com/openobserve/openobserve-docs/blob/HEAD/docs/administration/deployment/ha-deployment.md |
| 4 | CrowdStrike RCA: validator and interpreter disagreed on field count (21 vs 20), no runtime bounds check, no staged deployment for Rapid Response Content; mitigations include rings with bake time and customer control | Confirmed | Full PDF text read. RCA: "mismatch between the 21 inputs validated by the Content Validator versus the 20 provided to the Content Interpreter". Findings 2 (bounds check), 4 (validator logic error) and 6 (staged deployment) match; mitigations name canary, successive rings, "bake-in time" and customer control of where and when content deploys. | https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf |
| 5 | Fleet 100k hosts: 25 Fargate tasks (1 vCPU, 4 GB), Aurora db.r6g.2xlarge x3, Redis cache.r6g.large x3; MySQL single-writer only | Confirmed | Matches the "Up to 100000 hosts" table (1024 CPU units, 4 GB). Doc: "Fleet supports single-writer database setups ... Multi-writer or group-replication MySQL setups are not supported." 300k row (70 tasks, db.r6g.8xlarge, cache.r6g.xlarge) also matches. | https://github.com/fleetdm/fleet/blob/main/docs/Deploy/Reference-Architectures.md |
| 6 | Elastic at 100k agents: Fleet Server 16 GB / 16 vCPU, Elasticsearch hot tier 512 GB RAM / 128 vCPU; each check-in triggers an ES auth request | Confirmed | Table row matches. It sits under "Scaling recommendations (Elastic Cloud)", so it is hosted-deployment guidance that also covers the agents' data, not a pure control-plane cost. The auth-request sentence applies at 10k+ agents, with API key cache sized at 2x agents. | https://github.com/elastic/docs-content/blob/main/reference/fleet/fleet-server-scalability.md |
| 7 | Velociraptor orgs are "soft separation", one CA for all orgs, client mapped by shared nonce; 10k-15k endpoints per server; multi-frontend experimental on NFS/EFS | Confirmed | Docs: "this is a soft separation", keys "of clients from all Orgs are the same", nonce "acts as a shared secret"; "regularly used to serve up to 10k-15k endpoints"; multi-frontend "currently considered experimental" and outside the support policy, on NFS or EFS. | https://github.com/Velocidex/velociraptor-docs/tree/HEAD/content/docs/deployment |
| 8 | MCP 2026-07-28 is stateless: no initialize handshake, no Mcp-Session-Id, mandatory server/discover, DCR deprecated for Client ID Metadata Documents | Confirmed | All four items are in the spec repo changelog (SEP-2567, SEP-2575, PR 2858). Design caveats: `subscriptions/listen` is still a long-lived response stream, SSE resumability is gone (a broken stream loses the in-flight request), and DCR stays available for backwards compatibility. | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx |
| 9 | OpAMP is beta; WebSocket and HTTP polling (30 s default); remote config with hash and APPLIED/FAILED; package offers; connection-setting rotation; packages and CSR flow less mature | Corrected | Beta status (v0.20.0, 2026-08-12), transports, 30 s default, config hash and APPLIED/APPLYING/FAILED all hold. Maturity detail is off: packages (`packages_available`, `PackageStatuses`) are marked Beta like the rest of the spec. What is marked Development is the agent-initiated CSR flow, `ConnectionSettingsStatus`, heartbeat capability, custom messages, available components and `PackageStatus.download_details`. Package signing is not a "Development" feature: `DownloadableFile.signature` is an optional field and the spec says the signing and verification method is agent-specific and outside its scope. | https://github.com/open-telemetry/opamp-spec/blob/main/specification.md |
| 10 | Heavy workstation about 100k events and 60 MB raw per day (about 150 MB/month compressed); 100k endpoints about 6 TB/day raw | Unverifiable | Self-declared estimate with no measured basis; the cited Loki page supports only the envelope comparison. Arithmetic is internally consistent (100k x ~600 B = 60 MB; 10-15x compression gives 4-6 MB/day or 120-180 MB/month; 100k endpoints = 6 TB/day and 116k events/s). The 450-700 B average event size is an assumption that swings the result linearly; treat every downstream number as plus or minus 3x until a pilot measures it. | (none) |
| A | TL;DR and anti-pattern table: Grafana "tried a third middle shape twice and killed it twice" | Corrected (overstated) | Mimir's read-write mode never left experimental. Loki did not abandon the middle tier; it swapped SSD for HA Monolithic, which is a documented third topology built from the `all` target. This supports "two targets" but the plan should treat "N replicas of `all`" as a first-class, tested shape, with its own requirements (shared ring state, replication factor, singleton compactor). | https://github.com/grafana/loki/blob/main/docs/sources/get-started/deployment-modes.md |
| B | Section 4 and anti-pattern table: Wazuh 5.0 enrolment tokens "replacing the shared enrolment password" | Corrected | 5.0.0-rc2 adds JWT enrolment tokens (TTL, optional use cap, CA pinning) as an alternative that works "without the shared enrollment password", but the shared password stays and is now enabled by default (#36705), hardened and carried over by the migration tool. The HTTPS transport replacing MQ/DGRAM, cluster-by-default, `cluster:read_secrets` and the AGPLv3 engine licence are all confirmed. | https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/CHANGELOG.md |
| C | TL;DR: Agent 365 Observability SDK deprecated for a Microsoft OpenTelemetry Distro that can export to any OTLP endpoint simultaneously | Confirmed | Page (ms.date 2026-10-22) points existing users to "deprecated SDK documentation and migration guides" and lists multi-backend export to Azure Monitor, any OTLP-compatible endpoint and Agent 365 "at the same time". Agent 365 GA on 2026-05-01, per-user licensing, also confirmed on the overview page. | https://learn.microsoft.com/en-us/microsoft-agent-365/developer/microsoft-opentelemetry |

Additional spot checks that held: BeyondTrust AI Agent Security (Pathfinder agent, kernel and network enforcement plus hooks, Windows 11 / Server 2022+ x64 and macOS 14/15/26 only, tenant root CA, replay of recorded activity before saving a policy; the page implies but does not state "SaaS only"); ClickHouse KQL dialect is Beta via `enable_kusto_dialect` since 26.10 and PRQL is experimental (ClickHouse `src/Core/Settings.cpp`); OCSF 1.9.0 on 2026-08-03; Wazuh v4.14.10 stable; Teleport GitHub latest v18.10.0.
