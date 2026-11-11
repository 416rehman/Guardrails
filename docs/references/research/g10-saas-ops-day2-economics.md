# G10 — Operating the hosted service and self-hosted day-2: SRE, metering, billing, support and unit economics

_Researched 2026-11-09_

Method note: the shared web-search budget was exhausted before this brief started, so every source below was fetched directly (vendor docs, raw handbook Markdown, GitHub via `gh`). Prices and versions are as served on 2026-11-09. Cost-model outputs are my own arithmetic on stated assumptions, not vendor figures.

## TL;DR

- **LLM review, not storage, is the cost driver.** With edge-filtered telemetry (~5,000 events/endpoint/day) storage is cents per endpoint per month; LLM review is 65–80% of COGS at every scale unless the customer supplies model keys. Modelled COGS: roughly $0.40–$0.90 per endpoint-month with platform keys, ~$0.10–$0.30 with customer keys.
- **Reviewing every agent action with an LLM is unaffordable on mid-tier models** (~$47/heavy endpoint/month on Sonnet 5.5 list prices) and only marginal on the cheapest (~$2.50 on Haiku 5.5). Deterministic policy first, LLM on a 1–5% escalation slice, prompt caching and the Batch API (50% off) are mandatory levers.
- **Only two serious open billing engines are permissive:** OpenMeter (Apache-2.0, still `v1.0.0-beta.236`, needs Kafka + ClickHouse + Postgres) and Kill Bill (Apache-2.0, 0.24.22, JVM, since 2010). Lago, Flexprice and Meteroid are AGPL-3.0 and cannot be embedded in a product OEM partners will ship.
- **Build the usage ledger into the core, keep rating and invoicing outside it.** Emit CloudEvents usage records into the telemetry store; ship adapters (Stripe meters, OpenMeter, Kill Bill, CSV/PSA).
- **Elastic removed per-endpoint fees on 2026-03-23** and now charges ingest ($0.09–0.11/GB) plus retention ($0.017–0.019/GB-month). Microsoft Agent 365 (GA 2026-05-01) is licensed per user. The market has no settled unit; meter endpoints, users, agents and GB simultaneously.
- **Published SLAs are modest:** Grafana Cloud commits to 99.5% of requests per month, with a separate 99.5% for autonomous actions, and excludes volume above 300% of the prior 30-day peak.
- **Skew rule everyone converges on:** server is newest; agents may lag (Teleport one major, Kubernetes kubelet three minors, Wazuh "manager same or newer"); never skip a major; mandatory upgrade stops for migrations (GitLab x.2/x.5/x.8/x.11; Sentry hard stops).
- **Replication is not backup** (ClickHouse and NATS docs both say so explicitly). ClickHouse has native incremental `BACKUP ... TO S3`, no PITR; NATS DR is snapshots plus mirrors in a separate JetStream domain.
- **Content (rules) updates need their own ring-based release train with customer control**, per CrowdStrike's 2024 RCA; fleet-wide synchronized auto-update windows caused Datadog's 2023 multi-region outage.
- **Self-hosted support is whitespace:** PostHog declares self-hosting "officially unsupported", with no tagged releases or CVEs; Sentry does not patch old versions. A supported LTS plus a redacted diagnostics bundle is a differentiator.

## Findings

### 1. What a tenant costs, and the levers

**Verified unit prices (2026-11-09)**

- ClickHouse Cloud, AWS us-east-1: compute $0.218 (Basic) / $0.298 (Scale) / $0.390 (Enterprise) per compute-unit-hour (1 CU = 8 GiB, 2 vCPU); storage $25.30 per TB-month compressed; backups billed at the storage rate, default one per 24 h retained one day; public egress $0.115/GB. https://clickhouse.com/pricing
- Claude API: Haiku 5.5 $0.10 in / $0.50 out per MTok (cache hit $0.01) for prompts up to 100k tokens; Haiku 4.5 $1 / $5; Sonnet 5.5 $2 / $10 (cache hit $0.10); Batch API 50% discount; 4.7+ tokenizer yields ~30% more tokens for the same text. https://platform.claude.com/docs/en/about-claude/pricing
- Comparable retail: Elastic Security Serverless ingest "as low as" $0.09–0.11/GB, retention $0.017–0.019/GB-month, managed LLM resold at $4.50 in / $21 out per MTok. https://www.elastic.co/pricing/serverless-security
- Wazuh sizing for reference: 1–25 agents need 50 GB for 90 days, 51–100 need 200 GB (about 22 MB/agent/day indexed). https://documentation.wazuh.com/current/quickstart.html
- Telemetry shape: Claude Code already exports `claude_code.tool_result`, `tool_decision`, `api_request`, `user_prompt` events over OTel with a 5 s log export interval, prompt bodies redacted by default. https://code.claude.com/docs/en/monitoring-usage

**Cost model spreadsheet outline (assumptions are mine; make every one an input cell)**

Sheet `Inputs`: endpoints; share of heavy agent users (30%); tool calls/day heavy (1,000) and light (50); working days (22); shipped events/endpoint/day after edge filtering (5,000); bytes/event (600); compression ratio (10x); hot days (30); total retention months (13); LLM review rate (3% of tool calls); review tokens (1,500 cached + 500 fresh in, 100 out); investigations/endpoint/month (5 at 20k in, 1k out); model prices; BYOK flag; store unit prices; replica count.

Sheet `Volume`: events/day, EPS average and peak (x4), raw GB/month, compressed GB/month, steady-state TB.

Sheet `COGS`: store compute, storage, backup, bus and gateways, Postgres, egress, LLM review, LLM investigation, observability, support minutes x loaded rate, payment fees.

Sheet `Tenant P&L`: price per unit, COGS, gross margin, by plan and by MSP/partner discount.

Sheet `Sensitivity`: tornado over review rate, model choice, events/day, retention, BYOK.

| Scale | Events/day | Raw / compressed per month | Steady-state store (13 mo) | Infra share per month | LLM per month (Haiku 5.5 → Sonnet 5.5 review, Sonnet investigation) | Per endpoint-month |
|---|---|---|---|---|---|---|
| 10 | 50k | 0.9 GB / 0.09 GB | ~1 GB | <$1 marginal (pooled) | $2.75–$7.30 | $0.28–$0.73 |
| 1,000 | 5M (58 EPS) | 90 GB / 9 GB | 117 GB (~$3) | ~$150–$300 | $275–$730 | $0.40–$1.00 |
| 50,000 | 250M (2.9k EPS, ~12k peak) | 4.5 TB / 450 GB | 5.85 TB (~$148) | ~$5.2k compute (24 CU Scale) + ~$1.5k bus/Postgres | $13.8k–$36.5k | $0.42–$0.90 |

Per-review arithmetic: Haiku 5.5 ≈ $0.000115; Sonnet 5.5 ≈ $0.00215; one Sonnet 5.5 investigation ≈ $0.05. Reviewing 100% of a heavy user's 22,000 monthly tool calls costs ~$2.50 (Haiku 5.5), ~$25 (Haiku 4.5) or ~$47 (Sonnet 5.5).

**Levers, ranked by effect**

1. Customer-supplied model keys or a local model: removes 65–80% of COGS and is the only safe basis for a free tier.
2. Review rate: deterministic rules and allowlists first; LLM only on ambiguous or high-risk actions; cache verdicts by normalised action hash.
3. Prompt caching (cache hits at 0.05–0.1x input) and Batch API for non-inline triage.
4. Edge filtering: if the sensor ships EDR-style full telemetry (say 100 MB/endpoint/day) instead of agent-scoped process trees, 50,000 endpoints become ~150 TB raw per month, about 30x the modelled volume.
5. Tiered retention: ClickHouse TTL can delete, move `TO DISK/VOLUME`, or roll up with `GROUP BY`; partition by the TTL date so whole partitions drop. TTL runs only on merges (default 4 h timeout). Tiered storage is not available in ClickHouse Cloud. https://clickhouse.com/docs/guides/developer/ttl
6. Fixed floor: a three-replica store, R3 bus and HA Postgres per region cost on the order of $1.5–3k/month before the first tenant (inference). Regions are the expensive decision, not tenants.

### 2. Metering and billing

**Open components (licences verified via GitHub API, 2026-11-09)**

| Project | Licence | State | Notes |
|---|---|---|---|
| OpenMeter | Apache-2.0 | `v1.0.0-beta.236` (2026-10-09), "releases are beta and can include breaking changes" | CloudEvents ingest; Kafka, ClickHouse, Postgres, optional Redis dedup (off by default), Svix webhooks; entitlements, credits, invoices; hosted version is now Kong Konnect Metering & Billing |
| Kill Bill | Apache-2.0 | 0.24.22 (2026-09-29), in production since 2010 | JVM; per-tenant API keys and config; consumable and capacity usage, in-arrear only; parent/child invoices; plugin gateways |
| Polar | Apache-2.0 | active | Merchant-of-record style; not a metering engine |
| Lago | AGPL-3.0 | v1.57.0 (2026-11-05) | Vendor states commercialising a fork requires publishing source or buying a licence; premium features exist |
| Flexprice, Meteroid | AGPL-3.0 | active | Same embed problem |

Sources: https://github.com/openmeterio/openmeter, https://github.com/killbill/killbill, https://github.com/getlago/lago, https://getlago.com/blog/open-source-licensing-and-why-lago-chose-agplv3

**Stripe constraints if used for the hosted service:** 1,000 meter events/s per account (10,000/s on v2 streams), one concurrent call per customer per meter, timestamps within 35 days back and 5 minutes forward, 100 unique dimension combinations per customer per meter, asynchronous aggregation; late events can be accepted yet miss a finalised invoice. https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api

**Design**

- Usage ledger in core: an append-only `usage_events` table in the telemetry store, fed by CloudEvents (`id` as idempotency key, `subject` = tenant, `source` = component) from ingest, gateways and the review service. Never meter from the billing provider's copy.
- Meters: `endpoints.active` (daily distinct, billed on monthly average or p95, not peak), `users.active`, `agents.observed`, `events.ingested` and `bytes.ingested`, `retention.gb_month` by tier, `llm.tokens` by model and key owner (platform vs customer), `gateway.requests`, `decisions.enforced`.
- Hierarchy: partner (embed/OEM) → MSP → customer → site. Roll-ups materialised per level; every row carries all ancestor IDs so pass-through and revenue share are plain `GROUP BY`s.
- Exposure: usage API and console page per level, daily export (CSV/Parquet), webhook at 50/80/100% of quota, monthly immutable usage statement signed by the instance key.
- Self-hosted and embedded installs: signed usage attestations generated locally and uploaded or emailed, so partner revenue share works air-gapped (inference; no vendor documents this well).
- Adapters outside core: Stripe (pre-aggregate hourly to stay under dimension limits), OpenMeter, Kill Bill, PSA export. Invoicing, tax and dunning are never in the core.

### 3. SLOs, error budgets, on-call, incidents

**What others publish**

- Grafana Cloud SLA: 99.5% of requests succeed per month; 99.5% for autonomous actions; credits 10/20/50/100% at <99.5/<99.0/<98.0/<97.0; maintenance needs 24 h notice, at most one per quarter; "extraordinary volume" above 300% of the highest sustained 24 h in the prior 30 days is excluded; claims within 10 days. https://grafana.com/legal/grafana-cloud-sla/
- GitLab: S1–S4; on-call engineer auto-paged only for S1/S2; incidents over 5 minutes communicated publicly within 1 hour; "investigating" beyond 30 minutes escalates; review mandatory for S1/S2; roles Incident Lead, Responder, Communications Lead. https://gitlab.com/gitlab-com/content-sites/handbook/-/raw/main/content/handbook/engineering/infrastructure-platforms/incident-management/_index.md
- PostHog: three severities; anyone declares via Slack (incident.io); incident lead owns the status page; ingestion delays of 30 minutes or more are customer-communicated; security incidents coordinate disclosure; audited break-glass "force-merge". https://posthog.com/handbook/engineering/operations/incidents
- Google SRE workbook: page at burn rate 14.4 (1 h/5 min, 2% budget) and 6 (6 h/30 min, 5%); ticket at 1 (3 d/6 h, 10%); freeze non-P0 releases when the four-week budget is spent; postmortem when one incident burns more than 20%. Low-traffic services need synthetic traffic or pooled SLOs. https://sre.google/workbook/alerting-on-slos/ and https://sre.google/workbook/error-budget-policy/

**Draft SLOs (28-day window)**

| Service | SLI | Target |
|---|---|---|
| Inline verdict API (hooks, gateways) | Valid verdict within 150 ms p99 | 99.95% |
| Ingest | Batches accepted | 99.9% |
| Freshness | Events queryable within 60 s | 99% |
| Detection | Alert emitted within 2 min of last contributing event | 99% |
| Console and API | Successful requests | 99.9% |
| Notifications and response actions | Delivered within 60 s | 99.5% |

Sensors must enforce cached policy locally, so a cloud outage degrades freshness, not protection. Contractual SLA should sit below SLO (99.5–99.9%) with a Grafana-style volume exclusion.

**Draft incident process:** three severities; agent or human may declare; a human Incident Lead for Sev1/Sev2 within 15 minutes; first public status post within 30 minutes for Sev1 and 60 for Sev2, then every 30/60 minutes; per-region, per-component status; blameless review within 5 business days for Sev1/Sev2 and for any incident burning over 20% of budget; security incidents use a separate private channel and disclosure checklist.

### 4. Noisy tenants, quotas, abuse, free tier

- ClickHouse workload scheduling: `CREATE WORKLOAD ... IN parent` with `max_concurrent_queries`, `max_queries_per_second`, `max_cpus`, `max_bytes_per_second`, weights and priorities; pin per user via a constrained settings profile; `throw_on_unknown_workload`. Caveats: memory reservation is experimental, merges and mutations are not CPU-scheduled, blocked queries wait indefinitely. https://clickhouse.com/docs/operations/workload-scheduling
- NATS: stream limits default to unlimited and "a full disk takes the server down"; set max bytes/age and `discard new` per tenant; dedup window defaults to 2 minutes. https://docs.nats.io/nats-concepts/jetstream/streams
- Sentry spike protection: per-project threshold from a 168-hour weighted baseline, dynamic rate limit, hourly recalculation; no notification unless configured. https://docs.sentry.io/pricing/quotas/spike-protection/
- PostHog billing limits: ingestion stops and data "is lost forever"; emails at 80% and 100%. https://posthog.com/docs/billing/limits-alerts
- GitLab sign-up: risk-scored verification, email for all, phone for medium risk, card for high risk. https://docs.gitlab.com/security/identity_verification/

For a security product, dropping telemetry at quota is itself a detection gap: degrade to sampled raw events but always keep verdicts, detections and audit records.

### 5. Backup, restore, DR, region evacuation

- ClickHouse: `BACKUP/RESTORE` to `S3`/`AzureBlobStorage`, incremental via `base_backup`, `ON CLUSTER`, `ASYNC`, `system.backups`; config-file users are not included; no PITR; "replication guards against hardware failure but not human error". https://clickhouse.com/docs/operations/backup
- NATS JetStream: R3 "is not a recovery mechanism"; `nats stream restore` needs snapshots taken with `--consumers`; restore fails if the stream exists; mirrors must live in a separate JetStream domain; promotion is edit `--no-mirror`, remove origin, re-add subjects; `nats server cluster rescue` (2.15+) for lost quorum. https://docs.nats.io/running-a-nats-service/nats_admin/jetstream_admin/disaster_recovery
- NATS upgrades: lame-duck (`SIGUSR2`), non-leaders first, meta-leader last, PodDisruptionBudget `minAvailable: 2`. https://docs.nats.io/running-a-nats-service/nats_admin/upgrading_cluster
- Cloudflare 2023-11-02: Kafka and ClickHouse ran in one facility with hidden dependencies from HA services; full-facility loss had never been tested; the DR site was overwhelmed by a surge of API calls. https://blog.cloudflare.com/post-mortem-on-cloudflare-control-plane-and-analytics-outage/
- Datadog 2023-03-08: a default OS update window (06:00 UTC) hit five independent regions at once; recovery was limited by cloud API rate limits and quorum stores; lesson is to prioritise live data over backfill. https://www.datadoghq.com/blog/2023-03-08-multiregion-infrastructure-connectivity-issue/

**DR runbook requirements:** RPO/RTO per store (Postgres config 5 min/1 h; telemetry 15 min/4 h with sensors buffering 24–72 h and replaying; bus is rebuildable); weekly full plus daily incremental ClickHouse backups to a second region and account, with object lock; quarterly automated restore into a scratch cluster with row-count and checksum comparison; a written evacuation sequence (freeze deploys, promote Postgres, restore or attach store, promote bus mirrors, repoint DNS, throttle sensor reconnect with jitter); a dependency inventory checked in CI; an annual full-region game day; SOC 2 A1.2/A1.3 evidence captured automatically from each drill.

### 6. Self-hosted upgrades and version skew

| Project | Skew rule | Stops / skipping | Support window |
|---|---|---|---|
| Teleport | Auth newest; proxy ≤ auth; agents and clients may be one major behind, never ahead | One major at a time; rollback of auth requires restoring the pre-upgrade backend backup | — |
| Kubernetes | kubelet up to three minors older than apiserver, never newer; kubectl ±1 | No skipping minors | Three minors, ~12 months each |
| Wazuh | Manager same or newer than agents; central components identical to patch level | — | — |
| GitLab | — | Required stops x.2, x.5, x.8, x.11 since 17.5; finish background migrations at each | Bug fixes current minor only; security fixes current + 2 |
| Sentry self-hosted | — | Hard stops (latest 26.5.0, 26.7.0); seven published "versions to avoid" in 2025–26 | "We don't patch old versions"; downtime expected |
| Grafana | — | — | 9 months per minor, 15 for the last minor of a major |
| Elastic | — | — | Major maintained 30 months; two latest minors + last minor of prior major |
| ClickHouse | — | — | Three latest stables plus an LTS (26.3 still supported) |

Sources: https://goteleport.com/docs/upgrading/overview/, https://kubernetes.io/releases/version-skew-policy/, https://documentation.wazuh.com/current/upgrade-guide/index.html, https://docs.gitlab.com/update/upgrade_paths/, https://docs.gitlab.com/policy/maintenance/, https://develop.sentry.dev/self-hosted/releases/, https://grafana.com/docs/grafana/latest/upgrade-guide/when-to-upgrade/, https://www.elastic.co/support/eol, https://github.com/ClickHouse/ClickHouse/blob/master/SECURITY.md

Fleet rollout references: Teleport Managed Updates v2 uses `autoupdate_config`/`autoupdate_version`, named groups with maintenance windows, `halt-on-error` or `time-based` strategies, `canary_count`, automatic per-agent rollback on failed health checks, and `--base-url` mirrors for disconnected sites (https://goteleport.com/docs/upgrading/agent-managed-updates/). CrowdStrike's RCA commits content updates to canary then successive rings with bake time, plus customer control over where and when content deploys (https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf).

**Draft policy**

- Order: control plane → gateways → sensors. Sensors never newer than the server.
- Server accepts sensors from the current and two previous minors and from the previous LTS; wire protocol is additive within a major; unknown fields preserved.
- Monthly minors; two LTS branches a year, each supported 12 months; security fixes to the latest three minors and live LTS.
- Upgrades are LTS-to-LTS or minor-by-minor; required stops are declared in a machine-readable manifest and enforced by a preflight command that refuses unsafe jumps.
- Migrations are expand/contract across two releases, so the previous binary runs on the new schema and rollback needs no restore; long migrations run in the background with a completion gate.
- Three independent channels: binaries, policy/schema, detection content. Content is data-only, validated by the same interpreter the sensor runs, ring-deployed, pinnable and instantly revertible.
- Air-gapped bundle: one signed archive (images, charts, sensor packages, content, SBOM, migration manifest); Zarf and Hauler are both Apache-2.0 precedents.

### 7. Support model

- PostHog: first-response targets 72 h (pay-as-you-go), 48 h, 24 h, 8 h (enterprise), weekdays only; free tier is community only, mostly answered by AI and other users; product engineers rotate weekly as "Support Hero"; self-hosted is "officially unsupported", no paid plans, no tagged releases, no CVEs, Kubernetes deployments discontinued. https://posthog.com/handbook/growth/customer-support and https://posthog.com/docs/self-host
- Diagnostics: Replicated `troubleshoot` (Apache-2.0) ships support bundles with a built-in redaction phase covering AWS keys, password/token/database/user environment variables and connection strings, plus custom redactors. `sos` is GPL-2.0. https://troubleshoot.sh/docs/redact/ and https://github.com/replicatedhq/troubleshoot
- Recommended tiers: community (forum, AI answerer grounded in docs and source); paid self-hosted support on LTS only; hosted plans with response targets, not resolution guarantees; partner tier with a shared channel and pre-release content.

### 8. Agents versus humans

| Agents run unattended | Agent proposes, human approves | Human only |
|---|---|---|
| Alert triage and enrichment; SLO burn analysis; status-page drafts | Publishing Sev1/Sev2 status and customer email | Declaring a security breach and regulator or customer notification |
| Restore drills into scratch environments | Production restore, failover, region evacuation | Deleting backups or tenant data; key ceremonies |
| Dependency and base-image update PRs; release notes; upgrade-path manifests | Promoting a release or content pack past the canary ring | Signing releases; changing signing or root keys |
| First-line support answers; bundle analysis | Credits, refunds, plan changes, quota overrides | Contracts, pricing, legal and abuse escalations |
| Usage reconciliation between ledger and billing provider | Invoice corrections | Access to customer telemetry outside a support grant |
| Scaling within pre-approved bounds; quota throttling of a noisy tenant | Suspending a tenant | Production IAM and break-glass |

Every agent action needs an audit record naming the approving human, which also satisfies SOC 2 change-management evidence. On-call needs at least two humans per rotation; agents shorten time-to-context, they do not hold the pager.

### 9. Adjacent vendor docs (requested)

- Microsoft Agent 365: GA 2026-05-01, licensed per user, at least one licensed user to enable, "works best" with E5; registry and agent map in the Microsoft 365 admin center with Entra, Purview and Defender. https://learn.microsoft.com/en-us/microsoft-agent-365/overview (page dated 2026-08-19)
- BeyondTrust AI Agent Security: "Pathfinder" endpoint agent on Windows 11/Server 2022+ x64 and macOS 14/15/26 only; kernel- and network-level enforcement plus tool-call hooks; requires a trusted tenant root certificate for HTTPS inspection; policy replay against recorded activity before saving; macOS support is current major plus two; console is hosted; licensing unit unpublished. https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security

## Matrix

| Decision | Reuse | Build | Avoid |
|---|---|---|---|
| Usage metering | CloudEvents format; ClickHouse materialised views | Native ledger, hierarchy roll-ups, signed statements | A second Kafka stack only for metering |
| Rating and invoicing | Stripe (hosted), Kill Bill or OpenMeter (self-hosted, optional) | Thin adapters | Lago/Flexprice/Meteroid inside the product (AGPL) |
| Tenant isolation | ClickHouse workloads and quotas; NATS stream limits | Per-tenant token buckets at ingest; sensor backpressure | Dropping detections at quota |
| Backups | ClickHouse `BACKUP` to S3; NATS snapshots and mirrors | Automated restore drills with evidence | Treating replicas as backups |
| Fleet upgrades | Teleport-style groups, canaries, auto-rollback | Preflight and upgrade-path manifest | Shared global auto-update windows |
| Diagnostics | `troubleshoot` redactor patterns | Preview-and-approve bundle with domain redactors (prompts, paths, repo names) | GPL collectors in an Apache product |
| Air-gap | Zarf or Hauler packaging | Signed offline content packs | Pull-at-install images |

## Weak points, gaps and risks

- The cost model rests on unmeasured assumptions (events per endpoint, review rate, tokens per review). A two-week telemetry capture on real developer machines should precede any pricing.
- OpenMeter is beta after 236 pre-releases and its hosted business moved into Kong; its KNOWN-ISSUES file documents an under-billing bug in legacy invoicing. Treat it as optional.
- Kill Bill is mature but JVM, in-arrear usage only, and heavy for a single-laptop install.
- ClickHouse workload scheduling does not yet cover merges or memory reliably; large tenants still need a siloed service.
- AWS SaaS Lens is dated 2023-04-04; useful vocabulary (silo/pool/bridge), stale detail.
- Model prices changed materially during 2026; any hard-coded price table will rot within a quarter.
- An inline verdict SLO of 99.95% is stricter than what observability vendors contract; it is only credible with local enforcement and a fail-mode setting per policy.

## Implications for our design

1. Make "who pays for tokens" a first-class tenant setting (customer key, platform key with cap, local model) and meter tokens by key owner from day one.
2. Put a deterministic policy engine in front of every LLM review; add a verdict cache and a per-tenant daily token budget with a defined fallback verdict.
3. Scope sensor telemetry to agent process trees at the edge and expose the filter as policy; ship volume estimates in the console before a tenant enables a noisy source.
4. Implement the usage ledger, hierarchy and signed statements in core under a permissive licence; keep billing engines as adapters.
5. Encode the skew policy in the handshake: the server advertises supported sensor range; out-of-range sensors keep enforcing cached policy and report a health finding.
6. Ship `preflight`, `backup`, `restore --verify` and `support-bundle --preview` commands in the first self-hosted release; they are also the agent-operable surface.
7. Separate release channels for binaries and detection content, both with rings, pinning and one-command rollback, in SaaS and self-hosted alike.
8. Design every stateful component with a documented, tested restore, and generate SOC 2 availability evidence from the drills.

## Ideas worth stealing and whitespace

- Policy replay against recorded activity before saving (BeyondTrust) doubles as a cost preview: show how many LLM reviews a rule would have triggered.
- Grafana's separate SLO for autonomous actions maps directly onto enforcement and response actions.
- Elastic's switch away from per-endpoint fees suggests offering both a predictable per-endpoint plan and a volume plan from the same ledger.
- Whitespace: supported LTS for a self-hosted security product with offline bundles; cryptographically signed usage statements for MSP and OEM revenue share; a public per-tenant cost calculator; quota behaviour that degrades fidelity without dropping detections; redaction that understands prompts and source paths.

## Could not verify / open questions

- SLA pages for Teleport, Elastic Cloud and ClickHouse Cloud returned 404 at the URLs tried; no EDR vendor SLA was retrieved.
- AICPA Trust Services Criteria text sits behind a login; A1.1 (capacity), A1.2 (backup and recovery infrastructure) and A1.3 (recovery testing) are cited from memory.
- AWS SaaS Lens sub-pages and Elastic Fleet Server compatibility pages returned no usable body.
- No primary source found for MSP billing practice (PSA integrations, per-endpoint minimums) or for real per-endpoint telemetry volumes from AI coding agents.
- Postgres PITR tooling, object-store list prices and self-managed compute prices were not fetched; the model uses ClickHouse Cloud list prices as an upper bound.
- Teleport's supported-version window and Microsoft Agent 365 list price were not on the pages read.

## Sources

All accessed 2026-11-09.

- https://clickhouse.com/pricing — ClickHouse Cloud pricing
- https://clickhouse.com/docs/operations/backup — ClickHouse backup and restore
- https://clickhouse.com/docs/guides/developer/ttl — ClickHouse TTL
- https://clickhouse.com/docs/operations/workload-scheduling — ClickHouse workload scheduling
- https://github.com/ClickHouse/ClickHouse/blob/master/SECURITY.md — supported versions
- https://platform.claude.com/docs/en/about-claude/pricing — Claude API pricing
- https://code.claude.com/docs/en/monitoring-usage — Claude Code OpenTelemetry events
- https://www.elastic.co/pricing/serverless-security — Elastic Security Serverless pricing
- https://www.elastic.co/support/eol — Elastic maintenance policy
- https://documentation.wazuh.com/current/quickstart.html and https://documentation.wazuh.com/current/upgrade-guide/index.html — Wazuh sizing and upgrade compatibility (4.14)
- https://github.com/openmeterio/openmeter (README, docs/architecture.md, KNOWN-ISSUES.md) — OpenMeter
- https://github.com/killbill/killbill and https://docs.killbill.io/latest/userguide_subscription.html — Kill Bill
- https://github.com/getlago/lago and https://getlago.com/blog/open-source-licensing-and-why-lago-chose-agplv3 — Lago licence
- https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api — Stripe meter events
- https://grafana.com/legal/grafana-cloud-sla/ — Grafana Cloud SLA
- https://grafana.com/docs/grafana/latest/upgrade-guide/when-to-upgrade/ — Grafana release and support policy
- https://gitlab.com/gitlab-com/content-sites/handbook/-/raw/main/content/handbook/engineering/infrastructure-platforms/incident-management/_index.md — GitLab incident management
- https://docs.gitlab.com/update/upgrade_paths/ and https://docs.gitlab.com/policy/maintenance/ — GitLab upgrade paths and maintenance policy
- https://docs.gitlab.com/security/identity_verification/ — GitLab identity verification
- https://posthog.com/handbook/engineering/operations/incidents, https://posthog.com/handbook/growth/customer-support, https://posthog.com/docs/self-host, https://posthog.com/docs/billing/limits-alerts — PostHog
- https://docs.sentry.io/pricing/quotas/spike-protection/ and https://develop.sentry.dev/self-hosted/releases/ — Sentry
- https://goteleport.com/docs/upgrading/overview/ and https://goteleport.com/docs/upgrading/agent-managed-updates/ — Teleport
- https://kubernetes.io/releases/version-skew-policy/ — Kubernetes version skew
- https://docs.nats.io/running-a-nats-service/nats_admin/jetstream_admin/disaster_recovery, https://docs.nats.io/running-a-nats-service/nats_admin/upgrading_cluster, https://docs.nats.io/nats-concepts/jetstream/streams — NATS
- https://sre.google/workbook/alerting-on-slos/ and https://sre.google/workbook/error-budget-policy/ — Google SRE Workbook
- https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/saas-lens.html — AWS SaaS Lens (2023-04-04)
- https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf — CrowdStrike RCA (2024-08-06)
- https://www.datadoghq.com/blog/2023-03-08-multiregion-infrastructure-connectivity-issue/ — Datadog outage review
- https://blog.cloudflare.com/post-mortem-on-cloudflare-control-plane-and-analytics-outage/ — Cloudflare post-mortem (2023-11)
- https://troubleshoot.sh/docs/redact/ and https://github.com/replicatedhq/troubleshoot — support bundles and redaction
- https://github.com/zarf-dev/zarf and https://github.com/hauler-dev/hauler — air-gap packaging (Apache-2.0)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Microsoft Agent 365 (2026-08-19)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — BeyondTrust AI Agent Security

## Independent verification

Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (shared budget exhausted), so every check is a direct fetch of primary documentation or a read-only `gh` query against source repositories. Where the researcher's page is the only primary source (price lists, SLA text) it was re-fetched and cross-checked against a second page where one exists.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Claude API list prices: Haiku 5.5 $0.10/$0.50 (≤100k prompts, cache hit $0.01); Sonnet 5.5 $2/$10 (cache hit $0.10); Batch 50% off | Confirmed | Both the docs table and claude.com/pricing agree. Haiku 5.5 over 100k tokens is $0.50/$2.50. US-only inference (`inference_geo`) adds a 1.1x multiplier, which the model omits. The "review is the dominant line" inference is only partly right, see row 9. | https://claude.com/pricing, https://platform.claude.com/docs/en/about-claude/pricing |
| 2 | ClickHouse Cloud AWS us-east-1: $0.218/$0.298/$0.390 per CU-hour, 1 CU = 8 GiB + 2 vCPU, $25.30/TB-month, backups at storage rate | Confirmed | Exact list values are $0.21811/$0.29846/$0.39030. The billing docs' worked examples back-calculate to the same rates and use $25.30/TB for data and backup. | https://clickhouse.com/docs/cloud/manage/billing/overview, https://clickhouse.com/pricing |
| 3 | OpenMeter and Kill Bill Apache-2.0; Lago, Flexprice, Meteroid AGPL-3.0; OpenMeter latest `v1.0.0-beta.236`; README says beta with breaking changes | Confirmed | GitHub API: licences as stated; `releases/latest` = v1.0.0-beta.236 (2026-10-09). README: "Releases are beta and can include breaking changes." Kill Bill 0.24.22 and Lago v1.57.0 also match. | `gh api repos/{openmeterio/openmeter,killbill/killbill,getlago/lago,flexprice/flexprice,meteroid-oss/meteroid}` |
| 4 | OpenMeter needs Kafka, ClickHouse, PostgreSQL; Redis optional (dedup off by default); Svix for webhooks; hosted service is Kong Konnect Metering & Billing | Confirmed | README "Running OpenMeter" and docs/architecture.md say exactly this; with dedup enabled and no Redis driver it falls back to an in-process memory store. openmeter.io/pricing headline: "OpenMeter Cloud is now Konnect Metering & Billing". The official Helm chart is described as for development, not production. | https://openmeter.io/pricing, https://openmeter.io/docs/open-source/architecture, repo README |
| 5 | ClickHouse: replication does not protect against human error or bugs; BACKUP/RESTORE to S3, incremental via `base_backup`, config-file users excluded, no PITR | Confirmed | Actual wording: "While replication provides protection from hardware failures, it doesn't protect against human errors ... and software bugs". The brief's quoted sentence is a paraphrase, not a quote. "No PITR" is correct but is an inference from absence: the backup docs never mention point-in-time recovery, and the only PITR in ClickHouse docs is for Managed Postgres. | https://clickhouse.com/docs/operations/backup/overview, `gh search code --repo ClickHouse/ClickHouse "point-in-time recovery"` |
| 6 | NATS: R3 "is not a recovery mechanism"; DR is snapshots (`--consumers`) plus mirrors in a separate JetStream domain; unlimited default limits can fill the disk and take the server down | Corrected | The phrase "is not a recovery mechanism" does not appear; the page says "R3 is availability, not a backup" and "it's availability, not recovery". A separate domain is not mandatory: a DR mirror is "normally placed in its own JetStream domain (a leaf node) or an independent cluster". Snapshots with `--consumers`, unlimited defaults and "a full disk takes the server down with it" are confirmed. | https://docs.nats.io/running-a-nats-service/nats_admin/jetstream_admin/disaster_recovery, https://docs.nats.io/nats-concepts/jetstream/streams, `nats-io/nats.docs` |
| 7 | Teleport: Auth newest; agents and clients one major behind, never ahead; no skipping majors; Auth rollback needs pre-upgrade backend restore | Confirmed | Read from doc source (`docs/pages/upgrading/overview.mdx`, `includes/compatibility.mdx`). Extra rule worth encoding: Proxy and agents refuse to connect to an Auth Service on an older major by default. | https://github.com/gravitational/teleport/blob/master/docs/pages/includes/compatibility.mdx |
| 8 | Grafana Cloud SLA: 99.5% of requests per month, 99.5% for autonomous actions, credits 10/20/50/100%, 300% volume exclusion | Confirmed | Credit bands <99.5/<99.0/<98.0/<97.0; maintenance 24 h notice, one per quarter; claims within 10 days. Autonomous actions are alert evaluation and synthetic monitors, not AI agents. | https://grafana.com/legal/grafana-cloud-sla/ |
| 9 | Modelled COGS about $0.40–$0.90 per endpoint-month at 10 / 1,000 / 50,000 endpoints, LLM 65–80% of total | Corrected | The arithmetic reproduces from the stated inputs, but the summary is tighter than the brief's own table ($0.28–$1.00). LLM share recomputes to roughly 48–84% (1,000 endpoints: 48% with Haiku review and $300 infra; 50,000: 67–84%). In the Haiku case review is only ~$0.025 per endpoint-month; the 5 Sonnet investigations ($0.25) are ~90% of LLM spend, so the dominant line is LLM investigation, not review. The 10-endpoint row is marginal cost in a pooled service and excludes the $1.5–3k/month regional floor. | Recomputed from the prices in rows 1–2 |
| 10 | PostHog self-host is officially unsupported, no paid support, no tagged releases, no CVEs; Sentry self-hosted does not patch old versions and has hard stops | Confirmed | PostHog: "We don't do tagged releases", "We don't publish CVEs". Sentry: "We don't patch old versions, but if a bug is bad enough we may cut an out-of-cycle point release"; hard stops 9.1.2, 21.5.0, 21.6.3, 23.6.2, 23.11.0, 24.8.0, 25.5.1, 26.5.0, 26.7.0. | https://posthog.com/docs/self-host, https://develop.sentry.dev/self-hosted/releases/ |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Reviewing 100% of a heavy user's 22,000 monthly tool calls costs "~$25 (Haiku 4.5)" | Corrected | The figure assumes a 1,500-token cached prefix at $0.10/MTok, but Haiku 4.5's minimum cacheable prompt is 4,096 tokens, so that prefix is silently processed uncached. Uncached cost is about $0.0025 per review, roughly $55/month. Haiku 5.5 and Sonnet 5.5 have a 512-token minimum, so those figures ($2.50, $47) stand. | https://platform.claude.com/docs/en/build-with-claude/prompt-caching |
| Sentry: "seven published versions to avoid in 2025–26" | Corrected | Seven are listed in total, but one is 23.7.0; six fall in 2025–26 (25.6.0, 25.6.1, 25.9.0, 25.12.0, 26.3.0, 26.4.0). | https://develop.sentry.dev/self-hosted/releases/ |
| Stripe meter-event constraints (1,000/s, 10,000/s v2, one concurrent call per customer per meter, 35 days / 5 minutes, 100 dimension combinations per customer) | Confirmed, with omissions | Also applies: 10,000 unique dimension combinations per meter per hour, and Connect platforms calling on behalf of a connected account get only the regular 100 operations/s. The second matters for a partner/MSP hierarchy built on Connect. Up to 200,000 events/s is available through sales. | https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api |

Also spot-checked and found accurate: Elastic per-endpoint fees removed 2026-03-23 with the stated ingest, retention and managed-LLM prices; Microsoft Agent 365 GA 2026-05-01, per-user licensing; BeyondTrust platform support and policy replay (the page does not explicitly say the console is hosted, only that sign-in is at a vendor URL per tenant); ClickHouse supported versions 26.10/26.9/26.8 plus 26.3; ClickHouse TTL merge timeout of 4 h and no tiered storage in Cloud; Elastic maintenance (precisely: the longer of 30 months from GA or 18 months from the next major's GA).
