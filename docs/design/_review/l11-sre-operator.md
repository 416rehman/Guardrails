# L11 review: site reliability and operations (whole spine)

Reviewed 2026-11-10 against draft 1, as the person who will run the hosted cells and answer self-hosted tickets. References are to `research/` briefs. I endorse and do not repeat c1 (backup, volume reconciliation, cells), c5 (trust topology, skew) and l05 (usage ledger).

## Summary

The spine designs the sensor's failure modes with care and the service's not at all. Nothing says which server paths sit inline on enforcement, who is paged, how tenants are kept apart under load, how the server is upgraded, or what a restore does to counters. Four decisions quietly put the hosted service back on the enforcement path, against P4. The change that matters most is F1: tier every server dependency and state what the endpoint does when each is gone.

## Findings

### F1 (blocker, missing). P4 against D-40, D-31, D-27, D-36: no service tiers, no offline contract

**Problem.** D-40's verdict-provider adapters are synchronous calls from vendor clouds into our hosted decision API. D-31 sends step-up approvals through the server. D-27 releases short-lived credentials. D-36 issues certificates and TUF metadata that expire. Each is an inline dependency with no stated behaviour when it is down. A regional blip then fails open unseen (webhooks) or stops every developer (`STEP_UP` becomes `DENY`; no credentials).

**Evidence.** 26 weak points ("A cloud-only decision point will silently fail open"); 03 line 68 (Copilot Studio: 1,000 ms, then allow); g10 weak points (a 99.95% inline objective is "only credible with local enforcement"); 36 implication 6 (cached policy on control-plane loss).

**Amendment, new D-48.** "Tier 0 (inline): a `decide` target serves verdict-provider adapters and AuthZEN from compiled bundles in memory, with no call to Postgres, bus or lake on the request path, deployed apart from every other target; approval relay and command dispatch are also tier 0. Tier 1: ingest, control, content. Tier 2: query, review, intel. A lower tier never blocks a higher one. With the server unreachable: cached policy and grants keep working; `STEP_UP` falls back to the local platform authenticator; the credential broker serves from the customer's store with a stated cache lifetime; certificate or TUF timestamp expiry marks a device Stale and never stops enforcement or renewal; kill state persists. D-33 gains a table: target, tier, state, scaling model, effect of loss."

### F2 (blocker, missing). Section 6, P9, D-22: no service objectives, no self-monitoring

**Problem.** P9 covers hosts, not the pipeline. A stalled `detect` consumer or stuck outbox produces a quiet console, which a customer reads as "nothing found". Section 6 has no service target. D-22 makes heartbeat gaps tamper findings, so a cell outage yields one per device on recovery.

**Evidence.** g10 section 3 (draft objectives, burn-rate paging); 24 sizing ("SLOs to publish").

**Amendment, new D-49.** "28-day objectives: tier 0 verdict in 150 ms, 99.95%; ingest acknowledgement 99.9%; events queryable in 60 s, 99%; finding within 2 minutes, 99%; policy to connected sensors in 60 s at p99; console and API 99.9%; notifications and response commands in 60 s, 99.5%. Page on burn rates 14.4 and 6, for tiers 0 and 1 only. Every cell and self-hosted install runs a synthetic sensor that sends a signed known-bad sequence every five minutes and alarms through an independent path when the finding or notification is missing. Per-organisation pipeline lag is shown as 'could not look'. The server records its own unavailability windows and suppresses gap findings inside them."

### F3 (major, risky). D-33, D-34: tenant queries share a process with ingest; no fairness decision

**Problem.** g10's noisy-tenant controls rested on ClickHouse workloads. D-34 removed ClickHouse and put nothing in their place. In `all` and N replicas of `all`, a 30-day hunt, a review batch and compaction share a process with ingest and detect, so one out-of-memory kill stops ingest for every tenant. DataFusion's memory pool counts only operators that reserve (recalled, not re-checked). "Quotas" appears once, in section 3.

**Evidence.** g10 section 4 (NATS: "a full disk takes the server down"; "always keep verdicts, detections and audit records"); 24 reference architecture (per-organisation query queues and caps).

**Amendment, new D-50.** "Ingest: per-organisation token buckets on events and bytes; over quota the sensor is told to sample raw events; receipts, findings, health and audit are never dropped. Bus: per-organisation byte and age limits with discard-new. Query: per-organisation concurrency, memory, scanned-bytes and time limits with spill to disk. In the `all` shape, `query` and `review` run as a child process under a cgroup or job-object memory cap. The hosted service runs one target per process only." Settled by S1.

### F4 (major, missing). D-30, D-31, D-36, D-39: a restore rewinds monotonic state

**Problem.** Restoring Postgres to five minutes ago rewinds kill-switch counters (the next command is rejected as a replay), grant revocations (a revoked approval lives again), enrolment-token use caps, and acknowledgement watermarks (sensors have deleted what the server just lost). A tile log restored to a smaller tree is a fork to its witnesses.

**Evidence.** g10 section 5 (recovery points of 5 and 15 minutes); 36 implication 4 (monotonic counter and expiry); 23 section 4.

**Amendment, added to c1's D-34a.** "Restore is a signed state transition. `restore` mints a new server epoch signed by the deployment root; counters are (epoch, n). Revocations, kill states and consumed token ids are also written synchronously to versioned object storage and replayed after restore. Sensors keep acknowledged batches until a durable watermark that advances only after lake commit and catalogue backup, and re-send from it when the epoch changes. The audit log and TUF repository are never restored backwards: the old log is frozen with a final checkpoint and a new shard starts." Settled by S3.

### F5 (major, missing). D-36: reconnect storms and connection draining

**Problem.** A cell near brief 24's cap of 250,000 endpoints holds two long-lived connections per sensor. Every gateway deploy drops them, and after an outage every sensor replays its spool at once. D-36 has no server-driven flow control.

**Evidence.** g10 section 5 (Cloudflare's recovery site "overwhelmed by a surge"; Datadog: live data before backfill; "throttle sensor reconnect with jitter").

**Amendment to D-36.** "The server controls flow. Sensors reconnect with full-jitter exponential backoff seeded by device id; any response may carry retry-after and a backfill credit. Receipts, findings and health drain before backfill, which is credited per organisation. Gateways drain over a jittered window of at least five minutes. A cold start of a full cell is a release gate." Settled by S2.

### F6 (major, missing). D-37: the server has no lifecycle decision

**Problem.** D-37 covers what reaches sensors. Nothing covers server cadence, long-term support for self-hosters, upgrade paths, migration rules, lake files written under older schemas across 13 months of retention, or hosted deploy order. "One-command rollback" is false for the server unless migrations are expand and contract.

**Evidence.** g10 section 6 (draft policy; Sentry's nine hard stops and six versions to avoid in 2025-26) and section 5 (Datadog's shared update window hit five regions).

**Amendment, new D-37a.** "Order: server, gateways, sensors. Monthly minors; two LTS branches a year, each patched 12 months, for every user. Migrations are expand and contract across two releases; long ones run in the background behind a completion gate. A machine-readable upgrade-path manifest and `grd server preflight` refuse unsafe jumps and a stale backup. Lake files carry a schema version; readers support every version inside the longest retention. CI upgrades from every supported version and rolls back one release. Hosted: one canary cell, then waves with a 24-hour bake; no change, node patching included, runs in two regions in one window."

### F7 (major, missing). D-47, section 8: nobody holds the pager

**Problem.** D-47's list of what humans keep omits on-call, incident lead, production restore, tenant deletion, break-glass and access to customer data. M3 ships a hosted beta. Operations agents with production credentials are the insider this product exists to contain.

**Evidence.** g10 section 8 ("at least two humans per rotation"; agents "do not hold the pager").

**Amendment.** D-47 adds: "Humans also keep the pager and the incident lead role for Sev1 and Sev2, production restore and failover, tenant suspension and deletion, break-glass and breach declaration. Operations agents triage, draft and propose; every production change names the approving human. Operator access to an organisation's data needs a tenant-visible, time-boxed support grant." Section 8, question 3 becomes: "Who carries the pager? Hosted beta is business-hours with no SLA until two humans staff each rotation."

### F8 (major, risky). D-37: gates unnamed, small fleets cannot canary, no rapid lane

**Problem.** "Health-gated halt" names no signal. A five-device organisation or a 20-device self-hosted install has no canary population. Pinning across three channels creates combinations nobody tests.

**Evidence.** 24 Fleet (automatic halt on crash-free rate, check-in loss, CPU, block-rate anomalies); g06 implication 6 (`standard` and `rapid` channels); 25 implication 7 (48-hour delayed ring).

**Amendment to D-37.** "Gates: crash-free rate, check-in loss, CPU and memory against baseline, deny-rate and prompt-rate change, hook latency p99, agent-start probe. Halt is automatic; resume is human. Hosted rings span organisations: project dogfood, opted-in early organisations, 25%, all. Self-hosted installs default to a channel 48 hours behind hosted broad. A rapid lane carries only indicators and reputation verdicts and still bakes 30 minutes in each of the first two rings. Pinning is N or N-1."

### F9 (major, missing). P6, D-34 Blobs: no self-hosted server contract

**Problem.** The scaled Blobs adapter is "S3, GCS, Azure Blob", but MinIO was archived in April 2026, so on-premises HA and air-gapped sites have no named object store. There is no tested matrix, no server diagnostics and no decision on phoning home.

**Evidence.** 11 section 11 (SeaweedFS Apache-2.0; Garage AGPL); g10 section 7 and implication 6.

**Amendment, new D-51.** "Each release publishes the tested Kubernetes lines, Postgres and NATS versions and object stores (AWS, GCS, Azure, SeaweedFS), checked by a conformance test inside `preflight`. M2 ships `grd server preflight`, `backup`, `restore --verify` and `support-bundle --preview` (redaction on the host). Self-hosting is supported as `all` and N replicas of `all`; one target per process is supported above a stated size. No phone-home by default; an opt-in advisory check lists versions to avoid."

### F10 (major, missing). D-29, D-04: who pays for tokens

**Problem.** D-29 runs review "by default under a per-tenant token budget" without saying whose key pays or what happens when the budget is spent. A free tier on platform keys is an open tap.

**Evidence.** g10 verification row 9 (model spend is 48 to 84% of cost; Sonnet investigations are about 90% of it) and implications 1 and 2.

**Amendment to D-29.** "Token payer is an organisation setting: customer key, capped platform key or local model. Free organisations use customer keys or local models only. When the budget is spent, model tiers stop, deterministic tiers continue and the console shows 'review skipped'."

## Spikes

| Id | Question | Method | Pass |
|---|---|---|---|
| S1 | Does `all` survive a hostile query? | Three `all` replicas, 10,000 simulated endpoints at 100,000 events a day; one organisation runs 20 concurrent 30-day hunts during compaction. | No process killed; ingest acknowledgement p99 under 200 ms; other organisations' freshness within 60 s. |
| S2 | Does a cell survive a cold start? | Restart all gateways with 50,000 simulated sensors each holding a 24-hour spool. | Live-lane findings within 2 minutes; no gateway out of memory; backfill done in 6 hours. |
| S3 | Is restore safe? | Restore Postgres to 15 minutes earlier with 100 sensors, one revoked grant and one issued kill. | No acknowledged event missing after replay; the grant stays revoked; a new command is accepted and an old one refused. |
| S4 | Does a server outage stop developers? | Block the server for four hours on 20 real developer machines. | Step-up and credential helpers still work; no new denials; zero tamper findings on recovery. |

## Agreed

- P4: local decisions make an availability promise affordable.
- One binary; `all` and N replicas of `all` as tested shapes (24 verification row A).
- Three release channels with last-known-good; content disabled before binaries roll back.
- TUF with offline roots.
- Organisation as the hard boundary, its id taken from the device credential.
- Real-time detection on the bus, never on the store.
