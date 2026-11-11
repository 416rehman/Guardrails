# Review L05: the spine read by an MSP technical director

Lens: 80 small and mid-sized clients, twelve technicians, most clients with no IT staff. Briefs: 24, g07, g10, 27, 33, plus 25, 26, 36, h04 and h08.

## Summary

The core suits me: local decisions, a hard Organisation boundary, layered policy with locks, and a provider tier in the open build. But the provider tier is one clause in section 3 and one sentence in D-35. What I would operate daily is undecided: who owns a tenant I create, how I bill it, how a baseline change reaches 80 clients safely, how I enrol through an RMM, where the cross-client queue comes from, and how tickets reach my PSA. The change that matters most is finding 1: fix the tenancy vocabulary before thirty documents inherit a hierarchy that cannot express an MSP.

## Findings

### 1. Blocker, missing: the hierarchy cannot express operator, distributor or client segments (section 3, D-35, D-41 L6)

Problem. "Provider" is one level and is conflated with "operator", which D-35 uses and never defines. When Loonaro hosts and I manage there are three parties, and it is unclear whose key co-signs policy. An L6 OEM or a distributor needs MSPs beneath it. With no unit for "my 12 healthcare clients", one Provider layer means one baseline for all 80.

Evidence. g10 section 2: "partner (embed/OEM) > MSP > customer > site ... every row carries all ancestor IDs". 24 section 2: Defender tenant groups are "the MSSP feature bar".

Amendment. Add to section 3: "**Operator**: whoever runs the server. **Provider**: manages Organisations under delegation; may have one parent Provider (distributor or OEM) holding provisioning and billing rights only, never data access. **Organisation set**: a named Provider-side grouping of Organisations, the unit for baseline assignment, rollout rings, queue filters, delegation scope and reports. Co-signing and customer-managed keys sit at Provider or Organisation level, never with the Operator."

### 2. Major, missing: GDAP-only delegation does not fit tenants the MSP creates (D-35, D-38)

Problem. "Customer-approved, time-bound" assumes a customer administrator exists. I create the tenant and am its admin by contract. A delegation that lapses mid-incident is an outage of my service.

Evidence. Microsoft GDAP FAQ (learn.microsoft.com/partner-center/customers/gdap-faq, fetched today): unapproved requests expire after 90 days, maximum two years, expired means request again. h08 acceptance: "new tenant from template in 10 minutes".

Amendment. Add to D-35: "Two origination modes. Provider-originated: the Provider is owner of record from creation; the customer may claim ownership later, converting access to a delegation. Customer-originated: GDAP-style approval. Delegations bind Provider groups to roles, auto-extend by default, warn 30 days before expiry and are revocable by the customer. Technicians sign in at the Provider's IdP and get per-Organisation tokens by token exchange. Every cross-organisation action is written to both audit logs under the named technician. Organisation lifecycle (active, suspended, detached, exported, crypto-shredded) is a defined state machine; a suspended Organisation's sensors keep enforcing cached policy."

### 3. Major, missing: no usage ledger, so nothing can be billed or rolled up (D-04, D-29, D-33)

Problem. D-33 has no metering target; D-04 lists revenue with no measurement behind it; D-29 has a token budget but no token payer. I cannot invoice 80 clients.

Evidence. g10 section 2 and implications 1 and 4: ledger in core, ancestor ids on every row, signed monthly statements, rating outside core, token payer as a first-class setting. h08 implication 11.

Amendment. Add D-48: "Usage ledger in core. Append-only CloudEvents usage records carrying all ancestor ids. Meters: active endpoints (daily distinct, monthly average), active users, agents observed, bytes ingested, retention GB-months, LLM tokens by model and key owner (Organisation, Provider, Operator). Roll-ups per level, export, signed monthly statement. Rating, invoicing and tax are adapters (Stripe, Kill Bill, PSA agreements). At quota, raw fidelity degrades; verdicts, detections and audit never drop." Add `usage` to the D-33 targets.

### 4. Major, risky: a Provider-layer change is a fleet change with no staging rule (D-11, D-30, D-37)

Problem. D-11 says narrowing changes "apply automatically". A narrowing Block rule in my baseline can stop every developer at 80 clients at once. D-37 rings are per customer; nothing makes the Organisation a ring unit. D-30's provider-scope kill switch makes my console a high-value target.

Evidence. 24 TL;DR: policy and content "must ride the same rings as binaries". 36 implication 7: a declared maximum blast radius and per-tenant rate limit for automated actions.

Amendment. D-11: "'Applies automatically' waives approval, never staging. A Provider-layer change is a rollout whose ring unit is the Organisation: the Provider's own Organisation, then a canary Organisation set, then the rest, with bake time and automatic halt on per-Organisation block-rate or prompt-rate anomaly." D-30: "Provider-scope actions need two Provider approvers with step-up authentication, a default cap of Organisations per hour, and an entry in each affected Organisation's audit log."

### 5. Major, risky: isolation and cross-client views are undefined for a small self-hosted MSP (D-34, D-35)

Problem. D-35 names Postgres row-level security as an isolation layer; D-34 lets the relational port be SQLite, which has none. D-34's revisit targets test one large tenant, never many small ones. Nothing says how a cross-client queue is served, and the easy implementation is a role that bypasses tenant context.

Evidence. 24 "Tenancy model": cross-tenant views are federated queries returning `org_id`. 24 weak points: implementers "will happily add ... cross-tenant joins unless the framework makes them impossible".

Amendment. D-35: "More than one Organisation requires the PostgreSQL adapter (single-node is supported); the SQLite adapter refuses a second Organisation. Provider views use a set-valued tenant context computed by the framework from live delegations for relational data, and per-Organisation fan-out for the lake. No code path reads without a tenant context. A Provider's Organisations in one region share a cell." Add a many-small-tenants profile to the D-34 spike (S1).

### 6. Major, missing: enrolment and onboarding ignore RMM rollout (D-36, section 6)

Problem. "Short-lived use-capped tokens" means re-minting keys per client every week while machines trickle online through an RMM script. Section 6 has no onboarding target.

Evidence. 25 implication 6: 7-day default keys. 24 verifier correction B: Wazuh 5.0 kept its shared enrolment password default-on beside tokens. 25 TL;DR: macOS system extensions need MDM, which my clients often lack.

Amendment. D-36: "Two enrolment credentials: single-device tokens, and a per-Organisation deployment key for RMM and MDM (revocable, rotatable, device-capped, expiry by policy, default 90 days, never on argv). A device enrolled by deployment key starts in Watch with no response authority until an auto-approve rule or a technician admits it." Section 6: "New Organisation from a Provider baseline: 10 minutes of technician time. A 25-seat client reporting, with assurance level stated per device, within 60 minutes of an RMM push, with no MDM and no per-device step."

### 7. Major, missing: PSA and RMM integration is unnamed and rests on unverified research (D-40)

Problem. D-40 names enterprise importers only. Integration instances appear Organisation-scoped, but I have one PSA and one RMM for 80 clients.

Evidence. 26 section 2 and "Could not verify": every MSP API (ConnectWise, Kaseya/Datto, NinjaOne, N-able, HaloPSA, Pax8) is prior knowledge, "not verified this run". g10 "Could not verify": no primary source for MSP billing practice.

Amendment. D-40: "Provider-scoped integration instances: one connection owned by a Provider, fed by Organisations that delegate forwarding, metadata-only unless the Organisation grants content, with an Organisation-to-external-company mapping. The provider pack ships with the provider tier: two-way PSA ticket sync, usage posting to PSA agreements, RMM deploy-script generation and company import." Commission a verified brief on these APIs before the integrations design document.

### 8. Major, missing: no provider workbench in the experience rules (D-44, D-31, D-46)

Problem. Queue, approvals and reports are specified per Organisation. With no client-side admin, every admin approval and unknown-agent triage lands on twelve technicians, 80 times over. Clients do not read OSCAL.

Evidence. 33 "MSP patterns": one queue with tenant groups, per-customer approval instructions. h08 section 4: false positives eating technician time; only 42% of MSPs show clients automated reports.

Amendment. D-44: "Provider workbench: one cross-Organisation queue (approvals, sessions worth a look, unhealthy sensors, unknown agents) filtered by Organisation set; admin approvals route to it with per-Organisation instructions, a service-level timer and deny on timeout; a disposition (approve or block an agent, an exception template) can be saved to the Provider library and applied to an Organisation set; a scheduled, branded per-Organisation report (inventory, coverage by assurance level, blocks, exceptions) needs no technician input. Approval requests per technician per day is a budgeted metric."

### 9. Minor, over-built: L6 makes MSP branding wait for OEM machinery (D-41, D-18, section 7)

Problem. I need my name on the tray, block message, domain, emails and report. L6 bundles that with re-signed content and LTS builds in M4, a milestone after the provider tier. D-18 also undercuts a white-label desktop: the macOS entitlement is bound to one Team ID.

Evidence. 27 part 5: theme tokens, custom domains, per-tenant branding, "no hard-coded product name in agent-facing block messages".

Amendment. Split L6. "L6a Co-brand: a Provider branding profile (name, logo, tokens, domain, sender, support contact, block-message text, report template) inherited by Organisations; configuration only; binaries stay Loonaro-signed. Ships with the provider tier in M3. L6b White-label: the partner builds and signs under its own Apple Team ID, Windows certificate and content root; M4." Nothing is lost.

### 10. Minor, missing: no provider commercial terms (D-04, section 8)

Problem. D-04 has an OEM programme and no Provider programme. I cannot quote a client without a wholesale unit.

Evidence. h04 section 4: public anchors of USD 15 to 20 per user or agent per month. g10 verification row 9: modelled cost USD 0.28 to 1.00 per endpoint-month, unmeasured.

Amendment. D-04: "Provider programme: published hosted wholesale price per active endpoint (monthly average), no minimum, a free not-for-resale Organisation for the Provider's own staff, tokens passed through or on the Provider's key, a partner support channel." Add open question 5: the unit and price, set after the telemetry pilot g10 calls for.

Note on D-23 (my own fleet, not the briefs): add Huntress, Bitdefender GravityZone and ThreatLocker to the lab; default-deny allowlisting blocks the hook shim without publisher-certificate rules.

## Spikes

| # | Question | Method | Pass |
|---|---|---|---|
| S1 | Do the lake and queue hold with many small tenants? | 1,000 synthetic Organisations of 20 endpoints for 30 days on scaled adapters; 80 on single-node Postgres | Cross-Organisation queue page p95 under 1 s at 100 and 3 s at 1,000; session timeline under 2 s; a query with no tenant context fails closed |
| S2 | Can a client be onboarded in an hour? | RMM-style scripted install on 25 mixed virtual machines (Windows, macOS without MDM, Linux) with one deployment key | 10 minutes hands-on; 90% reporting with a stated assurance level in 60 minutes; failed enrolments visible |
| S3 | Can a baseline change be proven and staged across 80 clients? | 80 Organisations, 300 Cedar policies; change one locked setting; run compile, ceiling proof and 7-day replay; inject a block-rate anomaly in a canary | Recompute under 10 minutes; rollout halts at the canary |
| S4 | Do declarative manifests cover a PSA? | ConnectWise PSA and HaloPSA ticket sync and usage posting as manifests against vendor sandboxes | Two-way status, company mapping and idempotent retry with no code component |

## Agreed

- D-35: Organisation as the hard boundary, organisation id from the device credential.
- P11, D-04: tenancy, SSO, roles, audit and the provider tier in the open build.
- D-11: default and locked layers with a ceiling proof and replay before enforcement.
- P4, D-15: local decisions; a hosted outage degrades freshness, not protection.
- D-38: content access as a separate, purpose-bound, tenant-visible permission.
- D-44: new packs start in Watch, so onboarding never breaks a client on day one.
- P9: I can tell a client honestly that unmanaged Macs are AL2.
