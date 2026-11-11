# Review L07: privacy, works council and the monitored developer

Lens: data protection officer working with a German works council, and a monitored senior developer. Scope: the whole spine (draft 1). Briefs: 34, 33, 01, 05, plus 17, 23, 24, 39, g06, g07, g09.

## Summary

P8 has the right intent, but it rests on two undefined terms ("metadata" and "not employees") and other decisions contradict it: job 2 attributes every action to "the human behind it", D-29 runs LLM review "by default", D-11 replays against "recorded history", D-26 signs git trailers, and D-46 makes the privacy shape an optional mode. The research states what is needed (34 Implications 1 and 5; g07 line 159); the spine dropped it. A works council would refuse this default, and a DPO cannot finish a DPIA when nothing says which fields leave the device. The change that matters most: put pseudonymous principals and field-level data classes into the event schema (D-06), so the schema enforces P8.

## Findings

### 1. Blocker, missing: no pseudonymisation or re-identification decision (P8, D-06, D-38, D-46)

Problem: job 2 and D-25 bind actions to a named human; P8 says findings attach to agents and sessions, "not employees". On a one-user laptop a session, an agent instance and a device are each a person. Only a pseudonymous principal with controlled re-identification reconciles the two. The spine has neither.

Evidence: 34 Implications 1 and 5(c)(d); 34 matrix row for BetrVG s.87; g07 line 159 ("Pseudonymise users by default") and its Privacy Reviewer role; 34 verification row 8.

Amendment: add D-48. "Human principals are pseudonymous everywhere outside the identity vault. The sensor emits a per-organisation keyed pseudonym; the name mapping lives in the `identity` target, sealed with the D-35 endpoint-sealed mechanism. Re-identification needs a purpose code, a case reference and two approvers, one of whom may hold a works-council delegate role, and is shown to the subject. This is the default in every shape." Amend D-06: the envelope carries `principal_pseudonym`, never a username, email or name-derived hostname.

### 2. Blocker, wrong: "metadata-only" is undefined and contradicted by replay, server detection and three bypass paths (P8, D-11, D-34, D-36, D-30, D-41)

Problem: commands, paths and URLs are the substance of `exec`, `file.*` and `net.request`; they carry commit messages, search terms and personal paths. D-11 replay and the server `detect` target need them centrally, so either the default is not metadata-only or replay fails. The D-36 "full-fidelity flight recorder", D-30 "capture evidence" and the D-41 L1 local feed sit outside the capture level and the content permission.

Evidence: 34 Implications 5(a)(b)(h) and "Content capture is the legal fault line"; 39 line 63 ("raw events never have to leave"); 01 section 6 (10 of 12 private business rules recovered from traces).

Amendment: add to D-06: "Every protobuf field carries a `data_class` option: `identifier`, `structural`, `derived`, `content`. Capture level is a sensor-side filter over it, enforced by a lint and a canary test. Default upload is `structural` plus `derived` facts (action class, host class, secret type, command verb, path class), not raw arguments." Amend D-11: "Replay of rules that read `content` fields runs on the device against local history and returns counts." Amend D-36, D-30, D-41: recorder, evidence capture, L1 feed and SIEM export obey the same filter; pulling recorder content needs a D-38 content grant.

### 3. Major, missing: per-person evaluation is left open (D-09, D-29, D-31, section 6)

Problem: Sigma correlation rules can group by principal, giving a per-employee behaviour count from an open contribution lane. Section 6 budgets prompts "per developer per day"; briefs 33 and 34 propose flagging individual approvers by decision speed. Nothing forbids productivity views or a judge that reads mood from user messages.

Evidence: 34 TL;DR on Annex III 4(b) (prior knowledge; wording confirmed) and Implication 5(e) "enforced in code"; 34 section A (Art. 5(1)(f)); 33 line 144.

Amendment: add D-49. "No score, baseline, correlation or report is keyed or groupable by human principal. The pack validator rejects correlation `group-by` on principal fields; the query layer refuses aggregation by principal outside an open case; baselines key on agent type, project and peer group. Approval-health metrics are per rule and per group of at least five. No productivity, per-person adoption or emotion inference exists in code; the conformance suite tests this." Change section 6 to "budget per rule and per group".

### 4. Major, wrong: LLM review "by default" contradicts metadata-only by default (D-29, D-38)

Problem: finder, verifier and investigator read raw sessions, which the default does not collect. In the hosted service the model is a third party under the operator's key: a sub-processor the tenant never chose. The D-38 MCP server exposes the same data to further models.

Evidence: 39 line 134 ("a data-processing decision the tenant must own"), line 156 (laptop mode is T0 and T1 only), line 157 ("metadata-only review"); 01 lines 60 and 173.

Amendment: replace the D-29 sentence with: "Tiers 3 to 5 are off until the organisation selects a judge back end and a capture level of redacted content or higher; at metadata-only they run on structural features or not at all. The hosted service has no default third-party model. Trace content is tokenised on the device before review. No tenant content trains a shared model." Add to D-38: MCP server responses apply the caller's column sensitivity and return pseudonyms.

### 5. Major, missing: retention, erasure and subject access have no storage design (D-34, D-39, D-46)

Problem: D-34 stores day-partitioned Parquet sorted by session; D-39 hash-chains events and puts delegation chains (a human) into a witnessed Merkle log. D-46's presets are floors (six months to six years); nothing sets a ceiling or lets content expire before metadata. Erasure and access requests are absent. The AI Act log duty yields to data protection law.

Evidence: 34 matrix rows for GDPR Arts. 15 to 17; 34 Implication 5(g); 34 verification row 2; 24 line 125 (`store` does crypto-shredding, dropped from the spine); 23 line 71.

Amendment: add to D-34: "Data classes are stored in separate column groups under per-organisation, per-class, per-day keys; retention and erasure are key destruction plus partition drop. Defaults: content 30 days, structural events 180 days, receipts 13 months; presets extend these only with a recorded legal basis." Add to D-39: "Chains and the Merkle log commit to salted digests; receipts carry pseudonyms." Add to D-46: subject-keyed index, access and erasure workflow, Art. 30 export.

### 6. Major, missing: purpose limitation when an MSP or Loonaro operates the service (D-11, D-35, D-32, D-04)

Problem: D-11 lets the Provider layer lock settings, so an MSP can raise a customer's capture level; "widening needs approval" does not say whose. Customer co-signing is optional. Nothing limits operator use of tenant data. D-32 and D-04 tie feed access to reciprocal sharing, and digest lookups reveal a tenant's private MCP servers and skills.

Evidence: g07 line 159 ("deny MSP and SaaS-operator access unless the customer approves"); 33 MSP patterns; g06 lines 96 and 189 (opt-in counters, digest-prefix lookups).

Amendment: add to D-11: "Capture level, retention, content roles and exclusions are privacy settings. Provider and operator layers may only narrow them. Widening needs the organisation's co-signature, on by default in hosted and provider deployments." Add D-50: "The operator processes tenant data only to run the service: no model training, no cross-tenant analytics, no telemetry beyond documented metering counters. Intelligence sharing is opt-in, sends digests of publicly distributed artefacts only, uses digest-prefix lookups, and never gates the feed."

### 7. Major, risky: content rings change what is monitored without the works council seeing it (P7, D-37, D-46)

Problem: co-determination covers the application of the tool, and works agreements enumerate permitted evaluations. A detection pack promoted through rings adds an evaluation of employee behaviour with nobody at the customer involved. The impact-assessment pack the brief names is also missing.

Evidence: 34 TL;DR Germany; matrix row for BetrVG ("published monitoring catalogue"); Implications 4 and 5(k); verification row 2 (Art. 26(7) notice).

Amendment: add to P7 and D-37: "Each pack declares the fields and data classes it reads and the labels it writes. A version that reads a new field or a higher class is privacy-relevant: it does not auto-promote and appears as a diff in the monitoring catalogue." Add to D-46: monitoring catalogue, DPIA and FRIA pack and worker notice generated from live configuration, with a works-agreement annex.

### 8. Major, risky: pushing identity outward writes permanent markers into other systems (D-26)

Problem: a sensor-signed git trailer sits in the commit message: immutable, pushed to public forges, and a permanent, unerasable record of which of a developer's commits were agent-assisted. The brief chose notes; the spine did not.

Evidence: 17 line 171 ("Write a sensor-signed git note per commit rather than trusting trailers") and line 108.

Amendment: change D-26: "Outward tags carry the session pseudonym only. Git attribution is a signed note under `refs/notes`, never a trailer, is off by default, is not pushed to remotes outside the organisation's allow-list, and is disclosed in the developer panel."

### 9. Major, missing: collection beyond agent activity is not excluded (D-24, D-25, `ui.act`, M2 enrolment)

Problem: the research proposes a low-level keyboard hook and "absence of human keystroke timing" as features. A works council treats a global keyboard hook as a keylogger (German case law is prior knowledge; confirm with counsel). Browser discovery sees personal accounts. Enrolment could upload a standalone install's personal history.

Evidence: g09 lines 123 and 171 (`WH_KEYBOARD_LL`); 39 line 171; 05 Implication 4 and line 102 (Push asks for consent on personal-domain logins).

Amendment: add D-51. "The sensor installs no global keyboard or mouse hook and records no human input timing, screen content or clipboard. Synthetic-input evidence comes from process-side signals only. Non-corporate account identifiers are hashed on the device. History recorded before enrolment stays local unless the user exports it. Enrolment shows the disclosure screen first."

### 10. Major, missing: the transparency floor is not decided (D-44, D-41, D-43)

Problem: D-44 gives the developer a panel but no floor. White-label and embedded rungs can drop it, "tenant-visible" audit is not visible to the person whose prompt was read, and no scope can be excluded.

Evidence: 33 lines 97 and 153; 34 Implication 5(j) and 5(l) ("covert mode absent, not merely disabled"); 33 line 61.

Amendment: add to D-44: "There is no covert mode in the code. The disclosure surface cannot be hidden. Every content access and re-identification is shown to the subject, delayed only under a recorded legal hold. Organisations can exclude principals, paths and repositories (works council, HR, legal, medical)." Add to D-41: the conformance marks require the privacy floor (D-48 to D-51) at rungs L2 to L6.

## Spikes

| Question | Method | Pass criteria |
|---|---|---|
| Does the default keep content on the device? | Annotate `grd-proto` with `data_class`; run recorded Claude Code, Codex and Cursor sessions seeded with canary strings (prompt, commit message, secret, personal path) at the default level | Zero canaries in upload batches, findings, L1 feed, OCSF export and LLM review input |
| Can replay work without central content? | On-device replay of 20 draft rules on 20 devices against local history, returning counts | Counts equal a central full-content replay; under 60 s per device; no `content` field leaves |
| Can we expire and erase by class without breaking audit? | On a synthetic 10,000-endpoint lake, expire content at 30 days and erase one principal | Offline verifier passes; no plaintext recoverable from lake, search segments, spool or backups; done within 24 hours |
| Would a works council sign the default? | Give the monitoring catalogue, DPIA pack and default configuration to a German employment-law expert (the s.80(3) role) | Written opinion: no red-line item; a position on Annex III 4(b) for the risk ranker |

## Agreed

- D-16: no mandatory TLS interception; browsers never intercepted.
- P4, D-36: local decisions and device-side filtering to agent-scoped activity.
- P2: deterministic decisions keep the product away from solely automated decisions about staff.
- D-38: content access as a separate permission with purpose and time box.
- D-35: customer-approved, time-bound MSP delegation; endpoint-sealed fields.
- P11: open source lets the works council's expert verify collection.
