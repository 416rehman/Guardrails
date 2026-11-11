# Review L03: SOC lead and detection engineer

Spine draft 1. Briefs: 36, g06, 26, 23, 39, 01, 21, and 24 for hunting.

## Summary

The enforcement side of the spine is strong. The operations side is thin: it names Finding, Incident and Case, then says almost nothing about how findings are tuned, suppressed, hunted or exported. Three things would hurt me most. D-09 lets any detection rule write a label that a Block policy reads, with no maturity gate and no ordering guarantee, so a noisy rule update can stop every coding agent in a company. The cross-check that P3 and D-13 treat as a detection is, on the only published data, 96% harness housekeeping. D-36 uploads about 5,000 events a day with no statement of what an investigator is guaranteed to have. The most important change is the first: put a maturity and consistency contract between detection content and enforcement.

## Findings

### 1. Blocker, missing. D-09, D-37, P7: detection content can cause blocks with no gate

D-09 makes labels the bridge from rules to Cedar, and D-37 gives detection content its own channel. Nothing stops an experimental rule or a fast content push from writing a label that a Block policy reads. Nothing says whether a label written from event N is visible to the verdict on event N+1, or how a label from the server `detect` target reaches the device.

Evidence: g06 "Weak points" (a bad block rule stops every coding agent in a company); g06 "Implications", content schema ("block requires status: stable") and pipeline step 6 (rapid content "can never raise `action_ceiling`").

Amendment, new D-09a: "Labels are advisory or enforcing. Enforcing labels, the only ones visible to policies in Ask or Block, may be written only by typed analysers and by rules with `status: stable` and an `action_ceiling` at or above the reading posture. Advisory labels raise risk and create findings and evaluate as absent in Cedar. Enforcing labels are written synchronously before the next verdict in that session; server-written labels are advisory until delivered and acknowledged. The rapid channel carries indicators and reputation verdicts only. Every rule carries status, action_ceiling, requires, tunables, tests, false_positives and known_gaps."

### 2. Major, wrong. P3, D-13: the hook-versus-OS gap is not a detection as stated

P3 cites "Harness OTel missed 27 executions". The verifier's correction in 01 (verification row 4) says 26 of those 27 were harness housekeeping (`git`, `tasklist`, `reg query`) and one was the injected process. An unfiltered "lineage activity with no matching tool call" rule fires on nearly every session.

Amendment to D-13: "Each catalogue entry ships a housekeeping profile per agent version, generated from the CI installs of D-24, listing what the harness does without a tool call. Lineage activity outside that profile is the detection. A configured hook that stays silent across observed tool executions is the tamper signal. A version with no profile reports 'cross-check not calibrated' under P9 and raises no findings." Reword P3: "A gap between them is a signal, and a detection once harness housekeeping is subtracted."

### 3. Major, missing. Vocabulary, D-44: no finding lifecycle, suppression or tuning model

The spine has Grants and three review buckets. It has no finding verdicts, no suppression object, no way to tune a shipped rule without forking it, nothing on tenant-authored detections, and no statement that a blocked attempt is still a finding.

Evidence: 36 "Incident and case model" (suppressions with owner, scope, mandatory expiry; OCSF 2005 verdicts) and "Weak points" (Defender stops alerting once it blocks); g06 section 3 (Splunk per-detection filter macro); 39 "Assistant, detections, feedback".

Amendment, new D-48: "Findings use OCSF 2005 states and verdicts. A Suppression is a scoped, owned object with justification and mandatory expiry; it hides a finding and never changes a policy. Every rule exposes declared tunables; tenant overrides survive pack updates and show as a diff. Blocked attempts always create findings. Tenants author rules in the pack format, in git or the console, with a positive and a negative test and a replay over their own history before leaving Watch. Analyst verdicts train the ranker and propose suppressions; they never change rule logic or judge prompts silently."

### 4. Major, risky. D-36, P8: no guaranteed investigative record

The 5,000 events a day target is an unmeasured assumption (g10 "Weak points"); 24's TL;DR infers about 100,000 for a heavy workstation. The rest lives in a recorder of unstated length. D-29 review is post hoc, so a finding may arrive after the recorder has rolled over. P8 does not say whether a command line is metadata or content.

Amendment to D-36: "Always uploaded: every Action with canonical command, paths, destination and digests (secrets redacted); every Verdict and Receipt; process start and exit in agent lineage; network connects; writes outside the workspace and to protected paths; config changes; credential use; session boundaries with attribution basis. The flight recorder keeps full fidelity for at least 72 hours, uploads its look-back when a device-side finding fires, and answers a signed capture-evidence command for late findings; data that expired first is reported as a gap." Amendment to P8: "Metadata includes action arguments in canonical, redacted form. Content means prompts, model output, tool output and file text. A finding carries its matched evidence span, redacted, except in works-council mode. The human principal is recorded and role-gated, not omitted."

### 5. Major, missing. D-34: hunting is not designed

The lake is sorted by session with bloom filters on session and device only, so daily pivots (which other devices ran this MCP server digest or contacted this host) become full scans. No hunting language is chosen. Rules run on the bus only, so a new rule or a new D-32 indicator never looks backwards.

Evidence: 24 "Implications" (SQL, a pipe-style front end, Sigma import) and its open question on DataFusion without a secondary index; 36 "Hunting and baselines".

Amendment to D-34: "Hunting is SQL, a pipe-style front end, and Sigma rules run as hunts; saved hunts can be scheduled and promoted to rules. An observable index, built at ingest, maps (organisation, type, value) to first seen, last seen, devices and sessions for executable hash, command hash, destination host, MCP server digest, tool-manifest hash, skill digest, package, credential id and principal. Every new or changed rule and every new indicator is replayed over the retention window by the same core; results are findings marked retro." Add a target: fleet-wide observable pivot under 2 s.

### 6. Major, risky. D-06, D-40, section 7: SIEM and SOAR landing is late and underspecified

A SOC lives in its SIEM. The spine ships "importers first" and puts integrations in M3. Security Lake accepts OCSF 1.3 classes only, and most parsers do not know `ai_agent` (26 TL;DR and "Weak points": per-SIEM parsers, dashboards and detections are "the real cost").

Amendment to D-40: "Export contract: findings and incidents as OCSF 2004 and 2005 with stable ids and an update event on every state change; decisions and response actions; optional full event stream. Delivery is at-least-once with a cursor per destination and replay by time range. Down-converters (OCSF 1.3, ECS, ASIM, CIM, UDM, CEF) are versioned data with golden tests. Each first-tier destination (webhook, syslog, object storage, Splunk, Sentinel, Falcon NG-SIEM, Elastic) ships as a package: parser, mapping, dashboard, converted rules. Case state syncs both ways with ticketing." Move generic sinks, Splunk and Sentinel to M2.

### 7. Major, risky. D-30: response actions are listed as if every host can run them

36's verification row 10: Windows has no documented job-wide suspend, WFP keys on application path and user, not a process tree, and Endpoint Security cannot kill or pause. The guard rails in 36 "Response architecture" item 7 (blast radius, rate limits, simulate) are absent.

Amendment: "Each actuator declares, per OS and assurance level, which actions it executes and the fallback; the console shows the effective action before confirmation. Session freeze and session-scoped isolation are promised at AL3 and above only. Rules may automatically deny or hold a call, end a session, and disable an MCP server, tool or skill by digest with a time limit. Device isolation, credential revocation, file restore and persistence removal need a human unless the tenant opts in per rule. Automated rules declare a blast-radius cap, a tenant limiter caps the share of the fleet acted on per hour, and every action has simulate mode, expiry and an undo reference."

### 8. Major, missing. Section 6, D-45: no alert-quality targets

Section 6 budgets prompts for developers and nothing for analysts. Uber's detector had zero benchmark false positives and 49% in production (39 section 1). Capable models exceed scope in 43 to 61% of runs with no adversary (39 verification row 8), so overeager-agent findings will dominate.

Amendment: add a finding class (threat, policy violation, overeager, tamper, coverage gap); only threat and tamper page. Add targets: worth-a-look under 2% of sessions; stable rules at 90% precision on analyst verdicts, with automatic demotion to Watch below 50% over 20 verdicts; zero stable-rule hits on a benign session corpus as a release gate (g06 pipeline step 4); review coverage per tier displayed; seeded canary sessions measuring live recall (39 "Architecture" item 6).

### 9. Minor, risky. D-09, D-41 rung L0: "Sigma-compatible" leaves portability undecided

Sigma has no agent, LLM or MCP log source and no ATLAS tag namespace (23 section 1; g06 TL;DR). Rules that read labels, facts or correlations will not convert to KQL or SPL over a partner's telemetry. `rsigma` is v0.26.0 with one author holding about 2,100 of roughly 2,400 commits (`gh`, today).

Amendment: "Rules use canonical field names under a published logsource taxonomy with conversion pipelines per export schema. Each rule declares what it requires; L0 packs hold only the portable subset, computed and fixture-tested per backend in CI. ATLAS mappings carry their release. `rsigma` sits behind our own trait with a conformance corpus."

### 10. Minor, missing. Vocabulary: an Incident is more than one session

39 "Weak points" says session-scoped review misses multi-agent and compaction attacks; 21's TL;DR records 1,200 coordinated runs and worm lineages.

Amendment: "An Incident groups findings by session lineage, then merges across device, principal, credential and artefact digest within a window. One malicious artefact across the fleet is one incident with many sessions."

## Day one: "an agent did something bad on a developer laptop"

| Question | What must exist |
|---|---|
| Which agent, session, human | Session graph with attribution basis; role-gated principal (finding 4) |
| What it did, in order | One timeline of tool calls, verdicts, processes, files, network, including blocked attempts (3, 4) |
| What it touched | Credentials, files, destinations, with digests |
| Why | Redacted evidence span, behind the content permission |
| Who else | Observable pivots and retro-detection (5) |
| Contain | Preview of the effective action on this host (7) |
| Hand off | Signed evidence bundle; incident in SIEM and ticket (6) |

## Spikes

| Question | Method | Pass |
|---|---|---|
| Is 5,000 events a day enough? | Full capture on 10 developers for 5 days on three OSes; apply the filter; an analyst reconstructs 5 scripted incidents from uploaded data only | Volume within target at p95; 5 of 5 reconstructed |
| Gap-detection base rate | 50 benign tasks each on Claude Code, Codex, Cursor, Copilot CLI; count unmatched executions before and after housekeeping profiles | Under 1 unexplained execution per 100 sessions; injected process caught 20 of 20 |
| Hunt speed | 1.5 billion synthetic rows on object storage; 10 pivots with and without the observable index | Timeline and pivot under 2 s; 30-day aggregation under 10 s |
| Sigma fit | Write the detection rows of 21 section 18 as Sigma; convert to KQL and SPL against fixtures; build `rsigma` with an injected clock for wasm32 | 60% expressible; identical results native and wasm; 80% of stateless rules convert |

## Agreed

- P2 and D-29: a deterministic hit is never cleared by a model; verifier spans checked in code.
- D-09's split itself: detections say "suspicious", policies say "may proceed".
- D-06: own IDL inside, OCSF and OTel at the edges.
- D-11: replay with "almost matched" before Ask or Block.
- D-15: failure mode per rule class.
- D-30: isolation before revocation; two approvers for fleet scopes.
- D-31: approvals bound to an action digest.
- D-41 rung L1: a local event feed for existing SIEM agents.
