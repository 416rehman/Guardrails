# Review C8: detection, response, AI and data control

Scope: P2, D-28 to D-32, D-45. Reviewed 2026-11-10.

## Summary

The direction holds; four things do not. P2 contradicts the spine's own label pipeline. D-31 leaves the first standalone release with no valid way to approve anything. The trifecta gate in D-28 is true of nearly every coding session. D-30 has a fleet-wide stop without the brakes brief 36 specified. Nothing says what ships on day one. F1 matters most: every other document inherits P2.

## Findings

### F1. P2 is contradicted by D-09, D-28 and D-29 (wrong, blocker)

P2 says no blocking decision depends on a model. D-29 permits bring-your-own inline model gating, and D-09 plus D-28 let the T1 injection classifier write a label that Cedar reads to gate a sink. An attacker or a security README can then flood model-derived labels and stall work: phrase-style injection detections are "noisy on security documentation" (g06, weak points), and small classifiers reach 72 to 82% recall at about 1% false positives (09).

Amendment, replacing P2: "Models may only restrict. No ALLOW, grant, declassification, suppression or clearing of a finding depends on a model. Every label carries provenance `rule` or `model`. A policy whose outcome depends on a `model` label is flagged model-dependent, is capped at STEP_UP unless the operator raises it, and falls back to its rule-only outcome when the model is missing. Never model-dependent: egress default-deny, protected paths, agent-config writes, credential brokering, kill switch, tenant isolation, failure mode" (list from 39).

### F2. D-31 leaves standalone, Linux and headless hosts with no approval channel (wrong, blocker)

D-20 runs the first standalone release as one user-level daemon: no privileged helper, no server for push, and no platform authenticator on Linux, SSH or CI. D-31 calls everything else "never an approval", yet D-44 ships Ask in M1. Brief 36 (approval system, item 2) proposed channels "in rising assurance" mapped to risk. Also unsettled: 33 recommends self-approval at Ask, 36 says the requester never approves. And a call cannot be held for a human: hook timeouts fall open and Codex has no ask (36 verification rows 1, 2, 10).

Amendment: "Approval tiers: A0 agent-native ask (a request); A1 same-user helper rendered from the canonical action; A2 user-presence authenticator bound to the action digest; A3 out-of-band push with a binding code. Policy sets the minimum tier per risk class; receipts record the tier. At Ask the session's user may approve; exceptions to Block need another principal. The mechanic is deny, grant, retry. Three unanswered or denied requests in a row freeze the session."

### F3. The trifecta gate fires on almost every coding session (risky, major)

A coding agent reads web pages and issues, touches source and `.env`, and pushes. Brief 35 (weak points): "Session-level taint creeps... approval prompts become noise", with false-positive rates unknown. Users accept 93% of prompts (36). Labels also launder through a new session, a child agent or a written file.

Amendment to D-28: "Day-one labels: `secret-read`, `sensitive:<class>`, `untrusted:web`, `untrusted:external-tool`, `injection-suspected` (model provenance). Day-one sinks: `net.request` outside the session egress profile, `git.push` outside the organisation, `pkg.publish`, `message.send`, `mcp.call` to an unpinned write-capable tool, `llm.request` to a non-tenant provider. Defaults: `secret-read` to a sink is Block; `injection-suspected` is Ask; `untrusted:*` alone is Watch. Child sessions and files written by a labelled session inherit labels. Declassification is a digest-bound grant. Sink gating leaves Watch only after replay shows it within the prompt budget." Spike S1.

### F4. D-30 has a fleet-wide stop with no brakes (missing, major)

Brief 36 (implications 4 to 7) specified endpoint-verified dual signatures, expiry, break-glass, offline behaviour, per-rule blast radius and fleet rate limits. The spine kept "signed, counter-protected, two approvers". So a compromised server or MSP technician can stop every customer; a bad pack can trigger mass response (g06: "stops every coding agent in a company"); two approvers delay a real incident; and Windows has no documented job-wide suspend for "freeze" (36 verification row 10).

Amendment: "Commands carry scope, counter, expiry and signatures verified on the endpoint. One approver may issue a reversible freeze at any scope for 60 minutes; kill, revoke or extension at organisation scope or wider needs two signatures or the offline break-glass key, which opens an incident. Automated response is capped per rule (maximum scope, share of fleet per hour) and runs in simulate first. Offline devices apply pending commands before the next tool call on reconnect. The model provider's admin API is a fourth actuator. Device isolation is delegated to the host EDR when present. Order: freeze, isolate, capture, revoke."

### F5. There is no day-one detection or response list (missing, major)

Add D-29a and D-30a. Ranked from brief 21 section 18; brackets are its incident items.

Thirty detections:

1. Write to any agent's hooks, MCP, settings, skills, rules or memory files [5, 6, 8, 10, 104]
2. Agent lineage editing guardrail files [6, 10, 14]
3. Repository-carried agent config at clone [8, 15, 16, 31]
4. New hook or MCP entry launching an interpreter from temp or repo [104]
5. Credential-store read from agent lineage [31, 64, 104]
6. Destructive command classes [119 to 128]
7. Irreversible action on a production target [121, 123, 124, 127]
8. Mass delete or rename rate [120, 126, 128]
9. Non-agent process launching an agent CLI with permission-skipping flags [100]
10. Package lifecycle script spawning agents or reading credential stores [100 to 104]
11. Base-URL or proxy drift [8, 97, 105]
12. Execution in agent lineage with no matching hook event [P3; brief 01]
13. Shell parse ambiguity [9, 22]
14. Pivot after denial through another tool [24]
15. Nested headless agent, or child with weaker settings [24, 100]
16. Secret in tool input, output or prompt [31]
17. Egress to capture, paste, form or webhook hosts [85, 134]
18. Tunnel, mesh VPN or Tor from agent lineage [56, 134, 135]
19. Persistence created by agent or install lineage [56, 103, 104]
20. Known-bad or typosquat server, skill, extension or package [42, 53]
21. Vulnerable agent or gateway version against GHSA and KEV
22. MCP tool definition changed after approval [5, 34, 42]
23. Instructions, credential paths or invisible Unicode in tool descriptions and skills [1, 34, 54, 57]
24. `secret-read` session reaching an external sink [76 to 85]
25. Registry publish or account creation [133, 135, 138]
26. Push outside the organisation or to a new public repository [100, 104, 108]
27. Cloud metadata access or token minting [134]
28. Tampering with endpoint protection or our sensor [131, 134]
29. Link out of the workspace followed by a write [10, 14, 39]
30. Git running helper programs in a fresh clone [14, 19]

Ten response actions, in order: deny with reason and safe alternative; hold for a grant; freeze session; kill session tree with an expiring restart block; cut session egress; quarantine a config artefact to last known good; revoke brokered leases; capture the flight-recorder bundle; restore files; redact. Defer automated persistence removal, native device isolation and IdP actuators.

### F6. Redaction "through hooks and proxy" is true for one agent (wrong, major)

Only Claude Code rewrites any tool output; Cursor rewrites MCP output only; Copilot documents none; no hook rewrites the user prompt (36 hook matrix). The proxy needs a settable base URL, which D-16 does not give for Cursor or Copilot back ends. Claude Code's OTel still records the original (35 verification row 2).

Amendment to D-28: "Redaction is declared per agent and channel as rewrite, deny-read or none. Where rewrite is unavailable the secrets class falls back to deny-read. Redaction substitutes a stable per-session placeholder the broker can re-inject for approved hosts. Our own ingest of harness telemetry redacts on the device." Spike S3.

### F7. Five tiers is too many for the first releases (over-built, major)

The ranker has no labels until analysts exist; ADR had zero benchmark false positives and 49% in production (39, section 1). "A cheap first stage caps recall for everything behind it" (39, weak points). Review needs content that P8 does not capture by default.

Amendment to D-29: "M1 and M2 ship T0 only. M3 ships one review stage (finder plus verifier with mechanical span check), ordered by a deterministic priority score, with a 2% random sample and seeded recall canaries. The learned ranker and investigator wait for M4. Review input is metadata-only, redacted or full; hosted review uploads only reviewed sessions and names the model provider as a sub-processor." Lost: ensemble robustness and the investigator's recall gain for two milestones.

### F8. D-32 publishes verdicts with no legal, poisoning or cost model (missing, major)

No brief covers legal exposure. In Enigma Software v. Malwarebytes (9th Cir. 2023, 69 F.4th 665) "malicious" and "threat" labels were held actionable statements of fact. "Computed centrally in a sandbox" implies scanning 80,000-plus servers, against g06's "do not try to out-scan vendors". A false verdict on a popular digest is a fleet-wide block.

Amendment: "Records publish named findings with scanner, version and evidence; `malicious` needs two independent sources or human review; `withdrawn` and a dispute route exist. Sightings feed prevalence only, above a k-tenant threshold. A verdict on a high-prevalence artefact goes through rings, not the rapid channel. We scan what fleets observe and aggregate the rest. The broker pins tool definitions locally regardless. Delivery: mirrored OpenSSF and GHSA pack in M1, own scanning in M4."

### F9. D-45 would not produce credible or affordable numbers (risky, major)

CAISI moved AgentDojo from 57% to 80% by allowing 25 attempts (g08). Frontier models resist most injections, so product-absent baselines retire the scenarios that matter. The full matrix is about 100,000 live runs per release, and Inspect SWE is Linux-only (g08 verification row 10). A skipped hook is unobservable at AL1 and AL2.

Amendment: "Two scenario families: model-driven, counted only when active, and scripted, where a replay model endpoint makes the real agent emit fixed tool calls. Replay per commit; live nightly and per release, with a stratified subset on Windows and macOS. The scorecard reports attack success at 1, 10 and 100 attempts, the tune-versus-locked margin, and silent fail-open per assurance level, with zero the target at AL3 and above."

### F10. Honeytokens and checkpoints are in the wrong shape (over-built, minor)

Protected paths deny the reads a decoy credential relies on, and capable models over-collect in 43 to 61% of runs (39, verification row 8). Six of eleven destruction incidents hit remote databases or infrastructure (21, items 119 to 128), beyond any file checkpoint.

Amendment: put "irreversibility gate (action class by target class)" third in D-28's order; replace "file checkpoints before destructive actions" with "workspace baseline at session start, copy-on-first-write, and a mass-change breaker that freezes the session"; define the first honeytoken as a phantom token seen at a non-approved host; defer cloud-validated canaries to M4.

## Spikes

- **S1, prompt budget.** Replay the F3 rules over SWE-chat v2 (17,968 sessions) and dogfood history. Pass: median under 1 and p95 under 3 prompts per developer-day.
- **S2, approval forgery.** On Windows 11, macOS 26 and Ubuntu, a same-user process drives A1 and A2 prompts with synthetic input and accessibility APIs. Pass: zero synthetic approvals; a failing tier is relabelled A0.
- **S3, redaction matrix.** Seed a synthetic secret; try hook and proxy rewrite on Claude Code, Codex, Cursor and Copilot CLI. Pass: secret absent from provider-bound requests in every cell marked rewrite.
- **S4, freeze drill.** Fifty devices, five offline, one restored from snapshot; freeze and release during `terraform apply` and a rebase. Pass: p95 under 10 s online, applied before the first tool call on reconnect, no replay accepted, workspace intact.

## Agreed

- A deterministic hit is never cleared by a model; keyed frames; span checks; post hoc review under a budget.
- One signed response contract; isolate before revoke.
- Prompts rendered from the canonical action and bound to a digest.
- Digest-keyed reputation; no execution of unknown servers on endpoints.
- Protected paths and environment scrubbing first; phantom tokens.
- Product-absent baseline, independent oracle, AMTSO vocabulary.

Outside source: [Winston & Strawn on Enigma v. Malwarebytes](https://www.winston.com/en/blogs-and-podcasts/competition-corner/potential-lanham-act-reverberations-malicious-and-threat-are-statements-of-fact-not-opinion).
