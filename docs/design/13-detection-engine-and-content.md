# 13. Detection engine and content

_Status: draft for implementation. Revised 2026-11-11 for principles P15 to P17 and the owner's kit instructions (`_review/04-owner-kit-instructions.md`). Owning squad: `content` (SQ-08, SQ-09), which owns the `detect` module; `core` (SQ-01) owns `grdr-core::analyze` and `identity-data` (SQ-10) its content detectors (team/02; trust core where they feed verdicts, D-63). Specifies D-09, D-10, D-53, the detection side of D-54 and the content side of D-29 and D-37. Read with: 00 (spine); 04 (field registry, findings); 07 (cross-validation); 12 (session state, Essentials, replay); 14 (intelligence); 16 (secret and PII detectors, honeytokens); 17 (MCP broker); 18 (response, incident workflow); 19 (model tiers); 20 (lake, observable index); 22 (rings); 26 (L0 delivery); spine D-45 and D-64 for the efficacy harness and lab (the detailed document, 31, is pending)._

## Summary

Policy (12) decides whether an action may proceed; this document decides what is suspicious and ships that as signed content (P7), evaluated by a sans-IO core module (D-05) on the device, on the server, in replay and inside partners' products.

Key choices:

1. **Two rule kinds, two channels.** Session rules write enforcing labels synchronously and ship with policy. Detections write findings, risk and advisory labels asynchronously, ship on the detection channel and reach enforcement only through capped response bindings (18).
2. **Sigma plus one `x_grdr` block** over 04's field registry, behind an engine trait. We vendor `rsigma-parser` and `rsigma-eval` for matching and own correlation state; a test-only reference interpreter is the oracle.
3. **Five typed analysers**, each returning `resolved`, `unresolved` or `malformed` and tested against the real consumer of its input.
4. **Tier 0 only by default** (D-29); heuristic and model findings never trigger automated containment.
5. **46 detections**: `c8`'s thirty in order, then sixteen from incident evidence and other documents' requirements.
6. **Data-driven maturity**: per-field fixtures, zero benign-corpus hits for stable, per-rule precision and recall per release.
7. **L0 is its own pack** over generic Sigma categories, compiled to five query languages, each labelled executed or syntax-checked.

## Requirements

| # | Requirement | Source |
|---|---|---|
| R1 | Only deterministic session rules write enforcing labels, before the observing control point is acknowledged | D-09; c2 F2; l03 F1 |
| R2 | Detections are asynchronous Sigma rules with correlations, on device and server, behind a trait with conformance vectors | D-09; c2 F9 |
| R3 | Normalisers return three outcomes, each with a real oracle and a differential fuzz target | D-10 |
| R4 | Every fact, label and risk input records its origin; nothing permissive depends on a model | P2; c8 F1 |
| R5 | Essentials enforces from first protection; the first thirty detections come from `c8` | D-53 |
| R6 | Packs declare reads and introduce nothing to execute, contact or set (host patterns, environment variable names and path templates only as typed match fields); no grouping by person; content-reading rules on the device | P7, P8; D-51 |
| R7 | Per-field fixtures in the production interpreter; staged rollout; rapid lane for indicators only | D-37; g06 |
| R8 | Expiring scoped suppressions; durable tunables; blocked attempts always create findings | D-54 |
| R9 | A broken rule or lagging engine reports "could not look" | P9; g06 |
| R10 | Compile to KQL, LogScale, EQL, XQL, SPL, generic Sigma; a conversion pipeline for the OCSF export | D-41, D-09 |
| R11 | Per-rule precision and recall published; stable at 90% precision, demoted below 50% over 20 verdicts | D-45; spine section 6; l03 F8 |
| R12 | Encoded payloads are decoded before matching | h07 implication 7 |
| R13 | Agent-config integrity with writer lineage, at clone and on change | 21 implication 1; h07 implication 1 |

## Design

### 1. Rule kinds, outputs and channels

Analysers turn events into classes and facts. Session rules read them synchronously and write enforcing labels that Cedar reads (12). Detections read events and facts asynchronously and write findings, risk, advisory labels and capped response bindings (18); the server runs the cross-device, retro and hunt passes over metadata events.

| Content item | Output | Policy-readable | Channel (D-37) |
|---|---|---|---|
| Session rule | Enforcing label, counter | Yes | Schema and policy |
| Analyser vocabulary (path, host and command classes, wrapper table, MCP extractors) | Classes, deterministic facts | Yes | Schema and policy |
| Detector pack (YARA-X, secret and PII patterns) | Facts with declared origin | Deterministic facts only | Policy if an enforced rule reads any of its facts, else detection |
| Detection (Sigma rule or correlation) | Finding, risk, advisory label, response binding | No | Detection content |
| Tripwire definition | Finding | No | Detection content (planting is code, 16) |
| Indicator, reputation verdict | Classes in feed-managed `protect` lists, inventory facts | Deterministic classes only (14 section 1) | Detection content, standard or rapid lane (14 section 7) |

The compiler (12 section 7) rejects any enforced rule that reads a fact, class or label from a pack outside the policy channel, except the restrict-only feed-managed intel lists of 14, so detections cannot cause blocks by construction (l03 F1).

### 2. Rule format: the Sigma dialect

A detection is a Sigma rule (correlations per specification v2.1.0, brief 20) plus a required `x_grdr` block. Sigma `id` is the exchange identity; findings, receipts and suppressions bind to `x_grdr.rule_id`. Generic-Sigma export moves `x_grdr` to a sidecar, since tolerance of unknown keys by every validator is unverified.

Sigma `title` and `description` are the English sources of the language tokens `pack.<rule id>.title` and `pack.<rule id>.description`, translated in the pack's `messages/<locale>.mf2.toml` (D-69); L0 exports keep the English text.

```yaml
title: Credential store read from agent lineage
id: 0b9a3d4e-6f1c-4c6e-9a51-3f0d2a7c1e88
status: stable
logsource: {product: grdr, category: action, service: file.read}
detection:
  sel: {actor_kind: agent, file.path_class: [cred-store, private-key, agent-store]}
  tmp: {file.path_class: session-tmp}
  condition: sel and not tmp
x_grdr:
  rule_id: grdr.det.cred-store-read
  version: 3                          # CI requires a bump on any logic change
  finding_class: policy-violation
  ceiling: notify
  risk: {name: cred-store-read, points: 150}
  requires: {fields: [actor_kind, file.path_class], min_provenance: claimed, placement: device}
  stage: K4
  mappings: {atlas: [{id: AML.T0083, release: "2026.10"}], asi: [ASI03]}
  tunables: [{name: exclude_image_class, type: list, field: exec.image_class, max_items: 50}]
  tests: [{fixture: pos-ssh-key.jsonl, expect: 1}, {fixture: neg-env-example.jsonl, expect: 0}]
  known_gaps: [Reads by a helper reached through a broker hop]
```

Dialect rules:

- **Log source.** `product: grdr`, `category` the 04 event category, `service` the class (04 rule 2). Rules for other products live only in the L0 pack (section 16).
- **Matching.** Sigma conditions with the modifiers `contains`, `startswith`, `endswith`, `re` (Rust `regex`, linear time), `cidr`, `exists` and `expand` (placeholders from pack lists). A set-valued field matches when any member matches.
- **Ceiling.** `ceiling` is the strongest automated response the rule may bind, following D-30's split between automatic and opt-in verbs (18 section 1):
  - `record`: finding only.
  - `notify`: finding and notification; it pages only for a threat or tamper finding from a `stable` rule (D-54).
  - `contain`: D-30's automatic verbs, time-limited: hold the next call, freeze, end the session with an expiring restart block, disable an MCP server, tool or skill by digest.
  - `remediate`: `contain` plus cutting session egress and quarantining a config artefact. These run only once the organisation opts the rule in (section 14).

  Lease revocation, device isolation and file restore are never automated from content (deviation 4).
- **Placement.** `placement` is `device`, `server` or `any`. Reading a content-class field forces `device` (P8); an organisation-scope correlation forces `server`.
- **Provenance.** On input below `min_provenance` (04's six steps) the rule is `not_evaluable` and does not run (D-60).

### 3. Log-source taxonomy and field names

Field names are registry paths with the payload prefix collapsed, generated with the Cedar schema under a drift test (04 rule 2).

| Fields | Class |
|---|---|
| `actor_kind`, `attribution.grade`, `provenance`, `control_point` | derived, structural |
| `agent.type`, `agent.version`, `session.id`, `session.root` (default correlation key), `session.depth` | identifier, structural |
| `session.labels` (each label carries kind and origin), `facts` (keys with origin; `x.<owner>.*` for third parties) | derived |
| `tool.name`, `tool.phase` | identifier, structural |
| `exec.image_class`, `exec.classes`, `exec.resolution`, `exec.image_digest` | derived, identifier |
| `exec.argv`, `exec.image`, `file.path`, `net.url` | content (argument): device only by default |
| `file.path_class`, `file.prefix`, `file.in_workspace`; `net.host`, `net.host_class`, `net.port` | derived, structural, identifier |
| `mcp.server.id`, `mcp.tool.manifest_hash`, `mcp.tool.pinned`; `config.artefact_kind`, `config.change_classes` | identifier, derived |
| `decision.verdict`, `decision.mode`, `decision.rule`; `novelty.session`, `.device`, `.org` (`org` is server-only, from the observable index) | derived |

### 4. Correlations and ordered sequences

```yaml
title: Network tool denied, then a shell fetch to the same host
correlation:
  type: temporal_ordered
  rules: [grdr.det.net-request-denied, grdr.det.exec-net-request]
  group-by: [session.root, net.host]
  timespan: 10m
x_grdr: {rule_id: grdr.det.pivot-after-denial, finding_class: threat, ceiling: contain, stage: K3}
```

Types: `event_count`, `value_count`, `temporal` and `temporal_ordered` run on the device and the server; `value_sum`, `value_avg` and `value_percentile` run on the server only, so they require the server (specification v2.1.0, brief 20). Semantics the specification leaves open:

- **Group keys.** `group-by` contains `session.root` or `session.id` unless the rule declares `scope: device` or `scope: organisation`. Keys derived from a human principal are rejected (D-51).
- **Artefact-state rules.** A rule whose subject is an artefact state change (rows 20, 22, 23 and 44, and every rule over `inventory.*` change records) declares `scope: organisation` and `group-by: [artefact.key, artefact.digest_from, artefact.digest_to]`, so a benign change to a popular artefact is one finding per organisation and transition, with device and session counts.
- **Placement of organisation scope.** A correlation whose group key is not contained in one device runs in two stages. Stage 1, in each bus partition's `detect` consumer, evaluates the base rules and emits `detect.keyed {organisation, rule_id, version, group_key_digest, value_digest, event_time, event_ref}` only for the first occurrence of each (group key, value) in its open window. Stage 2 consumes the `detect-keyed` stream, partitioned by `hash(organisation, rule_id, group_key_digest)` and placed in the organisation's home shard (20 section 11), and owns window, threshold and finding. Cross-device joins (06 section 7) use the same stream keyed by the join key. Stage-2 lag above 2 minutes is `detect-lag` for that organisation. In `embedded`, and for an organisation on one partition, both stages run in one consumer.
- **Time.** Event time only. The device orders by `(epoch, monotonic_ns)`. The server orders by `observed_time` corrected for recorded skew. There is no wall-clock fallback (c2 F2).
- **State** is ours (`grdr-core::detect::corr`) and lives inside `DetectionEngine::snapshot`. Bounds per session lineage (targets): 4,096 open entries in total and 256 group keys per rule. On overflow we evict that rule's oldest key and raise one `detect.state-overflow` coverage-gap finding per session and rule, so flooding is visible; `value_count` keeps at most `threshold + 1` distinct values per group key and window and then saturates, so the comparison stays exact and the finding records `count: >threshold`; each server `detect` partition has a state budget (256 MB, target), over which it evicts the lowest-priority rule's state first (section 7's shedding order); `rsigma`'s bulk eviction of the stalest 10% (c2 F2) is not used.
- **Lateness.** D-33 requires a stated window; the server's is 20 section 7's (15 minutes). A later event re-runs the affected windows on 20's late path, and the resulting findings carry `retro: true` (04 section 8).
- **Idempotence.** This document fixes 04's `dedup_key` for detections as SHA-256 over organisation, rule id, group key and window start. Device, server, replay and retro runs that produce the same key update one finding.
- **Absence** ("A not followed by B") stays in built-in code (07 section 9). The trigger for a content extension is three catalogue proposals that need it.

### 5. What detections write

- **Findings** use the 04 schema. Each Ask or Block receipt creates a policy-violation finding through built-in `grdr.det.decision` (D-54).
- **Risk.** Each rule declares at most one named contribution (1 to 250 points, maximum kept per session). Session risk is the sum capped at 1,000; lineage risk is the maximum over sessions. Risk orders review (D-29 priority score) and incidents and is never `policy_readable` (P2; c2 F4).
- **Advisory labels** (`injection-suspected`, `agent-suspected`) carry their origin. They evaluate as absent in Cedar, and session rules cannot read them.
- **Origin cap.** A finding whose determining input is `heuristic` or `model` binds at most `notify`, so flooding advisory labels cannot stall work (c8 F1).
- **Paging under storms.** Paging is limited to one page per organisation, rule and hour; later findings join that page's digest.

### 6. Session rules (contract in 12 section 9)

Session rules are match tables in `session-rules.yaml` inside policy packs, over deterministic facts and classes only:

```yaml
- id: grdr.base.secret-read
  on: {action: file.read, phase: decided-allow, resource_classes_any: [cred-store, private-key, browser-store]}
  set: {label: secret-read, scope: lineage, decay: session-end}
- id: grdr.destructive.mass-change
  on: {action: [file.delete, file.write], phase: observed, actor: agent}
  count: {counter: bulk-change, window: 60s, threshold: 200, label: mass-change}
```

Built-ins: `grdr.approval-streak` (12), `secret-read` (its source rules are 16 section 5's), `undeclared-activity` (one in a fail-closed target class, or three in 10 minutes; 07 section 9), `mass-change`, and the deterministic D-28 day-one labels. `injection-suspected` is model origin and therefore always advisory.

### 7. The engine on the device and on the server

```rust
pub trait DetectionEngine {
    fn load(c: &VerifiedDetectionContent, host: &HostProfile) -> Result<(Self, LoadReport), LoadError> where Self: Sized;
    fn on_event(&mut self, ev: &EventView<'_>, out: &mut DetectOutput); // event time is inside ev
    fn on_tick(&mut self, now: Timestamp, out: &mut DetectOutput);     // window expiry only
    fn snapshot(&self) -> DetectState;
    fn restore(&mut self, s: &DetectState) -> Result<(), LoadError>;
}
```

`EventView` reads fields by registry id over decoded protobuf. `rsigma-eval` expects JSON (c2 F9), so our pinned fork adds a field-accessor trait; the fallback is our own matcher over `rsigma-parser`'s AST (SP13-1). `rsigma`, `rsigma-runtime` and `rsigma-mcp` stay banned (03). `LoadReport` lists every skipped rule as "could not evaluate"; one bad rule never stops the others.

**Device.** The sandboxed `grdr-engine` runs detections after the event's decision is returned, over spine and local-lane events in session order, seeing content at the organisation's capture level (D-52). Targets, to be measured in SP13-1: p99 300 µs per event at 300 rules; 32 MB of state. A backlog over 10,000 events or 2 seconds raises `health.coverage` reason `detect-lag`; decisions come first. The daemon appends findings to the `decision` lane.

**Server** (requires the server and its bus, D-33). The `detect` target consumes the bus in session order (D-33) and runs `server` and `any` rules over metadata-class events, organisation-scope correlations and retro replays; target, a finding within 2 minutes for 99% of events (D-56). An `any` rule runs on the device for sensor events and on the server for connector and gateway events, never both. Rules are indexed by log source (`category`, `service`) and by required field presence on the server and the device, so an event meets only rules that can match its class. Compiled rule sets are cached by bundle digest and shared by every organisation pinning the same packs, with tunables as an overlay. Each organisation has a detection cost budget in rule-microseconds per event (default 50, target), computed at compile from each rule's measured cost (section 12 check 6) times its log source's share of that organisation's events over 7 days; a bundle over budget is refused for live placement, and its over-budget organisation rules run as scheduled hunts, named with their cost in the console. Under overload `detect` sheds lowest maturity first: organisation `experimental`, project `experimental`, `test`, then `stable` at `record`; tamper and threat `stable` rules and `grdr.det.decision` are never shed, and each shed rule is `health.coverage` reason `engine-overload` for that organisation.

**Retro and hunts** (require the server and the lake, 20). A new indicator is matched over retention through the observable index (14 section 8). A new or changed rule is replayed by the same engine over the last 24 hours (20 section 7); a longer range is a `retro` job an investigator starts, with estimated scan bytes shown first, charged to the organisation's query quota. `review` batches every changed rule of one bundle change into one scan per (cell, table, day), newest day first. Findings are marked `retro` (D-54), never page, and raise one summary notification per organisation and rule. A hunt is a rule run once over a time range: literal predicates are pushed down to the lake scan (20) as a pre-filter and the engine decides matches, so hunt and live detection cannot disagree. Content-reading hunts fan out only to devices that the observable index or `session_summary` names for the hunt's range and literal predicates, at most `hunt_fanout_max` (default 1,000, sampled by `HMAC(organisation sample key, device_id)`), one fan-out hunt per organisation at a time, 200 ms of CPU per device (the rest answers `partial`) and a 24-hour expiry; they return counts only (12 section 11) and state the share of targeted devices that answered.

### 8. Typed analysers

Analysers are pure functions in `grdr-core::analyze` with pack-data vocabularies, a `Resolution`, facts with origin and a fuzz target (D-10). `malformed` denies (12 section 4, row 1); `unresolved` sets the class's opaque fact with reasons.

**Shell canonicaliser (POSIX shells, PowerShell and cmd).**
- *Input:* raw command, dialect from the adapter manifest, working-directory class, environment delta. *Parsers:* `brush-parser` (MIT) for POSIX shells, `tree-sitter-powershell` (MIT), our own `cmd.exe` tokeniser (09).
- *Output:* a tree of lists, pipelines and subshells whose leaves carry canonical argv (quotes removed, escapes processed), assignments and redirect targets.
- *Recursion:* a pack wrapper table says which argv positions hold nested commands (`bash -c`, `pwsh -Command`, `cmd /c`, `env`, `sudo`, `timeout`, `xargs`, `find -exec`, `git -c core.*`). Depth is capped at 8, and inner classes propagate outward.
- *Decoding:* deterministic, before classification. `-EncodedCommand`, `base64 -d | sh`, gzip and hex, up to 3 layers and 1 MiB, recorded as `exec.decoded`.
- *Unresolved:* unknown-variable or `$IFS` expansion, substitution or arithmetic in command position, dynamic `eval` or `source`, `Invoke-Expression`, undefined aliases, and limits exceeded.
- *Facts:* pipe or heredoc into an interpreter, inline passwords (`PGPASSWORD=`, `sshpass -p`, `mysql -p`), and bypass flags as literal `argv_token` matches.
- *Classification:* over canonical argv only, never raw node text. GuardFall bypassed the five agents that had pattern guards because their matchers read raw node text (09, verification row 4).

**Path canonicaliser (Linux, macOS and Windows).**
- *Lexical stage:* `~` and the workspace root; collapse `.`, `..` and repeated separators; `\\?\` and UNC forms; trailing dots and spaces; NTFS streams (`path.ads`); NFC; case folding per volume, taken from host facts.
- *Symlinks:* the core does no I/O. The engine returns the paths as `pending`, and the daemon attaches `PathFacts {realpath, is_symlink, volume_case}` within the deadline. A late answer leaves the path `unresolved`.
- *OS effects* are judged on the opened object the sensor reports, which defeats TOCTOU swaps.
- *Classes:* from pack glob sets: `agent-control`, `grdr-control`, `monitoring-config`, `cred-store`, `private-key`, `agent-store`, `browser-store`, `autorun`, `session-tmp` (the protected-path lists are 16 section 2's).

**Host and URL classifier.**
- *Parsing:* WHATWG URL parsing; UTS 46 IDNA to A-labels; lower case; trailing dot removed.
- *Addresses:* decimal, octal and hex IPv4, plus IPv4-mapped and NAT64 IPv6 (cat. 39). The registrable domain comes from a versioned Public Suffix List pack, plus the organisation's `org.internal-suffixes`, which count as public suffixes.
- *Facts:* `url.userinfo` (cat. 71), `url.long-query` (over 512 characters, tunable), `host.raw-ip`, and heuristic `dns.label-entropy`.
- *Classes:* `paste-capture`, `tunnel-service`, `cloud-metadata`, `model-provider`, `multi-tenant-api` (only path and credential pinning means anything there), `package-registry`, `signup`, `org.*`. Lookalikes of an allowed host are heuristic and feed findings only. The pack's host lists name public services, which a site without internet never reaches, so `model-provider` also takes the organisation's declared model endpoints and gateways (05 section 7) and `package-registry` an `org.package-mirrors` list in the layer document; adding a host is a layer change at the class's grade (12 section 7). In isolated mode with either list empty, `grdr doctor` and the assurance record report `host-class-unpopulated` for that class instead of evaluating its rules as if nothing matched (P9).

**Content detectors (catalogue and redaction owned by 16).**
- *Contract:* `content.secret`, `secret.type` (value: the kind) and `pii.class` (value: the class), each with spans (16 section 4).
- *Origin:* deterministic only for structurally validated tokens (checksum, prefix with length, Luhn, IBAN). Entropy and rarity are heuristic; NER is model origin.
- *Decoding:* inputs are decoded first (base64, gzip, hex, URL encoding). Key bodies match without their prefixes, because stripping `sk-ant-` evaded masking (cat. 31).
- *Engine:* Kingfisher crates (Apache-2.0) reading the Betterleaks catalogue (MIT), offline, validation off on endpoints (09, verification row 7).

**MCP tool-definition differ.**
- *Input:* the pinned and the current tool lists for one server, in JCS form (04 manifest hash).
- *Output:* deterministic `mcp.manifest.drift` with change classes:
  - `tool-added`, `tool-removed`, `description-changed`;
  - `schema-widened` (new property, dropped `required`, wider enum or type, opened `additionalProperties`);
  - `annotation-weakened` (`readOnlyHint` cleared, `destructiveHint` set);
  - `name-shadow` (equal to or confusable with another configured server's tool).
- *Description scans:* invisible characters (U+E0000 to U+E007F, zero-width, bidi), credential paths and cross-server tool references are deterministic. Instruction phrasing is heuristic, because phrase lists are noisy (g06).

### 9. Content scanning, tripwires and config integrity

**YARA-X** (1.23.0, BSD-3-Clause) scans artefacts, not every tool output:
- skills and plugins at first sight and on digest change;
- agent config files on change;
- scripts and binaries that agent lineage writes, before they are executed;
- stdio MCP server directories at first sight.

Limits are 16 MiB and 50 ms per file; exceeding either is a could-not-look fact. Embedded builds use the interpreter (03). Matches emit `yara.<namespace>.<rule>` with the pack's declared origin. We ship our own rules and malcontent's own Apache-2.0 rules, never its `third_party` directory (g06 verification row 6). Skill drift is the difference in rule hits between versions (`skill.capability-added:<cap>`, malcontent's method).

**Config-integrity monitor.**
- *Locations:* agent adapter manifests (03) list each agent's config, hook, MCP, skill, rule, memory and policy-source paths per OS. `grdr.config-map` adds `.vscode/settings.json` and `tasks.json`, `*.code-workspace`, `AGENTS.md`, `CLAUDE.md`, `.git/config` (`core.fsmonitor`, `core.sshCommand`, `core.hooksPath`) and `HEARTBEAT.md`.
- *Baseline:* the first-run scan records digests and parsed structure.
- *Change classes:* file events with writer lineage feed version-aware parsers, which emit `config.change_classes`: `adds-hook`, `adds-mcp-stdio`, `permission-widened`, `base-url-changed`, `env-injected`, `policy-source-added`, `task-folder-open`.
- *Repository trees:* the checked-out tree is scanned at session start and when a repository appears. `grdr scan repo` and CI mode scan every branch, as h07 implication 1 asks.
- *Version awareness:* parsers declare the agent versions they cover. For example, `bypassPermissions` set in project or local settings has no effect from Claude Code v2.1.257, while repository hooks, MCP entries, `env` and allow rules still apply after the trust step (21 verification B).

**Tripwires.**
- *Honeytoken:* 16 plants a phantom credential. Any use is an Essentials Block (12 policy 2); use or egress carrying its value is a threat finding (c8 F10).
- *Canary files* at paths the owner chooses: a read by agent lineage is a threat finding.
- *Monitoring config:* our alerting settings and the monitors the organisation lists join the `monitoring-config` class; a write by agent lineage raises row 31 (h07 N5).
- *Synthetic sensor:* D-56's signed known-bad sequence every five minutes is the pipeline's live recall canary.

Decoy MCP tools (HoneyMCP, h01) would introduce an MCP server, which P7 forbids for packs, so they cannot ship as content; they require organisation-layer templates in 12.

### 10. Detection catalogue

Rows 1 to 30 are `c8` F5 in order (D-53). Data: H hook, S OS sensor, C config monitor, B MCP broker, P proxy, I inventory, T intelligence pack, F server (rows with F require the server). Default: enforcing policy rule and its shipped Mode (12 sections 5 and 14), finding class, ceiling; any block also yields the blocked-attempt finding. Mapping: stage (02), ATLAS v2026.10 without `AML.`, OWASP ASI 2026, all validated in CI. Evidence: "cat." is a brief 21 row, "N" an h07 item.

Essentials' `elevate` rule (Ask from agent lineage in the protected profile, Watch in the user profile; D-53, R-10) is a policy rule in 12 with no row here; its Ask receipts reach findings through `grdr.det.decision` (section 5).

| # | Behaviour | Data | Logic sketch | Mapping | Default | Evidence |
|---|---|---|---|---|---|---|
| 1 | Write to any agent's hooks, MCP, settings, skills, rules or memory | S C H | Write or `config.change`, `agent-control`, actor agent | K5; T0081, T0080.000; ASI06 | Essentials Block; tamper; remediate | cat. 5, 6, 8, 10, 104; N15 |
| 2 | Agent lineage editing Guardrails files or disabling the product | S H | `grdr-control` path; service-stop and uninstall classes | K9; T0138; ASI10 | Essentials Block; tamper; contain | cat. 6, 10, 14 |
| 3 | Repository-carried agent config at clone | C S | Tree scan finds hook, stdio MCP, permission widening, base-URL env | K2; T0081, T0142; ASI05 | none; threat; remediate | cat. 8, 15, 16, 31; N13 |
| 4 | New hook or MCP entry launching an interpreter from temp or repo | C | `adds-hook` or `adds-mcp-stdio`, interpreter, prefix `$TMP`, `$WORKSPACE`, `~/.config` | K5; T0081; ASI06 | none; threat; remediate | cat. 104, 5; Securonix 311 |
| 5 | Credential-store read from agent lineage | S H | Section 2 example | K4; T0083, T0055; ASI03 | Essentials Ask; policy-violation; notify | cat. 31, 64, 104 |
| 6 | Destructive command classes | H S | `rm-recursive-root`, `git-history-rewrite`, `infra-teardown`, `db-destroy`, `disk-format` | K8; T0101; ASI08 | `grdr.destructive` Watch; overeager; contain | cat. 119 to 128 |
| 7 | Irreversible action on a production target | H P | Irreversible class with target `org.production` (credential or tag) | K8; T0101, T0034.002; ASI08 | `cloud.prod-mutation` Off until lists set; overeager; contain | cat. 121, 123, 124, 127 |
| 8 | Mass delete or rename rate | S | Session rule `mass-change` | K8; T0101; ASI08 | `grdr.destructive` Watch; overeager; contain (freeze) | cat. 120, 126, 128 |
| 9 | Non-agent process launching an agent CLI with permission-skipping flags | S | Catalogued agent image, `flag.bypass-permissions`, parent not interactive | K3; T0112.000, T0053; ASI02 | Essentials Block only where a boundary judges the exec (07 `bypass-flag`), else none; threat; contain | cat. 100, 24 |
| 10 | Package lifecycle script spawning agents or reading credential stores | S | `temporal_ordered` by lineage: install, then spawn or `cred-store` read, 5 min | K2; T0010.001, T0011.002; ASI04 | none; threat; contain | cat. 100 to 104 |
| 11 | Base-URL or proxy drift | C S H | Start environment or config sets a model base URL or proxy outside `org.model-approved` | K6; T0108; ASI10 | `grdr.egress` Watch; threat; remediate | cat. 8, 97, 105 |
| 12 | Execution in agent lineage with no matching hook event | S H | 07 `undeclared-activity` outside the housekeeping profile | K3; T0053; ASI02 | built-in; tamper or coverage-gap; notify | brief 01; P3 |
| 13 | Shell parse ambiguity | H | `exec.resolution` unresolved or malformed | K3; T0107; ASI02 | `destructive.opaque-command` Watch; policy-violation; record | cat. 9, 22; GuardFall |
| 14 | Pivot after denial through another tool | H S P | Section 4 example | K3; T0107; ASI02 | none; threat; contain | cat. 24; Origin 17 |
| 15 | Nested headless agent, or child with weaker settings | H S | Spawn with headless or bypass flags, or contained parent and uncontained child | K3; T0053; ASI02 | `agents.subagent-ceiling` Watch; threat; contain | cat. 24, 100; Origin 1 |
| 16 | Secret in tool input, output or prompt | H P | `content.secret` on arguments, results or model request (device) | K8; T0055; ASI03 | `secrets.prompt-redact` Watch; policy-violation; notify | cat. 31, 27 |
| 17 | Egress to capture, paste, form or webhook hosts | S P | `paste-capture` host, actor agent | K8; T0077, T0086; ASI02 | `grdr.egress` Watch; threat; contain | cat. 85, 134 |
| 18 | Tunnel, mesh VPN or Tor from agent lineage | S | Image class `tunnel` (userspace `tailscaled`, `cloudflared`, `ngrok`, `tor`, `ssh -R`) or `tunnel-service` host | K6; T0108; ASI10 | `grdr.egress` Watch; threat; contain | cat. 56, 134, 135 |
| 19 | Persistence created by agent or install lineage | S C | Write to `autorun` (user units, LaunchAgents, scheduled tasks, `authorized_keys`, linger) | K5; T0081; ASI06 | none; threat; notify | cat. 56, 103, 104 |
| 20 | Known-bad or typosquat MCP server, skill, extension or package | I T | Digest or purl in the mirrored OSV pack; lookalike (heuristic) | K2; T0010.001; ASI04 | `grdr.supply-chain` Watch; threat; remediate | cat. 42, 53; N16, N19 |
| 21 | Vulnerable agent or gateway version | I T | Version inside a GHSA or KEV range (`grdr.det.vulnerable-version`, 14 section 6) | no stage; T0049; ASI04 | none; threat; record | 21 CVE rows; h01 OffGuard |
| 22 | MCP tool definition changed after approval | B I | `mcp.manifest.drift` | K1; T0110, T0099; ASI04 | `mcp.tool-pin` Watch; threat; remediate | cat. 5, 34, 42; N21 |
| 23 | Instructions, credential paths or invisible Unicode in tool descriptions and skills | B I | Differ and YARA-X facts | K1; T0051.001, T0110; ASI01 | none; threat; notify | cat. 1, 34, 54, 57 |
| 24 | `secret-read` session reaching an external sink | core | `data.flow` with `secret-read` | K8; T0077; ASI02 | `dataflow.secret-to-sink` Watch; threat; contain | cat. 76 to 85 |
| 25 | Registry publish or account creation | H S P | Sink `pkg.publish`; request to `signup` class | K8; T0125; ASI10 | `supply.publish` Watch; policy-violation; notify | cat. 133, 135, 138; N7 |
| 26 | Push outside the organisation or to a new public repository | H S P | Sink `push-outside-org` | K8; T0086; ASI02 | `grdr.dataflow` Watch; threat; contain | cat. 100, 104, 108; N3 |
| 27 | Cloud metadata access or token minting | S P | `cloud-metadata` host, or token-mint command classes | K4; T0055; ASI03 | `grdr.egress` Watch; threat; contain | cat. 134 |
| 28 | Tampering with endpoint protection or our sensor | S | `edr-tamper` classes: service stop, exclusion add, log delete, history edit | K9; T0138; ASI10 | Essentials Block for our sensor, none for other products; tamper; contain | cat. 131, 134 |
| 29 | Link out of the workspace followed by a write | S | `temporal_ordered`: outward link created, then write through it, 10 min | K4; T0105; ASI05 | none; threat; contain | cat. 10, 14, 39 |
| 30 | Git running helper programs in a fresh clone | S | Non-git child of `git` in a repository under 1 h old, or `fsmonitor` or `sshCommand` set | K2; T0142; ASI05 | none; threat; notify | cat. 14, 19 |
| 31 | Agent edits monitoring or alerting configuration, or tests asserting monitoring | S C | `monitoring-config` write; recipient list emptied | K9; T0138; ASI10 | Essentials Block; tamper; contain | N5 |
| 32 | Non-agent process reads an agent's local stores | S | `agent-store` read by a process that is not that agent | K4; T0083; ASI03 | `grdr.secrets` Watch; threat; notify | N18; D-22 |
| 33 | Hook dark or hook silent | S H | 07 section 9 | K9; T0138; ASI10 | built-in; tamper; notify | brief 01; D-13 |
| 34 | Executed command differs from the approved one | S H | 07 `effect-mismatch` | K3; T0107; ASI09 | built-in; tamper; contain | cat. 66 |
| 35 | Agent writes a script or binary, then runs it | S H | `temporal_ordered`: write with digest d, then exec of d | K3; T0053; ASI02 | none; overeager; record | cat. 24; brief 06 |
| 36 | Standard-library module shadowing | S | Stdlib-named module written into the working directory, then interpreter run there | K3; T0053; ASI02 | none; threat; notify | cat. 24 |
| 37 | Encoded or nested payload executed | H | `exec.decoded` into an interpreter | K3; T0107; ASI02 | none; threat; notify | cat. 66, 134 |
| 38 | Credential in command-line arguments or approval memory | H C | Inline-password facts; a secret inside a `settings.local.json` allow rule | K4; T0055; ASI03 | none; policy-violation; notify | cat. 27; Origin 14 |
| 39 | New higher-precedence agent policy source | C | `policy-source-added` by a writer other than us or the MDM owner | K5; T0081; ASI06 | none; tamper; notify | Origin 18 |
| 40 | Agent control server listening beyond loopback | S | Agent image listening on a non-loopback address | K6; T0049; ASI04 | none; threat; notify | Origin 19; cat. 2, 20, 60 |
| 41 | High-entropy DNS labels from agent lineage | S | `dns.label-entropy` above a tunable | K8; T0025; ASI02 | none; threat; notify | cat. 7, 25; N4 |
| 42 | Many sessions writing to one shared store | F | `value_count` of distinct sessions per destination prefix, 20 in 1 h, organisation scope | K7; T0118; ASI07 | none; threat; notify | cat. 134; N1, N7 |
| 43 | Same suspicious artefact digest across devices | F | `value_count` of devices per digest that has a row 20, 22 or 23 finding | K7; T0143; ASI07 | none; threat; remediate | D-54 |
| 44 | Skill drift or run-time remote fetch | I S | `skill.capability-added`, or a skill-attributed request outside the profile | K2; T0010.005; ASI04 | none; threat; remediate | h01 MalSkill; cat. 12, 53, 57 |
| 45 | Enforcing label arrived after a decision it would have changed | core | `label.late` (12 section 9) | none | built-in; coverage-gap; notify | c2 F2 |
| 46 | Probing a model-backed verdict provider (`grdr.det.judge-probing`) | H | `event_count`: five model-backed objections in 10 minutes over three distinct action digests of one tool class (19 section 1) | none | built-in; tamper; notify | h01 |

### 11. Content repository and pack layout

| Path | Content |
|---|---|
| `packs/<pack>/pack.toml` | Kind, semver, `min_engine`, channel, declared reads and data classes |
| `detections/<domain>/`, `tests/<rule>/` | Sigma rules; fixtures as 04 JSON lines |
| `policy/<pack>/` | Cedar, lists, `session-rules.yaml` (12) |
| `analysers/`, `yara/`, `detectors/` | Vocabularies; YARA-X rules; pattern packs (16) |
| `agents/<agent>/` | Adapter manifests with config map and housekeeping profiles |
| `mappings/` | Pinned ATLAS, ASI, SAF-MCP and ATT&CK releases, plus migration tables |
| `corpora/{positive,negative,goodlog}/`, `l0/` | Inert fixtures, public benign corpus, L0 sources |
| `conformance/`, `schema/`, `.agents/skills/`, `CODEOWNERS` | Engine vectors, schemas, contributor skills |

Packs are selectors, never copies (g06): `grdr.essentials` (policy), `grdr.det.core`, `grdr.det.experimental`, `grdr.det.tripwires`, `grdr.analysers`, `grdr.config-map`, `grdr.l0`.

### 12. Maturity, mandatory tests, benign corpus, shadow and rings

**Mandatory checks**, run in CI with the shipping engine (native and `wasm32`) at every supported engine version from `min_engine` up:

1. The rule loads.
2. One positive and one near-miss negative fixture pass.
3. Every constrained field has a concrete, non-wildcard value in some positive fixture (Channel File 291).
4. Declared reads equal computed reads.
5. Mappings resolve in the pinned releases.
6. Cost on the reference machine (one named free hosted CI runner type, D-64) stays inside the targets: p99 50 µs on a matching event and 1 µs on a non-matching one, which keeps 300 rules inside section 7's device target.
7. A logic change bumps `version`.
8. The benign corpus result matches the rule's status.
9. L0 portability is computed.

For organisation-authored rules, `grdr content lint` and `test` run these checks with no network: mappings resolve against the installed signed mapping pack, the public `goodlog` corpus comes from the air-gap bundle's `-verify` companion (24 section 7), and a check whose data is absent is reported `not run` with its reason, never passed.

| Status | Gate to enter | Behaviour |
|---|---|---|
| `experimental` | Checks pass; at most 1 benign hit per 1,000 corpus sessions | Counted only; ceiling forced to `record` |
| `test` | 14 days in ring 0 (the development fleet, D-47) with at least 500 sessions evaluated, and in ring 1 where the deployment has rings (rings require the server, 22); zero benign hits; fires in a harness scenario; `eval-acceptance` and `eval-adversarial` pass with their evidence (for a community rule, from two evaluators on different models, D-61) | Visible findings, never pages, ceiling at most `notify` |
| `stable` | 30 days at `test`, zero benign hits, at least 90% precision over 20 or more analyst verdicts where verdicts exist, the same evaluator passes as `test`, plus `eval-security` and a pass by the model that did not write the rule when the ceiling is `contain` or above | Pages for threat and tamper; declared ceiling |
| `deprecated` | Superseded or demoted | Replay only |

A bot proposes promotions from this evidence, never from age (Sigma's only promotion rule is 300 days unchanged, with its automation disabled; g06 verification). Rules below 50% precision over 20 verdicts are demoted automatically. Essentials admission is 12's gate (D-53).

**Benign corpus ("goodlog").** Recorded sessions from our development fleet, which runs under the product (D-47): D-64's tier B machines and the free hosted CI runners, since there is no money for lab hardware. Targets: 2,000 sessions (Claude Code and Codex, Linux and macOS), which Essentials admission and the `test` gate require (E5.2); 10,000 across four agents and three systems for the whole catalogue. SWE-chat v2 (17,968 sessions, ODC-BY; brief 39, `c8` S1) is a second set. Samples are redacted on the device and approved by `eval-acceptance` and a second evaluator on the other model, with their evidence (D-61, R-58), and can only make tests fail. `known-fps.yaml` lists reviewed exceptions; a held-out slice stays private until rotation (P11).

**Shadow and rings.** Shadow means experimental status, or a pack in Watch. Rings, bake times (detection content: 2, 4 and 12 hours) and the D-37 gates are 22's (section 7). This document adds three detection-channel gates to `rollout-gates.toml`: a rule's finding rate above five times its ring baseline; any load error; `detect-lag` on more than 1% of devices. An analyser vocabulary ships on the policy channel and is held by 22's deny-rate and prompt-rate gates. The rapid lane carries indicators and verdicts only, never changes a ceiling or status, and still bakes (D-37). Rollback is a new signed release.

**Mode on detection packs.** The packs keep the one ladder (D-44):

| Mode | Effect |
|---|---|
| Off | Not evaluated |
| Watch | Findings; responses simulated |
| Ask | Responses limited to holding the next call for a grant |
| Block | Responses up to each rule's ceiling (`remediate` verbs only for opted-in rules) |

Packs ship at Watch and propose promotion after seven days with simulated counts (D-53).

### 13. Tuning and suppression

Standalone keeps tunables and suppressions in the device and user layers; organisation-wide tuning, the approver role and the suppression workflow require the server.

- **Tunables** are typed (bounded list over a field; bounded integer or duration), live in layer settings (12 section 7), survive pack updates and show as a diff. Locked tunables cannot be loosened lower down; loosening writes an `audit.admin` widening record and needs the approver role (D-55).
- **Suppressions** (04 schema, 18 workflow) must name an observable, agent type, group or device; whole-rule scope is refused, because disabling a rule is a Mode change. Expiry is mandatory, at most 90 days, and renewals are audited. A suppressed finding is still recorded, including blocked attempts.
- **Analyst verdicts** feed precision and propose suppressions. They never edit rule logic (l03 F3).

### 14. Response bindings

`x_grdr.response` names 18's `ResponseAction` verbs at or below the rule's ceiling, with a blast-radius block: `max_scope` session by default and 18's `max_share_bp` default of 500 (5% of the organisation's devices per hour). Actuators degrade by host capability (18 section 2). The section 5 origin cap applies. Every binding starts in `simulate`; `remediate` verbs stay there until a policy approver other than the author opts the rule in after seven days of "would have acted N times" (18 section 1, D-55). A pack change to a rule's verbs or caps is widening (12 section 7).

### 15. Precision and recall reporting

Each detection pack release ships `content-report.json` inside the signed pack, so the rule pages (27) render from local data in every shape, air-gapped included, and the same file feeds the public scorecard (spine D-45; the harness document is pending), per rule:
- recall on the public `verify` scenarios by family, and on the held-out set once that set is published two releases later (D-45);
- benign hits per 1,000 sessions;
- firing rate in rings 0 and 1;
- detection latency;
- cost per event.

Recall, benign rate and cost require only the harness (D-45). Precision comes from analyst verdicts, which require the server's review queue; it is computed inside each organisation, and the public figure aggregates verdict counts from opted-in organisations only when five or more contribute (D-51).

### 16. Compiling content for embedding option L0

Partner telemetry has no session, label or verdict fields, so `grdr.l0` holds generic-Sigma rules over `process_creation`, `file_event` and `network_connection`, each with `derived_from`. Rules reading only portable fields convert automatically; the rest are hand-written (c2 F9 with l03 F9).

- **Agent lineage** is expressed as `ParentImage|endswith: '%grdr_agent_images%'`, expanded from tier A catalogue entries. That reaches direct children only, and each rule states the gap.
- **Targets** are the five in D-41: KQL, LogScale, EQL, XQL and SPL (ES|QL is not one), through pySigma backends run as a CI tool (LGPL-2.1, not linked); each detection release also ships the converted rules per target as signed archives beside the L0 archives, so a site with no package index imports them directly. A Rust emitter covers any backend that is missing.
- **Defender join rule** (R-29). A KQL rule meant to let the partner isolate a device joins its Defender tables on `DeviceId` and returns `DeviceId` in every result row, so the partner's device action can target the device. A rule that cannot produce `DeviceId` is marked detect-only in the coverage manifest.
- **Verification.** Each backend is labelled `executed` (fixtures loaded into a local instance of the target engine, for example Elasticsearch or Splunk) or `syntax-checked` (no local engine). With no budget, a local engine counts only if it is free to run in CI (a free or developer licence, or an open-source build); a backend without one is `syntax-checked`. Which backends and local engines exist is unverified (SP13-3).
- **Delivery.** One signed archive per backend, with a coverage manifest. 26 owns delivery to partners.
- **OCSF export pipeline** (D-09). A pySigma processing pipeline, `grdr_ocsf`, generated from the field registry, maps our field names to 04's OCSF 1.9 export, so an organisation can run `grdr.det.*` rules in its own SIEM over exported events.

### 17. Contribution workflow

Outside contributors require the contributor skills and templates (E5.4).

1. Open an issue from a template: detection gap, false positive, new agent or malicious artefact.
2. Open a pull request with the rule, inert fixtures, evidence and mappings. AI agents follow the same path through the repository skills `add-rule`, `add-agent` and `triage-fp` (g06). Rules are written fresh: SigmaHQ rules (DRL 1.1, attribution duty), Elastic rules (Elastic License 2.0) and malcontent's `third_party` YARA are never copied in, because content is Apache-2.0 with no attribution duty (D-02; g06 verification row 6).
3. CI runs the section 12 checks and posts the version bump, pack placement and L0 portability.
4. A first-party rule lands once `eval-acceptance`, `eval-adversarial` and `eval-licence` pass with their evidence; a community rule needs those passes from two evaluators on different models. A ceiling of `contain` or above also needs `eval-security`. A community rule without both passes stays in Watch (D-61).
5. The rule merges as `experimental` into ring 0, and the bot proposes promotions.

## Interfaces and contracts

| Interface | Shape | Other side |
|---|---|---|
| `DetectionEngine`, `EventView`, `DetectOutput` | Section 7; vectors in `conformance/detect/` | `grdr-core` `step` (03); embedders (26) |
| Analyser outputs | `Fact`, `Resolution` (04); `resource.classes`, `context.facts` | 12 |
| `PathFacts` effect | Engine asks; daemon answers within the deadline | Daemon (03) |
| Findings, risk, labels | `finding.state`, `session.label` (04) | 18, 20, 25 |
| Response binding | `ResponseAction` verbs and blast-radius block | 18 |
| Pack kinds `detection`, `detector`, `analyser-vocab`, `tripwire`, `l0` | `pack.toml`; channel per section 1 | 22, 11 |
| CLI | `grdr content` (`lint`, `test`, `replay`, `explain`, `l0`), `grdr detect status`, `grdr scan repo`, `grdr hunt` (requires the server) | Contributors, CI |
| `content-report.json` | Section 15 | 27; the public scorecard (spine D-45) |

## Behaviour by deployment shape

| Shape | Difference |
|---|---|
| Standalone | All rules on the device; organisation scope means the device. Precision from corpus and harness; local suppressions; notifications, no paging |
| Self-hosted | Server adds cross-device rules, retro, hunts, verdict precision. Organisation-authored rules need positive and negative tests and replay on own history before leaving Watch (l03 F3) |
| Air-gapped | As self-hosted, with every pack from the bundle or content exports (24 section 7); retro matching runs on each import (14 section 8.3); host classes take organisation lists (section 8); rule pages show the organisation's own precision beside the bundled public figure |
| Hosted | Requires the hosted service's preconditions (D-63). As self-hosted; tenant rules see only their organisation; opt-in counts feed the public report |
| Embedded | L0 archives; L1 feed; L3 under the partner's `HostProfile` (unsupported rules `not_evaluable`); L4 over the partner's lake; re-signing through the content relay (D-60) |

## Extension points

Packs of detections, session rules, vocabularies, YARA-X rules and tripwires (section 17); third-party facts under `x.<owner>.*` with declared origin; alternative `DetectionEngine` implementations that pass the vectors (Tier 2, contrib repository); new L0 emitters with fixture sets.

## Security and privacy

- **Content cannot execute** (P7); linear-time regex, cost limits, state bounds and YARA-X timeouts bound denial of service.
- **Poisoning.** Evaluator passes with evidence for first-party rules and corpus samples, and from two evaluators on different models for community content (D-61); no content path widens policy (section 1).
- **Secrecy.** Detection content and findings are protected paths for agent lineage; governed sessions cannot read them (D-38).
- **Privacy.** Declared reads enforced; content rules on the device; no grouping by person; redacted evidence spans (16); baselines by agent type, project and peer group (D-51).
- **Bypasses** of an analyser or the engine are vulnerabilities with CVE and VEX; a missed detection is a content gap (D-62).

## Test and evaluation strategy

| Property | Oracle | Pass |
|---|---|---|
| Canonical argv equals what runs | Real `bash`, `dash`, `zsh`, `pwsh` 7, PowerShell 5.1, `cmd` with argv-recording stubs on `PATH`, on the free hosted runners (D-64); GuardFall A to E | No mismatch on `resolved` |
| Canonical path equals the kernel's | `/proc/self/fd`, `F_GETPATH`, `GetFinalPathNameByHandle` after `open` | Equal on every system |
| Host equals what consumers fetch | Node WHATWG `URL`; curl URL API | Equal hosts |
| Schema widening classified | JSON Schema validator on generated instances | Newly accepted instances imply `schema-widened` |
| Sigma matching | `grdr-sigma-ref` by a different worker (12 section 16 pattern) | Identical findings native, C ABI, `wasm32` |
| Correlation order independence | Simulation with shuffled arrival within lateness | Identical `dedup_key`s and findings |
| State bounds | Key flooding at ten times the bound | Overflow finding; memory capped |
| Rules; L0 | Fixtures, corpus, harness (spine D-45 and D-64; detailed document pending); backend fixtures | Section 12 gates; equal match counts |
| Declared endpoints classify | An agent pointed at an internal vLLM listed as a declared endpoint | Classified as an LLM client; moved to an unlisted host it fires row 11; empty lists report `host-class-unpopulated` |
| Organisation rule checks offline | A fixture organisation rule with no route | Checks 1 to 7 and 9 pass; SWE-chat is reported `not run` |
| Rule pages offline | A crawl of the rule pages (air-gap conformance run S-31, step 15) | No request outside the server origin |

## Work breakdown

**E1 Engine**
- E1.1 Trait, `EventView`, `rsigma` fork, SP13-1. Accept: the row 12 finding leaves through `DetectOutput`; native and `wasm32` agree on the conformance vectors; SP13-1 is decided.
- E1.2 Correlation with bounds, snapshot and restore. Accept: section 4 properties hold over one million simulated interleavings.
- E1.3 Findings, risk and labels; `grdr.det.decision`. Accept: every Ask or Block receipt has a finding; a schema test proves risk never enters a Cedar request.
- E1.4 Load report and `detect-lag`. Accept: an injected malformed rule and a stalled engine each show "could not look" within 60 s.
- E1.5 Response bindings, `record` to `remediate` with the opt-in. Accept: a binding above its ceiling or without a blast-radius block fails pack validation; in the harness no heuristic- or model-origin finding triggers a `contain` verb; a `remediate` verb stays in `simulate` until opted in.

**E2 Analysers**
- E2.1 POSIX canonicaliser. Accept: shell oracle green; GuardFall classes resolved or opaque; S-14 measured.
- E2.2 PowerShell and `cmd`. Accept: oracle green; `-EncodedCommand` decoded.
- E2.3 Path canonicaliser for Linux, macOS and Windows. Accept: kernel oracle green per system.
- E2.4 Host and URL classifier. Accept: consumer oracle green; a Public Suffix List update needs no rebuild.
- E2.5 MCP differ. Accept: schema oracle green; a fixture per change class.
- E2.6 (with 16) Detector fact contract and decoding. Accept: a prefix-stripped key is found; origins are correct.

**E3 Monitors and scanning**
- E3.1 Config map and differ for Tier 1 agents. Accept: the Securonix 311 pair and the Shai-Hulud files raise rows 1, 3 and 4.
- E3.2 YARA-X. Accept: a timeout yields a could-not-look fact; the licence check finds no malcontent `third_party` content.
- E3.3 Tripwires. Accept: honeytoken use is blocked offline; the synthetic recall canary fires every five minutes.

**E4 Catalogue**
- E4.1 Every catalogue row, rows 1 to 30 first in `c8` order (D-53). Accept: each is at `test` or above; Essentials rows pass D-53 admission. Requires: rows 22, 23 and 44 need the MCP differ (E2.5) or YARA-X (E3.2); rows 42 and 43 need the server (E6.4).
- E4.2 Harness coverage for every row. Accept: each fires in a harness scenario on every Tier 1 cell that has its data.

**E5 Pipeline**
- E5.1 Repository, schema, CI checks. Accept: a wildcard-only fixture on a constrained field fails CI.
- E5.2 2,000-session corpus. Accept: no unreviewed sample; zero Essentials hits.
- E5.3 Status gates and promotion bot. Accept: `stable` is unreachable without verdict or corpus evidence.
- E5.4 Contributor skills and templates. Accept: an outsider lands a Watch detection from the guide alone.
- E5.5 Detection-channel rollout gates. Requires: rings (22). Accept: in a staged-rollout drill, a rule firing at over five times its ring baseline halts the ring, and resume needs the operator's recorded decision in a deployment, or a new release that passes the gates in the project's rings (22 section 7.3).

**E6 Server** (requires the server, its bus and the lake)
- E6.1 `detect`, lateness, retro. Accept: findings within 2 minutes for 99%; a retro finding equals the live one.
- E6.2 Hunts with push-down. Accept: hunt equals live on the same range.
- E6.3 Tunables and suppressions. Accept: a whole-rule suppression and one without expiry or over 90 days are refused; a suppressed blocked attempt is still recorded; loosening a tunable writes a widening record.
- E6.4 Rows 42 and 43. Accept: fixtures over 20 sessions and 3 devices fire.

**E7 L0**
- E7.1 `grdr.l0` and five backends. Accept: coverage manifest published; executed backends match the reference.
- E7.2 `grdr_ocsf` pipeline. Accept: for every `grdr.det.core` rule that converts, its fixtures give the same match count over the OCSF export in one executed backend as over our events.

**E8 Reporting**
- E8.1 `content-report.json`. Requires: the harness (D-45); precision requires E6. Accept: every rule has recall, benign rate and cost; precision appears only at five or more organisations.

## Risks, open questions and spikes

| Item | Question | Settled by |
|---|---|---|
| SP13-1 Sigma fit | Can `rsigma-eval` run without JSON? One author wrote about 2,100 of its 2,400 commits, and its sibling crates had five 2026 advisories (20, 11) | Write all 46 rows. Pass: 80% expressible, a fork patch under 500 lines, and section 7's device target met at 300 rules. Otherwise our own matcher over `rsigma-parser` |
| S-14, S-07 (spine) | Benign opaque rate; row 12 base rate | Under 2% opaque, or row 13 and `destructive.opaque-command` stay in Watch; 07 owns S-07 |
| SP13-3 L0 backends | Do pySigma backends exist for LogScale and XQL, under which licences, and which targets have a local engine for `executed` runs? | Convert `grdr.l0`. Pass: 80% of rules for KQL and SPL with fixtures executed |
| SP13-4 Corpus cost | Evaluator review cost per corpus session, in turns and share of the usage window (the unit `garden-cost` measures) | Measured over 100 sessions; the corpus routine stays inside its `usage_cap` in `.agents/kit/usage.toml` |
| SP13-5 Batched retro | Does one scan per (cell, table, day) carry a large rule change (section 7, P15)? | A 46-rule change over 24 hours of a simulated 50,000-endpoint cell at 100,000 events: each file read once; under 2 core-hours (estimate); findings equal to live evaluation |
| `PathFacts` latency | Cold-cache symlink resolution inside hook deadlines | Measured inside S-15 |

## Deviations from the spine and objections

1. **D-61's two human approvals for content.** Resolved by R-58, then replaced by owner instruction 7 (spine D-61): content lands on evaluator passes with evidence, and community content needs them from two evaluators on different models.
2. **Partial use of `rsigma`.** We vendor its matching and keep correlation state in our own module, because replay, snapshot and the section 4 bounds must be exact. This is a narrower reading of D-09. Open.
3. **Mode on detection packs** (section 12). The spine does not define Ask for a detection. We map it to "hold the next call". Open.
4. **Content ceilings are narrower than D-30.** D-30 lets a rule opt into any wider action; detection content never automates lease revocation, device isolation or file restore. A person issues those (18). Open.

## Sources

**Research briefs:** `09-oss-detectors.md`, `20-policy-languages.md` (Sigma correlation, `rsigma` verification), `11-oss-platform-blocks.md` (pySigma licence, `rsigma` commits), `g06-threat-intel-content-ops.md`, `21-threats-incidents.md` (sections 15 to 18 and verification), `22-research-conferences.md`, `36-response-operations.md`, `39-ai-ml-strategy.md`, `01-origin.md` (section 8), `06-market-runtime.md`, `h07-incidents-sweep.md`, `h01-conference-talks-agents.md`.

**Review notes:** `c2` (F2, F4, F9), `c8` (F1, F5, F10, S1), `l03` (F1, F3, F8, F9), `00-resolution.md`.

**Primary URLs (via the briefs):** https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md ; https://github.com/timescale/rsigma ; https://github.com/chainguard-dev/malcontent/blob/main/third_party/README.md ; https://adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/ . No fact was added from outside the briefs, the review notes and the design documents.
