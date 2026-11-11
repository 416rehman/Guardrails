# Review C2: policy and detection (D-07 to D-12, P2)

Date: 2026-11-10. Sources: spine draft 1; briefs 20, 09, g06, g07, 33, 35, 36, 02, 11, 15; read-only `gh` checks today against `cedar-policy/cedar` and `timescale/rsigma`.

## Summary

Cedar, forbid-unless-evidence, and the "detections write, policies read" split survive as ideas but not as written, because the spine never says how they meet at run time. Four things are unspecified and each breaks a promise elsewhere: how Ask produces evidence, when a label becomes visible to the next decision, what a ceiling proof covers, and what enforces on day one. The change that matters most: policy may read only state written synchronously and deterministically inside `grd-session` (source rules and the session monitor); Sigma correlation and models write findings and risk. That one rule fixes the race, the P2 leak, the replay gap and the rsigma exposure together.

## Findings

### F1. Ask has no evidence path, and contradicts D-31 and D-13 (blocker; D-07, D-08)

D-07 implies `STEP_UP` maps to the hook's native `ask` where one exists. A native ask is a click in the agent's own UI, which D-31 says is never an approval. It also mints no grant, so when D-13 re-evaluates the policy at the OS, `forbid ... unless grant` denies an action the user just approved. Holding the hook open instead runs into hooks that fail open on timeout and into macOS Endpoint Security deadlines.

Evidence: 36 TL;DR and capability table (verbs differ, timeouts fail open); 36 verifier ("AUTH deadlines rule out holding for human approval"); 33 TL;DR (93% of prompts accepted); 20 section 5 (Claude hooks cannot bypass ask rules).

Amendment to D-07: "`STEP_UP` never uses an agent's native ask. Every control point returns DENY with a retry token; the approval helper mints a grant; the agent retries. Holding is an optimisation only where the fail-closed flag is set and the deadline is known. A grant names the rule ids it lifts, the action digest or pattern, and the session label epoch; a label escalation voids it."

### F2. No guarantee that a label is visible to the next decision (blocker; D-09)

D-34 says real-time detection runs on the bus, so label writes are asynchronous by design. Three writers with different latencies (inline analysers, streaming Sigma, lagging OS telemetry) feed one label set, and hooks for parallel tool calls run concurrently. A `secret-read` label that lands after the next egress decision is a silent allow, and replay (D-05, D-11) cannot reproduce a decision without knowing which labels were present. rsigma defaults make this worse: wall-clock timestamp fallback, and a hard cap of 100,000 state entries that evicts the stalest 10% in bulk, which an agent can trigger by flooding group keys.

Evidence: spine D-34; 36 Weak points ("concurrent hooks for parallel tool calls"); 20 TL;DR (monitors must update at observe time); `rsigma-eval` README, CorrelationConfig and Memory Management (checked today).

Amendment, replacing D-09's label sentence: "Labels that policy reads are written only by source rules and the session monitor in `grd-session`, synchronously, before the observing control point is acknowledged. Sigma correlations write findings and risk. Each label is typed `sync` or `eventual` (OS or server origin); an eventual label arriving after a decision it would have changed raises a finding and a response. Every receipt records the session-state sequence number."

### F3. Ceiling proof is unsound across slots and blind to lists (major; D-11)

SymCC treats context slots as free variables. If a child keeps the Cedar text and changes a slot definition (approval window 15 minutes to 24 hours), the proof says "equivalent" while behaviour widened. Lowered slot names are per-policy indexes, so the same formula in parent and child yields false widenings. The commonest edit, adding a host to a trusted list, is entity data the proof never sees. SymCC also has no timeout (an open issue shows a `like` disjunction stuck over ten minutes in encoding), no template-linked policies, and needs an external cvc5 binary, so it cannot run on a standalone device.

Evidence: 20 Weak points and verifier row 5; g07 verifier row 3; `cedar-policy/cedar` issues 2594, 2288, 2658 (all open today).

Amendment: "Ceilings hold by construction: each layer is its own policy set and any layer's deny wins, as with AWS service control policies. Lists carry a parent maximum checked by set containment. Slot identity is the hash of its definition. SymCC produces the advisory diff and lints on the server; a timeout or unknown counts as widening."

### F4. P2 is violated through labels and risk (major; P2, D-09, D-29)

D-09 lets detections write "labels and risk" that Cedar reads, and D-29 puts small models in the detection tiers. A `forbid when principal.risk > 80` or a model-written `injection-suspected` label is a blocking decision that depends on a model. Worse, a model-origin value inside `unless` lets a model lift a deterministic forbid.

Evidence: 09 TL;DR (over 90% adaptive attack success; stacking did not help); 20 verifier (wrong-shaped provider output can leave a forbid unsatisfied).

Amendment to P2 and D-09: "Every label and risk input carries an origin: `deterministic`, `heuristic` or `model`. The bundle compiler rejects any policy where a model-origin slot appears in `unless`, and rejects Block posture where satisfiability depends on a model-origin slot unless the operator sets an explicit bring-your-own-model flag recorded in the receipt."

### F5. Day one enforces nothing (major; missing decision, D-44, D-15, D-28)

D-44 starts every pack in Watch. That is the BeyondTrust weakness the research holds up as an opening ("a default deployment enforces nothing"), and it contradicts D-15 and D-28 (protected paths by default). The content pipeline also requires `stable` status for a block ceiling, which no rule can have at first release.

Evidence: 02 Surprises; 33 Design review ("allow-all first runs break Smart Defaults"); g06 content schema and contribution workflow; 35 Weak points (taint creep makes approval noise).

Amendment, new D-11a: "A Baseline pack ships enforced on first run: agent-lineage writes to agent or Guardrails control files (Block); honeytoken use (Block); reads of credential stores and private keys (Ask); recursive delete outside the workspace (Ask); bypass or hook-disabling flags (Block). Admission to Baseline requires zero hits on the goodlog corpus and full coverage in the efficacy harness, replacing age-based promotion. The trifecta gate ships in Watch until its prompt rate is measured."

### F6. Compile-down has no soundness direction (major; D-12)

"Lossy" can mean stricter or looser. A native deny generated from an Ask rule cannot be lifted by our grant, because Claude Code hooks cannot override deny or ask rules. A generated native ask double-prompts and violates D-31. Leash shows transpiled Cedar drifting to most-specific-wins. Managed settings are also written by the customer's MDM and by rival products.

Evidence: 20 section 5 and verifier row 8; 36 Surprises (hourly refresh, fails open on first fetch); 15 Implications (drop-in `managed-settings.d/50-aidr.json`).

Amendment: "Only unconditional locked forbids over path classes, host classes and MCP server identity compile to native deny, plus hardening flags (managed hooks only, bypass mode off, sandbox on). No command-string rules and no native ask. Output is a drop-in fragment or an MDM artefact, never an overwrite. Each target has a per-agent-version conformance test on a real install proving native denials are a subset of Cedar always-denies. M1 targets Claude Code and Codex; the other six follow."

### F7. The fact vocabulary is the real policy language, and it is compiled code (major; D-08, D-09, D-10)

Cedar has no regex, no path type and one wildcard that crosses separators. Every glob, command shape and MCP argument test therefore lives in an analyser, and D-09 makes analysers Rust. A new policy idea then needs a binary release and a schema change, against P7. The MCP question is also open: brief 20 generates one action per tool (a per-device schema that defeats a published schema and signed bundles), while the vocabulary fixes `mcp.call`.

Evidence: 20 section 1 (gaps), Weak points (expressiveness), Layer 0; 02 section 5 (BeyondTrust offers input globs such as `*rm -rf*`, which users will expect).

Amendment, new D-08a: "The schema is fixed: `mcp.call` on an `McpTool` resource. Analysers are engines; their vocabularies are signed pack data: path pattern sets, host sets, command classes over canonical argv, MCP argument extractors keyed by tool-manifest hash. Results reach Cedar as open sets (`resource.classes`, `context.facts`). Removing a pattern from a protective class is a widening. `like` is limited to short identifier fields."

### F8. "Ambiguous parses deny" will not survive real workloads (major, risky; D-10)

Agent shell commands routinely contain substitutions, variables, `bash -c` and heredocs. The one guard that held in GuardFall escalates on ambiguity rather than denying, and even it had gaps. Blanket deny makes the canonicaliser the main source of blocks.

Evidence: 09 section 6 and verifier (Continue 0/21 is "tokenise-canonicalise-escalate", default GUI only).

Amendment: "Ambiguity is a fact (`exec.opaque`). At AL3 and AL4 the concrete exec, open and connect are judged at the OS; at AL2 an opaque command in a fail-closed class is `STEP_UP`. Only parser failure denies." Settle with spike S3.

### F9. Two stateful engines, and Sigma does not know agents (major, over-built; D-09)

The session monitor (D-08) and rsigma correlation both keep windowed per-session state. Sigma has no agent log source and no ATLAS namespace; its correlations cannot express rarity or lineage. rsigma is nine months old with 26 minor releases and one author on 2,100 of about 2,400 commits. It takes JSON events, not protobuf.

Evidence: 11 Findings and Weak points (bus factor); g06 section 3; 36 Implications (first-seen and rarity baselines, denial ledger).

Amendment: "Sigma is the exchange and alerting format only. `grd-detect` owns a trait and conformance vectors; rsigma is one vendored implementation with a pinned fork. We publish a `product: guardrails` log-source taxonomy and a pySigma pipeline for the OCSF export. Enforcement-relevant sequences live only in the session monitor. Rules for rung L0 are written separately against generic Sigma process and network categories."

### F10. The "one representation" is not Cedar text (minor; D-11, D-07)

Posture is not expressible in Cedar, Watch needs a shadow evaluation, and neither `MODIFY` nor `DEFER` has a stated Cedar source. A casual user edits modes and lists, never rules.

Evidence: 33 Implications (Simple is "packs as switches"); 20 Layer 2.

Amendment: "The canonical object is a pack manifest: Cedar policies, typed parameters (lists), posture. Simple view edits posture and lists only; the sentence builder emits a named Cedar subset with round-trip tests. Posture is compiled into two signed sets, enforced and shadow. A normative table derives each of the five verdicts from the determining policies' annotations."

## Spikes

| # | Question | Method | Pass |
|---|---|---|---|
| S1 | Is Cedar fast enough end to end? | Build the schema; measure request and entity construction plus evaluation at 100 and 1,000 policies on a low-end x64 and ARM64 laptop | p99 under 1 ms at 1,000 including construction |
| S2 | Can SymCC gate anything? | `check_implies` over every request environment for a 300-policy layered set with slots and host lists | Under 60 s, zero unknowns; else SymCC is advisory only |
| S3 | How often is a command opaque, and how noisy is the trifecta gate? | Run a canonicaliser prototype and the gate over 10,000 or more recorded tool calls from the development fleet, plus GuardFall A to E | Under 2% benign opaque; every GuardFall case resolved or flagged; gate under the prompt budget |
| S4 | Do labels race? | Deterministic simulation interleaving hook, proxy and delayed OS events with parallel tool calls; rsigma with explicit timestamps and state-cap flooding | No decision on a stale sync label; every late label yields a finding; receipts replay identically |

## Agreed

- Cedar over Rego or CEL as the single enforced language.
- Dogwood as lowering front end only.
- Forbid-unless-evidence with annotations as hints: the failure direction is right once F1 is fixed.
- The AARM five as the verdict vocabulary.
- YARA-X for content; CEL confined to manifests.
- No DRL or ELv2 content in the default pack.
- Vendoring rsigma over writing a matcher: `rsigma-eval` has no async runtime and accepts explicit timestamps.
- Replay before Ask or Block; reference models for our normalisers (not for Cedar, which has a Lean model).
