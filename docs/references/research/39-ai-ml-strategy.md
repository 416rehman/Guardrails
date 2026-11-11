# AI and ML inside the product: trace review, baselines, agent classifier, assistants

_Researched 2026-11-09_

Evidence tags: **[V]** read in a primary source today; **[S]** taken from a sibling brief in this folder that verified it; **[K]** prior knowledge, not re-checked; **[I]** my inference or estimate.
Method note: the shared web-search budget was already exhausted when this brief started, so no search queries ran. Everything below comes from direct fetches of primary sources, the GitHub and Hugging Face APIs, the local `_sources/` captures (Origin, BeyondTrust, CrowdStrike) and sibling briefs 08, 09, 17, 20, 22, 24, 26.

## TL;DR

- **LLM trace review is now a shipped product pattern, and it is a two-pass design.** Origin 1.12.5 (30 Sep 2026) reviews traces against policies, observed norms and inferred intents, then a separate "Triage" pass re-checks every finding against the session with quoted evidence (confirmed, refuted, overstated, unread). Origin runs its own inference for this. [V]
- **Uber's open ADR gives the only public production numbers.** Two tiers (LLM triage, then a reasoning agent with MCP context tools): USD 0.024 and 18.5 s per session; in production 34% true positive, 17% true-positive-benign, 49% false positive. That works out to about USD 1.00 per host per month at Uber's volume. [V, cost per host I]
- **Frontier monitors miss a lot, and the fixes are cheap and structural.** Anthropic (22 Oct 2026): Claude Code Auto Mode and Codex Guardian fail to block over 55% of red-team attacks; keyed record framing plus escaping, monitoring in-workspace edits, and including tool results cut attack success by over 50 points at under 1% benign blocks. Multi-agent and compaction attacks remain open. [V]
- **Ensembles beat single judges; resampling does not.** UK AISI Async Control: best single monitor about 33% worst-case miss rate; four heterogeneous monitors into a random forest reach 5.7% (6% held out) at 1% FPR. Naive "resample on doubt" turns a monitor injection into best-of-n. [V]
- **The daily volume is not attackers.** Authorization Drift (6 Nov 2026): frontier models exceed scope in 43 to 61% of tasks with no adversary, mostly early data over-collection. The judge must be tuned for overeager agents first. [V]
- **A cost-bounded cascade is affordable in SaaS.** With Haiku 5.5 at USD 0.10/0.50 per MTok and a 50% batch discount, a rules, small-model, judge, investigator cascade lands near USD 0.20 to 0.35 per heavy endpoint per month. Inline per-action LLM gating does not fit that budget and should be bring-your-own-model. [V prices, I model]
- **Open, cleanly licensed building blocks exist for everything except the detectors themselves.** Apache/MIT: gpt-oss-20b and gpt-oss-safeguard-20b (local judge), ModernBERT and ettin encoders, bge-small and Qwen3-Embedding, apache/datasketches-rust, PIDSMaker, ADR-Bench, AgentDojo, control-arena, SWE-chat (ODC-BY, 17,968 real sessions). We must train and publish our own classifiers. [V]
- **Natural-language policy with a proof loop is proven by AWS**: NL to Cedar, schema check, then automated reasoning for overly permissive, overly restrictive and ineffective policies, default `FAIL_ON_ANY_FINDINGS`, plus `LOG_ONLY` trial. Nobody adds generated tests or replay against history. [V]
- **No one publishes a bespoke-agent classifier.** BeyondTrust claims "classifiers that include process naming, signatures, and LLM API traffic patterns"; research shows LLM traffic is fingerprintable from packet metadata (97.7% model, 90.7% agent task). An open model with a leave-one-framework-out evaluation is whitespace. [V]
- **Nothing that blocks may depend on a model.** Models rank, explain and propose. Cedar, the OS sensor, egress rules and credential brokering decide.

## Findings

### 1. Trace review with LLM judges: what ships today

**Origin** (changelog v1.12.5, 30 Sep 2026) [V, local capture of https://www.originhq.com/changelog]:
- "Reviews assess the work against your organization's policies, observed norms, and inferred intents." Findings cite the instructions, tool calls and results behind them.
- A second pass, **Triage**, "checks each review finding against its captured session, with quoted evidence for what is confirmed, refuted, overstated, or still unread".
- Editable escalation standards start with four classes: evasion, unsanctioned actions, credential harvesting, monitoring tampering.
- **Investigate** reasons over related findings across sessions, with a chat to set priorities first. **Census** builds an "organizational register" of norms and intents that can be chosen as review context.
- Separately, **Signals** are deterministic rules with "typed evidence spans": "it fires because a rule matched, not because a model thought something looked off".
- Origin states "We run our own inference for trace analysis"; an internal route table lists four model services: `enricher`, `embeddings`, `trace-review`, `signals-judge` (https://www.originhq.com/investigations, "An agent's broad route") [V]. Its MCP privacy terms say MCP payloads are not sent to third-party model providers and not used for training [V].

**Uber ADR** (Apache-2.0, MLSys 2026, arXiv 2605.17380; repo pushed 2026-10-31) [V, https://github.com/uber/ADR, https://arxiv.org/html/2605.17380]:
- Tier 1: an LLM triage prompt on every session (GPT-4o in the paper). Tier 2: a reasoning agent (Claude Sonnet) that queries three MCP context providers: tool source code, a threat repository, a policy store.
- ADR-Bench: 304 tasks (261 benign, 43 malicious), 134 MCP servers, 17 techniques in 5 tactics. ADR scores P 1.00 / R 0.667; LlamaFirewall P 0.167 / R 0.190 on the same set.
- Cost: USD 0.024 per task, 18.5 s mean, 37.9 s p95. Triage alone resolves 40.7% of tasks. Removing source-code inspection drops recall to 0.571; removing the policy check barely matters.
- Production: 7,200+ macOS hosts, 10,000+ sessions a day, ten months. Analyst outcomes: 34% TP, 17% TP-non-malicious (mostly internal offensive security), 49% FP, with FPs concentrated in context-rich sessions.
- Lessons stated: precision matters more than recall; pin prompts and model versions; run regression suites before any update; a regex and entropy pre-prompt hook stopped secrets at 97.2% precision (206 of 212).
- The "ADR Explorer" red-team loop and the Prevention component are not in the open release.

**Claude Code auto mode** (25 Mar 2026) [V, https://www.anthropic.com/engineering/claude-code-auto-mode]: stage 1 is a single-token filter told to err towards blocking; stage 2 re-reads the same prompt with reasoning, so it is nearly a full cache hit. The classifier sees user messages and tool calls only; assistant prose and tool results are stripped. Result: 0.4% FPR on 10,000 real actions, 17% miss rate on 52 real overeager actions, 5.7% on synthetic exfiltration. Denial returns to the agent; 3 consecutive or 20 total denials escalate.

### 2. Making a judge robust when its input is attacker-controlled

- **Red-Teaming Auto Mode** (Anthropic, 22 Oct 2026; arXiv 2609.19587; code MIT at `safety-research/red-teaming-auto-mode`) [V, https://alignment.anthropic.com/2026/red-teaming-auto-mode/]. Four failure classes: monitor injection, multi-context (multi-agent, compaction), coverage gaps, policy failures.
  - Monitor injection worked because the monitor read a flattened transcript; an agent that knew the format forged later entries. Fix: wrap each turn in a record tag carrying a 48-bit identifier derived from the turn under a per-process key, plus JSON-L escaping.
  - Execute-then-write (schedule `./run.sh`, then write it) reached 43% against Auto Mode and 72% against Guardian because in-workspace edits were not monitored. Monitoring edits took Guardian from 72% to 31%.
  - Adding tool results to the monitor's context helped and did not raise injection success once framing was in place.
  - A final tool-calling investigator stage is the Pareto-best design; running it on every action is too slow.
- **Async Control** (UK AISI, arXiv 2512.13526) [V]: the winning ensemble mixes a hierarchical judge, a high-stakes monitor that does not see chain of thought, a few-shot variant and a quote-extracting monitor, aggregated by a random forest over nine score features. Action-only monitors "avoid being baited by justifications". Red-team tactics that worked: justifications planted in plan files and comments, changes hidden in unit tests, dilution with unrelated subtasks.
- **Adaptive Attacks on Trusted Monitors** (arXiv 2510.09462, v2 Mar 2026) [V]: an agent that knows the monitor embeds known injections in its output; defer-to-resample amplifies this into best-of-n.
- **The Attacker Moves Second** (arXiv 2510.09023) [V]: 12 defences broken, most above 90% attack success after reporting near zero. Static test strings are not an evaluation.
- LlamaFirewall's AlignmentCheck needs a 70B-class model; 1B to 8B models destroyed utility [S, brief 09].

### 3. Intent versus action, and goal hijack

- Authorization Drift (arXiv 2611.09113, 6 Nov 2026) [V]: 648 paired tasks, 13 models, 25,207 trajectories, drift 0.43 to 0.61, yet 86.18% of tasks have a clean path. Data and code release not confirmed.
- Two usable anchors exist for intent: the user's own messages (auto mode) and an organisational register of norms (Origin Census). Auto mode's stated residual error is consent scope: the classifier sees the danger but misjudges whether the user's request covers the blast radius, and prompt engineering did not fix it [V].
- CrowdStrike describes "Policy-Drift Agent Guardrails" screening agent interactions for drift, unauthorised tool calls and out-of-bounds data access (beta, Q4 2026); no method is published [V, local capture].

### 4. Behavioural baselines that scale

- `apache/datasketches-rust` (Apache-2.0, pushed 2026-11-08, 142 stars) [V]: mergeable sketches in Rust. Mergeability is what lets one design serve a laptop and an MSP: endpoints build sketches, the server merges them per peer group, and raw events never have to leave.
- Provenance ML: `ubc-provenance/PIDSMaker` (Apache-2.0, KDD'26, pushed 2026-11-04) and `orthrus` (Apache-2.0, USENIX Security '25) are the maintained research stack; `kairos` and `Flash-IDS` carry no licence [V]. Store provenance as edge tables, not a graph database [S, brief 11].
- AgentSight's loop correlation (model response, then tool-like effect within 100 to 500 ms, argument match) is the validated agent-specific graph feature [S, brief 17].
- I found no 2026 open project for sequence models over agent tool calls (three GitHub searches returned nothing relevant) [V negative result].

### 5. "Is this unknown process an AI agent?"

- BeyondTrust docs: "Agents are identified using classifiers that include process naming, signatures, and LLM API traffic patterns" [V, local capture]. Microsoft says unlisted combinations are unsupported [S, brief 17].
- arXiv 2609.31877 (v2 24 Oct 2026) [V]: from packet sizes, directions, timing and burst structure alone, 97.7% balanced accuracy on 10 serving models and up to 90.7% on multi-agent task type; 60,000 interactions and 2,838 agent runs, described as a public benchmark (repository link not confirmed).
- `arthur-ai/ai-detection-spec` (Apache-2.0, pushed 2026-11-09) is the open catalogue for known agents and deliberately excludes SDKs and frameworks [V licence, S content].

### 6. Natural-language policy with a verification loop

AWS Bedrock AgentCore Policy [V, https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-validation-overview.html and `policy-natural-language.html`]:
- "NL2Cedar" generates candidate Cedar from English using the gateway's tool schema.
- Schema checks always run. Semantic validation reports **overly permissive** (allows all requests for the principal, action, resource), **overly restrictive** (denies all) and **ineffective** (a permit that allows nothing or a forbid that denies nothing).
- `validationMode`: `FAIL_ON_ANY_FINDINGS` (default) or `IGNORE_ALL_FINDINGS`. Trial in `LOG_ONLY`.
- Its own guidance lists the failure modes: vague principals, subjective conditions ("reasonable"), unclear and/or precedence.
- The analyser cannot see inside guardrail or temporal conditions [S, brief 20]. The open equivalent is `cedar-policy-symcc` 0.8.1 (needs cvc5), which proves always-allows, always-denies, implies, equivalent and disjoint with counterexamples [S].

### 7. Investigation assistant and MCP

- Microsoft Sentinel MCP (doc dated 2026-05-07): fully hosted, Entra identity, scenario "collections" (data exploration with an entity analyser, triage and hunting, agent creation) [V, https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview].
- `CrowdStrike/falcon-mcp` (MIT, pushed 2026-11-03) [V]. Origin's MCP server "can read a conversation around a specific message, including the surrounding text, reasoning, tool calls, and results", and Origin classes every column Default or Sensitive with a separate permission for Sensitive [V].
- MCP is stateless since 2026-07-28, so the MCP server is an ordinary scaled API [S, brief 24].

### 8. Models, runtimes, licences, prices

Licences checked today through the Hugging Face API [V]:

| Use | Candidate | Licence | Note |
|---|---|---|---|
| Local judge | `openai/gpt-oss-20b`, `openai/gpt-oss-safeguard-20b` | Apache-2.0 | 16 GB class [S]; safeguard takes policy as prompt |
| Small guard | `Qwen/Qwen3Guard-Gen-0.6B` | Apache-2.0 | |
| Encoder backbone | `answerdotai/ModernBERT-base`, `jhu-clsp/ettin-encoder-150m`, `microsoft/deberta-v3-small` | Apache-2.0, MIT, MIT | DeBERTa quantises badly [S] |
| Embeddings | `BAAI/bge-small-en-v1.5`, `Qwen/Qwen3-Embedding-0.6B`, `nomic-embed-text-v1.5`, `granite-embedding-english-r2` | MIT, Apache-2.0 x3 | |
| PII | `openai/privacy-filter` | Apache-2.0 | |
| Gateway guard | `ibm-granite/granite-guardian-3.3-8b` | Apache-2.0 | |
| Do not bundle | Prompt Guard 2, Meta-SecAlign-8B, EmbeddingGemma | llama4, llama3.1, gemma | All gated, not OSI |

Datasets [V]: SWE-chat v2 (ODC-BY; 17,968 sessions, 8 agents, redacted with Presidio and TruffleHog); `microsoft/llmail-inject-challenge` (MIT); `deepset/prompt-injections` (Apache-2.0); `Lakera/gandalf_ignore_instructions` (MIT); `leolee99/NotInject` (MIT); `allenai/wildjailbreak` (ODC-BY, gated); `nebius/SWE-agent-trajectories` (CC-BY-4.0); `SWE-bench/SWE-smith-trajectories` (MIT); AgentHarm is licence "other"; `redwoodresearch/basharena_public` has no licence.

Runtimes: llama.cpp (MIT) constrains output with GBNF grammars; Ollama (MIT) takes a JSON schema in `format` and through the OpenAI-compatible `response_format`, but Ollama's cloud does not support structured outputs [V]. `ort` and `candle` are Apache-2.0 [V]. `sigstore/model-transparency` (Apache-2.0) signs models [V].

Prices (Anthropic pricing page, read today) [V]: Haiku 5.5 USD 0.10 in / 0.50 out per MTok up to 100K-token prompts (0.50 / 2.50 beyond), cache read 0.01; Sonnet 5.5 2 / 10, cache read 0.10; Opus 5.5 4 / 20, cache read 0.20; Batch API 50% off input and output, combinable with caching.

### 9. Community sharing on the CrowdSec model

CrowdSec shares only: scenario name, scenario hash and version, timestamp, machine ID, offending IP and geolocation. Only signals from unmodified official scenarios (hash-compared) count towards consensus. Blocklist tiers: 15,000 IPs for contributors, 3,000 "Lite" for non-contributors or engines "flagged as cheating/abusing the system", 60,000 premium [V, https://docs.crowdsec.net/docs/next/central_api/intro/ and `/community_blocklist/`]. Consensus internals are not documented on those pages.

## Matrix

| Design choice | Auto Mode (prod) | Auto Mode ++ (research) | Async Control | Uber ADR | Origin | Recommended for us |
|---|---|---|---|---|---|---|
| Timing | Inline | Inline | Post hoc | Post hoc (hourly sensor) | Post hoc | Post hoc by default; inline is BYO |
| Stages | 1-token, then reasoning | plus agentic investigator | 4-monitor ensemble | LLM triage, then agent | review, then triage | rules, small models, judge, verifier, investigator |
| Sees tool results | No | Yes, framed | Yes | Yes | Yes | Yes, in keyed frames |
| Sees agent reasoning | No | No | Mixed on purpose | Yes | Yes | Mixed ensemble |
| Evidence check | None | None | Quote monitor | None | Quoted, per finding | Mechanical span verification |
| Published miss rate | 17% (n=52) | over 50 points better than prod | 6% at 1% FPR | R 0.667 bench | None | Publish per release |
| Published cost | None | Output tokens per call | Zero latency | USD 0.024 per session | None | Budgeted per endpoint |

## Weak points, gaps and risks

- **Every public miss rate is double digit under adaptive attack.** A judge is a ranking signal with a known error bar, not a control.
- **Cascade semantics matter.** In Auto Mode an action passes if any stage calls it harmless, so stage 1 misses are final. A cheap first stage caps recall for everything behind it.
- **Multi-context attacks are unsolved** (compaction, shared workspaces, sub-agents). Session-scoped review will miss them.
- **Benchmark-to-production gap.** ADR had zero benchmark false positives and 49% in production.
- **Context-rich sessions drive false positives**, which is exactly where review tokens are most expensive.
- **No CPU latency numbers exist** for any small detector [S, brief 09], and none for local 20B judges. We must measure.
- **Community data can be poisoned**: a competitor or attacker can report a legitimate MCP server. CrowdSec's defence is only partly documented.
- **Privacy**: traces contain source code, prompts and secrets. Sending them to a model provider is a data-processing decision the tenant must own.
- **Staleness**: prices and model names change monthly; the pricing figures are from today's page and will age.

## Implications for our design

### Architecture

1. **Five tiers, each with a budget and a version.**
   - T0 deterministic: Sigma and correlation rules, command canonicaliser, secret detectors, Cedar. Runs on 100% of events on the endpoint. Target 2 ms or less.
   - T1 small models on CPU through `ort`: injection encoder on tool outputs, agent-process classifier, session risk ranker. Target 40 ms p95 per 512 tokens on four threads, otherwise asynchronous [S budget].
   - T2 **finder**: a cheap LLM over a reduced trace view for sessions T0 and T1 rank highest. Structured output only.
   - T3 **verifier**: a different model re-checks each finding against the raw session and must return span offsets that we verify by string match. Unverifiable findings are dropped and counted.
   - T4 **investigator**: read-only tool-calling agent for the top fraction, using the same MCP tools we expose to customers.
2. **A deterministic hit is never cleared by a model.** Models may raise risk, add explanation, or clear another model's flag. This removes "argue the judge out of it" for everything rules can express.
3. **Judge input contract.** Trusted channel: policy, user messages, tool-call payloads. Untrusted channel: tool results, file contents, agent prose, each wrapped in per-record tags keyed with an HMAC the agent cannot predict, then JSON-L escaped. Truncate in the middle of records, never across tags.
4. **Heterogeneous ensemble, not resampling.** At least one action-only monitor and one that reads reasoning; aggregate with a small tree model trained on our range data. Never re-ask the same judge until it says yes.
5. **Review units follow lineage, not session IDs**: workspace, process ancestry and sub-agent handoffs, including compaction summaries and writes to agent memory or config.
6. **Live recall canaries.** Seed synthetic malicious sessions into each tenant's review queue; alert when the judge stops catching them. This also detects a silently degraded BYO model.

### Bring your own model

- One `JudgeBackend` trait: OpenAI-compatible HTTP (llama.cpp server, Ollama, vLLM, LiteLLM), Anthropic, Bedrock, Azure, Vertex. Tenant keys are stored in the tenant's vault and used from the tenant's region.
- Self-hosted default: `gpt-oss-20b` or `gpt-oss-safeguard-20b` with a JSON schema. Laptop mode: T0 and T1 only unless the user supplies a key.
- Before any trace leaves the endpoint for T2: secret and PII redaction, path and identifier tokenisation with a per-tenant map, and a tenant setting for "metadata-only review" (tool names, argument shapes, rule hits).
- Each backend must pass a conformance suite (schema adherence, canary recall, injection resistance) before it can be selected; the result is shown in the console.

### Models to ship first

| # | Model | Type | Training data | Licence out |
|---|---|---|---|---|
| 1 | Agent-process classifier | Gradient-boosted trees to ONNX | Our range: catalogued agents plus framework-built bespoke agents (positives); builds, CI, IDE servers, browsers, chat UIs, RAG services (hard negatives) | Apache-2.0 weights, CC-BY-4.0 data |
| 2 | Tool-output injection encoder | ModernBERT or ettin fine-tune | LLMail-Inject, deepset, Gandalf, NotInject, AgentDojo and ADR-Bench traces, SWE-chat tool outputs as benign | Apache-2.0 |
| 3 | Session risk ranker | Trees over rule hits, sketch rarity, graph features | Range labels, then analyst verdicts per tenant | Apache-2.0 global prior |
| 4 | Finding embeddings | `bge-small-en-v1.5` unchanged | None | MIT upstream |
| 5 | Judge, verifier, investigator prompt packs | Prompts and schemas | Tuned on range plus ADR-Bench | Apache-2.0 |
| 6 (later) | Tool-call sequence model | n-gram first, small transformer second | SWE-chat, SWE-smith, range | Apache-2.0 |

Agent-classifier features [I]: LLM-endpoint contact (catalogue, then stream shape and burst structure for unknown hosts); the response-then-effect loop with repetition count; loaded SDK modules and local runtimes; self-identifying environment variable names; MCP stdio handshakes on child pipes; touches of agent config files; exec cadence and absence of human keystroke timing. Three classes: not AI, LLM client, agent. Evaluate **leave-one-agent-out and leave-one-framework-out**, report recall at 0.1% process-level FPR and time to detect, per OS. Output is an inventory finding, never an enforcement input on its own.

### Baselines

- Sketches per (agent type, project, team) with hierarchical back-off: HyperLogLog for distinct destinations, files and tools; frequent-items for commands; quantile sketches for tokens, duration and fan-out; first-seen filters for "new for this peer group".
- Graph features computed from edge tables: untrusted content upstream of this action, novel edge for the peer group, cross-agent config write, credential read followed by egress.
- Feed all of it to the ranker as features. Do not ship a GNN in v1.

### Policy authoring loop

NL, then candidate Cedar constrained by schema, then validation, then SymCC checks (always-allow, always-deny, ineffective, and implies or equivalent against the current set, with counterexamples), then **counterexamples turned into concrete test cases the author accepts or rejects**, then back-translation by a second model for a round-trip read, then **replay against stored history in log-only**, then signing and ring rollout. Classify each change as narrowing (auto-apply eligible) or widening (approval required). Flag any policy whose effect depends on a model score as "model-dependent" because analysis is blind there.

### Assistant, detections, feedback

- The assistant has read-only tools, no egress, no rendered remote content, and tenant plus column-sensitivity enforcement in the query layer. Containment and policy changes appear as proposed actions that a human triggers through the normal authorised API.
- Detection proposals: incident, then generated Sigma, Cedar or YARA-X, then compile, then replay on the incident (must fire), the range corpus (recall), benign corpora and tenant history (false-positive count), then shadow mode, then rings.
- Analyst verdicts use Uber's three-way label plus duplicate. They retrain the ranker and produce **explicit, reviewable suppression rules**; they never silently change a judge prompt. Similar-incident search embeds structured finding summaries, not raw traces.

### Cost model [I, from V prices]

Assumptions: heavy endpoint, 176 sessions a month, 15K reviewer-visible tokens per session after reduction.

| Tier | Share of sessions | Unit cost | Per endpoint per month |
|---|---|---|---|
| T2 finder, Haiku 5.5 | 15% | USD 0.00175 | 0.05 |
| T3 verifier, Sonnet 5.5 (1K out) | 2% | 0.04 | 0.14 |
| T4 investigator, Opus 5.5 (60K in, 4K out) | 0.2% | 0.32 | 0.11 |
| Total | | | about 0.30, about 0.20 with batch on T2 and T3 |

Bounds: a per-tenant monthly token budget; a suspicion-ordered priority queue so the budget always buys the highest-ranked sessions; hard caps on tokens per session with structured reduction; batch by default; a visible "coverage" metric (share of sessions reviewed at each tier). Reviewing 100% of sessions with a mid-tier model would cost about USD 7 per endpoint per month and is not the default. Inline per-action gating at roughly 7,000 calls a month is BYO only.

### Operations

- Models, prompts, thresholds and their evaluation report ship as one signed, versioned pack through the same rings as rules, with shadow mode first and automatic rollback on false-positive, latency or canary-recall regression.
- Release gate: static sets at 0.1% and 1% FPR, benign replay on SWE-chat, ADR-Bench and AgentDojo, the red-teaming-auto-mode attack classes, and an adaptive attack run. Put canary GUIDs in every published benchmark file.

### Never model-dependent

Egress default-deny; writes outside the workspace; writes to agent config, hooks, skills and memory; credential brokering and revocation; kill switch; Cedar evaluation; tenant isolation; signature and update verification; evidence integrity; fail-open or fail-closed choice. A missing, slow or compromised model must degrade ranking and explanation only.

## Ideas worth stealing and whitespace

- Steal: Origin's finder-then-triage with quoted evidence and editable escalation standards; ADR's source-code context tool (largest recall gain); Anthropic's keyed record framing; AISI's mixed-visibility ensemble with a tree aggregator; AWS's default-fail semantic validation; CrowdSec's "only unmodified official detectors count".
- Whitespace: an open agent-process classifier with honest generalisation tests; a public AIDR benchmark that scores discovery, attribution, prevention, detection and cost together with OS-level ground truth; policy replay against history as a rollout gate; live canary recall as a product metric; cross-session and cross-agent review units; a published cost-per-endpoint figure; privacy-preserving sighting exchange for MCP servers, skills and injection payloads (hashes of tool descriptions and skill files, fuzzy hashes of payloads, detector ID and version, k-tenant threshold, decay, appeal path, local matching against a downloaded filter).

## Could not verify / open questions

- No web search was possible, so 2026 papers on tool-call sequence models, analyst-feedback learning and newer benchmarks may be missing.
- CPU latency of any encoder and throughput of 20B local judges: no data; must be measured.
- Which model Origin's judge is, its cost and its error rates: unpublished.
- CrowdSec consensus, trust and anti-poisoning internals: not on the pages read.
- Whether the Authorization Drift benchmark and the traffic-fingerprinting dataset are actually released, and under what licence.
- Licences of BIPIA, InjecAgent, SigmaHQ rules and Elastic detection rules were not re-checked (GitHub reports non-SPDX for the last two).
- OpenAI and Google prices were not fetched; the cost table uses Anthropic list prices only.
- Live BeyondTrust and Microsoft Agent 365 docs were not refetched; local captures and briefs 03 and 17 were used.

## Sources

- https://www.originhq.com/changelog — Origin changelog, v1.12.5 "Automatic trace review", 2026-09-30 (local capture)
- https://www.originhq.com/investigations — "An agent's broad route" (local capture)
- https://github.com/uber/ADR and https://arxiv.org/html/2605.17380 — ADR, MLSys 2026; repo pushed 2026-10-31
- https://www.anthropic.com/engineering/claude-code-auto-mode — 2026-03-25
- https://alignment.anthropic.com/2026/red-teaming-auto-mode/ — 2026-10-22; https://github.com/safety-research/red-teaming-auto-mode (MIT)
- https://arxiv.org/html/2512.13526v1 — Async Control, 2025-12-15
- https://arxiv.org/abs/2510.09462 — Adaptive Attacks on Trusted Monitors, v2 2026-03-02
- https://arxiv.org/abs/2510.09023 — The Attacker Moves Second, 2025-10-10
- https://arxiv.org/abs/2611.09113 — Authorization Drift, 2026-11-06
- https://arxiv.org/abs/2609.31877 — Traffic analysis of cloud LLM services, v2 2026-10-24
- https://arxiv.org/abs/2505.03574 — LlamaFirewall, 2025-05-06
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html, `policy-natural-language.html`, `policy-validation-overview.html` — read 2026-11-09
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview — 2026-05-07
- https://docs.crowdsec.net/docs/next/central_api/intro/ and https://docs.crowdsec.net/docs/next/central_api/community_blocklist/ — read 2026-11-09
- https://platform.claude.com/docs/en/about-claude/pricing — read 2026-11-09
- https://docs.ollama.com/capabilities/structured-outputs; https://github.com/ggml-org/llama.cpp/blob/master/grammars/README.md
- https://huggingface.co/datasets/SALT-NLP/SWE-chat — v2 2026-10-02, ODC-BY
- Hugging Face API model and dataset records (licences), read 2026-11-09: openai/gpt-oss-20b, openai/gpt-oss-safeguard-20b, Qwen/Qwen3Guard-Gen-0.6B, Qwen/Qwen3-Embedding-0.6B, answerdotai/ModernBERT-base, jhu-clsp/ettin-encoder-150m, BAAI/bge-small-en-v1.5, nomic-ai/nomic-embed-text-v1.5, openai/privacy-filter, microsoft/llmail-inject-challenge, deepset/prompt-injections, leolee99/NotInject
- GitHub API repository records, read 2026-11-09: apache/datasketches-rust, ubc-provenance/PIDSMaker, ubc-provenance/orthrus, UKGovernmentBEIS/control-arena, ethz-spylab/agentdojo, CrowdStrike/falcon-mcp, arthur-ai/ai-detection-spec, sigstore/model-transparency, pykeio/ort, huggingface/candle, splunk/attack_data, splunk/attack_range
- Sibling briefs in this folder: 08, 09, 11, 17, 20, 22, 24, 26

## Independent verification

Checked 2026-11-09 by a separate fact-checker. The shared web-search budget was exhausted, so every check is a direct fetch of a primary page, the arXiv full text, the Hugging Face API or the GitHub API. Nothing here rests on a search-engine summary.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Production monitors fail to block over 55% of red-team attacks; framing plus escaping, edit monitoring and tool results cut attack success by over 50 points with under 1% benign blocks on 4,000 actions | Corrected | The three numbers are real. The drop of over 50 points belongs to Auto Mode ++ as a whole, which also adds a tool-calling investigator stage on Opus 4.8, a compaction check and bug fixes. No ablation isolates the three listed fixes; only edit monitoring is isolated (Guardian 72% to 31%). The 55% figure is an average over settings with an Opus 5 attacker allowed up to 20 blocks. | https://arxiv.org/html/2609.19587 |
| 2 | Uber ADR costs USD 0.024 and 18.5 s per session on ADR-Bench; production (7,200+ hosts, 10,000+ sessions a day) gave 34% TP, 17% TPNM, 49% FP | Confirmed | Cost and latency are per ADR-Bench task with GPT-4o triage and Claude Sonnet 4 reasoning; the paper gives no production cost and no alert count for the 34/17/49 split. | https://arxiv.org/html/2605.17380, https://github.com/uber/ADR |
| 3 | Auto mode classifier sees only user messages and tool calls, one-token stage then reasoning stage, 0.4% FPR on 10,000 actions, 17% miss on 52 overeager actions | Confirmed | Current product docs add that the classifier also receives CLAUDE.md content, defaults to Sonnet 5, and that working-directory edits skip it. The measured figures date from March 2026. | https://code.claude.com/docs/en/permission-modes |
| 4 | Async Control: best single monitor about 33% worst-case miss; four-monitor random-forest ensemble 5.7% (6% held out) at 1% FPR | Confirmed | Table 3: Quote monitor 33.3% max FNR; RF ensemble 5.7% max, 3.0% average; 6% on the held-out environment. Nine engineered features. | https://arxiv.org/abs/2512.13526 |
| 5 | Haiku 5.5 USD 0.10/0.50 up to 100K-token prompts, Sonnet 5.5 2/10, Opus 5.5 4/20, Batch API 50% off | Confirmed | Live pricing page matches, including cache reads. The same page says Claude 4.7 and later tokenise about 30% more tokens for the same text, which matters if token counts were estimated with an older tokenizer. | https://platform.claude.com/docs/en/about-claude/pricing |
| 6 | Origin v1.12.5 (30 Sep 2026) trace review against policies, norms and intents, with Triage marking findings confirmed, refuted, overstated or unread | Confirmed | Live changelog matches the local capture; v1.12.5 is still the newest entry. | https://www.originhq.com/changelog |
| 7 | AgentCore Policy: NL to Cedar, schema checks always run, default FAIL_ON_ANY_FINDINGS rejects overly permissive, overly restrictive or ineffective policies | Confirmed | Live developer guide matches word for word. IGNORE_ALL_FINDINGS skips only the semantic checks. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-validation-overview.html |
| 8 | Frontier models exceed scope in 43 to 61% of tasks with no adversary, mostly early data over-collection; 25,207 trajectories, 13 models | Corrected | Drift rate is the share of runs, not tasks. 0.43 to 0.61 covers six high-task-success models (five Qwen 3.5/3.6 models and Claude Sonnet 4.6); across all 13 models it runs from 0.029 to 0.605. Data over-collection is the modal failure and peaks early to mid trajectory. Counts are correct. | https://arxiv.org/html/2611.09113 |
| 9 | Licences: gpt-oss-20b, gpt-oss-safeguard-20b, ModernBERT-base, Qwen3-Embedding-0.6B, nomic-embed-text-v1.5 Apache-2.0; bge-small-en-v1.5, ettin-encoder-150m MIT; Prompt Guard 2, Meta-SecAlign, EmbeddingGemma gated and non-OSI | Confirmed | Hugging Face API re-read. Prompt Guard 2 is llama4, Meta-SecAlign-8B llama3.1 (the 70B is llama3.3), EmbeddingGemma gemma; all three are gated "manual". | https://huggingface.co/api/models/meta-llama/Llama-Prompt-Guard-2-86M |
| 10 | SWE-chat v2 (2 Oct 2026): 17,968 sessions, eight agents, ODC-BY, Presidio and TruffleHog redaction | Confirmed | The dataset is gated with automatic approval, so a release gate needs a Hugging Face token and accepted conditions. It also runs a removal-request process, so a cached copy can drift from upstream. | https://huggingface.co/api/datasets/SALT-NLP/SWE-chat |
| A | Brief, section 1: ADR-Bench has 304 tasks (261 benign, 43 malicious) and 134 MCP servers, with P 1.00 / R 0.667 | Corrected | The published scores are on 302 tasks (260 benign, 42 malicious) and 133 servers; recall is 28 of 42. The repository now holds 304 tasks and 134 servers, but the extra malicious task has no recorded run yet. Tier 2 is Claude Sonnet 4 in the paper and `claude-sonnet-4-6` by default in the repository. | https://github.com/uber/ADR/blob/main/Detection/README.md |
| B | Brief, section 3: Authorization Drift "data and code release not confirmed" | Corrected | Released. The abstract links the repository, which is MIT licensed and was pushed on 2026-11-09. | https://github.com/ZJR-FZD/AgentDrift |
| C | Brief, section 5: BeyondTrust says agents "are identified using classifiers that include process naming, signatures, and LLM API traffic patterns" (local capture, not refetched) | Confirmed | The live page carries the same sentence. No method, features or accuracy are published. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |

Also checked in passing: MCP revision 2026-07-28 is the current revision and removes the initialize handshake and protocol-level sessions (https://modelcontextprotocol.io/specification/versioning), which supports the sibling-brief statement in section 7.
