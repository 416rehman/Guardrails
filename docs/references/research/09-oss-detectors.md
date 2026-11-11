# Open detection components for an AIDR sensor and gateway: injection classifiers, safety models, secrets, PII, command analysis

_Researched 2026-11-09_

Method note: repo facts (licence, last push, archived, release tags) come from the GitHub API on 2026-11-09; model facts (licence tag, parameter count, gating, file sizes) from the Hugging Face API the same day. Web search quota ran out part-way, so some items rest on one primary source plus my prior knowledge; those are marked "(unverified)".

## TL;DR

- **No small injection classifier is both good and cleanly licensed.** Prompt Guard 2 is the strongest small model but ships under the Llama 4 Community License (not OSI; "Built with Llama" notice, derivative names must start with "Llama", 700M-MAU clause, manually gated download). The Apache-2.0 alternative, `protectai/deberta-v3-base-prompt-injection-v2`, was **archived and declared unmaintained in July 2026** along with LLM Guard.
- **Adaptive attackers beat every detector.** "The Attacker Moves Second" (Nasr, Carlini et al., arXiv Oct 2025, USENIX Security 2026) reports >90% attack success against Protect AI, PromptGuard and Model Armor, 71% against PIGuard; human red-teamers succeeded in every case. Stacking detectors did not help.
- **Even frontier-model monitors fail.** Anthropic (22 Oct 2026) reports Claude Code Auto Mode and Codex Guardian missed >55% of red-team attacks; cheap fixes (keyed transcript framing, monitoring in-workspace edits, including tool results) helped substantially.
- **Command guards are the weakest shipped layer.** GuardFall (Adversa, 30 Jun 2026): 10 of 11 open-source coding agents' shell guards bypassed by quote removal, `$IFS`, command substitution, base64-to-shell and alternative destructive argv. tree-sitter alone did not help (opencode 16/16 leaked). Only Continue's tokenise-canonicalise-escalate evaluator held (0/21).
- **Model names understate size.** PG2 "22M" has 70.8M parameters (283 MB fp32, 73 MB quantised ONNX); PG2 "86M" has 278.8M (1.1 GB). Both have a 512-token window.
- **Independent numbers are much lower than model cards.** Lakera PINT (May 2025): Protect AI v2 79.1%, PG2-86M 78.8%, vs Lakera 95.2%. CodeIntegrity (Sep 2026): PG2-86M 71.9% recall at 0.54% FPR; Protect AI 81.8% at 1.13%.
- **Secrets: the ecosystem consolidated.** Nosey Parker is retired (replaced by Titus, Go). Betterleaks (MIT, Go, by the Gitleaks author) is now the main rule catalog; **Kingfisher (Apache-2.0, Rust) embeds as crates** and consumes Betterleaks TOML. TruffleHog remains AGPL-3.0.
- **PII: Presidio left the Microsoft org** (now `data-privacy-stack/presidio`, MIT). New Apache-2.0 options: OpenAI `privacy-filter` (Apr 2026, 1.4B params, 128k context, includes a `secret` label), GLiNER2 (Fastino), knowledgator GLiNER-PII edge (46 MB int8 ONNX). `gline-rs` runs GLiNER in Rust on `ort`.
- **Large safety models with OSI licences exist for the gateway only:** `gpt-oss-safeguard-20b` (Apache-2.0, policy-as-prompt, 16 GB VRAM) and Granite Guardian 4.1 8B (Apache-2.0, includes function-calling hallucination). Llama Guard 4 (12B) and ShieldGemma are not OSI.
- **Rust runtime: `ort`** (Apache-2.0, v2.0.0-rc.15, ONNX Runtime 1.31) is the pragmatic choice; it now has pluggable `tract`, `candle` and `web` backends. candle 0.11 has native DeBERTa-v2 and ModernBERT.
- **Consequence:** ML detectors are a noisy signal for scoring and triage. Blocking guarantees must come from deterministic layers we build: command canonicalisation, provenance/taint, egress and capability policy.

## Findings

### 1. Prompt-injection and jailbreak classifiers

**Llama Prompt Guard 2 (Meta, Apr 2025).** 86M (mDeBERTa-base) and 22M (DeBERTa-xsmall) backbones; 512-token context. Model card: AUC 0.998 / recall@1%FPR 97.5% (86M) and 0.995 / 88.7% (22M) on Meta's English jailbreak set; multilingual AUC 0.995 vs 0.942. AgentDojo attack-prevention at 3% utility cost: 81.2% (86M), 78.4% (22M), Protect AI 22.2%, deepset 13.5%. Latency 92.4 ms and 19.3 ms per 512 tokens **on an A100 GPU**; no CPU figure published. Languages: en, fr, de, hi, it, pt, es, th. Licence: Llama 4 Community License; HF gating is `manual`. An ungated ONNX conversion exists (`gravitee-io/Llama-Prompt-Guard-2-22M-onnx`, 73 MB quantised) but carries the same licence. [Model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M), [licence](https://dev.meta.ai/llama/llama4/license/).

**Protect AI DeBERTa v2.** 184M params, 739 MB ONNX shipped in-repo, English only, Apache-2.0. **Archived 2026-07-08**; README states the project and its HF models are no longer maintained. Still 520k downloads/month. [Repo](https://github.com/protectai/llm-guard).

**PIGuard / InjecGuard (ACL 2025).** DeBERTa-v3-base, 184M, MIT code and weights, English. Introduced NotInject (339 benign prompts dense with trigger words) showing existing guards fall to ~60% on over-defence; claims +30.8% over prior best. Most adaptive-attack-resistant classifier in Nasr et al. (71% ASR). Last push Dec 2025. [arXiv 2410.22770](https://arxiv.org/abs/2410.22770), [HF](https://huggingface.co/leolee99/PIGuard).

**Qualifire Sentinel v2.** Qwen3-0.6B fine-tune, 596M params, 1.2 GB, 32k context, English only; self-reported average F1 0.957 vs Protect AI 0.750; 38 ms latency on unstated hardware; GGUF build exists. Licence tag `other`, card says "Elastic license" — **not OSI**, gated. [Model card](https://huggingface.co/qualifire/prompt-injection-jailbreak-sentinel-v2).

**Others.** deepset DeBERTa (MIT) has a 50% false-alarm rate in the CodeIntegrity run — unusable. Rebuff archived (Aug 2024). Vigil dead since Jan 2024. Semalith v1.4 (arXiv 2607.22545, single author, DeBERTa-v3-base, 22-class head) claims wins over Llama-Guard-3-8B on 7 injection sets; weight availability unverified. NeMo Guardrails' own jailbreak detector is a Snowflake arctic-embed-m-long embedding plus a random forest run through onnxruntime, alongside perplexity heuristics and YARA rules for code/SQLi/XSS/template injection (verified in source).

**Independent results.**

| Source (date) | Protect AI v2 | PG2-86M | PG2-22M | Notes |
|---|---|---|---|---|
| Lakera PINT score (May 2025) | 79.14% | 78.76% | – | Lakera 95.2%, Bedrock 89.2%, Azure Prompt Shields 89.1%, Model Armor 70.1%. Repo archived Apr 2026. |
| CodeIntegrity SafeGuard test (Sep 2026) | recall 81.8%, FPR 1.13% | 71.9%, 0.54% | 69.2%, 0.98% | threshold 0.5, 512-token windows, 64 overlap |
| Qualifire avg F1 (self-reported) | 0.750 | – | – | Sentinel v2 0.957 |
| Nasr et al. adaptive ASR | >90% | >90% | – | PIGuard 71% |

Sources: [PINT](https://github.com/lakeraai/pint-benchmark), [CodeIntegrity](https://www.codeintegrity.ai/research/promptguard-benchmark/index.html).

### 2. Safety and policy models (gateway-class)

- **gpt-oss-safeguard-20b / -120b** (OpenAI, Oct 2025; Apache-2.0). Reasoning classifier that takes a written policy at inference time; 21B params (3.6B active), fits 16 GB VRAM; harmony format required; reasoning effort tunable. No benchmark numbers on the card. [HF](https://huggingface.co/openai/gpt-oss-safeguard-20b).
- **Granite Guardian 4.1 8B** (IBM, Apr 2026; Apache-2.0). Replaces 3.3. Pre-baked criteria: harm, jailbreak, RAG groundedness, **function-calling hallucination**; bring-your-own criteria; think and no-think modes. FC Reward Bench balanced accuracy 0.79; OOD safety F1 0.79. English only. GGUF published (Q4 roughly 5 GB). Small sibling: `granite-guardian-hap-38m` (Apache-2.0, 154 MB) for hate/abuse/profanity only. [HF](https://huggingface.co/ibm-granite/granite-guardian-4.1-8b).
- **Llama Guard 4 12B** (Llama 4 licence, gated, multimodal, S1–S14 incl. Code Interpreter Abuse). Meta's own in-house numbers: English recall 69%, FPR 11%, F1 61%. The card says it is itself susceptible to prompt injection. [HF](https://huggingface.co/meta-llama/Llama-Guard-4-12B).
- **ShieldGemma 2B / ShieldGemma 2 4B** — Gemma terms (not OSI, prohibited-use policy), gated.
- **LlamaFirewall** (MIT code; last substantive commits are type-suppression housekeeping, Oct 2026). AgentDojo: baseline ASR 17.6% / utility 47.7%; PG2 alone 7.5% / 47.0%; AlignmentCheck (Llama 4 Maverick) 2.9% / 43.1%; combined 1.75% / 42.7%. AlignmentCheck needs a 70B-class model; 1B–8B models wrecked utility. CodeShield: 96% precision, 79% recall, 50+ CWEs, ~60 ms first tier, ~300 ms second tier. [arXiv 2505.03574](https://arxiv.org/html/2505.03574v1).
- **Frameworks.** NeMo Guardrails v0.24.1 (Apache-2.0, repo moved to `NVIDIA-NeMo/Guardrails`): 67 rail surfaces including `hf_classifier`, `tool_safety_check`, `context_bloat_detection`, `gliner`, `regex`, `cel`, and vendor rails including `crowdstrike_aidr`, `ai_defense`, `zscaler_aiguard`, `prompt_security`, `trend_micro`, `pangea`; rails declare manifests with privacy properties; `/v1/checks` endpoint runs rails without generation. Guardrails AI v0.11.0 (Apache-2.0). OpenAI Guardrails Python v0.3.6 (MIT): checks include `prompt_injection_detection`, `jailbreak`, `pii`, `secret_keys`, `urls`. mozilla-ai/any-guardrail (Apache-2.0) is a thin switch layer across guard models.
- **Commercial reference point.** Azure Prompt Shields docs (updated Oct 2026): separate user-prompt and document shields, up to five documents per call, tool-response scanning in preview, "primarily trained and evaluated on English". [Microsoft Learn](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection).

### 3. Robustness to adaptive attacks

- **Nasr et al.** Twelve defences across prompting, training, filtering and secret-knowledge classes; gradient, RL, random-search and human attacks. Spotlighting >95% ASR; MetaSecAlign 2% static → 96% adaptive; MELON 76% → 95% with defence knowledge; detectors as above. Authors: detectors "may still block unsophisticated attacks", recommend simple human-analysable defences and adaptive evaluation. [arXiv 2510.09023](https://arxiv.org/abs/2510.09023).
- **PISmith** (arXiv 2603.13026, Mar 2026, COLM 2026): black-box RL attacker; "state-of-the-art prompt injection defenses remain vulnerable".
- **AgentDyn** (arXiv 2602.03117, Feb 2026; MIT): 60 open-ended tasks, 560 injections including *helpful* third-party instructions; ten defences "either not secure enough or suffer from significant over-defense".
- **Anthropic, "Red-Teaming Auto Mode"** (22 Oct 2026): three-stage monitor (one-token pre-screen, reasoning classifier, optional agentic investigator). Production monitors omit tool results and in-workspace edits; execute-then-write succeeded 43% (Auto Mode) and 72% (Guardian). False positives <1% on 4,000 benign actions. Multi-agent and compaction attacks remain open. [Post](https://alignment.anthropic.com/2026/red-teaming-auto-mode/).

### 4. Secrets

| Tool | Licence | Lang | Status (Nov 2026) | Notes |
|---|---|---|---|---|
| Kingfisher (MongoDB) | Apache-2.0 | Rust | v2.18.1, active | Crates `kingfisher-core/-rules/-scanner`; Python and Node SDKs; Vectorscan; 503 rules; validation, blast-radius mapping, revocation; reads Betterleaks TOML |
| Betterleaks | MIT | Go | v2.0.0-rc.7, active | Gitleaks author; BPE "rarity" filter, CEL/Expr filters, validation; Go library |
| Gitleaks | MIT | Go | v8.30.1 (Mar 2026), slow | Rule format is the de facto standard |
| TruffleHog | AGPL-3.0 | Go | v3.99.8 | Best verification coverage; licence blocks embedding |
| Titus (Praetorian) | Apache-2.0 | Go | v1.3.0 | Successor to Nosey Parker (archived Feb 2026); 487 rules; Burp and Chrome extensions |
| detect-secrets | Apache-2.0 | Python | last push Apr 2026 | Baseline workflow; slow-moving |

Kingfisher's published runtimes: Linux kernel 205 s vs TruffleHog 598 s vs Gitleaks 549 s; on GitLab's repo TruffleHog made 15,624 outbound requests vs Kingfisher 17. Vendor numbers. [COMPARISON.md](https://github.com/mongodb/kingfisher/blob/main/docs/COMPARISON.md). Betterleaks' CredData recall claims (98.6%) are from its launch material (unverified here).

### 5. PII

- **Presidio** 2.2.366 (MIT, Python): regex + checksum + NER recognisers; org moved April 2026.
- **GLiNER** v0.2.30 (Apache-2.0). PII variants: `knowledgator/gliner-pii-edge-v1.0` (Apache-2.0, 46 MB quint8 ONNX), `-small` (83 MB), `-base` (197 MB); `urchade/gliner_multi_pii-v1` (Apache-2.0, six languages); `nvidia/gliner-PII` (570M, 55+ types, F1 0.70 Argilla / 0.64 AI4Privacy; **NVIDIA Open Model License**, not OSI, English). `piiranha-v1` is CC-BY-NC-ND — avoid.
- **GLiNER2-PII** (Fastino, arXiv 2605.09973, May 2026): 0.3B, 42 types, multilingual; base GLiNER2 is Apache-2.0; PII checkpoint licence unverified (HF returned 401).
- **OpenAI privacy-filter** (Apache-2.0, Apr 2026): bidirectional token classifier, 8 categories including `secret`, 128k context, ONNX and Transformers.js builds. Independent evaluation (arXiv 2608.02616): F1 0.855 AI4Privacy, 0.464 SPY, precision 0.31–0.54 with recall 0.70–0.85, **collapses on non-Latin scripts (Arabic 0.04, Cyrillic 0.03)**.
- **Rust:** `fbilhaut/gline-rs` (Apache-2.0) on `ort`. One community report puts GLiNER2 int8 on CPU at ~180 ms p50 (self-reported).

### 6. Command and code analysis

- **Parsers.** tree-sitter-bash (MIT; 100 open issues; last push Sep 2026); `airbus-cert/tree-sitter-powershell` (MIT, active); `brush-parser` crate from reubeno/brush (MIT, Rust bash-compatible shell with fuzzing); mvdan/sh (BSD-3, Go); yash-rs (POSIX, licence unlisted via API); conch-parser archived.
- **Why parsing is not enough.** GuardFall: matchers ran on raw node text, so quote removal and expansion still bypass. A Mistral Vibe CVE arose from tree-sitter extraction dropping a `PATH=` assignment. Claude Code reportedly chains 25+ validators with early-allow short-circuits. [Adversa](https://adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/).
- **Existing guards.** `destructive_command_guard` (Rust, 6.3k stars, 50+ packs, sub-ms, heredoc scanning) is **MIT with a rider denying rights to OpenAI and Anthropic and anyone acting for them** — not OSI, do not embed. `tirith` (AGPL-3.0; 244 rules: homograph URLs, pipe-to-shell, ANSI injection). `shellfirm` (Apache-2.0).
- **SAST.** Semgrep engine LGPL-2.1, but **Semgrep Rules License v1.0 forbids distribution and hosted use** (internal business use only). Opengrep (LGPL-2.1, v1.33.1, consortium-backed) keeps rule compatibility and adds intrafile taint; rules must be our own. CodeShield (MIT) wraps Meta's Insecure Code Detector.
- **Supply-chain scanners for agent artefacts:** snyk/agent-scan (Apache-2.0), cisco-ai-defense/mcp-scanner and skill-scanner (Apache-2.0).

### 7. Benchmarks and red-team tools

| Tool | Licence | Status |
|---|---|---|
| AgentDojo | MIT | Last push Jun 2026; still the base everything extends |
| AgentDyn | MIT | Feb–May 2026; dynamic tasks, helpful instructions |
| AutoDojo (arXiv 2606.15057) | unverified | Generates injections adaptively per agent and defence |
| ASB | MIT | Active (Sep 2026) |
| InjecAgent | MIT | Dead since Jul 2024 |
| BIPIA | custom | Archived |
| PINT | MIT harness, private data | Archived Apr 2026; all Lakera repos archived |
| WASP | custom | Archived Apr 2026 |
| CyberSecEval 4 | PurpleLlama (mixed) | Adds CyberSOCEval; injection tests English-only text plus visual |
| garak | Apache-2.0 | v0.17.1 (Oct 2026) |
| PyRIT | MIT | Moved to `microsoft/PyRIT`, v1.1.0 (Sep 2026), web UI |
| promptfoo | MIT | 0.125.1; **now part of OpenAI**, stays MIT |
| DeepTeam | Apache-2.0 | Last release Nov 2025 |

### 8. Rust inference, quantisation, WASM, distribution

- **ort** v2.0.0-rc.15 (Oct 2026), Apache-2.0, wraps ONNX Runtime 1.31; features `download-binaries`, `load-dynamic`, `alternative-backend`; execution providers include CoreML, DirectML, OpenVINO, QNN, XNNPACK, WebGPU. Backends directory: `tract`, `candle`, `web`. Still a release candidate after years; pin exactly. Used by HF text-embeddings-inference and Google Magika.
- **candle** 0.11.0 (Apache-2.0): `debertav2.rs`, `modernbert.rs`, `bert.rs`, `xlm_roberta.rs` present — pure Rust, WASM-capable, slower on CPU per third-party reports.
- **tract** v0.23.10 (pure Rust ONNX), **burn** 0.23 pre-release (ONNX import to Rust code), **llama-cpp-rs** (Apache-2.0) for GGUF guard models.
- **Quantisation risk.** DeBERTa's disentangled attention quantises poorly: one mDeBERTa injection model reports PR-AUC 0.997 → 0.46 after int8; another project reports ~5 points of recall lost; a third reports 101 ms (int8, M1) vs 646 ms (fp32) for DeBERTa-v3-base. All self-reported; we must measure per model and gate on accuracy deltas.
- **Distribution.** HF Hub is the default channel; Meta models require manual licence acceptance, so a product cannot silently fetch them. Sigstore `model-transparency` (Apache-2.0) provides model signing with Sigstore, keys or PKCS#11. Kingfisher documents provenance for rule bundles. tirith ships a signed threat-intel database.

## Matrix

| Component | Params / size | Context | Licence (weights) | OSI? | Languages | Endpoint CPU fit |
|---|---|---|---|---|---|---|
| PG2-22M | 70.8M / 73 MB q8 | 512 | Llama 4 | No | 8 (weak non-EN) | Yes, opt-in only |
| PG2-86M | 278.8M / 1.1 GB | 512 | Llama 4 | No | 8 | Marginal |
| Protect AI v2 | 184M / 739 MB | 512 | Apache-2.0 | Yes | en | Yes; unmaintained |
| PIGuard | 184M / 738 MB | 512 | MIT | Yes | en | Yes |
| Sentinel v2 | 596M / 1.2 GB | 32k | Elastic | No | en | No |
| gpt-oss-safeguard-20b | 21B | large | Apache-2.0 | Yes | multi | No (16 GB VRAM) |
| Granite Guardian 4.1 | 8B / ~5 GB Q4 | 8k (example) | Apache-2.0 | Yes | en | Workstation only |
| Llama Guard 4 | 12B | – | Llama 4 | No | 8 | No |
| ShieldGemma 2 | 4B | – | Gemma | No | – | No |
| OpenAI privacy-filter | 1.4B (50M active) | 128k | Apache-2.0 | Yes | Latin scripts | Possibly (q4 ONNX) |
| GLiNER-PII edge | 46 MB q8 | 512 | Apache-2.0 | Yes | en | Yes |
| nvidia/gliner-PII | 570M | – | NVIDIA Open Model | No | en | Marginal |
| Kingfisher | Rust crates | n/a | Apache-2.0 | Yes | n/a | Yes |
| Betterleaks rules | TOML | n/a | MIT | Yes | n/a | Yes (as data) |

## Weak points, gaps and risks

- **Licence traps:** Llama 4 (PG2, Llama Guard), Gemma, Elastic (Sentinel), NVIDIA Open Model, Semgrep Rules License, AGPL (TruffleHog, tirith), dcg's rider, CC-BY-NC-ND (piiranha). An "everything open source" product cannot bundle any of these weights or rules by default.
- **Abandonment:** LLM Guard, Rebuff, Vigil, InjecAgent, BIPIA, PINT, WASP, Nosey Parker are all dead or archived. Single-vendor detector projects have a short half-life after acquisition.
- **512-token windows** force chunking of tool outputs; an injection split across a window boundary or diluted in a long document is the common miss. Max-over-windows also inflates FPR with document length.
- **Multilingual:** only PG2-86M and mDeBERTa-based community models are multilingual; everything Apache/MIT is English. Privacy-filter fails on non-Latin scripts.
- **Base rates:** a coding agent reads hundreds of tool results a day, many being security docs, READMEs and prompts. At 1% FPR that is multiple false blocks per developer per day; NotInject shows trigger-word bias is real.
- **Monitor blind spots:** omitting tool results and workspace edits is exploitable; monitors are themselves injectable through the transcript.
- **No authoritative CPU latency numbers** exist for any of these models.

## Implications for our design

**(a) Endpoint, CPU-only, hard budget** (suggested: deterministic tier ≤2 ms, ML tier ≤40 ms p95 on four threads, otherwise the check runs asynchronously and only raises risk score):

1. *Deterministic tier, built in Rust:* command canonicaliser (below); secrets through Kingfisher crates (Apache-2.0) with the Betterleaks catalog (MIT), offline only, validation disabled on endpoints; PII via regex + checksum recognisers ported from Presidio patterns (MIT); Unicode, bidi, zero-width and ANSI normaliser.
2. *Small encoder via `ort`:* default to **our own Apache-2.0 classifier** (see below). Interim default PIGuard (MIT) with Protect AI v2 (Apache-2.0) as fallback, int8 only if the accuracy delta passes our gate. PG2-22M as an explicit user-accepted download, never bundled.
3. *Optional async NER:* knowledgator GLiNER-PII edge (46 MB) through gline-rs, off the blocking path.
4. *No LLM judge on the endpoint by default;* allow a workstation-class opt-in (Granite Guardian GGUF via llama.cpp) or delegate to the gateway.

**(b) Gateway:** same deterministic tier; ensemble of encoders (ours + PIGuard; PG2-86M and Sentinel v2 as operator-enabled plug-ins); Presidio service or GLiNER2 / privacy-filter for PII spans; `gpt-oss-safeguard-20b` for tenant-written policies and Granite Guardian 4.1 for tool-call hallucination and jailbreak, both asynchronous or on escalation only; an AlignmentCheck-style auditor (LlamaFirewall is MIT) using whatever model the tenant supplies; Opengrep (LGPL, out-of-process) with our own rules for generated code.

**Detectors we must build ourselves:**

1. **Shell and PowerShell risk analyser.** Parse (brush-parser or tree-sitter-bash; tree-sitter-powershell), then *canonicalise*: quote removal, variable and `$IFS` expansion flags, recursive command substitution with verdict capping, pipe-to-interpreter detection, heredoc and `-c` inline scripts, env-assignment prefixes, redirect targets. Fail closed on anything unparsed. Ship the GuardFall A–E corpus as a public conformance suite.
2. **An Apache-2.0 injection classifier** trained on MIT/Apache bases (DeBERTa-v3-xsmall/small, mDeBERTa, ModernBERT), targeted at *tool outputs* for coding agents, multilingual, calibrated, with NotInject-style hard negatives and token-level localisation.
3. **Provenance and taint tracking** with keyed transcript framing, plus monitoring of in-workspace writes and tool results (the cheap fixes Anthropic validated).
4. **Behavioural secret-flow detection:** correlate secret reads with subsequent egress rather than relying on content matching.
5. **Signed detector packs:** versioned bundle of model, tokenizer, thresholds, rule sets and eval report, signed with sigstore model-signing, distributed as OCI artefacts with staged rollout and offline import for air-gapped and MSP tenants.
6. **Detector plug-in ABI** so non-OSI weights are operator-installed, with licence metadata surfaced in the UI and SBOM.

**Evaluation plan.** (1) Static: NotInject, PINT if Lakera grants access, BIPIA, CodeIntegrity-style clean splits, our own benign corpus from real agent tool outputs; report recall at 0.1% and 1% FPR, never accuracy at threshold 0.5. (2) Agentic: AgentDojo, AgentDyn, ASB with and without each layer; report ASR and utility together. (3) Adaptive: search with score feedback (Nasr), PISmith-style RL, AutoDojo, and paid human red-teaming before each major release. (4) Command guard: A–E corpus plus fuzzing against real bash/pwsh execution as oracle. (5) Performance: p50/p95/p99 and RSS on three reference CPUs, fp32 vs int8, per token length. (6) Run garak, PyRIT and promptfoo in CI; publish all results with the detector pack.

**Honest limits to state in the product.** A classifier is a cost-raising filter against opportunistic and known attacks; a motivated attacker with query access defeats it. We should publish that verdicts are probabilistic, never describe a detector as preventing injection, and make the default posture "detect and score with ML, block with deterministic policy".

## Ideas worth stealing and whitespace

- Continue's five-stage command evaluator; NeMo's rail manifests declaring privacy properties and `RailOutcome` (decide once, render many); NeMo's `/v1/checks` endpoint.
- Betterleaks' BPE rarity filter in place of Shannon entropy; Kingfisher's offline checksum verification and blast-radius mapping.
- gpt-oss-safeguard's policy-as-prompt for per-tenant policy without retraining.
- Anthropic's staged monitor: one-token pre-screen, then reasoning, then agentic investigation.
- **Whitespace:** an OSI-licensed, maintained, multilingual, tool-output-oriented injection classifier; a public CPU latency leaderboard; a coding-agent-specific injection benchmark; an open shell-guard conformance suite; cross-session and memory-borne injection evaluation; a neutral successor to the archived PINT.

## Could not verify / open questions

- CPU latency for PG2, PIGuard and Protect AI on reference hardware (none published; CodeIntegrity's figures are only in SVG charts).
- PIGuard's full results table (PDF unreadable here); AgentDyn and PISmith per-defence numbers.
- Exact text of Sentinel's Elastic licence; licences of GLiNER2-PII, Semalith and AutoDojo artefacts.
- gpt-oss-safeguard accuracy figures; newer ShieldGemma or NemoGuard releases (HF returned 401 for several IDs).
- Whether Vectorscan-based Kingfisher crates build cleanly on Windows ARM64 and whether the `ort` web backend is production-ready.
- Why ONNX Runtime's latest GitHub release tag reads v1.30.1 while `ort` targets API 31.
- `ort.pyke.io` (403) and the NeMo Guardrails docs page (404) were unreachable; facts taken from source instead.
- Semgrep/Opengrep, CyberSecEval and promptfoo web searches did not run (quota); covered through repository contents only.

## Sources

- https://arxiv.org/abs/2510.09023 — The Attacker Moves Second (10 Oct 2025; USENIX Security 2026)
- https://alignment.anthropic.com/2026/red-teaming-auto-mode/ — Red-Teaming Auto Mode (22 Oct 2026)
- https://adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/ — GuardFall (30 Jun 2026)
- https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M — Prompt Guard 2 card (Apr 2025)
- https://dev.meta.ai/llama/llama4/license/ — Llama 4 Community License (5 Apr 2025)
- https://github.com/protectai/llm-guard — archived notice (Jul 2026)
- https://github.com/lakeraai/pint-benchmark — PINT scores (May 2025; archived Apr 2026)
- https://www.codeintegrity.ai/research/promptguard-benchmark/index.html — classifier benchmark (11 Sep 2026)
- https://arxiv.org/abs/2410.22770 — InjecGuard/PIGuard and NotInject
- https://huggingface.co/qualifire/prompt-injection-jailbreak-sentinel-v2 — Sentinel v2 card
- https://arxiv.org/html/2505.03574v1 — LlamaFirewall paper (May 2025)
- https://huggingface.co/openai/gpt-oss-safeguard-20b — gpt-oss-safeguard card
- https://huggingface.co/ibm-granite/granite-guardian-4.1-8b — Granite Guardian 4.1 (Apr 2026)
- https://huggingface.co/meta-llama/Llama-Guard-4-12B — Llama Guard 4 card
- https://github.com/NVIDIA-NeMo/Guardrails — NeMo Guardrails v0.24.1 source and release notes (Sep 2026)
- https://github.com/openai/openai-guardrails-python — OpenAI Guardrails v0.3.6
- https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection — Prompt Shields (updated Oct 2026)
- https://arxiv.org/abs/2603.13026 — PISmith (Mar 2026)
- https://arxiv.org/abs/2602.03117 — AgentDyn (Feb 2026)
- https://github.com/mongodb/kingfisher and docs/COMPARISON.md — Kingfisher v2.18.1
- https://github.com/betterleaks/betterleaks — Betterleaks v2.0.0-rc.7
- https://github.com/praetorian-inc/titus, https://github.com/praetorian-inc/noseyparker — Titus / Nosey Parker retirement
- https://github.com/data-privacy-stack/presidio — Presidio 2.2.366
- https://huggingface.co/openai/privacy-filter — OpenAI Privacy Filter (Apr 2026)
- https://arxiv.org/abs/2608.02616 — Privacy Filter evaluation across 32 benchmarks (Aug 2026)
- https://arxiv.org/abs/2605.09973 — GLiNER2-PII (May 2026)
- https://huggingface.co/nvidia/gliner-PII — NVIDIA GLiNER-PII (Oct 2025)
- https://github.com/fbilhaut/gline-rs — GLiNER in Rust
- https://semgrep.dev/legal/rules-license/ — Semgrep Rules License v1.0
- https://github.com/opengrep/opengrep — Opengrep v1.33.1
- https://github.com/Dicklesworthstone/destructive_command_guard — dcg licence rider
- https://github.com/pykeio/ort — ort v2.0.0-rc.15; https://github.com/huggingface/candle — candle 0.11.0
- https://github.com/sigstore/model-transparency — model signing
- https://github.com/meta-llama/PurpleLlama — CyberSecEval 4, CodeShield, LlamaFirewall
- https://github.com/promptfoo/promptfoo, https://github.com/microsoft/PyRIT, https://github.com/NVIDIA/garak — red-team tools

## Independent verification

_Checked 2026-11-09 by a second reviewer. Method: GitHub API (`gh`, read-only), Hugging Face API and raw model cards, crates.io API, and direct fetches of the primary pages. Web search was unavailable (quota exhausted), so no claim was tested against secondary coverage._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Adaptive attacks: >90% ASR vs Protect AI, PromptGuard, Model Armor; 71% vs PIGuard; humans succeeded in all cases; stacking detectors does not solve it | Confirmed | Section 5.3 wording matches. Detector figures are for the search attack with Gemini 2.5 Pro as base model. Human red-teaming yielded 123 successful injections under the strictest setting. USENIX Security 2026 venue also confirmed. | https://arxiv.org/html/2510.09023v1 ; https://www.usenix.org/conference/usenixsecurity26/presentation/nasr |
| 2 | Prompt Guard 2 (22M, 86M) under Llama 4 Community License: "Built with Llama", "Llama" name prefix, 700M-MAU clause, manual gate, not OSI | Confirmed | Licence text read from the HF gate prompt: 1.b.i notice and name-prefix duties, section 2 MAU clause, Acceptable Use Policy incorporated. HF API reports `gated: manual`, `license: other (llama4)` for both. | https://huggingface.co/api/models/meta-llama/Llama-Prompt-Guard-2-86M ; https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Prompt-Guard-2 |
| 3 | LLM Guard and Protect AI HF models archived July 2026, declared unmaintained | Confirmed | Repo `archived: true`, last push 2026-07-08; README and the model card both carry the archive warning (card modified 2026-07-09). Model is Apache-2.0; the repo code is MIT. | https://github.com/protectai/llm-guard ; https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2 |
| 4 | GuardFall bypassed the shell guards of 10 of 11 agents; opencode 16/16; only Continue held (0/21) | Corrected | Ten of eleven were left exploitable, but only five had a pattern guard that was bypassed: Hermes (all five classes), opencode 16/16, Goose 22/23, Cline 2/13 and 8/13 (opt-in guard only), Roo-Code 4/18. Aider, Plandex and Open Interpreter have no static guard; OpenHands and SWE-agent rely on a container sandbox and failed only in local mode. Continue's 0/21 is for the default GUI; its CLI `--auto` relaxes a verdict tier, and gaps remain for class C inside quoted arguments and most of class E. Tested versions are not listed ("as of May 2026"). | https://adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/ |
| 5 | Auto Mode and Codex Guardian failed to block >55% of red-team attacks (Sep 2026); keyed framing, workspace-edit monitoring and tool results substantially reduced ASR | Confirmed | Caveats: the attacker is a persistently misaligned agent (Opus 5, 20-block budget), not third-party injection; the Guardian tested is "an approximation of Codex's production default"; 55% is an average over settings. Only one fix is isolated numerically (Guardian 72% to 31% with edit monitoring). The >50-point gain of "Auto Mode ++" also includes a larger model (Opus 4.8) and an agentic stage. arXiv abstract adds: injection ran arbitrary bash in 79% of trials. | https://alignment.anthropic.com/2026/red-teaming-auto-mode/ ; https://arxiv.org/abs/2609.19587 |
| 6 | PINT (May 2025): Protect AI v2 79.14%, PG2-86M 78.76%, Lakera 95.2%, Bedrock and Azure about 89% | Confirmed | README table: Lakera 95.2200, Bedrock 89.2404, Azure 89.1241, Protect AI 79.1366, PG2-86M 78.7578, Model Armor 70.0664 (Aug 2025). The PG score is jailbreak detection only; indirect injection is out of scope. A commented-out PINT v1 row shows open-source WhyLabs LangKit at 80.02% (June 2024, not re-run). Benchmark is run by Lakera, which tops it. Repo archived, last push 2026-04-16. | https://github.com/lakeraai/pint-benchmark |
| 7 | Kingfisher: Apache-2.0, Rust, embeddable via `kingfisher-core`, `-rules`, `-scanner`; 503 rules; reads Betterleaks TOML | Confirmed | All three crates are on crates.io (core 1.0.6, rules 3.2.0, scanner 3.0.3), versioned independently of the CLI (v2.18.1, released 2026-11-09). README: bundled catalog 503 rules, 502 selected by default loaders; both `.toml` (Betterleaks) and `.yml` rule formats supported. | https://github.com/mongodb/kingfisher ; https://crates.io/crates/kingfisher-scanner |
| 8 | gpt-oss-safeguard-20b and Granite Guardian 4.1 8B are both Apache-2.0, the only OSI-licensed large safety models surveyed | Corrected | Licences, 16 GB VRAM and the function-calling hallucination criterion are confirmed. "Only" is true of the brief's survey but not of the field: Qwen3Guard-Gen 0.6B/4B/8B and Qwen3Guard-Stream (Apache-2.0, ungated, 119 languages, has a Jailbreak category), allenai/wildguard (Apache-2.0, auto-gated, 7B) and MD-Judge (Apache-2.0) were not surveyed. gpt-oss-safeguard also ships a one-line usage policy (comply with applicable law). | https://huggingface.co/Qwen/Qwen3Guard-Gen-8B ; https://huggingface.co/openai/gpt-oss-safeguard-20b ; https://huggingface.co/ibm-granite/granite-guardian-4.1-8b |
| 9 | PG2: 512-token context; only published latency is A100 GPU (19.3 ms / 92.4 ms); real sizes 70.8M and 278.8M | Confirmed | Safetensors totals are 70,830,722 and 278,810,882. Meta's "22M/86M" column is labelled "Backbone Parameters", so the gap is the embedding matrix, not a misstatement. No CPU latency in the card. | https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md |
| 10 | Semgrep Rules License v1.0: internal business use only, no distribution or offering as a service; cannot be bundled | Confirmed | Text (last updated 2024-12-13): internal business purposes only; no distributing or making available as a service. `semgrep/semgrep-rules` LICENSE points to it. The pre-change fork `opengrep/opengrep-rules` is archived and is LGPL-2.1 plus Commons Clause, so it is not a clean bundling source either. | https://semgrep.dev/legal/rules-license/ ; https://github.com/opengrep/opengrep-rules |

### Further statements checked

| Statement in brief | Verdict | Note | Source |
|---|---|---|---|
| "Only PG2-86M and mDeBERTa-based community models are multilingual; everything Apache/MIT is English" (Weak points) | Refuted | Qwen3Guard (Apache-2.0) covers 119 languages and dialects, with generative (0.6B to 8B) and streaming token-level variants. The statement holds only for small encoder injection classifiers. | https://huggingface.co/Qwen/Qwen3Guard-Gen-8B |
| "A Mistral Vibe CVE arose from tree-sitter extraction dropping a `PATH=` assignment. Claude Code reportedly chains 25+ validators" (section 6, cited to Adversa) | Unverifiable | Neither statement appears in the cited GuardFall page, and the GitHub advisory database returns nothing for the `mistral-vibe` package. Treat as unsourced. | https://adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/ |
| CodeIntegrity (Sep 2026): Protect AI 81.8% recall / 1.13% FPR; PG2-86M 71.9% / 0.54%; PG2-22M 69.2% / 0.98%; deepset 50% FPR | Confirmed | Figures match. It is a vendor benchmark on the vendor's own SafeGuard test split (5,140 prompts, threshold 0.5, 512-token windows with 64 overlap); CodeIntegrity's own model scored 53.26% / 7.82% under that window policy. Latency is chart-only, on an Apple M5 Pro. | https://www.codeintegrity.ai/research/promptguard-benchmark/index.html |

Also confirmed in passing through the GitHub API: Presidio now at `data-privacy-stack/presidio` (MIT); Nosey Parker archived 2026-02-21; `destructive_command_guard` licence rider denying rights to OpenAI and Anthropic; `ort` v2.0.0-rc.15 (2026-10-19); PyRIT at `microsoft/PyRIT`; PIGuard weights MIT (loads with `trust_remote_code=True`, which an embedding product must account for). Continue's evaluator lives in `packages/terminal-security` of the Apache-2.0 `continuedev/continue` repo.
