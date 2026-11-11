# G06 - Threat intelligence and the detection-content lifecycle for an open AIDR

_Researched 2026-11-09_

Method note: the web-search budget for this run was exhausted before this brief started, so nothing here comes from a search engine. Everything was read directly from primary sources: GitHub (via `gh`), vendor docs pages, spec sites, and public APIs. News-only facts (incident write-ups, acquisitions, AI-ISAC status) are therefore thinner than the repo and docs facts and are marked where unverified.

## TL;DR

- There is **no open, machine-readable feed for malicious MCP servers or agent skills**. The OSV schema has no ecosystem for MCP servers, skills or model files (it does have `VSCode`, incl. `VSCode:https://open-vsx.org`). The verdicts that exist are locked in vendor UIs or token-gated APIs (Snyk, Backslash, Socket, Gen, Palo Alto/Koi). This is the clearest whitespace.
- The best free supply-chain base layer is **OpenSSF malicious-packages** (Apache-2.0, OSV format, 240,309 reports, pushed daily) plus **GitHub Advisory Database** (CC-BY-4.0, `type=malware`). Both cover npm/PyPI and VS Code/Open VSX extensions, which is how most malicious MCP servers and skill installers actually arrive.
- The **official MCP Registry is not a trust source**: still "preview", states consumers should assume "minimal-to-no moderation", does not remove servers with vulnerabilities, and by its own design doc does not yet validate entries against its schema. It is a useful *enumeration* source (`GET /v0.1/servers?updated_since=`, soft-delete via `status: "deleted"`).
- Scanning an MCP server to judge it **executes it**. Snyk agent-scan warns that it starts stdio servers and calls remote URLs with configured headers. Reputation must be computed centrally in a sandbox, never by running unknown servers on a user endpoint.
- Mature open rule repos converge on the same lifecycle: **maturity tiers** (Sigma experimental/test/stable; Falco sandbox/incubating/stable/deprecated; Elastic `maturity`), **mandatory per-rule tests**, a **benign "goodlog" corpus**, and **packaged releases by tier**. Falco is the only one that ships **signed OCI artifacts** (cosign keyless).
- **Licences differ and matter for embedding**: Sigma rules DRL 1.1, Elastic rules Elastic License 2.0 (not open source), Splunk/Falco/Chainguard Apache-2.0. Use Apache-2.0 for our rules and CC-BY-4.0/CC0 for intel data; re-derive rather than copy Elastic logic.
- Real AI-agent detections already exist in vendor repos: Elastic has ~150 GenAI-tagged rule files (`Domain: GenAI`, `Mitre Atlas:` tags; e.g. "Potential Prompt Injection Coercing Shell Execution", 2026-10-09); Splunk has 5 MCP detections; Sigma has one. Sigma's tag spec has **no ATLAS namespace**.
- **MITRE ATLAS ships monthly** (v2026.10, 2026-10-28: 16 tactics, 129 techniques, 92 sub-techniques) and **renumbers techniques** between releases. Mappings must carry the ATLAS version and be CI-checked.
- **CrowdStrike's Channel File 291 RCA** maps directly to our pipeline: the validator and the interpreter disagreed about input count (21 vs 20), tests used wildcards in the failing field, there was no bounds check, and content went to everyone at once. Fixes: same-engine validation, non-wildcard tests per field, fuzzing, canary then rings with bake time, customer control.
- Microsoft delivers AI-agent prompt-injection detection as **Defender security-intelligence content** (signature >= `1.451.224.0`) with `Disabled/Audit/Block` modes and an EICAR-style benign test string; BeyondTrust offers **policy replay against recorded activity before saving**. Both are patterns to copy.
- **Agent BOM has no standard.** CycloneDX 1.7.2 has no agent/MCP/skill component type (proposals #895 and #941 were closed in 2026); SPDX 3.0.1 AI profile describes models, not agents. We must define our own inventory schema and export to CycloneDX.
- Privacy-preserving aggregate telemetry is still not standardised: **DAP is draft-20 (2026-10-20), not an RFC**. Start with a simpler, fully inspectable, opt-in counter scheme.

## Findings

### 1. What agent-specific intelligence exists

**Packages, extensions (verified 2026-11-09).**
- `ossf/malicious-packages`: Apache-2.0, OSV JSON, directories for npm, pypi, crates.io, go, maven, nuget, packagist, rubygems, `vscode` (4 entries) and `vscode:open-vsx.org` (17 entries). Total 240,309 reports. Scope explicitly includes typosquats, account takeover and dependency confusion. https://github.com/ossf/malicious-packages
- `github/advisory-database`: CC-BY-4.0, continuous; malware advisories queryable with `GET /advisories?type=malware`. Latest entries are npm spam floods, so the feed needs a noise filter. https://github.com/github/advisory-database
- `microsoft/vsmarketplace` `RemovedPackages.md`: a Markdown table (~2,500 rows) of `publisher.name | date | Malware/Untrustworthy/Spam`, updated 2026-11-09, several removals per day. No hashes, no versions, no JSON. https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md
- Open VSX (`eclipse-openvsx/openvsx`, EPL-2.0) now has publish-time scanning (`ovsx.scanning` config, secret-scanning rules that block publication) but I found no public takedown feed; the OSSF `vscode:open-vsx.org` directory is the nearest thing.
- `DataDog/malicious-software-packages-dataset` (Apache-2.0, samples), `DataDog/guarddog`, `safedep/vet` and `safedep/pmg` (Apache-2.0), `chainguard-dev/malcontent` (Apache-2.0, 14,500+ YARA rules, differential analysis).

**MCP servers.**
- Official registry (`modelcontextprotocol/registry`, v1.8.8 on 2026-11-06, licence in transition MIT to Apache-2.0). Moderation policy: removes illegal content, malware, spam, broken servers; does **not** remove vulnerable servers; relies on upstream package registries and downstream "subregistries". Removal sets `status: "deleted"` and keeps metadata readable, which makes it a usable takedown signal. https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/moderation-policy.mdx
- Backslash MCP Server Security Hub: 80,000+ public servers scored 0-100 with labels; from source code and declared tools; study of top 8,000 found 29% with at least one finding. No API or bulk data. https://mcp.backslash.security/
- Snyk agent-scan (formerly Invariant mcp-scan; Apache-2.0 client, v0.6.11, 2026-11-06): requires `SNYK_TOKEN`; sends client info, MCP configs and tool signatures, and skill files to a server-side analysis API (version `2026-07-10`); returns named risk indicators scored 0-1000 (100/300/600/1000). CLI output is declared unstable. https://github.com/snyk/agent-scan
- Cisco `mcp-scanner` (Apache-2.0): YARA + LLM judge + Cisco AI Defense API, VirusTotal hash lookups, offline static mode on pre-generated JSON. Cisco `skill-scanner`: YAML + YARA-X patterns, AST/dataflow, optional LLM judge, CEL decision layer (`cel-go` v0.32.0), and published recall/FPR/F1 per preset. https://github.com/cisco-ai-defense
- Test fixtures: `canack/bad-mcp` (MIT, 10 intentionally malicious servers), `m10x/malim` (Apache-2.0).

**Skills.**
- Snyk "ToxicSkills" (2026-02-05): 3,984 skills from ClawHub and skills.sh; 36.82% with a flaw, 13.4% critical, 76 confirmed malicious payloads, 91% of malicious skills combine prompt injection with code. https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
- skills.sh `/audits` shows per-skill verdicts from three providers side by side (Gen Agent Trust Hub, Socket, Snyk). It is an ensemble display, not a downloadable feed. https://skills.sh/audits
- Corpora: `protectskills/MaliciousAgentSkillsBench` (MIT), `lxyeternal/MalSkillBench`, `snyk-labs/toxicskills-goof`, `elliottwaves-20/agent-guard-corpus` (MIT, inert samples). `SkillCamo` (NeurIPS 2026) attacks skill scanners with multimodal hidden instructions, so text-only scanners are already known-evadable.

**Prompts and injection payloads.**
- PromptIntel (SecurityBreak / Thomas Roccia): adversarial prompt DB, "Indicators of Prompt Compromise" taxonomy v2.0.0-alpha (30 techniques, mapped to OWASP, ATLAS, SAIF, CSA), a "MoltThreats" agent threat feed, and paid "Agent Files" (malicious skills, instruction files). Paired with NOVA rules (`Nova-Hunting/nova-framework`, `nova-rules`, both MIT). Reuse licence for the data is not stated. https://promptintel.novahunting.ai/
- Hugging Face datasets (licence, last modified): `deepset/prompt-injections` (Apache-2.0, 2024), `Lakera/gandalf_ignore_instructions` and `mosscap_prompt_injection` (MIT, 2025-02), `hackaprompt/hackaprompt-dataset` (MIT, gated, 2024), `TrustAIRLab/in-the-wild-jailbreak-prompts` (MIT, 2024), `allenai/wildjailbreak` (ODC-BY, gated), `microsoft/llmail-inject-challenge` (MIT, 2025-05, the only large *indirect*-injection set). Most are 12-24 months stale and chat-centric, not tool-result-centric.
- Generators that stay fresh: `NVIDIA/garak` (Apache-2.0), `promptfoo/promptfoo` (MIT), `ethz-spylab/agentdojo` (MIT, last push 2026-06), `meta-llama/PurpleLlama`.

**Hallucinated-package squatting.** Spracklen et al., USENIX Security 2025: 576,000 samples across 16 models; hallucination rate at least 5.2% (commercial) and 21.7% (open-source); 205,474 unique invented names. https://arxiv.org/abs/2406.10279. No maintained public watchlist was found; only small checkers (`sloppy-joe`, `slopcop`, `slopcheck`).

**Model files.** Hugging Face exposes scan verdicts by API: `GET /api/models/{repo}?securityStatus=true` returns `securityRepoStatus.filesWithIssues[{path, level}]`, and `/tree/main?expand=true` returns per-file `securityFileStatus` with `avScan`, `pickleImportScan` and `protectAiScan` (threat IDs such as `PAIT-PKL-100`). Docs list ClamAV, pickle, secrets, Protect AI and JFrog scanners. Report links now point at `insights-db.paloaltonetworks.com`. Local tools: `protectai/modelscan` (Apache-2.0, last push 2026-09-28), `mmaitre314/picklescan` (MIT), `sigstore/model-transparency` (Apache-2.0).

**Frameworks and sharing bodies.** MITRE ATLAS data (`mitre-atlas/atlas-data`, Apache-2.0): YAML is authoritative (`dist/ATLAS-latest.yaml`), with generated STIX 2.1, Navigator layers and STIX Attack Flow bundles per case study. CoSAI publishes workstream papers and a risk map (`cosai-oasis/secure-ai-tooling`, Apache-2.0), not indicators. AI-ISAC: no primary source reached; treat as not available to build on.

**Attacker infrastructure and rogue model endpoints.** No AI-specific open feed found. Elastic's rules approximate it behaviourally (`command_and_control_genai_process_unusual_domain`, `..._suspicious_tld_connection`, `initial_access_ollama_api_external_access`).

### 2. How existing reputation services work

All four observed services (Snyk, Backslash, Cisco scanners, skills.sh ensemble) follow the same shape: enumerate from registries and GitHub, fetch source and tool manifests, run static patterns plus an LLM judge, emit a score and named findings. Common weaknesses: the verdict is keyed to a *name*, not a content digest, so "rug pull" updates and same-name-different-registry collisions are not addressed in the public outputs; scores are not comparable across vendors; none publishes false-positive rates except Cisco skill-scanner; none publishes bulk data; and local scanning requires executing the server.

Microsoft's approach is inventory-first: Defender for Endpoint discovers local agents and their MCP servers into the `AgentsInfo` advanced-hunting table (fields include `McpServers`, `DeclaredTools`, `RawAgentInfo.localAgentMetadata.autoApprove`, `trustedProcess`, `localMcps`) and the exposure graph (`ai-agent` nodes, `uses` edges to `mcp/server`). The pages read describe posture risk indicators, not an MCP reputation feed. https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents

### 3. How open rule repositories run

**Sigma** (rules DRL 1.1, spec public domain, spec v2.1.0 2025-09-12). Three rule types (generic, emerging-threats, threat-hunting) in separate top-level directories; five release packages built from `status` x `level` x type (`core` = test/stable + high/critical; `core+`, `core++`, ET add-on, all). Promotion to `test` needs roughly six months without FP reports. CI: schema validation, "goodlog" tests that run every rule over benign EVTX baselines (`NextronSystems/evtx-baseline` v0.8.5) with a `known-FPs.csv` allowlist, and regression tests where each test/stable rule points to `regression_data/.../info.yml` with a real event sample and an expected `match_count`. Release cadence slowed in 2026 to quarterly (r2026-01-01, r2026-04-01, r2026-07-01; nothing since). Not signed. Tag namespaces: attack, car, cve, d3fend, detection, stp, tlp.

**Elastic** (Elastic License 2.0). One TOML per rule with `[metadata] maturity`, `false_positives`, an investigation-guide `note`, `risk_score`, `severity`, tags from a controlled taxonomy (`Domain: GenAI`, `Mitre Atlas: AML.T0051`, `Resources: LLM` for rules that call a model and cost tokens). `version.lock.json` pins rule versions by content hash; rules release separately from tooling, per stack version (current v9.4, supports current-3). Tests include `test_all_rules.py` and `test_atlas.py`, with ATLAS vendored as `atlas-v2026.09.json.gz`. `PHILOSOPHY.md` requires documented known gaps and evidence that a rule fires.

**Splunk** (Apache-2.0, v6.10.0 on 2026-11-04, roughly weekly). YAML per detection built with `contentctl`: `version`, `status`, `type`, `data_source`, `how_to_implement`, `known_false_positives`, `analytic_story`, and `tests` pointing at replayable logs in `splunk/attack_data`. Every detection ends in a `<name>_filter` macro for local tuning without forking the rule. MCP detections require a specific add-on and sourcetype (`mcp:jsonrpc`): the "required telemetry" is declared in the rule.

**Falco** (Apache-2.0). `maturity_stable|incubating|sandbox|deprecated` tags, one rules file per tier, each ruleset versioned independently by semver and git tag (`falco-rules-5.2.0`), CI posts suggested version bumps, tested engine versions recorded in `FALCO_VERSIONS`, released as OCI artifacts with cosign keyless signatures declared in `registry.yaml` and pulled by `falcoctl`. High-cost rules cannot go beyond sandbox.

**Chainguard** `malcontent` organises YARA rules by behaviour (`c2`, `exfil`, `evasion`, `persist`), keeps a `false_positives` directory, and scores *diffs* between versions, which is the right primitive for rug-pull detection.

**Emerging agent-native rule formats.** Cisco `project-quarry` (Apache-2.0, v0.1.0-alpha, 2026-10-28): YARA-like DSL over messages, tool calls and event order, compiled to a symbolic finite-state automaton, RE2 only, explicit compile/time/model-call limits, exit code `2` for an incomplete scan. `arthur-ai/ai-detection-spec` (Apache-2.0, v0.17.1, created 2026-08-28): a discovery-signature catalogue (63 agents, 174 identifiers) where every identifier must be produced by a CI job that installs the real software; identifiers are `current` or `superseded` (still matched, no longer tested); output distinguishes "could not look" from "nothing there"; conformance vectors make two matchers agree.

### 4. Testing and staged rollout

CrowdStrike RCA (2024-08-06), six findings: field count not validated at compile time; no runtime bounds check in the Content Interpreter; tests used a wildcard in the 21st field; Content Validator logic error; Template Instances not tested in the interpreter; no staged deployment. Mitigations: canary testing, successive rings with bake-in time and telemetry gates, rollback, and customer control over where and when Rapid Response Content lands, with subscribable release notes. https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf

Microsoft Defender: platform and engine channels Beta, Preview, Staged, Broad, and "Critical: Time Delay" (48 h); security-intelligence updates only Staged/Broad, and the docs warn Staged is currently equivalent to Broad. AI agent runtime protection (Preview, 2026-09-25) recommends Test, Review 1-2 weeks, Deploy in Audit, then Block; Audit-mode alerts are Informational. https://learn.microsoft.com/en-us/defender-endpoint/configure-updates

BeyondTrust AI Agent Security (2026-10-13): policy "Replay" runs a draft policy over recorded activity from a past window to show what it would have blocked. https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security

### 5. Distribution and sharing standards

- **TUF** 1.0.37 (2026-10-08): root/targets/snapshot/timestamp roles, threshold signing, delegations by path, consistent snapshots; defends rollback, freeze, mix-and-match. Rust client: `awslabs/tough`. Server: `repository-service-tuf`.
- **STIX 2.1/TAXII**: ATLAS already emits STIX; an OpenCTI connector for OpenSourceMalware exists (`n1dhp/osm-opencti`). Export target, not authoring format.
- **OSV**: the right format for "this package/extension/server version is malicious"; needs new ecosystems for MCP and skills.
- **CSAF 2.1** is Committee Specification Draft 04 (2026-10-21), not yet a standard; has VEX, Withdrawn and Superseded profiles. **OpenVEX** spec is CC0.
- **CycloneDX** 1.7.2 (2026-09-17): no agent, MCP or skill types; Agent BOM (#895) and ASBOM (#941) proposals closed; #1015 (linking agent actions to BOM components) open. **SPDX** 3.0.1 is latest (3.1-RC1 since 2026-01); AI profile has `autonomyType` but no tool/agent structure. OWASP AIBOM Generator emits CycloneDX 1.6 for Hugging Face models; Cisco `aibom` inventories agents, tools and MCP servers from code. "AgBOM" has no standard body behind it.

### 6. Privacy-safe prevalence telemetry

DAP (`draft-ietf-ppm-dap-20`, 2026-10-20, "Waiting for Write-Up") gives two-aggregator secret-shared counts but is operationally heavy. The arthur spec shows a pragmatic pattern: one event per run sent from the *matcher*, never from endpoint scripts; values restricted to numbers, booleans and fixed vocabulary; `--telemetry-check` prints the exact event; off in CI; and the doc table is CI-checked against the code. It still sends source IP to a third party, which we should not copy.

## Matrix

| Source | Covers | Format | Licence | Cadence | Bulk access |
|---|---|---|---|---|---|
| OpenSSF malicious-packages | npm, PyPI, VS Code, Open VSX, others | OSV JSON | Apache-2.0 | Daily | Git |
| GitHub Advisory DB | Malware + vulns | OSV JSON | CC-BY-4.0 | Continuous | Git, REST |
| VS Marketplace removals | Extensions | Markdown table | MIT (repo) | Daily | Git (scrape) |
| MCP Registry | Server metadata, deletions | REST JSON | MIT to Apache-2.0 | Live | REST, hourly scrape asked |
| Hugging Face scan status | Model files | REST JSON | HF terms | Per commit | Per-repo API only |
| MITRE ATLAS | TTPs, case studies | YAML, STIX 2.1 | Apache-2.0 | Monthly | Git releases |
| PromptIntel / NOVA | Prompts, IoPC, rules | Web, API, NOVA | Data unstated; rules MIT | Unstated | API key |
| HF injection datasets | Prompts | Parquet | MIT / Apache / ODC-BY | Mostly stale | Yes |
| Snyk agent-scan | MCP, skills verdicts | JSON via API | Client Apache-2.0; data proprietary | Live | No |
| Backslash MCP hub | MCP scores | Web | Proprietary | Unstated | No |
| Socket threat feed | Packages | Dashboard/API | Proprietary | Seconds to minutes | Paid |
| Sigma | SIEM rules | YAML | DRL 1.1 | Quarterly (2026) | Git, zip |
| Elastic detection-rules | SIEM/EDR rules | TOML | Elastic License 2.0 | Per stack release | Git |
| Splunk security_content | SIEM rules + tests | YAML | Apache-2.0 | ~Weekly | Git |
| Falco rules | Runtime rules | YAML, OCI | Apache-2.0 | Per ruleset | OCI, cosign-signed |

## Weak points, gaps and risks

- Verdicts keyed to names rather than digests cannot express "v1.4.1 was fine, v1.4.2 is malicious", and remote MCP servers have no version at all.
- Vendor consolidation: `koi.ai` now redirects to a Palo Alto Networks Cortex page, and Protect AI's Hugging Face reports are served from a Palo Alto domain. Two of the seed sources are now one commercial vendor.
- Phrase-list injection detections (Splunk's MCP rule, Elastic's shell-coercion rule) are trivially evaded and noisy on security documentation; both say so in their FP notes. They are useful as low-severity signals only.
- ATLAS renumbering (e.g. v2026.10 moved "LLM Data Leakage" AML.T0057 under AML.T0085.002) silently breaks rule mappings and dashboards.
- LLM-judge detections are non-deterministic and cost tokens; Elastic already flags them with a dedicated tag. Without that flag, a content update can change a customer's bill.
- A content update that can block agent actions is a fleet-wide availability risk of the CrowdStrike kind, and for us the "kernel" is the developer's workflow: a bad block rule stops every coding agent in a company.
- Open contribution plus AI-written rules invites poisoned content (a rule that allowlists an attacker's server, or a "benign" corpus sample that teaches an exclusion).

## Implications for our design

**Content schema (one YAML file per item, JSON Schema validated).** Five `kind`s share one envelope: `detection`, `prevention`, `discovery-signature`, `indicator`, `reputation-verdict`.

```yaml
id: <uuid>            # stable forever
kind: detection
name: ...
version: 7            # integer, bumped by CI on logic change
status: experimental  # experimental | test | stable | deprecated | superseded
type: generic         # generic | emerging-threat | hunting
severity: high
confidence: medium
action_ceiling: audit # audit | ask | block ; block requires status: stable
cost: {llm_calls: 0, deterministic: true}
mappings: {atlas: [{id: AML.T0051, release: "2026.10"}], owasp_llm: [...], owasp_agentic: [...], attack: [...]}
requires:
  events: [agent.tool_call.pre, mcp.tools_list]   # our event taxonomy
  fields: [tool.name, tool.arguments, mcp.server.digest]
  sensors_any: [hook.claude_code, gateway.mcp, os.process]
  engine: ">=0.9"
logic: {...}           # language chosen by topic 20
tunables: [{name: allowed_servers, type: list}]   # Splunk-style filter hook
tests: [{corpus: positive/x.jsonl, expect: 1}, {corpus: negative/y.jsonl, expect: 0}]
false_positives: [...]
known_gaps: [...]
triage: ...
references: [...]
provenance: {authors: [...], evidence: ci-run-url}
license: Apache-2.0
```

**Repository layout.**

```
content/
  rules/{generic,emerging,hunting}/<domain>/<rule>.yml
  signatures/agents.yml  routes.yml          # discovery, arthur-style, proof by CI install
  intel/osv/{mcp,skill,vscode,npm,pypi}/...  # OSV records, our ecosystems
  intel/indicators/{domains,hashes,names}.jsonl
  corpora/{positive,negative,goodlog}/       # replayable agent sessions, inert samples
  mappings/atlas-<release>.json  owasp-*.json
  packs/{core,core-plus,experimental,emerging}.yml   # selectors, not copies
schema/  conformance/vectors.json  tools/  CODEOWNERS
```

**Pipeline.**
1. Lint and schema; mapping IDs checked against the vendored ATLAS release; licence and DCO check.
2. Compile with the *shipping* engine crate (same Rust code as the sensor, also built to WASM for CI). A rule that compiles in CI but not on the endpoint must be impossible. Enforce RE2-class regex, fuel and memory limits; fuzz the loader on every engine change.
3. Per-rule tests: at least one positive and one negative sample, and no test may rely on a wildcard for a field the rule constrains.
4. Goodlog replay: all rules over a corpus of benign sessions from Claude Code, Cursor, Codex, Copilot; any hit fails unless listed in a reviewed `known-fps` file.
5. Shadow backtest: opted-in fleets and the SaaS run the candidate in observe-only mode against stored events (BeyondTrust-style replay) and return only match counts and latency percentiles.
6. Rings: R0 project dogfood, R1 opt-in early adopters, R2 25%, R3 all, with bake times and automatic halt on engine errors, match-rate spikes or hook latency. Separate `standard` and `rapid` channels; rapid content is limited to `indicator` and `reputation-verdict` kinds and can never raise `action_ceiling`.
7. Publish as a TUF repository (targets delegated per pack; offline root; online timestamp). Offline bundle = a consistent snapshot tarball. Mirror to OCI with cosign for Kubernetes users.
8. Tenant controls: pin N-1/N-2, per-pack ring choice, 48 h delay channel, one-click rollback, per-rule mode override (audit/ask/block), and a built-in benign test string to prove the path works.
9. Engine guarantees: a malformed or over-budget rule is skipped and reported as "could not evaluate"; it never crashes the sensor and never silently passes.

**Reputation service.**
- Identity is content-addressed: package purl + artifact digest; MCP stdio server = purl + digest + hash of the canonical `tools/list` result; remote MCP = origin + TLS SPKI + tool-manifest hash (re-pinned on change); skill = repo + commit + tree hash; extension = `publisher.name@version` + VSIX sha256; model = repo@commit + file sha256.
- Record format: OSV with proposed ecosystems (`MCP`, `AgentSkill`), plus a VEX-style `status` (`malicious`, `suspicious`, `vulnerable`, `no-known-issue`, `withdrawn`) and an `evidence[]` array naming each scanner, its version, and its finding. Never a single opaque score.
- Inputs: OSSF/GHSA mirrors, marketplace removals, MCP Registry deletions, Hugging Face scan API, our own sandboxed scans (Cisco scanners, modelscan, malcontent diff between versions), typosquat distance to popular names, a hallucinated-name watchlist generated by sampling models, publisher/namespace verification, age and prevalence.
- Serving: signed full snapshot plus deltas through the same TUF channel (works offline); online lookups by digest-prefix so the server does not learn the exact item; endpoints never execute unknown servers to classify them.
- Run it, yes, in three parts: an open data repo (CC-BY-4.0), a self-hostable server, and a public instance. Aggregate third-party verdicts where licences allow; do not try to out-scan vendors.

**Contribution workflow.** Issue templates for detection gap, false positive, new agent, and malicious artifact report. PR must include rule, tests and evidence; CI posts suggested version bump and pack placement. New rules enter as `experimental` with `action_ceiling: audit`. Promotion to `test` and `stable` is data-driven (fleet prevalence, FP reports, age), proposed by a bot and approved by two CODEOWNERS for the domain; `block` ceilings need a third reviewer. Ship `add-rule`, `add-agent` and `release` skills in the repo so AI coding agents follow the same path (the arthur repo already does this). Samples in `corpora/` must be inert and are scanned before merge.

## Ideas worth stealing and whitespace

- Arthur's "proved by CI install" rule and `superseded` status for discovery signatures; "could not look" as a first-class result.
- Falco's per-ruleset semver with CI-suggested bumps and cosign-declared registry.
- Splunk's per-detection filter macro and declared data-source requirement; Elastic's `Resources: LLM` cost tag and mandatory known-gaps.
- Cisco's published FPR/recall per preset and a separate FPR-calibration tool across model releases.
- Chainguard's version-diff scoring as the rug-pull primitive.
- Whitespace: OSV ecosystems for MCP servers and skills; a digest-keyed, multi-scanner open verdict feed; a maintained slopsquatting watchlist; an indirect-injection corpus drawn from tool results rather than chat; a benign agent-session "goodlog" baseline (nobody publishes one); an ATLAS tag namespace for Sigma; an agent BOM profile for CycloneDX.

## Could not verify / open questions

- AI-ISAC status and any MITRE AI incident-sharing data format (`ai-incidents.mitre.org` failed TLS; the CISA page returned unreliable text).
- Koi's current feed or API (domain redirects to Palo Alto Networks); Pillar's MCP registry (no reachable URL); Socket's API reference and redistribution terms; OpenSourceMalware.com (JavaScript-only page).
- Whether the hallucinated-package dataset from the USENIX paper is published.
- Reuse terms for PromptIntel data and for Hugging Face scan results at scale.
- CrowdStrike's current content-control documentation (behind login).
- Whether Sigma's slower 2026 release cadence is a pause or a policy change.
- No news search was possible, so recent incident-specific indicator sets (individual campaigns) are not inventoried here.

## Sources

- https://github.com/ossf/malicious-packages - OpenSSF Malicious Packages (2026-11-09); stats https://ossf.github.io/malicious-packages/stats/total.json
- https://github.com/ossf/osv-schema/blob/main/docs/schema.md - OSV schema ecosystems (2026-11-05)
- https://github.com/github/advisory-database - GitHub Advisory Database (2026-11-09)
- https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md - Removed extensions (2026-11-09)
- https://github.com/eclipse-openvsx/openvsx - Open VSX server (2026-11-09)
- https://github.com/modelcontextprotocol/registry - MCP Registry docs: moderation-policy, registry-aggregators, proposed-enhanced-validation (v1.8.8, 2026-11-06)
- https://github.com/snyk/agent-scan - README, docs/scanning.md, docs/risks.md (v0.6.11, 2026-11-06)
- https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ - ToxicSkills (2026-02-05)
- https://github.com/cisco-ai-defense/mcp-scanner , /skill-scanner , /project-quarry , /aibom (2026-11)
- https://mcp.backslash.security/ - Backslash MCP Server Security Hub (fetched 2026-11-09)
- https://skills.sh/audits - skills.sh audits (fetched 2026-11-09)
- https://promptintel.novahunting.ai/ ; https://github.com/Nova-Hunting/nova-framework - PromptIntel and NOVA (2026)
- https://docs.socket.dev/docs/threat-feed - Socket Threat Feed (fetched 2026-11-09)
- https://huggingface.co/docs/hub/security ; https://huggingface.co/docs/hub/security-protectai ; https://huggingface.co/api/models/mcpotato/42-eicar-street?securityStatus=true (fetched 2026-11-09)
- https://github.com/mitre-atlas/atlas-data - ATLAS data, release v2026.10 (2026-10-28)
- https://arxiv.org/abs/2406.10279 - Package hallucinations (USENIX Security 2025)
- https://github.com/arthur-ai/ai-detection-spec - README, docs/signature-lifecycle.md, docs/telemetry.md (v0.17.1, 2026-11-06)
- https://github.com/SigmaHQ/sigma - Releases.md, regression_data/README.md, workflows (r2026-07-01); https://github.com/SigmaHQ/sigma-specification (v2.1.0, 2025-09-12)
- https://github.com/elastic/detection-rules - PHILOSOPHY.md, docs-dev/versioning.md, docs-dev/rule-tag-taxonomy.md, rules/cross-platform/execution_prompt_injection_coercing_shell_execution.toml (2026-10/11)
- https://github.com/splunk/security_content - detections/application/mcp_prompt_injection.yml (v6.10.0, 2026-11-04)
- https://github.com/falcosecurity/rules - RELEASE.md, CONTRIBUTING.md, registry.yaml (falco-rules-5.2.0, 2026-09-07)
- https://github.com/chainguard-dev/malcontent (2026-11-09)
- https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf (2024-08-06)
- https://learn.microsoft.com/en-us/defender-endpoint/configure-updates (2026-09-15)
- https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection (Preview, 2026-09-25)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents (2026-11-02)
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai (2026-10-30)
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (2026-08-19; GA 2026-05-01)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (2026-10-13)
- https://theupdateframework.github.io/specification/latest/ - TUF 1.0.37 (2026-10-08); https://github.com/awslabs/tough
- https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html - CSAF 2.1 CSD04 (2026-10-21)
- https://github.com/CycloneDX/specification - 1.7.2 (2026-09-17), issues #895, #941, #1015; https://github.com/spdx/spdx-3-model
- https://github.com/GenAI-Security-Project/aibom-generator - OWASP AIBOM Generator (2026-10)
- https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/ - DAP draft-20 (2026-10-20)
- https://github.com/cosai-oasis - CoSAI workstream repositories (2026-11)

## Independent verification

_Checked 2026-11-09/10 by a separate fact-checker against primary sources (GitHub API via `gh`, the source PDF, datatracker API, vendor docs). Each claim was tested for refutation; none of the ten was refuted. Notes carry the caveats the architecture should respect._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | OSV schema has no ecosystem for MCP servers, agent skills or model files; it has `VSCode` (with Open VSX variant) and `GitHub Actions` | Confirmed | Full ecosystem table read (AlmaLinux to WordPress): no MCP, skill or model entry. `VSCode` takes an optional `:<REMOTE-REPO-URL>` suffix, e.g. `VSCode:https://open-vsx.org`. An open proposal exists: osv-schema issue #568 "ecosystem for AI agent skills (MCP / agent skill registries)", opened 2026-06-21, 7 comments, not merged. Two ID-prefix requests for MCP advisories (#627, #643) were closed. | https://github.com/ossf/osv-schema/blob/main/docs/schema.md ; https://github.com/ossf/osv-schema/issues/568 |
| 2 | OpenSSF malicious-packages: Apache-2.0, OSV, 240,309 reports, pushed daily, has `vscode` and `vscode:open-vsx.org` | Confirmed | Licence Apache-2.0 (API). `stats/total.json` returns 240309. Directories include `vscode` (4 entries) and `vscode:open-vsx.org` (17). "Daily" understates it: several ingest commits per hour (last push 2026-11-10T05:20Z). | https://api.github.com/repos/ossf/malicious-packages ; https://ossf.github.io/malicious-packages/stats/total.json |
| 3 | MCP Registry: preview, "minimal-to-no moderation", does not remove vulnerable servers, removal = `status: "deleted"` with metadata readable | Confirmed | All four statements are verbatim in the moderation policy. Extra caveat in the same file: "in extreme cases" metadata may be overwritten or erased, so a deleted record is not guaranteed to stay readable. Latest release v1.8.8 (2026-11-06). | https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/moderation-policy.mdx |
| 4 | Snyk agent-scan starts stdio servers, contacts remote URLs, needs a Snyk token, sends configs, tool signatures and skills to a server-side API | Confirmed | README "Security Warning" says exactly this. Qualifiers: interactive runs ask per-server consent; background and push-key scans contact remote servers automatically but do not start stdio servers unless `--dangerously-run-mcp-servers`; secrets are redacted before upload; it sends skill *content*. v0.6.11 (2026-11-06), analysis API `2026-07-10`, Apache-2.0. Bulk use of the API is called abuse. | https://github.com/snyk/agent-scan/blob/main/README.md |
| 5 | CrowdStrike Channel File 291 RCA: six findings incl. 21 vs 20 inputs, missing bounds check, wildcard-only tests, Content Validator logic error, no staged deployment; mitigations canary, rings with bake time, customer control | Confirmed | PDF text extracted and read. Findings 1-6: field count not validated at compile time; missing runtime bounds check; test coverage (wildcard in 21st field); Content Validator logic error; Template Instances not tested in the Content Interpreter; staged deployment. Mitigations name canary testing, successive rings with "bake-in time", rollback, customer control of where and when, and subscribable release notes. | https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf |
| 6 | Sigma rules DRL 1.1; Elastic rules Elastic License 2.0; Splunk security_content, Falco rules, malcontent Apache-2.0 | Confirmed, with one caveat | All five LICENSE files read. Caveat for embedding: malcontent's *code and own rules* are Apache-2.0, but the "14,500+" figure includes bundled third-party YARA under other terms: Elastic protections-artifacts (Elastic License 2.0), TTC-CERT (no licence), YARA Forge (mixed), plus MIT and BSD-3 sets. The CLI flag `--third-party` is documented as "may have licensing restrictions". Do not redistribute that directory as Apache-2.0. | https://github.com/SigmaHQ/sigma/blob/master/LICENSE ; https://github.com/elastic/detection-rules/blob/main/LICENSE.txt ; https://github.com/chainguard-dev/malcontent/blob/main/third_party/README.md |
| 7 | Falco rules: per-ruleset semver, `maturity_*` tiers, OCI artifacts with cosign keyless signatures declared in `registry.yaml` | Confirmed | RELEASE.md, CONTRIBUTING.md, registry.yaml and release.yaml all agree; the release workflow signs with a GitHub OIDC token. Detail: `registry.yaml` carries a cosign block for the stable, incubating and sandbox rulesets only. The deprecated ruleset has no signature block and its file now sits in `archive/`, so there are three signed, live tiers. Latest tags falco-rules-5.2.0 and falco-sandbox-rules-6.2.0 (2026-09-07). | https://github.com/falcosecurity/rules/blob/main/registry.yaml ; https://github.com/falcosecurity/rules/blob/main/.github/workflows/release.yaml |
| 8 | ATLAS data: Apache-2.0, YAML-authoritative, monthly, v2026.10 on 2026-10-28 with 129 techniques, IDs move between releases | Confirmed | LICENSE and README confirm licence and YAML authority. Release notes and a count of the YAML give 129 techniques and 92 sub-techniques. Monthly cadence is a stated policy only since v2026.05 (2026-05-27); earlier releases were semver v5.x at irregular intervals, and actual gaps since run two to six weeks. Stronger than the brief says: AML.T0056 and AML.T0057 are absent from the v2026.10 YAML with no tombstone or redirect field, so a stale mapping fails lookup rather than resolving. `dist/ATLAS-latest.yaml` is a symlink to `dist/v6/`. | https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.10 ; https://github.com/mitre-atlas/atlas-data/blob/main/CHANGELOG.md |
| 9 | CycloneDX 1.7.2 has no agent, MCP or skill component type; #895 and #941 closed in 2026; SPDX 3.0.1 latest | Confirmed | 1.7 component `type` enum has 13 values, none agent-related. 1.7.2 released 2026-09-17. #895 closed 2026-04-29 with the maintainer note that agentic AI is being handled in the Blueprints and Threat Modeling working groups; #941 closed 2026-05-29; #1015 open. The `2.0-dev` branch has new `behavior`, `blueprint` and `ai-ml` modules but no agent, MCP or skill type found by search, so 2.0 is the place to watch. SPDX: 3.0.1 (2024-12-12) is the latest full release; 3.1-rc1 (2026-01-24) is a pre-release. | https://github.com/CycloneDX/specification/releases ; https://github.com/CycloneDX/specification/issues/895 ; https://github.com/spdx/spdx-3-model/releases |
| 10 | DAP is still an Internet-Draft (draft-ietf-ppm-dap-20, 2026-10-20), not an RFC | Confirmed | Datatracker API: rev 20, timestamp 2026-10-21T01:02Z, no standards level; WG state "Waiting for Write-Up" with "Revised I-D Needed" noted, so a -21 is likely before IESG review. The working-group repo has tag `draft-ietf-ppm-dap-20`. | https://datatracker.ietf.org/api/v1/doc/document/draft-ietf-ppm-dap/ ; https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/tags |

### Further statements checked in the brief

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Section 3, Sigma: "Promotion to `test` needs roughly six months without FP reports" | Corrected | The only promotion rule in the repo is `tests/promote_rules_status.py`: `nb_days = 300`, measured from the rule's `modified` (or `date`) field, with no false-positive input at all. The scheduled workflow that ran it (`sigma-rule-promoter.yml`) is fully commented out, so promotion is currently manual. Neither the spec nor sigmahq.io states a time period. Treat Sigma as "age-based, 300 days unchanged, automation disabled", not as an FP-driven six-month gate. | https://github.com/SigmaHQ/sigma/blob/master/tests/promote_rules_status.py ; https://github.com/SigmaHQ/sigma/blob/master/.github/workflows/sigma-rule-promoter.yml |
| TL;DR and section 3: Sigma tag spec has no ATLAS namespace; 2026 releases are quarterly with nothing since r2026-07-01 | Confirmed | Namespaces in `sigma-appendix-tags.md`: attack, car, cve, d3fend, detection, stp, tlp. Releases: r2026-01-01, r2026-04-01, r2026-07-01; none later as of 2026-11-10. | https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-tags.md ; https://github.com/SigmaHQ/sigma/releases |
| Sections 4 and 5: Microsoft Defender signature `1.451.224.0`, `Disabled/Audit/Block`, benign test string; BeyondTrust policy replay; Agent 365 GA 2026-05-01; TUF 1.0.37; CSAF 2.1 CSD04 | Confirmed | Microsoft page (ms.date 2026-09-25, Preview) matches, and adds two things the brief omits: there are two separate switches (`AiAgentProtection` for agent-native events, `AiAgentNetworkInspection` for network inspection), and preview devices must take platform and engine updates from the Beta channel. BeyondTrust page (2026-10-13) describes replay of recorded activity before saving a policy; enforcement is a kernel and network level endpoint agent on Windows and macOS, with hooks as an addition. Agent 365 page states GA "as of May 1, 2026". TUF spec header: 1.0.37, 2026-10-08. CSAF 2.1 title block: Committee Specification Draft 04, 21 October 2026. Snyk ToxicSkills figures (3,984; 36.82%; 13.4%; 76; 91%) also match the source. | https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection ; https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security ; https://learn.microsoft.com/en-us/microsoft-agent-365/overview ; https://github.com/theupdateframework/specification |
