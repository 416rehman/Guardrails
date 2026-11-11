# Review L10: simplicity auditor

Lens: remove scope and complexity from the whole spine. Briefs: 11, 15, 20, 23, 24, 27, 28, 30, 31, 33, 38, g10. Reviews c1, c2, c5 and c9 cover storage, policy semantics, transport and milestones; I cite them and do not repeat them.

## Summary

Most decisions are defensible alone. The total is not. Counted from the spine:

| What | Count | Reference |
|---|---|---|
| Named vocabulary terms in section 3 | 26, with 44 enumerated values | 33 recommends 11 objects |
| Grading scales a reader meets | 9 (boundary or request, AL, tamper grade, attribution basis, identity assurance, provenance grade, confidence, two severity axes) | |
| Endpoint artefacts in section 5 | 10, with 5 long-lived processes in D-20's target topology and up to 3 kernel or system components | |
| Server targets | 14; brief 24 listed 13, and the lists differ in seven names | |
| External services in HA | Stated as 3; D-35, D-36, D-38, D-39, D-40 and D-29 add KMS, TUF origin, IdP, witness, gateway and model endpoint: 9 | |
| Crates and packages in section 5 | 52, before a line of code | |
| Rule and expression languages | 5 (Cedar, Sigma, Sigma correlation, YARA-X, CEL), Dogwood later | |
| External-format adapters | About 60 across nine families (D-06, D-12, D-14, D-27, D-38, D-41 L0, L1, L3, D-46) | |

Nothing says which of this the first two milestones need, and M1 never exercises the product's thesis. The change that matters most: give every decision a horizon and write design documents only for the near one.

## Findings

### 1. Blocker, over-built. All of section 4: 47 decisions at equal weight

**Problem.** Thirty design documents will be written from a spine in which 14 decisions, or large parts of them, are not needed before M3: D-04, D-12 (beyond two targets), D-26, D-27 (beyond helper protocols), D-29 tiers 3 to 5, D-32, D-35 (cells, delegated access, key modes 3 and 4), D-39 (beyond the chain), D-40 tiers 2 and 3, D-41 L2 to L6, D-43, D-46 crosswalks, D-17 phase 1, D-18 tiers 2 and 3. Their inputs are moving: Rune is 19 days old, Dogwood four weeks, OTel GenAI has no tagged release.

**Evidence.** 11 digest (TensorZero and MinIO archived within a year of being default picks); 31 "Weak points" ("Anything bespoke we build may be dead weight in months"); 30 digest (Astryx: 47 releases in 136 days, 26 breaking migrations in one minor).

**Amendment.** Add to the decision format: "Horizon: Now (M0 to M2, gets a design document), Next (M3, one page stating only the seam it needs today), Later (M4 onward, this paragraph plus a trigger). A Later decision may constrain Now work only through a named seam: a port, a reserved proto field or a pack type."

### 2. Major, missing. Section 7: no thin slice tests the thesis

**Problem.** M1 is hooks plus local policy on three operating systems for four agents. D-01's own rationale says open hook guards already do that, and P1 calls it a request. The claims that distinguish the product (P3, D-13 cross-check, D-25 session container, D-24 pass 3) first run inside an eleven-item M2.

**Evidence.** 31 section 1 (parallel agents need an oracle); 31 verification (hosted Linux x64 runners have KVM); c3 F8 and c4 F3 both rate the cross-check and loop evidence as unproven.

**Amendment.** Add slice S0 as the M0 exit: "Linux x64 only. Claude Code plus one scripted bespoke agent (a Python loop over a model SDK). Hook shim to daemon to `grd-core` verdict; one cgroup-v2 scope per session; observe-only exec, open and connect from that scope; a finding when the scope acts with no matching tool call; the bespoke agent found by passes 2 and 3; SQLite history; `grd` CLI; one three-pass harness scenario per claim. No server, tray, console, sandbox, proxy or second operating system." M1 widens S0; it does not start beside it.

### 3. Major, missing. No definition of "complete": support tiers

**Problem.** The owner says the product cannot be incomplete. The spine answers with breadth: nine host kinds, at least four agents, five control points, five assurance levels. A matrix that size will be incomplete everywhere.

**Evidence.** 28 design implications (Falco-style maturity tiers for content); 15 "Weak points" ("adapters need version probes and conformance tests, not static assumptions"); 31 (start at three to five writers).

**Amendment, new decision.** "Every agent adapter, host target, control point, integration and dialect has a support tier. Tier 1: first-party, release-blocking, in the conformance suite and scorecard. Tier 2: community manifest or adapter, conformance-gated, may lag. Tier 3: experimental, off by default. Complete means every Tier 1 cell reaches its stated assurance level with zero silent fail-open. Tier 1 at M1 is Claude Code and Codex on Linux x64 and macOS arm64. Promotion needs a named maintainer and 30 green days."

### 4. Major, over-built. Adapter fan-out has no budget

**Problem.** About 60 adapters each track an external format that changes without notice.

**Evidence.** 23 digest (OTel GenAI: about 20 pending breaking changes); 15 "Weak points" (three vendors moved documentation domains this year); 27 digest (Defender-passive fleets are the opening, which sets the order).

**Amendment, new decision.** "Each adapter family ships two first-party members in the milestone where it first appears; the rest arrive as manifests through the content lane." First two: D-12 Claude Code managed settings and Codex `requirements.toml`; D-14 Claude Code dialect and Codex translator; D-06 OCSF export and OTel GenAI ingest; D-41 L0 Sigma and LogScale; L3 Rust crate and C ABI; D-38 Connect and generated OpenAPI; D-27 git and model-key helpers; D-46 SOC 2 and EU AI Act deployer duties. Lost: launch-day breadth against Defender's 60 named agents.

### 5. Major, over-built. Section 3: no surface vocabulary, and the spine breaks its own synonym rule

**Problem.** Section 3 says Posture; D-44 says mode ladder. Section 3 says Grant; D-31 says approval, D-44 exception. A casual user is given no smaller set.

**Evidence.** 33 "Core vocabulary" (11 objects) and "Progressive disclosure" (Simple view is packs as switches).

**Amendment.** "Each term is marked Surface or Internal. Surface, shown in Simple view, tray and default CLI output: Agent, Session, Action, Pack, Rule, Mode, Approval, Finding. Mode replaces Posture everywhere. Grant is the API noun; the interface says Approval or Exception. Case is deleted: an Incident has an owner and a status. Of the grading scales, Simple view shows only the assurance level name."

### 6. Major, over-built. D-33 and D-34: 14 deployable targets and an undercounted dependency list

**Problem.** A deployable target is an internal API with version skew. Fourteen are promised before any load number exists.

**Evidence.** 24 verification row 3 ("plan N replicas of all as a tested shape"); 24 TL;DR (Fleet serves 100,000 hosts from 25 one-vCPU tasks); g10 (the 5,000-event figure is an assumption, so even at ten times that, 10,000 endpoints is under 6,000 events a second).

**Amendment.** D-33: "Targets are module boundaries. Supported shapes through M3 are `all` and N replicas of `all`. A target becomes its own process only when a load test names it as the bottleneck; `ingest` and `query` are the first candidates." D-34: "KMS, update origin, witness, gateway and model endpoint each have a built-in default, so HA requires no external service beyond the three named." Lost: independent scaling of small roles.

### 7. Major, wrong. Section 5 contradicts D-10 and P5

**Problem.** `grd-llm-proto` and `grd-mcp` sit in the adapter layer, yet D-10 calls them security-critical normalisers with reference models and P5 runs the core in gateways. "Adapters do not depend on each other" cannot hold for `grd-proxy`, `grd-wire`, `grd-opamp` and `grd-crypto`.

**Evidence.** 38 design implication 1 (one core crate holding provider, MCP and A2A parsers, compiled into proxy, gateway, shim and WASM).

**Amendment.** "Layer 1 gains `grd-llm-proto` and the parsing half of `grd-mcp`. `grd-crypto` and `grd-wire` move to Layer 2 as shared libraries. Adapters depend on each other only through Layer 2. The workspace starts at no more than 20 crates; a crate is split when it gains a second consumer or a different licence."

### 8. Major, over-built. Two mechanisms, one job

See the merge rows in the cut list. The largest: four carriers change sensor behaviour (OpAMP remote config, TUF-verified packs, D-12 generated settings, the binary updater) across three ring channels. **Amendment to D-36 and D-37:** "Everything that changes sensor behaviour except a response command is one signed bundle type with one verifier and one last-known-good store. The control channel announces desired digests and reports health." Evidence: 24 verification row 2 (OpAMP leaves signing to us); c5 finding 3.

### 9. Major, over-built. D-35 and D-39: research-grade features with no stated demand

**Problem.** HPKE-sealed fields with blind-index search and co-signed policy, and a witnessed tile log with SCITT receipts, defend against a malicious operator. P11 already gives that customer the answer: self-host.

**Evidence.** 23 TL;DR ("cryptographic proof is a differentiator rather than a compliance requirement"); P8 (metadata-only default leaves little to seal).

**Amendment.** D-35: two key modes, operator KMS and customer-managed key. D-39: "sensor hash chain, a signed checkpoint per batch written to object-locked storage, and an offline verifier." The rest becomes Later with the trigger "a paying hosted customer requires it".

### 10. Minor, missing. Three places the spine waves at a hard problem

- **D-11.** SymCC needs an external `cvc5` binary that links LGPL GMP by default (20 findings, "Weak points" and verification row 1). Add: "Symbolic analysis runs only in the server `control` target and `grd policy check`. It never runs on a sensor. Standalone has no ceiling proof."
- **D-20.** "Process topology by deployment" is unbounded. Add: "Exactly two topologies are tested: `user` (one daemon) and `managed` (privileged core plus engine). The proxy and broker split out when credential injection ships."
- **No removal policy.** Add: "Any adapter or feature without a Tier 1 owner for two releases is demoted, then removed" (31: "delete what no longer pays").

## Cut list

| Cut or merge | Action | What is lost |
|---|---|---|
| Rune console (D-43) | Defer behind c9's soak spike; tray plus localhost web console | Native window at first release; the owner asked for Rune, so this is a delay |
| `Search` port (D-34) | Merge into lake scans plus relational full-text | Fast free-text over captured content |
| CEL in manifests (D-09) | Delete; manifests are match tables | Computed mappings, written as analysers instead |
| OpAMP wire, dictionary zstd, priority lanes (D-36) | Later | Nominal OpAMP interoperability; kilobytes a day |
| Detection tiers 3 to 5 (D-29) | Later; ship rules and one small model | LLM triage in early releases |
| Standards stack in D-27 | Later; keep helper protocols and leases | Standards-shaped delegation evidence |
| WASM and out-of-process integration tiers (D-40) | Later; manifests only | Third-party code integrations |
| L4 to L6 and four language bindings (D-41) | Later | White-label and cloud-connector deals before M4 |
| D-32 reputation service, D-26 outward tagging | Later | Digest reputation; agent-separated cloud logs |
| Boundary or request label, tamper grade | Merge under the assurance level in the interface | Nothing |
| `Case` (section 3) | Merge into Incident; export to ticketing | In-product notes and evidence bundles |

## Spikes

| # | Question | Method | Pass |
|---|---|---|---|
| 1 | Does S0 hold end to end? | Build it with three writers; 100 benign Claude Code sessions plus 20 scripted bypasses | Every bypass flagged; "no matching tool call" false rate under 1%; bespoke agent found; hook p99 under 30 ms |
| 2 | Does one process carry a fleet? | `--target=all` on 4 vCPU; synthetic 10,000 endpoints at 5,000 and at 100,000 events a day | Ingest under 50% CPU; detection lag under 5 s; session timeline under 2 s |
| 3 | Is eight terms enough? | Five developers use the S0 CLI and a paper Simple view to find a session and block one action | Done in ten minutes without documentation; no Internal term needed |
| 4 | How fast do adapters rot? | Replay 90 days of the four agents' releases against frozen hook and settings adapters | More than one break per adapter per month keeps the budget at two |

## Agreed

- D-05 sans-IO core: every cut above relies on it.
- P6 two adapters per port.
- D-08 one enforced authorisation language, no Dogwood interpreter.
- D-16 no mandatory TLS interception.
- D-17 driverless Windows first.
- D-34 no ClickHouse, Kafka, Redis or graph database.
- D-40 integrate agentgateway instead of writing a gateway.
- D-02 one licence, one build matrix.
