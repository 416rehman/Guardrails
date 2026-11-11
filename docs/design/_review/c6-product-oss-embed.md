# Review C6: product shape, licensing, open-source model, embedding

Scope: D-01 to D-04, D-40, D-41, P11, P12. Reviewed 2026-11-10 against the briefs cited below. Re-read today at source: the AAIF project lifecycle policy and Regulation (EU) 2024/2847.

## Summary

Apache-2.0 everywhere survives the challenge. The promises built around it do not. The naming plan contradicts the foundation plan and freezes a company name into wire identifiers that embedders compile against. The revenue list in D-04 sells things the covenant gives away. Embedding is scheduled in reverse of the evidence, and the gateway decision contradicts D-33 and P4. The change that matters most: separate a neutral, coined project name from the "Guardrails ADR" distribution before the first public commit, because it is irreversible.

## Findings

### 1. Name and marks contradict the foundation plan (D-03, section 3 names, D-41). Wrong, blocker

**Problem.** D-03 says the protectable mark is "Loonaro" and conformance marks build on it, and also promises to transfer the trademark to a foundation. A foundation takes the project's marks; Loonaro cannot hand over its house mark, and "Guardrails" alone is descriptive and taken. Section 3 meanwhile fixes `loonaro.guardrails.v1`, the Cedar namespace `Guardrails`, `libguardrails` and `guardrailsd` as wire and ABI identifiers.

**Evidence.** AAIF lifecycle policy, Sandbox acceptance criteria (marks go to the LF at entry); brief 28 verifier row 2. GitHub today: `guardrails-ai/guardrails` (7,594 stars, owns the `guardrails` import and CLI) and `NVIDIA-NeMo/Guardrails` (7,463).

**Amendment.** Add D-03a: "The upstream project carries a coined, vendor-neutral name, cleared by trademark and namespace search before the first public commit. 'Guardrails ADR' names Loonaro's distribution and hosted service. Every wire and ABI identifier uses the project name, never 'loonaro'. Conformance marks belong to the project and move with it; Loonaro sells testing services, not the mark."

### 2. Foundation timing and the D-02 revisit clause cannot both hold (D-03, D-02, section 7 M5). Wrong, major

**Problem.** AAIF takes the marks at Sandbox entry and discusses archival if the project has not applied for Growth within twelve months. Growth needs commits from two organisations over six months, which a single-writer agent fleet (D-47) will not produce unaided. Section 7 places transfer at M5. D-02's revisit clause relies on trademark control that D-03 gives away and on a relicence the covenant excludes.

**Evidence.** AAIF policy, Sandbox expectations and "Graduation to Growth"; brief 28 verifier rows 2 and B.

**Amendment.** D-03 trigger: "Transfer on the earlier of (a) two unaffiliated production adopters plus one external committing organisation, or (b) 18 months after first public release. Until then a springing assignment of mark, domain and GitHub organisation sits in escrow. Do not enter AAIF Sandbox before external commits exist." D-02 revisit: "Never after first public release; hold a go or no-go review before it."

### 3. D-04 sells what P11 and the covenant give away (D-04, P11, D-32). Wrong, major

**Problem.** Paid "signed LTS builds" contradict "binaries under the same licence as source". Paid "embargoed notices" make security a tier. The conformance mark leaves with the trademark. A "reciprocity-tiered" feed contradicts D-32 ("open", published as OSV). Multi-tenancy, the provider tier and white-label are free, so MSPs need not pay. No price unit or viability gate exists.

**Evidence.** Brief 28 weak points ("close to feature withholding"; "no legal defence" against others hosting). CRA Annex I Part II(8): security updates free and without delay. Brief g10 section 1: modelled cost USD 0.28 to 1.00 per endpoint-month. Brief h04 section 4: anchors USD 15 to 20 per user.

**Amendment.** Rewrite D-04: "Paid: hosting at a published per-user price; support; LTS maintenance beyond the public window; OEM services (integration engineering, private conformance runs, warranty, a tailored CRA due-diligence file); the intelligence service. Every intelligence record is public after a fixed delay; contributors and payers get it live. Vulnerability pre-disclosure is free to any redistributor." Add to P11: "Exceptions: signing keys, the held-out corpus, intelligence freshness." Docs become `Apache-2.0 OR CC-BY-4.0`.

### 4. L3 has bindings but no contract a sensor vendor can accept (D-41). Missing, major

**Problem.** Missing: a sidecar for vendors who will not link foreign code; ABI negotiation; behaviour when a pack is malformed inside the host; bounded evaluation; an engine latency target; a support period covering the partner's own five-year duty; provenance for agent-written code; liability. Five bindings are over-built for a first release.

**Evidence.** Brief 27 Part 5 (sidecar; three version numbers) and weak points ("inherits their availability blame"). Brief 28 weak points (embedders' lawyers and agent-built code). CRA Art. 13(5) and 13(8) against D-37's window.

**Amendment.** Add D-41a: "Artefacts: crate, C ABI, WASM and a sidecar daemon; other bindings follow demand. Engine, load-time ABI and content schema versions are independent. No panic crosses the boundary; evaluation is fuel- and memory-bounded; a rejected pack leaves last-known-good active. Targets: p99 under 200 microseconds per event, under 30 MB. One LTS line a year with five years of security fixes. Permissive-only dependency closure with SBOM and provenance scan. Warranty and indemnity only under the OEM agreement."

### 5. The cheapest rungs are scheduled last (D-41, D-40, section 7). Wrong, major

**Problem.** Content compilers, the provider interface and the SDK sit in M4 and integrations in M3, although D-40 says importers "ship first". D-17 makes the owner's WESP requirement depend on an MVI member embedding L3, yet no partner search appears among the external lead times. L2's demand is unproven: Claude Code already merges vendors' hooks with deny winning.

**Evidence.** Brief 27 matrix (rung 1: high feasibility, low effort), implication 6 ("Deliver rung 1 immediately"), weak points ("we own nothing"), verifier row 4.

**Amendment.** Section 7: "M1: L0 for process, file and network rules, and L1 feeds. M2: the four importers and the Microsoft L4 connector. From M0: recruit one MVI-member or MDR design partner for an L3 sidecar pilot, listed under external lead times. L2's third-party interface waits for spike 1. L6 last."

### 6. Integrating with agentgateway leaves a hole and contradicts D-33 (D-40, D-33, P4). Risky, major

**Problem.** D-33 lists a `gateway` target; D-40 says we do not write one. Through agentgateway our policy is a remote guardrail call, so P4's "evaluated in the gateway from signed, cached bundles" is untrue there and the fail mode is the host's. The gateway is the only control point for unmanaged machines and server-side agents, and an actuator for the kill switch (D-30) and credential injection (D-27). The hosted service names no operator for it.

**Evidence.** Brief 38 section 5 (CEL plus remote "ExtMCP") and implication 1. GitHub today: GHSA-mvgg-jvj2-4frq (high) and GHSA-7hv4-jgp9-mgx2, sessions crossing routes overwrite authorisation and `mcpGuardrails`. Brief h08 implication 8.

**Amendment.** D-40: "The `gateway` target is `grd-proxy` in server mode: an enforcement point for LLM routes and MCP over HTTP with in-process Cedar, fail-closed defaults, kill-switch and credential actuators, not a routing or key-management gateway. agentgateway, Agent Router, Kong and LiteLLM are adapters; each declares its verbs and fail mode, and a host that can fail open is reported as a request, not a boundary." Otherwise delete `gateway` from D-33 and record the hole.

### 7. No wedge against free and bundled offerings; M1 standalone is a me-too (D-01, P12). Risky, major

**Problem.** M1 standalone (hooks, local policy, history, catalogue discovery for four agents) is what free Apache-2.0 tools ship today; our distinguishing parts land in M2. OpenShell, the largest free overlap with D-21, is absent from the spine. On fleets where Defender is passive, CrowdStrike's bundled product is the rival. D-14's admin-only install conflicts with "one developer, no account".

**Evidence.** Brief h04 section 1 (Numbat, DefenseClaw, SolonGate, Prempti; OpenShell 21,332 stars) and implication 1. Brief g02 section 2. Brief g03 (Falcon Guardian GA, no Linux statement).

**Amendment.** Add D-48: "We lead where bundled products are absent: native Linux, WSL, Kubernetes and CI; unregistered agents; offline local decisions; Codex and Cursor enforcement; self-hosting; published efficacy. We ingest from and export policy to OpenShell, DefenseClaw, Numbat and Prempti." D-01: "Standalone is a mode of the one daemon. M1 includes hook-against-OS reconciliation and building-block discovery. User-scope installs are allowed and labelled tamper grade `user`. Revisit 90 days after M2 against a stated conversion target."

### 8. Manufacturer duties start earlier and reach further than D-46 assumes (D-46, D-04). Missing, major

**Problem.** Once anything is monetised, the free sensor and standalone build are manufacturer products, the hosted server is remote data processing within the product, and reporting is already in force. Self-assessment needs public technical documentation when the product is placed on the market, which is the M3 hosted beta. D-27's broker may add a Class I category. Product liability appears nowhere.

**Evidence.** Brief 28 verifier rows 3 and 4 (guidance point 54; Art. 32(5) timing). CRA Art. 3(2), 13(8), 13(9), 14. Brief 34 weak points. Directive (EU) 2024/2853 applies from 9 December 2026 per law-firm summaries (not checked at source).

**Amendment.** Add D-46a: "Before any paid offer: counsel opinion on CRA class, the Art. 32(5) route and product liability; a human-staffed PSIRT able to meet the 24-hour, 72-hour and 14-day clocks; an EU contact. At M3: public technical documentation, risk assessment and a support statement (five years of free security updates per LTS, kept available ten years). Declaration of conformity before 11 December 2027."

### 9. The three integration tiers do not say where each runs (D-40). Missing, minor

**Problem.** "No third-party native code in sensors" leaves WebAssembly in sensors open, against the memory budget and D-20's privilege split. Cloud-side verdict adapters answer vendor services that fail open by default and lack the device's session labels, so one call can get two verdicts.

**Evidence.** Brief 26 implications (tier B runs in-process) and verifier (fail-open defaults at Anthropic inference hooks and Copilot Studio). D-09.

**Amendment.** Add to D-40: "Sensors run declarative manifests only. WebAssembly components and out-of-process plugins run on the server or a sidecar. Cloud-side verdict adapters evaluate only policies marked stateless, report the vendor's fail mode, and never count above AL2."

## Spikes

| # | Question | Method | Pass criteria |
|---|---|---|---|
| 1 | Do other vendors need a hook broker? | Install Defender hooks, DefenseClaw, a CrowdStrike collector and our shim on Claude Code, Codex, Cursor and Copilot CLI, with and without managed-hooks-only. Record which hooks fire and how verdicts merge. | Native merging drops or misorders a verdict on two or more agents. Otherwise L2 leaves the table. |
| 2 | Is agentgateway a safe enforcement host? | Attach the engine as an ExtMCP guardrail on v1.7.0. Kill the policy server, add a two-second delay, replay the cross-route session pattern. | Every fault yields deny; added p99 under 20 ms; a kill-switch command takes effect within five seconds. Otherwise build the first-party target. |
| 3 | Can a sensor vendor link the engine? | Build the C ABI and sidecar with 50 rules. Fuzz malformed packs through a C host for 24 hours. Collect written asks from two vendors' engineers and counsel. | No abort across the boundary; p99 under 200 microseconds; under 30 MB; D-41a answers both lists. |
| 4 | Will anyone pay with nothing withheld? | Ten conversations (five MSP or MDR, five enterprises on CrowdStrike or Defender) with a mock price page and the L0 rule pack. | Three letters of intent for hosting or support and one L0 or L3 pilot. Otherwise reopen the server licence before the first public commit. |

## Agreed

- Apache-2.0 for engine, sensors, SDKs, schemas and content: GPL engines force a daemon boundary (brief 27 Part 1).
- Apache-2.0 for the server over AGPL: AGPL without a CLA earns nothing and closes CNCF, OpenSSF and AAIF. D-02 should say plainly that anyone may host it.
- DCO with no CLA; D-03's admission that only asset ownership makes the promise credible.
- The isolated dual-licensed eBPF crate; no DRL or ELv2 content in the default pack.
- LiteLLM as a collector target only.
- Importers for incumbent inventories first; only the milestone is wrong.
- A public conformance suite and identifier registry; L4's plain statement that it cannot block.
