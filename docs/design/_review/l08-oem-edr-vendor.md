# Review L08: an EDR vendor deciding whether to embed or white-label

Lens: product and engineering leads of a mid-sized, MVI-member EDR vendor with its own sensor, content pipeline and PSIRT. Reviewed 2026-11-10 against briefs 27, 28, 10, 12, 13, 37, g02, g06 and 26. Checked at source today: `VirusTotal/yara-x` `lib/Cargo.toml`. Review C6 covers the neutral project name, D-04, the sidecar, ABI negotiation, a five-year LTS and rung ordering. We concur and do not repeat them.

## Summary

We would take L0 and L1 tomorrow. We would not take L3 or L6 as written. The ladder says what a partner takes. It does not say what our sensor must supply, how the engine lives inside a protected process, or what we control after we ship it. Without those answers we would build on Cedar plus the hook contracts that DefenseClaw and Prempti publish under the same licence. The change that matters most is a host contract (finding 1): what a host declares, the assurance level that results, and a test of our mapping, not only of the engine build.

## Findings

### 1. No host contract for L3 (D-41, D-25, D-06). Missing, blocker

**Problem.** L3 blocks "wherever the host enforces", but the core's inputs assume Loonaro's collectors: session containers created at launch, hook join keys, provenance grades. Our telemetry is process, file and network events with our own lineage. Nothing states the minimum event set per capability, how a host declares what it supplies and can execute, or what assurance level results. The conformance suite tests the engine build; the mapping is where embedders err.

**Evidence.** Brief 27 Part 4 (EDR telemetry lacks the tool call and session identity). Brief 10 implications (a backend trait so a vendor's own driver replaces our collectors). D-07 already has per-control-point verb declaration.

**Amendment.** Add D-41b: "Host contract. A host supplies a host profile: event classes with provenance grade, session-container mechanism, actuator verbs. The engine derives the achievable AL and attribution bases from it and returns `not-evaluable` per rule instead of passing. A published table gives the minimum events for each discovery pass, attribution basis and action class. Conformance has three kits: golden vectors for the engine build; a scripted scenario pack from the D-45 harness that the partner runs on its own sensor; a provider kit for L2. Marks state rung and AL."

### 2. The protected-process route contradicts D-20 and cannot use signed builds (D-17, D-20, D-04, D-09). Wrong, blocker

**Problem.** D-17 reaches WESP and PPL by an MVI member loading the engine. That DLL must be signed with, or catalogued under, the vendor's certificate, so D-04's "signed LTS builds" cannot load; we need source and a reproducible build. Loading the whole engine also puts Cedar, Sigma, YARA-X and the protocol parsers in our most privileged user-mode process, the opposite of D-20. YARA-X's default back end is a Cranelift JIT that needs executable pages; its interpreter is an opt-in `pulley` feature.

**Evidence.** Brief 12 Implications item 7 and Findings 2 (antimalware signing). Brief 37 Architecture. yara-x `lib/Cargo.toml` features, read today.

**Amendment.** D-41: "L3 has two parts. A fast-path library: fixed-layout inputs, precompiled decision tables, no parsers, no JIT, no threads, bounded allocation through a host allocator. It is the only part meant for a protected or privileged host process. The content engine (parsers, Sigma, YARA-X, Cedar over content) ships as an unprivileged sidecar or WASM. The OEM deliverable is source with a reproducible build and provenance, not our signature. Embedded profiles build YARA-X with the interpreter."

### 3. The content channel is ours to control only at L6 (P7, D-36, D-37, D-41). Missing, major

**Problem.** Re-signing appears only at L6. At every rung we must relay content through our own rings (MVI 3.0 requires staged rollout), validate it with our exact engine build, and supply sensors that stay in the field for years. P7's "production interpreter" is then our build. No pack-to-engine compatibility window exists. C5's compiled-in vendor root makes this worse.

**Evidence.** Brief 27 Part 5 (OEMs re-host and re-sign; official-only switch) and Part 2 (MVI 3.0). Brief g06 implications (rules declare engine version; per-pack TUF delegations; N-1 and N-2 pinning).

**Amendment.** Add D-37a: "Trust roots are host-supplied configuration; the core embeds none. `grd content relay` pulls upstream, verifies, runs the pack through a named engine build, re-signs and emits a target for the partner's rings. Every pack declares required engine capabilities; constructs an engine lacks are skipped and reported, never a load failure. Packs are published for every supported engine line for its whole support period. Overlay order: upstream, partner, tenant."

### 4. No hot-path contract (section 6, D-08, D-36). Missing, major

**Problem.** Section 6 dropped brief 37's authorisation budget. D-08 tolerates 1 ms p99. Our file-open path cannot call anything per event, so the host must know which events to send and which verdicts it may cache. D-36's agent-scoped filtering describes Loonaro's sensor, not an interface.

**Evidence.** Brief 37 Performance budgets (exec and open p99 under 5 ms; cached under 100 microseconds). Brief 10 implications (Santa's cacheable identity fields against non-cacheable context).

**Amendment.** Add to D-05: "The engine exports an interest set per bundle and session (process scope, path, host and port tables in a fixed format a host can compile into its kernel filter). Each verdict carries a cache key, scope and expiry." Section 6 adds: embedded fast path p99 under 100 microseconds cached and 1 ms uncached; interest-set update within 50 ms of session start; engine memory at 50 sessions, measured.

### 5. Embargoes leak through the public content repository and the agent fleet (D-47, D-10, section 5). Missing, major

**Problem.** The spine has no security-response decision. A normaliser bypass is fixed in code or content, and `guardrails-content` is public, so the fix discloses the bypass before partners finish their rings. D-47 keeps "disclosure handling" human, but agents on third-party model accounts write the fixes, so embargoed detail leaves the embargo. curl abandoned brief 28's GitHub-only reporting plan.

**Evidence.** Brief 28 verification row A and Implications (security and releases). D-10. Open question 2.

**Amendment.** Add D-48: "Security response. Engine or normaliser bypass and memory-safety faults are vulnerabilities, with CVE and VEX per engine line; a missed detection is a content gap. Embargoed fixes are developed in a private fork by named humans, with agents only on zero-retention model contracts. Pre-disclosure list members receive signed packs or patches at least ten working days before publication, backported to every supported line. The reporting channel is chosen after testing GitHub private reporting against HackerOne."

### 6. L2 puts Loonaro's shim in our customers' only hook slot (D-14, D-41). Risky, major

**Problem.** Our product becomes a provider behind a Loonaro-signed broker and inherits its availability. Any registered provider receives prompts and tool arguments (against P8), deny-wins lets one provider veto everything, and `MODIFY` from two providers is undefined.

**Evidence.** Brief 27 Weak points and verification row 4 (competing `updatedInput` undocumented).

**Amendment.** D-14 adds: "The broker is a library and a specification. A host vendor may build and sign the shim and run our engine as one provider. Registration is admin-owned and signed; each provider declares the event classes and capture level it receives, metadata-only by default. One provider per action class may `MODIFY`. A provider that exceeds its error budget is suspended under its fail policy and raises Degraded."

### 7. Adapter freshness, the thing we would pay for, has no target (D-24, D-04). Missing, major

**Problem.** Hook schemas and install layouts change continuously. D-24 proves identifiers in CI but sets no time-to-support and no behaviour for an unknown agent version.

**Evidence.** Brief g02 Findings 2 (contracts pinned to version ranges; "Versions with no contract are refused") and Weak points (contracts lag releases). Brief 28 Ideas (fingerprints go stale monthly).

**Amendment.** D-24 adds: "Adapters carry version-ranged contracts. A canary job installs each catalogued agent's new release within 24 hours; a break ships to the early ring within two working days and to stable within five. An unknown version runs the nearest contract in Watch and reports Degraded. A support matrix is generated per pack." D-04: the OEM tier sells these as contractual targets.

### 8. No stability classes for the surfaces we compile and author against (section 3, D-06, D-07, D-14). Missing, major

**Problem.** Action classes, verdicts, labels, the Cedar schema and the pack format are contracts too. Nothing says how an old engine treats a new action class or how long a major lives. The native provider protocol is unnamed among four dialects, two of them drafts or previews.

**Evidence.** Brief 27 Part 5 (additive-only) and verification (Copilot Studio contract is preview). Brief 26 implications (stability levels). Index entry 08 corrections (OWASP ACS is v0.1.0).

**Amendment.** Add D-41c: "Each public surface is marked experimental, beta or stable. Stable means additive-only within a major, at most one major per 24 months, 12 months of overlap. Unknown action classes and enum values evaluate to `not-evaluable` and are reported. The native provider protocol is our own protobuf service; the others are adapters. Nothing is stable before one external embed pilot completes."

### 9. Channel conflict and data terms are unstated (D-01, D-32, D-44). Risky, major

**Problem.** Loonaro sells L5 and hosting to our customers. D-32's reciprocity follows CrowdSec, which counts only unmodified content verified by hash, so a partner that overlays or re-signs drops out, and contributing means sending our customers' signals to a competitor.

**Evidence.** Brief 28 verification row 10. Brief 27 Weak points.

**Amendment.** D-41 adds: "Embedded and white-label builds make no network call to Loonaro, carry no Loonaro strings, and resolve reputation lookups through the partner. Partners contribute in aggregate, digest-keyed, with no organisation or device identifiers; overlays do not disqualify upstream packs."

### 10. White-label stops at the theme (D-41 L6, D-18). Missing, minor

**Problem.** The OS shows the publisher, Team ID, system-extension, service and process names, paths, event channel, hook path and block messages. The Endpoint Security entitlement binds to one Team ID.

**Evidence.** Brief 13 Weak points. Brief 27 Part 5 (white label).

**Amendment.** D-41: "L6 has two modes. Themed: our signed binaries and the partner's theme; OS-level identity stays ours and is disclosed. Rebuilt: the partner builds from source with a brand manifest and its own signing identities and entitlements. No product name is hard-coded outside the manifest."

## Spikes

| # | Question | Method | Pass criteria |
|---|---|---|---|
| 1 | Can the fast path live in a protected process? | Build it and the engine with YARA-X `pulley`. Load in a Windows process with dynamic code prohibited and a macOS hardened-runtime process without the JIT entitlement, at 1,000 policies. | Loads; no executable-page allocation; p99 under 100 microseconds cached and 1 ms uncached; binary size and memory recorded. |
| 2 | Does foreign telemetry map? | Record 20 scripted agent sessions with Sysmon and one open EDR. Write a host profile and mapping; compare with our own sensor. | At least 90% of process, file and network rules reach the same verdict; every shortfall is `not-evaluable`; under two engineer-weeks. |
| 3 | Does the relay hold across an LTS gap? | Pin an engine one LTS behind under a partner root. Feed 30 days of packs, one with an unknown construct and one malformed. | No abort or load failure; skips reported; upstream-only signatures rejected; one-command rollback. |
| 4 | Is the freshness target staffable? | Replay 90 days of Claude Code, Codex, Cursor and Copilot CLI releases through the canary job. | Every contract break detected within 24 hours; no unknown version enforced silently; break count fits the five-day target. |

## Agreed

- Apache-2.0 for code and content, DCO, no CLA, no DRL or ELv2 content (D-02, D-09).
- The sans-IO deterministic core (D-05).
- Assurance levels and tamper grade, with `platform` supplied by the host EDR (section 3, D-22).
- No exclusive OS slots and a generated coexistence pack (D-23).
- Failure mode per rule class (D-15).
- L0 compiled content; L4 stated as non-blocking (D-41).
- Driverless Windows first, WESP through an MVI member (D-17), subject to finding 2.
- C6 findings 1, 3, 4 and 5.
