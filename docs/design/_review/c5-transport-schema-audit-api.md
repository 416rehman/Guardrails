# Review C5: transport, schema, audit and API (D-06, D-10, D-36 to D-39)

Decision challenger, 2026-11-10.

## Summary

The direction holds; the detail in D-36 to D-39 does not: a volume target that contradicts three other decisions, three protocol stacks for a near-idle sensor, an audit chain that cannot be verified, and no rules for skew, rollback or our own MCP server.

The change that matters most: replace "5,000 events a day" with a written fidelity contract and a specified flight recorder, then measure.

## Findings

### 1. Blocker, wrong: the 5,000-event target contradicts D-11, D-13 and D-29 (D-36, section 6)

Problem. The figure is a cost-model input, not a measurement: g10 assumes 1,000 tool calls a day for a heavy user, brief 24 assumes 100,000 events. D-13 re-evaluates policy at the OS on every resulting exec, open and connect, and one build produces thousands. Reaching 5,000 means discarding most OS observations, so D-11 replay and server-side correlation run on a biased sample and late intelligence cannot be hunted. Brief 37's flight recorder is a 64 MB ring of about ten minutes.

Evidence. 37 "Performance budgets"; 24 TL;DR; g10 cost-model inputs and weak points.

Amendment. Replace the target with a fidelity contract. Always shipped, never sampled: session and tool-call spine, every non-default verdict, detections, labels, `cred.use`, `config.change`, `agent.spawn`, `mcp.*`, `llm.request` metadata, and first-seen executable, destination and path prefix per session. Repeated allowed `exec`, `file.*` and `net.connect` within a tool call ship as counted roll-ups carrying a Merkle root of the elided events. The flight recorder is sized by policy in days, uploads around any finding, is fetchable as a response action, answers server-pushed retro-hunt queries and is flushed at job end in CI.

### 2. Major, wrong: the audit chain is unverifiable as specified and built too early (D-39, D-34, D-06)

Problem. Brief 23 rule 8 hashes the exact bytes sent; D-34 stores OCSF-shaped Parquet, so those bytes no longer exist server-side, and D-06 rejects storing OCSF names at all. A TPM cannot sign per event. Regulators name no cryptographic mechanism; a self-hosted node has no external witness; Tessera is Go, so tiles are new Rust work.

Evidence. 23 section 4, implications (4) rule 8, weak points; spine D-06 against D-34.

Amendment. Rewrite D-39: sensors hash-chain events per lane and sign each batch head with a per-boot software key certified by the device key. The server archives batches byte-exact on the blob port; lake columns follow the canonical model and OCSF is a versioned export view. M1: local chain and `grd audit verify`. M2: per-organisation checkpoint chain in signed-note format, exported to a customer-controlled sink. M3 onward: tiles, inclusion proofs, external witness, SCITT receipts. The log holds digests only. Lost by deferring: third-party witnessing before M3.

### 3. Major, over-built: three protocol stacks for a near-idle sensor (D-36)

Problem. A gRPC stream, an HTTP/2 unary fallback and an OpAMP WebSocket are three stacks to secure and test. At 3 MB raw a day a trained dictionary saves kilobytes and makes old dictionaries part of the evidence archive. Rust OpAMP is one client (`newrelic-opamp-rs` 0.3.0, four stars, no server; read with `gh` today); its packages, connection offers and commands duplicate TUF, certificate renewal and our signed commands. Brief 24 asked for OpAMP semantics, not the wire.

Evidence. 23 section 6 and verifier note A; 24 weak points ("must own a compatibility shim").

Amendment. Data plane: unary acknowledged batch POST (Connect unary, valid on HTTP/1.1 and HTTP/2) with `(device, epoch, lane, seq)` idempotency, spool and gap events; streaming only for gateway and node emitters, after M2. Control plane: a `fleet.v1` service on the same endpoint and credentials with OpAMP semantics and one push channel with long-poll fallback; an OpAMP wire adapter waits for a real interop consumer. Plain zstd unless spike 1 shows material savings. Lost: nominal OpAMP compliance.

### 4. Major, missing: proxies, TLS inspection, FIPS and post-quantum fallback (D-36)

Problem. Mutual TLS as the only device authentication fails wherever a corporate proxy re-signs TLS; Origin's agent needs an inspection bypass. D-36 is silent on explicit proxies, PAC and Negotiate authentication, on middlebox failures from the larger hybrid ClientHello, and on FIPS, which the spine never mentions.

Evidence. 01 enrolment notes; g05 findings and implication 4; 23 weak points, verifier rows 8 and B; 25 implication 11.

Amendment. Add to D-36: the uplink works through an explicit or PAC-discovered proxy with Negotiate authentication and through a TLS-inspecting proxy. Device authentication is application-layer: each request carries an RFC 9421 signature by the device key. Mutual TLS is used where the path allows; its absence is a reported fact. Hybrid key exchange falls back to classical with a health fact. Pin rustls 0.23.46 or later. A FIPS flavour is built for Linux and Windows; macOS is stated as unvalidated.

### 5. Major, missing: TUF trust topology and running cost (D-36, D-47)

Problem. With monthly minors, nightly channels and daily content, something online signs, so brief 23's "server compromise cannot ship code" is untrue for content and policy. Nothing says whose root a self-hosted server, an OEM re-signed channel or an air-gapped site trusts, what timestamp expiry means offline, or who holds keys.

Evidence. 23 implications (3); 25 implications 7 and 11; 37 fail-open table.

Amendment. Add D-36a. Two roots. The vendor root (two of three offline hardware keys) is compiled into binaries and alone authorises binaries; targets delegates `binaries` to a release key requiring SLSA provenance and `content` to an online KMS key. A deployment root (self-hosted operator, SaaS cell or OEM), pinned at enrolment, authorises policy and configuration, never binaries. Air-gapped imports verify against the vendor root. Timestamp expiry is a deployment setting; expiry means stale, shown in health.

### 6. Major, missing: rules for skew, rollback and the crash-loop ladder (D-37)

Problem. Brief 24 says one major behind; g10 says two minors plus an LTS, so a laptop offline for a quarter falls out. "Accepts" is undefined; refusing events from neglected machines loses the data we most want. A hand-upgraded self-hosted server will meet newer sensors. TUF forbids metadata rollback. An agent that can crash the engine can walk the ladder to "content disabled".

Evidence. 24 "Fleet"; g10 section 6 and implication 5; 37 "Update and rollback".

Amendment. Add to D-37: the server ingests events from, and delivers signed updates to, any sensor of the same wire major; the support window governs fixes and new policy features only. In platform mode the server sets the sensor version ceiling. Packs declare a minimum engine version and are validated against every supported engine. Rollback is a new signed release pointing at the old artefact; last-known-good honours a signed minimum-version floor; each ladder step is a server-visible finding and never relaxes fail-closed rule classes.

### 7. Major, missing: device identity beyond the managed laptop (D-36)

Problem. Fleet ships TPM identity on Linux only; Secure Enclave is P-256 only and unproven from a system daemon. Containers and CI runners have no TPM and must not mint long-lived certificates. Cloned golden images share keys, and deduplication on a shared device id would silently drop a clone's events.

Evidence. 23 weak points; 25 VDI notes; D-38 gives federation to API clients only.

Amendment. Add D-36b. Enrolment methods: use-capped token; MDM-delivered token or platform attestation; workload identity federation (Kubernetes service-account token, CI OIDC, cloud instance identity) for containers and ephemeral runners. Device id is the key hash for persistent hosts and workload identity plus instance id for ephemeral ones. Each device reports key protection (`hardware`, `os-keystore`, `file`) as a fact policy can require. Two chains under one device id is a clone finding, never a deduplication.

### 8. Major, missing: boundaries for our own MCP server (D-38)

Problem. Read-only is not safe: agent names, command lines and tool descriptions are attacker-controlled text read by a client model we do not control. An untrusted-data envelope is a request under P1, not a boundary. A provider-wide token lets one customer's poisoned data steer writes in another. A governed agent that can read policy has an evasion oracle.

Evidence. g07 weak points, "Our MCP server" and section 7; 24 "API".

Amendment. Add D-38a. Tokens are bound to one organisation. Default scope returns metadata only; content needs the D-38 content grant. No server-side code execution. Sessions of a governed agent cannot read policy, detection content or their own exception state. Proposals are rendered by the server from the canonical diff, never from agent-supplied text, and approved under D-31. Response actions are not exposed. Envelopes are labelled request-grade. Row, time and cost limits apply per call.

### 9. Major, risky: the contract rests on young libraries and has no evolution rules (D-38, D-06)

Problem. `connect-rust` and `buffa` were created in March 2026, are 0.x, and one author wrote most of the former (read with `gh` today). D-38 says "one stack", dropping g07's tonic escape hatch. The spine adopts none of brief 23's eight evolution rules and names the package `v1` before design. Rule 4 (preserve unknown fields) fails on prost (issue 2 still open).

Evidence. g07 section 1 and weak points; 23 implications (4); 26 (Security Lake accepts OCSF 1.3 at most).

Amendment. The contract is the protobuf package and the Connect, gRPC and gRPC-Web protocols, not a library. connect-rust is the primary binding and tonic a second binding run in CI until connect-rust reaches 1.0. One codec with unknown-field preservation generates `grd-proto`. Packages start at `v1alpha1` and freeze at the M2 exit; `buf breaking` gates every change; brief 23's eight rules are normative. Mapping files carry their own version and target (OCSF 1.9, OCSF 1.3, a pinned OTel commit). Spike 4 settles the binding and codec.

### 10. Major, wrong: "ambiguous parses deny" and the choice of oracle (D-10)

Problem. The one shell guard that survived GuardFall escalates on ambiguity; it does not deny. Dynamic constructs are routine, so blanket deny contradicts D-15. For LLM protocol parsers, a provider format change would block every proxied agent at once. P7 calls parsers signed data; D-10 calls them code. A reference model written by the same team shares its mistakes.

Evidence. 09 TL;DR and implication 1; 32 implications; spine P7, D-13, D-15.

Amendment. Normalisers return `resolved`, `unresolved` or `malformed`. Malformed denies. Unresolved is a fact: fail-closed classes deny or step up, others defer to the OS control point on the concrete action. Oracles are the real consumers: shells under exec tracing, kernel path resolution, each agent's own JSON and SSE parser; Cedar reuses cedar-spec's Lean model and differential tests. Vendor message schemas ship as packs; only framing is code. An unknown schema version marks Degraded, never a fleet-wide deny.

## Spikes

1. **Volume and fidelity.** Two-week full-fidelity capture on ten developer machines; apply the contract offline; replay ten policies on full and filtered sets. Pass: the 95th-percentile endpoint fits the budget; replay matches are identical for always-ship classes; a dictionary saves over 30% or is dropped.
2. **Hostile networks.** An HTTP/1.1 proxy requiring Negotiate, a TLS-inspecting proxy, a middlebox dropping large ClientHellos, 30 days offline. Pass: enrolment, acknowledged delivery, policy update and a kill command within 60 s in each; no loss or duplicates on replay.
3. **Device keys.** Use a non-exportable key from a service on Windows TPM, macOS Secure Enclave, Linux TPM, a container and a CI runner. Pass: unattended operation or a recorded downgrade in each; a cloned VM flagged within one batch.
4. **Codec and binding.** One proto through buffa with connect-rust and prost with tonic; unknown fields through sensor, ingest and archive; a 72-hour soak of 10,000 simulated sensors. Pass: byte-identical archive, verifying hashes, interoperating bindings, flat memory.

## Agreed (tried to break, held)

- D-06: our own protobuf model, OCSF and OTel GenAI as dialects.
- D-36: an acknowledged batch protocol instead of OTLP; TUF as update trust; hybrid key exchange; separately signed commands.
- D-37: three channels through one ring pipeline.
- D-38: AIP mechanics; Cedar console authorisation in its own namespace.
- D-39: the sensor-side hash chain in OCSF `record_integrity` shapes.
