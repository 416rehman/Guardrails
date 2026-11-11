# Rulings on objections raised by the design documents

_2026-11-10. Applies with version 3 of `design/00-decisions.md`._

After the design and team documents were written, each document's second reader and the eight consistency passes recorded objections to the spine and conflicts between documents. Each is settled below. A ruling binds every document it names. "Spine" means a change already made in version 3.

## Decision mechanics

| Id | Conflict | Ruling | Documents to change |
|---|---|---|---|
| R-01 | 07 lets STEP_UP use the agent's native ask at G0 | D-07 wins. The agent's own prompt is never an approval at any grade (spine, section 3). Delete 07's native-ask row, the pending-ask expectation and degradation row (a). The native prompt may only point the person to `grdr-approve` | 07 |
| R-02 | Decision-record field names and which decisions are signed | 04 and 12 win: fields `verdict` and `executed_as`; only non-default decisions get a signed receipt; the fail-open oracle checks the decision record | 07 |
| R-03 | Who serves the local console | `grdr console serve`, an unprivileged per-logon-session process started on demand, reading through the daemon's local API; the daemon binds no TCP port (spine D-42, D-43) | 27, 28 confirm; 03, 11 already agree |
| R-04 | Who verifies pack signatures | `grdr-updater` verifies signatures and writes the last-known-good store; the daemon checks each pack's digest against the updater's signed index before loading | 12 |
| R-05 | Who signs the shim's fail-safe table | Compiled on the device by the privileged service and signed with a device-local artefact key (21's key table). Fast-path tables are compiled on the device too; 26's relay compiles them only for embedded hosts that cannot, signed by the partner's root | 07, 12, 26 confirm |
| R-06 | Shim fallback during Windows update handover | 250 ms, or until a valid handover marker deadline, never beyond 2 s (spine D-14) | 07, 11 |
| R-07 | Principal for agent rules | Agent rules apply when `actor_kind` is agent, which requires the catalogue entry's `min_attribution_grade` (2 in shared hosts). Below that the actor is `undetermined` and each rule class states its handling | 12 |
| R-08 | Only writer of the lanes | The daemon is the only writer of every lane, `local` included; the engine sends records to the daemon | 03 |
| R-09 | Unanswered requests | Retry tokens for routed approvals (approver other than self) are renewed until 18's route timer (default 4 h) expires; self-approvals count as unanswered at token expiry | 12 |
| R-10 | Elevation in Essentials | Essentials ships Ask for `elevate` from agent lineage in the protected profile; Watch in the user profile (spine D-53) | 12, 13 |
| R-11 | Standalone time lock (18 deviation 1) | Accepted for the user's own local policy in the user profile only (spine D-31) | 18, 28 |
| R-12 | Packs introducing host patterns or environment names (05 deviation 1) | Allowed as typed match fields (spine P7). SR-25 reads the same way | 02, 05 |
| R-13 | Feed-managed list churn | Not a widening change when the list is restrict-only and comes from a signed intelligence pack (spine D-08) | 12, 14 |
| R-14 | Delay on intelligence records | Malicious verdicts and withdrawals are public immediately; the delay applies to enrichment and prevalence (spine D-04) | 14, 36 |

## Schemas and contracts

| Id | Conflict | Ruling | Documents to change |
|---|---|---|---|
| R-15 | Values other documents need in the event model | 04 adds: channels `sysmon`, `win-event-channel`, `win-driver`, `wesp`, `host-edr`, `seccheck`; `session.link` kinds `member`, `bound`, `child-session`, `resume`, `handoff`, `outward`; evidence values `human-entry`, `system-principal`, `influenced`; classes `outward.receipt`, `identity.lifecycle`, `identity.correlation`, `credential.lease`; fields `lease_id` and `peer_verified` on `cred.use`; `health.coverage` reasons; a `workload` object for Kubernetes; an outcome-dependent lane for inventory records so `llm-client` records stay local | 04 |
| R-16 | Lake tables | 20 wins: three physical retention tables with categories as views | 04 |
| R-17 | Provenance of foreign telemetry | D-60 wins: host events carry the host profile's declared grade once the profile passes the conformance kit; until then they are `reported` | 04 |
| R-18 | Pseudonym issuance (29 deviation 4) | Two layers: device-side keyed pseudonym, then server re-pseudonymisation at ingest with a key the device never holds (spine D-51). Owner question 9 can reverse it | 04, 21, 29 |
| R-19 | Structural retention default | 184 days (spine D-51) | 04, 20, 29 |
| R-20 | Pack kinds | 22 adds a standard lane for `intel` (snapshots) beside the rapid lane (deltas), and the `integration` kind 25 reserves | 22 |
| R-21 | Lint numbers | 03 assigns ARCH-014 `tier0-no-port` (20), ARCH-015 `tenant-path` (21), ARCH-016 `rune-leaf` (28) | 03, 20, 21, 25, 28 |
| R-22 | Crates and timing in 03 | `grdr-integrations` and WebAssembly components at M3 (spine D-40); add `grdr-fastpath-ffi` in the core squad with its unsafe exception; the engine-sandbox crate at M0; split the tray and local-console footprint figure | 03, team/02 |
| R-23 | Missing API resources | 23 adds 15's resources: `agentInstances` `:transferSponsor`, `:suspend`, `:retire`; `credentials:adopt`; `leases:revoke`; `outwardReceipts` | 23 |
| R-24 | Identity rules in packs | 12 lists `cred.release.requires-containment` and 15's other rules in `grdr.agents` | 12 |
| R-25 | Provider-scope commands | Two provider approvers plus a co-signature from the claimed organisation's roster for anything beyond reversible containment (21, 02, 22) | 18 |
| R-26 | Destructive-command limits | 22 owns device verification: 3 destructive commands per 10 minutes per scope unless two approvers signed. 18 owns the server-side automation cap per hour. After reconnect a device denies with `syncing` until pending commands are applied (D-30) | 18, 22 |
| R-27 | Provider registration | 07 adds the `model_backed` field 19 requires | 07 |
| R-28 | Judge worker credentials | 02 records the SR-37 exception for judge workers that 19 needs | 02 |
| R-29 | Defender join rule | 13 states the `DeviceId` join rule for KQL rules meant to isolate; the L0 backends are the five in D-41, ES\|QL is not one | 13 |
| R-30 | Windows services list | 24 lists `grdr-proxy` as a service and the user-profile engine as an AppContainer child | 24 |
| R-31 | First-run discovery passes | 05 wins: first run uses passes 1 and 4 (local declared sources); pass 2 needs `llm-client` classification first | 24 |
| R-32 | Count MCP stdin writes as loop cycles (05 deviation 2) | Accepted as an S-09 variant, kept only if precision holds | 05 |

## Milestones and horizons

| Id | Conflict | Ruling | Documents to change |
|---|---|---|---|
| R-33 | Horizon tags against section 7 | Spine retagged: D-27 (inventory M1, identity target M3, broker M4), D-29 (judge trait M2, review stage M4), D-43 (M2), D-46 (project obligations now, customer evidence M4) | 02, 12, 15, 19, 28, 29, 33 confirm |
| R-34 | Judges at M3 | The judge back-end trait lands at M2; the review stage and the natural-language authoring model step at M4 | 12, 19, 33, team/02 |
| R-35 | Identity milestones | 15 wins: observed identifiers and credential inventory at M1, helpers and broker at M4 | 01 |
| R-36 | Hosted track timing | Opens no earlier than the M4 `distributed` load test (spine section 7) | 32, 33, 36 |
| R-37 | macOS discovery-recall gate | Linux and Windows at M2, macOS at M3 (spine section 7) | 05, 33 |
| R-38 | Self-hosting above the `ha` ceiling | `distributed` supported for self-hosters from M4 above about 50,000 endpoints (spine D-33, D-58) | 20, 24 |
| R-39 | Table-stakes SaaS connectors | Two read-only connectors (Anthropic Compliance API, OpenAI Compliance Logs) move to M3; credential halves of parity items T12 and T16 remain M4 and are stated as a known gap at self-hosted 1.0 | 01, 25, 33, 36 |
| R-40 | Linux AL3 at M2 | The `cgroup_sock` enforcement program is audited at M2 (35 already lists it) | 10, 33 |
| R-41 | Trust-core cut rule | Applies at the start of the first trust-core work item for a component, not at milestone entry (spine D-63) | 33, team/06 |
| R-42 | Persona council | The full eight-seat council runs from M0 | team/01, team/02 |

## Lifecycle, operations and supply chain

| Id | Conflict | Ruling | Documents to change |
|---|---|---|---|
| R-43 | Supported lines | 34 wins: current minor, two before and the live LTS; first LTS is the first minor at least 90 days after 1.0, then every twelfth; hops of at most two minors with required stops (spine D-58) | 22, 24, 30, 32 |
| R-44 | Crash dumps | No memory dumps in support bundles (11 wins on privacy) | 24, 34 |
| R-45 | Dependency cooldown | 7 days | 24 |
| R-46 | Team plan minimum | 32 wins: a minimum monthly charge that covers support cost, set with prices at M3 | 36 |
| R-47 | Join checklist | 27 section 6 owns it | 36 |
| R-48 | Classifier file and vulnerability severities | `.agents/risk-tiers.toml`; vulnerabilities are V1 to V4, support severities S1 to S4 | 35, team/05 |
| R-49 | Release role | 30 adds a human release-manager role | 30 |
| R-50 | Security squad | A `security` squad owns `grdr-crypto`, `grdr-approve` and IPC peer authentication | 03 |
| R-51 | `xtask` ownership | Core owns the `xtask` framework; agent-kit owns the kit, hook, risk, queue, approval and audit subcommands | team/06 confirm |
| R-52 | Acceptance files | A person lands every acceptance file; S-20 measures the load | team/01 |
| R-53 | Trust-core paths | `security/trust-core.paths` lists `audits/**` explicitly | 02 |
| R-54 | Work-item prefix | team/01's TM- items become TO- | team/01 |
| R-55 | Browser extension owner | The interfaces squad | team/01, team/02 |
| R-56 | Operations agents | team/02 adds 32's operations agents (`ops-triage`, `ops-runbook`, `usage-reconciler` and the rest) | team/02 |
| R-57 | Owner succession for signing (30 deviation 3) | A named delegate from the second maintainer onward; the covenant states succession (spine D-61) | 30 |
| R-58 | First-party content approval (13 deviation 1) | One human plus evaluator evidence; community content needs two (spine D-61) | 13, 30 |
| R-59 | Desktop sandbox profile | 11 adds a profile for the Rune window: no network, IPC only to the daemon's local endpoint, AppContainer on Windows | 11 |
| R-60 | Block message at M1 | Uses 28 section 1's M1 path (the dialect's user-message field, the console Now route, `grdr why`); the tray from M2 | 18 |
| R-61 | Lab gaps | Incumbent licences through a design partner or vendor programme by M2; the x64 host at M0 runs the held-out suite; confirm in M0 whether hosted Windows runners allow real-time protection; agents with no custom model endpoint (Cursor) run model-driven scenarios only; efficacy model tokens are budgeted separately (spine D-64, section 7) | 31, team/05, 33 |
| R-62 | Open-source guardrail projects missing from the competitive map | 01 adds rows for NeMo Guardrails, Guardrails AI, LlamaFirewall and Llama Guard, garak, PyRIT and promptfoo with capability, weak points and our stance (integrate, test with, or not compete) | 01 |

## Left for the owner

Owner questions 7 to 9 in the spine: licensing of the owner's own skills for the open kit, who the second person is, and whether pseudonym issuance moves entirely to the server.

## Rulings from the final audit

| Id | Conflict | Ruling | Documents to change |
|---|---|---|---|
| R-63 | 15 derives agent identifiers from the human principal on the device, against two-layer pseudonyms | Agent-instance identifiers (`agi_` and the SPIFFE path) derive from program identity, device and sponsor reference, never from the human principal; the principal pseudonym is a separate field, re-pseudonymised at ingest | 15 |
| R-64 | The ingest pseudonym key across restore and export | The ingest pseudonym key is part of 21's key hierarchy, wrapped by the organisation key, included in backups and in the portable organisation bundle, so the lake can be rebuilt from the byte-exact archive | 20, 21 |
| R-65 | `ha` ceiling against the load test | The ceiling is what the load test proves; the test targets 50,000 endpoints at 5,000 events a day and 10,000 at 100,000 | 20 |
| R-66 | Keys port with three gating adapters | P6 counts per profile, and per operating system for endpoint ports (spine). Keys has `local` (embedded) and `cloud-kms` (ha, distributed); AWS and GCP are provider back ends of `cloud-kms`, each tested by the port test kit | 21, 03 |
| R-67 | 19's `grdr-review` crate and `grdr-infer` program | Accepted; 03 adds `grdr-review` at M3 (its deterministic priority score and sample serve the M3 review queue; judge-output validation is used from M4) and `grdr-infer` at M4 | 03 |
| R-68 | The loopback OTLP receiver at M1 | `grdr-proxy` starts at M1 with only the OTLP receiver (untrusted input stays out of the privileged daemon); its network-proxy functions arrive at M2 | 03 |
| R-69 | Audit timing | 35 wins: core, updater, shim and approval helper audited before R1 reaches stable (spine D-62) | none further |
| R-70 | Hook canary and verdict-adapter timing | The passive canary (session start plus first tool call matched to an OS observation) satisfies D-49; verdict-provider adapters are M4 (spine D-49, D-40) | none further |
| R-71 | Remaining small conflicts | team/06 builds the 22 M0 crates and lints ARCH-001 to ARCH-016; team/05 and team/06 cite team/01 items as TO-; Cargo `min-publish-age` and Renovate minor and patch updates wait 7 days, majors 14 (this refines R-45); PLAN.md counts 64 agent definitions | team/05, team/06, 24 |
