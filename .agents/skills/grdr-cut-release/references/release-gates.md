# Release gates for a candidate

Sources: team/05 section 16 (release gates and the scorecard), design/24 section 10 (release
engineering), team/04 sections 5 and 9 (the release audit set and its gate), D-45, D-50, D-58, D-64.
Where a figure here and its source differ, the source wins and the difference is a finding against
this file.

Every row is run on the candidate commit of SKILL.md section 3 and cited by evidence id. A row that
cannot run is `not run` with its reason and blocks the release.

## Before the tag: the `release-candidate` workflow runs these

| Gate | Requirement | Evidence |
|---|---|---|
| Tier 1 matrix | Every Tier 1 cell of `support.toml` green (D-50) | `cargo xtask matrix-run <job> --cells tier1 --commit <sha>` (skill `grdr-matrix-run`) |
| Conformance suites | Every conformance suite for the shipped components passes (design/24 section 10, step 7) | The conformance jobs' check runs on the candidate |
| Release audit set | team/04 section 9's release row: M01 to M05, B02, B04, B05, B07, B08, B09, C05, D02, D04, F01, F02, F04, F05, F07, F08, G04, H02, I04, J02, K04, on the candidate, diffed against the previous release | Skill `grdr-audit`, then the runner's diff. Blocks on any severity 1 result from S1 to S5, or severity 1 or 2 from F04 or F08, in `upheld`, `triage`, `proven` or `regressed`; a result still `open` blocks until its verification finishes |
| Harness thin slice | Thin-slice scenarios pass (Linux x64, Claude Code and one scripted bespoke agent); the held-out evaluator returns category counts | `scorecard/<version>.json`, signed with its run manifest |
| Silent fail-open | Zero in at least 1,000 fault injections per Tier 1 cell (kill, hang, socket black-hole, disk full, corrupt bundle); Degraded visible within 60 s | Scorecard `fault_injection` track |
| Essentials block reliability | Zero failures in 3,000 scripted attempts per Tier 1 cell; zero block-induced task failures on the benign workload (D-53) | Scorecard prevention track |
| First value | Inventory, timeline and a deterministic block within five minutes on a clean machine, scripted and timed | Scorecard |
| Coexistence | Zero detections from Defender, Falcon and one more incumbent on install, run and uninstall, read from the incumbent's own log or API. Falcon and the other licensed incumbent run only on a licence from a design partner or a free vendor programme; without one the cell is not run and broad release stays blocked (D-23, D-64) | Coexistence cells through `matrix-run` |
| Prompts | Median 3 or fewer and p95 8 or fewer per developer-day on the development fleet's replayed history | Scorecard |
| Held-out margin | Tuning minus held-out under 5 points on every track (spine section 9) | Category counts from the held-out evaluator service only (D-45) |
| Discovery | Precision 95% against LLM-calling non-agents; held-out recall 85% on at least 200 generated bespoke agents on Linux, Windows and macOS; the macOS cell requires the Network Extension | Scorecard discovery track |
| Hook-against-OS false rate | Under 1% on benign sessions | Scorecard |
| Upgrade drills | CI upgrades from every supported version to the candidate and rolls back one release, in `embedded` and `ha`, and runs the LTS-to-LTS sequence from imported bundles with no route out (design/24 section 11). Requires the server | Drill job check runs |
| Hosted-to-self-hosted round trip | Required for every server release (design/24 section 11). Requires the server and 21's organisation bundle | Round-trip job check run |
| Storage, restore, review findings | Storage targets of spine section 6 met, restore drills pass, findings of the reviews D-62 requires closed. Requires the server | Drill reports; closed findings |
| Install and uninstall journal | Uninstall restores every file it touched byte for byte | Install-channel job check run |
| Egress, every shape | Every observed destination appears in `grdr egress` or `grdr server egress` with its purpose, for standalone, an enrolled device on each Tier 1 OS, the server in `embedded` and `ha`, the gateway and the node sensor chart; with updates off a standalone device sends nothing; in isolated mode nothing leaves the allow-list | Egress job check run |
| Air-gap conformance run (24-28, spike S-31) | Green for `embedded` and `ha` (and `distributed` once its load test passes) from the bundle alone: every step's oracle met, zero frames outside the lab, zero DNS queries outside its zone. Required for every server release and for any release that changes the uplink, updater, importer, `Dialer`, Keys, notify or backup (P16) | The conformance run's check run |
| Air-gap bundle contents | The bundle and its delta carry every artefact and third-party component every profile needs, with `THIRD-PARTY-NOTICES`, the CycloneDX SBOM and `sources/` for each copyleft component; a component whose terms forbid redistribution is absent and optional (owner instruction 20) | The bundle manifest and the licence gate's report |
| Fleet scale (P15) | The herd simulation of spike S-23 passes at 10 million devices; a fixed `retry_after_ms` or an unjittered timer fails it | Simulation job check run |
| Compatibility matrix | Every supported sensor line against the server (N-2 to N+1), every pack against every supported engine line, the driver and eBPF interface ranges and the upgrade path's hops, generated from `support.toml` (D-71) | Matrix job check run |
| Shipped locales | Every token of every `shipped` locale translated with a current `source_hash` and an `equivalent` or `minor` verdict; a locale that fails is demoted to `preview` for the release and the notes say so (D-69) | `cargo xtask interface check` evidence |

Statistical rule (team/05 section 16): a zero-tolerance target is met only by zero failures in at least
the stated number of trials. Every cell runs at least ten repetitions and reports Wilson intervals.
Never round a rate into a pass.

## After the tag: the release workflow runs these

You cannot produce this evidence before release-please's tag starts `.github/workflows/release.yml`.
List each row in the hand-off's `next` as something the release workflow confirms before it signs the
TUF targets.

| Step | Requirement |
|---|---|
| Hermetic build | `--locked`, vendored sources, `SOURCE_DATE_EPOCH` from the commit, `--remap-path-prefix`, `cargo-auditable`; toolchain and build tools from their pins |
| Independent rebuild | Unsigned artefact digests equal on a second runner image for every Linux artefact and image, and for Windows and macOS artefacts before signing |
| Signing | Every artefact signed keylessly with Sigstore cosign through GitHub's OIDC identity, with its Rekor inclusion proof; where a vendor programme also signs (Authenticode, Apple notarisation), verified with that platform's tool; without one, marked "not platform-signed" in the release manifest (owner instruction 23) |
| SBOM | CycloneDX from Cargo and pnpm metadata, cross-checked against a syft scan and the `cargo-auditable` section; any difference fails |
| Provenance | SLSA provenance, SBOM and cosign bundles attached; images get them as OCI referrers |
| VEX | An OpenVEX statement for every CVE in the SBOM, within seven days (design/24 24-5). List the gaps; writing statements is the security squad's item, never this skill's |
| Release manifest | `release-manifest.json` with its `compat` block (D-71) and the generated coexistence pack written; the bundle and its `compat` block are a TUF target |
| Gates again | Step 7 of design/24 section 10 re-runs the release gates on the built artefacts |
| TUF signing | `gh attestation verify` passes on every artefact before the release workflow signs the TUF `binaries` targets with the keys of its two GitHub Actions environments |
| Hosted deployment | Refused without the hosted-service gate's record of team/05 section 16 and before the `distributed` load test has passed. Self-hosting needs neither |
