# Review L02: enterprise buyer (20,000 seats, Falcon primary, Defender passive)

## Summary

I would run a Watch-only pilot on a few hundred developer machines at M2. I would not approve fleet enforcement from this spine. The principles are right (P1, P4, P8, D-16), but the spine is written as if Guardrails owns the endpoint. In my estate Intune and Jamf own agent managed settings, Falcon owns prevention, the web gateway owns egress, and ServiceNow and the SIEM own workflow. Three decisions are contradicted by the briefs' own verifier corrections (hook delivery, fail-closed flags, Sysmon and AMSI), and the decisions procurement needs (support, assurance, roles, data boundary) are absent. The change that matters most is F1: hook delivery must be owner-aware, or AL2 is silently AL1 on every MDM-managed machine.

## Findings

### F1 (blocker, wrong). D-14, D-12: a hook drop-in is skipped on MDM-managed machines

**Problem.** D-14 installs the shim "in admin-owned managed settings" and D-12 generates those files. Claude Code's default is `managedSourcesBehavior: first-wins`: if Intune (HKLM), Jamf (plist) or server-managed settings deliver any policy key, the whole file tier is ignored, hooks included. Large estates already push such a policy, so the hook never fires while the product reports AL2. Other vendors collide too: Zscaler's guide overwrites the whole `hooks` key.

**Evidence.** `15-coding-agent-surfaces.md`, verification row 2 and check C; `h03-incumbent-vendor-docs.md` TL;DR; `h08-practitioner-voice.md` section 3.

**Amendment.** Add to D-14: "Delivery has one owner per agent per device, found by probing the harness's effective managed source. Where MDM or server-managed policy exists, Guardrails writes nothing: it renders a fragment for that owner and requires `merge` where sources must compose. It never edits another vendor's entries. AL2 is claimed only after a canary tool call proves the hook fired; 'configured, not effective' is a health state and a finding."

### F2 (blocker, wrong). D-14 against D-15: vendor fail-closed flags are global, not per rule class

**Problem.** `onFailure: block` and Cursor's `failClosed` apply per hook entry. If the shim cannot start (quarantined by Falcon, mid-update, timed out), every matched tool call is blocked: the global default D-15 forbids. A thin shim also cannot tell a destructive command from a harmless one, because the analysers live in the daemon, and each daemon restart in a binary ring would deny calls.

**Evidence.** `15`, verification rows 1 and 5; `25-deployment.md`, weak points and implication 4; `g02` digest (Cisco's enterprise build defaults fail-open).

**Amendment.** Replace D-14's third sentence and extend D-15: "Harness layer: the vendor flag defaults to continue; `block` is a per-group strict choice shown with its blast radius. Shim layer: the shim carries a signed, compiled fail table (tool class, path and command prefixes) used when the daemon is unreachable. The daemon hands its socket over across updates; update-induced denials are budgeted at zero."

### F3 (major, risky). D-16: the explicit proxy takes a slot the estate already uses

**Problem.** Enterprises already pin the agent base URL to an LLM gateway and send egress through an inspecting proxy. D-16's third tier takes the same slot and drops brief g05's rule to originate upstream through the system proxy with the OS trust store. Unconfirmed field reports say that setting a base URL bypassed server-managed settings and the managed-hooks-only lock.

**Evidence.** `g05-edr-coexistence-testlab.md` section 3 and implication 4; `h08` sections 1 to 3 (rollout account; Claude Code issue 51123); `38-network-gateways.md` "Signed requests".

**Amendment.** Add to D-16: "The local proxy never replaces a customer-set base URL or proxy. It chains: agent, local listener, customer gateway or system proxy and PAC, trusting the OS store. Where a harness's managed settings or hook enforcement change when a base URL is set, tier three is off for that harness version."

### F4 (major, wrong). D-17 against D-23: Sysmon and AMSI break "no exclusive slots, no injection"

**Problem.** Built-in Sysmon has one configuration and cannot coexist with standalone Sysmon, which my SOC already runs. An AMSI provider is an in-process COM DLL loaded into every PowerShell, Office and script host: our code inside processes we do not own, and one crash domain across the fleet.

**Evidence.** `12-windows.md` capability table (Sysmon and AMSI rows), implication 2, verification row 8; `g05` section 1.

**Amendment.** D-17 phase 0: "ETW is the baseline. Sysmon is consumed read-only when the customer already runs it; Guardrails never installs, enables or reconfigures it. The AMSI provider leaves phase 0 and becomes a per-group opt-in on its own ring; PowerShell script-block ETW is the default." Lost: script-content blocking on Windows before the driver.

### F5 (major, missing). D-37, D-12: generated native configuration is a fourth, unringed channel

**Problem.** D-37 rings cover binaries, policy and content. D-12 writes into other vendors' configuration, where one malformed managed file stops Claude Code from starting. Agents update several times a week and hook contracts move (`onFailure` arrived in 2.1.295). The spine has no version-ranged contract.

**Evidence.** `25` section 2 and verification row 3; `g02` implication 4; `h08` section 2.

**Amendment.** D-37: "Four channels; the fourth is native agent configuration. Each generated file is validated against the vendor schema for the installed version, canaried with an 'agent starts and hook fires' probe, and rolled back automatically. Adapters declare tested version ranges; outside the range the adapter drops to Watch and raises a health finding. In MDM-owned estates the channel emits a signed change record (diff, replay result) for the customer's change process."

### F6 (major, missing). D-23, D-41, section 7: no profile for a Falcon estate, and the lowest-friction rungs ship last

**Problem.** With Defender passive, its agent discovery and runtime protection are off, so my alternatives are Falcon Guardian and Cortex's Targeted Sensor, which already sells "alongside your EDR". Buyers' top objection is another endpoint agent. Yet importers, L0, L1 and L4, the path with no new agent, sit in M3 and M4 although D-40 says importers ship first. Windows AL4 is unreachable here: CrowdStrike will not embed a rival, and Claude Code ignores `processWrapper` on Windows. Falcon coexistence is untested (documents gated).

**Evidence.** `27-embed-oem.md` TL;DR; `h03` TL;DR; `h08` sections 1 and 3; `g05` weak points; `04-crowdstrike.md` integration table.

**Amendment.** Add D-23a: "Each release publishes a ceiling matrix (OS, agent, incumbent: reachable AL and tamper grade) and passes an interference oracle against Falcon and Defender before Broad." Move importers, L0 for LogScale and KQL, and L1 to M2. Add to D-12: "compile to incumbent prevention policy (Falcon Custom IOA, IOC) as a boundary-grade target."

### F7 (major, risky). Section 6, D-14, D-20: performance targets are not end to end or measured beside an incumbent

**Problem.** A command shim is a process spawn per tool call, each inspected by Falcon; "p50 under 5 ms" holds only if measured inside the daemon. Brief 15 recommended an `http` hook to remove the spawn; D-14 chose the shim without saying why. "150 MB" does not say whether it sums D-20's processes with ONNX models loaded. g05's budgets (2% incremental per incumbent, 5 ms streaming first byte) were dropped.

**Evidence.** `15` deliverable 3 and "ideas"; `g05` section 4; `25` section 1 (Falcon sidecar: 1 to 3% CPU, 200 to 500 MB).

**Amendment.** Section 6: "Targets are measured at the harness, summed over every Guardrails process, with Falcon in prevention mode and Defender passive. Add: incremental developer-workload overhead under 2% per incumbent; streaming first byte under 5 ms. Publish numbers per release; ship `grd diag overhead`." D-14: hook transport is chosen per harness by spike S3.

### F8 (major, missing). D-04, D-46, D-47, section 8: procurement cannot complete

**Problem.** Nothing states who I contract with, how long a release is patched, or the vulnerability process; LTS appears only for OEMs. SOC 2 Type II lands at M5, ISO 27001 is absent, and brief 34's external penetration test was dropped. D-47 keeps human review only for the kernel driver, yet agents write the SYSTEM service, updater and credential broker. Nothing lists what leaves my boundary (LLM review, intelligence sharing, update pulls).

**Evidence.** `00-index.md` g10 digest; `34-compliance.md` roadmap table, verification row 3 (five-year support, Art. 13(8)), matrix row "DORA Art. 30".

**Amendment.** Add D-48: "LTS yearly, patched 24 months, for all self-hosters; PSIRT with CSAF and VEX and severity SLAs; five-year support statement; independent audit of privileged core, updater, shim and transport before M3, summary published; human security sign-off for anything running as SYSTEM or root; ISO 27001 beside SOC 2." Add D-49: "Every flow leaving the organisation is a tenant setting, off by default, region-bound, listed in a generated manifest." Resolve open question 1 before M2.

### F9 (major, missing). D-38, D-44, D-31: no role set and no separation-of-duties invariants

**Problem.** Roles "ship" and content is gated, but no invariant is stated. BeyondTrust's weakest point is that every console user is an administrator and users self-approve; the spine rules out neither. D-44's one-click exception names no approver.

**Evidence.** `00-index.md` 02 digest and surprises; `34` matrix row "SOC 2 CC6; 800-53 AC-5, AC-6" and implication 4.

**Amendment.** Add to D-38: "Roles: policy author, policy approver, responder, investigator, content reader, auditor (read-only, time-boxed), privacy officer, platform operator. Invariants, enforced in Cedar and tested: author is never approver for a widening change or a promotion to Ask or Block; exception requester is never approver; platform operator cannot read content; response and policy roles are separate; roles map from IdP groups through SCIM; elevation is just-in-time; break-glass needs two people."

### F10 (major, missing). D-06 against D-34, D-40, section 7: SIEM and ticketing

**Problem.** D-06 rejects storing OCSF names internally; D-34 stores "OCSF-shaped Parquet". Export is OCSF 1.9 only, but sinks lag (Security Lake accepts 1.3) and each SIEM needs parsers and dashboards. No sink ships before M3, so an M2 pilot cannot reach my SOC. Case duplicates ServiceNow without a system-of-record rule.

**Evidence.** `26-integrations.md` TL;DR, weak points ("sink lag"), catalogue matrix (generic sinks P0, ServiceNow P1).

**Amendment.** D-34: "Parquet uses the canonical model's published, versioned columns; OCSF is a materialised export." D-40: "Generic sinks (signed webhook, syslog, OTLP, OCSF JSON to object storage, HEC) ship in M2 with at-least-once delivery, cursor replay and stable ids. NG-SIEM, Sentinel, Splunk and ServiceNow are P0 with parsers and dashboards. When ticketing is connected, the external ticket owns status and assignee."

## Spikes

| # | Question | Method | Pass criteria |
|---|---|---|---|
| S1 | Can we detect and survive first-wins? | Macs (Jamf plist) and Windows 11 machines (HKLM) with one unrelated policy key; add our drop-in, then a second vendor's hook | Effective source detected without user action; under `merge` both hooks fire and deny wins; canary flags "configured, not effective" every run |
| S2 | Does a chained base URL keep enforcement? | Current and two prior Claude Code minors with managed-hooks-only and server-managed settings; base URL to local listener to gateway behind a re-signing proxy | Managed hooks fire, server settings load, streaming works, no extra CA |
| S3 | Shim or `http` hook beside Falcon? | 10,000 PreToolUse calls per transport on Windows 11 (x64, ARM64) and macOS, Falcon prevention on, Defender passive | Harness-side p50 at most 15 ms, p99 at most 50 ms; zero Falcon detections; `cargo build` and `npm ci` regress under 2% |
| S4 | Is Custom IOA a usable boundary? | In a design partner's Falcon test tenant, push a generated process-creation rule (agent parent image, command-line pattern) by API | Blocked before start in 20 of 20 trials with hooks removed; rollback by API; the same command from a human shell runs |

## Agreed

- P4 and D-08: local decisions from signed bundles; Guardian's 30-second cloud call is my main objection to it.
- D-16: no mandatory TLS interception; a second interception point would not pass change control.
- P8 and D-44: metadata-only default and the developer transparency panel.
- P1 with assurance level and tamper grade: lets me write an honest risk acceptance.
- D-02 and P11: Apache-2.0 with SSO, RBAC and audit in the open build passes licence review.
- D-11: replay before enforce; narrowing automatic, widening approved.
- D-35: regional cells, customer-held keys, co-signed policy.
