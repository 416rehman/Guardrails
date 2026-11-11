# Review L04: endpoint engineering lead

## Summary

The sensor architecture is sound. What is missing is the part I own: how this lands on a fleet, upgrades, goes offline and is removed. The spine has no decision on packaging, update authority, proxies, VDI, diagnostics or uninstall, and three decisions contradict each other or the briefs. The most important change: treat everything we write into another product's configuration (D-12, D-14) as a ringed, journalled release channel. As written, our hook is silently ignored on any Claude Code fleet that already uses MDM or server-managed policy, and one malformed file stops every developer's agent from starting.

## Findings

### 1. Blocker, wrong. D-12, D-14, D-16: native-config writes can be ignored or brick the agent

Claude Code ranks managed sources remote, then MDM plist or HKLM, then files, and by default uses only the first that has a policy key, with no warning. A lower source cannot opt into merging, so our `managed-settings.d` drop-in is dead on fleets that already manage Claude Code. Setting `ANTHROPIC_BASE_URL` to our proxy (D-16) makes Claude Code skip remote settings altogether. A file that does not parse stops Claude Code starting even when another source is valid. If the incumbent blocks `grd-hook` (Defender's ASR prevalence rule `01443614-…` can block new low-prevalence executables) while `onFailure: block` is set, every tool call is denied. D-14 also says "only admin-owned", which a Standalone user without elevation cannot do.

Evidence: 37 verification row 2; 15 verifier's corrections; 25 §2 and verification row 3; code.claude.com/docs/en/managed-settings and Microsoft's ASR rules reference, both re-read today.

Amendment, new D-14a: "Native-config writes are a fourth release channel. The installer probes each agent's effective managed source and chooses MDM-owned delivery (`grd hook install --print` emits the profile or registry value; we write nothing) or a sensor-owned drop-in. A hook hidden by a higher source is reported `shadowed` and the instance stays AL1. Generated files are schema-validated, proven by starting the pinned agent in CI, written atomically with the previous copy kept, and ringed with a halt on agent-start failure. Fail-closed flags are set only after an on-device shim self-test. An install journal records every external write and its prior value. Standalone without elevation uses user scope at tamper grade `user`."

### 2. Major, missing. D-36: uplink cannot cross inspecting or authenticating proxies

Transport-layer mutual TLS does not survive a re-signing proxy, gRPC streams and WebSockets are routinely broken, and hybrid key shares trip middleboxes. Brief 24 recommended request signing and renewal by proof of possession; brief 23 recommended an HTTP polling fallback for OpAMP. The spine carries none of them.

Evidence: g05 §3; 23 weak points (ClientHello size) and design implications; 24 implications (enrolment); h08 TL;DR (TLS inspection).

Amendment to D-36: "Device authentication is application-layer: requests and batches are signed with the device key; mutual TLS is an extra binding where the path allows. A probed, reported ladder: gRPC stream, HTTP/2 unary, HTTP/1.1 POST and long-poll through the system proxy (PAC, MDM-set, environment) with Negotiate, NTLM or Basic authentication. The egress host list is fixed, small and published. The D-16 local proxy chains upstream through the system proxy and OS trust store."

### 3. Major, missing. D-36, D-37: update authority and the offline lifecycle

Enterprises patch through Intune, Jamf, Configuration Manager and apt or yum; a self-updater fights all of them. Network Extension activation drops every connection, so an unscheduled upgrade kills SSH sessions. With monthly minors, "two prior minors" is about three months: a laptop back from leave is out of window with an expired certificate, and the spine does not say what happens next.

Evidence: 25 §2 and implications 7, 12; 13 §3 (lazy install); g10 §6 (monthly minors, out-of-range behaviour); 24 implications (renewal by proof of possession); 36 implication 6; 37 fail table.

Amendment, new D-37a: "Update authority is a group setting: `self` (TUF, two slots, rings), `managed` (MDM or the package manager owns binaries; our updater is inert and the server reports skew), `image` (no binary writes). Content and policy flow in all three. Extension replacement on macOS waits for reboot, wake or idle. A device offline past certificate expiry renews by proof of possession (default limit 180 days). Out-of-window sensors keep cached policy and are never refused renewal or upgrade. Sleep and shutdown send a signed going-down state so gaps are not tamper findings."

### 4. Major, missing. D-36, D-11, D-43: VDI, session hosts and clones

`(device, boot, seq)` idempotency discards real events when cloned images share an identity. Use-capped short-lived tokens and hardware keys cannot enrol pooled non-persistent desktops. "One effective set per device" is wrong on a 30-user session host, where a loopback console and a single broker process are also reachable by every user.

Evidence: 25 §2 (VDI) and implication 6; g04 §5 and implication 5; 12 §8; 29 TL;DR.

Amendment, new D-36b: "Enrolment methods: token, MDM-delivered file, and platform attestation for images. `grd image prepare` strips identity. The server treats divergent boot or sequence under one credential as a clone: it quarantines the stream and forces re-enrolment, never deduplicates. On session hosts policy, assurance level, broker, proxy and local console are per logon session, bound to the user SID over peer-checked pipes, never a shared loopback port. Until that ships, the installer refuses session hosts."

### 5. Major, wrong. D-18 contradicts D-23 on the macOS DNS-proxy slot

D-18 ships "content filter and DNS proxy"; D-23 says we never take the DNS-proxy slot. ZTNA and DNS-security clients normally own it.

Evidence: g05 TL;DR, matrix row "macOS DNS proxy or VPN slot" and implication 3; g05 verification row 10 (filter grade is documented, verdict combination is not).

Amendment to D-18: "Tier two is a content filter only, its grade chosen by the slot broker and reported. No DNS proxy, transparent proxy or VPN configuration by default; hostnames come from flow metadata. A DNS proxy is opt-in where the slot is free." Lost: resolver-level visibility where another product owns the slot.

### 6. Major, wrong. D-17 Phase 0: AMSI provider and built-in Sysmon

An AMSI provider is an in-process DLL in every PowerShell, Office and script host, including the SYSTEM scripts Intune uses to repair us: our code in other processes (against D-23), handling untrusted content at high privilege (against D-20). Sysmon takes one configuration, and built-in Sysmon cannot coexist with the standalone Sysmon many SOCs already feed to a SIEM: an exclusive slot.

Evidence: 12 §5 table and implication 2; g05 §1; h08 TL;DR (EDR collisions).

Amendment to D-17: "Phase 0 baseline is ETW, including PowerShell script-block events. Sysmon is read when present and never installed, enabled or configured by us. The AMSI provider is opt-in and outside Phase 0: forward-only, lineage early-out, 50 ms fail-open, unregistered automatically after repeated host crashes." Lost: synchronous blocking on de-obfuscated script content.

### 7. Major, risky. D-14, D-15: fail-closed "by rule class" inside a thin shim

With the daemon down, deciding that a call is a secret, destructive or config action needs the canonicalisers that D-10 calls security-critical and D-20 keeps out of the untrusted shim. Every daemon restart, including every upgrade, becomes a denial window.

Evidence: 37 fail-open table and architecture table (shim is an opaque forwarder); 25 implication 4; h08 acceptance criteria (2 s watchdog, block message).

Amendment to D-15: "Loss-of-sensor behaviour is declared per pack and group, default allow with Degraded, always so in Standalone. Packs in Block may declare deny. The shim carries only a signed precompiled tripwire table (tool name and literal path, no parsing), waits up to 2 s, and prints component, rule, receipt code and next step. Upgrades hand the socket to the new daemon. Help desk can issue a signed, time-boxed code that puts one device in Watch offline."

### 8. Major, risky. D-21 and M2: "sandbox launcher (AL3) everywhere"

AL3 depends on developers starting agents through `grd run`; Claude Code's process wrapper is ignored on Windows and misses terminal-started sessions. A Windows sandbox principal has no Kerberos ticket, DPAPI, credential manager or SSH agent, so proxy authentication, git and package installs are likely to fail (my inference, untested). On macOS a non-root descendants client blocks every setuid exec, so `sudo` breaks. On Ubuntu, AppArmor blocks the user namespaces that optional bubblewrap needs.

Evidence: h08 (corporate launcher; failure pattern 7); 13 verifier's corrections; 14 digest; g03 verifier (MXC confines only what we launch); 12 weak points.

Amendment: D-21 adds "AL3 is opt-in per agent type and OS until the developer-workload corpus passes inside the launcher; the launcher probes first and stays at AL2 with a stated reason. The Windows default is tool-subprocess containment, not re-homing the whole agent." M2 reads "AL3 where the corpus passes; coverage table published".

### 9. Major, risky. Section 6 targets

Three briefs give three hook numbers; the spine took the tightest without saying where it is measured. On Windows each tool call starts a process that the incumbent scans. 150 MB cannot hold D-20's processes (brief 37 budgets 60 MB plus 150 MB for two of them) and D-29's models. There is no disk or over-incumbent budget.

Evidence: 37 budgets; h08 acceptance criteria (30 ms Windows cold start); g05 §4.

Amendment: replace the rows with "Hook, agent-observed including shim start: p50 10 ms, p99 50 ms on Linux and macOS; p50 25 ms, p99 100 ms on Windows with Defender and one third-party EDR", "All endpoint processes, no models: 1% of one core idle, 250 MB resident; models opt-in and budgeted separately", "Disk cap 1 GB", "Build overhead 3% alone, 2% added per incumbent".

### 10. Major, missing. No deployment and support contract

Nothing covers packages, supported OS versions, diagnostics or uninstall. g05 warns that the newest agent is blamed for every slowdown and removed first; the help desk needs proof of what we did.

Evidence: 25 §2 and implications 6, 12; 37 test matrix and self-protection table; g05 ideas (overhead self-attribution); g10 implication 6 (support bundle, server only).

Amendment, new D-48: "Per-machine MSI (x64, ARM64), one notarised universal pkg, signed deb and rpm repositories: silent, idempotent, offline-installable, default paths, no enrolment secret on the command line; the Rune console is an optional package. A support matrix per release (Windows 11 and Server 2022 or later; macOS current and two previous; Linux by probed capability with a kernel floor). `grd doctor` reports capabilities, slot owners, whether each agent's hook fired, network rung and overhead by path. `grd support-bundle --preview` redacts on the device. Uninstall accepts a token, MDM profile removal or an organisation-held offline key, and restores the D-14a journal."

## Spikes

1. **Where does our hook fire?** Pinned Claude Code, Codex, Cursor and Copilot CLI on three OSes, across remote, MDM and file policy, merge on and off, base URL at loopback, one malformed drop-in. Pass: the installer probe predicts hook presence in every cell, and no write of ours stops an agent starting.
2. **Is the hook budget reachable on Windows?** 10,000 no-op shim calls on Windows 11 x64 and ARM64 with Defender ASR rules in block, then with one third-party EDR. Pass: p50 25 ms, p99 100 ms, zero blocks or detections; otherwise use a persistent connection.
3. **Does the uplink survive enterprise proxies?** Squid with Kerberos and PAC; a TLS-inspecting proxy with HTTP/1.1 downgrade. Pass: enrol, upload, config, update and a signed command succeed in each, and the rung is reported.
4. **What breaks inside the launcher?** h08's package and agent matrix on domain-joined Windows 11, macOS 27 non-root and Ubuntu 24.04. Pass: zero failures, or each maps to a probe that keeps the session at AL2.

## Agreed

- D-16: no mandatory TLS interception (h08, g05).
- D-17: driverless first, driver on its own train, WESP only through embedding.
- D-22: prevent against user-level agents, detect against administrators.
- D-23: slot broker and coexistence pack, apart from findings 5 and 6.
- D-37: content separate from binaries; crash-loop ladder disables content first.
- D-43: GPU-free tray, local web console fallback.
- P9 with assurance level and tamper grade: a truthful state for the help desk.
