# Review L06: solo developer and five-person startup lens

Stance: I run Claude Code, Cursor and Codex all day with auto-approve on, have no MDM, and would install this by choice. Briefs: 33, 15, 08, 35, 01, h08, 25.

## Summary

The spine promises a standalone product with no account (D-01, D-44) but specifies the endpoint as if an administrator always installs it. Three decisions would make me uninstall within a week: hooks only in admin-owned managed settings (D-14), vendor fail-closed flags set wherever they exist (D-14 against D-15), and approvals that never accept a same-privilege click (D-31). Each is right for a managed fleet and wrong as the only mode. The change that matters most is an explicit `user` install profile with its own failure, approval and tamper rules, labelled request-level under P1. Second: nothing states what standalone sends off the machine, or how it joins a server without rewriting signed history.

## Findings

### 1. D-14 has no install path for the standalone product (wrong, blocker)

**Problem.** "Installed only in admin-owned managed settings" needs elevation on every OS, yet D-20 makes the first standalone release a user-level daemon and section 3 defines a `user` tamper grade. On Claude Code the file tier is skipped when a server-managed or MDM source sets any policy key, so the hook can silently never fire.

**Evidence.** 25 deployment matrix row 1: solo is "User install; no MDM; hooks-only". 15 verification row C: `first-wins` skips the file tier, hooks included. 15 forbids only project scope.

**Amendment.** Replace that sentence with: "The shim installs in one of two profiles. `user` (standalone default): no elevation, hooks in each agent's user-scope settings, tamper grade `user`, reported as request-level. `managed`: admin-owned paths and managed settings. Never project scope. Before writing, the installer resolves which settings source each agent honours and writes there, requires `managedSourcesBehavior: merge`, or reports `hook-shadowed`. A per-session canary confirms the hook fired within 60 s. Events are de-duplicated by agent, session and tool-use id, because Copilot, Cursor and Devin also read `.claude` hooks."

### 2. Vendor fail-closed flags contradict per-rule-class failure (wrong, blocker)

**Problem.** `onFailure: block` and `failClosed` apply to a whole hook handler, not a rule class. With them set, a crashed daemon blocks every tool call, including `ls`. The shim cannot know "the rule class says so" when the daemon holding the policy is unreachable. Default hook timeouts are 600 s in Claude Code and Codex, so a hung daemon is a hung session.

**Evidence.** 15 section 1 and verification row 1; 25 weak points ("fail-closed hooks or a malformed managed file stop developers working"); h08 section 2: all write tools blocked for 30 minutes during a classifier outage.

**Amendment.** Replace the fail-closed sentence in D-14 with: "The shim carries a signed fail-safe table compiled from the last-known-good bundle (the fail-closed rule classes as canonical patterns). If the daemon does not answer in 250 ms the shim decides from that table: deny for those classes, otherwise allow, spool and flag Degraded. The shim always returns within 2 s and every hook registration sets an explicit timeout. Vendor fail-closed flags are set only in the `managed` profile when the organisation sets `on-sensor-loss: block`."

### 3. D-31 makes Ask unusable for auto-approve users and contradicts D-07 (wrong, major)

**Problem.** D-07 relies on the hook's native ask; D-31 says a click in the agent's own UI is never an approval. Standalone is left with an authenticator tap for every Ask, or a dead-end deny on Codex, which has no ask verb. Section 6 gives the prompt budget no number.

**Evidence.** 33 approval prompt anatomy and acceptance table (median 3, p95 8); h08 TL;DR: prompt fatigue ends in bypass aliases; h08 acceptance: no dead-end denials; 15 translation notes: ask degrades to deny on Codex.

**Amendment.** Add to D-31: "Approvals have two grades. `confirm`: the agent's native ask or the tray, same privilege, labelled a request; allowed for reversible, in-workspace rule classes. `verified`: privileged helper or out of band, bound to the action digest; required for irreversible, secret, out-of-boundary and config-tamper classes and for any grant longer than the session. Each rule class declares its minimum grade. Where a control point has no ask, the request surfaces in the tray and the denial tells the agent to retry after approval." Section 6 prompt row becomes: "median 3 or fewer and p95 8 or fewer interruptive prompts per developer per active day; after 3 same-shape prompts in a session, offer a scoped rule."

### 4. D-10 denies everything the morning an agent auto-updates (missing, major)

**Problem.** "Ambiguous parses deny" is right for a shell command. Applied to a hook envelope from a newer agent version it blocks all work. D-37 stages our releases, not the vendors'. There is no adapter compatibility policy.

**Evidence.** 15 weak points: "adapters need version probes and conformance tests"; h08 section 2: Claude Code went from v2.1.240 (2026-08-22) to v2.1.304 (2026-10-20); 08 section 4: openclaw-shield "rots within days".

**Amendment.** Add to D-10: "Deny-on-ambiguity applies to the action inside a recognised envelope, and only for fail-closed rule classes. An unrecognised harness envelope, tool or field never denies: the adapter drops that agent to Watch and raises `adapter-unknown-version`. Adapters declare a tested version range; CI runs the hook conformance suite nightly against each vendor's latest and pre-release builds; an adapter pack ships within 24 hours of a breaking vendor release."

### 5. Day-one posture is undefined and three decisions disagree (missing, major)

**Problem.** D-44: new packs start in Watch. D-28: protected paths by default. D-15: secrets and destructive actions fail closed. Nobody can tell what blocks in minute one, and pure Watch gives an auto-approve user only a log.

**Evidence.** 33 design review: allow-all first runs "break Smart Defaults"; 33 fatigue controls: seven-day Watch, then propose rules; h08 section 5: individuals install narrow destructive-command guards.

**Amendment.** Add to D-44: "First run: everything in Watch except a baseline tripwire pack in Block (recursive delete outside the workspace, credential-store reads by agent lineage, writes to any agent's hooks, settings or MCP configuration, disabling Guardrails). A rule enters that pack only with zero false positives in replay over the benign corpus. Install shows 'would have blocked N times last month' from back-filled transcripts. After seven days the product proposes promotions from observed history."

### 6. No statement of what standalone sends off the machine (missing, major)

**Problem.** D-36 (TUF), P7 packs and D-32 reputation all imply network calls. Per-digest reputation lookups would disclose my MCP servers and skills. D-04's "reciprocity-tiered" feed means sharing data to get content, which strains P11.

**Evidence.** 25 matrix row 1: "no network egress"; h08 section 2: an email in a request header drew 1,060 reactions; 01 section 6: trace stores are crown-jewel targets.

**Amendment.** Add D-48: "Standalone network contract. The only outbound traffic is anonymous TUF fetches of binaries and content from a mirrorable static origin, with no device id, which can be disabled. Reputation is matched on the device against a downloaded feed. No usage or crash telemetry without opt-in. The base feed needs no sharing. `grd egress` lists every destination; CI asserts that a standalone run with updates off opens no non-loopback socket. Local history stores metadata by default, redacts secrets before write and sits on the default protected-path list."

### 7. Growing into the console hides a migration in the envelope (missing, major)

**Problem.** Section 3 gives standalone "one constant organisation"; D-06 puts the organisation in the envelope; D-39 hash-chains signed events. Joining a server then means rewriting signed history or importing colliding ids. D-36 enrolment assumes an admin; a five-person startup has no MDM.

**Evidence.** 25 matrix row 2 (device-code login); h08 implication 8 (self-install with a join code); 33 personas (invite link).

**Amendment.** Add D-49: "Standalone generates a random organisation id and device key at install. `grd join <code>` enrols with no MDM; the server records the local id as an alias, so chains and receipts verify unchanged. Local history stays on the device, upload starts at join, back-fill is a per-user opt-in. Before joining the user sees the capture level, who can read it and which rules become locked. Local policy becomes the user layer of D-11. `grd leave` restores standalone. A team with no server shares a pack by git URL pinned to a digest."

### 8. Install is not reversible by decision, and first value waits on hooks (missing, major)

**Problem.** D-22 has uninstall tokens for fleets and nothing for me. D-12 generates native settings that can disable the bypass mode I work in. D-44's "value before sign-up" names no mechanism.

**Evidence.** 08: numbat and uber/ADR reconstruct sessions from on-disk transcripts with no instrumentation; h08 section 5: stray dotfiles (34 comments).

**Amendment.** Add D-50: "`grd init` step one changes nothing: scan plus transcript back-fill, first agent and session inside five minutes. Step two shows the diff of each settings change and asks. Every changed file is journalled; `grd uninstall` restores byte for byte and CI proves zero diff. `grd pause <duration>` unhooks within 5 s under a `verified` approval. D-12 generation is opt-in in the `user` profile."

### 9. M1's only window depends on Rune, and the loopback surface is open to the agent (risky, major)

**Problem.** M1 lists "tray and local console"; the web console is M2; D-43 calls the localhost web console the fallback. M1 therefore has no fallback without a GPU. Separately, a same-user agent can call a loopback API or run `grd policy apply` itself.

**Evidence.** 29 digest: no CPU renderer, 180 MB floor, no macOS tray; 35 section 3: DNS rebinding against a local credential endpoint.

**Amendment.** Section 7, M1: "CLI, tray, and the web console subset served on loopback"; the Rune shell moves to M2 after soak. Add to D-43: "The local API uses a Unix socket or named pipe; the browser path uses a one-time launch URL with Host and Origin checks. Mutating verbs need a `verified` approval and are refused when the caller's lineage is an agent session."

### 10. Section 6 targets are ambiguous or unmeasured (risky, minor)

**Problem.** "Hook decision p99 under 30 ms" does not say whether shim process start counts; on Windows it probably dominates. D-14 drops the `http` handler that 15 recommended to avoid spawn cost. The 5,000 events a day figure is an assumption.

**Evidence.** 15 deliverable 3 step 1; h08 acceptance table (30 ms Windows cold start; agent and package matrices); g10: events per endpoint is unmeasured.

**Amendment.** Define the row as "added wall-clock per tool call seen by the agent, including shim start: p50 10 ms, p99 50 ms on Windows with real-time scanning on; p50 5 ms, p99 30 ms elsewhere". Add release-blocking rows: agent matrix (launch, sign-in, streaming, self-update, stdio and HTTP MCP) for the M1 agents on three OSes; package-manager matrix; zero detections of our shim by Defender, Falcon, SentinelOne and Sophos.

## Spikes

| # | Question | Method | Pass |
|---|---|---|---|
| 1 | Does a command shim meet the latency target? | 10,000 pre-tool calls per OS, command shim against `http` handler, Defender on | p50 10 ms, p99 50 ms on Windows; otherwise adopt `http` with command fallback |
| 2 | What happens when we break? | Kill, hang, delete and corrupt daemon, shim and bundle under the four M1 agents, default and bypass modes | No hang over 2 s; benign calls proceed; tripwire classes denied; Degraded shown in 60 s; hooks block in bypass mode |
| 3 | Is user-scope install reversible? | Install and uninstall on clean machines and one with server-managed Claude settings | Zero diff after uninstall; shadowed hook reported in 60 s |
| 4 | What is real event volume? | Counting hook on five heavy auto-approve users for two weeks | Measured p95 developer-day replaces the 5,000 figure |

## Agreed

- D-01: standalone as a real product with no account.
- D-16: no mandatory TLS interception.
- P4 and P2: local, deterministic decisions; no classifier as a hard gate.
- D-11: replay before Ask or Block.
- P8 and D-44: the panel showing what is collected and why something was blocked.
- P11 and D-02: console and roles in the open build.
- D-23: designed coexistence with incumbent EDR.
- D-43: approvals never resting on a Rune click.
