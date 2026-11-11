# 09. macOS sensor

_Status: draft 5 (aligned with spine v4, the rulings, the owner's answers in `_review/02-owner-answers.md` and the owner's instructions of 2026-11-11 in `_review/04-owner-kit-instructions.md`), 2026-11-11. Owning squad: macOS (the Swift shell and system extensions are trust core under D-63). Read with: `00-decisions.md` (spine v4, authoritative); 03 (topology, crates, lint); 04 (events, provenance grades); 05 (inventory); 06 (attribution); 07 (control points, shim, assurance record); 11 (on-device update mechanics); 12 (policy); 18 (approvals); 22 (update protocol, rings); 24 (build, signing, packaging); spine D-45 and D-64 for the efficacy harness and test lab (the detailed document is pending)._

## Summary

This document specifies D-18 and the macOS part of D-20 to D-23 and D-59. The sensor is `grdr-sensor-macos` (layer 3) plus a Swift shell under `platform/macos/`. It reaches its assurance in three tiers that depend on what Apple has approved, never on what we would like to claim.

Key choices:

1. **Three tiers, each useful alone.** Tier 1 (no Apple approval at all): hooks, compile-down, discovery, and Seatbelt containment. Tier 2 (requires Apple's Developer Program for Loonaro): a Network Extension content filter. Tier 3 (requires the Program and Apple's Endpoint Security entitlement): Endpoint Security. Without the Program, macOS ships with Sigstore signatures and provenance, marked not platform-signed and not notarised, at tier 1 only (D-18, D-59, spine question 8).
2. **Honest visibility.** Tiers 1 and 2 report `visibility: claimed` for `exec` and `file.*` (D-18). The transcript tail is the second claim source (07 section 9). Tier 2 raises only `net.connect` to `observed`.
3. **One system extension per technology.** One Network Extension (content filter; DNS proxy and transparent proxy as opt-in providers in the same extension) and, at tier 3, one Endpoint Security extension hosting one ES client per concern. The clients that watch agent trees follow them themselves and re-select the exec target on every exec.
4. **Full ES clients never hold for a human.** `STEP_UP` from a full client is a denial with a retry token (D-07). Only the macOS 27 descendants client, used by the launcher, may hold, and only within a deadline floor. The ES extension answers fail-closed classes from its own copy of the floor table, so they never wait on the daemon or the engine (D-20).
5. **No exclusive slots.** No DNS proxy, transparent proxy, VPN configuration or PF by default. The content filter's grade comes from the slot broker (D-23).
6. **A Rust static library with a C ABI behind a thin Swift shell.** All policy, process tree and telemetry logic is in Rust; Swift owns only Apple object lifecycles. An embedding EDR vendor does not take this library: it feeds the same fixed-layout records to the L3 fast-path library (`grdr-ffi`) inside its own entitled extension (D-41).
7. **MDM first for fleets, a guided manual path for one Mac.** We generate the profiles, and every manual approval is optional and explained.
8. **Apply for the ES entitlement as soon as Loonaro's Team ID exists.** While it is pending, tiers 1 and 2 are the product and ES is built and tested only on SIP-disabled test guests.

## Requirements

| # | Requirement | Trace |
|---|---|---|
| R1 | A working product with no Apple approval at all (tier 1, Sigstore-signed and marked not platform-signed without the Developer Program); signed and notarised when Loonaro holds Apple's Developer Program | D-18, P12; brief 13 implication 1 |
| R2 | The assurance record per action class matches what the active tier can prove; no tier overstates `visibility` or `control` | P1, P9, D-18; c3 F6 |
| R3 | No exclusive OS slot is taken by default; the slot owner and the chosen rung are reported | D-23; g05 implication 3; l04 F5 |
| R4 | No ES handler waits for the engine or a person past its deadline; on macOS 27 a miss never kills our client; a stalled engine never freezes the Mac | D-15, D-20; brief 13 section 1; g05 verification 4 |
| R5 | On loss of the engine or daemon, fail-closed classes deny only for processes inside session containers | D-15 |
| R6 | A silent install is possible on a user-approved-MDM Mac; a single Mac installs by hand with each approval optional | D-59, D-48; brief 25 |
| R7 | One universal pkg, notarised when Loonaro holds Apple's Developer Program; uninstall restores every file we changed, byte for byte | D-59, D-49 |
| R8 | Coexistence with Defender for Endpoint, and with Falcon and at least one more incumbent where their licences come through design partners or free vendor programmes, is tested before broad release; a ceiling matrix is published, with untested cells marked | D-23, D-64 |
| R9 | Agents inside VMs are reported as covered, partly covered or not covered, never assumed covered | P9; brief 13 section 8 |
| R10 | A self-builder without our signing identity gets tier 1 and a clear statement of what is missing | P11; brief 13 section 2 |
| R11 | Supported releases: the current macOS major and the two before it (15, 26, 27 at 2026-11-10); arm64 is support tier 1, x86_64 support tier 2 | D-50, D-59; briefs 25, 37 |

## Design

### 1. Tiers and assurance

| Tier | What ships | Apple dependency |
|---|---|---|
| 1 | Hook shim and broker; compile-down to Claude Code and Codex managed settings; discovery passes 1 and 2 from user-space scans; transcript tail; Seatbelt launcher (`grdr-run`) | None. Signed with Developer ID and notarised when Loonaro holds Apple's Developer Program; otherwise Sigstore-signed only and marked not platform-signed (D-59) |
| 2 | Network Extension system extension: content filter; DNS proxy and transparent proxy as opt-in providers | Apple's Developer Program for Loonaro (Team ID, Developer ID with the NE capability; annual fee, spine question 8); no request step beyond that (brief 13 verification 5) |
| 3 | Endpoint Security system extension; on macOS 27 the descendants-scoped launcher | The Program plus `com.apple.developer.endpoint-security.client`, granted by Apple (section 7) |

Assurance record per class, protected profile, for a support-tier-1 agent (D-50: Claude Code and Codex), as `visibility / control`; 07 section 11 gives the value rules. The launcher column applies only to sessions that entered our launcher or a delegated sandbox whose conformance covers the class (section 4).

| Class | Tier 1 | Tier 1 with launcher | Tier 2 adds | Tier 3 adds |
|---|---|---|---|---|
| `exec` | claimed / request | claimed / scoped-boundary | (no change) | cross-checked / mandatory-boundary |
| `file.read`, `file.write`, `file.delete` | claimed / request | claimed / scoped-boundary | (no change) | cross-checked / mandatory-boundary over every path set a file rule names (the guard's unmuted targets, section 6) |
| `net.connect` | claimed / request | claimed / scoped-boundary (the profile allows only the `grdr-proxy` listener) | observed / mandatory-boundary | cross-checked once ES lineage joins flows to tool calls |
| `elevate` | claimed / request | claimed / scoped-boundary (the profile denies elevation paths, D-22) | (no change) | observed / mandatory-boundary for execs of elevation binaries and connects to container sockets; ES `SUDO`, `SU`, `AUTHORIZATION_*` are notify only |
| `config.change` | claimed / request, plus an FSEvents integrity watch | claimed / scoped-boundary for writes from inside the profile | (no change) | cross-checked / mandatory-boundary (protected-path guard) |

The launcher column is per agent. Claude Code's own sandbox covers shell commands only; its Read, Edit and Write tools, MCP servers and hooks run outside it, while Codex's sandbox also covers its built-in file operations (brief 13 verification 8). In delegate mode Claude Code therefore reaches scoped-boundary for `exec` from its shell tool only, and `file.*` stays at request; AL3 for Claude Code needs wrap-agent, which S-11 decides.

Resulting levels: tier 1 gives AL2 (protected profile, canary passed); tier 1 with the launcher gives AL3 where the workload corpus passes inside the launcher (D-21), for Codex by delegate and for Claude Code only if S-11 admits wrap-agent; tier 2 keeps the level, with stronger network control; tier 3 gives AL4 for support-tier-1 agents, which requires the entitlement. In the user profile every control is `request` and `tamper: user` (D-48).

`on_failure`: the Seatbelt profile is `closed`, because it stays applied when our processes die. The ES extension is `closed` for fail-closed classes inside session containers, because it answers them from its own floor table (section 6), and `open` for everything else. The content filter is `open` until spike SP-MAC3 shows what the system does to flows when our provider stops; the briefs do not establish it.

### 2. Process topology on macOS (D-20)

| Process | Form | Account (protected) | Notes |
|---|---|---|---|
| `grdr-daemon` | launchd daemon | root | Process tree, session containers, floor table, actuators, spool, peer checks. Links no content parser (ARCH-004) |
| `grdr-engine` | child of the daemon | `_grdr-engine` role account (24), Seatbelt profile of 11 section 2 | All parsing and policy |
| `grdr-uplink`, `grdr-proxy` | children of the daemon (11 section 1) | low-privilege role account (`_grdr-uplink` for the uplink, 24) | As 03 |
| `grdr-updater` | on demand | root | Pack verifier (D-37) |
| `grdr-run` | launcher | caller's user; on macOS 27 in the protected profile a root supervisor spawned by the daemon (section 4) | Applies the Seatbelt profile; on macOS 27 holds the descendants client |
| Network Extension | system extension, `NEFilterDataProvider`; `NEDNSProxyProvider` and `NETransparentProxyProvider` opt-in | root, under the system extension sandbox | Tier 2; verdicts from its own `grdr-fastpath` tables; fixed-layout flow records to the daemon over XPC |
| Endpoint Security extension | system extension | root | Tier 3; answers AUTH events from its own copy of the floor and fast-path tables; fixed-layout events to the daemon over XPC |
| Container app | `/Applications/<product name>.app`, the name from the brand manifest's `product_name` (`Guardrails ADR.app` in Loonaro's distribution; D-66) | user | Only activates system extensions and hosts the approval helper; not load-bearing |

IPC: the hook socket of 07 (`/var/run/grdr/decide.sock`, root-owned directory; user profile `~/Library/Application Support/grdr/run/`). Peers are identified by audit token, never PID. Between our own signed components we use XPC with `xpc_connection_set_peer_code_signing_requirement` pinned to our Team ID and the component's signing identifier (brief 37 section 3, where the API and its macOS 12 floor are prior knowledge; E1.1 proves them). Extensions send only fixed-layout records, so the daemon parses no extension-supplied content. Both extensions are privileged programs under ARCH-004: their closure holds `grdr-fastpath` and the fixed-layout codec, no content parser.

**Tables in the extensions.** The daemon pushes every floor-table and fast-path-table swap, and every enforcing-label change, to each extension over XPC and waits for the extension's acknowledgement before it acknowledges the control point that caused the change, so the extension's copy is never older than the daemon's projection (03 section 4, item 3). If the daemon is gone, the extensions keep answering from the last tables they hold and report Degraded.

**User profile.** Only tier 1 and the user-run Seatbelt launcher exist: the daemon is a LaunchAgent under the user's account, and neither extension is activated, because both need a root daemon (D-48).

### 3. Tier 1 in detail

1. **Discovery.** User-space scans with `libproc` and code-signature checks (`SecCode`) find running agents and their program identity: Team ID plus signing ID for signed native agents, `cdhash` for the exact build, and argv plus package metadata for Node-hosted agents whose signer is Node or Homebrew (brief 13 section 6). Agent configuration, MCP and skill files are read only from known locations (05, D-24). Polled process events carry provenance `observed-user` (04 section 9) and feed inventory, not the assurance record. In the protected profile the daemon opens transcript and configuration files and passes the descriptors to the engine, which parses them (ARCH-004); a Full Disk Access grant therefore belongs to the daemon (section 8).
2. **Hooks.** The shim and broker are as 07. The admin-scope routes are the Claude Code drop-in `/Library/Application Support/ClaudeCode/managed-settings.d/` and, where MDM owns delivery, the Claude Code `com.anthropic.claudecode` plist and the Codex `com.openai.codex` key `requirements_toml_base64` (07 section 4). Where MDM owns them we write nothing and render the fragment (D-49).
3. **Second claim source.** Without a process event stream, the transcript tail checks that each tool-use entry had a `tool.pre`. A missing one raises `canary-missed` (07 sections 9 and 11). This is the gating proof that lets AL2 hold at tier 1 with `visibility: claimed`.
4. **Protected files.** Agent and product control files are watched with FSEvents. FSEvents names the changed path, not the writer, so each change is matched against the install journal and against open `tool.pre` writes for that path; an unmatched change to an agent's control file is a `config.change` finding with `actor_kind: undetermined`. Admin-scope managed settings are root-owned, so a user-level agent cannot write them in the protected profile; denial of user-scope writes requires tier 3 or the launcher profile.
5. **Agent sandbox signal.** An exec of `/usr/bin/sandbox-exec`, or a running process already under a sandbox profile, is recorded as an inventory fact about that agent's own containment (brief 13 section 5).

### 4. The launcher and containment (D-21)

**Modes by agent.** These are from the catalogue and confirmed or overturned by spike S-11.

| Agent | macOS mode | How |
|---|---|---|
| Claude Code | delegate | Lock its sandbox on through managed settings with `allowUnsandboxedCommands: false`, so the `dangerouslyDisableSandbox` retry is refused (brief 13 section 5). Covers its shell tool only (section 1) |
| Codex | delegate | Pin the sandbox mode in `requirements.toml`; its sandbox covers spawned commands and built-in file operations |
| Cursor | delegate | Team or file settings where the agent honours them; otherwise request level with the reason stated |
| Bespoke agents with no sandbox | wrap-agent | `grdr-run` launches the agent under our Seatbelt profile |
| Agents whose own sandbox conflicts with ours | wrap-tools or delegate | Nested Seatbelt is a known conflict (brief 13 matrix); S-11 decides per agent. Wrap-tools uses the hook's MODIFY to replace the shell tool's command with `grdr-run --session <id> --tool-call <id>`, which fetches the evaluated command from the daemon (08 section 5, route 4), so each tool subprocess starts under our profile and nothing is re-quoted |

**Verifying a delegated sandbox.** Below tier 3 the verification is a claim: the managed setting is effective and locked (07 section 6), the agent reports its own outcome where it can (Codex `codex.sandbox_outcome`, 07 section 4), and polled children are seen under `/usr/bin/sandbox-exec`. At tier 3 the exec authoriser checks at `AUTH_EXEC` that `sandbox-exec` ran with the expected profile digest, as Santa's `SandboxExpectations` does (brief 13). `control` reaches scoped-boundary only for classes the conformance suite proves that agent version's sandbox covers.

**Seatbelt back end.** `grdr-sandbox-seatbelt` implements the shared sandbox trait. `grdr-run` asks the daemon for the session's profile; the engine compiles it from the bundle's protected-path set, workspace root and egress profile, and `grdr-run` applies it with `sandbox_init_with_parameters` and then execs. The profile:

- allows writes only under the workspace root and the agent's own state directories, and denies reads and writes on the protected-path set;
- allows outbound network only to the `grdr-proxy` loopback listener and the decide socket, so egress host rules are enforced by the proxy (D-16) and a contained session cannot reach the loopback port that `grdr console serve` binds (the daemon binds no TCP port; D-42, D-43);
- denies exec of elevation binaries (`/usr/bin/sudo`, `/usr/bin/su`, `/bin/launchctl`) and connects to container sockets such as `docker.sock` (D-22).

Seatbelt needs no root and no entitlement, applies to the whole subtree, and the confined process cannot remove it (brief 13 section 5). `sandbox-exec` and SBPL are deprecated and undocumented, so the profile generator is versioned per macOS release and every rule is proven by the sandbox conformance suite on each supported macOS version (D-21). The choice between our own generator and the `nono` crate behind the trait is made before the Seatbelt back end is built (E2.1); brief 08 recommends `nono` over writing another generator. `nono` is Apache-2.0 but had 15 advisories in 2026 (h05), so it enters only pinned and vendored, and only if it passes the same suite.

Known gaps carried into the conformance suite: `/tmp` versus `/private/tmp` canonicalisation, and unlink or rename inside a write-allowed path (h05, sandbox-runtime issues #596 and #545). Every path is canonicalised before the profile is written.

**Adoption.** A running agent cannot be put into Seatbelt from outside. Adoption gives attribution only, and the console offers "restart contained"; where containment is on for the agent, credential release to uncontained sessions is refused by default (D-21, P13).

**Descendants-scoped launcher on macOS 27 (tier 3; requires the entitlement).** The launcher creates an `es_new_descendants_client`, which gives AUTH and NOTIFY over the launched subtree, including descendants that already exist, without root and without TCC approval, but with the ES entitlement (brief 13 verification 3; h02 verification 3). On macOS 27 the launcher applies the Seatbelt profile as well: Seatbelt keeps the file and network boundary if the client dies, and the client adds exec authorisation, holds and observation. Rules:

- **Privilege.** A descendants client whose creator is not root stops the whole subtree executing setuid or setgid binaries; a blocked exec is killed with no EXEC event (brief 13 verification 3). In the user profile `grdr-run` creates the client itself and documents that `sudo` and other setuid tools fail inside it. In the protected profile `grdr run` asks the daemon over the decide socket; the daemon spawns `grdr-run --supervise` as root, which creates the client, forks a child that drops to the caller's uid and gids (taken from the caller's audit token), receives the caller's terminal descriptors over the socket, and execs the agent. The supervisor stays root for the life of the session so setuid works, and `elevate` stays subject to policy. The supervisor is trust core (D-63).
- **Holds.** It may set a deadline floor (`es_set_deadline_min_milliseconds`) so that an exec can wait for an approval. The hold is capped at 80% of that floor (D-07). The floor cannot be set for the bootstrap events, and a floor within 10 s of `UINT32_MAX` ms is refused, so bootstrap events are never held (brief 13 verification 3).
- **Miss mode.** `es_set_deadline_miss_mode` takes one mode per client, not per class. Everything the supervisor sees is inside a session container, so it sets `FAIL_CLOSED` when the session's pack declares `on-sensor-loss: block` and `FAIL_OPEN` otherwise (D-15). Fail-closed classes are answered from the floor table before the deadline in either case, so the mode governs only queue-full drops and stalls.
- **Watchdog.** If the client dies, Apple removes all its restrictions (forum thread 845644; brief 13 verification 4). The supervisor forwards every `FORK`, `EXEC` and `EXIT` of its subtree to the daemon, so the daemon holds the member list as audit tokens. The daemon watches the supervisor through its XPC connection's invalidation handler and a kqueue process-exit filter. When the supervisor exits while members live, the daemon stops every member with `SIGSTOP`, checks each pid against its recorded pidversion so a recycled pid is never touched, kills them, and records `response.action` with reason `supervisor-lost` (D-18's kill-subtree watchdog). Target: subtree ended within 500 ms of supervisor exit. The console then offers "restart contained".
- **Denied execs leave no EXEC event**, only EXIT. The daemon writes a synthetic `action.exec` record with phase `effect` and outcome `denied`, built from our own verdict (h02 matrix and verification 3).

### 5. Tier 2: Network Extension (requires Apple's Developer Program)

- **Content filter by default.** An `NEFilterDataProvider` (socket flows only; `FilterSockets` on, `FilterPackets` off) sees each flow's `sourceAppAuditToken` and `sourceProcessAuditToken`. We use the app token for policy where a system delegate opened the socket for an app (LuLu's pattern, brief 13 section 4) and join tokens to the process tree by pid and pidversion. Below tier 3 the join uses the daemon's polled tree, so short-lived processes may resolve only to their agent root.
- **Verdicts.** Allow or drop per flow, evaluated in the extension from `grdr-fastpath` tables compiled from the egress profile and host classes, with no engine round trip. The host comes from the flow's connect-by-name hostname where the app connected by name; otherwise the extension peeks the first outbound bytes and reads the TLS server name with the `grdr-fastpath` bounded field scanner. There is never TLS interception (D-16). A flow with neither (ECH, connect by address) has an opaque host and is judged as D-10 says: denied under a default-deny egress profile, otherwise allowed with a finding. For governed processes only, UDP/443 is dropped so that QUIC falls back to TCP and stays visible. The hostname, peek and QUIC behaviour are inferred in brief 13 section 4 and measured in E3.1.
- **Grade.** Apple documents that `firewall`-grade filters see traffic before `inspector`-grade ones, that order within a grade is undefined, and that the default is `firewall`; how verdicts of several filters combine is not documented (g05 verification 10). The slot broker therefore sets `inspector` (`FilterGrade` in the profile, `NEFilterManager.grade` on the manual path), so another product's firewall filter runs first, and reports the grade. That deny-wins holds across filters is proven by test, not assumed.
- **No DNS proxy, transparent proxy or VPN configuration by default (D-18).** The explicit local listener of D-16 remains the route for model and MCP traffic. The system VPN and DNS proxy slots are effectively single-owner (g05, field knowledge), so both opt-ins below are offered only when the slot broker finds the slot free, and are withdrawn if another product claims it later.
- **DNS proxy (opt-in).** An `NEDNSProxyProvider` in the same extension forwards every query unchanged to the configured resolvers and records name-to-address answers per source process, so host rules apply to connect-by-address flows. It never answers a query itself, and in-app DNS over HTTPS bypasses it (brief 13 section 4, inferred).
- **Transparent proxy (opt-in).** An `NETransparentProxyProvider` in the same extension returns false from `handleNewFlow` for every flow except those from agent lineage to model and MCP host classes, which it relays to the `grdr-proxy` listener; `grdr-proxy` chains upstream through the system proxy and trusts the OS store (D-16). This is the route for agents with no proxy or base-URL setting. Fleets deliver it with `com.apple.vpn.managed` and `VPNType = TransparentProxy`, which cannot be installed from the command line (brief 25); on a single Mac the app saves the configuration through `NETransparentProxyManager` and the user approves the system prompt (not in the briefs; E3.4 confirms it).
- **Lazy activation.** Activating a network extension tears down every existing connection (brief 13 section 3). We activate and replace it only at reboot, wake or a user-chosen idle moment, as Santa does.

### 6. Tier 3: Endpoint Security (requires the Program and the entitlement)

One system extension hosts several ES clients, one per concern, over a shared Rust process tree (Santa's layout, brief 13 section 9):

| Client | Subscriptions | Muting |
|---|---|---|
| Recorder | NOTIFY `EXEC`, `FORK`, `EXIT`, file notify events, `UIPC_CONNECT`, `XPC_CONNECT`, `SUDO`, `SU`, `AUTHORIZATION_PETITION`, `AUTHORIZATION_JUDGEMENT`, `BTM_LAUNCH_ITEM_ADD`, `TCC_MODIFY` (15.4); on macOS 27 `BOOTSTRAP_LOOK_UP` for hand-off edges (06) | Inverted process muting: only agent trees are unmuted |
| Exec authoriser | AUTH `EXEC` | Inverted process muting over agent trees |
| Protected-path guard | AUTH `OPEN`, `CREATE`, `RENAME`, `UNLINK`, `TRUNCATE`, `LINK`, `CLONE`, `UIPC_CONNECT` | Inverted target-path muting over every path set a file rule names, the protected socket set (container sockets, `ssh-agent`) and agents' local stores. Not process-scoped, so it also covers non-agent processes reading agent stores (D-22; 02 SR-12) |
| Self-protection | AUTH `SIGNAL`, `UNLINK`, `RENAME`, `OPEN`, `GET_TASK`, `PROC_SUSPEND_RESUME` on our own paths and processes | Target path on our install and state directories |

Rules:

1. **Our own tree follower.** Muting is per audit token and not inherited, and Santa's client does not follow a tree across exec (brief 13 verification 6). On `NOTIFY_FORK` we unmute the child; on `NOTIFY_EXIT` we clean up. For exec, the exec authoriser selects the target's audit token (from the `AUTH_EXEC` message) on every tree-scoped client before it responds, and carries the agent-root pointer, so no event of the new image arrives before it is selected; `NOTIFY_EXEC` then removes the old pid and pidversion entry.
2. **Deadlines.** Handlers run serially per client, so each AUTH message is retained (`es_retain_message`), copied into a fixed-layout record, queued and answered out of order (brief 13 section 1). Rules that need only the floor or fast-path tables are answered in the extension at once. Content-dependent cases go to the daemon with the remaining budget; if no verdict has arrived at 50% of the message's own deadline (target), the extension answers from its floor table. Full clients never wait for a person (D-18).
3. **Miss mode.** `es_set_deadline_miss_mode` takes one mode per client, not per class. On macOS 27 every full client sets `FAIL_OPEN`, so a miss never kills it and a person's own shell is never denied by a stall (D-15); fail-closed classes do not depend on the mode because rule 2 answers them in time. Before macOS 27 a missed deadline "may terminate the client process, or restart the process if it's a system extension" (g05 verification 4); each such restart is a `health.sensor` event and a loss counter.
4. **Caching.** We never let ES cache a DENY. ALLOW is cached only for targets nobody can modify, keyed on content identity (`cdhash`). Flags events use `UINT32_MAX` when caching (brief 13 section 1). The cache is shared by every ES client on the Mac, `es_clear_cache` is global and rate-limited, and creating any client clears it (brief 13 section 1; g05 verification 10), so we clear it only on a bundle swap that changes an exec or file rule, and count each clear.
5. **Unknown event types.** Tables are sized at run time from the SDK and unknown types are ignored; the enum has gained reserved slots within 27.x. `RESERVED_*` events, including the undocumented network events, are never used (brief 13 verification, further statements).
6. **Sequence gaps** (`seq_num`) become loss counters and `health.gap` events (P9).
7. **Muting other security products.** Processes signed by the Team IDs in the coexistence pack's incumbent list are muted on every client to avoid feedback loops. This is field practice, not Apple guidance (g05 section 2).
8. **Client creation fails** with `ERR_TOO_MANY_CLIENTS` (the cap is not published), `ERR_NOT_PERMITTED` (no Full Disk Access) or `ERR_NOT_ENTITLED`. The slot broker records the failure, drops that concern's classes to the next rung, and the assurance record says so (g05; brief 25 verification 2).
9. **Self-protection** denies agent lineage and non-root processes; for other root processes it notifies and raises a tamper finding, so an administrator's `grdr uninstall` or MDM removal still works (D-22).

### 7. Entitlement application and what ships while it is pending

- **Who and when.** Loonaro's Apple Developer Program account files the request for `com.apple.developer.endpoint-security.client` as soon as its Team ID exists (spine section 7). This requires Loonaro to pay the Program's annual fee (spine question 8); without the Program there is no Team ID and no request. It names two bundle identifiers: the ES system extension and `grdr-run` (the descendants client needs the same entitlement). We do not request the separate approval to let other developers host our system extension, because embedders link a library instead (brief 13 implication 5).
- **What the request says.** An agent detection and response (ADR) use case: observe and authorise exec and protected-path access for AI agent process trees, and supervise agents we launch; Apache-2.0 source; the Santa, BlockBlock and Mac Monitor precedents held by organisations (brief 13 section 2). We also file feedback supporting the self-add descendants entitlement (FB24830531), which Apple describes as probable and has not scheduled (brief 13 verification 4).
- **Follow-up.** Long waits with no reply are reported, all old (brief 13 section 2). Loonaro's Program account follows up with Apple while the request is pending, an external precondition that nothing else waits on (owner instruction 7), and the status (not filed, pending, granted, refused) is a fleet fact and a `grdr doctor` line.
- **While pending.** Tiers 1 and 2 are the product. The ES extension and the descendants launcher are built in CI behind the `macos-es` feature and tested only on SIP-disabled test guests (brief 13 verification 2; see the test lab under "Test and evaluation strategy"). The release pkg carries no ES component, because without a provisioning profile holding the entitlement it cannot be signed for SIP-on Macs.
- **If refused or still pending.** The spine risk register applies: Endpoint Security reaches customers only through an embedding partner's entitled extension (D-41 L3), and macOS AL4 is not claimed.
- **If Loonaro does not join the Program.** macOS ships with Sigstore signatures and provenance, marked not platform-signed, at tier 1 only: no Network Extension, no Endpoint Security, no notarised package (D-18, D-59, spine risk register). Tier 1 remains the complete product described in sections 3 and 4.

### 8. Consent: Full Disk Access and approvals

| Grant | Needed by | Without it |
|---|---|---|
| Full Disk Access (`SystemPolicyAllFiles`) for the daemon | Tier 1 reads of transcripts and configuration in TCC-protected locations (brief 13 matrix: "FDA for some paths"); ES full clients, where `es_new_client` fails without it (brief 13 verification 10). Not the descendants client | Those sources are "could not look" in `health.coverage` with reason `no-permission`, never "nothing found"; ES classes drop a rung (section 6, rule 8) |
| System extension approval | Tiers 2 and 3 | The tier is absent; the record says so |
| Content filter configuration | Tier 2 | Same |
| Background item ("Allow in the Background" in Login Items & Extensions) | Daemons | A user who switches it off stops the daemons: shims fall back to their fail-safe tables, compiled and signed on the device (D-14), the server sees a heartbeat gap, and `grdr doctor` names the switch. MDM locks it (section 9) |

Apple has announced that Full Disk Access will require "very explicit user action", with no date and nothing said about MDM or security software (brief 13 verification 10). So no tier-1 feature requires FDA to work; FDA only widens what can be read. The descendants client needs no TCC approval at all.

We never request Screen Recording, Accessibility or Input Monitoring (D-51).

### 9. Installation (D-59)

**Artefact.** One universal flat pkg (arm64 and x86_64), signed with Developer ID Installer and notarised when Loonaro holds Apple's Developer Program, containing the app in `/Applications` (required for `OSSystemExtensionRequest`, brief 13 section 3), the launchd daemons, the shim and the CLI. Optional components, selected by the pkg's choices or by MDM: Network Extension, ES extension (once entitled), desktop app. The pkg is silent, idempotent and installs offline (D-59). Without the Program the pkg has no Developer ID signature and is not notarised; it carries a Sigstore signature and provenance, the release manifest marks it "not platform-signed", and it carries tier 1 only (D-18, D-59, owner instruction 23); `grdr doctor` says so.

**MDM (silent install).** `grdr mdm profile` emits signed or unsigned `.mobileconfig` files:

- `com.apple.system-extension-policy` with `AllowedTeamIdentifiers` and `AllowedSystemExtensions`, plus `NonRemovableSystemExtensions` on macOS 15 and later. This payload is device-channel, user-approved MDM only, forbidden under User Enrollment, and cannot be installed by hand (brief 25 verification 1).
- `com.apple.TCC.configuration-profile-policy` granting `SystemPolicyAllFiles` to the daemon and the ES extension by code requirement pinned to our Team ID.
- `com.apple.webcontent-filter` for tier 2 (`FilterDataProviderBundleIdentifier`, `FilterSockets`, `FilterGrade` set to the grade the slot broker would choose); the declarative `webcontent-filter.plugin` on macOS 27 (brief 25).
- `com.apple.vpn.managed` with `VPNType = TransparentProxy`, and a DNS proxy payload, only when those opt-ins are chosen (section 5).
- `com.apple.servicemanagement` (macOS 13 and later) with a `TeamIdentifier` rule locking our background items.
- The Claude Code and Codex managed-settings payloads when the organisation owns them (D-49).
- On macOS 26 and later, the declarative `package` configuration for install (brief 25).

Payloads keyed to our Team ID (system extension policy, TCC by code requirement, background-item rule) require Apple's Developer Program; without it the generator emits only the managed-settings payloads and the install payload.

No certificate payload is generated: the opt-in interception CA of D-16 is per process tree and memory-only. Enrolment uses an MDM-delivered file carrying the per-organisation deployment key, never a secret on the command line, and the device starts in Watch until admitted (D-36, D-59).

**A single Mac (manual path).** First run changes nothing (D-48). Choosing Protected asks for one administrator elevation, which installs the pkg; tier 1 is then complete. Each further step is offered separately with the reason and the record field it will change: Full Disk Access (one approval), tier 2 (system extension approval in Login Items & Extensions, then the filter configuration prompt), tier 3 (system extension approval and Full Disk Access for the extension). Skipping any of them leaves a working product at the lower tier. Brief 25 reports five manual approvals for BeyondTrust's equivalent and notes that solo users will not do five; ours are at most one for tier 1 and two more per extra tier.

**Several logged-in users.** Policy and listeners are keyed by uid and audit session, so fast user switching gives each user their own `grdr-proxy` listener and session state. macOS has no terminal-server mode, so D-59's multi-session refusal does not arise.

**`grdr doctor`** reports, per D-59: active tier and why a higher one is missing, slot owners and the chosen rung and filter grade, hook-fired per agent, FDA and background-item state, signing state, entitlement status, network path and measured overhead. `grdr support-bundle --preview` redacts on the device.

**Uninstall.** `grdr uninstall` restores the install journal byte for byte (D-49), deactivates the extensions and removes profiles we installed. An MDM-removed system-extension profile deactivates the extension (macOS 11.3 and later, brief 13 section 3); with `NonRemovableSystemExtensions` only MDM can remove it.

### 10. Build and notarisation (24 owns signing)

- `grdr-sensor-macos` builds as a Rust static library (`crate-type = ["staticlib"]`, both Apple targets joined with `lipo`) with a C ABI, `grdr_macos_*`: fixed-layout events in, verdicts and actions out, no Apple types across the boundary. It links `grdr-fastpath` for the in-extension tables.
- The Swift shell (`platform/macos/`, an Xcode project built with `xcodebuild`) owns `es_new_client` and the descendants client, the NE provider classes (which must be Objective-C-compatible classes named in `Info.plist`), `OSSystemExtensionRequest`, and XPC. It contains no policy. ES handlers are C blocks that copy the message into a fixed-layout record and call the library (brief 13 section 10).
- The `endpoint-sec` crate (0.6.2, MIT or Apache-2.0, one maintainer, open issues #166 and #169 for macOS 26 and 27) sits behind our trait; we add `-sys` bindings for macOS 27 APIs ourselves (brief 13 section 10 and verification).
- The Swift shell and extensions are outside `default-members` (ARCH-011), so a stranger's build needs no Xcode.
- Entitlements: the container app carries the system-extension install entitlement; the NE extension the content-filter, DNS-proxy and app-proxy provider system-extension values; the ES extension and `grdr-run` the ES client entitlement once granted (brief 13 section 3 and "Needs an Apple developer organisation account").
- Release job: build on a free hosted macOS arm64 runner (D-64 tier A), sign with Developer ID and hardened runtime, embed the provisioning profiles for the restricted entitlements, notarise with `notarytool` and staple the ticket to every container we ship (the pkg, each app bundle before it enters the pkg, the Safari extension app and the user-profile dmg, 24 section 2), then run `stapler validate` on each and `spctl` and `pkgutil --check-signature` in CI with the network blocked, so Gatekeeper passes on a Mac with no route out. The signing, notarisation and provisioning steps require Apple's Developer Program; without it the job produces the tier-1 pkg with Sigstore signatures and provenance only, marked "not platform-signed", and verifies its contents. Two administrators named by Loonaro hold the Program account; the Developer ID identity is a secret of the release workflow's GitHub Actions environment, so no person signs a release (owner instructions 7 and 23; spine risk register).
- A self-builder's ES extension loads only with SIP disabled (brief 13 verification 2); a self-builder with their own paid Developer ID can sign tier 2. `grdr doctor` says exactly which tier is missing and why.

### 11. Agents in virtual machines

- **Claude Cowork** runs in a Virtualization.framework Linux guest whose egress goes through a host-side allowlist proxy in Claude.app (brief 13 section 8). Host-side we see the VM process and Claude.app at tier 1, Claude.app's flows at tier 2, and file events on shared folders only at tier 3. The VM process is a session member when the session launched it (06); shared-folder file events are attributed to it at attribution grade 1 (`lineage`).
- Anthropic's EDR-in-Cowork programme is detection-only and limited to supported vendors that Anthropic lists (brief 13 verification 9). We record it as a coverage fact and do not depend on joining it.
- `apple/container`, Docker Sandboxes and other microVMs get the Linux sensor (10) as an in-guest package where the user controls the guest. Whether the content filter sees guest traffic is unknown (brief 13 open questions) and is measured in E5.2.
- Without a guest sensor, a VM-hosted agent is reported as partly covered: `visibility: claimed` at most, with a coverage-ledger entry for the VM process listing the classes left at `none` (as 10 does for sandboxed pods) and reason `vm-guest`.

### 12. Tamper resistance (D-22)

- **Against user-level agents, protected profile:** root-owned binaries, configuration, spool and socket directory; managed hook configuration in admin paths; the `elevate` class (sudo, `launchctl`, our launcher) is Ask by default (Essentials, D-53; Watch in the user profile) and fail-closed from contained sessions. Below tier 3 tampering is detected; at tier 3 it is prevented.
- **At tier 3:** ES self-protection on signal, task-port, suspend, unlink and rename of our files and processes (section 6, rule 9); `NonRemovableSystemExtensions` on MDM fleets.
- **Against administrators:** detection only. Server-side heartbeat-gap findings, a signed going-down event on sleep and shutdown, and the hash-chained spool (D-39). Kernel-grade tamper resistance comes from a host EDR when we are embedded.
- **Test cases from Santa's 2026 advisories** (h05): oversized argv overflowing a telemetry buffer, a local user crashing the daemon to pause enforcement, relocating the data directory to bypass tamper checks, and a context-dependent allow cached and reused.

### 13. Coexistence (D-23)

- The slot broker probes, at start and on change: `es_new_client` results (`ERR_TOO_MANY_CLIENTS`, `ERR_NOT_PERMITTED`), activated system extensions and their categories (`systemextensionsctl list`), network configurations (`scutil --nc list`), our filter's effective grade, and declarative execution-control rules (macOS 27 allows or denies execution by code-signing properties through ES; h02 section 2, WWDC26 session 206). Command output is parsed in the engine (ARCH-004).
- It chooses a rung per capability (enforce; observe; or ingest the incumbent's telemetry and delegate response to its API) and reports it. Where Santa is installed its logs are an ingest source (brief 10).
- Our exec denials are added to, never replace, declarative execution-control rules and XProtect; a binary denied by either is recorded as an incumbent denial, not ours.
- No PF rules (TN3165, g05 verification), no injection, no `DYLD_INSERT_LIBRARIES`, no encoded scripts.
- Each release publishes the coexistence pack (generated by `xtask dist`, 11 section 9; published by 24): Team ID, signing identifiers, bundle IDs, paths, loopback ports and exclusion snippets for Defender, Falcon, SentinelOne, Cortex, Elastic and Jamf Protect, plus the ceiling matrix: per macOS version, agent and incumbent, the reachable assurance record (D-23). Cells for incumbents with no licence through a design partner or free vendor programme are marked untested (spine risk register).
- With several ES clients every AUTH event is expected to wait for all subscribers, so our latency adds to the incumbents'. This is field knowledge (g05), so performance is always measured beside incumbents.

## Interfaces and contracts

| Contract | With | Owner |
|---|---|---|
| Hook socket, `grdr.decide.v1alpha1` | Shim, broker | 07 |
| Fixed-layout ES and NE records over XPC (`#[repr(C)]` layouts shared with `grdr-fastpath`, layout version `grdr.sensor.macos.v1alpha1`, size-capped) | Daemon | This document |
| Table and label push from the daemon to the extensions, acknowledged (section 2) | Both extensions | This document |
| C ABI of the static library (`grdr_macos_*`): event in, verdict out | Our Swift shell only; unpublished (layer 3) | This document; experimental |
| Subtree membership stream from the supervisor and the watchdog contract (section 4) | Daemon | This document |
| `health.sensor`, `health.coverage`, `assurance.record`, `response.action` | Core, console | 04, 07 |
| Profile generator output (`.mobileconfig`) | MDM | This document; 24 packages it |
| Sandbox trait and conformance suite | `grdr-run` | 07, this document for the Seatbelt back end |
| Coexistence pack and ceiling matrix (macOS rows) | Operators, incumbents | 11 generates, 24 publishes; this document supplies the data |

## Behaviour by deployment shape

- **Standalone:** tiers available on the device; MDM payloads not used; manual approvals optional; nothing sent but the anonymous update fetches, which can be turned off (D-48).
- **Platform (self-hosted, or hosted when the hosted service's preconditions are met, D-63):** MDM profiles from the console; tier and rung per device in fleet views; the content filter's grade and the ES entitlement status are fleet facts.
- **Embedded:** an entitled EDR vendor feeds its own ES events, as fixed-layout records, to the L3 fast-path library (`grdr-ffi`) inside its own extension, runs the content engine as an unprivileged sidecar, and supplies the host profile (D-41, D-60). We ship no second system extension (brief 25 deployment model 8), and hosting ours would need Apple's separate approval (brief 13 section 2).

## Extension points

- New agents: catalogue manifests with their macOS paths, signing identity and containment mode (05).
- Sandbox back ends: the shared trait with its conformance suite.
- Slot-broker probes for new incumbents: data in the coexistence pack.
- A host EDR embedding the engine through `grdr-ffi` (26).

## Security and privacy

- Extensions and the daemon parse no untrusted content; the engine does (D-20).
- Fixed-layout records are size-capped and versioned; argument capture is bounded (03 limits).
- No screen, keystroke or clipboard capture; no TCC services beyond Full Disk Access (D-51).
- Every ES and NE handler has a fuzz target over the fixed-layout record decoder.
- Trust-core review applies to the Swift shell, both extensions, the XPC peer checks, the root supervisor and the launcher: a change lands only after two independent evaluators on different models pass it (D-63), and each leaves the internal ring only with the review D-62 sets for it, run by `eval-security` and `eval-adversarial` plus any free external audit that arrives.

## Test and evaluation strategy

| Property | Oracle |
|---|---|
| Assurance record never overstates | For each tier and class, a scripted agent action whose effect is checked independently on a test Mac; a record claiming more than the oracle shows fails the build |
| Hook fired | The session canary of 07 against the replay model endpoint |
| Seatbelt boundary | Sandbox conformance suite: each declared denial attempted inside the profile on each supported macOS version |
| Content filter verdicts | Flows to listed and unlisted hosts, by name and by address, with and without ECH; result checked at a test server that logs connections |
| Filter coexistence | Our inspector-grade filter beside another vendor's firewall-grade filter: a flow either denies is refused at the test server |
| ES deadlines | Engine and daemon stalled by fault injection; no client is killed on macOS 27, fail-closed classes are answered from the extension's floor table before 50% of the deadline, and a person's shell outside any container is never denied |
| Tree follower | Agent tree runs fork, exec and exec-chain storms; every descendant's events reach the recorder, checked against `eslogger` |
| Watchdog | Kill the supervisor mid-session; every member is gone within 500 ms (target), no recycled pid is signalled, and a `response.action` record exists |
| Synthetic denied exec | Deny an exec in a descendants subtree; exactly one `action.exec` effect record with outcome `denied` |
| Tamper | Santa's 2026 advisory classes (section 12) attempted from agent lineage; each is denied at tier 3 or detected below it |
| Coexistence | Install, run and uninstall beside each incumbent with a licence; zero incumbent alerts, overhead within the spine's section 6 targets (under 2% added build overhead per incumbent) |
| No connection drop outside chosen moments | NE replacement never happens during an active SSH session in the soak test |

**Test lab (D-64).** There is no money for lab hardware. Tier A, the free hosted macOS arm64 runners for a public repository, builds and runs everything that needs no system extension: the static library, the Swift shell build, tier 1, the Seatbelt conformance suite on the macOS versions the runners offer, and the held-out suite. Hosted macOS runners cannot nest VMs (g05), so all extension work needs tier B: Macs available to the project as optional self-hosted runners, which execute merge-queue commits only. Apple's licence allows two additional macOS instances per Mac for development and testing (g05 verification 7), so each such Mac can host two guests.

Where a Mac is available, its roles are:

| Role | Bare metal | Guests |
|---|---|---|
| Approval path | MDM-enrolled, SIP on: the real approval path (user-approved MDM, silent sysext, PPPC, filter) and the manual path | Two SIP-off guests for ES and NE development |
| Overhead and soak | Overhead and soak runs (never in a VM; nothing else running) | Two guests with incumbents (Defender, Falcon, a third) under licences obtained only through design partners or the vendors' free test programmes (D-64), which often restrict benchmarking (g05) |
| Version spread | Current macOS major | Two guests on the two previous majors, for the conformance suite (R11) |

One Mac may take several roles in turn; overhead runs always take the bare metal alone. Tests whose role has no machine are marked "requires hardware" and run when a machine is available; extension work and the SIP-on approval path also require Apple's Developer Program. Guests are reset from clean disk images before each run. `eslogger` runs on test machines only, as an independent oracle for exec and file effects, and never during overhead runs because it is itself an ES client; it is not shipped.

## Work breakdown

**E0 Apple entitlement**
- E0.1 Entitlement request filed and feedback for the self-add descendants entitlement submitted (section 7). Requires: Apple's Developer Program for Loonaro (Team ID). Accept: filed once the Team ID exists; status visible in `grdr doctor` (requires E1.1).

**E1 Tier 1**
- E1.1 Static library skeleton, C ABI, Swift shell that builds outside `default-members`; XPC peer requirement between our components. Accept: `verify` green without Xcode; the shell links the library on macOS arm64; an XPC peer signed by another Team ID is refused (the peer check requires the Program; a build without a Developer ID signature has no XPC between extensions).
- E1.2 Discovery scans with code-signature identity. Accept: Claude Code and Codex identified by program identity on a clean test image.
- E1.3 Transcript-tail claim source and `canary-missed` (07 section 11, with 07 E5.3). Accept: a disabled-hooks run raises `canary-missed` within one session; a hooked session reaches AL2 with `visibility: claimed`.
- E1.4 pkg, notarisation and uninstall journal. Accept: uninstall restores every file byte for byte (file diff); with the Program, `stapler validate`, `spctl` and `pkgutil --check-signature` pass in CI with the network blocked (24-30(a)); without it, the pkg without a Developer ID signature installs tier 1, its Sigstore signature verifies, and `grdr doctor` reports it "not platform-signed".
- E1.5 MDM profile generator for managed settings, Full Disk Access and background items. Accept: profiles validate against `apple/device-management` schemas; on an MDM-enrolled test Mac (requires hardware and the Program for Team-ID payloads) a silent install reaches tier 1 with no prompt.
- E1.6 FSEvents integrity watch and the manual consent flow. Accept: a scripted write to `~/.claude/settings.json` outside any `tool.pre` raises `config.change` within 5 s (target); skipping every optional approval leaves tier 1 working and each gap named in `health.coverage`.
- E1.7 Defender for Endpoint on macOS interference run at tier 1 (with 11 EN-J4). Accept: zero Defender alerts on install, run and uninstall (D-23 interference test).

**E2 Containment**
- E2.1 Seatbelt back end and profile generator (or `nono` behind the trait). Accept: conformance suite green on the three supported majors, including `/private/tmp` and unlink-in-writable-path cases; a contained session cannot connect to any loopback port but `grdr-proxy`'s.
- E2.2 Delegate mode for Claude Code and Codex. Accept: S-11 passes or the agent is fixed to delegate; the record shows `scoped-boundary` only for classes the agent's sandbox covers.
- E2.3 Workload corpus inside the launcher. Requires: E2.1. Accept: zero failures, or each failure maps to a probe that keeps the session at request level with a reason.
- E2.4 Coexistence pack and ceiling matrix rows for macOS; interference runs beside Falcon and a third incumbent at tier 1. Requires: incumbent licences through design partners or free vendor programmes. Accept: published with each release; zero incumbent alerts where licensed, and the other cells marked untested.

**E3 Tier 2 (requires Apple's Developer Program)**
- E3.1 Content filter extension, in-extension tables and fixed-layout flow records. Accept: flow verdicts match the oracle for by-name, by-address and ECH flows; tokens join the process tree; held-out discovery recall of 85% on macOS (spine section 6 discovery row; pass 3 on macOS requires tier 2, D-24).
- E3.2 Slot broker probes and grade selection. Accept: beside another vendor's firewall-grade filter, our grade and rung are reported correctly and the filter-coexistence oracle passes.
- E3.3 Lazy activation. Accept: no connection drop during the soak.
- E3.4 DNS proxy and transparent proxy opt-ins. Requires: E3.1. Accept: offered only when the slot broker finds the slot free; a claimed agent flow reaches `grdr-proxy` and every other flow goes direct; the manual-path approval behaviour is recorded.
- E3.5 SP-MAC3 provider-stop spike. Accept: measured flow behaviour sets `on_failure` for `net.connect` in the contract.

**E4 Tier 3 (requires the Program and the Endpoint Security entitlement; built and tested on SIP-disabled guests while the entitlement is pending)**
- E4.1 ES extension with four clients, the tree follower and in-extension floor tables. Accept: cross-check calibrated per S-07 (under 1 unexplained execution per 100 sessions; injected process caught 20 of 20); no client killed in a 72-hour soak; ES deadline oracle passes.
- E4.2 Descendants-scoped supervisor, root mode and watchdog on macOS 27. Accept: watchdog and synthetic denied-exec oracles pass; `sudo` works under the protected-profile supervisor and fails, as documented, under the user-profile launcher.
- E4.3 Self-protection client and tamper cases. Requires: E4.1. Accept: tamper oracle passes; an administrator's `grdr uninstall` still succeeds.

**E5 VMs**
- E5.1 VM-process modelling and the `vm-guest` coverage entry. Accept: a Cowork session is reported as partly covered.
- E5.2 Linux sensor as an in-guest package for `apple/container` and Docker Sandboxes; content-filter visibility of guest traffic measured. Requires: the Linux sensor (10); E3.1 for the filter measurement. Accept: guest exec visible at Linux sensor grades; the measured filter result recorded in the ceiling matrix.

## Risks, open questions and spikes

| Item | Settles it |
|---|---|
| Loonaro does not pay Apple's annual Developer Program fee (spine question 8) | Spine risk register: macOS ships Sigstore-signed but not platform-signed or notarised, with tier 1 only; no Network Extension, no Endpoint Security, no notarised package |
| Apple does not grant the ES entitlement, or it stays pending | Spine risk register: ES only through an embedding partner; tiers 1 and 2 remain the product |
| No Mac is available for extension, SIP-on or overhead runs | Those tests are marked "requires hardware" and run when a machine is available (D-64); no tier is claimed above what has been tested |
| No incumbent licence beyond Defender | Ceiling-matrix cells for that incumbent are marked untested (spine risk register) |
| Full Disk Access changes break the install flow | No feature requires FDA; re-test each macOS beta |
| SP-MAC1: nested Seatbelt with each agent's own sandbox | S-11 |
| SP-MAC2: which developer tools fail inside the launcher on macOS 27, root and non-root | E2.3 corpus |
| SP-MAC3: what happens to flows when our content filter provider stops | Kill the provider under load on a test Mac; sets `on_failure` for `net.connect` |
| SP-MAC4: overhead of the content filter and ES beside Falcon and Defender | Spine section 6 build-overhead targets |
| SP-MAC5: does the content filter see Virtualization.framework and vmnet guest traffic? | E5.2 |
| Self-add entitlement for the descendants client | Watch Apple's feedback response; unscheduled by Apple (brief 13 verification 4) |
| A macOS point release changes SBPL or `sandbox_init_with_parameters` (both undocumented) | Conformance suite on every beta; a failing rule drops that class to request with a reason |
| The ES client cap is reached beside several incumbents | Section 6 rule 8; measured in the coexistence runs |
| Several filters' verdicts do not combine as deny-wins | Filter-coexistence oracle (E3.2); if it fails, the ceiling matrix lowers `net.connect` control beside that product |

## Deviations from the spine and objections

- Open. D-18 pins tiers 1 and 2 to `visibility: claimed` for `exec` and `file.*`. An opt-in `eslogger` collector (root plus Full Disk Access, notify only; brief 13 recalls, without re-reading, that its man page says it is not API) could reach `observed` for `exec` without the entitlement. I follow the spine and use `eslogger` only as a test oracle, but propose a spike to judge whether it is stable enough to offer as a support-tier-3 collector (experimental, off by default; D-50).

## Sources

Research briefs: `13-macos.md`, `10-oss-sensor-blocks.md`, `g05-edr-coexistence-testlab.md`, `37-sensor-engineering.md`, `25-deployment.md`, `08-oss-agent-security.md`, `h02-conference-talks-sensors.md`, `h05-open-source-sweep.md`. Reviews: `c3-endpoint-control.md`, `l04-it-endpoint-engineer.md`.

Primary URLs (as cited and verified in those briefs):
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:)
- https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:)
- https://developer.apple.com/forums/thread/845644
- https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
- https://developer.apple.com/documentation/devicemanagement/webcontentfilter
- https://github.com/apple/device-management
- https://developer.apple.com/news/?id=p6zjojqw
- https://developer.apple.com/videos/play/wwdc2026/206
- https://github.com/northpolesec/santa
- https://github.com/HarfangLab/endpoint-sec
