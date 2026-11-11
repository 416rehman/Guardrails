# 16. Data protection and secrets

_Status: draft for implementation. Date: 2026-11-10. Revised 2026-11-11 for principles P15 to P17 and the owner's kit instructions (`_review/04-owner-kit-instructions.md`). Owning squad: Data protection (detectors in `grdr-analyze`, the capture step in `grdr-model`, the `DetectorPort` adapters, the workspace baseline store in `grdr-daemon`). Read with: `00-decisions.md` (D-28, D-51, D-16, D-53, P1, P2, P8; section 3 vocabulary); 04 (data classes, `PathRef`, `Redaction`, labels, receipts); 07 (control points, MODIFY, the per-agent matrix, the assurance record); 12 (the Cedar policies that read labels, the `data.flow` derivation, the `snapshot` obligation); 13 (the `mass-change` session rule); 15 (the broker, phantom tokens, the `credential-locator` pack); 17 (explicit listener, interception, browser extension); 18 (freeze and restore actions); 21 (keys); 25 (classification connectors as integrations, export destinations); 29 (privacy regimes, DPIA, works council); 05 (MCP and skill inventory)._

## Summary

This document specifies the data-protection side of the product: what is protected on the device, which destructive actions are gated, how secrets and PII are found and sometimes removed, how information-flow labels gate sinks, how egress is pinned, how the workspace is recoverable, and how we redact what we ourselves collect. It specifies D-28 in full, the capture-and-redaction half of D-51, and the egress and tenant-pinning uses of D-16. The credential broker itself (inject and release, helper protocols, minting) is document 15; here it appears only as the consumer of phantom tokens and the source of the phantom-misuse finding.

Key choices:

1. **Protected paths, environment scrubbing and the irreversibility gate head D-28's order of value, as deterministic classes, on every OS** at whatever assurance the host allows (D-28 items 1 and 2). The default lists are signed pack data, one per OS.
2. **Detection is layered: a deterministic tier that policy may read, and a model tier that may only restrict** (P2). Secret detection uses the Kingfisher crates; PII uses ported Presidio recognisers plus an optional NER adapter. Every detector fact carries `origin`.
3. **Redaction is declared per agent and channel as `rewrite`, `deny-read` or `none`, and falls back to `deny-read` where rewrite is not available** (c8 F6). Only Claude Code rewrites every tool output today; we never pretend otherwise.
4. **Labels have two axes (integrity and confidentiality), the D-28 day-one set, and deterministic decay.** Taint creep is held down by a trifecta gate that needs both axes, by quarantined sub-sessions whose labels never reach the parent, and by declassification grants bound to a payload digest.
5. **Egress is pinned by method, path and tenant, not by hostname alone** (D-16). Tenant-restriction headers are set only where the request already reaches us in plaintext (base-URL routes, the opt-in interception CA, the browser extension), plus the agents' own managed settings.
6. **Phantom tokens are a confidentiality control and an attribution signal**: a peer-verified substitution proves the agent made the request, and a phantom seen anywhere else is a threat finding. Phantom tokens require the broker; planted decoys carry the honeytoken rule without it.
7. **A workspace baseline with copy-on-first-write and a mass-change breaker replaces per-action file checkpoints** (c8 F10). External side effects are not restorable; the irreversibility gate exists for them.
8. **We upload metadata by default and redact on the device before any sink.** The four capture levels (04) are a mechanical filter; this document owns which detectors run at capture and the rule that a secret is never stored, even at `full content`.

## Requirements

| # | Requirement | Source |
|---|---|---|
| R1 | Default protected-path and protected-environment lists per OS, as signed pack data: Ask on credential-store reads, Block on agent writes to control files | D-28, D-22, D-53, brief 35, brief 21 |
| R2 | Irreversibility gate: action class by target class, production identified by credential or tag | D-28, c8 F10, brief 21 section 12 |
| R3 | Secret and PII detection on device, deterministic tier readable by policy, model tier restrict-only | D-28, P2, brief 09 |
| R4 | Redaction declared per agent and channel; fall back to deny-read where rewrite is unavailable | c8 F6, brief 35 |
| R5 | Day-one labels, sources, sinks, flow rules, declassification; taint-creep controls (quarantined sub-sessions, decay) | D-28, D-09, c8 F3, brief 22, brief 35 |
| R6 | Egress rules with method, path and tenant pinning; no reliance on hostname allow-lists | D-16, brief 38, brief 21 section 16 |
| R7 | Tenant-restriction headers and managed settings per provider, without mandatory TLS interception | D-16, D-12, brief 35, brief 05 |
| R8 | Phantom-token injection bound to host, method and path, usable as an attribution proof | D-28, D-27, brief 35 |
| R9 | Honeytokens: planted and watched, Essentials Block on use, model-free trigger | D-28, D-53, brief 21 (ATLAS AML.M0039) |
| R10 | Workspace baseline, copy-on-first-write, mass-change breaker, restore | D-28, c8 F10, brief 35 |
| R11 | Computer use and clipboard handled as sinks without capturing screen, keystroke or clipboard content | D-51, brief 35, g09 |
| R12 | Classification connectors (MSIP labels, Purview verdict, Drive labels) as a source of confidentiality labels | D-28, brief 35 |
| R13 | Provider posture: per-(app, principal) account-context record from signed adapters | D-28, brief 05 |
| R14 | Content capture levels and on-device redaction of our own telemetry; a secret is never stored, even at full content | D-51, P8, brief 35, l07 |
| R15 | Each control reported as boundary, scoped boundary or request per host and profile (P1) | P1, D-13, D-48 |

## Design

### 1. Order of value and the control inventory (D-28)

D-28 fixes the order of value of the data controls. Rows 1 to 10 are D-28's list in its order; row 11 is D-51's on-device redaction, which this document also owns. The class column uses the assurance record's `control` values (spine section 3) and is never better than the host enforces; section 13 gives it per profile. The Requires column names the components each control cannot work without (spine section 7).

| # | Control | Requires | Mechanism | Best `control` class reachable |
|---|---|---|---|---|
| 1 | Protected paths and environment scrubbing | Hook shim; OS sensor for observation; launcher for scrubbing | Path classes read by Essentials rules at hook and sensor; environment filter at launch | `request` at hooks; `scoped-boundary` in contained sessions; `mandatory-boundary` at the Linux kernel tier |
| 2 | Irreversibility gate | Hook shim; production targets also require the explicit proxy and organisation production lists | Action class by target class (section 3) | `request`; `scoped-boundary` in contained sessions |
| 3 | Secret handling per agent and channel | Secret detector; each agent's hook interface (Claude Code, Codex, Cursor, Copilot CLI) | Deterministic detection, then `rewrite`, `deny-read` or `none` | `request` at hooks; `scoped-boundary` for model requests forced through the listener |
| 4 | Session labels with sink gating | Session rules; flow rules leave Watch only after S-14 shows them inside the prompt budget | Session rules write labels; `data.flow` gates sinks (12) | `request`; `scoped-boundary` when egress is forced through our proxy |
| 5 | Egress rules (method, path, tenant) | Explicit proxy (D-16) | Proxy on the explicit listener; tenant headers on plaintext flows | `request`; `scoped-boundary` behind sandbox-forced egress; `mandatory-boundary` at a `gateway` the network forces traffic through |
| 6 | Injected credentials (phantom tokens) | Credential broker (15, D-27); explicit proxy | Broker `inject` mode (15); `swap-credential` at the proxy | `scoped-boundary`: the secret never enters the session |
| 7 | Honeytokens | Decoys: hook shim and the decoy pack; phantom misuse: the broker | Planted decoys and `cred.use` of class `honeytoken` | The class of the control point that sees the use |
| 8 | Workspace baseline and mass-change breaker | `mass-change` label: session rules and file events; baseline, breaker and restore: the daemon's store and response actions (18) | Copy-on-first-write store; freeze on mass change (section 9) | Recovery, not a control: no class claimed |
| 9 | Classification connectors | Integration host (25); for Purview and Drive, a customer tenant with that API | MSIP reader on device; Purview `processContent`; Drive labels | Labels only; enforcement inherits row 4 |
| 10 | Provider posture | Signed app adapters; browser extension (17) | Account-context record from signed adapters | Posture facts only |
| 11 | On-device redaction of our own capture | Capture filter in the core; detectors of row 3; privacy canary test | The capture step in `grdr-model` before every sink (section 11) | Not an agent control; held by lint and the privacy canary test (04) |

Items 1 to 3 close the cheapest high-value gap (brief 35): no agent protects credential stores by default, and Claude Code's documentation states there is no built-in credential deny list (brief 35, verification row 1).

### 2. Protected paths and environment scrubbing (D-28 item 1, D-22)

The lists are `protect`-polarity analyser lists (12 section 2), so growing them is always narrowing. They are data, not code: path templates and environment variable names are typed match fields, and a device never gets a path to execute or a variable to set from them (P7). The `cred-store`, `private-key` and `agent-store` classes are generated from the `credential-locator` pack of 15 section 12, so inventory and protection cannot disagree; this section fixes the defaults that pack must contain. Entries beyond brief 35's verified list are seed defaults: the pack CI proves each one against a fixture install of the owning tool on that OS before it ships, and an unproven entry ships in a Watch-only list.

**Protected-path classes, per OS.** `~` is the user profile (`%USERPROFILE%` on Windows); workspace-relative entries (`.env*`, `.npmrc`, `.mcp.json`) match in any directory.

| Class | All systems | Linux | macOS | Windows |
|---|---|---|---|---|
| `cred-store` | `.env*`, `~/.git-credentials`, `~/.netrc`, `~/.aws/credentials`, `~/.azure/`, `~/.docker/config.json`, `~/.kube/config`, `.npmrc`, `.pypirc`, `*-service-account.json` (brief 35) | `~/.config/gcloud/application_default_credentials.json`, `~/.config/gh/hosts.yml` (brief 35); `/proc/<pid>/environ` of any process other than the reader itself | As Linux for gcloud and gh | `%APPDATA%\gcloud\`, `%APPDATA%\GitHub CLI\hosts.yml` |
| `private-key` | `*.pem`, `*.key`, `~/.ssh/` (brief 35), `~/.gnupg/` | | | |
| `agent-store` | `~/.claude/.credentials.json`, `~/.claude.json` (brief 35); `~/.codex/auth.json` (path unverified, 15); MCP configuration `env` blocks; agents' transcript and conversation stores from the 07 section 4 table (D-22) | | Claude Code keeps its token in the Keychain and falls back to the file (brief 07 verification row 6) | Same file paths under `%USERPROFILE%` |
| `browser-store` | Cookie, login and key databases of Chromium-family and Firefox profiles | `~/.config/google-chrome/`, `~/.config/chromium/`, `~/.mozilla/firefox/`; `~/.local/share/keyrings/` | `~/Library/Application Support/Google/Chrome/`, `~/Library/Application Support/Firefox/`, `~/Library/Cookies/`, `~/Library/Keychains/` | `%LOCALAPPDATA%\Google\Chrome\User Data\`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\`, `%APPDATA%\Mozilla\Firefox\`, `%APPDATA%\Microsoft\Credentials\`, `%LOCALAPPDATA%\Microsoft\Credentials\`, `%APPDATA%\Microsoft\Protect\` |
| `agent-control` | `.claude/settings*`, `.claude/{skills,agents,commands,hooks}`, `.mcp.json`, `.cursor/`, `.codex/`, `.agents/`, `.vscode/tasks.json`, `*.code-workspace`, `.git/hooks/`, `.git/config`, `~/.gitconfig`, `~/.claude/`, `~/.codex/` (briefs 35, 21); the user-scope and admin-scope paths of 07 section 4 | `~/.bashrc`, `~/.zshrc`, `~/.profile` | As Linux | PowerShell profile files |
| `grdr-control`, `monitoring-config` | Our policy, keys, spool and managed settings; configuration of any incumbent EDR named in the coexistence pack (D-23) | | | |

Behaviour (Cedar in 12 section 5, policies 1, 2, 4 and 16):

- Reads of `cred-store` and `private-key` by agent lineage are Essentials **Ask** (policy 4: class `secret`, approver `self`, minimum G1). Reads of `browser-store` are a rule of the same shape in `grdr.secrets` (12 section 14), in Watch until D-53's admission evidence promotes it. In the User profile approvals are G0 (02, SR-07), so D-31 turns this Ask into Block there, and the first-run screen says so. D-31's disclosed time lock stands in for G1 only in the user's own local policy, never in Essentials rules, so these stay Block. A process outside agent lineage reading them is normal and not gated.
- An agent's own main process reading its own `agent-store` entry is normal. A read of an `agent-store` entry by that agent's tool subprocesses or by another agent is treated as a `cred-store` read. A read by a process **outside** agent lineage is D-22's protected-store detection: infostealers with agent modules read exactly these files (h07, verification row 6). It is a finding wherever the OS sensor observes file opens (on Linux, the observation sensor) and a deny at the Linux kernel tier.
- Writes and deletes of `agent-control`, `grdr-control` and `monitoring-config` by agent lineage are Essentials **Block, final** (policy 1); an undetermined actor in an agent-capable host is capped at Ask (policy 16). This is NVIDIA's third mandatory control (brief 22, verification row 3) and the first item of brief 21's backlog.
- Honeytoken files (section 8) are planted outside every pattern above, so the read gate never hides the bait.

**Protected-environment list.** Variable names, matched exactly or by suffix pattern, that never reach an agent's tool subprocesses unless a rule grants them:

| Scope | Names |
|---|---|
| All systems | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_BEARER_TOKEN_BEDROCK`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `AZURE_CLIENT_SECRET`, `ARM_CLIENT_SECRET`, `GH_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `TWINE_PASSWORD`, `VAULT_TOKEN`, `DATABASE_URL`; suffixes `_TOKEN`, `_SECRET`, `_PASSWORD`, `_API_KEY`, `_ACCESS_KEY` |
| CI runners (10) | `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, `CI_JOB_TOKEN` |
| Linux, macOS | `SSH_AUTH_SOCK` is kept (removing it breaks git over SSH) but recorded as a signing capability; it is removed only in contained sessions; where the broker is present, its sign-only SSH agent (15) replaces it |
| Windows | No socket variable; the OpenSSH agent pipe is reached by name and is a `cred.use` the sensor observes |

**Environment scrubbing.** The launcher (`grdr-run`, the agent's process wrapper, D-17 and D-21) removes listed names from the child's environment by default; contained sessions can opt into allow-list mode, where only named variables pass. This list is separate from D-24's capture allow-list, and no protected name is ever captured. Where the broker is present, a listed credential the broker binds is served through 15 section 5's helper binding for its type (a phantom, or a helper such as `credential_process`) instead of being removed. Where we do not own the launch, we set the agent's own scrub control where it has one (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` for Claude Code, brief 35; Codex's `shell_environment_policy` is unconfirmed, brief 35) and report `request`. We never rewrite user dotfiles (D-27).

`/proc/<pid>/environ` is in `cred-store` because environment-mode injection leaks there (brief 35, nono); phantom injection is therefore preferred over environment injection whenever the broker is present.

### 3. Irreversibility gate (D-28 item 2)

Six of eleven destruction incidents hit remote databases or infrastructure, beyond any file checkpoint (c8 F10, brief 21 section 12), so the gate is defined over what an action destroys, not over files. The command classifier (canonical argv, D-10), the path classifier, the cloud-request classifier and the MCP argument extractors (12 section 2) place each action in a destructive family and its target in a target class. The rules are 12 policies 3, 5, 9 and 13, in class `irreversible` (minimum G1, `on_failure: open` unless a pack raises it); one rule per family so the block message names it.

| Destructive family (examples) | `workspace` | `outside-workspace` | `vcs-remote` | `production` |
|---|---|---|---|---|
| Recursive delete (`rm -rf`, `Remove-Item -Recurse`, `git clean -fdx`) | Allowed; recoverable from the baseline (section 9) | Essentials Ask (policy 3) | n/a | Ask, sponsor |
| History rewrite (`git reset --hard`, `git checkout -- .`, `git branch -D`, `git push --force`) | Watch; recoverable from the baseline | Watch | Ask for force-push or delete of a ref on the organisation's remotes | n/a |
| Infrastructure teardown (`terraform destroy`, `kubectl delete`, `helm uninstall`, cloud `delete-*` calls) | n/a | Watch | n/a | Ask, sponsor (policy 5; policy 13 at G2 for mutating cloud requests) |
| Data destruction (`DROP`, `TRUNCATE`, unbounded `DELETE` through known database CLIs and MCP database tools) | Watch | Watch | n/a | Ask, sponsor |
| External publication (`pkg.publish`, `message.send`) | These are sinks: section 5 and policy 9 | | | |

All non-Essentials cells ship in Watch and promote after seven days by D-53's rule.

**Production is identified by credential or tag, never by a model.** A target is `production` when (a) the credential used carries the class `production` in the credential inventory (15), (b) the cloud account, project or subscription derived from the signed request is in `org.production` (12 policy 13), or (c) the kube context, database host, git remote or host class is in an organisation-declared `org.production-*` list. Name heuristics (a context called `prod`) are `heuristic` facts: they may raise a rule to Ask and never lower one (P2). Without a declared list the production column is inert and replay reports it as not evaluable.

Where it runs: the hook judges canonical argv and the sensor reports the effect; the explicit proxy judges mutating HTTP to production accounts where it has plaintext, and the sandbox enforces the outside-workspace column in contained sessions.

### 4. Secret and PII detection, and where redaction applies (D-28 item 3, c8 F6)

Detection is two tiers, and the tier decides what policy may do with the result (P2).

**Deterministic tier.** Facts `secret.type`, `content.secret`, `pii.class` with `origin: deterministic`. Policy may read these, so they can gate a block. The PII recognisers and the normaliser are pure Rust in `grdr-analyze` (layer 1). Kingfisher links Vectorscan, so it runs behind `DetectorPort` in the sandboxed engine process (D-20) and the core still builds for `wasm32` (D-05); an embedded host without it gets "not evaluable" for rules that read `content.secret` (D-60). Engines:

- **Secrets:** the Kingfisher crates (`kingfisher-core` 1.0.6, `kingfisher-rules` 3.2.0, `kingfisher-scanner` 3.0.3; Apache-2.0, Rust), which read the Betterleaks TOML catalogue (MIT), plus our own rules (brief 09, verification row 7). Live validation is **disabled on endpoints**, because it is outbound I/O that reveals the key to its issuer. The device keeps offline checksum verification and a rarity filter modelled on Betterleaks' BPE filter (brief 09, ideas). TruffleHog (AGPL-3.0) is never embedded.
- **PII:** regex and checksum recognisers ported from Presidio patterns (MIT). These are the deterministic floor.
- **Normalisation:** the Unicode, bidi, zero-width and ANSI normaliser shared with the command analyser (D-10), because invisible-Unicode instructions in tool descriptions and skills are a day-one detection (c8 F5).

**Model tier, behind `DetectorPort` (layer 3).** Facts carry `origin: heuristic` or `origin: model`, so the validator (04 section 6) refuses any `permit`, `unless` or session rule that reads them; they can only raise risk, findings and advisory labels (P2, D-09). Off by default; the organisation enables them together with a capture level that permits them. Candidates: our own Apache-2.0 injection classifier, with PIGuard (MIT) as interim default and the archived Protect AI v2 (Apache-2.0) as fallback; an optional NER adapter, knowledgator GLiNER-PII edge (46 MB int8, Apache-2.0), through `gline-rs` on `ort` (brief 09). OpenAI's `privacy-filter` is Apache-2.0 but an independent evaluation found it collapses on non-Latin scripts (Arabic F1 0.04, Cyrillic 0.03; brief 09), so it is never a default for a multilingual organisation. Non-OSI weights (Prompt Guard 2) are never fetched by the product and are off until an administrator turns them on. Where the licence policy (35) finds their terms redistributable, the air-gap bundle's `-models` companion carries them and `grdr server airgap import` asks for acceptance of those terms on its combined terms screen (24 section 7); otherwise an administrator installs files they obtained with `grdr model install <dir> --licence <name> --accept`. Either route hashes weights and tokenizer, records the licence in the SBOM (brief 09) and wraps them in a `model` pack signed by the deployment root, or the local root in standalone (22 section 6.3), so they reach devices through the normal channel and rings, air-gapped included. Every model we ship is a `model` pack carried in the air-gap bundle's `-models` companion (24 section 7), and no `DetectorPort` adapter contains a model-hub client (`cargo deny` bans one). Adaptive attacks beat every classifier tested (over 90% against Protect AI and Prompt Guard, 71% against PIGuard; brief 09, verification row 1), which is why no model verdict blocks.

**The detector that matters most is not content matching.** `secret-read` to a sink is deterministic: once 12 policy 11 leaves Watch, a session that read a credential and then reaches a sink is blocked whether or not the secret bytes are recognised in the outgoing body. That survives the adaptive attacker.

**Where redaction can and cannot be applied, per agent and channel** (c8 F6, brief 35, 07 section 4). A pack declares, per agent version and channel, `rewrite`, `deny-read` or `none`. The `redact-secrets` transform (12 section 4) is offered only in `rewrite` cells; it replaces each detected span with a stable per-session placeholder, and where the broker is present it can re-inject the real value for approved hosts, so the placeholder behaves as a phantom token (c8 F6). Elsewhere the secrets class falls back to `deny-read` on the known source.

| Channel | Claude Code | Codex | Cursor | Copilot CLI | Proxy, base-URL route |
|---|---|---|---|---|---|
| Tool input (pre) | `rewrite` (`updatedInput`) | `rewrite` (allow plus `updatedInput`) | `rewrite` (`updated_input`) | `rewrite` (`modifiedArgs`) | n/a |
| Tool output (post) | `rewrite`, all tools (`updatedToolOutput`) | `none` | `rewrite` for MCP output only | `none` (not documented) | n/a |
| User prompt | `none` (cannot rewrite; can block) | `none` | `none` | `none` | `rewrite` in the model request (12 policy 17) |
| File read into context | `deny-read` | `deny-read` | `deny-read` (`beforeReadFile`) | `deny-read` | `rewrite` in the model request |

File reads are `deny-read` even where `updatedToolOutput` could rewrite them: an agent that edits a file it read with a placeholder in it writes the placeholder back. A `none` cell means a secret printed by an arbitrary command reaches the model's context unless the model request passes through our listener; the detector still sets `secret-read` from the hook's or transcript's copy of the output (section 5), and a late arrival raises `label.late` (04 section 6). The Claude Code `PostToolUse` rewrite requires 07 to register that event as modifying, not only observed.

Two cautions from brief 35. Claude Code's OTel still records the original tool output after a `PostToolUse` rewrite (verification row 2), so the harness's own telemetry is redacted by us on the device (section 11). Claude Code's `sandbox.credentials` masking needs experimental `network.tlsTerminate`, denies masked files on macOS, falls back to deny for directories, globs, files over 8 MiB and non-UTF-8 files, substitutes on every allowed domain when `injectHosts` is unset, and its `onExtractNoMatch` default `warn` leaves the real file readable (verification row 3). Where we write that setting we set `injectHosts` and `onExtractNoMatch: deny`, and masking stays a convenience over our own deny-read, never a substitute for it.

### 5. Labels, sources, sinks, flows and declassification (D-28 item 4)

Labels are the schema of 04 section 6 and reach Cedar as sets (12 section 2), with the monitor's roll-ups `untrusted` and `sensitive`. This document owns the day-one set, the source rules, the sink catalogue and the declassification mechanic. Two axes:

- **Integrity:** `untrusted:web`, `untrusted:external-tool`, `injection-suspected`. The last is model origin, so it is advisory: it evaluates as absent in Cedar and can raise risk, a finding and review priority, never Ask or Block (D-09, 13).
- **Confidentiality:** `secret-read`, `sensitive:<class>`.

**Source rules.** These are session rules with deterministic origin, so they write *enforcing* labels synchronously, at phase `decided-allow` or `observed` (D-09, 12 section 9). Every day-one label has `session-lineage` scope, so children inherit it (c8 F3).

| Source | Label | Requires |
|---|---|---|
| `file.read` of `cred-store`, `private-key`, `browser-store` or another agent's `agent-store`; `cred.use` in `release` mode (15) | `secret-read` | Hook shim or OS sensor; the broker for `release` mode |
| A deterministic `content.secret` fact on tool output the hook, proxy or transcript ingest sees | `secret-read` | Secret detector (section 4) |
| `WebFetch`, `WebSearch` or `net.request` response; browser read of an origin outside `org.trusted-origins` | `untrusted:web` | Hook shim; explicit proxy for `net.request`; browser extension for browser reads |
| `mcp.call` result from a tool whose source trust is `third-party-authored` or unknown; any telemetry-class connector output (D-28) | `untrusted:external-tool` | MCP broker; source-trust pack attribute |
| `file.read` inside an organisation-declared `org.sensitive-paths` or `org.sensitive-repos` list | `sensitive:<class>` with the list's class | The organisation's lists |
| Deterministic PII recognisers on tool output, at or above a pack-parameter count of distinct values | `sensitive:pii` | PII recognisers (section 4) |
| An MSIP label read on the device (section 10) | `sensitive:<class>` from the label mapping | MSIP reader |
| The model injection classifier fires | `injection-suspected` (advisory) | Model tier enabled (section 4) |

*Source trust* is a pack attribute per MCP tool, keyed by tool-manifest hash: `first-party` means the tool returns data the organisation controls (workspace files, its own databases); `third-party-authored` means anyone can write what it returns (issues, pull-request comments, email, tickets, web pages, logs). Unknown tools count as `third-party-authored`.

A child session's labels join the parent's when its result returns (`SubagentStop` and equivalents), because that result enters the parent's context. The only exception is a quarantined sub-session (below).

**Day-one sinks.** These are the `data.flow` resource classes 12 section 2 derives, by their schema names: `egress-outside-profile` (a `net.request` outside the session's egress profile, section 6), `push-outside-org` (a `git push` to a remote outside the organisation's list), `pkg.publish`, `message.send`, `mcp-unpinned-write` (an `mcp.call` to a write-capable tool whose manifest is not pinned), `llm-non-tenant` (an `llm.request` to a provider outside `org.model-tenants`). A caller can neither raise nor suppress the derived request. Git push and package publishing are first-class sinks because no agent treats them as distinct today (brief 35). `clipboard.write` (section 12) is a sink class outside the day-one set; file writes outside the workspace join the sink set only by a spine change.

**Flow rules** (12 policies 9 to 11; c8 F3 defaults). `secret-read` to any sink is **Block** (policy 11, class `secret`; not final, so its only route is a declassification Exception). `untrusted` and `sensitive` together, then a sink, is **Ask** with a steer to summarise and confirm (policy 10, the Rule of Two default; briefs 35 and 22). `untrusted:*` alone is **Watch**. Package publishing is Ask with the sponsor as approver (policy 9). Every flow rule ships in Watch (`grdr.dataflow`, 12 section 14) and leaves it only after S-14 replay over the development fleet's history shows the whole rule set inside the spine's prompt budget (median 3, p95 8 per developer-day) with the flow rules' own share at median under 1 and p95 under 3 (c8 spike S1, folded into S-14).

**Declassification** is a grant (12 section 6) bound to the session lineage, the sink, the SHA-256 digest of the outgoing payload and an expiry. It lifts the flow rule for that exact payload only; a new payload needs a new grant, and any label escalation voids it (D-31). For the trifecta gate the grant is an Ask approval at G1 or above; for `secret-read` it is an Exception, whose approver is not `self` and whose grade is at least G1 (12 section 3). Each grant has a receipt and appears in the session timeline the developer sees.

**Taint-creep controls.** Session-level taint creeps until prompts become noise (brief 35, weak points), and users already accept 93% of prompts (brief 22, verification row 4). Four mechanisms, in order of effect:

1. **Two-axis gate.** The trifecta needs both axes, so a coding session that read a web page (integrity only) is not stopped from pushing code. Only a session that read both untrusted content and sensitive data is gated.
2. **Quarantined sub-sessions**. A read of untrusted content runs in a child session with every day-one sink denied, which returns only a typed, low-capacity result (bool, enum, or a string under a declared capacity) to the parent (FIDES; brief 35). The child's labels do not join the parent, so the parent is not tainted by having looked. Microsoft Agent Framework's experimental FIDES implementation (MIT) is the reference for label semantics (brief 35, verification row A). This is offered to in-house agents through the SDK (07 section 12); third-party agents cannot use it, and their sub-agents' labels join the parent.
3. **Deterministic decay.** Each label carries a decay (`session-end`, a duration or an event count; 12 section 9). Day-one decay: `secret-read` and `sensitive:<class>` last until session end; `untrusted:*` also lasts until session end. Shortening any decay is a widening change (12 section 7) and needs the organisation's signature in hosted and provider deployments.
4. **Repetition cap.** Three unanswered or denied flow requests in a row freeze the session (D-31), so a gate cannot be worn down by retrying.

Labels launder through a child agent, a written file or a new session (c8 F3). Lineage scope closes the child-agent path. A file written by a labelled session carries the label on its `file.write` event, and a later read of that file re-applies it through an artefact edge (04 `session.link`); this is also how agent-created content inherits the label of what it was made from, which Microsoft says its own labels do not do (brief 35). A human who starts a fresh agent sheds the labels; that is a residual risk (Risks section).

### 6. Egress rules: method, path, tenant pinning (D-16, D-28 item 5)

Hostname allow-lists are not an egress control: Anthropic's documentation warns that allowing `github.com` creates an exfiltration path and that a proxy trusting the client-supplied hostname is open to domain fronting (brief 35, verification row 4), and the incident catalogue is full of allow-listed multi-tenant hosts used with the attacker's own key or as a redirector (brief 21 section 16: the `api.anthropic.com` Files API, Hugging Face download counters, GitHub Camo, Google Forms). An egress profile is therefore a signed set of rules, each `(host-class, methods, path-prefix, tenant, verdict)`, plus default-deny categories. The proxy evaluates it on the explicit local listener (17 section 3), which chains to any customer gateway or system proxy and trusts the OS store; there is no mandatory TLS interception (D-16).

- **Method and path** exist only where the request is in plaintext: a hook's tool arguments, a base-URL route, or a flow under the opt-in interception CA. Without them the rule degrades to connect and SNI with `verified: false` (12 section 2); an organisation that routes model traffic through our listener may set the strict variant that forbids unverified tenants.
- **Tenant pinning** is the `org.model-tenants`, `org.aws-approved` and `org.production` checks of 12 policies 12 and 13. The cloud-request classifier derives the tenant from the signed request (AWS account from the SigV4 credential scope, Entra tenant from a verified token, GCP project header; 12 section 2).
- **SigV4 requests are judged, not rewritten**, unless the broker holds the AWS credentials and re-signs them; streaming uploads, presigned URLs and SigV4A cannot be re-signed (brief 35).
- **Default-deny categories**, even in a permissive profile: tunnels and mesh VPNs (Tailscale userspace, reverse SSH, Tor), paste sites, request-capture and webhook hosts, form hosts used as drop boxes, instance-metadata endpoints (169.254.169.254), and names that resolve to loopback, private or link-local addresses (brief 35 section 5; brief 21 section 16; 17 section 8).
- **DNS, QUIC and ECH.** The proxy resolves names itself, so client DoH is irrelevant on proxied flows and ECH hides nothing, because CONNECT names the host (brief 35, inference). Contained sessions block UDP/443 so clients fall back to TCP; in `redirected` mode known DoH endpoints are blocked (17 sections 2 and 12). Outside those, the sensor attributes DNS per process and a detection flags high-entropy labels.

### 7. Tenant-restriction headers and managed settings per provider (D-16)

Tenant restriction is the only provider-enforced data control: a header the provider honours, which its documentation assumes a TLS-inspecting proxy will add (briefs 35 and 05). A header can be added only to a request we see in plaintext, so we set it in three places and nowhere else: (a) base-URL routes on the explicit listener, which originate the upstream TLS themselves and need no CA (17 section 3); (b) flows under the opt-in interception CA (17 section 5); (c) the force-installed browser extension, through `declarativeNetRequest` `modifyHeaders` with `set`, which needs no interception (brief 05; the Apache-2.0 `forced-headers-chrome-ext` proves the mechanism; 17 section 10). The header is always set, never appended (brief 35, verification row 8; 17 test N-22). A CONNECT tunnel without interception cannot carry one, and the product reports that flow as unpinned. Headers cannot apply when the agent reaches the model through Bedrock, Vertex or another gateway (17 section 8).

| Provider | Header or setting | Hosts | Preconditions and gaps |
|---|---|---|---|
| Anthropic | `anthropic-allowed-org-ids`: up to 10 header lines and 500 UUIDs; others get 403 `permission_error`, code `tenant_restriction_violation` | claude.ai, api.anthropic.com, claude.com, anthropic.com | Enterprise plans and Console organisations; covers web, desktop, API-key and OAuth sign-in. The article does not mention Bedrock, Vertex or mobile (brief 35, verification row 8) |
| OpenAI (ChatGPT) | `ChatGPT-Allowed-Workspace-Id` | chatgpt.com | Team or Enterprise workspace; does not cover api.openai.com; blocking logged-out use at `chatgpt.com/backend-anon/` is an undocumented path at medium confidence (brief 05, verification row 4) |
| OpenAI (Codex) | `allowed_chatgpt_workspaces`, `allowed_login_methods` in `requirements.toml` | Managed settings file | API keys bypass unless the `api` login method is excluded (brief 05) |
| Microsoft | TRv2 `sec-Restrict-Tenant-Access-Policy`; v1 `Restrict-Access-To-Tenants` with `Restrict-Access-Context`; `sec-Restrict-Tenant-Access-Policy: restrict-msa` on login.live.com | login.microsoftonline.com, login.microsoft.com, login.windows.net, login.live.com | Entra ID P1 or P2 (brief 35). Consumer Copilot is reachable at copilot.cloud.microsoft, so URL blocks are not enough (brief 05) |
| Google | `X-GoogApps-Allowed-Domains`; omit `consumer_accounts` to block personal accounts | `*.google.com` | Applies to all Google sign-in, does not guarantee every Gemini path, and existing personal sessions may persist (brief 05) |
| GitHub Copilot | `sec-GitHub-allowed-enterprise` | github.com, api.github.com, `*.githubcopilot.com` | Enterprise Managed Users only; otherwise block `*.individual.githubcopilot.com` (brief 05) |

**Managed settings per agent** carry the same rule to agents directly, written through the D-49 writer and compiled by D-12, whose first targets are exactly these two files: Claude Code `forceLoginOrgUUID`, and `allowedProviders: ["customEndpoint"]` with `ANTHROPIC_BASE_URL` in the managed file's `env` block, which pins Claude Code to our listener (v2.1.285 and later; brief 38, verification row 4); Codex `allowed_chatgpt_workspaces` and `allowed_login_methods`; Cursor `AllowedTeamId` as a further D-12 target (brief 05, implications; unverified, proven by conformance before use; `CURSOR_API_KEY` bypasses it). With `forceLoginOrgUUID` set, Claude Code blocks `apiKeyHelper`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` at start (brief 07, verification), so it is written only for instances whose credential mode is `vendor-login` (15). One signed tenant pack compiles to all three enforcement points (17 section 10); it is content, so it changes without a client release.

### 8. Phantom tokens and honeytokens (D-28 items 6 and 7)

**Phantom tokens**. They require the credential broker (15). In the broker's `inject` mode the agent holds a per-session phantom and the proxy substitutes the real value only for the hosts, methods and paths the grant names (brief 35: Claude Code `mask`, nono, Infisical Agent Vault and Fly's tokenizer use the same shape). Substitution needs plaintext, so it happens on base-URL routes (no CA) or on intercepted flows (opt-in CA), never in a plain CONNECT tunnel. The broker (15 section 5) mints the phantom and holds the secret; this document owns two properties:

1. **Transform.** `swap-credential` (12 section 4) is the proxy rewrite that replaces the phantom with the brokered secret for an approved destination and strips it everywhere else.
2. **Attribution proof.** A substitution happens only with `peer_verified`, a kernel-observed peer inside the phantom's session lineage (D-27, SR-34, 15). A peer-verified substitution is recorded as `session-credential` evidence (04), which separates agent from human on a shared credential in our own receipts. Third-party logs still see one credential; only D-26's `credential` grade separates them there.

**Honeytokens.** A honeytoken is a `Credential` of class `honeytoken`. Its `cred.use` is Essentials **Block, final, `@on_loss("block")`** (12 policy 2) and a threat finding that pages (D-54). The trigger is model-free (P2): use of a value that exists only as bait is unambiguous. ATLAS lists AI honeypots as mitigation AML.M0039 (brief 21, ideas).

- **Decoys.** Per device, from a signed template pack: a decoy AWS credentials file, a dotenv-format secrets file, a kubeconfig and a standalone MCP configuration file that no agent loads (Canarytokens ships an "MCP Configuration" type, brief 35). Each is a **new file at a plausible path that matches no section 2 pattern (so no `.env*` name and not `~/.kube/config`) and lies outside any git work tree**, so the read gate never hides it and no decoy is ever committed or pushed. We never add a decoy to an existing user file such as `~/.aws/credentials` (D-27). Decoy values are random, shaped to the credential type's prefix and length class (15), and kept on the device as HMAC digests in the `honeytoken` class.
- **What counts as use.** The deterministic scanner matches decoy values in tool arguments and launch environments (hook, request level), in request headers and bodies on plaintext proxy flows (requires the explicit proxy), and in `cred.use` events from helper protocols (requires the broker). A *read* of a decoy file is a low-severity finding, not a block: the most capable models over-collect data in 43 to 61% of benign runs (brief 39, verification row 8), so a read alone would fire on honest exploration.
- **Phantom misuse.** A phantom presented at a host outside its host set, or by a process outside its lineage, is denied and raises `cred.phantom.misuse` in the threat class (15). This is c8 F10's preferred first honeytoken because it needs no planted file; it requires the broker, so the decoys above carry D-53's Essentials rule wherever the broker is absent.
- **Cloud-validated canaries** (a decoy key that alerts when presented to the real provider) are opt-in, for the same over-collection reason (c8 F10). HoneyMCP (Apache-2.0) is the reference for decoy MCP tools (h01).

### 9. Workspace baseline, copy-on-first-write and the mass-change breaker (D-28 item 8)

Agents' own undo is file-only and partial: Claude Code checkpoints miss files changed only by Bash and most sub-agent edits, Gemini CLI's shadow repository is off by default, and nothing reverses external side effects (brief 35, verification row 9). Our baseline is agent-independent and is what response action 10 restores from (18 section 2).

- **Baseline at session start.** For each session-exclusive session (D-25) the daemon records a manifest of the workspace (path, size, mode, SHA-256) excluding git-ignored paths, excluded paths (D-51) and files above a size cap (target 32 MiB, recorded by digest and reported as not restorable). Where the filesystem clones cheaply (APFS `clonefile`, `FICLONE` on btrfs and XFS, ReFS block clone on Dev Drive) the whole manifest is cloned into the store at start. Elsewhere the eager copy is limited to what git cannot restore: modified, staged and untracked non-ignored files.
- **Copy-on-first-write.** Before the first write, rename or delete of a manifest file in the session, its prior content enters the store. For file tools this is the `snapshot` must-obligation (12 section 4): the hook's pre-action decision returns ALLOW only after the daemon has copied the file, and a control point that cannot honour the obligation gets DENY `obligation-unmet`. The obligation is attached only to file-tool writes and to `exec` actions whose canonical argv names its targets (the recursive-delete and history-rewrite families of section 3); an opaque shell command is never denied for lack of a snapshot, and relies on the session-start copy instead.
- **Store.** Content-addressed (SHA-256) in the daemon's state directory, never uploaded, data class `content`. Caps are targets: 5 GB per device and the last 10 sessions, retained 72 hours after session end; when a cap is hit, the oldest finished session goes first and an active session's baseline is never evicted. In the Protected profile the store is not writable by the user; in the User profile it is, and tamper grade is `user`.
- **Mass-change breaker.** The `mass-change` session rule (13: 200 changes in 60 s, a pack parameter) counts file events from the OS sensor and file tools. In Watch it raises a finding. Once promoted, and where the baseline store is present, it freezes the session automatically (18 section 1: freeze is automatic with a default 4-hour limit), and the console offers restore. The change rate is observed after the fact, so files changed before the threshold are restored from the store, not prevented.
- **Restore** (`grdr restore --session <id> [--path <glob>]`, and response action 10). Files are written back atomically from the store with a pre-restore copy kept (18). The report lists what could not be restored: files over the cap, changes outside the workspace, and the session's external effects from its events (pushes, publishes, mutating cloud and database calls, messages). The irreversibility gate of section 3 exists for those.
- **Class.** The baseline is recovery, not a control: it never raises the `control` value in the assurance record, and the freeze acts at the session's existing class.

### 10. Classification connectors and provider posture (D-28 items 9 and 10)

**Classification connectors** supply confidentiality labels. They are `connector` control points and integration adapters (D-40; 25 owns the adapter host):

- **MSIP labels on local files**, read in the sandboxed engine without the MIP SDK, for unencrypted Office files: keys `MSIP_Label_<GUID>_Enabled`, `_SiteId`, `_Name`; the LabelInfo stream used with co-authoring; the `MSIP_Labels` email header. Only `Enabled` and `SiteId` are mandatory, and a reader checks both the legacy location and LabelInfo (brief 35, verification row 7). An organisation-supplied table maps label GUIDs to `sensitive:<class>`; a label whose `SiteId` is not the organisation's tenant maps to `sensitive:external-label`. Because the read is deterministic and on the device, the session rule writes an *enforcing* label at the read.
- **Purview `processContent`** (Graph v1.0 `POST /users/{id}/dataSecurityAndGovernance/processContent`, permissions `Content.Process.User` or `Content.Process.All`) returns `policyActions` with `restrictionAction` of `warn`, `audit` or `block`. It may return 202 or 204 with no body, so the caller defaults to no restriction; it is unavailable in the China cloud and for personal Microsoft accounts (brief 35, verification row 6). Its hot-path latency is unmeasured (Risks), so it runs asynchronously: its result is an *advisory* label (D-09) and a finding, and a result that arrives after a decision it would have changed raises `label.late`. It becomes an inline, restrict-only fact only after the latency spike passes.
- **Drive labels** are structured metadata read through the Drive API by a SaaS connector; a synced local copy appears to carry no label (brief 35, inference), so a Drive label applies to source-side reads only. The Graph and Drive base URLs are connector configuration with no compiled default. Where neither is reachable, as on a site without internet, both connectors report `not configured` and produce no label; the MSIP reader needs no network and still writes enforcing labels, and nothing that blocks depends on Purview or Drive.

Labels are sparse in developer environments: source code, `.env` files and database dumps carry none (brief 35). That is why the deterministic secret detection and the path classes of section 2 carry the weight, and classification connectors are an enterprise addition, not the floor.

**Provider posture.** A per-(app, principal) **account-context** record (brief 05, implications 3): email domain class (corporate or personal; a non-corporate address is kept only as an HMAC under the organisation key, per D-51 and 04 section 11), IdP and login method, MFA, tenant or workspace id, plan tier, training opt-out state, connected OAuth apps. Each field carries provenance and confidence. Per-app adapters are **signed, versioned data** (selectors and endpoint descriptors), not code, so the community maintains them and an update needs no store review. Whether an account trains on the organisation's data is something nobody verifies today (brief 05); we record it with stated confidence, never as fact. Session riding (calling an app's private endpoints with the user's cookie) is how plan and MFA state are learned, but the endpoints are undocumented and may breach provider terms (brief 05): it is off by default, needs the organisation to enable it per app, and is never done for a personal-domain login. Posture produces facts and findings; it is not itself a control.

### 11. Content capture levels and on-device redaction of our own telemetry (D-51, P8)

The four capture levels, the filter and the redaction markers are specified in 04 section 11; this document owns the two things 04 defers to it, and the treatment of telemetry we ingest.

**Which detectors run at capture.** Capture is one step on the device: the deterministic secret and PII detectors of section 4 run at every capture level and replace each hit with a 04 marker (`[[grdr:r:<n>]]`, reason `secret` or `personal-data`, `value_digest` an HMAC under the organisation key); then the filter removes the classes the level withholds; then digests are computed. The model tier never runs at capture. Honeytoken values are redacted like any secret. The per-session placeholder of section 4 belongs to the agent's channel, not to our records.

**A secret is never kept, even at `full content`.** At `full content` the `original` bytes of other redactions are stored, bound by `value_digest`, but a redaction with reason `secret` stores no `original` at any level. A security product must not become the place the secret finally lands: Claude Code's "don't ask again" rules were found holding 1,379 secrets in 1,122 public files (brief 21, verification row 10, from a secondary source).

**Telemetry we ingest is captured like our own.** Default upload is `metadata` (D-51), and `redacted arguments` leave the device only as an `EvidenceSpan` on a finding or under a content grant. The flight recorder, response-time evidence capture and the L1 local feed obey the same filter (04), so none is a bypass (l07). Harness telemetry and transcripts are claims (P3), and Claude Code's OTel records the original output even after a hook rewrite (brief 35, verification row 2), so ingested OTel and transcripts pass through the same capture step before they enter any store or sink. A redaction at the agent's hook is never trusted to have cleaned them.

**No covert collection.** The sensor installs no keyboard or mouse hook and records no keystroke timing, screen content or clipboard content (D-51; l07: a works council treats a global keyboard hook as a keylogger). Synthetic-input evidence for `ui.act` therefore comes only from process-side signals; g09's proposal to read injected-input flags through low-level input hooks on Windows is not adopted.

### 12. Computer use and clipboard (D-28, D-51)

Computer-use agents act on the real desktop with per-app prompts and no sandbox (brief 35), and clipboard and screenshots are exfiltration channels (brief 35, channel table).

- **Clipboard and screen are observed structurally, never captured.** A clipboard write is derived from what the agent does, never from reading the clipboard: an `exec` whose canonical argv is in the `clipboard-write` command class (`pbcopy`, `xclip`, `wl-copy`, `clip.exe`, `Set-Clipboard`), or a computer-use tool action of that kind in the hook payload (04 `action.ui.act`). The event records target application or origin and action kind. `clipboard.write` is a sink class; it is not one of D-28's day-one sinks. Purview Endpoint DLP already gates paste and clipboard on Windows and macOS for files saved to disk (brief 35); where a customer runs it we coexist and do not duplicate it (P12).
- **The capability inventory on macOS is the TCC grant set** (Accessibility, Screen Recording, Automation), read from MDM privacy profiles and Endpoint Security TCC events at tier 3, never from the TCC database, which macOS 27 closes (g09, verification row 10). It lists which apps are computer-use capable; it is not per-action attribution.
- **Synthetic-input flags miss UI Automation and Accessibility-pattern automation** (g09), which better computer-use agents prefer, so "no synthetic input detected" is reported as a coverage limit, not an all-clear (P9).
- The computer-use TOCTOU (the screen changes between screenshot and click; brief 21 item 74) is the agent's residual risk, outside our control points.

### 13. How each control is reported: boundary or request (P1)

Every control reports its `control` class per device, agent instance and action class in the assurance record (07 section 11), never better than the host enforces. In the User profile every control is a request and grants are G0 (D-48, SR-07). The table is a summary; the record is authoritative.

| Control | User profile | Protected profile, uncontained | Contained session | `gateway` the network forces traffic through |
|---|---|---|---|---|
| Protected-path read gate | `request` | `request`; `mandatory-boundary` at the Linux kernel tier | `scoped-boundary` | n/a |
| Control-file write block | `request` | `request`; `mandatory-boundary` at the Linux kernel tier | `scoped-boundary` | n/a |
| Environment scrubbing | `request` | `scoped-boundary` where our launcher starts the process; `request` where we set the agent's own flag | `scoped-boundary` | n/a |
| Irreversibility gate | `request` | `request` | `scoped-boundary` for the outside-workspace column; `request` for remote targets | `mandatory-boundary` for mutating HTTP it sees |
| Secret redaction | `request` | `request` | `request` at hooks; `scoped-boundary` for model requests forced through the listener | `mandatory-boundary` for model requests it carries |
| Egress and tenant pinning | `request` | `request` (explicit listener) | `scoped-boundary` | `mandatory-boundary` |
| Phantom injection (requires the broker) | Not offered (no broker, D-48) | `scoped-boundary` | `scoped-boundary` | `scoped-boundary` |
| Honeytoken use | `request` | Class of the point that sees the use | Same | `mandatory-boundary` for requests it carries |
| Label sink gating | `request` | `request` | `scoped-boundary` | `mandatory-boundary` for flows it carries; labels it did not observe are absent (17 section 9) |
| Workspace baseline | Recovery; no class | Same | Same | n/a |

A control reported as `request` carries the note that a same-user agent can evade it; the product says so instead of calling a hook "kernel-level" (P1).

## Interfaces and contracts

- **Facts and labels** (to 12 via 04): `secret.type`, `content.secret`, `pii.class` (deterministic, policy-readable); `injection-suspected` (model, advisory). Labels and source rules per section 5. The `data.flow` resource classes of 12 section 2 are this document's day-one sink catalogue.
- **Path, command and target classes** (to 12): `cred-store`, `private-key`, `agent-store`, `browser-store`, `agent-control`, `grdr-control`, `monitoring-config`, `honeytoken` (section 2, generated with 15's `credential-locator` pack); destructive families and the target classes `workspace`, `outside-workspace`, `vcs-remote`, `production` (section 3); `clipboard-write` (section 12).
- **Transforms** (to 07, 12, 17): `redact-secrets` and `swap-credential` are closed-enum transforms named by `@remedy`. This document defines what they replace, 12 owns the policies that name them, 07 and 17 own whether a control point can apply one.
- **Capture step** (`grdr-model`, 04 section 11): this document supplies the detector set that runs at capture and the rule that `secret` redactions keep no `original`.
- **`DetectorPort`** (layer 3): `classify(bytes, kind) -> {facts, spans, origin}`. Adapters: Kingfisher (deterministic), model encoders (`heuristic` or `model`), administrator-installed non-OSI weights. No network I/O in any shape.
- **Classification connectors** (to 25): MSIP reader, Purview `processContent` client, Drive label reader; each returns `sensitive:<class>` with provenance and label kind (enforcing or advisory).
- **Account-context record** (to 05 and 17's browser extension): `{app, principal, email_class, idp, login_method, mfa, tenant_id, plan, training_opt_out, connected_apps}`, each field with provenance and confidence, filled from signed adapter data.
- **Egress profile** (to 17): a signed set of `(host-class, methods, path-prefix, tenant, verdict)` rules plus default-deny categories; the tenant pack compiles to proxy header sets, browser rules and D-12 native settings.
- **Workspace baseline** (to 12 and 18): the content-addressed store and manifest of section 9, the `snapshot` must-obligation (12 section 4), and `restore(session, paths) -> {restored, not_restorable[]}` used by response action 10 (18).

## Behaviour by deployment shape

- **Standalone.** Nothing leaves the device (D-48), so the capture step serves the local store, the local feed and support bundles. In the User profile there is no broker and no interception CA: secret handling is detection, `deny-read` and the agent's own mask where it has one; every control is a request and the credential-store Ask becomes Block (section 2). Protected paths, the irreversibility gate, honeytokens and the baseline all work. The Protected profile adds launcher-owned environment scrubbing at `scoped-boundary`, the opt-in interception CA (memory-only, name-constrained, per process tree; D-16, SR-38) and, where present, the broker.
- **Platform, self-hosted and hosted.** The organisation can raise the capture level, visibly (D-51); provider and operator layers may only narrow privacy settings (D-11). Classification connectors, the account-context record and provider posture run here. Self-hosting is the default; the hosted service requires revenue, sponsorship or donated cloud credits (spine section 7). The hosted operator uses tenant data only to run the service and cannot read content (D-55, SR-43). Review input follows the capture level, and the model provider is named as a sub-processor (29).
- **Embedded.** The host supplies a profile (D-60); a redaction channel or detector the host cannot provide returns "not evaluable" instead of claiming a boundary. The L1 feed obeys the capture filter and omits `identity.mapping`, `content.blob` and `audit.access` (04). No Loonaro trust roots and no network call to us.

## Extension points

None touch the core. (1) **Secret and PII rule lists** as pack data (Betterleaks TOML plus ours); growing a `protect` list is narrowing. (2) **Detector packs**: YARA-X and patterns emitting facts with recorded origin; `DetectorPort` adapters for models. (3) **Protected-path and protected-environment lists** per OS, and **destructive families and production lists**, as signed content. (4) **Classification connector adapters** as signed data plus WebAssembly components for a verdict API (D-40). (5) **Account-context app adapters** as signed data. (6) **Honeytoken templates**. (7) **Egress profiles and the tenant pack** as content. Administrator-installed non-OSI detector weights carry licence metadata into the SBOM.

## Security and privacy

- **No control depends on a model** (P2): protected paths, the irreversibility gate, egress default-deny, the secret-read-to-sink block, credential handling and honeytoken verdicts are deterministic. Model detectors only restrict and are off until the organisation enables them with a capture level that permits them.
- **The product must not become the secret store** (section 11): `secret` redactions keep no `original` at any capture level; live validation is disabled on endpoints; `/proc/<pid>/environ` is a protected read; decoy values are held only as HMAC digests.
- **The baseline store holds workspace content** on the device only, under the session's retention, excluding excluded paths; it is never uploaded and `grdr leave` and `grdr uninstall` delete it.
- **Privacy floor** (D-51, 29): default upload is metadata; redacted arguments travel only as finding evidence or under a content grant; no clipboard, screen or keystroke capture; the pack validator rejects grouping by principal. Classification connectors see tenant data only under the tenant's own grant.
- **Redaction is a claim unless we own the channel** (P3): a hook-side rewrite is a request, and the harness's own telemetry passes through our capture step before ingest.
- **The interception CA** is opt-in, per device, name-constrained, memory-only and never touches browsers or updaters (D-16, SR-38); it breaks certificate-pinned tools, which the product detects and reports instead of forcing.

## Test and evaluation strategy

| Property | Oracle |
|---|---|
| Protected-path Ask fires for agent lineage and not for humans; Block in the User profile | Seeded files from every per-OS class; agent and non-agent reads; OS open events as the independent record |
| Per-OS defaults are real | Pack CI installs each owning tool on each OS fixture (free hosted CI runners for Linux, Windows and macOS) and asserts the listed path exists after login or first use |
| Irreversibility gate | Scripted agent runs one command per destructive family against each target class, with production declared by credential class, account list and kube-context list; verdicts match section 3; heuristic `prod` names raise and never lower |
| A secret is never stored | Seeded canary secret at every capture level; search upload batches, flight recorder, L1 feed, OCSF export, support bundle, review input and ingested OTel; zero hits (04 privacy canary test, l07) |
| Redaction matrix holds per agent | c8 spike S3: seed a synthetic secret; attempt hook and proxy rewrite on Claude Code, Codex, Cursor and Copilot CLI; secret absent from provider-bound requests in every `rewrite` cell |
| Sink gating prompt budget | S-14 with c8 S1: replay the flow rules over SWE-chat v2 (17,968 sessions) and development-fleet history; flow rules median under 1 and p95 under 3 prompts per developer-day, all rules inside the spine budget |
| Child labels join the parent; quarantine does not | A child reads a canary-injected page and returns free text (parent gains `untrusted:web`), then a quarantined child does the same and returns an enum (parent unchanged) |
| Egress is not hostname-only | Replay brief 21 section 16's channel catalogue; each allow-listed-host channel is denied by method, path or tenant |
| Tenant header set on plaintext flows only | Base-URL route and browser extension: provider returns 403 for a non-allowed organisation; a plain CONNECT tunnel is reported unpinned; exactly one header value (17 N-22). The 403 check requires a provider tenant on the qualifying plan, through a design partner or a free developer programme, and is marked "requires tenant" until one is available |
| Honeytoken use is a model-free block | Scripted agent reads a decoy (low finding, no block) and then uses it (Essentials Block, paging threat finding, no model consulted); no decoy inside a git work tree or a protected pattern |
| Baseline and breaker | c8 spike S4 freeze drill plus a scripted 500-file delete through Bash: the session freezes, restore returns every file under the cap, and the report lists the push the script made as not restorable |
| No covert collection | Audit the sensor binaries for input hooks and screen or clipboard APIs; works-council review of the default (l07) |
| Operator-installed models work with no route out | A fixture ONNX model installed with `grdr model install` loads in `grdr-infer` with no route; a `model` pack from any other signer class is refused |
| Labels without vendor clouds | G1's labelled Office file yields an enforcing label offline; Purview and Drive show `not configured`; no Microsoft or Google DNS query leaves |

## Work breakdown

**Epic A. Protected paths, environment and the irreversibility gate.**
- A1 Per-OS protected-path and protected-environment lists as signed packs, generated with 15's `credential-locator`. Accept: a new path takes effect from a pack with no rebuild; lint rejects a permissive reference; pack CI proves every Linux and macOS entry on a fixture install, and unproven entries ship Watch-only.
- A2 Environment scrubbing at launch and through the agent's own flag. Accept: a seeded `AWS_SECRET_ACCESS_KEY` and a `FOO_TOKEN` are absent from a tool subprocess's environment and `/proc/<pid>/environ`; `SSH_AUTH_SOCK` is kept outside contained sessions and recorded.
- A3 Protected-store read detection for processes outside agent lineage (Linux). Requires the Linux observation sensor. Accept: an infostealer-style read of `~/.claude.json` raises a finding; the agent's own read of its own store does not.
- A4 Irreversibility rules for the workspace and outside-workspace columns at the hook. Accept: the gate test passes for every family on Claude Code and Codex; recursive delete outside the workspace is Ask in Essentials and Block in the User profile.
- A5 Production targets: `org.production-*` lists, credential class, proxy judgement of mutating HTTP. Requires A4 and the explicit proxy. Accept: a mutating AWS call to a listed account is Ask at G2 (policy 13); with no lists, replay reports the column not evaluable.

**Epic B. Detection and redaction.**
- B1 Kingfisher and Betterleaks secret engine behind `DetectorPort` in the engine process, validation disabled. Accept: a scan of a 10,000-file fixture makes zero outbound connections (sensor-observed); facts carry `origin: deterministic`; the core still builds for `wasm32`.
- B2 Presidio-ported PII recognisers; Unicode, bidi, zero-width and ANSI normaliser. Accept: an invisible-Unicode instruction in a tool description raises the c8 detection; recogniser unit tests pass on Presidio's published pattern examples.
- B3 Redaction matrix per agent and channel with the `deny-read` fallback, Claude Code and Codex. Requires B1. Accept: c8 S3 passes in every `rewrite` cell; a `none` cell for a known credential file denies the read.
- B4 The same for Cursor and Copilot CLI, and the proxy's model-request rewrite. Requires B3 and, for the proxy rewrite, the explicit proxy. Accept: c8 S3 passes for both agents and for a base-URL route.
- B5 Capture step: detectors at capture, no `original` for `secret`, ingested OTel and transcripts captured. Accept: the privacy canary test finds zero hits at `full content`, including in ingested Claude Code OTel.
- B6 `DetectorPort` model tier, off by default. Accept: the validator rejects a `permit`, `unless` or session rule reading a model fact; a quantised model ships only with a measured accuracy delta inside its gate.

**Epic C. Labels and flows.**
- C1 Day-one source rules with lineage scope and child-to-parent join. Accept: `secret-read` precedes the next egress decision under parallel tool calls (12 ordering test); the child-join test passes.
- C2 Sink catalogue and `data.flow` derivation (with 12). Accept: a caller cannot raise or suppress the derived request; each of the six sink classes is derived from a scripted action.
- C3 `grdr.dataflow` in Watch with replay. Requires C1, C2 and the S-14 replay. Accept: the S-14 replay result is attached to the pack and the rules stay in Watch until it passes.
- C4 Declassification grant bound to the payload digest; decay rules. Accept: a grant lifts exactly one payload and a changed byte needs a new grant; shortening a decay is classified as widening.
- C5 Quarantined sub-session in the SDK with capacity-typed return. Requires the SDK (07 section 12). Accept: the quarantine half of the child-label test passes.

**Epic D. Egress and tenant pinning.** Requires the explicit proxy (17).
- D1 Egress profile object and `(host-class, methods, path-prefix, tenant, verdict)` evaluation in the proxy. Accept: every channel in brief 21 section 16 is denied in the replay.
- D2 Tenant pack: provider header sets and native settings through D-12 for Claude Code and Codex; the proxy applies the headers in 17's N2.8. Accept: a non-allowed organisation gets 403 through the listener; `forceLoginOrgUUID` is never written for an instance in `key-helper` mode.
- D3 Default-deny categories; UDP/443 drop and DoH handling in contained and redirected sessions. Accept: a Tailscale-userspace enrolment and a webhook.site request from agent lineage are denied.
- D4 Browser tenant rules (with 17 N6.2). Requires D2 and the browser extension. Accept: personal sign-in to each listed provider is refused on test accounts; a provider whose restriction needs a paid plan is tested through a design partner's tenant or a free developer programme and is marked "requires tenant" until one is available.

**Epic E. Honeytokens and phantom tokens.**
- E1 Decoy template pack, planting outside protected patterns and work trees, value matching, Essentials Block. Accept: the honeytoken test passes on Linux and macOS.
- E2 `swap-credential` and the phantom attribution proof (with 15). Requires the credential broker and the explicit proxy. Accept: TM-19 passes; a phantom at a host outside its set raises `cred.phantom.misuse`.

**Epic F. Workspace baseline.**
- F1 `mass-change` session rule in Watch (with 13). Accept: a scripted 500-file delete raises one finding per session.
- F2 Manifest, clone or eager copy, copy-on-first-write with the `snapshot` obligation, store caps. Accept: a file-tool write on a control point without the capability returns DENY `obligation-unmet`; an opaque shell command is not denied for lack of a snapshot.
- F3 Automatic freeze and restore (with 18). Requires F1 and F2. Accept: the baseline-and-breaker test passes on Linux and macOS; on Windows it requires the snapshot spike below.

**Epic G. Classification, posture and computer use.**
- G1 MSIP reader, Purview `processContent` client (asynchronous), Drive label reader. Requires the integration host (25); the Purview and Drive checks require a tenant through a design partner or a free developer programme. Accept: a labelled unencrypted Office file yields an enforcing `sensitive:<class>`; a Purview `block` yields an advisory label and a finding; a 202 or 204 defaults to no restriction.
- G2 Account-context record from signed app adapters. Accept: a personal address is stored only as an HMAC; with session riding off, no request reaches an app's private endpoint (proxy-observed).
- G3 `clipboard-write` command class and `ui.act` sink derivation. Accept: `pbcopy`, `xclip` and `Set-Clipboard` from agent lineage produce `ui.act` events with no clipboard bytes in any record.

## Risks, open questions and spikes

- **Session-taint prompt rate is unmeasured** (brief 35, c8 F3). Settled by S-14; flow rules stay in Watch until it passes. If it fails, the trifecta gate stays in Watch and only `secret-read` to a sink is promoted.
- **`processContent` hot-path latency is unknown** (brief 35). It runs asynchronously until a spike measures p95 on a representative tenant.
- **Kingfisher on every target.** Whether the Vectorscan-based crates build on Windows ARM64 is unverified (brief 09). A spike on a free hosted Windows arm64 runner is a prerequisite for B1 on that target; the fallback is a pure-Rust matcher over the same TOML rules with a measured recall delta.
- **Quantised DeBERTa models can lose accuracy badly** (brief 09, self-reported: PR-AUC 0.997 to 0.46 in one case). Every quantised model is gated on a measured delta; ship fp32 or skip.
- **Per-session snapshots on Windows without elevation are an open question** (brief 35). NTFS has no clone; ReFS block clone covers Dev Drive only, and VSS needs administrator rights. A spike is a prerequisite for F2's clone path on Windows; without it Windows gets the eager copy limited to what git cannot restore.
- **Chrome content analysis.** Brief 05 reports, unverified, that Chromium hard-codes the permitted local providers. If true, clipboard and paste classification in Chrome depends on an upstream change or on Purview.
- **The new-session laundering path** (a person starting a fresh agent to shed labels) is not closed; it is residual and visible in the session timeline.

## Deviations from the spine and objections

None from the spine, and no objection is open: no ruling in `_review/01-document-rulings.md` names this document, and spine version 4 removes milestones, which this document follows by stating prerequisites instead; beyond that, only the P7 and D-31 wording applied in section 2 changes here. Two review proposals are not adopted because the spine overrides them: c8 F3 makes `injection-suspected` Ask, but D-09 makes advisory labels absent in Cedar, so it raises risk and findings only; c8 F10 puts the irreversibility gate third and makes a phantom token the first honeytoken, but D-28 orders the gate second and D-53 needs honeytoken use in Essentials without depending on the broker, so planted decoys carry that rule and phantom misuse adds to it where the broker is present. One brief proposal is changed: brief 35 builds the child environment from an allow-list; the default here removes listed names, and allow-list mode is opt-in for contained sessions, because an allow-list breaks unlisted tool variables and Essentials requires zero block-induced task failures (D-53).

## Sources

Research briefs, each read with its Independent verification section, which overrides the body: `35-data-secrets.md` (protected paths, masking, IFC, tenant headers, honeytokens, undo), `09-oss-detectors.md` (secret, PII and injection detectors, licences, adaptive attacks), `38-network-gateways.md` (egress, Claude Code gateway pinning), `05-sidekick.md` (account context, provider posture, header injection without interception), `21-threats-incidents.md` (exfiltration-channel catalogue, destruction incidents, approval-memory secret leak), `22-research-conferences.md` (Rule of Two, NVIDIA mandatory controls, prompt acceptance), `39-ai-ml-strategy.md` (over-collection rate), `07-market-identity.md` (Claude Code login policies), `g09-os-native-agent-platforms.md` (TCC, synthetic input), `h01` (HoneyMCP), `h07` (infostealers with agent modules). Review notes: `c8-detection-response-ai-data.md` (F3, F6, F10; spikes S1, S3, S4), `l07-privacy-works-council.md`. Design documents 02, 04, 07, 12, 13, 15, 17, 18.

Primary URLs cited through the briefs' verification sections: Claude Code sandboxing, hooks and network-config docs (code.claude.com); Microsoft Graph `processContent` and MIP metadata (learn.microsoft.com); Anthropic tenant restrictions (support.claude.com); Kingfisher (github.com/mongodb/kingfisher); OpenAI privacy-filter evaluation (arxiv.org/abs/2608.02616); CaMeL (arxiv.org/abs/2503.18813) and FIDES (arxiv.org/abs/2505.23643); Agents Rule of Two (ai.meta.com/blog/practical-ai-agent-security); Canarytokens (docs.canarytokens.org).
