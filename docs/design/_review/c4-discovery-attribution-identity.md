# Review C4: discovery, attribution and identity (D-24 to D-27, actor fields in D-06)

Briefs are cited by number; "V-n" is a verification-table row.

## Summary

The direction holds, but the decisions are written for a CLI agent we launched and break on the cases the owner named. D-25 gives a per-session kernel container to agents whose sessions are not process subtrees, labelling human work as agent work at top confidence. The basis vocabulary is a flat list that policy cannot order. D-24's loop test mostly needs plaintext that D-16 withholds for the unregistered agents it targets. D-27 lists a model-key helper that the login policy from D-12 blocks. The change that matters most: replace the single basis value with an evidence set, a fixed ordinal grade and an explicit `undetermined` actor kind, so the product can say "do not know" instead of guessing.

## Findings

### F1. Blocker, wrong. D-25: a session is not always a process subtree

**Problem.** The container rule works for CLI agents and `grd run`. In IDEs and desktop apps one long-lived host runs several sessions, other extensions and the human's terminals. Containerising "at first sighting" captures the whole host; brief 17 scores container membership 1.0, so human commands become agent actions with the strongest basis. M1 includes Cursor.

**Evidence.** 17 "Could not verify" lists "many sessions sharing one long-lived daemon (IDE extension hosts, tmux)" and agent versus human in one terminal as open problems. 17 V-8: `CLAUDECODE` is also set in IDE integrated terminals.

**Amendment to D-25.** "A session container is created only where the root process is session-exclusive (CLI agent, `grd run`, managed process wrapper). For host-shared agents the container is scoped to the agent instance and proves only 'inside an agent-capable host'. Per-action attribution there needs a per-call binding: a hook match on tool-use id, command and working directory, or an exec-time tag. Everything else is emitted with actor kind `undetermined`, and each rule class states how that is treated. Catalogue entries declare `session_exclusive`."

### F2. Blocker, wrong. D-06 and D-25: the basis vocabulary cannot be ordered or used in Cedar

**Problem.** `hook-declared` is a claim (P3) with per-call precision; `session-container` is an observation with session precision; neither is "stronger", so "minimum strength" has no order. Missing: exec-time tag (17's second-strongest binding), brokered hop, session-bound credential (D-26's own mechanism), connector-reported (cloud-first Cowork, 16). `protocol-asserted` overlaps `hook-declared` (g09 defined it to include hook payloads). One value per event discards corroboration. Confidence weights are placeholders (17), so a float in policy changes enforcement when content retunes. "Subject and actor pair" is undefined and cannot hold a sub-agent chain.

**Amendment to D-06.** The envelope carries:

| Field | Content |
|---|---|
| `principal` | On whose behalf: human or service, and how it was mapped |
| `actor_chain[]` | Agent instance, session, child sessions, tool-call id |
| `actor_kind` | `agent`, `human`, `undetermined`, `system` |
| `attribution.evidence[]` | `os-principal`, `session-credential`, `session-container`, `exec-tag`, `declared-matched`, `declared-only`, `lineage`, `brokered`, `traffic`, `connector` |
| `attribution.grade` | 4 separate principal or credential; 3 session-exclusive container or exec tag; 2 claim matched to observation; 1 single source; 0 inferred |
| `attribution.score` | Advisory, for ranking only |

Policy may read grade and evidence, never score. Attribution decided after emission is a superseding graph edge, not an edit.

### F3. Major, risky. D-24 pass 3: loop evidence mostly needs content we do not have

**Problem.** A tools array and argument-matched effects need request plaintext; a stdio MCP exchange needs pipe content. D-16's default is connect and SNI; hooks, OTel and the explicit proxy exist only for agents already configured. For an unregistered agent the content-free evidence is "provider connection, then a child exec or file write", which also describes IDE completions, a batch summariser and a notebook. Agents behind a corporate gateway show no provider SNI.

**Evidence.** 38 TL;DR: transparent redirection "is the only one that catches unregistered bespoke agents". 17 Weak points: the loop window has no published precision or recall. The g08 targets are absent from spine section 6.

**Amendment.** D-24 states, per visibility tier, which evidence is reachable. Without plaintext the finding is `agent-suspected`: three or more response-then-new-child-exec cycles in one process lifetime plus a composition signal; it never drives Ask or Block. Section 6 gains: precision 95% against LLM-calling non-agents, recall 85% by packaging tier, and at most one new triage item per ten developer endpoints per week after week one. Configured internal gateways count as inference endpoints.

### F4. Major, wrong. D-27: model-key helper conflicts with forced login; helper install model is missing

**Problem.** 07 verifier: with `forceLoginMethod` or `forceLoginOrgUUID`, Claude Code blocks `apiKeyHelper`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` at startup. D-12 and D-28 deploy that login pin. Of the M1 agents only Claude Code documents a key helper; Cursor's store is "Unverified" (15, on-disk table). D-27 also omits how tool helpers are installed: rewriting `~/.gitconfig` or `~/.aws/config` routes the human's own pushes through the broker and trips D-22.

**Amendment.** "Model credentials have one mode per agent instance, chosen by the D-12 compiler, which rejects conflicts: `vendor-login` (default, organisation pinned, broker not involved), `gateway` (base URL pinned to our proxy, provider key held there), `key-helper` (API-key billing, no forced login), `federated` (headless and CI). Tool helpers are bound per session through the launch environment or the agent's managed `env` block (`GIT_CONFIG_*`, `AWS_CONFIG_FILE`, `SSH_AUTH_SOCK`, `DOCKER_CONFIG`, `KUBECONFIG`). User dotfiles are never rewritten."

### F5. Major, wrong. D-26: three strengths presented as one

**Problem.** A phantom credential never leaves the device; the proxy substitutes the real value (35 section 3), so the cloud log still shows the human's credential. Beyond base-URL routes it needs TLS termination, which D-16 makes opt-in (35 Weak points). SDK user-agent ids are "caller-set and unsigned", untested in CloudTrail (17 V-10). Brief 17 recommended signed git notes "rather than trusting trailers"; a signed trailer cannot cover its own commit id and rewrites commit messages. Brokered hops in D-25 are left to timing windows.

**Amendment.** D-26 defines grades. `tag`: unsigned markers, for search only. `receipt`: a sensor-signed record in our audit log keyed by the external object id (commit SHA, request id), publishable to the forge as a check. `credential`: a distinct upstream principal or session name minted by the broker (STS source identity, GitHub App token, exchanged token with `act`); only this is claimed to separate agent from human in third-party logs. Phantom tokens have a `route` mode (no CA) and an opt-in `intercept` mode. For Docker, SSH and Kubernetes the launcher substitutes per-session endpoints so the hop carries the session id; timing is grade 0.

### F6. Major, missing. D-27: who attests, what the trust domain is, and that we issue tokens

**Problem.** "Attested sessions" is undefined. The helper's caller is a tool the agent spawned, so it means "anything in the session", including an injected child. In the single user-level daemon (D-20) broker and agent share a UID, so release control is a request, not a boundary (P1; 35 Weak points; 07 Avoid list). Section 3's "one constant organisation" forces an identifier change at enrolment, contradicting "rise without changing the identifier". RFC 8693 exchange means we issue tokens. The "assurance" field collides with AL0 to AL4.

**Added decision D-27a.** "Trust domain is the organisation, named by an opaque id independent of operator hostname; standalone generates a random one at install and enrolment adopts it. SVIDs come only from the server identity target or a device sub-CA constrained to its path; standalone ids stay `observed`. We run a token service with no users or directory, trusted only by our gateway, our broker and relying parties the customer federates. The broker verifies callers by kernel handle, executable identity and request scope. Helpers that reveal a credential return only minted short-lived ones. The broker is a boundary only when it runs as another OS principal. The field becomes `identity_proof`."

### F7. Major, missing. D-24: no stable identity for a bespoke agent

**Problem.** "A local fingerprint" does not say what is fingerprinted. A bespoke agent's hash changes on every build, its process is `python3`, and pods are ephemeral. Each rebuild re-enters triage; instances churn (07 Weak points, "Identity churn").

**Amendment.** "The unit of discovery is a program identity: signing identity, else package or image repository name, else source remote plus entrypoint, else executable path. Hash and version are attributes. In clusters the instance is the workload; pods are replicas. Triage decisions attach to the program identity; a changed signer or remote reopens triage."

### F8. Major, missing. P8 versus discovery collection

**Problem.** Exec-time environment (D-25) contains API keys. Pass 2 reads `site-packages`, `node_modules` and workspace files (17 Part 3, signal classes G and H). No scope is set, so the default sensor could upload secrets and a package inventory of home directories (34: works councils).

**Amendment.** "Environment capture is an allow-list of names from the catalogue; values are kept only for join keys and markers; credential variables are recorded as name and presence. Composition scans run only for a process already classed `llm-client`, cover only its resolved environment or image, and record package name and version. No home or repository crawl. `llm-client` findings stay on the device unless upload is enabled."

### F9. Major, risky. D-24 pass 1: catalogue dependency and burden

**Problem.** The base format is ten weeks old with one human committer, 24 releases, 6 stars and no forks (GitHub API, 2026-11-10; 17 V-3). Eight added routes make a fork; adopting it as our format contradicts P10. Install proof for about 60 agents on three systems includes paid and login-gated products. No owner, tier or rot measure exists.

**Amendment.** "The catalogue schema is ours; `ai-detection-spec` is an import dialect behind a pinned adapter. Tier A (the M1 four, growing per milestone): all routes, nightly install proof, core-team owned. Tier B: identifiers only, imported. Tier C: community, marked unproven. A process that matches a type by behaviour but no current identifier opens a content issue."

### F10. Major, over-built and missing. Section 7: identity and attribution per milestone

**Problem.** Attribution is in no milestone; identity lands whole in M3 though the identifier is in every event. D-27 puts eight standards in one line. Pass 4 names seven registries, two weak today (g09: on-device registry is Insider preview; 17: Agent 365 sync is manual), and omits Defender `AgentsInfo` (03 verifier).

**Amendment.** Add an identity row:

| Milestone | Identity and attribution |
|---|---|
| M0 | Freeze identifier grammar, program identity key, actor fields, grade table |
| M1 | `observed` ids; hook and exec-tag attribution; unsigned tags; credential inventory |
| M2 | OS user mapped to IdP principal; sponsor in triage; launcher containers; gateway mode; per-session SSH and git helpers; pass 4 from local sources and Defender |
| M3 | Token service, minted AWS and GitHub credentials, federation, `act` chains, CAEP, AuthZEN |
| M4 | ID-JAG, CIMD, transaction tokens; cloud registry correlation |

Lost: the cloud-registry shadow diff before M4.

## Spikes

| # | Question | Method | Pass |
|---|---|---|---|
| S1 | Does per-action attribution work inside shared hosts? | Interleave scripted human terminal commands and agent tool calls in VS Code with Copilot, Cursor and the Claude Code extension; record trees, tags, hook matches | Precision 99% with at most 5% `undetermined`, else that agent ships instance-level only |
| S2 | Does content-free loop detection separate agents from LLM clients? | g08 generator plus negatives, sensor limited to connect, exec and file events; two weeks on our own fleet | Precision 95% and the F3 triage budget |
| S3 | Do per-session helpers reach tool subprocesses without touching dotfiles? | For the M1 agents, inject the F4 variables; run git, AWS and SSH as agent and as human | Agent calls hit the broker, human calls do not, forced login still works |
| S4 | Which outward marks survive in third-party logs? | UA app id in CloudTrail; broker-assumed role with source identity; commit receipt through squash and rebase | The cloud or forge log alone separates all scripted actions; failures become `tag` |

## Agreed

- Two findings, `llm-client` and `agent`, with evidence attached (D-24).
- A "building blocks" catalogue as the route to bespoke agents (D-24).
- Declared-versus-observed gaps as detections (D-24).
- File-mediated execution is "influenced by", never "performed by" (D-25).
- No directory of our own; secrets stay in the customer's store (D-27).
- Authority as human rights intersected with an agent ceiling (D-27).
- Drafts behind version-tagged adapters; AuthZEN as decision interface (D-27).
