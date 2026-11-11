# Resolution of the architecture review

_2026-11-10. Applies to version 2 of `design/00-decisions.md`._

Draft 1 of the decision spine was reviewed by nine decision challengers (`c1` to `c9`) and twelve stakeholder reviewers (`l01` to `l12`). They returned 209 findings (32 blockers, 160 major, 17 minor; 103 missing decisions, 55 wrong, 37 risky, 14 over-built) and 84 proposed spikes. A second research round with working web search (`research/h01` to `h09`) ran in parallel.

**Rule for readers.** Every finding in the review files is accepted and reflected in version 2 unless it appears under "Modified" or "Not adopted" below. Where a review file proposes exact wording or a table (for example the thirty day-one detections in `c8`, the per-agent entry routes in `c3`, the screen list in `c7`, the milestone table in `c9`), the design document for that topic should use it, adjusted to the final decision numbers and names here.

## Where each theme landed

| Theme raised by reviewers | Final decision |
|---|---|
| Install without elevation; the daemon running as the adversary; first run before any change | D-48, D-20 |
| Hook drop-ins ignored under first-wins managed sources; other vendors' hooks; proof that a hook fired | D-49, D-14 |
| Vendor fail-closed flags are per handler; shim must decide alone | D-14, D-15 |
| Assurance ladder is not a total order | Section 3 (assurance record), P1 |
| "Unforgeable" approvals; who approves; widening through our own surfaces | D-31, D-07, section 3 (approval grade) |
| Labels racing decisions; models reaching block decisions through labels | P2, D-09 |
| Cedar expressiveness; ceilings; compile-down soundness; ambiguous parses | D-08, D-11, D-12, D-10 |
| A default install that enforces nothing | D-53 |
| Windows and macOS levels overstated; Sysmon, AMSI and DNS proxy against coexistence | D-17, D-18, D-23 |
| Sandboxes that do not compose; adopting running agents | D-21 |
| Sessions that are not process subtrees; attribution basis unusable in policy | D-25, D-06, section 3 (attribution grade) |
| Discovery without plaintext; privacy scope of scanning; program identity | D-24 |
| Credential helper conflicts; attestation and trust domain; outward identity | D-27, D-26 |
| Pseudonymity, data classes, per-person evaluation, transparency floor | D-51, P8 |
| Event volume contradiction; what is always uploaded | D-52 |
| Table format, hot tier, bus, endpoint-local store, search | D-34 |
| Erasure, legal hold, backup, restore | D-57 |
| Service tiers, objectives, offline behaviour | D-33, D-56 |
| Server upgrades, LTS, self-hosted contract | D-58 |
| Packaging, support matrix, diagnostics, VDI, reference clouds | D-59 |
| Proxies and TLS inspection on the uplink; device identity for containers, CI and clones | D-36 |
| Trust roots, skew, rollback, crash-loop floor, update authority | D-37 |
| Our own MCP server | D-38 |
| Roles and separation of duties | D-55 |
| Finding lifecycle, suppression, hunting, export contract | D-54 |
| Kill-switch and automation brakes | D-30 |
| Reputation service legal and poisoning model | D-32 |
| Tenancy vocabulary for MSPs, origination, usage ledger | Section 3, D-35, D-68 |
| Portability and exit | D-67 |
| Embedding order, host contract, fast path, stability classes | D-41, D-60 |
| Gateway hole | D-40 |
| Naming, foundation, revenue, licence review | D-66, D-03, D-04, D-02 |
| Governance, contribution policy, DCO mechanism | D-61 |
| Security response and audits | D-62 |
| Human capacity, risk tiers, trust core, hosted gate | D-63 |
| Test lab | D-64 |
| Support tiers and the definition of complete | D-50 |
| Positioning against bundled products | D-65 |
| Milestones, exit gates, lead times, budget, risks, spikes | Sections 7 to 9 |

## Modified

| Finding | What version 2 does instead | Why |
|---|---|---|
| `l10` F1: write design documents only for near-term decisions | Every area still gets a document, but each decision and each document section carries a horizon (Now, Next, Later), and Later work may constrain Now work only through a named seam | The owner asked for the whole product to be planned; the reviewer's concern about premature detail is met by the horizon rule |
| `l06` F1 (user-scope install as the default) against `l01` F1 (protected install as the default) | Both profiles exist. The first run changes nothing; then Protected is recommended and User is offered without elevation and labelled request-level (D-48) | A voluntary user must be able to start without elevation; a control that the agent can remove must not be called protection |
| `l03` F4 (always upload redacted commands and paths) against `l07` F2 (upload structure and derived facts only) | Default upload is metadata. Redacted arguments stay on the device and travel as evidence spans attached to findings or under a content grant. An organisation can raise the level, visibly (D-51, D-52) | Investigators get evidence where something was found; routine work is not centralised |
| `c7` F1, `c8` F2, `l06` F3: three different approval scales | One scale, G0 to G3, with a minimum per rule class; an agent's own prompt is G0 (D-31) | One vocabulary |
| `l03` F1: stable detection rules may write enforcing labels | Only deterministic session rules write enforcing labels; detections write findings, risk and advisory labels (D-09) | Keeps enforcement synchronous and replayable, as `c2` F2 requires |
| `c1` F1: commit to the DuckLake layout | First candidate, decided by spike S-02; Iceberg second (D-34) | The DataFusion implementation is alpha |
| `c6` F1: rename the project now | Identifiers are vendor-neutral and come from a brand manifest (D-66); the product name stays the owner's choice and the question is put to the owner | The owner named the product |
| `c6` spike on willingness to pay, with AGPL as the fallback | A go or no-go review of the server licence before first public release (D-02), owner question 6 | A business decision for the owner, not a spike for the team |
| `c9` milestone table | Adopted, with a thin slice added to M0 (`l10` F2), and the provider tier, browser extension and L4 connector at M4 | Order of evidence and dependencies |
| `l10` F5: vocabulary cuts | "Mode" replaces "posture"; "case" is removed (incidents sync with ticketing); terms are marked surface or not | `l03`'s case workflow is kept as incident workflow |
| `l10` F8: one channel for everything | One pack format, verifier and last-known-good store; four channels with their own rings (D-37). CEL and the search port are removed | Rings differ by risk; the format need not |
| `l10` F9 (two key modes) against `l01` F3 and `l07` F6 (organisation signature for widening) | Two key modes now. The narrow-only rule for operator-signed artefacts is in the pack format from the start; the organisation signature ships with hosted and provider deployments. Endpoint-sealed fields and third-party proof of policy integrity are Later behind reserved fields (D-31, D-35) | Simplicity now without closing the door |
| `l01` F10: two human maintainers review the trust core | The owner plus an external specialist audit, with the component cut if no reviewer is contracted (D-63) | There is one human today |
| LTS proposals from `l11`, `l02` and `c6` (12 months, 24 months, five years) | One LTS line a year with 24 months of public fixes; longer support periods are set with counsel before any paid offer (D-58, D-46) | The Cyber Resilience Act support period needs legal advice |
| `l05` F9: co-branding at M3 | With the provider tier at M4 | Depends on the provider tier |
| `l02` F6: compile policy to an incumbent EDR's prevention rules | Listed as a later compile target (D-12) | Needs a partner API and a spike |
| `l12` F5: the CLI name `grd` is taken | Working namespace `grdr`, final at M0 (section 3, D-66) | Registry check on 2026-11-10 |

## Not adopted

| Finding | Reason |
|---|---|
| `l10` F8: derive boundary or request from the assurance level | Superseded by the per-action-class assurance record from `c3` F1, which is more precise |
| `l10` F6: no separate process for any target before M4 | The hosted service runs the `distributed` profile from its first tenant so that the inline decision path is isolated (`l11` F1); self-hosters stay on `embedded` and `ha` |

## New documents

The completeness review (`l12`) found topics with no home. Three documents were added and one narrowed:

- `design/34` Documentation, support and lifecycle.
- `design/35` Product security programme.
- `design/36` Legal, brand and commercial.
- `design/30` now covers open-source governance and community only.

## What the second research round changed

- Foundation preference moved from AAIF to CNCF or OpenSSF (h05).
- Windows: Dev Drive detaches file filters outside the antivirus range; user-mode ETW can be forged; the common Rust ETW crate is unmaintained; WESP still shows no user-mode blocking path (h02).
- Linux: BPF LSM enforcement must survive loader death; Palo Alto now covers Linux and sells a targeted sensor beside other EDRs, so Linux is a lead, not an empty field (h02, h03).
- Sandboxes of three major coding agents were broken through design seams, so every sandbox back end needs a conformance suite (h01).
- Other vendors' hook installers overwrite existing hooks; a portable hook specification draft exists (h03).
- Gateways we planned to rely on had authorisation bypasses in 2026; our own decision check sits behind them and an evaluation error denies (h05).
- UK NCSC and Five Eyes guidance add concrete controls: isolation ladders, an emergency stop that cuts the inference route, outbound attribution (h06).
- Incidents: agents removing their own monitoring; infostealers with agent modules; shared stores used as covert channels (h07).
- Practitioners rank discovery first, abandon tools that dead-end them, and object to per-person telemetry (h08).
- Agent-team practice: risk-tiered human approval bound to commits, review capped at three rounds, edit hooks bypassed through the shell, power prompts unproven against a plain control (h09).
