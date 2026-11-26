# Guardrails ADR Open-Source Covenant

This covenant binds Loonaro ("the Steward") with respect to Guardrails ADR (`grdr`)
under D-03 and `docs/design/30-open-source-governance-and-community.md` (section 13).
Amendments to this covenant may only strengthen its commitments; no governance body may weaken
or revoke any obligation below.

## 1. Perpetual OSI-Approved Licensing

All Guardrails ADR project code, detection content, and documentation remain under OSI-approved
open-source licences in perpetuity:
- Core code, server, SDKs, CLI, desktop, web console, and first-party content packs: `Apache-2.0`.
- Linux kernel eBPF programs under `bpf/`: `GPL-2.0-only OR BSD-2-Clause`.
- Documentation prose under `docs/`: `Apache-2.0 OR CC-BY-4.0`.

## 2. Reproducible Public Binaries With Zero Thresholds

All official project binaries and container images are built strictly from public source by the
public CI pipeline, released under the source licence with reproducible build attestation and
provenance, and carry zero seat, usage, endpoint, or revenue limits.

## 3. Covenant Assets

The following assets are dedicated to Guardrails ADR and transfer cleanly upon trigger:
1. Trademarks and logos: "Guardrails ADR" marks and conformance marks (`docs/governance/TRADEMARKS.md`).
2. Project domain: `guardrailshq.com` and its project subdomains (enrolment, updates, docs, status).
3. Project repositories: `416rehman/Guardrails`, `416rehman/Guardrails-packs`, `416rehman/Guardrails-contrib`.
4. Project TUF root, timestamp, snapshot, targets, binaries, content, and rollout signing authority.
5. Default update and threat-intelligence relay endpoints configured in distribution packages.
6. Conformance mark registry and published conformance test kits.
7. Held-out adversarial and regression test corpora.

See `docs/governance/assets.toml` for the authoritative machine-readable asset inventory.

## 4. Custody of Project Trust Roots

No natural person holds a project TUF root key alone. Release and content signing authority
operates with threshold signing across isolated GitHub Actions environments (release signer and
independent rebuilder), allowing an unaffiliated organisation to operate the independent rebuilder.
Upon foundation transfer, TUF root authority rotates via recorded threshold ceremonies signed by
both prior and foundation-held keys.

## 5. Signing Continuity Commitment

While Loonaro holds vendor platform signing identities (Windows open-source signing programme
access and, if enrolled, an Apple Developer Team ID), Loonaro commits to continue signing official
project releases produced by the public reproducible pipeline for as long as it holds them.

## 6. Foundation Transfer Trigger

The Steward will initiate transfer of all covenant assets to the chosen neutral foundation
(shortlist order: CNCF, OpenSSF, or conditional AAIF) upon the **earlier** of:
- **(a) Ecosystem independence:** 2 or more Unaffiliated Production Adopters AND 1 or more External
  Committing Organisations; OR
- **(b) Time ceiling:** 18 months after the first tagged public release.

### Definitions
- **Unaffiliated Production Adopter:** An organisation with no ownership, employment, contract, or
  funding affiliation with Loonaro that runs Guardrails ADR in production on at least 25 endpoints
  or at least 1 multi-endpoint server installation for at least 90 consecutive days and confirms
  its status in `docs/governance/ADOPTERS.md`.
- **External Committing Organisation:** An organisation with no affiliation (as above) whose
  contributors authored at least 10 merged pull requests across Guardrails ADR repositories over
  the trailing 6 months, at least 3 of which modified source code.

## 7. Springing Assignment & Fallback

A springing assignment covering the marks, project domain, and repository ownership is held in
escrow for execution when Trigger 6(a) or 6(b) fires (`docs/legal/counsel-register.yaml` L-06).
If no neutral foundation accepts the project when triggered, ownership transfers to an independent
steward foundation or public benefit entity formed by the unaffiliated maintainers, governed by the
same one-organisation voting caps and OSI licence lock.

## 8. Bad-Faith Commitments (Never Actions)

The Steward commits NEVER to:
1. Relicense any released component away from OSI-approved licences (any pre-release server-licence
   review closes before the first tagged public release and is never reopened afterward), or require
   a CLA or copyright assignment.
2. Create an `ee/` directory, "community edition", or withhold SSO, SCIM, roles, audit, CMK,
   provider tier, or full console features behind payment (`P11`).
3. Ship binaries under proprietary terms or gate software behaviour by seat/revenue/endpoint caps.
4. Keep source private behind binaries or deploy private hosted-only product runtime code.
5. Withhold or delay security fixes for supported lines, or sell early vulnerability pre-disclosure.
6. Enable telemetry, usage pings, or crash reports by default (default anonymous mirrorable update
   metadata fetch excluded and explicitly controllable).
7. Restrict forks using distinct names or truthful "built from Guardrails ADR" statements.
8. Deprioritise community pull requests that compete with hosted or commercial services.
9. Exceed steward steering caps, grant an AI agent a steering vote, or merge unreviewed changes.
10. Keep a private roadmap outside embargoed security response.
11. Archive project repositories or abandon supported release lines without completing transfer.
12. Manufacture synthetic adopters, stars, or contributor vouches.

## 9. Succession

The named second human maintainer in `docs/governance/MAINTAINERS.md` holds succession
administrative authority over repository settings and covenant assets if the primary owner is
unavailable until a permanent successor or foundation custodian takes custody.
