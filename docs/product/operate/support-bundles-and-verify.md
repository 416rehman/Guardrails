---
id: support-bundles-and-verify
type: how-to
personas:
  - operator
  - responder
shapes:
  - self-hosted
  - airgap
covers:
  - doctor
  - support-bundle
  - airgap
owner_squad: support
stability: beta
title: Diagnostics, Support Bundles, and Offline Verification
---

# Diagnostics, Support Bundles, and Offline Verification

## Endpoint Diagnostics (`grdr doctor`)

Run non-destructive health and connectivity checks on an endpoint:

```powershell
cargo run -p grdr -- doctor
```

Each diagnostic check prints structured `GRDR-<AREA>-<NNNN>` remediation hints pointing to relevant sections in this documentation bundle.

## Redacted Support Bundles

Collect redacted logs, configuration summaries, and state watermarks for troubleshooting without exposing prompt payloads or local credentials:

```powershell
cargo run -p grdr -- support-bundle
```

Always inspect the preview archive before sharing diagnostics outside your trust boundary.

## Air-Gapped Deployments (`grdr airgap`)

Air-gapped environments pack signed policy packs, CLI/daemon binaries, and offline documentation HTML from `website/build/` so operators and endpoints retain local docs search (Pagefind) without external network access.

After every rollout or cell drill, record completion against [Fleet Verification Checklist](../../runbooks/FLEET-VERIFY.md).
