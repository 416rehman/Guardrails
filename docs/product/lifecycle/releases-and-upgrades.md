---
id: releases-and-upgrades
type: reference
personas:
  - operator
  - auditor
shapes:
  - self-hosted
  - hosted
  - airgap
covers:
  - lifecycle
  - upgrade-path
  - deprecations
owner_squad: release
stability: beta
title: Releases, Support Windows, and Upgrades
---

# Releases, Support Windows, and Upgrades

Release cadence, upgrade hops, deprecations, and platform support tiers are defined machine-readably in:

- `contracts/support.toml` (supported OSes, architectures, databases, Kubernetes `1.35..1.37`, sensor skew `+1` / `-2`)
- `lifecycle.toml` (release lines, cadence, deprecation notice windows)
- `contracts/upgrade-path.json` (SemVer series hop and rollback policy matrix)
- `upgrade-path.json` (lifecycle command, preflight/migrate invocations, and runbook bindings)
- `docs/lifecycle/deprecations.toml` and `docs/lifecycle/known-issues.toml`

## Upgrade Constraints

- Monthly release cadence supporting up to `2` minor versions behind on active lines.
- Maximum direct upgrade jump: `2` minor versions (`max_upgrade_minor_hop = 2`).
- Rollback window: `1` minor version (`rollback_window_minors = 1`).
- Sensor skew tolerance: endpoints may lag up to `2` minor versions behind `grdr-server` or lead by `1` minor version.
- Breaking removals follow a minimum notice floor of `2` releases and `180` days once a surface enters stable GA compatibility.

## Pre-Release Surface Cleanup

Pre-release prototype REST JSON endpoints and loopback daemon HTTP ports were removed prior to `v0.1.0` in favor of typed Connect/Protobuf services and OS peer-authenticated IPC (`docs/lifecycle/deprecations.toml`).
