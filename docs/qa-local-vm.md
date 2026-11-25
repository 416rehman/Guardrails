# Tier-B Local VMware and WSL2 E2E Harness

This guide documents the local Tier-B snapshot-revert QA harness (`deploy/qa/vm/vmware-e2e.ps1` and `deploy/qa/vm/wsl-e2e.ps1`) aligned with `docs/design/33-build-order-and-risks.md` (`D-23`, `D-48`, `D-50`, `D-64`, `S-04`, `S-05`), `docs/design/08-sensor-windows.md`, and `docs/design/24-deployment-and-packaging.md`.

## Scope and VM Safety Rules

- **Strict target allow-list:** `deploy/qa/vm/vmware-e2e.ps1` only operates on the four QA virtual machines under `F:\VMs\`:
  - `win11`: `F:\VMs\Win11\Windows 11 x64.vmx` (encrypted VM)
  - `ubuntu`: `F:\VMs\Ubuntu 24.04\Ubuntu 24.04.vmx`
  - `rocky`: `F:\VMs\Rocky 9.6\Rocky Linux 64-bit.vmx` (baseline snapshot `init`)
  - `edr`: `F:\VMs\EDR Ubuntu 24.04\EDR Ubuntu 24.04.vmx`
- Unrelated VMs outside `F:\VMs\` (such as `F:\loonext-rig\vm\`) are explicitly rejected by path validation and never touched.
- **Snapshot-revert discipline:** Every VMware run verifies the clean snapshot exists before booting, reverts to that snapshot before executing tests, and reverts back to the clean snapshot inside `finally` on both success and failure (unless `-KeepRunning` is explicitly passed on a passing run).
- **Fail fast on unsnapshotted VMs:** If a VM has `0` snapshots (for example, before its clean base snapshot is captured), preflight aborts before booting or mutating guest state.
- **Isolated homes:** Both WSL2 (`wsl-e2e.ps1`) and VMware guest runners (`linux-guest-e2e.sh`, `win-guest-e2e.ps1`) use temporary isolated `HOME` / `USERPROFILE` directories and clean them up in `finally` / `trap` handlers.

## Environment Variables (Credentials)

Never commit credentials to git or pass secrets on command lines that get logged. Set these variables in your shell session before running live VMware E2E tests:

| Variable | Required For | Purpose |
|---|---|---|
| `GRDR_QA_VM_PASSWORD` | `win11` (encrypted `.vmx`) | Passed internally via `vmrun -vp` only when non-empty |
| `GRDR_QA_GUEST_USER` | All live VMware targets | Guest OS account for `vmrun` file transfer and execution |
| `GRDR_QA_GUEST_PASS` | All live VMware targets | Guest OS password for `vmrun` guest operations |

## Clean Base Snapshot Setup

Inspect current snapshot readiness across all four VMs without modifying any guest:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/vmware-e2e.ps1 -Target all -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/vmware-e2e.ps1 -Target all -InitSnapshot
```

If a VM reports `0` snapshots, power it off cleanly inside VMware Workstation (with VMware Tools installed and clean OS state) and create the base `init` snapshot:

```powershell
& "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws snapshot "F:\VMs\Ubuntu 24.04\Ubuntu 24.04.vmx" init
& "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws snapshot "F:\VMs\EDR Ubuntu 24.04\EDR Ubuntu 24.04.vmx" init
```

For encrypted VMs (`Win11`), pass `-vp` interactively or from `$env:GRDR_QA_VM_PASSWORD`.

## Windows Defender `S-04` Coexistence Check

When targeting `win11`, `deploy/qa/vm/win-guest-e2e.ps1` validates `S-04` coexistence automatically:

1. Queries `Get-MpComputerStatus` (recording `RealTimeProtectionEnabled`) and snapshots baseline `Get-MpThreatDetection` entries before touching any Guardrails files.
2. Runs the Slice 0 lifecycle: `grdr-server` health -> isolated `.claude\settings.json` seed -> `grdr scan --json` -> `grdr install-hook --apply` + idempotent rerun -> `grdr-daemon` check-in -> `grdr-hook` allow and deterministic `Block` verdicts -> `grdr doctor --json` -> server session and `/api/v1/exports/audit.jsonl` verification -> `grdr uninstall-hook` byte-for-byte restoration.
3. Re-queries `Get-MpThreatDetection` after uninstall and fails if any new threat detections reference `grdr` or `guardrails`.

## Single-Command Invocations

### WSL2 (`Ubuntu-24.04` default)

```powershell
# Preflight dry-run (no WSL2 mutations)
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/wsl-e2e.ps1 -DryRun

# Full live Slice 0 E2E on local WSL2 Ubuntu-24.04
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/wsl-e2e.ps1

# Target a specific distro or reuse existing /tmp build
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/wsl-e2e.ps1 -Distro Ubuntu-24.04 -SkipBuild
```

The WSL2 runner builds Linux binaries using `cargo` inside WSL2 (or falls back to Docker `rust:1-bookworm` if `cargo` is absent in the distro), stages everything under `/tmp/grdr-wsl-e2e`, runs `linux-guest-e2e.sh`, verifies Windows-host `wsl.exe` bridge discovery when `grdr.exe` is present, cleans `/tmp/grdr-wsl-e2e*`, and writes `target/qa/wsl/report.json`.

### VMware Workstation

```powershell
# Dry-run preflight across all 4 QA VMs
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/vmware-e2e.ps1 -Target all -DryRun

# Run live snapshot-revert E2E against Rocky 9.6 (once GRDR_QA_GUEST_USER / GRDR_QA_GUEST_PASS are set)
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/vmware-e2e.ps1 -Target rocky

# Run live snapshot-revert E2E against Win11 (with GRDR_QA_VM_PASSWORD + guest credentials set)
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/qa/vm/vmware-e2e.ps1 -Target win11
```

## Artifacts

All QA output artifacts live under gitignored `target/qa/`:

- `target/qa/wsl/report.json`: WSL2 Slice 0 E2E assertion report and bridge check result.
- `target/qa/vmware/preflight.json`: VMware `-DryRun` / `-InitSnapshot` preflight summary.
- `target/qa/vmware/<target>-report.json`: Per-VM guest E2E assertion report (`win11`, `ubuntu`, `rocky`, `edr`).
