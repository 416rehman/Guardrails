# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

param(
    [ValidateSet("win11", "ubuntu", "rocky", "edr", "all")]
    [string]$Target = "all",

    [string]$Snapshot = "init",

    [switch]$InitSnapshot,

    [switch]$DryRun,

    [switch]$KeepRunning,

    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$AllowedVmRoot = "F:\VMs\"
$ReportDir = Join-Path $RepoRoot "target\qa\vmware"

$VmCatalog = [ordered]@{
    win11 = [ordered]@{
        key       = "win11"
        name      = "Win11"
        os        = "windows"
        vmx       = "F:\VMs\Win11\Windows 11 x64.vmx"
        encrypted = $true
    }
    ubuntu = [ordered]@{
        key       = "ubuntu"
        name      = "Ubuntu 24.04"
        os        = "linux"
        vmx       = "F:\VMs\Ubuntu 24.04\Ubuntu 24.04.vmx"
        encrypted = $false
    }
    rocky = [ordered]@{
        key       = "rocky"
        name      = "Rocky 9.6"
        os        = "linux"
        vmx       = "F:\VMs\Rocky 9.6\Rocky Linux 64-bit.vmx"
        encrypted = $false
    }
    edr = [ordered]@{
        key       = "edr"
        name      = "EDR Ubuntu 24.04"
        os        = "linux"
        vmx       = "F:\VMs\EDR Ubuntu 24.04\EDR Ubuntu 24.04.vmx"
        encrypted = $false
    }
}

function Resolve-VmrunExe {
    $candidates = @(
        "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
    )
    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }
    $cmd = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    throw "vmrun.exe not found. Install VMware Workstation or add vmrun.exe to PATH."
}

function Assert-AllowedVmxPath {
    param([string]$VmxPath)
    $full = [System.IO.Path]::GetFullPath($VmxPath)
    if (-not $full.StartsWith($AllowedVmRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Safety guard blocked VM outside ${AllowedVmRoot}: $full"
    }
    if (-not (Test-Path $full)) {
        throw "Target VMX file not found: $full"
    }
    return $full
}

function Invoke-Vmrun {
    param(
        [string]$VmrunExe,
        [string[]]$CmdArgs,
        [string]$VmPassword = "",
        [string]$GuestUser = "",
        [string]$GuestPass = "",
        [switch]$AllowFailure
    )
    $fullArgs = New-Object System.Collections.Generic.List[string]
    $fullArgs.Add("-T")
    $fullArgs.Add("ws")
    if (-not [string]::IsNullOrEmpty($VmPassword)) {
        $fullArgs.Add("-vp")
        $fullArgs.Add($VmPassword)
    }
    if (-not [string]::IsNullOrEmpty($GuestUser)) {
        $fullArgs.Add("-gu")
        $fullArgs.Add($GuestUser)
    }
    if (-not [string]::IsNullOrEmpty($GuestPass)) {
        $fullArgs.Add("-gp")
        $fullArgs.Add($GuestPass)
    }
    foreach ($a in $CmdArgs) {
        $fullArgs.Add($a)
    }

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $VmrunExe @fullArgs 2>&1
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if (-not $AllowFailure -and $rc -ne 0) {
        throw "vmrun $($CmdArgs[0]) failed (exit $rc): $text"
    }
    return [PSCustomObject]@{
        ExitCode = $rc
        Output   = $text
    }
}

function Get-RunningVmxSet {
    param([string]$VmrunExe)
    $res = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("list") -AllowFailure
    $running = @{}
    foreach ($line in ($res.Output -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '\.vmx$') {
            $running[$trimmed.ToLowerInvariant()] = $true
        }
    }
    return $running
}

function Get-VmPreflightState {
    param(
        [hashtable]$VmSpec,
        [string]$VmrunExe,
        [string]$RequestedSnapshot,
        [bool]$ExplicitSnapshot,
        [string]$VmPassword,
        [string]$GuestUser,
        [string]$GuestPass,
        [hashtable]$RunningSet
    )
    $vmx = Assert-AllowedVmxPath $VmSpec.vmx
    $isRunning = $RunningSet.ContainsKey($vmx.ToLowerInvariant())
    $passToUse = if ($VmSpec.encrypted) { $VmPassword } else { "" }

    $snapRes = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("listSnapshots", $vmx) -VmPassword $passToUse -AllowFailure
    $needsPassword = $false
    $snapshots = @()
    $totalSnapshots = 0

    if ($snapRes.ExitCode -ne 0) {
        if ($snapRes.Output -match "password is required|Invalid password") {
            $needsPassword = $true
        } else {
            return [PSCustomObject]@{
                key               = $VmSpec.key
                name              = $VmSpec.name
                os                = $VmSpec.os
                vmx               = $vmx
                running           = $isRunning
                ready             = $false
                status            = "vmrun_error"
                resolved_snapshot = $null
                snapshots         = @()
                has_guest_creds   = (-not [string]::IsNullOrEmpty($GuestUser) -and -not [string]::IsNullOrEmpty($GuestPass))
                detail            = $snapRes.Output.Trim()
                operator_action   = "Inspect VMware Workstation state for $vmx"
            }
        }
    } else {
        $lines = @($snapRes.Output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        foreach ($line in $lines) {
            if ($line -match '^Total snapshots:\s*(\d+)$') {
                $totalSnapshots = [int]$matches[1]
            } else {
                $snapshots += $line
            }
        }
    }

    $hasGuestCreds = (-not [string]::IsNullOrEmpty($GuestUser) -and -not [string]::IsNullOrEmpty($GuestPass))
    $resolvedSnap = $null
    if (-not $needsPassword) {
        if ($snapshots -contains $RequestedSnapshot) {
            $resolvedSnap = $RequestedSnapshot
        } elseif (-not $ExplicitSnapshot -and ($snapshots -contains "clean-qa")) {
            $resolvedSnap = "clean-qa"
        }
    }

    $status = "ready"
    $detail = "clean snapshot '$resolvedSnap' present"
    $action = "none"

    if ($needsPassword) {
        $status = "needs_vm_password"
        $detail = "VM is VMware-encrypted; GRDR_QA_VM_PASSWORD is required"
        $action = "Set `$env:GRDR_QA_VM_PASSWORD (and GRDR_QA_GUEST_USER / GRDR_QA_GUEST_PASS)"
    } elseif ($totalSnapshots -eq 0) {
        $status = "needs_clean_snapshot"
        $detail = "VM has 0 snapshots; refusing to mutate an unsnapshotted VM"
        $action = "Power off '$($VmSpec.name)' cleanly and run: `"$VmrunExe`" -T ws snapshot `"$vmx`" $RequestedSnapshot"
    } elseif ([string]::IsNullOrEmpty($resolvedSnap)) {
        $status = "missing_snapshot"
        $detail = "Snapshot '$RequestedSnapshot' not found (available: $($snapshots -join ', '))"
        $action = "Pass -Snapshot <name> or create '$RequestedSnapshot' from a clean powered-off state"
    } elseif (-not $hasGuestCreds) {
        $status = "needs_guest_credentials"
        $detail = "Snapshot '$resolvedSnap' verified, but GRDR_QA_GUEST_USER / GRDR_QA_GUEST_PASS are unset"
        $action = "Set `$env:GRDR_QA_GUEST_USER and `$env:GRDR_QA_GUEST_PASS before running live E2E"
    }

    return [PSCustomObject]@{
        key               = $VmSpec.key
        name              = $VmSpec.name
        os                = $VmSpec.os
        vmx               = $vmx
        running           = $isRunning
        ready             = ($status -eq "ready")
        status            = $status
        resolved_snapshot = $resolvedSnap
        snapshots         = $snapshots
        has_guest_creds   = $hasGuestCreds
        detail            = $detail
        operator_action   = $action
    }
}

function Build-TargetArtifacts {
    param(
        [bool]$NeedWindows,
        [bool]$NeedLinux
    )
    $out = @{
        windows_bin_dir = $null
        linux_bin_dir   = $null
    }
    if ($NeedWindows) {
        $winBin = Join-Path $RepoRoot "target\debug"
        if (-not $SkipBuild) {
            Write-Output "Building Windows binaries..."
            & cargo build --locked --manifest-path (Join-Path $RepoRoot "Cargo.toml") -p grdr -p grdr-daemon -p grdr-hook -p grdr-server
            if ($LASTEXITCODE -ne 0) {
                throw "Windows cargo build failed (exit $LASTEXITCODE)."
            }
        }
        foreach ($b in @("grdr.exe", "grdr-daemon.exe", "grdr-hook.exe", "grdr-server.exe")) {
            if (-not (Test-Path (Join-Path $winBin $b))) {
                throw "Missing Windows binary: $(Join-Path $winBin $b)"
            }
        }
        $out.windows_bin_dir = $winBin
    }

    if ($NeedLinux) {
        $linuxBin = Join-Path $ReportDir "linux-bin"
        New-Item -ItemType Directory -Path $linuxBin -Force | Out-Null
        if (-not $SkipBuild) {
            $wslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
            $dockerCmd = Get-Command docker.exe -ErrorAction SilentlyContinue
            $built = $false
            if ($wslCmd) {
                $winPath = [System.IO.Path]::GetFullPath($RepoRoot)
                $wslRepo = if ($winPath -match '^([A-Za-z]):[\\/](.*)$') { "/mnt/$($matches[1].ToLowerInvariant())/$($matches[2] -replace '\\','/')" } else { "" }
                $wslOut = if ($linuxBin -match '^([A-Za-z]):[\\/](.*)$') { "/mnt/$($matches[1].ToLowerInvariant())/$($matches[2] -replace '\\','/')" } else { "" }
                $hasCargo = (& wsl.exe -d Ubuntu-24.04 -- bash -c 'export PATH="$HOME/.cargo/bin:$PATH"; command -v cargo >/dev/null && echo yes || echo no' 2>$null) -join ""
                if ($hasCargo -match "yes") {
                    Write-Output "Building Linux binaries via WSL2..."
                    $script = "set -euo pipefail; export PATH=`"`$HOME/.cargo/bin:`$PATH`"; cargo build --locked --manifest-path `"$wslRepo/Cargo.toml`" --target-dir /tmp/grdr-wsl-cargo-target -p grdr -p grdr-daemon -p grdr-hook -p grdr-server; cp /tmp/grdr-wsl-cargo-target/debug/grdr /tmp/grdr-wsl-cargo-target/debug/grdr-daemon /tmp/grdr-wsl-cargo-target/debug/grdr-hook /tmp/grdr-wsl-cargo-target/debug/grdr-server `"$wslOut/`""
                    & wsl.exe -d Ubuntu-24.04 -- bash -c $script
                    if ($LASTEXITCODE -ne 0) { throw "WSL2 Linux build failed." }
                    $built = $true
                }
            }
            if (-not $built -and $dockerCmd) {
                Write-Output "Building Linux binaries via Docker..."
                & docker run --rm -v "${RepoRoot}:/src:ro" -v "grdr-vmware-linux-target:/target" -v "${linuxBin}:/out" -w /src rust:1-bookworm bash -c "cargo build --locked --target-dir /target -p grdr -p grdr-daemon -p grdr-hook -p grdr-server && cp /target/debug/grdr /target/debug/grdr-daemon /target/debug/grdr-hook /target/debug/grdr-server /out/"
                if ($LASTEXITCODE -ne 0) { throw "Docker Linux build failed." }
                $built = $true
            }
            if (-not $built) {
                throw "Need WSL2 cargo or Docker on host to build Linux binaries for VMware guests."
            }
        }
        foreach ($b in @("grdr", "grdr-daemon", "grdr-hook", "grdr-server")) {
            if (-not (Test-Path (Join-Path $linuxBin $b))) {
                throw "Missing Linux binary: $(Join-Path $linuxBin $b)"
            }
        }
        $out.linux_bin_dir = $linuxBin
    }
    return $out
}

function Wait-VmwareTools {
    param(
        [string]$VmrunExe,
        [string]$Vmx,
        [string]$VmPassword
    )
    for ($i = 0; $i -lt 60; $i++) {
        $res = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("checkToolsState", $Vmx) -VmPassword $VmPassword -AllowFailure
        if ($res.ExitCode -eq 0 -and $res.Output -match "running|installed") {
            return
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out waiting for VMware Tools readiness on $Vmx"
}

function Invoke-VmwareTargetE2E {
    param(
        [PSCustomObject]$Preflight,
        [string]$VmrunExe,
        [string]$VmPassword,
        [string]$GuestUser,
        [string]$GuestPass,
        [hashtable]$Artifacts,
        [switch]$SkipTeardownRevert
    )
    $vmx = $Preflight.vmx
    $snap = $Preflight.resolved_snapshot
    $passToUse = if ($Preflight.key -eq "win11") { $VmPassword } else { "" }
    $guestReportHost = Join-Path $ReportDir "$($Preflight.key)-report.json"
    $succeeded = $false

    try {
        Write-Output "[$($Preflight.name)] Reverting to clean snapshot '$snap'..."
        $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("revertToSnapshot", $vmx, $snap) -VmPassword $passToUse

        Write-Output "[$($Preflight.name)] Booting VM headless (nogui)..."
        $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("start", $vmx, "nogui") -VmPassword $passToUse
        Wait-VmwareTools -VmrunExe $VmrunExe -Vmx $vmx -VmPassword $passToUse

        if ($Preflight.os -eq "windows") {
            $guestDir = "C:\Windows\Temp\grdr-qa"
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("createDirectoryInGuest", $vmx, $guestDir) -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass -AllowFailure
            foreach ($b in @("grdr.exe", "grdr-daemon.exe", "grdr-hook.exe", "grdr-server.exe")) {
                $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("CopyFileFromHostToGuest", $vmx, (Join-Path $Artifacts.windows_bin_dir $b), "$guestDir\$b") -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
            }
            $winScript = Join-Path $PSScriptRoot "win-guest-e2e.ps1"
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("CopyFileFromHostToGuest", $vmx, $winScript, "$guestDir\win-guest-e2e.ps1") -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
            $guestReport = "$guestDir\report.json"
            $psArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$guestDir\win-guest-e2e.ps1`" -BinDir `"$guestDir`" -ReportPath `"$guestReport`""
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("runProgramInGuest", $vmx, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", $psArgs) -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("CopyFileFromGuestToHost", $vmx, $guestReport, $guestReportHost) -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
        } else {
            $guestDir = "/tmp/grdr-vmware-qa"
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("createDirectoryInGuest", $vmx, $guestDir) -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass -AllowFailure
            foreach ($b in @("grdr", "grdr-daemon", "grdr-hook", "grdr-server")) {
                $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("CopyFileFromHostToGuest", $vmx, (Join-Path $Artifacts.linux_bin_dir $b), "$guestDir/$b") -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
            }
            $lfTemp = Join-Path $ReportDir "linux-guest-e2e.lf.sh"
            ((Get-Content -Raw (Join-Path $PSScriptRoot "linux-guest-e2e.sh")) -replace "`r`n", "`n") | Set-Content -Path $lfTemp -Encoding ASCII -NoNewline
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("CopyFileFromHostToGuest", $vmx, $lfTemp, "$guestDir/linux-guest-e2e.sh") -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
            $guestReport = "/tmp/grdr-vmware-report.json"
            $guestCmd = "chmod +x $guestDir/grdr $guestDir/grdr-daemon $guestDir/grdr-hook $guestDir/grdr-server $guestDir/linux-guest-e2e.sh && $guestDir/linux-guest-e2e.sh --bin-dir $guestDir --work-dir /tmp/grdr-vmware-work --report $guestReport --mode vmware"
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("runProgramInGuest", $vmx, "/bin/bash", "-lc", $guestCmd) -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("CopyFileFromGuestToHost", $vmx, $guestReport, $guestReportHost) -VmPassword $passToUse -GuestUser $GuestUser -GuestPass $GuestPass
        }

        $reportObj = (Get-Content -Raw $guestReportHost) | ConvertFrom-Json
        if ($reportObj.status -ne "passed") {
            throw "Guest E2E failed on '$($Preflight.name)': see $guestReportHost"
        }
        $succeeded = $true
        Write-Output "[$($Preflight.name)] Passed. Report saved to $guestReportHost"
    }
    finally {
        if ($SkipTeardownRevert -and $succeeded) {
            Write-Warning "[$($Preflight.name)] -KeepRunning requested; skipping teardown snapshot revert."
        } else {
            Write-Output "[$($Preflight.name)] Reverting to clean snapshot '$snap' on teardown..."
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("revertToSnapshot", $vmx, $snap) -VmPassword $passToUse -AllowFailure
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("stop", $vmx, "hard") -VmPassword $passToUse -AllowFailure
        }
    }
}

$vmrunExe = Resolve-VmrunExe
$vmPassword = if ($env:GRDR_QA_VM_PASSWORD) { $env:GRDR_QA_VM_PASSWORD } else { "" }
$guestUser = if ($env:GRDR_QA_GUEST_USER) { $env:GRDR_QA_GUEST_USER } else { "" }
$guestPass = if ($env:GRDR_QA_GUEST_PASS) { $env:GRDR_QA_GUEST_PASS } else { "" }
$explicitSnap = $PSBoundParameters.ContainsKey("Snapshot")

$selectedKeys = if ($Target -eq "all") { @("win11", "ubuntu", "rocky", "edr") } else { @($Target) }
$runningSet = Get-RunningVmxSet -VmrunExe $vmrunExe

$preflights = @()
foreach ($k in $selectedKeys) {
    $preflights += Get-VmPreflightState `
        -VmSpec $VmCatalog[$k] `
        -VmrunExe $vmrunExe `
        -RequestedSnapshot $Snapshot `
        -ExplicitSnapshot $explicitSnap `
        -VmPassword $vmPassword `
        -GuestUser $guestUser `
        -GuestPass $guestPass `
        -RunningSet $runningSet
}

New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

if ($InitSnapshot -or $DryRun) {
    $modeName = if ($InitSnapshot) { "init_snapshot_check" } else { "dry_run" }
    $preflightPath = Join-Path $ReportDir "preflight.json"
    [ordered]@{
        schema_version = 1
        mode           = $modeName
        target         = $Target
        snapshot       = $Snapshot
        targets        = $preflights
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $preflightPath -Encoding UTF8

    foreach ($p in $preflights) {
        $snapList = if ($p.snapshots.Count -gt 0) { $p.snapshots -join ", " } else { "none (0)" }
        Write-Output "[$($p.key)] $($p.name) ($($p.os)) | status=$($p.status) | running=$($p.running) | snapshots=[$snapList] | $($p.detail)"
        if ($p.operator_action -ne "none") {
            Write-Output "  -> Action: $($p.operator_action)"
        }
    }
    Write-Output "Preflight report written to $preflightPath (no VMs mutated)."
    if ($InitSnapshot) {
        $missing = @($preflights | Where-Object { [string]::IsNullOrEmpty($_.resolved_snapshot) })
        if ($missing.Count -gt 0) {
            exit 1
        }
    }
    exit 0
}

$notReady = @($preflights | Where-Object { -not $_.ready })
if ($notReady.Count -gt 0) {
    foreach ($p in $notReady) {
        Write-Error "[$($p.name)] $($p.detail). Action: $($p.operator_action)"
    }
    exit 1
}

$needWin = (@($preflights | Where-Object { $_.os -eq "windows" })).Count -gt 0
$needLinux = (@($preflights | Where-Object { $_.os -eq "linux" })).Count -gt 0
$artifacts = Build-TargetArtifacts -NeedWindows $needWin -NeedLinux $needLinux

foreach ($p in $preflights) {
    Invoke-VmwareTargetE2E `
        -Preflight $p `
        -VmrunExe $vmrunExe `
        -VmPassword $vmPassword `
        -GuestUser $guestUser `
        -GuestPass $guestPass `
        -Artifacts $artifacts `
        -SkipTeardownRevert:$KeepRunning
}
