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

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
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
        [switch]$AllowFailure
    )
    $fullArgs = New-Object System.Collections.Generic.List[string]
    $fullArgs.Add("-T")
    $fullArgs.Add("ws")
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

function Resolve-GuestSshSpec {
    param([string]$VmKey)
    $hostEnvName = "GRDR_QA_SSH_HOST_$($VmKey.ToUpperInvariant())"
    $sshHost = [Environment]::GetEnvironmentVariable($hostEnvName)
    if ([string]::IsNullOrWhiteSpace($sshHost)) {
        $sshHost = $env:GRDR_QA_SSH_HOST
    }
    $sshUser = if ($env:GRDR_QA_SSH_USER) { $env:GRDR_QA_SSH_USER } else { "grdrqa" }
    $sshKey = if ($env:GRDR_QA_SSH_KEY) { $env:GRDR_QA_SSH_KEY } else { "" }
    return [PSCustomObject]@{
        configured = (-not [string]::IsNullOrWhiteSpace($sshHost))
        user       = $sshUser
        host       = $sshHost
        key        = $sshKey
    }
}

function Invoke-GuestSsh {
    param(
        [PSCustomObject]$SshSpec,
        [string]$Command
    )
    $sshArgs = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new")
    if (-not [string]::IsNullOrWhiteSpace($SshSpec.key)) {
        $sshArgs += @("-i", $SshSpec.key)
    }
    $sshArgs += @("$($SshSpec.user)@$($SshSpec.host)", $Command)
    & ssh @sshArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ssh guest command failed (exit $LASTEXITCODE)"
    }
}

function Copy-ToGuestScp {
    param(
        [PSCustomObject]$SshSpec,
        [string]$LocalPath,
        [string]$RemotePath
    )
    $scpArgs = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new")
    if (-not [string]::IsNullOrWhiteSpace($SshSpec.key)) {
        $scpArgs += @("-i", $SshSpec.key)
    }
    $scpArgs += @($LocalPath, "$($SshSpec.user)@$($SshSpec.host):$RemotePath")
    & scp @scpArgs
    if ($LASTEXITCODE -ne 0) {
        throw "scp upload failed for $LocalPath (exit $LASTEXITCODE)"
    }
}

function Copy-FromGuestScp {
    param(
        [PSCustomObject]$SshSpec,
        [string]$RemotePath,
        [string]$LocalPath
    )
    $scpArgs = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new")
    if (-not [string]::IsNullOrWhiteSpace($SshSpec.key)) {
        $scpArgs += @("-i", $SshSpec.key)
    }
    $scpArgs += @("$($SshSpec.user)@$($SshSpec.host):$RemotePath", $LocalPath)
    & scp @scpArgs
    if ($LASTEXITCODE -ne 0) {
        throw "scp download failed for $RemotePath (exit $LASTEXITCODE)"
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
        [hashtable]$RunningSet
    )
    $vmx = Assert-AllowedVmxPath $VmSpec.vmx
    $isRunning = $RunningSet.ContainsKey($vmx.ToLowerInvariant())
    $sshSpec = Resolve-GuestSshSpec -VmKey $VmSpec.key

    $snapRes = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("listSnapshots", $vmx) -AllowFailure
    $needsUnlock = $false
    $snapshots = @()
    $totalSnapshots = 0

    if ($snapRes.ExitCode -ne 0) {
        if ($snapRes.Output -match "password is required|Invalid password") {
            $needsUnlock = $true
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
                has_guest_ssh     = $sshSpec.configured
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

    $resolvedSnap = $null
    if (-not $needsUnlock) {
        if ($snapshots -contains $RequestedSnapshot) {
            $resolvedSnap = $RequestedSnapshot
        } elseif (-not $ExplicitSnapshot -and ($snapshots -contains "clean-qa")) {
            $resolvedSnap = "clean-qa"
        }
    }

    $status = "ready"
    $detail = "clean snapshot '$resolvedSnap' present"
    $action = "none"

    if ($needsUnlock) {
        $status = "needs_vm_unlock"
        $detail = "VM is VMware-encrypted; unlock it in Workstation or use an unencrypted QA clone (CLI password arguments are prohibited)"
        $action = "Unlock '$($VmSpec.name)' interactively in VMware Workstation or decrypt the QA clone"
    } elseif ($totalSnapshots -eq 0) {
        $status = "needs_clean_snapshot"
        $detail = "VM has 0 snapshots; refusing to mutate an unsnapshotted VM"
        $action = "Power off '$($VmSpec.name)' cleanly and run: `"$VmrunExe`" -T ws snapshot `"$vmx`" $RequestedSnapshot"
    } elseif ([string]::IsNullOrEmpty($resolvedSnap)) {
        $status = "missing_snapshot"
        $detail = "Snapshot '$RequestedSnapshot' not found (available: $($snapshots -join ', '))"
        $action = "Pass -Snapshot <name> or create '$RequestedSnapshot' from a clean powered-off state"
    } elseif (-not $sshSpec.configured) {
        $status = "needs_guest_ssh"
        $detail = "Snapshot '$resolvedSnap' verified, but key-based SSH host env is unset"
        $action = "Set GRDR_QA_SSH_HOST_$($VmSpec.key.ToUpperInvariant()) (and GRDR_QA_SSH_USER / GRDR_QA_SSH_KEY) before live E2E"
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
        has_guest_ssh     = $sshSpec.configured
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
                    $script = "set -euo pipefail; umask 077; export PATH=`"`$HOME/.cargo/bin:`$PATH`"; SAFE_QA=`"`$HOME/.local/state/grdr-qa`"; if [ -L `"`$SAFE_QA`" ]; then echo 'Refusing symlinked QA directory' >&2; exit 1; fi; mkdir -p -m 0700 `"`$SAFE_QA`"; WSL_TARGET=`"`$SAFE_QA/cargo-target`"; cargo build --locked --manifest-path `"$wslRepo/Cargo.toml`" --target-dir `"`$WSL_TARGET`" -p grdr -p grdr-daemon -p grdr-hook -p grdr-server; cp `"`$WSL_TARGET/debug/grdr`" `"`$WSL_TARGET/debug/grdr-daemon`" `"`$WSL_TARGET/debug/grdr-hook`" `"`$WSL_TARGET/debug/grdr-server`" `"$wslOut/`""
                    & wsl.exe -d Ubuntu-24.04 -- bash -c $script
                    if ($LASTEXITCODE -ne 0) { throw "WSL2 Linux build failed." }
                    $built = $true
                }
            }
            if (-not $built -and $dockerCmd) {
                Write-Output "Building Linux binaries via Docker..."
                & docker run --rm -v "${RepoRoot}:/src:ro" -v "grdr-vmware-linux-target:/target" -v "${linuxBin}:/out" -w /src rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c bash -c "cargo build --locked --target-dir /target -p grdr -p grdr-daemon -p grdr-hook -p grdr-server && cp /target/debug/grdr /target/debug/grdr-daemon /target/debug/grdr-hook /target/debug/grdr-server /out/"
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
        [string]$Vmx
    )
    for ($i = 0; $i -lt 60; $i++) {
        $res = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("checkToolsState", $Vmx) -AllowFailure
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
        [hashtable]$Artifacts,
        [switch]$SkipTeardownRevert
    )
    $vmx = $Preflight.vmx
    $snap = $Preflight.resolved_snapshot
    $sshSpec = Resolve-GuestSshSpec -VmKey $Preflight.key
    $guestReportHost = Join-Path $ReportDir "$($Preflight.key)-report.json"
    $succeeded = $false

    try {
        Write-Output "[$($Preflight.name)] Reverting to clean snapshot '$snap'..."
        $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("revertToSnapshot", $vmx, $snap)

        Write-Output "[$($Preflight.name)] Booting VM headless (nogui)..."
        $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("start", $vmx, "nogui")
        Wait-VmwareTools -VmrunExe $VmrunExe -Vmx $vmx

        if ($Preflight.os -eq "windows") {
            $guestDir = "grdr-vmware-qa"
            $prepCmd = "powershell -NoProfile -Command `"`$d = Join-Path `$env:USERPROFILE 'grdr-vmware-qa'; if ((Test-Path `$d) -and ((Get-Item `$d -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing symlinked QA directory' }; Remove-Item -Recurse -Force -ErrorAction SilentlyContinue `$d; New-Item -ItemType Directory -Path `$d -Force | Out-Null`""
            Invoke-GuestSsh -SshSpec $sshSpec -Command $prepCmd
            foreach ($b in @("grdr.exe", "grdr-daemon.exe", "grdr-hook.exe", "grdr-server.exe")) {
                Copy-ToGuestScp -SshSpec $sshSpec -LocalPath (Join-Path $Artifacts.windows_bin_dir $b) -RemotePath "$guestDir/$b"
            }
            $winScript = Join-Path $PSScriptRoot "win-guest-e2e.ps1"
            Copy-ToGuestScp -SshSpec $sshSpec -LocalPath $winScript -RemotePath "$guestDir/win-guest-e2e.ps1"
            $guestReport = "$guestDir/report.json"
            $runCmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"`$d = Join-Path `$env:USERPROFILE 'grdr-vmware-qa'; & (Join-Path `$d 'win-guest-e2e.ps1') -BinDir `$d -ReportPath (Join-Path `$d 'report.json')`""
            Invoke-GuestSsh -SshSpec $sshSpec -Command $runCmd
            Copy-FromGuestScp -SshSpec $sshSpec -RemotePath $guestReport -LocalPath $guestReportHost
            Invoke-GuestSsh -SshSpec $sshSpec -Command "powershell -NoProfile -Command `"Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path `$env:USERPROFILE 'grdr-vmware-qa')`""
        } else {
            $guestDir = "grdr-vmware-qa"
            Invoke-GuestSsh -SshSpec $sshSpec -Command "umask 077 && rm -rf ~/$guestDir && mkdir -p -m 0700 ~/$guestDir"
            foreach ($b in @("grdr", "grdr-daemon", "grdr-hook", "grdr-server")) {
                Copy-ToGuestScp -SshSpec $sshSpec -LocalPath (Join-Path $Artifacts.linux_bin_dir $b) -RemotePath "$guestDir/$b"
            }
            $lfTemp = Join-Path $ReportDir "linux-guest-e2e.lf.sh"
            ((Get-Content -Raw (Join-Path $PSScriptRoot "linux-guest-e2e.sh")) -replace "`r`n", "`n") | Set-Content -Path $lfTemp -Encoding ASCII -NoNewline
            Copy-ToGuestScp -SshSpec $sshSpec -LocalPath $lfTemp -RemotePath "$guestDir/linux-guest-e2e.sh"
            $guestReport = "$guestDir/report.json"
            Invoke-GuestSsh -SshSpec $sshSpec -Command "chmod 0700 ~/$guestDir/grdr ~/$guestDir/grdr-daemon ~/$guestDir/grdr-hook ~/$guestDir/grdr-server ~/$guestDir/linux-guest-e2e.sh && ~/$guestDir/linux-guest-e2e.sh --bin-dir `"`$HOME/$guestDir`" --report `"`$HOME/$guestReport`" --mode vmware"
            Copy-FromGuestScp -SshSpec $sshSpec -RemotePath $guestReport -LocalPath $guestReportHost
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
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("revertToSnapshot", $vmx, $snap) -AllowFailure
            $null = Invoke-Vmrun -VmrunExe $VmrunExe -CmdArgs @("stop", $vmx, "hard") -AllowFailure
        }
    }
}

$vmrunExe = Resolve-VmrunExe
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
        -Artifacts $artifacts `
        -SkipTeardownRevert:$KeepRunning
}
