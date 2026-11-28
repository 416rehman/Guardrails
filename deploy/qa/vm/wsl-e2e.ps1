# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

param(
    [string]$Distro = "Ubuntu-24.04",

    [switch]$SkipBuild,

    [switch]$DryRun,

    [string]$ReportPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $RepoRoot "target\qa\wsl\report.json"
}

function Convert-ToWslPath {
    param([string]$WinPath)
    $resolved = [System.IO.Path]::GetFullPath($WinPath)
    if ($resolved -match '^([A-Za-z]):[\\/](.*)$') {
        $drive = $matches[1].ToLowerInvariant()
        $rest = $matches[2] -replace '\\', '/'
        return "/mnt/$drive/$rest"
    }
    throw "Cannot convert path to WSL mount path: $WinPath"
}

function Get-WslDistros {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $raw = & wsl.exe -l -q 2>&1
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    if ($rc -ne 0) {
        return @()
    }
    $list = @()
    foreach ($line in $raw) {
        $clean = ($line.ToString() -replace "`0", "").Trim()
        if (-not [string]::IsNullOrWhiteSpace($clean)) {
            $list += $clean
        }
    }
    return $list
}

function Invoke-WslBash {
    param(
        [string]$DistroName,
        [string]$ScriptText,
        [switch]$PassThru
    )
    $cleanScript = $ScriptText -replace "`r`n", "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($cleanScript)
    $b64 = [Convert]::ToBase64String($bytes)
    $cmd = "echo $b64 | base64 -d | bash -s"
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & wsl.exe -d $DistroName -- bash -c $cmd 2>&1
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $text = (($output | ForEach-Object { $_.ToString() -replace "`0", "" }) -join "`n").Trim()
    if (-not $PassThru -and $rc -ne 0) {
        throw "WSL command failed (exit $rc): $text"
    }
    return [PSCustomObject]@{
        ExitCode = $rc
        Output   = $text
    }
}

function Test-CrossBoundaryWslBridge {
    param(
        [string]$DistroName,
        [string]$RepoDir
    )
    $grdrExe = $null
    foreach ($candidate in @(
        (Join-Path $RepoDir "target\debug\grdr.exe"),
        (Join-Path $RepoDir "target\release\grdr.exe")
    )) {
        if (Test-Path $candidate) {
            $grdrExe = $candidate
            break
        }
    }
    if (-not $grdrExe) {
        return [ordered]@{
            checked = $false
            passed  = $true
            detail  = "host grdr.exe not prebuilt; cross-boundary Windows+WSL bridge check skipped"
        }
    }

    $bridgeProc = $null
    try {
        $bridgeProc = Start-Process -FilePath "wsl.exe" -ArgumentList @("-d", $DistroName, "--", "sleep", "8") -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 600
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $docRaw = & $grdrExe doctor --json --profile user 2>&1
            $docRc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($docRc -ne 0) {
            return [ordered]@{
                checked = $true
                passed  = $false
                detail  = "host grdr doctor --json failed: $docRaw"
            }
        }
        $docObj = ($docRaw -join "`n") | ConvertFrom-Json
        $bridges = @($docObj.windows_process_observation.active_wsl_bridges)
        $matched = @($bridges | Where-Object { $_.distro -eq $DistroName -or $_.image_name -match "wsl" })
        if ($matched.Count -lt 1) {
            return [ordered]@{
                checked = $true
                passed  = $false
                detail  = "host grdr doctor did not observe active wsl.exe bridge process"
            }
        }
        return [ordered]@{
            checked = $true
            passed  = $true
            detail  = "host grdr doctor observed active wsl.exe bridge (count=$($matched.Count))"
        }
    } finally {
        if ($bridgeProc -and -not $bridgeProc.HasExited) {
            Stop-Process -Id $bridgeProc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

$wslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wslCmd) {
    throw "wsl.exe not found on host."
}

$distros = Get-WslDistros
if ($distros -notcontains $Distro) {
    throw "WSL2 distro '$Distro' not found. Available distros: $($distros -join ', ')"
}

$wslRepoRoot = Convert-ToWslPath $RepoRoot
$runnerHostPath = Join-Path $PSScriptRoot "linux-guest-e2e.sh"
if (-not (Test-Path $runnerHostPath)) {
    throw "Missing Linux E2E runner script: $runnerHostPath"
}
$wslRunnerPath = Convert-ToWslPath $runnerHostPath

$probe = Invoke-WslBash -DistroName $Distro -ScriptText @'
export PATH="$HOME/.cargo/bin:$PATH"
if command -v cargo >/dev/null 2>&1; then
  echo "HAS_CARGO=true"
else
  echo "HAS_CARGO=false"
fi
if command -v python3 >/dev/null 2>&1; then
  echo "HAS_PYTHON3=true"
else
  echo "HAS_PYTHON3=false"
fi
'@
$hasCargo = $probe.Output -match "HAS_CARGO=true"
$hasPython3 = $probe.Output -match "HAS_PYTHON3=true"
$hasDocker = [bool](Get-Command docker.exe -ErrorAction SilentlyContinue)

if ($DryRun) {
    $reportDir = Split-Path -Parent $ReportPath
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    $dryReport = [ordered]@{
        schema_version = 1
        mode           = "dry_run"
        distro         = $Distro
        wsl_cargo      = $hasCargo
        wsl_python3    = $hasPython3
        host_docker    = $hasDocker
        skip_build     = [bool]$SkipBuild
        plan           = @(
            "build grdr, grdr-daemon, grdr-hook, grdr-server for Linux inside WSL2 or Docker",
            "stage binaries and linux-guest-e2e.sh into ~/.local/state/grdr-qa/wsl-<tag>",
            "run Slice 0 E2E with isolated HOME under ~/.local/state/grdr-qa/wsl-<tag>/home",
            "verify host Windows+WSL bridge discovery when host grdr.exe is present",
            "save report to target/qa/wsl/report.json and clean ~/.local/state/grdr-qa/wsl-<tag>*"
        )
    }
    $dryReport | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Output "WSL2 E2E dry-run ready (distro=$Distro, wsl_cargo=$hasCargo, wsl_python3=$hasPython3, host_docker=$hasDocker)."
    exit 0
}

if (-not $hasPython3) {
    throw "python3 is required inside WSL2 distro '$Distro'."
}

$wslHome = (Invoke-WslBash -DistroName $Distro -ScriptText 'printf %s "$HOME"').Output.Trim()
if ([string]::IsNullOrWhiteSpace($wslHome) -or $wslHome -match '^/(tmp|var/tmp|private/tmp|dev/shm)(/|$)') {
    throw "Unsafe WSL HOME directory '$wslHome' for QA staging."
}
$wslRunTag = [guid]::NewGuid().ToString("N").Substring(0, 12)
$wslSafeRoot = "$wslHome/.local/state/grdr-qa"
$wslTargetDir = "$wslSafeRoot/cargo-target"
$wslWorkDir = "$wslSafeRoot/wsl-$wslRunTag"
$wslBinDir = "$wslWorkDir/bin"
$reportDir = Split-Path -Parent $ReportPath
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}
$wslReportPath = Convert-ToWslPath $ReportPath

try {
    if (-not $SkipBuild) {
        if ($hasCargo) {
            Write-Output "Building Linux binaries inside WSL2 ($Distro)..."
            $buildScript = @"
set -euo pipefail
umask 077
export PATH="`$HOME/.cargo/bin:`$PATH"
if [[ -L "$wslSafeRoot" || -L "$wslWorkDir" ]]; then
  echo "Refusing symlinked QA directory" >&2
  exit 1
fi
mkdir -p -m 0700 "$wslSafeRoot" "$wslWorkDir" "$wslBinDir" "$wslTargetDir"
cargo build --locked --manifest-path "$wslRepoRoot/Cargo.toml" --target-dir "$wslTargetDir" -p grdr -p grdr-daemon -p grdr-hook -p grdr-server
for b in grdr grdr-daemon grdr-hook grdr-server; do
  cp "$wslTargetDir/debug/`$b" "$wslBinDir/`$b"
  chmod +x "$wslBinDir/`$b"
done
"@
            $null = Invoke-WslBash -DistroName $Distro -ScriptText $buildScript
        } elseif ($hasDocker) {
            Write-Output "Cargo missing in WSL2; building Linux binaries via Docker..."
            $dockerOutDir = Join-Path $RepoRoot "target\qa\wsl\linux-bin"
            New-Item -ItemType Directory -Path $dockerOutDir -Force | Out-Null
            $dockerCmd = "cargo build --locked --target-dir /target -p grdr -p grdr-daemon -p grdr-hook -p grdr-server && mkdir -p /out && cp /target/debug/grdr /target/debug/grdr-daemon /target/debug/grdr-hook /target/debug/grdr-server /out/"
            & docker run --rm -v "${RepoRoot}:/src:ro" -v "grdr-wsl-qa-target:/target" -v "${dockerOutDir}:/out" -w /src rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c bash -c $dockerCmd
            if ($LASTEXITCODE -ne 0) {
                throw "Docker Linux build failed (exit $LASTEXITCODE)."
            }
            $wslDockerBin = Convert-ToWslPath $dockerOutDir
            $copyScript = @"
set -euo pipefail
umask 077
mkdir -p -m 0700 "$wslSafeRoot" "$wslWorkDir" "$wslBinDir"
for b in grdr grdr-daemon grdr-hook grdr-server; do
  cp "$wslDockerBin/`$b" "$wslBinDir/`$b"
  chmod +x "$wslBinDir/`$b"
done
"@
            $null = Invoke-WslBash -DistroName $Distro -ScriptText $copyScript
        } else {
            throw "Neither cargo inside WSL2 '$Distro' nor docker on host is available to build Linux binaries."
        }
    } else {
        $stageExisting = @"
set -euo pipefail
umask 077
mkdir -p -m 0700 "$wslSafeRoot" "$wslWorkDir" "$wslBinDir"
for b in grdr grdr-daemon grdr-hook grdr-server; do
  if [[ -x "$wslTargetDir/debug/`$b" ]]; then
    cp "$wslTargetDir/debug/`$b" "$wslBinDir/`$b"
    chmod +x "$wslBinDir/`$b"
  elif [[ ! -x "$wslBinDir/`$b" ]]; then
    echo "Missing prebuilt binary for -SkipBuild: `$b" >&2
    exit 1
  fi
done
"@
        $null = Invoke-WslBash -DistroName $Distro -ScriptText $stageExisting
    }

    $bridgeCheck = Test-CrossBoundaryWslBridge -DistroName $Distro -RepoDir $RepoRoot

    $runScript = @"
set -euo pipefail
umask 077
if [[ -L "$wslSafeRoot" || -L "$wslWorkDir" ]]; then
  echo "Refusing symlinked QA directory" >&2
  exit 1
fi
mkdir -p -m 0700 "$wslSafeRoot" "$wslWorkDir"
tr -d '\r' < "$wslRunnerPath" > "$wslWorkDir/linux-guest-e2e.sh"
chmod 0700 "$wslWorkDir/linux-guest-e2e.sh"
"$wslWorkDir/linux-guest-e2e.sh" --bin-dir "$wslBinDir" --work-dir "$wslWorkDir" --report "$wslReportPath" --mode wsl
"@
    $runRes = Invoke-WslBash -DistroName $Distro -ScriptText $runScript -PassThru
    if (-not [string]::IsNullOrWhiteSpace($runRes.Output)) {
        Write-Output $runRes.Output
    }

    if (-not (Test-Path $ReportPath)) {
        throw "WSL2 E2E failed before producing report at $ReportPath (exit $($runRes.ExitCode))."
    }

    $reportObj = (Get-Content -Raw -Path $ReportPath) | ConvertFrom-Json
    $reportObj | Add-Member -NotePropertyName "wsl_distro" -NotePropertyValue $Distro -Force
    $reportObj | Add-Member -NotePropertyName "windows_wsl_bridge" -NotePropertyValue $bridgeCheck -Force
    $reportObj | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8

    if ($runRes.ExitCode -ne 0 -or $reportObj.status -ne "passed") {
        throw "WSL2 E2E assertions failed. See $ReportPath"
    }
    if ($bridgeCheck.checked -and -not $bridgeCheck.passed) {
        throw "Cross-boundary Windows+WSL bridge check failed: $($bridgeCheck.detail)"
    }

    Write-Output "WSL2 E2E passed on '$Distro'. Report: $ReportPath"
}
finally {
    $null = Invoke-WslBash -DistroName $Distro -ScriptText "rm -rf '$wslWorkDir' '${wslWorkDir}-home' '${wslWorkDir}-report.json'" -PassThru
}
