# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

param(
    [Parameter(Mandatory = $true)]
    [string]$BinDir,

    [string]$WorkDir = "",

    [string]$ReportPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP ("grdr-win-e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
}
$HomeDir = $WorkDir + "-home"
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = $WorkDir + "-report.json"
}

$assertions = New-Object System.Collections.Generic.List[object]
$serverProc = $null
$daemonProc = $null
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$origHome = $env:HOME
$origUserProfile = $env:USERPROFILE
$origLocalAppData = $env:LOCALAPPDATA

function Add-Assertion {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $assertions.Add([PSCustomObject]@{
        name   = $Name
        passed = $Passed
        detail = $Detail
    }) | Out-Null
}

function Fail-Assertion {
    param([string]$Name, [string]$Detail)
    Add-Assertion -Name $Name -Passed $false -Detail $Detail
    throw "FAIL [$Name]: $Detail"
}

function Get-FreeTcpPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}

function Invoke-HttpText {
    param([string]$Url)
    $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
    return $resp.Content
}

function Invoke-ConnectJson {
    param([string]$BaseUrl, [string]$MethodPath, [string]$BodyJson = "{}")
    $resp = Invoke-WebRequest `
        -Uri "$BaseUrl$MethodPath" `
        -Method Post `
        -ContentType "application/json" `
        -Headers @{ "Connect-Protocol-Version" = "1" } `
        -Body $BodyJson `
        -UseBasicParsing `
        -TimeoutSec 5
    return ($resp.Content | ConvertFrom-Json)
}

function Invoke-ProcessWithStdin {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$StdinText
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($ArgumentList | ForEach-Object {
        $arg = [string]$_
        if ($arg.Length -eq 0 -or $arg -match '[\s"\\]') {
            $escaped = ($arg -replace '(\\*)"', '$1$1\"') -replace '(\\*)$', '$1$1'
            '"' + $escaped + '"'
        } else {
            $arg
        }
    }) -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $null = $proc.Start()
    if (-not [string]::IsNullOrEmpty($StdinText)) {
        $inBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($StdinText)
        $proc.StandardInput.BaseStream.Write($inBytes, 0, $inBytes.Length)
        $proc.StandardInput.BaseStream.Flush()
    }
    $proc.StandardInput.BaseStream.Close()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        Stdout   = $stdout
        Stderr   = $stderr
    }
}

function Get-DefenderThreatKeys {
    $cmd = Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue
    if (-not $cmd) { return @() }
    try {
        $items = @(Get-MpThreatDetection -ErrorAction Stop)
        return @($items | ForEach-Object { "$($_.DetectionID)|$($_.InitialDetectionTime)|$($_.Resources -join ';')" })
    } catch {
        return @()
    }
}

function Write-QaReport {
    param([string]$Status, $Extra)
    $parentDir = Split-Path -Parent $ReportPath
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    $passedCount = @($assertions | Where-Object { $_.passed }).Count
    $failedCount = @($assertions | Where-Object { -not $_.passed }).Count
    $payload = [ordered]@{
        schema_version = 1
        mode           = "vmware-windows"
        status         = $Status
        os             = "windows"
        arch           = $env:PROCESSOR_ARCHITECTURE
        duration_ms    = [int64]$stopwatch.ElapsedMilliseconds
        passed_count   = $passedCount
        failed_count   = $failedCount
        defender       = $Extra
        assertions     = $assertions.ToArray()
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
}

$defenderStatus = [ordered]@{
    available            = $false
    realtime_enabled     = $null
    baseline_detections  = 0
    post_run_detections  = 0
    new_grdr_detections  = 0
}
$finalStatus = "failed"

try {
    $localAppDir = Join-Path $HomeDir "AppData\Local"
    New-Item -ItemType Directory -Path (Join-Path $WorkDir "server-data") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $WorkDir "daemon-data") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $HomeDir ".claude") -Force | Out-Null
    New-Item -ItemType Directory -Path $localAppDir -Force | Out-Null

    $env:HOME = $HomeDir
    $env:USERPROFILE = $HomeDir
    $env:LOCALAPPDATA = $localAppDir
    $env:PATH = "$BinDir;$env:PATH"

    foreach ($binName in @("grdr.exe", "grdr-daemon.exe", "grdr-hook.exe", "grdr-server.exe")) {
        $binPath = Join-Path $BinDir $binName
        if (-not (Test-Path $binPath)) {
            throw "Missing required binary: $binPath"
        }
    }

    $mpStatusCmd = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    $baselineThreats = @(Get-DefenderThreatKeys)
    if ($mpStatusCmd) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $defenderStatus.available = $true
            $defenderStatus.realtime_enabled = [bool]$mp.RealTimeProtectionEnabled
            $defenderStatus.baseline_detections = @($baselineThreats).Count
            Add-Assertion -Name "defender_baseline" -Passed $true -Detail "RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled), baseline_detections=$(@($baselineThreats).Count)"
        } catch {
            Add-Assertion -Name "defender_baseline" -Passed $true -Detail "Defender cmdlets present but status query skipped: $($_.Exception.Message)"
        }
    } else {
        Add-Assertion -Name "defender_baseline" -Passed $true -Detail "Get-MpComputerStatus unavailable on host image"
    }

    $serverPort = Get-FreeTcpPort
    $operatorPort = Get-FreeTcpPort
    $serverUrl = "http://127.0.0.1:$serverPort"

    $serverExe = Join-Path $BinDir "grdr-server.exe"
    $serverData = Join-Path $WorkDir "server-data"
    $serverOut = Join-Path $WorkDir "server.out.log"
    $serverErr = Join-Path $WorkDir "server.err.log"
    $serverProc = Start-Process -FilePath $serverExe `
        -ArgumentList @("--bind", "127.0.0.1:$serverPort", "--operator-bind", "127.0.0.1:$operatorPort", "--profile", "embedded", "--data-dir", $serverData) `
        -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr `
        -PassThru -WindowStyle Hidden

    $serverReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $health = (Invoke-HttpText "$serverUrl/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json") | ConvertFrom-Json
            if ($health.status -in @("SERVER_HEALTH_HEALTHY", "SERVER_HEALTH_OK")) {
                $serverReady = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    }
    if (-not $serverReady) {
        Fail-Assertion -Name "server_health" -Detail "grdr-server did not become healthy at $serverUrl/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json"
    }
    Add-Assertion -Name "server_health" -Passed $true -Detail "grdr-server healthy at $serverUrl"

    $claudeCfg = Join-Path $HomeDir ".claude\settings.json"
    $backupCfg = Join-Path $localAppDir "grdr\state\hook-backup-claude-code.json"
    [System.IO.File]::WriteAllText($claudeCfg, '{"permissions":{"allow":["Read"]},"theme":"dark"}', [System.Text.UTF8Encoding]::new($false))
    $origSha = (Get-FileHash -Path $claudeCfg -Algorithm SHA256).Hash

    $grdrExe = Join-Path $BinDir "grdr.exe"
    $hookExe = Join-Path $BinDir "grdr-hook.exe"

    $statusBeforeRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("hook", "status", "--agent", "claude-code", "--json") -StdinText ""
    $statusBeforeObj = $statusBeforeRes.Stdout | ConvertFrom-Json
    if ($statusBeforeRes.ExitCode -ne 1 -or $statusBeforeObj.data.installed -ne $false -or $statusBeforeObj.data.state -ne "not-configured") {
        Fail-Assertion -Name "hook_status_before" -Detail "expected not-configured exit 1 before install, got rc=$($statusBeforeRes.ExitCode)"
    }
    Add-Assertion -Name "hook_status_before" -Passed $true -Detail "grdr hook status --json reported not-configured (exit 1)"

    $scanRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("scan", "--json", "--profile", "user") -StdinText ""
    if ($scanRes.ExitCode -ne 0) {
        Fail-Assertion -Name "scan_isolated_agent" -Detail "grdr scan failed: $($scanRes.Stderr)"
    }
    $scanObj = $scanRes.Stdout | ConvertFrom-Json
    $foundClaude = @($scanObj.agents | Where-Object { $_.kind -eq "claude-code" -and -not $_.hook_installed })
    if ($foundClaude.Count -lt 1) {
        Fail-Assertion -Name "scan_isolated_agent" -Detail "claude-code not discovered in isolated home"
    }
    Add-Assertion -Name "scan_isolated_agent" -Passed $true -Detail "discovered unhooked claude-code in isolated home"

    $installRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("hook", "install", "--agent", "claude-code", "--command", $hookExe, "--apply") -StdinText ""
    $leakedBackup1 = Join-Path $HomeDir ".claude\.grdr-backup.json"
    $leakedBackup2 = Join-Path $HomeDir ".claude\settings.json.grdr-backup.json"
    if ($installRes.ExitCode -ne 0 -or -not (Test-Path $backupCfg) -or (Test-Path $leakedBackup1) -or (Test-Path $leakedBackup2)) {
        Fail-Assertion -Name "install_hook_apply" -Detail "hook install failed, state-dir backup journal missing, or backup leaked into .claude"
    }
    $installedSha = (Get-FileHash -Path $claudeCfg -Algorithm SHA256).Hash
    Add-Assertion -Name "install_hook_apply" -Passed $true -Detail "hook installed with state-dir backup journal"

    $rerunRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("hook", "install", "--agent", "claude-code", "--command", $hookExe, "--apply") -StdinText ""
    $rerunSha = (Get-FileHash -Path $claudeCfg -Algorithm SHA256).Hash
    if ($rerunRes.ExitCode -ne 0 -or $rerunSha -ne $installedSha -or $rerunRes.Stdout -notmatch "already installed") {
        Fail-Assertion -Name "install_hook_idempotent" -Detail "idempotent rerun mutated config or missed already installed message"
    }
    Add-Assertion -Name "install_hook_idempotent" -Passed $true -Detail "second hook install --apply was a clean no-op"

    $statusAfterRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("hook", "status", "--agent", "claude-code", "--json") -StdinText ""
    $statusAfterObj = $statusAfterRes.Stdout | ConvertFrom-Json
    if ($statusAfterRes.ExitCode -ne 0 -or $statusAfterObj.data.installed -ne $true -or $statusAfterObj.data.state -ne "effective") {
        Fail-Assertion -Name "hook_status_after" -Detail "expected effective exit 0 after install, got rc=$($statusAfterRes.ExitCode)"
    }
    Add-Assertion -Name "hook_status_after" -Passed $true -Detail "grdr hook status --json reported effective (installed=true)"

    $daemonExe = Join-Path $BinDir "grdr-daemon.exe"
    $engineExe = Join-Path $BinDir "grdr-engine.exe"
    $uplinkExe = Join-Path $BinDir "grdr-uplink.exe"
    $daemonData = Join-Path $WorkDir "daemon-data"
    $daemonState = Join-Path $WorkDir "daemon-state"
    New-Item -ItemType Directory -Path $daemonState -Force | Out-Null
    $floorBin = Join-Path $daemonState "floor.bin"
    $floorKey = Join-Path $daemonState "floor.pub"
    $pipeTag = "grdr-qa-win-$PID"
    $decidePipe = "\\.\pipe\$pipeTag-decide"
    $localPipe = "\\.\pipe\$pipeTag-local"
    $missingPipe = "\\.\pipe\$pipeTag-missing"
    $daemonArgs = @("--profile", "user", "--server", $serverUrl, "--data-dir", $daemonData, "--state-dir", $daemonState, "--decide-endpoint", $decidePipe, "--local-endpoint", $localPipe)
    if (Test-Path $engineExe) {
        $daemonArgs += @("--engine-bin", $engineExe)
    }
    if (Test-Path $uplinkExe) {
        $daemonArgs += @("--uplink-bin", $uplinkExe)
    }
    $daemonProc = Start-Process -FilePath $daemonExe `
        -ArgumentList $daemonArgs `
        -RedirectStandardOutput (Join-Path $WorkDir "daemon.out.log") `
        -RedirectStandardError (Join-Path $WorkDir "daemon.err.log") `
        -PassThru -WindowStyle Hidden

    $daemonReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        if ((Test-Path $floorBin) -and (Test-Path $floorKey)) {
            $activePipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
            if ($activePipes -contains $decidePipe -and $activePipes -contains $localPipe) {
                $daemonReady = $true
                break
            }
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $daemonReady) {
        Fail-Assertion -Name "daemon_health_and_checkin" -Detail "daemon failed named pipe IPC readiness ($decidePipe) or floor.bin/floor.pub write"
    }
    Add-Assertion -Name "daemon_health_and_checkin" -Passed $true -Detail "daemon running with Windows named pipes and signed floor bundle (floor.bin/floor.pub)"

    $allowRes = Invoke-ProcessWithStdin -FilePath $hookExe `
        -ArgumentList @("--agent", "claude-code", "--socket", $decidePipe, "--state-dir", $daemonState) `
        -StdinText '{"session_id":"sess-qa-win","tool_name":"Bash","tool_input":{"command":"git status"}}'
    if ($allowRes.ExitCode -ne 0) {
        Fail-Assertion -Name "hook_benign_allow" -Detail "expected exit 0, got $($allowRes.ExitCode): $($allowRes.Stderr)"
    }
    Add-Assertion -Name "hook_benign_allow" -Passed $true -Detail "git status returned Allow (exit 0)"

    $blockRes = Invoke-ProcessWithStdin -FilePath $hookExe `
        -ArgumentList @("--agent", "claude-code", "--socket", $decidePipe, "--state-dir", $daemonState) `
        -StdinText '{"session_id":"sess-qa-win","tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m test"}}'
    if ($blockRes.ExitCode -ne 2 -or $blockRes.Stderr -notmatch "BLOCKED") {
        Fail-Assertion -Name "hook_risky_exec_block" -Detail "expected exit 2 BLOCKED, got $($blockRes.ExitCode): $($blockRes.Stderr)"
    }
    Add-Assertion -Name "hook_risky_exec_block" -Passed $true -Detail "git commit --no-verify blocked deterministically (exit 2)"

    $offlineRes = Invoke-ProcessWithStdin -FilePath $hookExe `
        -ArgumentList @("--agent", "claude-code", "--socket", $missingPipe, "--state-dir", $daemonState) `
        -StdinText '{"session_id":"sess-qa-win-offline","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}'
    if ($offlineRes.ExitCode -ne 2 -or $offlineRes.Stderr -notmatch "BLOCKED") {
        Fail-Assertion -Name "hook_offline_failsafe" -Detail "expected exit 2 offline BLOCKED, got $($offlineRes.ExitCode): $($offlineRes.Stderr)"
    }
    Add-Assertion -Name "hook_offline_failsafe" -Passed $true -Detail "offline signed floor bundle blocked control-file write without daemon (exit 2)"

    $docRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("doctor", "--json", "--profile", "user") -StdinText ""
    if ($docRes.ExitCode -ne 0) {
        Fail-Assertion -Name "doctor_json" -Detail "grdr doctor failed: $($docRes.Stderr)"
    }
    $docObj = $docRes.Stdout | ConvertFrom-Json
    if ($docObj.discovered_agent_count -lt 1) {
        Fail-Assertion -Name "doctor_json" -Detail "expected discovered_agent_count >= 1"
    }
    Add-Assertion -Name "doctor_json" -Passed $true -Detail "grdr doctor --json reported discovered_agent_count=$($docObj.discovered_agent_count)"

    $ckptPath = Join-Path $daemonState "audit.checkpoint"
    $walPath = Join-Path $daemonData "receipts.wal.jsonl"
    if (-not (Test-Path $ckptPath)) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "missing signed audit.checkpoint at $ckptPath"
    }
    $auditVerifyRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("audit", "verify", "--json", "--path", $walPath) -StdinText ""
    if ($auditVerifyRes.ExitCode -ne 0) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "grdr audit verify failed: $($auditVerifyRes.Stderr)"
    }
    $auditVerifyObj = $auditVerifyRes.Stdout | ConvertFrom-Json
    if ($auditVerifyObj.verified -ne $true -or $auditVerifyObj.entries -lt 2) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "unexpected grdr audit verify payload: $($auditVerifyRes.Stdout)"
    }
    Add-Assertion -Name "server_uplink_and_audit_verify" -Passed $true -Detail "signed audit.checkpoint and native grdr audit verify verified"

    $uninstRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("hook", "uninstall", "--agent", "claude-code") -StdinText ""
    $restoredSha = (Get-FileHash -Path $claudeCfg -Algorithm SHA256).Hash
    if ($uninstRes.ExitCode -ne 0 -or $restoredSha -ne $origSha -or (Test-Path $backupCfg)) {
        Fail-Assertion -Name "uninstall_byte_restore" -Detail "settings.json restore mismatch or backup journal still present"
    }
    Add-Assertion -Name "uninstall_byte_restore" -Passed $true -Detail "settings.json restored byte-for-byte ($origSha)"

    $postThreats = @(Get-DefenderThreatKeys)
    $defenderStatus.post_run_detections = @($postThreats).Count
    $newThreats = @($postThreats | Where-Object { $baselineThreats -notcontains $_ -and $_ -match "grdr|guardrails" })
    $defenderStatus.new_grdr_detections = @($newThreats).Count
    if (@($newThreats).Count -gt 0) {
        Fail-Assertion -Name "defender_s04_coexistence" -Detail "Windows Defender flagged grdr artifacts: $($newThreats -join ', ')"
    }
    Add-Assertion -Name "defender_s04_coexistence" -Passed $true -Detail "zero Defender false-positive threat detections during install/run/uninstall"

    $finalStatus = "passed"
}
finally {
    $env:HOME = $origHome
    $env:USERPROFILE = $origUserProfile
    $env:LOCALAPPDATA = $origLocalAppData
    if ($daemonProc -and -not $daemonProc.HasExited) {
        Stop-Process -Id $daemonProc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
    Write-QaReport -Status $finalStatus -Extra $defenderStatus
    if (Test-Path $WorkDir) {
        Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $HomeDir) {
        Remove-Item -Path $HomeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
