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
        if ($_ -match '\s|"' ) { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
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
    $daemonPort = Get-FreeTcpPort
    $serverUrl = "http://127.0.0.1:$serverPort"
    $daemonUrl = "http://127.0.0.1:$daemonPort"

    $serverExe = Join-Path $BinDir "grdr-server.exe"
    $serverData = Join-Path $WorkDir "server-data"
    $serverOut = Join-Path $WorkDir "server.out.log"
    $serverErr = Join-Path $WorkDir "server.err.log"
    $serverProc = Start-Process -FilePath $serverExe `
        -ArgumentList @("--bind", "127.0.0.1:$serverPort", "--data-dir", $serverData) `
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
    $daemonData = Join-Path $WorkDir "daemon-data"
    $floorFile = Join-Path $WorkDir "floor.json"
    $floorKey = Join-Path $WorkDir "floor.pub"
    $deviceName = "qa-vmware-win11"
    $daemonProc = Start-Process -FilePath $daemonExe `
        -ArgumentList @("--bind", "127.0.0.1:$daemonPort", "--server", $serverUrl, "--profile", "user", "--interval-secs", "3", "--data-dir", $daemonData, "--floor-table", $floorFile, "--device-name", $deviceName) `
        -RedirectStandardOutput (Join-Path $WorkDir "daemon.out.log") `
        -RedirectStandardError (Join-Path $WorkDir "daemon.err.log") `
        -PassThru -WindowStyle Hidden

    $daemonReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $st = (Invoke-HttpText "$daemonUrl/local/v1/status") | ConvertFrom-Json
            if ($st.status -eq "running" -and $st.uplink.state -eq "connected") {
                $daemonReady = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    }
    if (-not $daemonReady -or -not (Test-Path $floorFile) -or -not (Test-Path $floorKey)) {
        Fail-Assertion -Name "daemon_health_and_checkin" -Detail "daemon failed uplink.state=connected readiness or floor bundle write"
    }
    Add-Assertion -Name "daemon_health_and_checkin" -Passed $true -Detail "daemon running, uplink connected to server, signed floor bundle written"

    $allowRes = Invoke-ProcessWithStdin -FilePath $hookExe `
        -ArgumentList @("--daemon", $daemonUrl, "--timeout-ms", "2000", "--floor-table", $floorFile, "--floor-key", $floorKey) `
        -StdinText '{"session_id":"sess-qa-win","tool_name":"Bash","tool_input":{"command":"git status"}}'
    if ($allowRes.ExitCode -ne 0) {
        Fail-Assertion -Name "hook_benign_allow" -Detail "expected exit 0, got $($allowRes.ExitCode): $($allowRes.Stderr)"
    }
    Add-Assertion -Name "hook_benign_allow" -Passed $true -Detail "git status returned Allow (exit 0)"

    $blockRes = Invoke-ProcessWithStdin -FilePath $hookExe `
        -ArgumentList @("--daemon", $daemonUrl, "--timeout-ms", "2000", "--floor-table", $floorFile, "--floor-key", $floorKey) `
        -StdinText '{"session_id":"sess-qa-win","tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m test"}}'
    if ($blockRes.ExitCode -ne 2 -or $blockRes.Stderr -notmatch "BLOCKED") {
        Fail-Assertion -Name "hook_risky_exec_block" -Detail "expected exit 2 BLOCKED, got $($blockRes.ExitCode): $($blockRes.Stderr)"
    }
    Add-Assertion -Name "hook_risky_exec_block" -Passed $true -Detail "git commit --no-verify blocked deterministically (exit 2)"

    $docRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("doctor", "--json", "--profile", "user") -StdinText ""
    if ($docRes.ExitCode -ne 0) {
        Fail-Assertion -Name "doctor_json" -Detail "grdr doctor failed: $($docRes.Stderr)"
    }
    $docObj = $docRes.Stdout | ConvertFrom-Json
    if ($docObj.discovered_agent_count -lt 1) {
        Fail-Assertion -Name "doctor_json" -Detail "expected discovered_agent_count >= 1"
    }
    Add-Assertion -Name "doctor_json" -Passed $true -Detail "grdr doctor --json reported discovered_agent_count=$($docObj.discovered_agent_count)"

    $flushed = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $st = (Invoke-HttpText "$daemonUrl/local/v1/status") | ConvertFrom-Json
            if ($st.pending_events -eq 0) {
                $flushed = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 300
    }
    if (-not $flushed) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "daemon pending_events did not drain to 0"
    }

    $session = Invoke-ConnectJson -BaseUrl $serverUrl -MethodPath "/grdr.api.activity.v1alpha1.SessionService/GetSession" -BodyJson '{"id":"sess-qa-win"}'
    $exportResp = Invoke-ConnectJson -BaseUrl $serverUrl -MethodPath "/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl" -BodyJson "{}"
    $auditRaw = $exportResp.payload
    $auditLines = @($auditRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
    $receiptRecords = @($auditLines | Where-Object { $_.record_type -eq "decision_receipt" })
    if (@($session.receipts).Count -lt 2 -or $receiptRecords.Count -lt 2) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "missing session receipts or ExportAuditJsonl records"
    }

    $walPath = Join-Path $daemonData "receipts.wal.jsonl"
    $auditVerifyRes = Invoke-ProcessWithStdin -FilePath $grdrExe -ArgumentList @("audit", "verify", "--json", "--path", $walPath) -StdinText ""
    if ($auditVerifyRes.ExitCode -ne 0) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "grdr audit verify failed: $($auditVerifyRes.Stderr)"
    }
    $auditVerifyObj = $auditVerifyRes.Stdout | ConvertFrom-Json
    if ($auditVerifyObj.verified -ne $true -or $auditVerifyObj.entries -lt 2) {
        Fail-Assertion -Name "server_uplink_and_audit_verify" -Detail "unexpected grdr audit verify payload: $($auditVerifyRes.Stdout)"
    }
    Add-Assertion -Name "server_uplink_and_audit_verify" -Passed $true -Detail "Connect RPC session/ExportAuditJsonl and native grdr audit verify verified"

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
