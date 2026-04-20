#Requires -Version 5.1
<#
.SYNOPSIS
    Integration test for the installed coding-agents-kit service on Windows.

.DESCRIPTION
    Drives the full installed pipeline (launcher -> Falco -> plugin -> rules
    -> verdict -> interceptor) using the binaries deployed under
    %LOCALAPPDATA%\coding-agents-kit\. It kills the currently-running service,
    starts a fresh launcher, sends sample hook JSON through the real
    interceptor, asserts the verdicts, and shuts the launcher down cleanly so
    its finally block can remove the Claude Code hook.

    Requires: coding-agents-kit installed via MSI + postinstall.

    WARNING: this script stops and restarts the installed service. It does not
    modify rules or switch modes, but Claude Code tool calls are blocked for
    the duration of the run (a few seconds).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Prefix = Join-Path $env:LOCALAPPDATA 'coding-agents-kit'
$Launcher = Join-Path $Prefix 'bin\coding-agents-kit-launcher.ps1'
$Hook = Join-Path $Prefix 'bin\claude-interceptor.exe'
$Ctl = Join-Path $Prefix 'bin\coding-agents-kit-ctl.exe'
$PASS = 0
$FAIL = 0
$launcherProc = $null

function Cleanup {
    # Graceful shutdown: stop Falco first, which causes the launcher's
    # WaitForExit to return and its finally block to run (ctl hook remove).
    # Only force-kill the launcher as a last resort.
    if ($script:launcherProc -and -not $script:launcherProc.HasExited) {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $null = & $Ctl stop 2>&1
        $ErrorActionPreference = $prev
        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline -and -not $script:launcherProc.HasExited) {
            Start-Sleep -Milliseconds 200
        }
        if (-not $script:launcherProc.HasExited) {
            & taskkill /F /T /PID $script:launcherProc.Id 2>$null | Out-Null
        }
    }
    Start-Sleep -Milliseconds 500
}

function Assert-True([bool]$Condition, [string]$TestName) {
    if ($Condition) {
        Write-Host "  PASS: $TestName"
        $script:PASS++
    } else {
        Write-Host "  FAIL: $TestName"
        $script:FAIL++
    }
}

function Assert-Contains([string]$Haystack, [string]$Needle, [string]$TestName) {
    Assert-True ($Haystack -and $Haystack.Contains($Needle)) "$TestName (expected to contain '$Needle', got: $Haystack)"
}

function Run-Hook([string]$Json) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Hook
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Do NOT set CODING_AGENTS_KIT_SOCKET: exercise the interceptor's default
    # socket path discovery (%LOCALAPPDATA%/coding-agents-kit/run/broker.sock).
    $psi.EnvironmentVariables['CODING_AGENTS_KIT_TIMEOUT_MS'] = '8000'
    $proc = [System.Diagnostics.Process]::Start($psi)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $proc.StandardInput.BaseStream.Flush()
    $proc.StandardInput.Dispose()
    $so = $proc.StandardOutput.ReadToEndAsync()
    [void]$proc.WaitForExit(10000)
    return $so.GetAwaiter().GetResult()
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

Write-Host "=== Preflight ==="
$missing = @()
foreach ($f in @($Launcher, $Hook, $Ctl, (Join-Path $Prefix 'bin\falco.exe'), (Join-Path $Prefix 'share\coding_agent.dll'), (Join-Path $Prefix 'config\falco.yaml'))) {
    if (-not (Test-Path $f)) { $missing += (Split-Path $f -Leaf) }
}
if ($missing.Count -gt 0) {
    Write-Error "coding-agents-kit not installed. Missing: $($missing -join ', ')"
    exit 1
}
Write-Host "  Installation verified"

# ---------------------------------------------------------------------------
# Start service
# ---------------------------------------------------------------------------

Write-Host "`n=== Start service ==="
Get-Process falco -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1
Remove-Item (Join-Path $Prefix 'run\broker.sock') -Force -ErrorAction SilentlyContinue

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'powershell.exe'
$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Launcher`" -Prefix `"$Prefix`""
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$launcherProc = [System.Diagnostics.Process]::Start($psi)

$retries = 0
$sockFile = Join-Path $Prefix 'run\broker.sock'
while ($retries -lt 40) {
    if (Test-Path $sockFile) { break }
    Start-Sleep -Milliseconds 250
    $retries++
}

Assert-True (Test-Path $sockFile) "broker socket created"
Assert-True (-not $launcherProc.HasExited) "service running"

if ($launcherProc.HasExited -or -not (Test-Path $sockFile)) {
    Write-Host "FATAL: service did not start"
    Cleanup
    exit 1
}

# Extra wait for the HTTP server to bind and for the seen-rule path to warm.
Start-Sleep -Milliseconds 800

# ---------------------------------------------------------------------------
# ctl health
# ---------------------------------------------------------------------------

Write-Host "`n=== ctl health ==="
$healthOut = & $Ctl health 2>&1
$healthStr = ($healthOut | Out-String).Trim()
Assert-Contains $healthStr 'pipeline healthy' 'ctl health reports pipeline healthy'

# ---------------------------------------------------------------------------
# Interceptor <-> installed service verdicts
# ---------------------------------------------------------------------------

Write-Host "`n=== Interceptor -> installed service ==="

$allowJson = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_allow1"}'
$out = Run-Hook $allowJson
Assert-Contains $out '"permissionDecision"' 'interceptor gets a verdict (allow path)'
Assert-Contains $out '"permissionDecision":"allow"' 'safe Bash command allowed'

$readJson = '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"C:\\Users\\test\\readme.txt"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_read1"}'
$out = Run-Hook $readJson
Assert-Contains $out '"permissionDecision":"allow"' 'read file inside cwd allowed'

$grepJson = '{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"test","path":"C:\\Users\\test"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_grep1"}'
$out = Run-Hook $grepJson
Assert-Contains $out '"permissionDecision":"allow"' 'grep allowed'

# Write outside cwd but not sensitive - should ASK.
$askJson = '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"C:\\Users\\other\\notes.txt","content":"x"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_ask1"}'
$out = Run-Hook $askJson
Assert-Contains $out '"permissionDecision":"ask"' 'write outside cwd triggers ask verdict'

# Denying ssh / .aws / .gnupg / .docker / etc. reads is in the default
# ruleset and is a key user-facing guarantee. The is_sensitive_path macro
# uses `contains "/.ssh/"` on `tool.real_file_path` (plugin-normalized to
# forward slashes), which matches on Windows as well.
$denySshJson = '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"C:\\Users\\test\\.ssh\\id_rsa"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_deny2"}'
$out = Run-Hook $denySshJson
Assert-Contains $out '"permissionDecision":"deny"' 'read of .ssh key is denied'

# Note: the default `sensitive_paths` list is Unix-only (/etc, /root, ...),
# and `basename(tool.file_path) in (sensitive_file_names)` uses the raw
# backslash path on Windows, so a .env write is NOT denied by the stock
# ruleset. That is a known ruleset limitation tracked separately, not a
# regression of the pipeline. Do not assert-deny here until the default
# rules gain Windows-aware coverage.

# ---------------------------------------------------------------------------
# ctl status reports a running PID
# ---------------------------------------------------------------------------

Write-Host "`n=== ctl status ==="
$statusOut = & $Ctl status 2>&1
$statusStr = ($statusOut | Out-String).Trim()
Assert-Contains $statusStr 'Service running' 'ctl status reports Service running'
Assert-Contains $statusStr 'PID ' 'ctl status lists at least one PID'

# ---------------------------------------------------------------------------
# Claude Code integration (only if claude is installed)
# ---------------------------------------------------------------------------

$claudeExe = Get-Command 'claude' -ErrorAction SilentlyContinue
if ($claudeExe) {
    Write-Host "`n=== Claude Code integration ==="
    $settingsPath = Join-Path $env:USERPROFILE '.claude\settings.json'
    if (Test-Path $settingsPath) {
        $settings = Get-Content $settingsPath -Raw
        Assert-Contains $settings 'claude-interceptor' 'hook registered in Claude Code settings'
    } else {
        Write-Host "  SKIP: no Claude Code settings.json found"
    }
} else {
    Write-Host "`n=== Claude Code integration ==="
    Write-Host "  SKIP: claude command not found"
}

# ---------------------------------------------------------------------------
# Graceful stop: verify launcher's finally block removes the hook
# ---------------------------------------------------------------------------

Write-Host "`n=== Graceful stop ==="
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$null = & $Ctl stop 2>&1
$ErrorActionPreference = $prev
$deadline = (Get-Date).AddSeconds(6)
while ((Get-Date) -lt $deadline -and -not $launcherProc.HasExited) {
    Start-Sleep -Milliseconds 200
}
Assert-True ($launcherProc.HasExited) 'launcher exited on ctl stop'

# After a clean stop the launcher's finally block should have removed the hook.
# We restore it at the end so the normal post-install state is preserved for
# whoever ran the test.
$hookStatus = (& $Ctl hook status 2>&1 | Out-String).Trim()
Assert-Contains $hookStatus 'Not registered' 'launcher finally removed the hook on clean exit'

# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

Write-Host "`n=== Cleanup ==="
Cleanup

# Re-register the hook and restart the service so we leave the machine as
# we found it. Use the captured invocation form (`& $Ctl start 2>&1`):
# - `Start-Process -Wait` waits for the *process tree* to exit, and our
#   launcher is long-lived (owns Falco), so -Wait hangs for many minutes.
# - `& $Ctl start 2>&1` is safe because ctl spawns the launcher via
#   PowerShell's ShellExecute (see service_start in the ctl source),
#   which fully detaches it from the caller's pipe — ctl returns in ~1s.
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$null = & $Ctl hook add 2>&1
$null = & $Ctl start 2>&1
$ErrorActionPreference = $prev

Write-Host "`n================================"
Write-Host "Results: $PASS passed, $FAIL failed"
Write-Host "================================"

exit $(if ($FAIL -eq 0) { 0 } else { 1 })
