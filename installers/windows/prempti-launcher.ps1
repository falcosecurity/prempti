#Requires -Version 5.1
<#
.SYNOPSIS
    Launch the Prempti supervisor.

.DESCRIPTION
    Hides the console window (via the PowerShell host invocation) and
    invokes `premptictl daemon`. The supervisor owns the Falco process,
    log files, rotation, and Claude Code hook lifecycle. Runs in the
    foreground so the supervisor's stop signals reach it. Captures the
    supervisor's own stderr to log/supervisor.err so an early crash
    (before Falco's logs are open) leaves a breadcrumb for the user.
#>
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'prempti')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Ctl = Join-Path $Prefix 'bin\premptictl.exe'
$LogDir = Join-Path $Prefix 'log'
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}
$SupervisorErr = Join-Path $LogDir 'supervisor.err'

# Truncate per-run; only the latest launch's supervisor stderr is useful for
# diagnosing a failed startup. Use UTF-8 without BOM so Add-Content / external
# tools don't have to skip a BOM.
[IO.File]::WriteAllText($SupervisorErr, '', [System.Text.UTF8Encoding]::new($false))

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Ctl
$psi.Arguments = "daemon --prefix `"$Prefix`""
$psi.UseShellExecute = $false
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi)

# Drain stderr asynchronously to avoid a 4 KB OS pipe-buffer deadlock if the
# supervisor logs steadily. Each line is appended to supervisor.err.
$drain = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
    if ($EventArgs.Data) {
        [IO.File]::AppendAllText($Event.MessageData, $EventArgs.Data + "`r`n",
            [System.Text.UTF8Encoding]::new($false))
    }
} -MessageData $SupervisorErr
$proc.BeginErrorReadLine()

$proc.WaitForExit()
# Per MSDN, calling WaitForExit() a second time after the first returns ensures
# all async events fire before we tear down the registration.
$proc.WaitForExit()

if ($drain) {
    Unregister-Event -SourceIdentifier $drain.Name -ErrorAction SilentlyContinue
}
exit $proc.ExitCode
