#Requires -Version 5.1
<#
.SYNOPSIS
    Launch the Prempti supervisor.

.DESCRIPTION
    Hides the console window (via the PowerShell host invocation) and
    invokes `premptictl daemon`. The supervisor owns the
    Falco process, log files, rotation, and Claude Code hook lifecycle.
    Runs in the foreground so the supervisor's stop signals reach it.
#>
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'prempti')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Ctl = Join-Path $Prefix 'bin\premptictl.exe'
& $Ctl daemon --prefix $Prefix
exit $LASTEXITCODE
