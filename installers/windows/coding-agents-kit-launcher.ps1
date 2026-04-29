#Requires -Version 5.1
<#
.SYNOPSIS
    Launch the coding-agents-kit supervisor.

.DESCRIPTION
    Hides the console window (via the PowerShell host invocation) and
    invokes `coding-agents-kit-ctl daemon`. The supervisor owns the
    Falco process, log files, rotation, and Claude Code hook lifecycle.
    Runs in the foreground so the supervisor's stop signals reach it.
#>
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'coding-agents-kit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Ctl = Join-Path $Prefix 'bin\coding-agents-kit-ctl.exe'
& $Ctl daemon --prefix $Prefix
exit $LASTEXITCODE
