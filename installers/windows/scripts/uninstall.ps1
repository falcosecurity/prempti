#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-uninstall cleanup for coding-agents-kit on Windows.

.DESCRIPTION
    Called by the MSI custom action before files are removed.
    Stops the service, removes the Claude Code hook, and removes
    the auto-start Registry key.
#>
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'coding-agents-kit')
)

$ErrorActionPreference = 'SilentlyContinue'

# Trim trailing "\" and "." the MSI CA appends as an escape-safety sentinel
# (see installers/windows/Package.wxs).
$Prefix = $Prefix.TrimEnd([char[]]@('\', '.'))

# Stop Falco if running
$falcoProcs = Get-Process -Name falco -ErrorAction SilentlyContinue
if ($falcoProcs) {
    Write-Host "Stopping Falco..."
    $falcoProcs | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# Remove Claude Code hook
$ctlExe = Join-Path $Prefix 'bin\coding-agents-kit-ctl.exe'
if (Test-Path $ctlExe) {
    & $ctlExe hook remove 2>$null
}

# Remove auto-start Registry key
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $regPath -Name 'CodingAgentsKit' -ErrorAction SilentlyContinue

# Remove bin/ from user PATH
$BinDir = Join-Path $Prefix 'bin'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -and $userPath -like "*$BinDir*") {
    $newPath = ($userPath -split ';' | Where-Object { $_ -ne $BinDir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "Removed $BinDir from user PATH"
}

Write-Host "Uninstall cleanup complete"
