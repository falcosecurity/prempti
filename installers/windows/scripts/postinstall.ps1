#Requires -Version 5.1
<#
.SYNOPSIS
    Post-installation setup for coding-agents-kit on Windows.

.DESCRIPTION
    Called by the MSI custom action after files are deployed.
    Generates Falco config with resolved paths, registers the Claude Code
    hook, and sets up auto-start via Registry Run key.
#>
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'coding-agents-kit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BinDir = Join-Path $Prefix 'bin'
$ConfigDir = Join-Path $Prefix 'config'
$ShareDir = Join-Path $Prefix 'share'
$RulesDir = Join-Path $Prefix 'rules'
$RunDir = Join-Path $Prefix 'run'
$LogDir = Join-Path $Prefix 'log'

# Ensure all directories exist
foreach ($dir in @($ConfigDir, $RunDir, $LogDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# ---------------------------------------------------------------------------
# Generate falco.yaml with resolved Windows paths
# ---------------------------------------------------------------------------

$falcoYaml = @"
# coding-agents-kit Falco configuration (Windows, auto-generated)
engine:
  kind: nodriver

config_files:
  - $($ConfigDir -replace '\\', '/')/falco.coding_agents_plugin.yaml

http_output:
  enabled: true
  url: http://127.0.0.1:2802

stdout_output:
  enabled: false

json_output: true
json_include_output_property: false
json_include_message_property: true
json_include_output_fields_property: true
json_include_tags_property: true

rule_matching: all
priority: debug

watch_config_files: true
"@

Set-Content -Path (Join-Path $ConfigDir 'falco.yaml') -Value $falcoYaml -Encoding UTF8
Write-Host "Generated falco.yaml"

# ---------------------------------------------------------------------------
# Generate plugin config with resolved Windows paths
# ---------------------------------------------------------------------------

$pluginYaml = @"
# coding-agents-kit plugin configuration (Windows, auto-generated)
plugins:
  - name: coding_agent
    library_path: $($ShareDir -replace '\\', '/')/coding_agent.dll
    init_config:
      mode: enforcement
      socket_path: "$($Prefix -replace '\\', '/')/run/broker.sock"
      http_port: 2802

load_plugins:
  - coding_agent

rules_files:
  - $($RulesDir -replace '\\', '/')/default/coding_agents_rules.yaml
  - $($RulesDir -replace '\\', '/')/user/
  - $($RulesDir -replace '\\', '/')/seen.yaml

append_output:
  - match:
      source: coding_agent
    extra_output: " | For AI Agents: inform the user that this action was flagged by a Falco security rule | correlation=%correlation.id"
"@

Set-Content -Path (Join-Path $ConfigDir 'falco.coding_agents_plugin.yaml') -Value $pluginYaml -Encoding UTF8
Write-Host "Generated falco.coding_agents_plugin.yaml"

# ---------------------------------------------------------------------------
# Register Claude Code hook
# ---------------------------------------------------------------------------

$ctlExe = Join-Path $BinDir 'coding-agents-kit-ctl.exe'
if (Test-Path $ctlExe) {
  try {
    $hookOutput = & $ctlExe hook add 2>&1
    $hookOutput | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Hook registration failed (exit $LASTEXITCODE). Install will continue."
    }
  } catch {
    Write-Warning "Hook registration failed: $($_.Exception.Message)"
  }
}

# ---------------------------------------------------------------------------
# Add bin/ to user PATH (persistent, avoids full-path invocations)
# ---------------------------------------------------------------------------

try {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$BinDir", 'User')
        Write-Host "Added $BinDir to user PATH"
    } else {
        Write-Host "bin/ already in user PATH"
    }
} catch {
    Write-Warning "Failed to update PATH: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Register auto-start via Registry Run key
# ---------------------------------------------------------------------------

$launcherScript = Join-Path $BinDir 'coding-agents-kit-launcher.ps1'
if (Test-Path $launcherScript) {
  try {
    $runCmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcherScript`""
    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if (-not (Test-Path $regPath)) {
      New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name 'CodingAgentsKit' -Value $runCmd
    Write-Host "Registered auto-start"
  } catch {
    Write-Warning "Auto-start registration failed: $($_.Exception.Message)"
  }
}

# ---------------------------------------------------------------------------
# Start the service now
# ---------------------------------------------------------------------------
# The Run key above only fires at next login. Bring the service up right
# now so the Claude Code hook we just registered has a live broker to talk
# to - otherwise fail-closed would block every tool call from the moment
# the MSI finishes until the user's next logout/login.
# Skip if another launcher is already running (e.g. MSI repair / re-run).

$falcoRunning = @(Get-Process -Name falco -ErrorAction SilentlyContinue).Count -gt 0
if (-not $falcoRunning -and (Test-Path $launcherScript)) {
    try {
        $startArgs = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-WindowStyle', 'Hidden',
            '-File', $launcherScript
        )
        Start-Process -FilePath 'powershell.exe' -ArgumentList $startArgs -WindowStyle Hidden | Out-Null
        # Wait up to 5s for Falco to appear before declaring success.
        $started = $false
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 250
            if (Get-Process -Name falco -ErrorAction SilentlyContinue) {
                $started = $true
                break
            }
        }
        if ($started) {
            Write-Host "Service started."
        } else {
            Write-Warning "Service start kicked off but Falco not detected yet - run 'coding-agents-kit-ctl status' to check."
        }
    } catch {
        Write-Warning "Could not start the service: $($_.Exception.Message). Run 'coding-agents-kit-ctl start' manually."
    }
} elseif ($falcoRunning) {
    Write-Host "Service already running."
}

Write-Host "Post-install complete: coding-agents-kit is installed, configured, and running."
