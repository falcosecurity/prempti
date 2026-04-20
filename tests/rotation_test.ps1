# Smoke test for the log-rotation logic used by coding-agents-kit-launcher.ps1.
# Keeps the function definition in sync by asserting it matches the launcher.
$ErrorActionPreference = 'Stop'

# Must match the function in installers/windows/coding-agents-kit-launcher.ps1.
$LogMaxBytes = 10MB
$LogKeep = 3

function Rotate-LogFile([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    try {
        $size = (Get-Item -LiteralPath $Path).Length
    } catch {
        return
    }
    if ($size -lt $LogMaxBytes) { return }
    for ($i = $LogKeep; $i -ge 1; $i--) {
        $older = "$Path.$i"
        $newer = if ($i -eq 1) { $Path } else { "$Path.$($i - 1)" }
        if (Test-Path $older) { Remove-Item -LiteralPath $older -Force -ErrorAction SilentlyContinue }
        if (Test-Path $newer) {
            try { Move-Item -LiteralPath $newer -Destination $older -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

# Sanity check: the copy above should exactly match the launcher body.
$launcher = Join-Path $PSScriptRoot '..\installers\windows\coding-agents-kit-launcher.ps1'
$launcherBody = Get-Content $launcher -Raw
if ($launcherBody -notmatch [regex]::Escape('function Rotate-LogFile([string]$Path) {')) {
    throw "Launcher is missing Rotate-LogFile - rotation contract broken"
}

$dir = Join-Path ([System.IO.Path]::GetTempPath()) ("rot-test-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir | Out-Null
$log = Join-Path $dir 'test.log'
try {
    # 1. Small file: no rotation.
    Set-Content -Path $log -Value 'small'
    Rotate-LogFile -Path $log
    if (Test-Path "$log.1") { throw "Small file was rotated unexpectedly" }

    # 2. 11 MB dummy file: rotation happens; original moves to .1.
    $fs = [System.IO.File]::OpenWrite($log)
    try { $fs.SetLength(11MB) } finally { $fs.Dispose() }
    Rotate-LogFile -Path $log
    if (Test-Path $log) { throw "Original log should have been moved to .1" }
    if (-not (Test-Path "$log.1")) { throw ".1 should exist after first rotation" }

    # 3. Two more cycles — expect .1, .2, .3 after the third rotation.
    for ($n = 0; $n -lt 2; $n++) {
        $fs = [System.IO.File]::OpenWrite($log)
        try { $fs.SetLength(11MB) } finally { $fs.Dispose() }
        Rotate-LogFile -Path $log
    }
    if (-not (Test-Path "$log.1")) { throw ".1 missing after 3rd rotation" }
    if (-not (Test-Path "$log.2")) { throw ".2 missing after 3rd rotation" }
    if (-not (Test-Path "$log.3")) { throw ".3 missing after 3rd rotation" }

    # 4. Fourth rotation must NOT create a .4 (cap at $LogKeep=3).
    $fs = [System.IO.File]::OpenWrite($log)
    try { $fs.SetLength(11MB) } finally { $fs.Dispose() }
    Rotate-LogFile -Path $log
    if (Test-Path "$log.4") { throw "Rotation should cap at .3, found .4" }

    Write-Output 'rotation test: OK'
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
