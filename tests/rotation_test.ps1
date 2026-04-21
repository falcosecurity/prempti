# Smoke test for the log-rotation logic of coding-agents-kit-launcher.ps1.
# Extracts the real function (and the constants it closes over) out of the
# launcher via the PowerShell AST, loads them into this session, and runs
# the behavioral checks against the live code. A body change in the
# launcher is reflected here without manual resync.
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $PSScriptRoot '..\installers\windows\coding-agents-kit-launcher.ps1'
$raw = Get-Content $launcher -Raw
$ast = [System.Management.Automation.Language.Parser]::ParseInput($raw, [ref]$null, [ref]$null)

$fn = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $args[0].Name -eq 'Rotate-LogFile'
}, $true) | Select-Object -First 1
if (-not $fn) { throw "Rotate-LogFile not found in $launcher" }

$assigns = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
    ($args[0].Left.VariablePath.UserPath -in @('LogMaxBytes', 'LogKeep'))
}, $true)
foreach ($a in $assigns) { Invoke-Expression $a.Extent.Text }
Invoke-Expression $fn.Extent.Text

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

    # 3. Two more cycles - expect .1, .2, .3 after the third rotation.
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
