#Requires -Version 5.1
<#
.SYNOPSIS
    Build the Prempti Windows MSI package.

.DESCRIPTION
    Compiles Rust crates, builds Falco from source (if needed), stages
    all files, and produces an MSI installer via WiX v4.

.PARAMETER Version
    Package version. Defaults to the workspace version from Cargo.toml.

.PARAMETER Arch
    Target architecture: x64 or arm64 (default: native).

.PARAMETER SkipFalcoBuild
    Skip building Falco (use pre-built binary).

.PARAMETER SkipRustBuild
    Skip building Rust crates (use pre-built binaries).

.PARAMETER FalcoExe
    Path to pre-built falco.exe (overrides Falco build).
#>
param(
    [string]$Version = '',
    [string]$Arch = '',
    [switch]$SkipFalcoBuild,
    [switch]$SkipRustBuild,
    [string]$FalcoExe = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$BuildDir = Join-Path $RootDir 'build'

# Read version from workspace Cargo.toml when not explicitly overridden.
if ([string]::IsNullOrWhiteSpace($Version)) {
    $cargoToml = Join-Path $RootDir 'Cargo.toml'
    if (-not (Test-Path $cargoToml)) {
        throw "Workspace Cargo.toml not found at $cargoToml"
    }
    $match = Select-String -Path $cargoToml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $match) {
        throw "Could not parse version from $cargoToml"
    }
    $Version = $match.Matches[0].Groups[1].Value
}

# Detect native architecture. PROCESSOR_ARCHITECTURE can lie when running under
# x64 emulation on ARM64 (returns AMD64 instead of ARM64). Check the registry
# for the true hardware architecture.
if ([string]::IsNullOrWhiteSpace($Arch)) {
    $hwArch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
    if (-not $hwArch) { $hwArch = $env:PROCESSOR_ARCHITECTURE }
    switch ($hwArch) {
        'AMD64' { $Arch = 'x64' }
        'ARM64' { $Arch = 'arm64' }
        default { $Arch = 'x64' }
    }
}

# Map to Rust target
$RustTarget = switch ($Arch) {
    'x64'   { 'x86_64-pc-windows-msvc' }
    'arm64' { 'aarch64-pc-windows-msvc' }
    default { throw "Unsupported architecture: $Arch" }
}

$WixArch = switch ($Arch) {
    'x64'   { 'x64' }
    'arm64' { 'arm64' }
    default { 'x64' }
}

$UtilCABinaryRef = switch ($Arch) {
    'x64'   { 'Wix4UtilCA_X64' }
    'arm64' { 'Wix4UtilCA_A64' }
    default { 'Wix4UtilCA_X64' }
}

Write-Host "Prempti Windows Package Builder"
Write-Host "  Version:  $Version"
Write-Host "  Arch:     $Arch"
Write-Host "  Target:   $RustTarget"
Write-Host ""

# ---------------------------------------------------------------------------
# Stage directory
# ---------------------------------------------------------------------------

$StageDir = Join-Path $BuildDir "stage-windows-$Arch"
if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'bin') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'share') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'config') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'rules\default') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'rules\user') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'scripts') | Out-Null

# ---------------------------------------------------------------------------
# Build Rust crates
# ---------------------------------------------------------------------------

if (-not $SkipRustBuild) {
    Write-Host "=== Building Rust crates ($RustTarget) ==="

    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw 'cargo not found. Install Rust toolchain.' }

    # Ensure target is installed (rustup writes info to stderr, suppress errors)
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & rustup target add $RustTarget 2>&1 | Out-Null
    $ErrorActionPreference = $prevPref

    $crates = @(
        @{ Path = 'hooks\claude-code';              Name = 'Claude Code interceptor' },
        @{ Path = 'hooks\codex';                    Name = 'Codex interceptor (experimental)' },
        @{ Path = 'plugins\coding-agents-plugin';    Name = 'Plugin' },
        @{ Path = 'tools\premptictl';    Name = 'CTL tool' }
    )
    foreach ($crate in $crates) {
        Write-Host "  Building $($crate.Name)..."
        Push-Location (Join-Path $RootDir $crate.Path)
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & cargo build --release --target $RustTarget
        $ErrorActionPreference = $prevPref
        if ($LASTEXITCODE -ne 0) { throw "$($crate.Name) build failed." }
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# Build Falco
# ---------------------------------------------------------------------------

$FalcoDir = Join-Path $BuildDir "falco-0.43.0-windows-$Arch"

if ([string]::IsNullOrWhiteSpace($FalcoExe)) {
    if (-not $SkipFalcoBuild) {
        if (-not (Test-Path (Join-Path $FalcoDir 'falco.exe'))) {
            Write-Host "=== Building Falco ==="
            & (Join-Path $ScriptDir 'build-falco.ps1') -Arch $Arch
            if ($LASTEXITCODE -ne 0) { throw 'Falco build failed.' }
        }
    }
    $FalcoExe = Join-Path $FalcoDir 'falco.exe'
}

if (-not (Test-Path $FalcoExe)) { throw "Falco binary not found: $FalcoExe" }

# Stage falco.exe (no binary patching needed — the Falco patch enables
# absolute library_path on Windows via std::filesystem::path::has_root_path).
Copy-Item $FalcoExe (Join-Path $StageDir 'bin\falco.exe') -Force

# ---------------------------------------------------------------------------
# Stage binaries
# ---------------------------------------------------------------------------

Write-Host "Staging files..."

# Find built artifacts in the workspace target/ tree. Check the target-triple
# subdir first (used when `cargo build --target <triple>` was invoked),
# then fall back to the plain release/ dir (used when no --target was passed).
# Also support legacy per-crate target/ dirs for older layouts.
function Find-Artifact([string]$CrateDir, [string]$FileName) {
    $candidates = @(
        (Join-Path $RootDir "target\$RustTarget\release\$FileName"),
        (Join-Path $RootDir "target\release\$FileName"),
        (Join-Path $CrateDir "target\$RustTarget\release\$FileName"),
        (Join-Path $CrateDir "target\release\$FileName")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw "Built artifact not found: $FileName (looked in $($candidates -join ', '))"
}

Copy-Item (Find-Artifact (Join-Path $RootDir 'hooks\claude-code') 'claude-interceptor.exe') (Join-Path $StageDir 'bin\') -Force
Copy-Item (Find-Artifact (Join-Path $RootDir 'hooks\codex') 'codex-interceptor.exe') (Join-Path $StageDir 'bin\') -Force
Copy-Item (Find-Artifact (Join-Path $RootDir 'tools\premptictl') 'premptictl.exe') (Join-Path $StageDir 'bin\') -Force
Copy-Item (Find-Artifact (Join-Path $RootDir 'plugins\coding-agents-plugin') 'coding_agent.dll') (Join-Path $StageDir 'share\') -Force

Copy-Item (Join-Path $ScriptDir 'prempti-launcher.ps1') (Join-Path $StageDir 'bin\') -Force

# ---------------------------------------------------------------------------
# Stage rules
# ---------------------------------------------------------------------------

Copy-Item (Join-Path $RootDir 'rules\default\coding_agents_rules.yaml') (Join-Path $StageDir 'rules\default\') -Force
Copy-Item (Join-Path $RootDir 'rules\seen.yaml') (Join-Path $StageDir 'rules\') -Force

# ---------------------------------------------------------------------------
# Stage scripts
# ---------------------------------------------------------------------------

Copy-Item (Join-Path $ScriptDir 'scripts\postinstall.ps1') (Join-Path $StageDir 'scripts\') -Force
Copy-Item (Join-Path $ScriptDir 'scripts\uninstall.ps1') (Join-Path $StageDir 'scripts\') -Force

Write-Host "  Staged to: $StageDir"

# ---------------------------------------------------------------------------
# Deterministic ProductCode from version
# ---------------------------------------------------------------------------

$versionBytes = [System.Text.Encoding]::UTF8.GetBytes("prempti-ProductCode-$Version")
$sha = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha.ComputeHash($versionBytes)
$guidBytes = $hashBytes[0..15]
$guidBytes[6] = ($guidBytes[6] -band 0x0F) -bor 0x50   # UUID version 5
$guidBytes[8] = ($guidBytes[8] -band 0x3F) -bor 0x80   # RFC 4122 variant
$ProductCode = [System.Guid]::new([byte[]]$guidBytes).ToString('B').ToUpper()
Write-Host "  ProductCode: $ProductCode"

# ---------------------------------------------------------------------------
# Build MSI
# ---------------------------------------------------------------------------

$WxsFile = Join-Path $ScriptDir 'Package.wxs'
$LicenseRtf = Join-Path $ScriptDir 'license.rtf'
$OutputDir = Join-Path $BuildDir 'out'
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$MsiName = "prempti-$Version-windows-$Arch.msi"

Write-Host "Building MSI..."

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) { throw 'WiX Toolset not found. Install via: dotnet tool install --global wix' }

# Ensure WiX v7 OSMF EULA is accepted in non-interactive build environments.
& wix eula accept wix7 2>&1 | Out-Null

& wix build $WxsFile `
    -d "StageDir=$StageDir" `
    -d "ProductVersion=$Version" `
    -d "ProductCode=$ProductCode" `
    -d "UtilCABinaryRef=$UtilCABinaryRef" `
    -bv "WixUILicenseRtf=$LicenseRtf" `
    -ext WixToolset.Util.wixext `
    -ext WixToolset.UI.wixext `
    -o (Join-Path $OutputDir $MsiName) `
    -arch $WixArch

if ($LASTEXITCODE -ne 0) { throw 'WiX build failed.' }

Write-Host ""
Write-Host "MSI created: $(Join-Path $OutputDir $MsiName)"
