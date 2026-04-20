# Windows Build & Installation Guide

## Architecture

### Platform

Builds target the native architecture of the machine. The build scripts auto-detect x86_64 or ARM64 and compile accordingly.

### Pipeline

The Windows port uses the same Falco plugin architecture as Linux/macOS. Alert delivery uses Falco's native `http_output` on all platforms:

```
Claude Code
    │  PreToolUse hook
    ▼
claude-interceptor.exe ──Unix socket──▶ Plugin broker (in Falco)
                                              │
                                              ▼
                                       Falco rule engine
                                              │
                                              ▼
                                       http_output (curl)
                                              │
                                              ▼
                                       Plugin HTTP server
                                              │
                                              ▼
                                       Verdict resolution
                                              │
                                              ▼
                                   Response to interceptor
```

| Component | Linux/macOS | Windows |
|-----------|------------|---------|
| Interceptor → broker | Unix domain socket | Unix domain socket (via `uds_windows` crate) |
| Broker | Embedded in plugin | Embedded in plugin |
| Plugin | .so / .dylib loaded by Falco | .dll loaded by Falco |
| Alert delivery | Falco `http_output` (curl) | Falco `http_output` (curl, patched in) |
| Processes | 1 (Falco) | 1 (Falco) |

### http_output on Windows

Falco's upstream build excludes `http_output` on Windows (CMake and preprocessor guards). A single patch (`falco-windows-http-output.patch`) enables it using the same `HAS_HTTP_OUTPUT` pattern as the macOS patch. System curl is provided via vcpkg with SChannel backend (no OpenSSL dependency). The patch also handles SChannel-specific curl limitations:

- **NOPROXY**: Adds `CURLOPT_NOPROXY="*"` to bypass system/environment proxy settings for localhost alert delivery. Tolerates `CURLE_NOT_BUILT_IN` because the SChannel curl backend may omit proxy support.
- **CA path**: Wraps the CA certificate path/bundle options in a Windows-specific block that tolerates `CURLE_NOT_BUILT_IN`. SChannel uses the Windows Certificate Store automatically and does not support `CURLOPT_CAPATH` / `CURLOPT_CAINFO`.
- **Plugin path resolution**: Replaces the POSIX-only `path[0] != '/'` check with `std::filesystem::path::has_root_path()` so that Windows absolute paths (`C:/...`) are recognized correctly and not prepended with the default plugins directory.

## Prerequisites

Install the following in order. All commands should be run from PowerShell.

### 1. Visual Studio Build Tools

Install [Visual Studio 2022+](https://visualstudio.microsoft.com/) (Community is free) with:
- **Desktop development with C++** workload
  - MSVC v143+ build tools
  - Windows SDK (10.0 or later)
  - C++ CMake tools for Windows

Verify:
```powershell
# Open "Developer Command Prompt for VS" and run:
cl
cmake --version   # requires 3.24+
```

### 2. Git

Install [Git for Windows](https://git-scm.com/download/win).

```powershell
git --version
```

### 3. Rust

```powershell
Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe
.\rustup-init.exe -y
# Restart your shell, then:
rustc --version    # requires 1.80+
cargo --version
```

On ARM64 Windows, rustup installs the native `stable-aarch64-pc-windows-msvc` toolchain. Add the x64 target only if you need cross-compilation:
```powershell
rustup target add x86_64-pc-windows-msvc
```

### 4. vcpkg + curl

vcpkg provides the system curl library used by Falco's `http_output`.

```powershell
git clone https://github.com/microsoft/vcpkg
.\vcpkg\bootstrap-vcpkg.bat

# Install curl for your architecture:
.\vcpkg\vcpkg install curl:x64-windows-static      # x64 hosts
.\vcpkg\vcpkg install curl:arm64-windows-static     # ARM64 hosts

# REQUIRED: set VCPKG_ROOT so the build scripts find it:
$env:VCPKG_ROOT = (Resolve-Path .\vcpkg).Path
# To persist across sessions, add to your PowerShell profile or system env vars.
```

Note: on recent vcpkg baselines, the `schannel` feature name is not required for this use case. The packaging/build scripts only require `libcurl.lib` to be present under the selected triplet.

### 5. .NET Runtime + WiX Toolset (for MSI packaging)

```powershell
winget install Microsoft.DotNet.Runtime.9 --accept-package-agreements --accept-source-agreements
dotnet tool install --global wix
wix eula accept wix7
wix --version
```

WiX v7 requires explicit OSMF EULA acceptance. Without this, packaging fails with `WIX7015`.

## Building

### Quick Build (all components + MSI)

```powershell
# From the repository root (VCPKG_ROOT must be set):
$env:VCPKG_ROOT = 'C:\path\to\vcpkg'
powershell -ExecutionPolicy Bypass -File installers\windows\package.ps1
```

This single command:
1. Compiles all Rust crates for the native architecture (interceptor, plugin DLL, ctl)
2. Clones and builds Falco 0.43.0 from source with patches (~10 min first time, cached after)
3. Stages all files and produces the MSI installer

Output: `build/out/coding-agents-kit-<version>-windows-<arch>.msi`

### Step-by-Step Build

```powershell
$env:VCPKG_ROOT = 'C:\path\to\vcpkg'

# 1. Build Rust crates (auto-detects native target)
cd hooks\claude-code && cargo build --release && cd ..\..
cd plugins\coding-agent-plugin && cargo build --release && cd ..\..
cd tools\coding-agents-kit-ctl && cargo build --release && cd ..\..

# 2. Build Falco from source (~10 minutes first time, cached after)
powershell -ExecutionPolicy Bypass -File installers\windows\build-falco.ps1

# 3. Package MSI (uses pre-built components)
powershell -ExecutionPolicy Bypass -File installers\windows\package.ps1 -SkipRustBuild -SkipFalcoBuild
```

### Build Options

| Flag | Description |
|------|-------------|
| `-Version X.Y.Z` | Override the version (default: workspace `Cargo.toml`) |
| `-Arch x64` or `-Arch arm64` | Target architecture (default: auto-detected from hardware) |
| `-SkipRustBuild` | Skip Rust compilation (use pre-built binaries) |
| `-SkipFalcoBuild` | Skip Falco build (use cached build) |
| `-FalcoExe <path>` | Use a specific pre-built `falco.exe` |

## Installing

### Recommended: `Install-CodingAgentsKit.ps1`

The `Install-CodingAgentsKit.ps1` helper (emitted next to the MSI in `build\out\`) is the recommended path. It runs the MSI silently and, if the product is already installed, opens the MSI maintenance UI instead of forcing a silent reinstall:

```powershell
powershell -ExecutionPolicy Bypass -File build\out\Install-CodingAgentsKit.ps1
```

### Manual `msiexec`

```powershell
msiexec /i build\out\coding-agents-kit-<version>-windows-arm64.msi
```

The MSI runs `postinstall.ps1` automatically via a deferred custom action. No manual follow-up script is required. The post-install step:

- generates the Falco config with resolved Windows paths,
- registers the Claude Code hook,
- adds `bin\` to the user `PATH`,
- registers an auto-start entry for subsequent logins, **and**
- starts the service straight away so Claude Code works immediately.

### First-time verification

The installer already started the service. Open a **new** terminal (so the updated `PATH` is picked up) and verify:

```powershell
coding-agents-kit-ctl status
coding-agents-kit-ctl health
```

Expected output: `OK: pipeline healthy (synthetic event → allow)`.

If the service did not come up (check `ctl status`), start it manually:

```powershell
coding-agents-kit-ctl start
```

### What the installer does

- Deploys binaries, plugin DLL, rules, and scripts to `%LOCALAPPDATA%\coding-agents-kit\`
- Generates Falco configuration with resolved Windows paths
- Registers the Claude Code interceptor hook in `%USERPROFILE%\.claude\settings.json`
- Adds `bin\` to the user `PATH` (persistent, so `coding-agents-kit-ctl` works without full path)
- Registers auto-start via `HKCU\…\Run\CodingAgentsKit`

### Uninstalling

Any of the three paths works — the MSI runs `uninstall.ps1` as a deferred custom action whenever `REMOVE=ALL`, so Apps & Features, `msiexec /x`, and the bundled helper all stop the service, remove the Claude Code hook, remove the auto-start Run-key entry, and clean `bin\` from the user `PATH` before removing files.

The bundled helper is still the most convenient:

```powershell
powershell -ExecutionPolicy Bypass -File Uninstall-CodingAgentsKit.ps1
```

> **Older 0.1.x builds**: MSI packages from before the uninstall custom action was added required the helper script — without it, Apps & Features would leave the Claude Code hook registered and brick Claude Code until `coding-agents-kit-ctl hook remove` was run manually.

## Running Tests

Tests are written in Rust and located in the `tests/` directory:

```powershell
# Run all tests (requires Falco + plugin built)
cargo test --manifest-path tests/Cargo.toml

# Interceptor unit tests only (mock broker, no Falco needed)
cargo test --manifest-path tests/Cargo.toml --test interceptor

# End-to-end tests (requires Falco in PATH or FALCO_BIN set)
cargo test --manifest-path tests/Cargo.toml --test e2e
```

## Directory Layout (installed)

```
%LOCALAPPDATA%\coding-agents-kit\
├── bin\
│   ├── falco.exe                          # Falco rule engine
│   ├── claude-interceptor.exe             # Claude Code hook
│   ├── coding-agents-kit-ctl.exe          # Service management CLI
│   └── coding-agents-kit-launcher.ps1     # Service launcher
├── share\
│   └── coding_agent.dll                   # Falco plugin (source + extract)
├── config\
│   ├── falco.yaml                         # Base Falco config
│   └── falco.coding_agents_plugin.yaml    # Plugin + rules config
├── rules\
│   ├── default\coding_agents_rules.yaml   # Default security rules
│   ├── user\                              # Custom user rules (preserved on upgrade)
│   └── seen.yaml                          # Catch-all rule (required)
├── scripts\
│   ├── postinstall.ps1                    # Post-install setup
│   └── uninstall.ps1                      # Pre-uninstall cleanup
├── run\                                   # Runtime state
└── log\                                   # Falco log files
```

## Known Caveats

- **`VCPKG_ROOT` must be set**: The Falco build script requires `VCPKG_ROOT` pointing to your vcpkg installation. The build fails immediately without it. Set it in your environment or pass it before each build command.

- **`-ExecutionPolicy Bypass`**: Windows default execution policy blocks PowerShell scripts. Always use `powershell -ExecutionPolicy Bypass -File <script>` when running the build, packaging, or install scripts.

- **External tools write to stderr**: `cargo`, `cmd.exe`, and `vswhere.exe` write non-fatal output to stderr. Since the build scripts use `$ErrorActionPreference = 'Stop'`, unguarded external calls fail. The scripts use `2>&1 | ForEach-Object { "$_" }` to merge stderr safely. If you add new external tool calls, follow the same pattern.

- **`broker response timeout` / stale pending requests**: If Claude Code tool calls are denied with a broker timeout and Falco logs show `reaping stale pending request`, the alert round-trip is not completing. The most common cause is a misconfigured `http_output.url` in `falco.yaml` (must match the plugin's `http_port`). Run `coding-agents-kit-ctl health` to confirm the pipeline is healthy after starting the service.

- **`basename()` in rules on Windows**: Falco's `basename()` transformer uses POSIX logic (splits on `/`). Use `basename(tool.real_file_path)` (forward slashes, normalized by the plugin) not `basename(tool.file_path)` (raw, may contain backslashes on Windows).

- **ARM64 hosts and Rust/MSVC arch alignment**: On ARM64 Windows, use matching ARM64 toolchain for Rust host (`stable-aarch64-pc-windows-msvc`) and MSVC (`vcvarsall arm64`) when building ARM64 artifacts. Mixed host/target toolchains can fail with unresolved externals at link time.

- **Falco nested CMake generator on ARM64 hosts**: Falco's `falcosecurity-libs` nested configure may choose a Visual Studio generator/platform different from the top-level build if generator/platform are not forwarded explicitly. Keep nested and top-level generator settings aligned to avoid `VCTargetsPath` / platform mismatch errors.

- **Git Bash PATH shadowing**: Git Bash's `/usr/bin/tar` misinterprets Windows paths with `C:` as a remote host. The build scripts prepend `C:\Windows\System32` to PATH so Windows native `tar.exe` is used. If running build scripts manually from Git Bash, use: `powershell -File <script>`.

- **Falco patches**: Patch files must be normalized from CRLF to LF before `git apply`. The `build-falco.ps1` script handles this automatically.

- **Falco launched from Git Bash**: Falco may segfault when launched directly from Git Bash due to stdin/stdout handling differences. Always launch via PowerShell or `cmd.exe`. The test scripts and launcher handle this correctly.

- **Path separators in rules**: The plugin normalizes all `real_file_path` and `real_cwd` fields to forward slashes (`C:/Users/...`), so Falco rules should use forward slashes for `startswith` and `contains` comparisons.
