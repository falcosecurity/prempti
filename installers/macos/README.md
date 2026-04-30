# macOS Installer

Packaging and installation scripts for Prempti on macOS (Apple Silicon and Intel).

## Prerequisites

Building from source requires:

- Rust (latest stable)
- CMake >= 3.24
- Xcode Command Line Tools
- OpenSSL via Homebrew

```bash
xcode-select --install
brew install cmake openssl@3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Packaging

Build a distributable package from the repo root:

```bash
make macos              # Native architecture of the host
make macos-aarch64      # Apple Silicon
make macos-x86_64       # Intel (native on Intel, or Rosetta cross-compile on Apple Silicon)
make macos-universal    # Universal binary (requires Rosetta + x86_64 Homebrew)
```

Or directly:

```bash
bash installers/macos/package.sh                      # Native architecture
bash installers/macos/package.sh --target aarch64      # Apple Silicon
bash installers/macos/package.sh --target x86_64       # Intel
```

Output: `build/prempti-<version>-darwin-<arch>.{tar.gz,pkg}`

The package is self-contained: Falco binary (built from source), interceptor, plugin, ctl tool, configs (`falco.yaml`, `falco.coding_agents_plugin.yaml`, `supervisor.yaml`), rules, launchd plist, and installer.

### Falco Build from Source

Falco does not ship pre-built macOS binaries. The first build compiles Falco from source (~5 min). Subsequent builds use the cached binary.

```bash
bash installers/macos/build-falco.sh                 # Native architecture
bash installers/macos/build-falco.sh --arch x86_64   # Cross-compile for Intel
bash installers/macos/build-falco.sh --force          # Rebuild from scratch
```

The build applies a patch (`falco-macos-http-output.patch`) to enable http_output on macOS with `MINIMAL_BUILD=ON`.

## Installation

> **Migrating from `coding-agents-kit`?** Prempti does not migrate or remove existing `coding-agents-kit` installations. Uninstall `coding-agents-kit` first to avoid duplicate services or stale Claude Code hooks.

### From .pkg (recommended)

```bash
open prempti-<version>-darwin-universal.pkg
```

The macOS Installer wizard guides you through the setup.

### From tar.gz

```bash
tar xzf prempti-<version>-darwin-<arch>.tar.gz
cd prempti-<version>-darwin-<arch>
bash install.sh
```

### Options

```bash
bash install.sh --dry-run                # Show what would be done
```

### What It Does

1. Verifies macOS and architecture match the package
2. Copies binaries (`falco`, `claude-interceptor`, `premptictl`), plugin, configs, and rules to `~/.prempti/`
3. Installs and loads a launchd user agent (`dev.falcosecurity.prempti`) that runs `premptictl daemon --prefix <prefix>`
4. The supervisor (`ctl daemon`) registers the Claude Code hook on start and removes it on stop

### Gatekeeper

Since the binaries are not code-signed, macOS Gatekeeper may block them (especially when installing from a tarball downloaded via a browser). Go to **System Settings > Privacy & Security** and allow the blocked binary, or clear the quarantine attribute from the entire install tree — both the executables in `bin/` and the plugin library in `share/` can be flagged:

```bash
xattr -dr com.apple.quarantine ~/.prempti
```

## Uninstallation

```bash
~/.prempti/bin/premptictl uninstall
~/.prempti/bin/premptictl uninstall --keep-user-rules    # Preserve custom rules
```

## Installation Directory

```
~/.prempti/
├── bin/                    # falco, claude-interceptor, premptictl
├── config/                 # falco.yaml, falco.coding_agents_plugin.yaml,
│                           # supervisor.yaml (preserved on upgrade)
├── log/                    # falco.log[.1..N], falco.err[.1..N] (rotated by supervisor)
├── run/                    # broker.sock, supervisor.sock (runtime)
├── share/                  # libcoding_agent.dylib
└── rules/
    ├── default/            # Default rules (overwritten on upgrade)
    ├── user/               # Custom rules (preserved on upgrade)
    └── seen.yaml           # Catch-all rule (required)
```

The launchd plist is installed to `~/Library/LaunchAgents/dev.falcosecurity.prempti.plist`.

## Service Management

launchd invokes `premptictl daemon --prefix <prefix>` directly — no shell wrapper. The supervisor handles hook registration on start and removal on stop, captures Falco's stdout/stderr into rotating log files, and exposes a control socket at `run/supervisor.sock` for graceful shutdown. SIGTERM from launchd reaches the supervisor, which then orchestrates the cleanup chain.

## Files

| File | Purpose |
|------|---------|
| `package.sh` | Build script: compiles Rust components and Falco, creates tar.gz and .pkg |
| `install.sh` | Installer: copies files, sets up launchd, kicks off the supervisor |
| `build-falco.sh` | Builds Falco from source with http_output patch |
| `falco-macos-http-output.patch` | CMake patch enabling http_output on macOS |
| `dev.falcosecurity.prempti.plist` | launchd user agent template (invokes `ctl daemon`) |
