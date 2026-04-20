# macOS Installer

Packaging and installation scripts for coding-agents-kit on macOS (Apple Silicon and Intel).

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
make macos-aarch64      # Apple Silicon
make macos-x86_64       # Intel (must build on matching hardware or via Rosetta)
make macos-universal    # Universal binary (requires Rosetta + x86_64 Homebrew)
```

Or directly:

```bash
bash installers/macos/package.sh                      # Native architecture
bash installers/macos/package.sh --target aarch64      # Apple Silicon
bash installers/macos/package.sh --target x86_64       # Intel
```

Output: `build/coding-agents-kit-<version>-darwin-<arch>.{tar.gz,pkg}`

The package is self-contained: Falco binary (built from source), interceptor, plugin, ctl tool, configs, rules, launchd plist, launcher script, and installer.

### Falco Build from Source

Falco does not ship pre-built macOS binaries. The first build compiles Falco from source (~5 min). Subsequent builds use the cached binary.

```bash
bash installers/macos/build-falco.sh                 # Native architecture
bash installers/macos/build-falco.sh --arch x86_64   # Cross-compile for Intel
bash installers/macos/build-falco.sh --force          # Rebuild from scratch
```

The build applies a patch (`falco-macos-http-output.patch`) to enable http_output on macOS with `MINIMAL_BUILD=ON`.

## Installation

### From .pkg (recommended)

```bash
open coding-agents-kit-<version>-darwin-universal.pkg
```

The macOS Installer wizard guides you through the setup.

### From tar.gz

```bash
tar xzf coding-agents-kit-<version>-darwin-aarch64.tar.gz
cd coding-agents-kit-<version>-darwin-aarch64
bash install.sh
```

### Options

```bash
bash install.sh --prefix=/custom/path    # Install to a custom directory
bash install.sh --dry-run                # Show what would be done
```

### What It Does

1. Verifies macOS and architecture match the package
2. Copies binaries (`falco`, `claude-interceptor`, `coding-agents-kit-ctl`), plugin, configs, and rules to `~/.coding-agents-kit/`
3. Installs and loads a launchd user agent (`dev.falcosecurity.coding-agents-kit`)
4. Registers the Claude Code hook via a launcher wrapper script

### Gatekeeper

Since the binaries are not code-signed, macOS Gatekeeper may block them. Go to **System Settings > Privacy & Security** and allow the blocked binary, or run:

```bash
xattr -dr com.apple.quarantine ~/.coding-agents-kit/bin/*
```

## Uninstallation

```bash
~/.coding-agents-kit/bin/coding-agents-kit-ctl uninstall
~/.coding-agents-kit/bin/coding-agents-kit-ctl uninstall --keep-user-rules    # Preserve custom rules
```

## Installation Directory

```
~/.coding-agents-kit/
├── bin/                    # falco, claude-interceptor, coding-agents-kit-ctl,
│                           # coding-agents-kit-launcher.sh
├── config/                 # falco.yaml, falco.coding_agents_plugin.yaml
├── log/                    # falco.log (stdout), falco.err (stderr)
├── run/                    # broker.sock (runtime)
├── share/                  # libcoding_agent.dylib
└── rules/
    ├── default/            # Default rules (overwritten on upgrade)
    ├── user/               # Custom rules (preserved on upgrade)
    └── seen.yaml           # Catch-all rule (required)
```

The launchd plist is installed to `~/Library/LaunchAgents/dev.falcosecurity.coding-agents-kit.plist`.

## Service Management

The launcher wrapper script (`coding-agents-kit-launcher.sh`) handles hook lifecycle — it registers the hook before starting Falco and removes it on exit via `trap`. Falco runs in the foreground (not `exec`) so the trap fires on SIGTERM from launchd.

## Files

| File | Purpose |
|------|---------|
| `package.sh` | Build script: compiles Rust components and Falco, creates tar.gz and .pkg |
| `install.sh` | Installer: copies files, sets up launchd, registers hook |
| `build-falco.sh` | Builds Falco from source with http_output patch |
| `falco-macos-http-output.patch` | CMake patch enabling http_output on macOS |
| `dev.falcosecurity.coding-agents-kit.plist` | launchd user agent template |
| `coding-agents-kit-launcher.sh` | Wrapper script for hook lifecycle management |
