# Linux Installer

Packaging and installation scripts for coding-agents-kit on Linux (x86_64 and aarch64).

## Packaging

Build a distributable tar.gz from the repo root:

```bash
make linux-x86_64     # Build for x86_64
make linux-aarch64    # Build for aarch64 (requires cross toolchain)
make linux            # Build both
```

Or directly:

```bash
bash installers/linux/package.sh                    # Native architecture
bash installers/linux/package.sh --target aarch64   # Cross-compile for aarch64
```

Output: `build/coding-agents-kit-<version>-linux-<arch>.tar.gz`

The package is self-contained: Falco binary, interceptor, plugin, ctl tool, configs, rules, systemd service template, and installer scripts.

## Installation

```bash
tar xzf coding-agents-kit-<version>-linux-x86_64.tar.gz
cd coding-agents-kit-<version>-linux-x86_64
bash install.sh
```

### Options

```bash
bash install.sh --prefix=/custom/path    # Install to a custom directory
bash install.sh --dry-run                # Show what would be done
```

If `dialog` is available, the installer provides an interactive confirmation prompt.

### What It Does

1. Copies binaries (`falco`, `claude-interceptor`, `coding-agents-kit-ctl`), plugin, configs, and rules to `~/.coding-agents-kit/`
2. Installs and starts a systemd user service (`coding-agents-kit.service`)
3. Enables auto-start on login (`loginctl enable-linger`)
4. Registers the Claude Code hook via `coding-agents-kit-ctl hook add`

## Uninstallation

```bash
~/.coding-agents-kit/bin/coding-agents-kit-ctl uninstall
~/.coding-agents-kit/bin/coding-agents-kit-ctl uninstall --keep-user-rules    # Preserve custom rules
```

## Installation Directory

```
~/.coding-agents-kit/
├── bin/                    # falco, claude-interceptor, coding-agents-kit-ctl
├── config/                 # falco.yaml, falco.coding_agents_plugin.yaml
├── run/                    # broker.sock (runtime)
├── share/                  # libcoding_agent.so
└── rules/
    ├── default/            # Default rules (overwritten on upgrade)
    ├── user/               # Custom rules (preserved on upgrade)
    └── seen.yaml           # Catch-all rule (required)
```

## Files

| File | Purpose |
|------|---------|
| `package.sh` | Build script: compiles Rust components, downloads Falco, creates tar.gz |
| `install.sh` | Installer: copies files, sets up systemd, registers hook |
| `coding-agents-kit.service` | systemd user service unit template |
