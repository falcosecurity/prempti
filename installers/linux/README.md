# Linux Installer

Packaging and installation scripts for Prempti on Linux (x86_64 and aarch64).

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

Output: `build/prempti-<version>-linux-<arch>.tar.gz`

The package is self-contained: Falco binary, interceptor, plugin, ctl tool, configs, rules, systemd service template, and installer scripts.

## Installation

```bash
tar xzf prempti-<version>-linux-x86_64.tar.gz
cd prempti-<version>-linux-x86_64
bash install.sh
```

### Options

```bash
bash install.sh --dry-run                # Show what would be done
```

If `dialog` is available, the installer provides an interactive confirmation prompt.

### What It Does

1. Copies binaries (`falco`, `claude-interceptor`, `premptictl`), plugin, configs, and rules to `~/.prempti/`
2. Installs and starts a systemd user service (`prempti.service`)
3. Enables auto-start on login (`loginctl enable-linger`)
4. Registers the Claude Code hook via `premptictl hook add`

## Uninstallation

```bash
~/.prempti/bin/premptictl uninstall
~/.prempti/bin/premptictl uninstall --keep-user-rules    # Preserve custom rules
```

## Installation Directory

```
~/.prempti/
├── bin/                    # falco, claude-interceptor, premptictl
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
| `prempti.service` | systemd user service unit template |
