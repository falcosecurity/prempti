# premptictl

CLI tool for managing the Prempti service. Controls hook registration, operational mode switching, supervisor lifecycle, and platform service integration (systemd / launchd / Windows Run key).

## Build

```bash
cargo build --release
```

Binary: `target/release/premptictl`

## Commands

### Hook Management

```bash
premptictl hook add       # Register interceptor in Claude Code settings.json
premptictl hook remove    # Remove interceptor from Claude Code settings.json
premptictl hook status    # Check if the hook is registered
```

### Mode Switching

```bash
premptictl mode                # Show current mode
premptictl mode guardrails     # Switch to guardrails (deny/ask enforced)
premptictl mode monitor        # Switch to monitor (all verdicts allow, alerts logged)
```

Mode changes rewrite the plugin config YAML and then restart the service (stop + start). The brief restart window is fail-closed.

### Service Management

```bash
premptictl start     # Start the supervisor (which spawns Falco)
premptictl stop      # Stop the service
premptictl restart   # Stop and start (use after editing config files)
premptictl enable    # Enable auto-start on login
premptictl disable   # Disable auto-start
premptictl status    # Show service status
```

### Supervisor

```bash
premptictl daemon [--prefix PATH]
                              [--config PATH]
                              [--log-rotate-bytes N]
                              [--log-rotate-keep N]
                              [--stop-timeout-secs N]
```

`daemon` is the supervisor process: it spawns Falco, captures and rotates its
stdout/stderr into `log/falco.log` and `log/falco.err`, owns the Claude Code
hook lifecycle, and exposes a control socket at `run/supervisor.sock` (commands:
`STOP`, `STATUS`).

Normally invoked by the platform service (systemd unit on Linux, launchd plist on
macOS, Windows Run key). Advanced users can run it manually for debugging or
non-managed setups. Only one supervisor at a time per prefix because
`supervisor.sock` is a singleton. Configuration defaults live in
`<prefix>/config/supervisor.yaml`; CLI flags override the file.

### Viewing Logs

```bash
premptictl logs                 # Print last 100 lines of Falco stdout, exit
premptictl logs --tail=500      # Override the default — print last 500 lines
premptictl logs -f              # Print last 100 lines, then stream new output
premptictl logs -f --tail=20    # Print last 20 lines, then stream
premptictl logs --err [flags]   # Same, but against the stderr log
```

`logs` defaults to a snapshot-and-exit (like `kubectl logs` / `docker logs`) of the **last 100 lines**. Pass `-f` / `--follow` to stream new output afterwards. `--tail=N` overrides the line count (use a large value if you want the entire file). The `--err` flag targets `falco.err` instead of `falco.log`.

## Service Lifecycle

The platform service (systemd unit on Linux, launchd plist on macOS, Windows
Run-key + launcher.ps1 wrapper) starts the supervisor (`ctl daemon`), not
Falco directly. The supervisor:

1. Registers the Claude Code hook (`hook::add`).
2. Spawns Falco with stdout/stderr piped back into the supervisor.
3. Captures Falco output to `log/falco.log` / `log/falco.err`, rotating at
   the configured size cap.
4. Listens on `run/supervisor.sock` for `STOP` and `STATUS` requests.
5. On stop, sends Falco a graceful shutdown signal, drains the pipes,
   removes the hook, and exits with Falco's exit code.

This ties the hook lifecycle to the service — the interceptor is only active
while the supervisor is running.

## Fail-Closed Warning

The interceptor runs in fail-closed mode. When the hook is registered but the service is not running (or is restarting), **all Claude Code tool calls are blocked**. The `hook add` and `mode` commands print explicit warnings about this.
