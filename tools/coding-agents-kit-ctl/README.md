# coding-agents-kit-ctl

CLI tool for managing the coding-agents-kit service. Controls hook registration, operational mode switching, supervisor lifecycle, and platform service integration (systemd / launchd / Windows Run key).

## Build

```bash
cargo build --release
```

Binary: `target/release/coding-agents-kit-ctl`

## Commands

### Hook Management

```bash
coding-agents-kit-ctl hook add       # Register interceptor in Claude Code settings.json
coding-agents-kit-ctl hook remove    # Remove interceptor from Claude Code settings.json
coding-agents-kit-ctl hook status    # Check if the hook is registered
```

### Mode Switching

```bash
coding-agents-kit-ctl mode                # Show current mode
coding-agents-kit-ctl mode guardrails     # Switch to guardrails (deny/ask enforced)
coding-agents-kit-ctl mode monitor        # Switch to monitor (all verdicts allow, alerts logged)
```

Mode changes rewrite the plugin config YAML and then restart the service (stop + start). The brief restart window is fail-closed.

### Service Management

```bash
coding-agents-kit-ctl start     # Start the supervisor (which spawns Falco)
coding-agents-kit-ctl stop      # Stop the service
coding-agents-kit-ctl restart   # Stop and start (use after editing config files)
coding-agents-kit-ctl enable    # Enable auto-start on login
coding-agents-kit-ctl disable   # Disable auto-start
coding-agents-kit-ctl status    # Show service status
```

### Supervisor

```bash
coding-agents-kit-ctl daemon [--prefix PATH]
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
coding-agents-kit-ctl logs                 # Print Falco stdout log, exit
coding-agents-kit-ctl logs --tail=100      # Print last 100 lines, exit
coding-agents-kit-ctl logs -f              # Print full log, then stream new output
coding-agents-kit-ctl logs -f --tail=100   # Print last 100 lines, then stream
coding-agents-kit-ctl logs --err [flags]   # Same, but against the stderr log
```

`logs` defaults to a snapshot-and-exit (like `kubectl logs` / `docker logs`). Pass `-f` / `--follow` to stream. `--tail=N` limits the initial output. The `--err` flag targets `falco.err` instead of `falco.log`.

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
