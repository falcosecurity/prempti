# coding-agents-kit-ctl

CLI tool for managing the coding-agents-kit service. Controls hook registration, operational mode switching, and systemd service lifecycle.

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
coding-agents-kit-ctl start     # Start the systemd user service
coding-agents-kit-ctl stop      # Stop the service
coding-agents-kit-ctl enable    # Enable auto-start on login
coding-agents-kit-ctl disable   # Disable auto-start
coding-agents-kit-ctl status    # Show service status
```

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

The systemd service (`coding-agents-kit.service`) uses this tool for hook management:

- `ExecStartPost`: `coding-agents-kit-ctl hook add` — registers the hook when Falco starts
- `ExecStopPost`: `coding-agents-kit-ctl hook remove` — removes the hook when Falco stops

This ties the hook lifecycle to the service — the interceptor is only active while Falco is running.

## Fail-Closed Warning

The interceptor runs in fail-closed mode. When the hook is registered but the service is not running (or is restarting), **all Claude Code tool calls are blocked**. The `hook add` and `mode` commands print explicit warnings about this.
