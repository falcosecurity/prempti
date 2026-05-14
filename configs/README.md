# Falco Configuration

Source configuration files for Prempti. Installed to `~/.prempti/config/`.

## Files

### `falco.yaml`

Base Falco configuration. Provides complete isolation from system-wide Falco defaults (`/etc/falco/`).

Key settings:
- `engine.kind: nodriver` — no kernel driver
- `rule_matching: all` — multiple rules fire per event (required for verdict resolution)
- `json_output: true` — required for HTTP alert parsing
- `watch_config_files: false` — disabled deliberately (the upstream feature is Linux-only). Config edits take effect at the next service restart; `premptictl mode` and other config-changing commands handle the restart explicitly.
- All non-essential outputs and services disabled

### `falco.coding_agents_plugin.yaml`

Plugin-specific configuration fragment. Merged into `falco.yaml` via `config_files` (append strategy).

Contains:
- Plugin definition (`coding_agent`) with `init_config` (mode, socket path, HTTP port, verdict tags)
- `load_plugins` list
- `rules_files` (default rules → user rules → seen rule)
- `http_output` configuration

#### `passthrough` (Experimental)

Embedding-only knob. When `true`, all interceptor requests are resolved
as `allow` immediately at register, without waiting for rule evaluation.
Events are still enqueued for Falco so observability via `http_output`
and `falco.log` is preserved. Defaults to `false`.

Use this only when embedding Prempti inside a host agent that handles
alerts via its own pipeline.

This is distinct from `mode: monitor`: monitor waits for rule
evaluation and then forces an `allow` verdict (synchronous, so
would-deny/would-ask log lines fire), while passthrough short-circuits
at register and skips the wait entirely.

## Path Expansion

All paths use `${HOME}` expansion (Falco native, `${VAR}` syntax). No hardcoded paths.

## Running Falco

```bash
falco -c ~/.prempti/config/falco.yaml --disable-source syscall
```

The systemd service handles this automatically.
