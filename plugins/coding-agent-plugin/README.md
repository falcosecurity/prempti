# Coding Agent Plugin

Falco source + extraction plugin with an embedded broker. Receives tool call events from [interceptors](../../hooks/claude-code/), feeds them to Falco's rule engine, and resolves verdicts (allow/deny/ask) via HTTP alert feedback.

See [SPEC.md](../../docs/plugins/coding-agent-plugin/SPEC.md) for the full specification, including sequence diagrams.

## Build

Requires latest stable Rust (the `falco_plugin` SDK tracks latest stable as MSRV).

```bash
cargo build --release
```

Output: `target/release/libcoding_agent.so` (Linux) / `.dylib` (macOS)

## How It Works

The plugin runs inside Falco and manages three background responsibilities:

1. **Unix socket server** — accepts interceptor connections, assigns a `correlation.id`, enqueues events
2. **Falco source plugin** — delivers events to the rule engine via `next_batch`
3. **HTTP alert receiver** — receives Falco alerts via `http_output`, resolves verdicts back to interceptors

## Falco Fields

| Field | Type | Description |
|-------|------|-------------|
| `correlation.id` | u64 | Broker-assigned unique ID (always > 0) |
| `agent.name` | string | Coding agent identifier |
| `agent.hook_event_name` | string | Hook lifecycle point |
| `agent.session_id` | string | Session identifier |
| `agent.permission_mode` | string | Session permission mode (e.g. `default`, `acceptEdits`, `bypassPermissions`) |
| `agent.transcript_path` | string | Session transcript file path (empty when the agent reports `null`) |
| `agent.cwd` | string | Working directory (raw) |
| `agent.real_cwd` | string | Working directory (resolved) |
| `tool.use_id` | string | Tool call ID from Claude Code (raw) |
| `tool.name` | string | Tool name |
| `tool.input` | string | Full tool input as JSON |
| `tool.input_command` | string | Shell command (Bash only) |
| `tool.file_path` | string | File path (raw, Write/Edit/Read) |
| `tool.real_file_path` | string | File path (resolved, Write/Edit/Read) |

## Configuration

Plugin config via `falco.yaml` → `init_config`:

```yaml
init_config:
  mode: guardrails           # "guardrails" or "monitor"
  socket_path: ${HOME}/.coding-agents-kit/run/broker.sock
  http_port: 2802
  deny_tags: [coding_agent_deny]
  ask_tags: [coding_agent_ask]
  seen_tags: [coding_agent_seen]
```

## Operational Modes

- **Guardrails** (default): Rules evaluated, verdicts enforced
- **Monitor**: Rules evaluated and logged, all verdicts resolve as allow

Switch via `coding-agents-kit-ctl mode <guardrails|monitor>`.

## Required Falco Configuration

- `rule_matching: all` — both deny/ask rules and the catch-all seen rule must fire per event
- `json_output: true` — HTTP alerts must be JSON for tag/field parsing
- `http_output` pointing to `http://127.0.0.1:2802`
- `--disable-source syscall` on the command line
