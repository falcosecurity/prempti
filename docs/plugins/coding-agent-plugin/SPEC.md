# Coding Agent Plugin — Specification

| Field    | Value                        |
|----------|------------------------------|
| Library  | `libcoding_agent.so` (Linux) / `libcoding_agent.dylib` (macOS) / `coding_agent.dll` (Windows) |
| Source   | `plugins/coding-agent-plugin/` |
| Language | Rust (falco_plugin SDK v0.5) |

## Overview

The coding agent plugin is a Falco source + extraction plugin with an embedded broker. It receives tool call events from interceptors, feeds them to Falco's rule engine, collects alert verdicts via HTTP, and responds to interceptors with allow/deny/ask decisions.

The plugin is the central component of coding-agents-kit — it bridges the interceptor (stateless CLI) with the Falco rule engine (policy evaluation).

## Design Principles

1. **Broker embedded in plugin**: No separate broker process. Falco is the only long-running process.
2. **Verdict via HTTP alerts**: All verdict signals flow through Falco's `http_output`. No parsing capability needed.
3. **Fail-closed**: If the broker cannot process an event, it responds deny.
4. **Monitor mode**: Rules evaluate and log, but all verdicts resolve as allow.

## Sequence Diagram

```
Interceptor          Socket Server       Event Queue       Falco Engine        HTTP Output        HTTP Server         Broker
    │                     │                   │                 │                   │                  │                 │
    │── connect ─────────▶│                   │                 │                   │                  │                 │
    │── JSON request ────▶│                   │                 │                   │                  │                 │
    │                     │── register ──────────────────────────────────────────────────────────────▶│ (pending map)   │
    │                     │── enqueue ───────▶│                 │                   │                  │                 │
    │                     │                   │                 │                   │                  │                 │
    │                     │                   │◀─ next_batch ──│                   │                  │                 │
    │                     │                   │── events ──────▶│                   │                  │                 │
    │                     │                   │                 │                   │                  │                 │
    │                     │                   │                 │── extract_fields ─▶│ (plugin)        │                 │
    │                     │                   │                 │◀─ field values ───│                  │                 │
    │                     │                   │                 │                   │                  │                 │
    │                     │                   │                 │── rule evaluation │                  │                 │
    │                     │                   │                 │                   │                  │                 │
    │                     │                   │                 │ [deny rule match]  │                  │                 │
    │                     │                   │                 │── enqueue alert ──▶│                  │                 │
    │                     │                   │                 │                   │── POST alert ───▶│                 │
    │                     │                   │                 │                   │◀─ 200 OK ────────│                 │
    │                     │                   │                 │                   │                  │── apply_deny ──▶│
    │                     │                   │                 │                   │                  │                 │── resolve
    │◀── JSON verdict ────│◀──────────────────────────────────────────────────────────────────────────│◀────────────────│
    │                     │                   │                 │                   │                  │                 │
    │                     │                   │                 │ [seen rule match]  │                  │                 │
    │                     │                   │                 │── enqueue alert ──▶│                  │                 │
    │                     │                   │                 │                   │── POST alert ───▶│                 │
    │                     │                   │                 │                   │◀─ 200 OK ────────│                 │
    │                     │                   │                 │                   │                  │── apply_seen ──▶│
    │                     │                   │                 │                   │                  │                 │── (already resolved)
    │                     │                   │                 │                   │                  │                 │
```

**Allow flow** (no deny/ask rules match):

```
Interceptor          Socket Server       Event Queue       Falco Engine        HTTP Server         Broker
    │                     │                   │                 │                   │                 │
    │── JSON request ────▶│                   │                 │                   │                 │
    │                     │── register ──────────────────────────────────────────────────────────────▶│
    │                     │── enqueue ───────▶│                 │                   │                 │
    │                     │                   │◀─ next_batch ──│                   │                 │
    │                     │                   │── events ──────▶│                   │                 │
    │                     │                   │                 │── rule evaluation │                 │
    │                     │                   │                 │   (no deny/ask)   │                 │
    │                     │                   │                 │ [seen rule match]  │                 │
    │                     │                   │                 │── enqueue alert ──▶│                 │
    │                     │                   │                 │                   │── apply_seen ──▶│
    │                     │                   │                 │                   │                 │── resolve (allow)
    │◀── JSON verdict ────│◀────────────────────────────────────────────────────────────────────────│
    │                     │                   │                 │                   │                 │
```

## Plugin Capabilities

| Capability | Trait | Purpose |
|------------|-------|---------|
| Sourcing | `SourcePlugin` + `SourcePluginInstance` | Delivers events from interceptors to Falco |
| Extraction | `ExtractPlugin` | Exposes event fields for rule conditions and output |

## Falco Integration

| Parameter | Value |
|-----------|-------|
| Plugin name | `coding_agent` |
| Plugin ID | `999` (development; register for production) |
| Event source | `coding_agent` |
| Required config | `rule_matching: all`, `json_output: true` |
| Alert delivery | `http_output` to `http://127.0.0.1:2802` |
| Run command | `falco -c <config> --disable-source syscall` |

## Components

### Socket Server (`socket_server.rs`)

Background thread spawned in `Plugin::new()`. Listens on a Unix domain socket for interceptor connections.

- **Bind**: `config.socket_path` (default `~/.coding-agents-kit/run/broker.sock`)
- **Protocol**: Newline-terminated JSON, one request per connection
- **Read timeout**: 5 seconds (prevents slow connections from blocking the accept loop)
- **Flow**: read request → validate → assign `correlation.id` → register in broker → enqueue event

### Event Queue (`crossbeam-channel`)

Bounded channel (capacity 1024) connecting the socket server thread to Falco's `next_batch` calls.

- **Producer**: Socket server thread (via `try_send`)
- **Consumer**: `next_batch` (via `recv_timeout` + `try_recv` drain)
- **Backpressure**: Full channel → immediate deny to interceptor
- **Wakeup**: Event-driven via `recv_timeout(100ms)` — no polling

### Source Plugin (`source.rs`)

Implements `SourcePlugin` + `SourcePluginInstance`.

- **`next_batch`**: Blocks on `recv_timeout(100ms)` for the first event, then drains up to 31 more via `try_recv`. Returns `Timeout` if no events, `Eof` if channel disconnected.
- **Event encoding**: `<correlation_id>\n<agent_name>\n<raw_event_json>` as raw bytes in the plugin event payload.

### Extract Plugin (`extract.rs`)

Implements `ExtractPlugin` with per-event caching via `ExtractContext`.

| Field | Type | Source |
|-------|------|--------|
| `correlation.id` | u64 | Broker-assigned monotonic counter (from payload header) |
| `agent.name` | string | Wire protocol `agent_name` field |
| `agent.hook_event_name` | string | `event.hook_event_name` |
| `agent.session_id` | string | `event.session_id` |
| `agent.cwd` | string | `event.cwd` (raw) |
| `agent.real_cwd` | string | `event.cwd` resolved via `canonicalize` + lexical fallback |
| `tool.use_id` | string | `event.tool_use_id` (raw from Claude Code) |
| `tool.name` | string | `event.tool_name` |
| `tool.input` | string | `event.tool_input` as JSON string |
| `tool.input_command` | string | `event.tool_input.command` (Bash only) |
| `tool.file_path` | string | `event.tool_input.file_path` (raw, Write/Edit/Read only) |
| `tool.real_file_path` | string | Resolved absolute path (Write/Edit/Read only) |
| `tool.mcp_server` | string | Extracted from `mcp__<server>__<tool>` pattern |

Event source restriction: `CodingAgentPayload` with `EventSource::SOURCE = Some("coding_agent")` prevents extraction from syscall events.

### HTTP Alert Receiver (`http_server.rs`)

Background thread spawned in `Plugin::new()`. Receives Falco JSON alerts via `http_output`.

- **Bind**: `127.0.0.1:config.http_port` (default 2802)
- **Library**: `tiny_http` (synchronous, minimal)
- **Response**: 200 OK immediately (must be fast — blocks Falco's output worker)
- **Body limit**: 1 MB
- **Alert parsing**: Extract `correlation.id` from `output_fields` (u64), classify tags

### Broker (`broker.rs`)

Tracks pending requests and resolves verdicts. Shared via `Arc<Broker>` across all threads.

- **Pending map**: `DashMap<u64, PendingRequest>` keyed by `correlation.id`
- **Correlation ID**: Monotonic `AtomicU64` counter (starts at 1, always > 0)
- **Wire ID**: The interceptor's original request `id` (stored per-request, used in the verdict response)
- **Monitor mode**: `AtomicBool`, set from plugin config on init

### Verdict Resolution

Tags in Falco alerts determine the verdict:

| Tag | Default | Verdict | Behavior |
|-----|---------|---------|----------|
| `coding_agent_deny` | configurable | Deny | Resolve immediately, remove from pending |
| `coding_agent_ask` | configurable | Ask | Escalate (deny > ask), wait for seen |
| `coding_agent_seen` | configurable | Seen | Resolve with best verdict (allow if no deny/ask) |

Escalation: `deny > ask > allow`. Multiple rules can match the same event (`rule_matching: all`).

**Alert ordering guarantee**: Falco enqueues alerts in rule-load order, the output worker delivers in FIFO order. Deny/ask alerts (from rules loaded before `seen.yaml`) always arrive before the seen alert.

**Monitor mode**: `apply_deny` and `apply_ask` log but don't resolve. `apply_seen` always resolves as allow.

### Verdict Reason Format

The reason string included in deny/ask verdict responses is constructed from the Falco JSON alert:

```
<rule name>: <message field>
```

The `message` field (from `json_include_message_property: true`) contains the rule output without the timestamp/priority prefix, plus any text appended by `append_output`. The `output` field is excluded (`json_include_output_property: false`).

The `correlation.id` field is declared with `add_output()` in the plugin's field schema, making it a suggested output field that Falco automatically includes in `output_fields` for every alert.

Example reason seen by the coding agent:
```
Deny writing to sensitive paths: Falco blocked writing to /etc/passwd because it is a sensitive path | For AI Agents: inform the user that this action was flagged by a Falco security rule | correlation=%correlation.id
```

## Configuration

Plugin config via `falco.yaml` → `init_config`:

```yaml
init_config:
  mode: enforcement        # "enforcement" or "monitor"
  socket_path: ${HOME}/.coding-agents-kit/run/broker.sock   # Linux / macOS
  http_port: 2802
  deny_tags: [coding_agent_deny]
  ask_tags: [coding_agent_ask]
  seen_tags: [coding_agent_seen]
```

All fields have defaults. `${HOME}` is expanded by Falco before reaching the plugin.

Windows defaults (rendered by `postinstall.ps1` with absolute paths and forward slashes — `%LOCALAPPDATA%` is not expanded by Falco):

```yaml
init_config:
  mode: enforcement
  socket_path: C:/Users/<user>/AppData/Local/coding-agents-kit/run/broker.sock
  http_port: 2802
```

On startup the plugin refuses to clobber a socket already held by another running instance and refuses to bind an HTTP port already in use — both surface as clean plugin init errors, not panics, so a stray `falco.exe -V ...` cannot take down a running coding-agents-kit service.

Mode switching via `coding-agents-kit-ctl mode <enforcement|monitor>` modifies this file. Falco's `watch_config_files: true` detects the change and performs a full restart (destroy → init).

## Catch-all Seen Rule

Required for verdict resolution. Must be loaded as the last rule file.

```yaml
- rule: Coding Agent Event Seen
  condition: correlation.id > 0
  output: Event seen
  priority: DEBUG
  source: coding_agent
  tags: [coding_agent_seen]
```

Since `correlation.id` is a broker-assigned monotonic counter starting at 1, this condition is always true for every event generated by the broker.

**Critical**: The seen rule uses `priority: DEBUG`. Falco's `min_priority` (aka `priority`) config filters rules at load time — if set above DEBUG, the seen rule is silently dropped and verdict resolution breaks (all tool calls hang). The plugin config fragment (`falco.coding_agents_plugin.yaml`) forces `priority: debug` to prevent this.

## Known Limitations

1. **Socket server is single-threaded**: One slow connection blocks the accept loop for other interceptors. Mitigated by the 5s read timeout.
2. **No pending request TTL**: If a seen alert never arrives for an event (e.g., Falco crashes mid-evaluation), the pending request leaks. The interceptor will timeout and fail-closed.
3. **Falco restart during config change**: `watch_config_files` triggers a full restart (~2-3s). During this window, the broker socket is unavailable and interceptors fail-closed.
4. **Background threads not joined on destroy**: Plugin threads may briefly outlive the plugin struct during Falco restart. The .so is not unloaded, so no segfault, but resources may leak temporarily.
