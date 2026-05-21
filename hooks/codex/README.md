# Codex Interceptor

Stateless CLI binary invoked by the OpenAI Codex CLI's hook system on every tool call. It sends the hook event to the prempti plugin broker via Unix socket and maps the verdict back to Codex's per-event hook response format.

The interceptor is a thin passthrough — all field extraction, path resolution, and policy evaluation happens in the [plugin broker](../../plugins/coding-agents-plugin/).

> **Status: experimental.** Codex support is in early development and not yet wired into the installers. Manual hook registration only.

## Build

```bash
cargo build --release
```

Binary: `target/release/codex-interceptor`

From the workspace root:

```bash
make build-codex-interceptor
```

## How It Works

The interceptor mounts on **two** Codex hook events:

| Hook event | Codex purpose | Interceptor responsibility |
|------------|---------------|----------------------------|
| `PreToolUse` | Fires before every tool dispatch | Hard-block deny rules; pass ask/allow through |
| `PermissionRequest` | Fires in the approval path before guardian/UI prompts | Surface ask/deny rules to the user via Codex's approval UX |

Both hooks send the same wire envelope to the broker (`agent_name = "codex"`); the broker runs the same Falco rules regardless of which event arrived. Only the **output translation** is per-event.

### Verdict translation

| Falco verdict | `PreToolUse` | `PermissionRequest` |
|---------------|--------------|---------------------|
| `allow` | `allow` | `allow` |
| `deny` | `deny` (with reason) | `deny` (with reason) |
| `ask` | `allow` (passes through to the approval flow) | `deny` (rule reason surfaced as the approval-denial message) |

This preserves three-verdict UX on Codex without collapsing `ask` to `deny` at `PreToolUse`. The cost is two registered hooks per tool call instead of one.

### Wire shape (Codex → interceptor)

Codex sends **snake_case** JSON over stdin. Both events share most fields:

```json
{
  "session_id": "…",
  "turn_id": "…",
  "transcript_path": null,
  "cwd": "/work",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5-codex",
  "permission_mode": "default",
  "tool_name": "Bash",
  "tool_input": { "command": "ls -la" },
  "tool_use_id": "…"
}
```

`PermissionRequest` omits `tool_use_id`; the interceptor falls back to `turn_id` as the broker correlation ID.

### Wire shape (interceptor → Codex)

Codex expects **camelCase** JSON on stdout.

`PreToolUse`:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Falco blocked …"
  }
}
```

`PermissionRequest`:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": { "behavior": "deny", "message": "Falco blocked …" }
  }
}
```

## Hook registration (Codex CLI)

The installer does not yet register Codex hooks automatically. Add them manually to your Codex configuration:

```toml
[[hooks]]
event = "PreToolUse"
command = "~/.prempti/bin/codex-interceptor"

[[hooks]]
event = "PermissionRequest"
command = "~/.prempti/bin/codex-interceptor"
```

(Codex's hooks configuration is under iteration upstream — consult `codex --help` for the current syntax.)

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PREMPTI_SOCKET` | `~/.prempti/run/broker.sock` (Unix) / `%LOCALAPPDATA%/prempti/run/broker.sock` (Windows) | Broker socket path |
| `PREMPTI_TIMEOUT_MS` | `5000` | Socket timeout in ms |
| `PREMPTI_FAIL_OPEN` | `0` | When set to `1`/`true`, broker communication failures allow the tool call instead of denying it |

Boolean values accept `1`, `true`, `yes`, `on` (case-insensitive, whitespace trimmed).

## Error handling

- **Fail-closed by default.** Broker communication failures emit a `deny` (with the failure reason) unless `PREMPTI_FAIL_OPEN=1` is set. The deny is emitted in the output shape matching the Codex hook event that fired.
- **Exit code 2** for malformed input (empty stdin, invalid JSON, unsupported `hook_event_name`). Codex treats exit 2 + stderr as a hard block.
- **Stdout safety.** If serialization fails, the interceptor writes a hardcoded deny literal in the correct shape for the event. No path produces empty stdout with exit 0 (Codex treats empty stdout as allow).

## Known v1 limitations

- **No `apply_patch` path resolution.** Codex's file-write tool is `apply_patch` (a patch-based input), not `Write`/`Edit`. The plugin's `tool.real_file_path` field is currently only populated for Claude Code's `Write`/`Edit`/`Read`, so path-based rules don't fire for Codex file writes. Bash rules work unchanged.
- **`agent.model` and `agent.turn_id` not exposed.** Codex sends these in every `PreToolUse` event; the plugin currently ignores them. Will be added once a rule needs model-aware policy.
- **Installer wiring deferred.** No `premptictl hook add codex` flow; manual configuration only.
- **`permission_mode = "dontAsk"` interaction with `PermissionRequest` unverified.** Whether `dontAsk` suppresses `PermissionRequest` entirely or fires it passive-observer needs runtime confirmation.

## Supported Codex hook events

Only `PreToolUse` and `PermissionRequest` are handled. Codex has 8 other hook events (`PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `SubagentStart`, `SubagentStop`, `UserPromptSubmit`, `Stop`) — registering this interceptor for those is a configuration error and exits 2 with a clear stderr message.
