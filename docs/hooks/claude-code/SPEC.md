# Claude Code Interceptor — Specification

| Field    | Value                    |
|----------|--------------------------|
| Binary   | `claude-interceptor`     |
| Source   | `hooks/claude-code/`     |
| Language | Rust                     |

## Overview

The Claude Code interceptor is a stateless CLI binary invoked by Claude Code's `PreToolUse` hook on every tool call. It reads the hook JSON from stdin, wraps it in a wire-protocol envelope, sends it to the plugin broker via Unix domain socket, receives a verdict (allow/deny/ask), and writes the hook response to stdout.

The interceptor is a **thin passthrough** — it does not interpret tool call content, extract fields, or evaluate policies. All semantic processing (field extraction, path resolution, policy evaluation) happens in the plugin broker. This design keeps the interceptor simple, agent-agnostic, and easy to maintain.

## Design Principles

1. **No content interpretation**: The interceptor treats the stdin JSON as an opaque payload. The only field it reads is `tool_use_id` (for the wire protocol request ID).
2. **Fail-safe output**: Every code path either produces valid JSON on stdout (exit 0) or blocks the tool call (exit 2). Empty stdout with exit 0 is prevented by design.
3. **Fail-closed by default**: If the broker is unreachable, the tool call is denied. Embedding integrations may opt into fail-open via `PREMPTI_FAIL_OPEN=1`.
4. **Minimal dependencies**: Only `serde`/`serde_json` and the Rust standard library. No async runtime.

## Execution Model

```
Claude Code                    Interceptor                  Plugin Broker
    │                              │                              │
    │──stdin (JSON)───────────────▶│                              │
    │                              │──Unix socket (JSON\n)───────▶│
    │                              │◀──Unix socket (JSON\n)───────│
    │◀──stdout (JSON)──────────────│                              │
    │                              │ exit 0                       │
```

- **Invocation**: Claude Code spawns the interceptor as a child process for each tool call.
- **Lifecycle**: Single invocation per tool call. The process starts, processes one event, and exits.
- **Concurrency**: Multiple interceptor instances may run in parallel (one per concurrent tool call). Each connects independently to the broker socket.

## Claude Code Hook API

### Input (stdin)

Claude Code writes a JSON object to the interceptor's stdin, then closes stdin (EOF).

```json
{
  "session_id": "string",
  "transcript_path": "string",
  "cwd": "string (absolute path)",
  "permission_mode": "string",
  "hook_event_name": "PreToolUse",
  "tool_name": "string",
  "tool_input": { ... },
  "tool_use_id": "string",
  "agent_id": "string (optional, subagents only)",
  "agent_type": "string (optional)"
}
```

The interceptor reads `tool_use_id` for correlation and passes the entire JSON as an opaque event to the broker. All other fields are consumed by the broker's field extraction logic.

### Output (stdout)

The interceptor writes a single JSON line to stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow|deny|ask",
    "permissionDecisionReason": "string"
  }
}
```

**Critical invariant**: The interceptor must ALWAYS produce valid JSON on stdout when exiting with code 0. Empty stdout with exit 0 causes Claude Code to silently allow the tool call.

### Exit Codes

| Code | Meaning | Claude Code behavior |
|------|---------|---------------------|
| 0    | Success | Parse stdout JSON for verdict |
| 2    | Blocking error | Block tool call, feed stderr to Claude as feedback |
| Other | Non-blocking error | Log to verbose output, allow tool call |

### Unused Hook Features

The following Claude Code hook output fields are not currently used but may be evaluated in the future:

- `updatedInput` — modify tool parameters before execution
- `additionalContext` — inject text into Claude's context
- `continue` — stop the session
- `suppressOutput` — hide hook output
- `systemMessage` — show warning to user

## Wire Protocol: Interceptor → Broker

### Transport

- **Socket type**: Unix domain stream socket (`AF_UNIX`, `SOCK_STREAM` — native kernel support on Windows 10+ via the `uds_windows` crate)
- **Default path**:
  - Linux / macOS: `$HOME/.prempti/run/broker.sock`
  - Windows: `%LOCALAPPDATA%/prempti/run/broker.sock` (forward slashes — Windows `AF_UNIX` treats the path as an opaque address, so both ends must produce identical byte strings)
- **Override**: `PREMPTI_SOCKET` environment variable
- **Framing**: Newline-terminated JSON (one line per request/response)
- **Shutdown**: On Unix, the interceptor shuts down the write half after sending the request so the broker's `read_line` sees EOF alongside `\n`. **Skipped on Windows** — `shutdown(SD_SEND)` on AF_UNIX resets the connection on some Windows builds and prevents the broker's response from reaching the interceptor.

### Request (interceptor → broker)

```json
{
  "version": 1,
  "id": "<tool_use_id>",
  "agent_name": "claude_code",
  "agent_pid": 12345,
  "event": { <raw stdin JSON> }
}
```

| Field | Source | Description |
|-------|--------|-------------|
| `version` | Hardcoded `1` | Protocol version |
| `id` | `tool_use_id` from stdin | Wire protocol request ID. `"unknown"` if missing. Broker uses this to send the verdict response back. |
| `agent_name` | Hardcoded `"claude_code"` | Identifies the coding agent |
| `agent_pid` | Platform PID lookup | PID of the interceptor's immediate parent (the agent process). Omitted from JSON when the platform lookup fails; the broker treats absence as `0`. Lets a side-by-side vanilla Falco correlate hook events with syscall events via `proc.apid[]`. |
| `event` | Raw stdin JSON | Complete hook input, passed through as-is using `serde_json::RawValue` (zero-copy, no re-serialization) |

The `event` field contains the entire Claude Code hook input verbatim. The broker is responsible for parsing it and extracting any fields it needs (tool_name, tool_input, cwd, etc.).

### Response (broker → interceptor)

```json
{
  "id": "<tool_use_id>",
  "decision": "allow|deny|ask",
  "reason": "optional explanation"
}
```

**Validation**: The interceptor verifies that:
- `id` matches the request's correlation ID
- `decision` is one of `allow`, `deny`, `ask`

Failures trigger `verdict_on_error` (fail-closed by default: deny).

## Error Handling

### Error categories

| Category | Trigger | Behavior |
|----------|---------|----------|
| **Input error** | Empty stdin, invalid JSON, invalid UTF-8, oversized input (default 4 MiB; configurable via `PREMPTI_INPUT_MAX_BYTES`) | Exit code 2, stderr message |
| **Broker error** | Socket unavailable, write/read failure, timeout, malformed response, ID mismatch, invalid decision | Deny by default; allow if `PREMPTI_FAIL_OPEN=1` |

### Fail-closed by default

All broker errors result in deny unless `PREMPTI_FAIL_OPEN=1` is set. This preserves standalone/default behavior while letting embedding integrations opt into fail-open operation when broker unavailability should not block tool execution.

### Stdout safety

If JSON serialization fails, the interceptor emits a hardcoded deny JSON literal. If any stdout write fails, it exits with code 2 (blocking error). No code path can produce empty stdout with exit code 0.

## Configuration

| Variable | Default (Unix) | Default (Windows) | Description |
|----------|----------------|-------------------|-------------|
| `PREMPTI_SOCKET` | `$HOME/.prempti/run/broker.sock` | `%LOCALAPPDATA%/prempti/run/broker.sock` | Broker socket path |
| `PREMPTI_TIMEOUT_MS` | `5000` | `5000` | Socket timeout in ms (clamped to 100–30000) |
| `PREMPTI_INPUT_MAX_BYTES` | `4194304` (4 MiB) | `4194304` (4 MiB) | Cap on stdin bytes per hook invocation. Clamped to `[4096, 67108864]` (64 MiB ceiling). Unparseable values fall back to the default. Pair with the plugin's `max_request_bytes` config so the broker doesn't truncate what the interceptor accepted. |
| `PREMPTI_FAIL_OPEN` | `0` | `0` | When set to `1`/`true`, broker communication failures allow the tool call instead of denying it |

## Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| Max stdin size | 4 MiB (default) | Configurable via `PREMPTI_INPUT_MAX_BYTES`; clamped to `[4 KiB, 64 MiB]`. Inputs exceeding the resolved cap are rejected with exit 2 and a stderr message naming the env var to raise. |
| Max broker response | 64 KB | Responses exceeding this are truncated at read |
| Socket timeout | 5s (default) | Covers connect+write+read |

## Known Limitations

1. **Per-syscall read timeout**: The socket read timeout is set once before `read_line`. A slow broker dripping bytes could extend the total read time beyond the configured timeout, since each `read()` syscall within `read_line` gets the full remaining timeout. The 64KB response size limit bounds the worst case. A proper fix requires a manual read loop with per-iteration deadline checks.

2. **Stdin format**: The interceptor reads until EOF and parses as JSON. It handles both compact and pretty-printed JSON. If Claude Code changes the delivery mechanism, this would need updating.

## Broker Responsibilities

Since the interceptor is a thin passthrough, the following are broker responsibilities:

- **Field extraction**: Parse `tool_name`, `tool_input`, `cwd`, `session_id`, etc. from the event JSON
- **Derived fields**: Extract `tool.input_command` (Bash), `tool.file_path`/`tool.real_file_path` (Write/Edit/Read)
- **Path resolution**: Resolve file paths to absolute canonical paths (`tool.real_file_path`, `agent.real_cwd`) via `canonicalize` with lexical normalization fallback
- **Content validation**: Verify required fields are present (e.g., `tool_name`)
- **Policy evaluation**: Forward events to Falco, collect alerts, resolve verdicts

## Hook Registration

Register in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.prempti/bin/claude-interceptor"
          }
        ]
      }
    ]
  }
}
```

The empty matcher `""` matches all tool names.
