# Copilot Interceptor

Stateless CLI binary invoked by GitHub Copilot CLI's hook system on every tool call. It sends the hook event to the Prempti plugin broker via Unix socket and maps the verdict back to Copilot's per-event hook response format.

The interceptor is a thin passthrough — all field extraction, path resolution, and policy evaluation happens in the [plugin broker](../../plugins/coding-agents-plugin/).

> **Status: experimental.** Copilot support is in early development and not yet wired into the installers. Manual hook registration only.

## Build

```bash
cargo build --release
```

Binary: `target/release/copilot-interceptor`

From the workspace root:

```bash
make build-copilot-interceptor
```

## How It Works

The interceptor mounts on **two** Copilot hook events:

| Hook event | Copilot purpose | Interceptor responsibility |
|------------|----------------|---------------------------|
| `preToolUse` | Fires before every tool dispatch | Block deny rules with the rule reason; pass allow/ask/defer through |
| `permissionRequest` | Fires in the approval path before permission prompts | Block deny/ask rules with the rule reason; pass allow through; defer if no rule matches |

Both hooks send the same wire envelope to the broker (`agent_name = "copilot"`); the broker runs the same Falco rules regardless of which event arrived. Only the **output translation** is per-event.

### Verdict translation

| Falco verdict | `preToolUse` | `permissionRequest` |
|---------------|--------------|---------------------|
| `allow` | 	{"permissionDecision":"allow","permissionDecisionReason":""} | 	{"behavior":"allow"} |
| `deny` | 	{"permissionDecision":"deny","permissionDecisionReason":"..."} | {"behavior":"deny","message":"..."} |
| `ask` | {"permissionDecision":"ask","permissionDecisionReason":"..."} | {"behavior":"deny","message":"..."} |
| `defer` | *(no output — falls through to normal permission flow)* | *(no output — falls through to normal permission flow)* |

### Defer: step aside for both hooks

The broker's `defer` (the no-rule-match floor when `default_action = defer`, and the monitor/passthrough resolution) emits **no output** from the interceptor for both `preToolUse` and `permissionRequest`. This causes Copilot to fall through to its own permission flow (prompting, auto-allow, etc.). By contrast, when Falco rules return `allow` or the broker's `default_action = allow`, the interceptor emits an explicit allow (`{"behavior":"allow"}` for permissionRequest, `{"permissionDecision":"allow","permissionDecisionReason":""}` for preToolUse), which short-circuits the normal permission flow — useful in `-p` (pipe) mode and other non-interactive CI usages.

## Wire shape (Copilot → interceptor)

Copilot sends **camelCase** JSON over stdin.

`PreToolUse`:
```json
{
  "sessionId": "…",
  "timestamp": 1783795023994,
  "cwd": "/home/user",
  "toolName": "create",
  "toolArgs": "{\"path\":\"/home/user/file.txt\",\"file_text\":\"…\"}"
}
```

`PermissionRequest`:
```json
{
  "hookName": "permissionRequest",
  "sessionId": "…",
  "timestamp": 1783795024001,
  "cwd": "/home/user",
  "toolName": "edit",
  "toolInput": {
    "file_path": "/home/user/file.txt",
    "diff": "diff --git a/… b/…"
  },
  "permissionSuggestions": []
}
```

Note the structural difference: `permissionRequest` uses a top-level `hookName` field (instead of `sessionId`-level naming), and its `toolName` + `toolInput` fields parallel the `tool_name`/`tool_input` shape from the Codex wire format. The interceptor normalizes both shapes into the same internal representation before forwarding to the broker:

- `hookName` → `hook_event_name` (PascalCase: `"PreToolUse"` or `"PermissionRequest"`)
- `toolArgs` (JSON string) → `tool_input` (parsed JSON object). If parsing fails, the original string value is preserved as a fallback.
- `toolInput` (parsed object) → `tool_input` (passed through as-is)
- `sessionId` → `id` (correlation ID; falls back to `"unknown"` if empty)
- `toolName` → `tool_name`, `cwd` → `cwd` (passed through)
- `permission_mode` and `tool_use_id` are set to empty strings (not provided by Copilot)

The wire envelope also includes `version: 1` and `agent_pid`

## Wire shape (interceptor → Copilot)

Copilot expects **camelCase** JSON on stdout.

`PreToolUse`:
```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "Falco blocked …"
}
```

`PermissionRequest`:
```json
{
  "behavior": "deny",
  "message": "Falco blocked …"
}
```

> **Progress messages** (optional). The interceptor may emit transient progress lines before the final decision object to give the user visibility into hook execution. Each progress line is a single-line JSON object: `{"type":"progress","message":"…","temporary":true}`. Copilot strips these from the output stream before parsing the final decision.

## Hook registration (Copilot CLI)

Register the interceptor with:

```bash
premptictl hook add copilot
```

This writes a `~/.copilot/hooks/prempti.json` file that mounts the packaged `copilot-interceptor` binary on both `preToolUse` and `permissionRequest` (matcher `.*`, 30s timeout). Remove with `premptictl hook remove copilot`; status with `premptictl hook status copilot`.

The hook remains opt-in. Once enabled, the Prempti supervisor manages its lifecycle alongside the Claude Code and Codex hooks: it re-asserts the hook configuration on service start and removes it on service stop so Copilot does not fail closed against a dead broker. The opt-in marker remains until `premptictl hook remove copilot`.

If you'd rather hand-roll the config — for example to bind it to a specific tool matcher or to combine with hooks you already have — the canonical shape for `~/.copilot/hooks/prempti.json` is:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "matcher": ".*",
        "type": "command",
        "command": "/abs/path/to/copilot-interceptor",
        "timeoutSec": 30
      }
    ],
    "permissionRequest": [
      {
        "matcher": ".*",
        "type": "command",
        "command": "/abs/path/to/copilot-interceptor",
        "timeoutSec": 30
      }
    ]
  }
}
```


## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PREMPTI_SOCKET` | `~/.prempti/run/broker.sock` (Unix) / `%LOCALAPPDATA%/prempti/run/broker.sock` (Windows) | Broker socket path |
| `PREMPTI_TIMEOUT_MS` | `5000` | Socket timeout in ms |
| `PREMPTI_INPUT_MAX_BYTES` | `4194304` (4 MiB) | Stdin cap. Clamped to `[4 KiB, 64 MiB]`. Raise this (and the plugin's `max_request_bytes`) to support large tool input envelopes. |
| `PREMPTI_FAIL_OPEN` | `0` | When set to `1`/`true`, broker communication failures emit empty stdout (defer) instead of denying it |

Boolean values accept `1`, `true`, `yes`, `on` (case-insensitive, whitespace trimmed).

## Error handling

- **Fail-closed by default.** Broker communication failures emit a `deny` (with the failure reason) unless `PREMPTI_FAIL_OPEN=1` is set. The deny is emitted in the output shape matching the Copilot hook event that fired.
- **Exit code 2** for malformed input (empty stdin, invalid JSON, unsupported `hook_event_name`). Copilot treats exit 2 + stderr as a hard block.
- **Stdout safety.** If serialization fails, the interceptor writes a hardcoded deny literal in the correct shape for the event. The only path that produces empty stdout with exit 0 is the intentional `defer` verdict, which correctly falls through to Copilot's normal permission flow. All error paths emit an explicit deny.
- **Timeout.** A timed-out hook (exceeding `timeoutSec`) surfaces a warning and lets the tool call proceed through the normal permission flow, per Copilot's `preToolUse` timeout semantics.

## Known v1 limitations

- **`PermissionRequest` hook event name.** Copilot uses `hookName: "permissionRequest"` (lowercase `p`, no underscore) but hook config keys are `camelCase` (`permissionRequest`). The interceptor normalizes these at read time. If a future Copilot version changes the event name, the interceptor must be updated.
- **`toolInput` vs `toolArgs`.** The two events use different field names for tool arguments: `PreToolUse` uses `toolArgs` (a JSON string), `PermissionRequest` uses `toolInput` (a parsed JSON object). The interceptor normalizes both to `tool_input` internally before forwarding to the broker.
- **Progress messages not yet implemented.** The interceptor does not currently emit progress lines. This is non-blocking — Copilot tolerates hook silence — but would improve UX when the broker takes >1s to respond.
- **`ask` on permissionRequest is lossy.** Copilot's `preToolUse` supports `"ask"` and maps Falco `ask` rules directly. However, `permissionRequest` does not support an ask behavior, so Falco `ask` rules are mapped to `deny` with the rule reason as the message for that hook.

## Supported Copilot hook events

Only `preToolUse` and `permissionRequest` are handled. Copilot has 10 other hook events (`agentStop`, `errorOccurred`, `notification`, `postToolUse`, `postToolUseFailure`, `preCompact`, `sessionEnd`, `sessionStart`, `subagentStart`, `subagentStop`, `userPromptSubmitted`) — registering this interceptor for those is a configuration error and exits 2 with a clear stderr message.

## See also

- [Codex interceptor README](../codex/README.md) — analogous design for OpenAI Codex CLI
- [Claude Code interceptor README](../claude-code/README.md) — analogous design for Anthropic Claude Code
- [Plugin broker](../../plugins/coding-agents-plugin/) — policy evaluation engine
- [Copilot hooks reference](https://docs.github.com/en/copilot/copilot-cli/reference/copilot-hooks-reference) — official Copilot CLI hooks documentation
