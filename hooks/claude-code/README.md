# Claude Code Interceptor

Stateless CLI binary invoked by Claude Code's `PreToolUse` hook on every tool call. It sends the hook event to the plugin broker via Unix socket and maps the verdict back to Claude Code's hook response format.

The interceptor is a thin passthrough — all field extraction, path resolution, and policy evaluation happens in the [plugin broker](../../plugins/coding-agents-plugin/).

See [SPEC.md](../../docs/hooks/claude-code/SPEC.md) for the full specification.

## Build

```bash
cargo build --release
```

Binary: `target/release/claude-interceptor`

## How It Works

1. Claude Code sends tool call JSON on stdin
2. Interceptor wraps it in a wire-protocol envelope and sends to the broker socket
3. Broker responds with a verdict (allow/deny/ask)
4. Interceptor writes the verdict to stdout in Claude Code's hook response format

The interceptor reads only `tool_use_id` from the input (for the wire protocol request ID). Everything else is passed through as raw JSON.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PREMPTI_SOCKET` | `~/.prempti/run/broker.sock` | Broker socket path |
| `PREMPTI_TIMEOUT_MS` | `5000` | Socket timeout in ms |

## Error Handling

- **Fail-closed**: All broker communication failures result in deny.
- **Exit code 2**: For malformed input (empty stdin, invalid JSON). Claude Code blocks the tool call.
- **Stdout safety**: If JSON serialization fails, emits a hardcoded deny literal. No path produces empty stdout with exit 0.
