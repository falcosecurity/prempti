# Codex Interceptor — Specification

| Field    | Value                                  |
|----------|----------------------------------------|
| Binary   | `codex-interceptor`                    |
| Source   | `hooks/codex/`                         |
| Language | Rust                                   |
| Status   | Experimental                           |

## Overview

The Codex interceptor is a stateless CLI binary invoked by the OpenAI Codex CLI on every tool dispatch and every approval request. It reads the hook JSON from stdin, wraps it in the same wire envelope used by the Claude Code interceptor, sends it to the plugin broker via Unix domain socket, receives a verdict (allow/deny/ask/defer), and writes Codex's per-event hook response shape back to stdout.

The interceptor is a **thin passthrough** — it does not interpret tool call content, extract fields, or evaluate policies. All semantic processing (field extraction, path resolution, policy evaluation, and the `apply_patch` multi-file multiplex) happens in the plugin broker. The interceptor only knows how to translate between Codex's per-event output shapes and the broker's agent-agnostic wire envelope.

## Design Principles

1. **Two mount points, one binary.** Codex's hook contract has separate event types for "before tool dispatch" (`PreToolUse`) and "before user approval" (`PermissionRequest`). The interceptor is registered for both and dispatches internally on the `hook_event_name` field in stdin.
2. **Same wire envelope as Claude Code.** `agent_name = "codex"` is the only routing distinction. The broker, plugin, and Falco rules are agent-agnostic by design.
3. **Fail-safe output.** Every code path either produces valid JSON on stdout (exit 0) or blocks the tool call (exit 2 + stderr message). PermissionRequest + defer is the deliberate exception: it emits no output (see "Verdict translation" below for why).
4. **Fail-closed by default.** Broker unreachable → deny. Embedding integrations may opt into fail-open via `PREMPTI_FAIL_OPEN=1`.
5. **No `ask` semantic on Codex.** Codex's hook contract is binary allow/deny. Falco `ask` verdicts collapse to Codex `deny` with the rule reason as the message (see "Verdict translation").
6. **Minimal dependencies.** Only `serde`/`serde_json` and the Rust standard library. No async runtime.

## Execution Model

```
Codex                          Interceptor                  Plugin Broker
  │                                 │                              │
  │── stdin (JSON, snake_case) ────▶│                              │
  │                                 │── Unix socket (JSON\n) ─────▶│
  │                                 │                              │  (broker may multiplex apply_patch
  │                                 │                              │   into N synthetic Falco events)
  │                                 │◀── Unix socket (JSON\n) ─────│
  │◀── stdout (JSON, camelCase) ────│                              │
  │   (or empty — see verdict        exit 0                        │
  │    table)                                                      │
```

- **Invocation.** Codex spawns the interceptor as a child process for each hook firing (per tool dispatch for `PreToolUse`; per approval request for `PermissionRequest`).
- **Lifecycle.** Single invocation per event. The process starts, processes one event, and exits.
- **Concurrency.** Multiple interceptor instances may run in parallel.

## Codex Hook API

### Input (stdin)

Codex writes a JSON object to the interceptor's stdin, then closes stdin (EOF). Fields are **snake_case**.

`PreToolUse`:
```json
{
  "session_id": "string",
  "turn_id": "string",
  "transcript_path": "string | null",
  "cwd": "string (absolute path)",
  "hook_event_name": "PreToolUse",
  "model": "string",
  "permission_mode": "string",
  "tool_name": "string",
  "tool_input": { ... any JSON ... },
  "tool_use_id": "string"
}
```

`PermissionRequest`:
```json
{
  "session_id": "string",
  "turn_id": "string",
  "transcript_path": "string | null",
  "cwd": "string (absolute path)",
  "hook_event_name": "PermissionRequest",
  "model": "string",
  "permission_mode": "string",
  "tool_name": "string",
  "tool_input": { ... any JSON ... }
}
```

`PermissionRequest` carries the same fields **minus `tool_use_id`** (per the upstream schema; `permission_request.command.input.schema.json`).

The interceptor reads `hook_event_name` (to decide output shape) and a correlation hint (`tool_use_id` on PreToolUse, fallback to `turn_id` on PermissionRequest, fallback to `"unknown"`). Everything else passes through to the broker as an opaque event.

Codex-only fields exposed by the broker as Falco fields:
- `model` → `agent.model`
- `turn_id` → `agent.turn_id`
- `permission_mode = "dontAsk"` is a Codex-only value (`agent.permission_mode`)

The `permission_mode` enum on the wire is `default | acceptEdits | plan | dontAsk | bypassPermissions`.

### Output (stdout)

Codex expects **camelCase** JSON on stdout (with `#[serde(deny_unknown_fields)]` on the receiving side — emitting extra fields is rejected).

`PreToolUse`:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow | deny",
    "permissionDecisionReason": "string"
  }
}
```

`PermissionRequest` (deny only):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": { "behavior": "deny", "message": "string" }
  }
}
```

`PermissionRequest` (allow): `decision: { "behavior": "allow" }` — Prempti approves, skipping Codex's prompt. `PermissionRequest` (defer): **no output**. See "Verdict translation" for why each renders the way it does.

### Exit Codes

| Code | Meaning | Codex behavior |
|------|---------|----------------|
| 0 | Success | Parse stdout JSON for verdict; empty stdout on PermissionRequest = "no objection, fall through to normal approval flow" |
| 2 | Blocking error | Block tool call, feed stderr to Codex |
| Other | Non-blocking error | Treated as exit 0 fallthrough (the upstream parser records a `HookRunStatus::Failed` entry but does not block) |

### Unused Output Fields

Codex's hook output schema reserves fields the interceptor does NOT emit. Several would silently break the contract or invite unsafe behavior if used:

| Field | Why we don't emit it |
|-------|----------------------|
| `decision.updatedInput` | Reserved / fail-closed in upstream (`output_parser.rs:393-406`) |
| `decision.updatedPermissions` | Same |
| `decision.interrupt` | Same |
| `additionalContext` | Reserved on `PermissionRequest` |
| `permissionDecision: "ask"` | Upstream `output_parser.rs:451-453` rejects this on `PreToolUse` and fails open — emitting `ask` would silently allow |

### Hook Trust Model

Codex requires non-managed command hooks to be **trusted** before they execute. Two paths:

1. `--dangerously-bypass-hook-trust` on the `codex` command line — per-invocation override.
2. The `/hooks` slash command in interactive mode — persistent trust stored in Codex's state.

`premptictl hook add codex` does not grant trust; it only writes the config that declares the hook. Users must trust the hook once before it actually fires.

## Verdict Translation

Codex's hook contract is binary allow/deny on both mount points. There is no per-call user-confirmation UX at the hook layer. The interceptor maps the broker's four-valued verdict (`allow`, `deny`, `ask`, `defer`) across the two mount points as follows:

| Broker verdict | `PreToolUse` output | `PermissionRequest` output |
|----------------|---------------------|----------------------------|
| `allow` | `permissionDecision: "allow"` | `decision: {"behavior": "allow"}` (Prempti approves, skips Codex's prompt) |
| `deny` | `permissionDecision: "deny"` with the rule reason | `decision: {"behavior": "deny", "message": "<reason>"}` |
| `ask` | Same as `deny` (with rule reason) | Same as `deny` (with rule reason) |
| `defer` | `permissionDecision: "allow"` (proceed to the gate) | **No output** (empty stdout, exit 0) — Codex's own approval flow decides |

`allow` and `defer` are the two faces of the plugin's no-rule-match floor (`default_action`): `allow` (the default) has Prempti actively approve, `defer` has Prempti step aside. Both proceed at `PreToolUse`; they diverge only at `PermissionRequest`, Codex's actual approval gate. `monitor` and `passthrough` modes always resolve as `defer`.

### Why `ask` becomes `deny`

`PermissionRequest` only fires when Codex's *own* `permission_mode` would have prompted the user (e.g. `default` / `acceptEdits`). Under `bypassPermissions`, `dontAsk`, or `--ask-for-approval never`, PermissionRequest never fires. An earlier design that routed `PreToolUse + ask → allow` on the assumption that PermissionRequest would catch it silently allowed in those non-prompting modes. Denying at the earliest mount point with the rule reason as the deny message is the only safe mapping that respects every Codex permission_mode.

### Why `allow` and `defer` render differently at `PermissionRequest`

`PermissionRequest` is Codex's approval gate, and the two "no deny/ask rule matched" intents map to two different wire shapes:

- **`allow`** (the default floor) emits `{"behavior": "allow"}`, telling Codex to skip its own approval prompt — Prempti actively approves, mirroring the Claude interceptor's `permissionDecision: "allow"`.
- **`defer`** emits nothing. Codex's contract treats empty stdout + exit 0 as "no objection, fall through to the normal approval flow", so the user's `permission_mode` choices decide.

Choose between them with the plugin's `default_action` (`allow` is the default; `defer` restores the fall-through), or run in `monitor` / `passthrough`, which always defer. Before `default_action` existed, the allow floor hardcoded the no-output fall-through (commit `8297274`); it is now an explicit, configurable choice.

## Wire Protocol: Interceptor → Broker

The wire envelope is **identical to the Claude Code interceptor**'s. See [`docs/hooks/claude-code/SPEC.md`](../claude-code/SPEC.md#wire-protocol-interceptor--broker) for the transport, framing, shutdown semantics, and response shape. The only Codex-specific differences:

| Field | Codex value | Notes |
|-------|-------------|-------|
| `agent_name` | `"codex"` | Routes through agent-agnostic broker; `agent.name` field in Falco rules |
| `id` | `tool_use_id` if non-empty; else `turn_id`; else `"unknown"` | PermissionRequest input has no `tool_use_id` per Codex's schema |
| `event` | Raw snake_case stdin JSON | Forwarded verbatim via `serde_json::RawValue` |

The broker's response (`{"id", "decision", "reason"}`) is validated the same way as Claude's: ID must match the request, `decision` must be one of `allow` / `deny` / `ask` / `defer`.

## `apply_patch` Multi-file Handling

The interceptor is **unaware** of `apply_patch` multi-file semantics. It forwards the patch body verbatim to the broker exactly like any other tool input. The broker is responsible for parsing the envelope and emitting one synthetic Falco event per touched `(operation, path)` tuple, all sharing the same `correlation.id`.

From the interceptor's perspective:
- One wire request goes out.
- One wire response comes back with the escalated verdict (`deny > ask > {allow|defer}`) across all the synthetic events the broker fired internally.

See [`docs/plugins/coding-agents-plugin/SPEC.md`](../../plugins/coding-agents-plugin/SPEC.md) for the broker-side mechanism.

## Error Handling

### Error categories

| Category | Trigger | Behavior |
|----------|---------|----------|
| **Input error** | Empty stdin, invalid JSON, invalid UTF-8, oversized input (default 4 MiB; configurable via `PREMPTI_INPUT_MAX_BYTES`), unsupported `hook_event_name` (anything other than `PreToolUse` / `PermissionRequest`) | Exit code 2, stderr message |
| **Broker error** | Socket unavailable, write/read failure, timeout, malformed response, ID mismatch, invalid decision | Deny by default (fail-closed); allow if `PREMPTI_FAIL_OPEN=1` |

### Fail-closed by default

Same model as the Claude Code interceptor: broker errors → deny unless `PREMPTI_FAIL_OPEN=1`. Fail-open resolves as `defer` (not `allow`), so on `PermissionRequest` it emits **no output** — letting the call proceed via Codex's own approval flow rather than having Prempti actively approve when its policy engine is the thing that's down. This keeps the error path byte-identical regardless of the configured `default_action`.

### Stdout safety

If JSON serialization fails, the interceptor emits a hardcoded deny literal in the shape matching the event (`PreToolUse` form or `PermissionRequest` form) — fail-closed, the safe direction even for an allow that failed to serialize. If any stdout write fails, it exits with code 2. The one path that deliberately produces empty stdout is `PermissionRequest + defer` — and that is the **correct** wire shape, not an oversight.

### Unsupported events

The interceptor recognizes only `PreToolUse` and `PermissionRequest`. Codex has 8 other hook events (`PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop`). Registering this interceptor for any of those is a configuration error — the interceptor exits 2 with a stderr explanation. Codex treats exit 2 as a hard block, surfacing the misconfiguration loudly rather than letting an unhandled event silently pass through.

## Configuration

Same env vars as the Claude Code interceptor:

| Variable | Default (Unix) | Default (Windows) | Description |
|----------|----------------|-------------------|-------------|
| `PREMPTI_SOCKET` | `$HOME/.prempti/run/broker.sock` | `%LOCALAPPDATA%/prempti/run/broker.sock` | Broker socket path |
| `PREMPTI_TIMEOUT_MS` | `5000` | `5000` | Socket timeout in ms (clamped to 100–30000) |
| `PREMPTI_INPUT_MAX_BYTES` | `4194304` (4 MiB) | `4194304` (4 MiB) | Cap on stdin bytes read from Codex per hook invocation. Clamped to `[4096, 67108864]` (64 MiB ceiling). Unparseable values fall back to the default. Pair with the plugin's `max_request_bytes` config so the broker doesn't truncate what the interceptor accepted. |
| `PREMPTI_FAIL_OPEN` | `0` | `0` | When set to `1`/`true`, broker communication failures allow the tool call instead of denying it |

Boolean values follow the project's `env_bool` convention: `1`, `true`, `yes`, `on` (case-insensitive, surrounding whitespace ignored) are truthy; everything else (including unset and empty) is falsy.

## Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| Max stdin size | 4 MiB (default) | Configurable via `PREMPTI_INPUT_MAX_BYTES`; clamped to `[4 KiB, 64 MiB]`. Inputs exceeding the resolved cap are rejected with exit 2 and a stderr message naming the env var to raise. |
| Max broker response | 64 KB | Responses exceeding this are truncated at read |
| Socket timeout | 5s (default) | Covers connect + write + read |

## Known Limitations

1. **`apply_patch` payloads above the configured cap are rejected.** The default 4 MiB stdin cap covers realistic multi-file refactors but is finite — `apply_patch` envelopes that exceed both the interceptor's `PREMPTI_INPUT_MAX_BYTES` and the broker's `max_request_bytes` are dropped (`InputError → exit 2`) before any Falco rule can fire. Raise both knobs in tandem if you need to support larger patches.
2. **`permission_mode = "dontAsk"` × `PermissionRequest` interaction is unverified at runtime.** Not blocking — `PreToolUse` already denies on `ask` in all modes — but the exact firing semantics of `PermissionRequest` under `dontAsk` are inferred from upstream source, not observed.
3. **`ask` is lossy.** Codex has no per-call user-confirmation UX at the hook layer, so Falco `ask` verdicts collapse to `deny + reason`. Users see the reason and can retry or change `permission_mode`, but cannot approve a single call inline.
4. **Hook trust is explicit.** `premptictl hook add codex` installs the packaged hook config and opt-in marker, and the supervisor re-asserts/removes the JSON hook on start/stop. It does not grant Codex hook trust; users must trust the hook with Codex's `/hooks` flow or per-invocation trust bypass before it runs.

## Broker Responsibilities

Since the interceptor is a thin passthrough, the following are broker responsibilities:

- **Field extraction** including Codex-only fields: `agent.model`, `agent.turn_id`, `tool.patch_op` (synthetic events from `apply_patch` multiplex).
- **`apply_patch` envelope parsing**: extract the per-hunk `(operation, path)` tuples and emit one Falco event per tuple, each carrying a per-hunk slice of `tool_input.command` for content isolation across files.
- **Path resolution**: resolve `tool.file_path` to `tool.real_file_path` for both Claude Code (`Write`/`Edit`/`Read`) and Codex (apply_patch synthetic events).
- **Verdict resolution**: collect alerts across all synthetic events sharing a `correlation.id`, escalate (`deny > ask > {allow|defer}`), and respond once on the interceptor's socket connection.

See [`docs/plugins/coding-agents-plugin/SPEC.md`](../../plugins/coding-agents-plugin/SPEC.md) for the full broker design.

## Hook Registration

Recommended:

```bash
premptictl hook add codex
```

This writes `~/.codex/hooks.json` registering the interceptor for both `PreToolUse` and `PermissionRequest` with matcher `.*` (regex; matches every tool name) and a 30-second timeout. It also records the Codex opt-in marker under the Prempti install prefix, so the supervisor re-asserts the JSON hook on service start and removes it on service stop. Remove with `premptictl hook remove codex`; check state with `premptictl hook status codex`.

The hand-rolled equivalent is documented in [`hooks/codex/README.md`](../../../hooks/codex/README.md). Codex also accepts an inline `[hooks]` block in `~/.codex/config.toml`; both layers are loaded together.

After registration, the hook still needs trust (see "Hook Trust Model" above).
