# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**Prempti** is a policy and visibility layer for AI coding agents. It intercepts tool calls (shell commands, file writes, web requests, etc.) before execution, evaluates them against Falco rules, and produces allow/deny/ask verdicts in real time. It operates entirely in user space with no elevated privileges.

It is not a sandbox or OS-level security boundary: at the hook level it only sees what the agent declares, not the runtime side effects of the resulting commands. It is a cooperative policy layer — the agent receives LLM-friendly feedback on blocked or flagged actions and adapts — meant to complement containment techniques, not replace them.

The project targets **Claude Code** as its primary integration on **Linux, macOS, and Windows**, with **experimental Codex CLI** support (interceptor + plugin path; installer wiring deferred). The wire envelope, broker, and plugin field schema are agent-agnostic by design — adding another agent is a new interceptor crate plus any agent-specific field decoding, not a rewrite.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌────────────────────────────┐
│ Coding Agent │───▶│ Interceptor  │───▶│     Falco (nodriver)       │
│              │     │   (hook)     │     │  ┌───────────────────────┐ │
│              │◀───│              │◀───│  │  Plugin (src + extract│ │
│              │     │              │     │  │  + embedded broker)   │ │
└──────────────┘     └──────────────┘     │  └───────────────────────┘ │
                                          │  Rule Engine + Rules       │
                                          └────────────────────────────┘
```

### Pipeline flow

1. **Interception** — The coding agent's hook API fires before each tool call. The interceptor captures structured event data and pauses tool execution while awaiting a verdict.
2. **Event delivery** — The interceptor sends the event to the plugin's embedded broker via Unix domain socket.
3. **Rule evaluation** — The plugin feeds the event to Falco's rule engine via the source plugin API (`next_batch`). Falco evaluates all loaded rules.
4. **Alert feedback** — Matching rules generate alerts. Falco delivers them back to the plugin's embedded broker via `http_output` (localhost).
5. **Verdict resolution** — The broker determines the verdict from rule tags (`deny`, `ask`, or allow-by-default) and responds to the interceptor.
6. **Verdict delivery** — The interceptor communicates the verdict to the coding agent using the standard hook response format.

### Components

| Component | Location | Language | Role |
|-----------|----------|----------|------|
| **Claude Code interceptor** | `hooks/claude-code/` | Rust | Thin passthrough: reads `PreToolUse` hook JSON from stdin, wraps in envelope, sends to broker, maps verdict to stdout. No content interpretation. |
| **Codex interceptor (experimental)** | `hooks/codex/` | Rust | Same passthrough role, but mounts on both `PreToolUse` and `PermissionRequest` and emits Codex's per-event output shape. See [`hooks/codex/README.md`](hooks/codex/README.md). |
| **Plugin** | `plugins/` | Rust (falco_plugin SDK) | Falco source+extract plugin with embedded broker. Parses events, extracts fields, feeds Falco, receives alerts, resolves verdicts. Multiplexes Codex `apply_patch` into N events (one per touched path). |
| **Supervisor** | `tools/premptictl/src/daemon/` | Rust | `ctl daemon` subcommand. Spawns Falco, captures and rotates its stdout/stderr into the log files, owns the Claude Code hook lifecycle, exposes a control socket for graceful shutdown. The init system (systemd / launchd / Windows Run key) starts the supervisor; the supervisor starts Falco. |
| **Rules** | `rules/` | YAML (Falco rule language) | Vendor and local security policies. |
| **Installer** | `installers/linux/`, `installers/macos/`, `installers/windows/` | Shell/PowerShell | Platform-specific packaging, installation, hook registration, mode switching. |
| **Skills** | `skills/` | Claude Code skill format | Coding agent skills for rule authoring, status, etc. |
| **Tests** | `tests/` | Rust | Cross-platform interceptor and E2E integration tests. |

## Key Design Decisions

### Broker embedded in plugin

The broker is part of the Falco plugin, not a separate process. This reduces moving parts: Falco is the only process the user needs to run (besides the stateless interceptor). The plugin spawns threads for the Unix socket server (accepting interceptor connections) and the HTTP server (receiving Falco alerts).

### Tags for verdict resolution

Rule verdicts are encoded in the `tags:` field of Falco rules, not in the `output:` string. The tag names are **configurable in the plugin configuration** and support multiple tags per verdict type. Defaults:

- `tags: [coding_agent_deny]` — block the tool call
- `tags: [coding_agent_ask]` — require user confirmation
- No deny/ask tag — allow (no explicit allow tag needed)

There is no allow tag because the absence of a verdict IS the allow verdict. Rules only fire when their condition matches — a tool call that doesn't match any deny or ask rule simply produces no deny/ask alert, and the broker resolves it as allow via batch-completion.

The broker parses the `tags` array from Falco's JSON alert output. Verdict escalation applies when multiple rules match: deny > ask > allow.

### Catch-all seen rule + HTTP verdict resolution

All verdict signals flow through Falco's `http_output` to the plugin's embedded HTTP server:

- Deny/ask alerts (from matching rules) resolve the pending request immediately.
- A **catch-all "seen" rule** (tagged `coding_agent_seen`) fires for every event. When the broker receives this alert, it knows rule evaluation is complete. If no deny/ask alert arrived for that correlation ID, the request is resolved as allow.

**Critical config**: `rule_matching: all` must be set in `falco.yaml`. The default (`first`) only fires one rule per event — this would prevent both a deny rule and the seen rule from firing on the same event.

**Rule load ordering**: The seen rule must be loaded as the last rule file so that deny/ask rules fire first and their alerts are enqueued before the seen alert.

**HTTP handler constraints**: The handler must respond fast (Falco's output worker thread is shared across all output channels — a slow handler blocks everything). The HTTP server must be ready before events flow (Falco does not retry on connection failure — alerts are silently dropped).

The plugin requires two capabilities: **sourcing** (event generation) and **extraction** (field extraction for rules).

### Single data source, generic event fields

One Falco data source: **`coding_agent`**. Two field namespaces:

| Field | Type | Description |
|-------|------|-------------|
| `correlation.id` | u64 | Broker-assigned unique ID for this event (monotonic counter, always > 0) |
| `agent.name` | string | Coding agent identifier (`claude_code` or `codex`) |
| `agent.os` | string | Host OS — `linux`, `macos`, `windows`, or `unknown` (static per build, derived from `cfg!(target_os)`) |
| `agent.pid` | u64 | PID of the agent process that invoked the hook (the interceptor's immediate parent). `0` when the platform lookup fails. Lets a side-by-side vanilla Falco correlate hook events with syscall events emitted by the same agent instance via `proc.apid[]`. |
| `agent.hook_event_name` | string | Lifecycle hook type (e.g., `PreToolUse`) |
| `agent.session_id` | string | Session identifier |
| `agent.cwd` | string | Working directory, raw from the hook JSON (`cwd` field on both Claude Code and Codex) |
| `agent.real_cwd` | string | Working directory, resolved to absolute canonical path (symlinks resolved if exists, lexical normalization otherwise) |
| `tool.use_id` | string | Tool call identifier (`tool_use_id`, raw value). Present on Claude Code hooks and Codex `PreToolUse`; absent on Codex `PermissionRequest`. May be empty. |
| `tool.name` | string | Tool name (e.g., `Bash`, `Write`, `Edit` for Claude Code; `Bash`, `apply_patch`, `mcp__<server>__<tool>` for Codex) |
| `tool.input` | string | Full tool input as JSON |
| `tool.input_command` | string | Shell command (Bash tool calls) |
| `tool.file_path` | string | Target file path. Raw from `tool_input.file_path` for Claude Code's `Write`/`Edit`/`Read`; for Codex `apply_patch` synthetic events the broker injects the per-event path parsed from the patch envelope. Empty otherwise. |
| `tool.real_file_path` | string | Target file path, resolved to absolute canonical path. Relative paths resolved against `agent.cwd`. Populated whenever `tool.file_path` is. |
| `tool.patch_op` | string | Per-event apply_patch operation for Codex synthetic events: `Add`, `Update`, `Delete`, or `Move`. Empty for all other events. |
| `agent.permission_mode` | string | Session permission mode reported by the agent (e.g., `default`, `acceptEdits`, `plan`, `bypassPermissions`; Codex also emits `dontAsk`) |
| `agent.transcript_path` | string | Session transcript file path. Empty when the agent reports `null`. |
| `agent.model` | string | Model identifier reported by the agent (Codex-only; empty for Claude Code) |
| `agent.turn_id` | string | Turn identifier within a session (Codex-only; finer than `session_id`; empty for Claude Code) |

This schema is agent-agnostic. The `agent.name` field distinguishes which coding agent generated the event.

Path fields come in raw/real pairs:
- **Raw** (`agent.cwd`, `tool.file_path`): exactly as reported in the hook JSON for Claude Code, or as injected by the broker per synthetic event for Codex `apply_patch`. Use for display and audit.
- **Real** (`agent.real_cwd`, `tool.real_file_path`): resolved via `canonicalize` (symlinks resolved, absolute). Falls back to lexical normalization if the path doesn't exist yet (common for `Write` / `Add`). Use for policy matching.

### Codex apply_patch: one event per touched path

Codex's `apply_patch` tool can touch multiple files in a single hook invocation (Lark grammar `start: begin_patch hunk+ end_patch`; an Update hunk can also carry a `*** Move to:` line that touches a second path). The broker parses the patch envelope at receive time and emits **one synthetic Falco event per (operation, path) tuple**, all sharing the same `correlation.id`. The broker waits for N "seen" alerts before resolving with the escalated verdict (`deny` > `ask` > `allow`).

Each synthetic event carries `tool.patch_op` (Add/Update/Delete/Move) and a single `tool.file_path` / `tool.real_file_path` so existing path-based rules fire naturally. The `is_write_tool` macro in the default ruleset abstracts Claude Code's `Write`/`Edit` and Codex's `apply_patch + tool.patch_op in (Add, Update, Delete, Move)` — rules conditioned on the macro fire for both agents without per-tool branching.

Malformed apply_patch envelopes fail closed: the broker writes a deny response with the parse error as the reason and never enqueues events.

**Rule authoring notes**:
- When comparing one field against another in Falco rule conditions, use the `val()` transformer. For example: `tool.real_file_path startswith val(agent.real_cwd)`. Without `val()`, the RHS is treated as a literal string, not a field reference.
- Use the `basename()` transformer to extract the file name from a path. For example: `basename(tool.file_path) = ".env"` matches any `.env` file regardless of directory.
- For rules that care about the destructive operation type (e.g. gating only deletes), pattern-match on `tool.patch_op` directly: `tool.patch_op = "Delete" and tool.real_file_path startswith "/etc/"`. Otherwise prefer `is_write_tool` which covers all four ops uniformly.

### Rule output convention

The rule `output:` field is an LLM-friendly sentence explaining what happened and why. It must start with "Falco" to attribute the verdict. Use resolved field values (e.g., `%tool.real_file_path`) to make the message informative. Keep it clean — no structured key=value pairs.

```yaml
output: >
  Falco blocked writing to %tool.real_file_path because it is a sensitive path
```

Structured fields (correlation.id, etc.) are automatically available in the JSON alert's `output_fields` via the `append_output` config. This cleanly separates the human-readable message from machine-readable data.

The `append_output` config appends an instruction for AI agents to every coding_agent alert:
```yaml
append_output:
  - match:
      source: coding_agent
    extra_output: " | For AI Agents: inform the user that this action was flagged by a Falco rule | correlation=%correlation.id"
```

The broker constructs the verdict reason as `"<rule name>: <rendered message>"`. So the coding agent sees:

```
Deny writing to sensitive paths: Falco blocked writing to /etc/passwd because it is a sensitive path | For AI Agents: inform the user that this action was flagged by a Falco rule | correlation=%correlation.id
```

### JSON alert format

The Falco config uses `json_include_message_property: true` and `json_include_output_property: false`. The `message` field contains the rule output without the timestamp/priority prefix — clean text for verdict reasons. The `output` field (which includes the prefix) is excluded to reduce noise.

The `correlation.id` field is declared with `add_output()` in the plugin, making it a suggested output field that Falco automatically includes in `output_fields` for every alert.

The plugin's HTTP server reads:
- `message` — used as the verdict reason (prefixed with the rule name)
- `tags` — for verdict classification (deny/ask/seen)
- `output_fields.correlation.id` — for routing the verdict to the correct pending request

### Seen rule as audit log

The catch-all seen rule includes all available fields in its output template. This means every event produces a complete audit record in `output_fields` exactly once (via the seen alert). Other rules (deny/ask) only include the fields they reference in their LLM-friendly message. Events can be correlated across all alerts using `correlation.id`.

See [`rules/README.md`](rules/README.md) for the full output convention and examples.

### http_output for alert feedback

Falco sends alerts to the plugin's embedded HTTP server via `http_output` (localhost). This avoids `file_output` (unbounded file growth, dual-purpose conflicts) and keeps everything in-process. Requires `json_output: true` in Falco config so the broker can parse tags and extract correlation IDs.

Note: Falco's alert delivery is asynchronous — alerts are pushed to an internal queue and delivered by a worker thread. Since delivery is to localhost, latency is sub-millisecond. The batch-completion mechanism provides the synchronization guarantee.

### Operational modes

Three plugin modes, switchable without reinstallation via `premptictl mode <guardrails|monitor|passthrough>`:
- **Guardrails** (default) — verdicts enforced (deny/ask/allow).
- **Monitor** — rules evaluated and logged, but all verdicts resolve to allow after the synchronous rule-eval wait. Would-deny / would-ask log lines still fire.
- **Passthrough** (Experimental, embedding-only) — every interceptor request is resolved as `allow` immediately at register, without waiting for rule evaluation. Events are still enqueued for Falco, so alerts continue to flow through `http_output` / `falco.log` and any observability pipeline hanging off them. No would-deny / would-ask log lines, because rule evaluation is decoupled from the verdict. Use only when embedding Prempti inside a host agent that has its own alert pipeline and does not want the hook's latency tied to Falco's rule loop.

The three modes are mutually exclusive — `mode:` is a single string, so only one is active at a time.

Mode changes are applied via an explicit service restart driven by `ctl mode`: it rewrites the plugin config fragment, stops the service, re-registers the interceptor hook (so the brief restart window stays fail-closed rather than passing tool calls through unchecked), and starts the service again. Behavior is identical on Linux, macOS, and Windows. The same flow applies to any other config edit: edits made directly to `falco.yaml` or any included config / rule file take effect on the next `ctl start` (or `ctl mode`) — Falco's own `watch_config_files` is disabled deliberately because it is Linux-only upstream.

`ctl restart` exposes the same stop → re-add hook → start cycle as a standalone command for users who edit config files directly.

Additionally, the interceptor hook can be unregistered via `premptictl hook remove`, which passes all tool calls through unmonitored (no mode is active because the hook isn't firing). This is a hook-removed bypass used when the service is intentionally stopped, and is distinct from `mode: passthrough` which keeps the hook live but short-circuits the broker.

### Supervisor (`ctl daemon`)

The init system (systemd user unit on Linux, launchd user agent on macOS, `HKCU\…\Run` key on Windows) does not spawn Falco directly. It spawns the **supervisor** — a Rust process running `premptictl daemon --prefix <prefix>` — which then spawns Falco as a child. The supervisor:

1. **Owns Falco's lifecycle**: spawns it with `-U -c falco.yaml --disable-source syscall`, waits on it, escalates SIGTERM → SIGKILL on shutdown timeout (Unix), or `TerminateProcess` (Windows).
2. **Owns the log files**: drains Falco's stdout into `log/falco.log` and stderr into `log/falco.err`, line by line. The `-U` (unbuffered) flag ensures Falco flushes after every alert so JSON lines arrive synchronously.
3. **Owns rotation**: rotation parameters live in `config/supervisor.yaml` (cap, archives kept, stop timeout). The supervisor checks size before each write; over the cap, it shifts `.1 → .2 → .3`, drops the oldest, and reopens. One implementation, identical on every platform.
4. **Owns the hook lifecycle**: runs `hook::add` on start, `hook::remove` on stop. Replaces systemd's `ExecStartPost`/`ExecStopPost`, the macOS launcher's `trap`, and the Windows launcher's `try/finally`.
5. **Exposes a control channel**: binds `run/supervisor.sock` (separate from `run/broker.sock`) and accepts two commands:
   - `STOP\n` — initiates graceful shutdown, returns `OK\n`.
   - `STATUS\n` — returns `OK pid=<sup> falco_pid=<falco> started=<unix-ms> rotated=<count>\n`.

This is what `ctl stop` on Windows uses to ask for a graceful shutdown (today's `taskkill /F` cannot reach a console-less process). Linux and macOS instead let the init system deliver SIGTERM to the supervisor; the supervisor then runs the same shutdown sequence.

The supervisor refuses to start if it can't open log files, register the hook, or bind `supervisor.sock` — fail-fast at startup is preferable to a half-broken service that silently loses logs.

Restart-on-failure is the init system's job. The supervisor is dumb: when Falco dies (whatever the cause), it exits with Falco's exit code and the init system decides whether to relaunch.

Advanced users can run the supervisor directly via `ctl daemon --prefix <path>` for debugging or non-managed setups. Only one supervisor at a time per prefix because `supervisor.sock` is a singleton.

### Fail-safety

- **Fail-closed**: if the plugin/Falco is unreachable, tool calls are denied.
- No timeout-based fail-safety (see batch-completion design above).

**Important**: When the hook is registered and the service is stopped or restarting (e.g., during a `ctl mode` or `ctl restart` cycle), ALL Claude Code tool calls are blocked. This is by design — fail-closed means no policy gap. Use `premptictl hook remove` to unblock Claude Code when the service is intentionally down. The supervisor adds the hook on start and removes it on stop on every platform; `ctl mode` and `ctl restart` re-register the hook between stop and start so the restart window itself stays fail-closed.

### Installation directory structure

All components are installed under `~/.prempti/`:

```
~/.prempti/
├── bin/                    # Executables: falco, claude-interceptor, premptictl
├── config/
│   ├── falco.yaml          # Base Falco config (engine, output, isolation)
│   ├── falco.coding_agents_plugin.yaml  # Plugin config (plugin def, rules, http_output)
│   └── supervisor.yaml     # Supervisor config (rotation, stop timeout); preserved on upgrade
├── log/                    # Falco logs (rotated by supervisor): falco.log[.1..N], falco.err[.1..N]
├── run/                    # Runtime: broker.sock, supervisor.sock
├── share/                  # Shared libraries: libcoding_agent.so (.dylib on macOS, .dll on Windows)
└── rules/
    ├── default/
    │   └── coding_agents_rules.yaml  # Default ruleset (overwritten on upgrade)
    ├── user/               # User custom rules (preserved on upgrade)
    └── seen.yaml           # Catch-all seen rule (loaded last)
```

### Falco configuration isolation

Falco runs with a fully isolated configuration — no default files from `/etc/falco/`:

- **`falco -c ~/.prempti/config/falco.yaml`** replaces the default config entirely
- **`config_files: []`** or pointing only to our fragment prevents loading `/etc/falco/config.d/`
- **`rules_files`** is the authoritative list — no hardcoded default rule paths
- **`engine.kind: nodriver`** — no kernel driver needed

The installer must run Falco with **`--disable-source syscall`** in addition to the config. `engine.kind: nodriver` makes the syscall source idle (no events), but it still exists and loads syscall-related resources. `--disable-source syscall` removes it entirely.

Config is split into two files:
- **`falco.yaml`**: base settings (engine, output, webserver, `config_files` pointing to the plugin fragment)
- **`falco.coding_agents_plugin.yaml`**: plugin definition, `init_config`, `load_plugins`, `rules_files`, `rule_matching: all`, `http_output`

All paths on Linux/macOS use `${HOME}` expansion (Falco 0.43 supports `${VAR}` syntax in all YAML scalar values), so the same config works across users as long as the install lives at `$HOME/.prempti`. Linux and macOS installers only support this default path; the Windows MSI regenerates both config files at install time via `postinstall.ps1`, which is how its `WixUI_InstallDir`-selected `INSTALLDIR` actually flows through to Falco.

### macOS: Falco build from source

Falco does not ship pre-built macOS binaries. `installers/macos/build-falco.sh` clones Falco 0.43.0, applies `falco-macos-http-output.patch`, and builds with `MINIMAL_BUILD=ON` + `HAS_HTTP_OUTPUT` (no gRPC, no webserver, just curl-based http_output). System libraries (OpenSSL via Homebrew, system curl + zlib) instead of bundled — Falco's bundled autotools deps don't respect `CMAKE_OSX_ARCHITECTURES`. Cross-compile (x86_64 on Apple Silicon) requires both `arch -x86_64` (so autotools detects via `uname -m`) and `CFLAGS="-arch x86_64"` (so Apple's universal compiler emits x86_64).

See [`installers/macos/README.md`](installers/macos/README.md) for the full rationale, rejected alternatives, and the universal-binary flow.

### macOS: service management (launchd)

macOS uses launchd instead of systemd. Key differences:

- **Plist**: `~/Library/LaunchAgents/dev.falcosecurity.prempti.plist` (label uses `dev.falcosecurity` — the Falco project's registered domain). `ProgramArguments` invokes `premptictl daemon --prefix <prefix>` directly; there is no launcher shell script.
- **Hook lifecycle**: handled by the supervisor (see "Supervisor" section above), not by an `ExecStartPost`/`ExecStopPost` equivalent (which launchd lacks).
- **ctl tool**: Platform-specific via `#[cfg(target_os)]` compile-time branching. Same commands on both platforms (`start/stop/enable/disable/status/restart`), different implementations (systemctl vs launchctl).
- **Plugin library**: `.dylib` on macOS (vs `.so` on Linux). The macOS packager transforms the plugin config via `sed`.

### macOS: `premptictl` service commands

| Command | Linux (systemctl) | macOS (launchctl) |
|---------|-------------------|-------------------|
| `start` | `systemctl --user start` | `launchctl load <plist>` |
| `stop` | `systemctl --user stop` | `launchctl unload <plist>` |
| `restart` | `service_stop` then `hook::add` then `service_start` (cross-platform helper) ||
| `enable` | `systemctl --user enable` | `launchctl load <plist>` (RunAtLoad in plist) |
| `disable` | `systemctl --user disable` | `launchctl unload -w <plist>` |
| `status` | `systemctl --user status` | `launchctl list <label>` |

On Linux/macOS, both `start` and `stop` operate on the supervisor; `launchctl unload` / `systemctl stop` deliver SIGTERM to the supervisor, which runs its own shutdown sequence (graceful Falco stop, drain pipes, hook remove).

The macOS implementation includes `is_service_loaded()` for idempotent start/stop.

### Windows: Falco build from source

Falco does not ship pre-built Windows binaries. `installers/windows/build-falco.ps1` clones Falco 0.43.0, applies `falco-windows-http-output.patch` (same `HAS_HTTP_OUTPUT` + `MINIMAL_BUILD=ON` pattern as macOS) and `falco-windows-cmake-generator.patch` (forwards generator/platform to nested libscap/libsinsp configure for ARM64 host correctness), and builds with MSVC + vcpkg using **static curl with the SChannel backend** — no OpenSSL on Windows. The patches also tolerate SChannel-specific curl limitations (`CURLE_NOT_BUILT_IN` on `CURLOPT_NOPROXY` / `CURLOPT_CAINFO` / `CURLOPT_CAPATH`) and fix the POSIX-only relative-path check in Falco's `configuration.h` so absolute Windows plugin paths (`C:/...`) resolve correctly.

See [`installers/windows/README.md`](installers/windows/README.md) for the http_output patch details, prerequisites, build steps, and known caveats (Git Bash path/CRLF traps, ARM64 host toolchain alignment).

### Windows: service management

Windows has no user-level systemd or launchd equivalent, so Prempti uses a **PowerShell launcher script invoked by a Registry Run key**, which in turn invokes the supervisor. The launcher exists solely to provide `WindowStyle Hidden` so the supervisor's console window does not flash at login.

- **Run key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Prempti` — value points at `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <launcher> -Prefix <prefix>`. Set by `postinstall.ps1` and by `ctl enable`; removed by `uninstall.ps1` and `ctl disable`.
- **Launcher**: `prempti-launcher.ps1` is a ~5-line wrapper that just `& <prefix>\bin\premptictl.exe daemon --prefix <prefix>` and propagates the exit code. All real work — Falco lifecycle, log capture, rotation, hook lifecycle — happens inside the supervisor.
- **Graceful shutdown via `supervisor.sock`**: `ctl stop` connects to `run/supervisor.sock` and sends `STOP\n`. The supervisor calls `Child::kill` (which is `TerminateProcess` on Windows) on Falco, drains the pipes, removes the hook, and exits. `ctl stop` polls for the supervisor's process to disappear and falls back to `taskkill /F /PID <sup-pid>` only if the supervisor itself doesn't exit within 30 seconds. This replaces the old `taskkill /F /IM falco.exe` path which lost the cleanup chain entirely.
- **No Windows Service**: the installer intentionally does not create a Windows Service. A per-user install cannot register a service without admin, and interception must run under the user's session anyway (it modifies `~/.claude/settings.json` in the user profile, and per-user-socket lifetime follows the user).
- **Path separators**: all runtime paths (broker socket, library_path, rules_files, http_output URL) are normalized to forward slashes at config-generation time. The plugin also canonicalizes paths to forward slashes for rule matching (stripping the Windows `\\?\` long-path prefix that `std::fs::canonicalize` sometimes adds).
- **AF_UNIX**: both `broker.sock` and `supervisor.sock` are real Unix domain sockets (Windows 10+ has kernel `AF_UNIX` support). The `uds_windows` crate provides Rust bindings.
- **Plugin library**: `coding_agent.dll` on Windows (vs `.so` on Linux and `.dylib` on macOS). The Windows packager copies the DLL into `%LOCALAPPDATA%\prempti\share\` and the post-install script renders a `library_path` in `falco.coding_agents_plugin.yaml` that points at the absolute path with forward slashes.
- **Fail-safety on MSI uninstall**: the MSI declares a deferred `REMOVE=ALL` custom action (`installers/windows/Package.wxs`) that runs `uninstall.ps1` before `RemoveFiles`, so Apps & Features and `msiexec /x` both stop the service, remove the hook, drop the Run-key entry and clean `bin\` from the user `PATH`. `Return="ignore"` on the CA keeps a user-edited `settings.json` from blocking the uninstall.
- **`ctl start` detachment**: the launcher is a long-lived descendant (it waits on the supervisor, which waits on Falco), so a direct `CreateProcess` of the launcher is tracked by the caller's PowerShell job object and keeps a captured pipeline (`& ctl start 2>&1`) open until everything exits. To break that chain, `service_start` invokes PowerShell's `Start-Process` (ShellExecute), producing a grandchild that's fully independent of the caller. Caveat: `Start-Process -Wait ctl start` from a script still hangs because `-Wait` follows the whole process tree — the captured form `& ctl start 2>&1` is the one to use.
- **Post-install auto-start fail-safety**: `postinstall.ps1` starts the service via `Start-Process` after registering the hook, polls up to 5s for Falco, and falls through to a `Write-Warning` if it doesn't see Falco in time. Install still completes; the user recovers with `premptictl start` manually. If Falco fails to start at all (port conflict, missing DLL, etc.) the user is not silently left with a registered hook and a dead broker.

### Windows: `premptictl` service commands

| Command | Linux (systemctl) | macOS (launchctl) | Windows |
|---------|-------------------|-------------------|---------|
| `start` | `systemctl --user start` | `launchctl load <plist>` | `powershell … -File <launcher>` (spawned, polled via `tasklist`) |
| `stop` | `systemctl --user stop` | `launchctl unload <plist>` | `STOP` over `supervisor.sock`, then poll for supervisor exit (fallback `taskkill /F /PID <sup>`) |
| `restart` | shared helper: `service_stop` → `hook::add` → `service_start` |
| `enable` | `systemctl --user enable` | `launchctl load <plist>` | `reg add <Run key>` |
| `disable` | `systemctl --user disable` | `launchctl unload -w <plist>` | `reg delete <Run key>` |
| `status` | `systemctl --user status` | `launchctl list <label>` | `tasklist /FI "IMAGENAME eq falco.exe"` |

All three platforms share `ctl health` (synthetic event through the full pipeline), `ctl hook add / remove / status`, `ctl mode`, and `ctl logs` with per-OS tail implementations (`tail -n N [-f]` on Linux/macOS vs `Get-Content -Tail N [-Wait]` on Windows). `--tail` defaults to 100 lines; pass an explicit value to override.

## Technology Stack

- **Falco 0.43** — rule engine, running in `nodriver` mode (no kernel instrumentation)
- **Rust** — interceptor and plugin (using `falco_plugin` crate v0.5.0)
- **Platforms** — Linux (official Falco builds), macOS (Falco built from source with http_output patch, system OpenSSL+curl), Windows (Falco built from source with http_output patch, static curl via vcpkg, SChannel backend)

## Build & Development

### Building

```bash
make build                  # Build all components for the native architecture
make build-interceptor      # Interceptor only
make build-plugin           # Plugin only
make build-ctl              # CTL tool only
```

Requires latest stable Rust (the falco_plugin SDK tracks latest stable as MSRV).

The repository is a Cargo workspace. The root `Cargo.toml` declares `[workspace.package].version` as the single source of truth for the Rust side — every crate inherits it via `version.workspace = true`, the plugin's reported version is derived from `CARGO_PKG_VERSION` at compile time, and `Makefile` / `package.ps1` read the version from the same file. The Claude Code plugin marketplace manifest (`.claude-plugin/marketplace.json`, `metadata.version`) carries an independent version string that must be kept in lockstep with the workspace version — so cutting a release is a two-file edit. Size-sensitive crates (`claude-interceptor`, `premptictl`) use `opt-level = "z"`; the plugin (hot path) uses `opt-level = 2`.

### Tests

```bash
make test                   # Run all tests (cross-platform)
make test-interceptor       # Interceptor unit tests (mock broker, no Falco needed)
make test-e2e               # E2E tests (requires Falco built, plugin, and interceptor)
```

Tests are written in Rust (`tests/` crate) and work on all platforms with the same targets. E2E tests automatically find the Falco binary from the project's build output (not the system). They skip gracefully if Falco is not built.

On Linux, use `make download-falco-linux` to download pre-built Falco binaries. On macOS, use `make falco-macos` to build from source. On Windows, use `make falco-windows` to build from source (requires vcpkg + MSVC).

### Packaging

```bash
# Linux (downloads pre-built Falco)
make linux-x86_64
make linux-aarch64

# macOS (builds Falco from source, requires cmake + Homebrew OpenSSL)
make macos-aarch64          # Apple Silicon
make macos-x86_64           # Intel (must run on Intel Mac)
make macos-universal        # Fat binary (requires Rosetta + x86_64 Homebrew)
make falco-macos            # Build only Falco (convenience target)

# Windows (builds Falco from source, requires vcpkg + MSVC + WiX)
make windows-x64            # x64 MSI package
make windows-arm64          # arm64 MSI package
make falco-windows          # Build only Falco (convenience target)
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PREMPTI_SOCKET` | `~/.prempti/run/broker.sock` | Broker Unix socket path |
| `PREMPTI_TIMEOUT_MS` | `5000` | Socket read timeout in milliseconds |
| `PREMPTI_INPUT_MAX_BYTES` | `4194304` (4 MiB) | Interceptor stdin cap (claude + codex). Clamped to `[4 KiB, 64 MiB]`. Pair with the plugin's `max_request_bytes` `init_config` field on the broker side. |

Boolean Prempti env vars are parsed by the `env_bool` helper in
`hooks/claude-code/src/main.rs`: it accepts `1`, `true`, `yes`, `on`
(case-insensitive, surrounding whitespace ignored) as truthy; everything
else — including unset and empty — is falsy. `PREMPTI_TIMEOUT_MS` is
numeric and `NO_COLOR` follows the external "any non-empty = true"
convention; `env_bool` is the convention for new Prempti booleans only.

## Code Style

### License headers

All source files must use the falcosecurity license header style:

**C/C++ files (.c, .h):**
```c
// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) <year> The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
```

**Rust files (.rs):** No per-file license headers (Rust ecosystem convention). Licensing is declared in `Cargo.toml` and the top-level `LICENSE` file.

The year must be the most recent year the file was modified. Use `The Falco Authors` as copyright holder.
