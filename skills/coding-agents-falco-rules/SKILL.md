---
name: coding-agents-falco-rules
description: Author custom Falco rules for coding-agents-kit — the runtime security layer for AI coding agents. Use this skill whenever the user asks to create, edit, or debug rules that control what coding agents (Claude Code, etc.) can do. Triggers on phrases like "add a rule", "block this tool", "deny access to", "allow writes to", "create a security policy", "custom Falco rule for coding agent", or any request to modify files under rules/user/. This skill covers the coding_agent plugin source and its specific fields — NOT syscall rules.
---

# Coding Agents Falco Rules Author

Write custom Falco rules that govern what AI coding agents can do at runtime. These rules intercept tool calls (shell commands, file writes/reads, MCP calls) and enforce allow/deny/ask verdicts before execution.

## Context: How This System Works

coding-agents-kit intercepts every tool call a coding agent makes. Each call becomes a Falco event with structured fields. Your rules evaluate these events and decide the verdict:

- **deny** — block the tool call entirely (the agent sees an explanation)
- **ask** — prompt the user for confirmation (they see your output message directly)
- **allow** — no tag needed; tool calls that match no deny/ask rule are allowed

The agent sees the verdict reason as: `"Rule Name: <your output message> | For AI Agents: ... | correlation=<id>"`. For deny verdicts, the LLM reformulates this for the user. For ask verdicts, the user reads your output message directly in a permission prompt — so write it for a human audience.

## Available Fields

Every tool call event exposes these fields for conditions and output:

| Field | Type | Description |
|-------|------|-------------|
| `correlation.id` | u64 | Unique event ID (always > 0, auto-included in output_fields) |
| `agent.name` | string | Agent identifier (e.g., `claude_code`) |
| `agent.session_id` | string | Session identifier |
| `agent.cwd` | string | Working directory as reported by the agent |
| `agent.real_cwd` | string | Working directory resolved to absolute canonical path |
| `tool.name` | string | Tool name: `Bash`, `Write`, `Edit`, `Read`, `Glob`, `Grep`, `Agent`, etc. |
| `tool.use_id` | string | Unique identifier for this tool call |
| `tool.input` | string | Full tool input as JSON |
| `tool.input_command` | string | Shell command (Bash tool only, empty otherwise) |
| `tool.file_path` | string | Target file path, raw (Write/Edit/Read only) |
| `tool.real_file_path` | string | Target file path resolved to absolute canonical path (Write/Edit/Read only) |
| `tool.mcp_server` | string | MCP server name (MCP tool calls only) |

Path fields come in raw/real pairs. Use `real_*` for security policy matching (resolved, absolute). Use raw fields for display.

## Rule Structure

Every rule needs these fields:

```yaml
- rule: <Human-readable name>
  desc: >
    <What this rule does and why>
  condition: >
    <Boolean expression using fields above>
  output: >
    <LLM-friendly message starting with "Falco">
  priority: <CRITICAL|WARNING|NOTICE|DEBUG>
  source: coding_agent
  tags: [<verdict tag>]
```

### Tags (verdict)

| Tag | Effect | Priority convention |
|-----|--------|---------------------|
| `coding_agent_deny` | Block the tool call | CRITICAL or ERROR |
| `coding_agent_ask` | Require user confirmation | WARNING |
| (empty `[]`) | Informational / audit only | NOTICE or INFORMATIONAL |

All Falco priorities are valid: `EMERGENCY`, `ALERT`, `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`, `INFORMATIONAL` (or `INFO`), `DEBUG`.

When multiple rules match the same event, verdicts escalate: **deny > ask > allow**.

### Output Convention

The `output:` field is the message the coding agent (or user) sees. Write it as a clear, self-contained sentence:

- Start with "Falco" to attribute the enforcement
- Use `%field` to interpolate resolved values (e.g., `%tool.real_file_path`)
- Do NOT include structured `key=value` pairs — those are handled automatically by `append_output`
- For **deny** rules: write for an LLM audience (it will rephrase for the user)
- For **ask** rules: write for a human audience (they read it directly in the permission prompt)

```yaml
# Good:
output: >
  Falco blocked running sudo because elevated privileges are not permitted

# Bad (structured fields leak into user-facing message):
output: >
  Denied | cmd=%tool.input_command correlation=%correlation.id
```

## Condition Language Quick Reference

### Operators

| Operator | Example |
|----------|---------|
| `=`, `!=` | `tool.name = "Bash"` |
| `contains` | `tool.input_command contains "rm -rf"` |
| `icontains` | `tool.input_command icontains "password"` — case-insensitive contains |
| `startswith`, `endswith` | `tool.real_file_path startswith "/etc/"` |
| `in` | `tool.name in ("Write", "Edit")` |
| `pmatch` | `tool.real_file_path pmatch (sensitive_paths)` — prefix match against a list |
| `glob` | `tool.real_file_path glob "/home/*/secrets/*"` — wildcard pattern matching |
| `regex` | `tool.input_command regex "curl.*\|.*sh"` — RE2 regular expression |
| `exists` | `tool.mcp_server exists` — field has a value (cleaner than `!= ""`) |
| `and`, `or`, `not` | Boolean combinators |

### Transformers

| Transformer | Usage |
|-------------|-------|
| `val()` | Field-to-field comparison: `tool.real_file_path startswith val(agent.real_cwd)` |
| `basename()` | Extract filename: `basename(tool.real_file_path) = ".env"` (POSIX split on `/` — use `real_file_path`, which the plugin normalizes to forward slashes on every platform) |
| `tolower()` | Case-insensitive comparison: `tolower(tool.input_command) startswith "sudo "` |
| `len()` | String length: `len(tool.input_command) > 1000` — detect anomalous inputs |

Transformers can be chained: `basename(tolower(tool.file_path))`.

Without `val()`, the right-hand side is a literal string, not a field reference.

### Lists and Macros

Lists define reusable sets of values. Macros define reusable condition fragments.

```yaml
- list: my_blocked_commands
  items: [rm, mkfs, dd, fdisk]

- macro: is_blocked_command
  condition: >
    tool.input_command startswith "rm -rf"
    or tool.input_command startswith "mkfs"

- rule: Deny dangerous commands
  condition: >
    tool.name = "Bash"
    and is_blocked_command
  ...
```

### Override and Append

The `override` key modifies existing rules, macros, and lists across files — essential for customizing defaults without editing them:

```yaml
# In rules/user/my_overrides.yaml:

# Add paths to the default sensitive_paths list
- list: sensitive_paths
  items: [/opt/secrets/]
  override:
    items: append

# Add conditions to the default is_sensitive_path macro
- macro: is_sensitive_path
  condition: or tool.real_file_path contains "/.vault/"
  override:
    condition: append

# Disable an existing rule
- rule: Monitor activity outside working directory
  enabled: false
  override:
    enabled: replace

# Change a rule's priority
- rule: Ask before writing outside working directory
  priority: CRITICAL
  override:
    priority: replace

# Append an extra condition to an existing rule
- rule: Deny writing to sensitive paths
  condition: and not tool.real_file_path startswith "/etc/my-app/"
  override:
    condition: append
```

**Appendable** fields: `condition`, `output`, `desc`, `tags`, `exceptions`.
**Replaceable** fields: all appendable fields plus `priority`, `enabled`.

## Where to Put Rules

- **Default rules**: `rules/default/coding_agents_rules.yaml` — shipped with the project, overwritten on upgrade
- **User rules**: `rules/user/*.yaml` — preserved across upgrades, this is where custom rules go
- **Seen rule**: `rules/seen.yaml` — DO NOT modify, required for verdict resolution

When creating rules for the user, always write to `rules/user/`.

Before writing a new rule, read `rules/default/coding_agents_rules.yaml` to check for overlaps. The default ruleset already covers sensitive path protection, outside-cwd writes, and file monitoring. If the user's request overlaps with an existing rule, consider using `override: append` to extend it rather than creating a duplicate. If the new rule is more restrictive (e.g., deny where the default only asks), explain the interaction to the user.

## Validation

After writing a rule, always validate it with Falco. The validation step catches syntax errors, unknown fields, and malformed conditions before the rule goes live.

### Finding the Falco binary

Check these locations in order. The "installed" locations are written by the platform packagers; the "development build" locations are produced by `make falco-*` and `make download-falco-linux`.

**Linux / macOS**

1. **Installed binary** (most common): `~/.coding-agents-kit/bin/falco`
2. **System PATH**: `falco` (if installed globally)
3. **Development build**: `build/falco-*-<arch>/usr/bin/falco` (Linux, downloaded) or `build/falco-*-darwin-<arch>/falco` (macOS, source)

**Windows** (PowerShell)

1. **Installed binary**: `$env:LOCALAPPDATA\coding-agents-kit\bin\falco.exe`
2. **System PATH**: `falco.exe` (rare on Windows — `PATH` usually points to the installed bin dir via the post-install step)
3. **Development build**: `build\falco-0.43.0-windows-<arch>\falco.exe` (built via `make falco-windows-x64` / `falco-windows-arm64`)

### Running validation

Use the installed config so the plugin is loaded and all fields are recognized.

**Linux / macOS**

```bash
~/.coding-agents-kit/bin/falco \
  -c ~/.coding-agents-kit/config/falco.yaml \
  --disable-source syscall \
  -V ~/.coding-agents-kit/rules/user/my_rules.yaml
```

**Windows** (PowerShell)

```powershell
& "$env:LOCALAPPDATA\coding-agents-kit\bin\falco.exe" `
  -c "$env:LOCALAPPDATA\coding-agents-kit\config\falco.yaml" `
  --disable-source syscall `
  -V "$env:LOCALAPPDATA\coding-agents-kit\rules\user\my_rules.yaml"
```

This validates:
- YAML syntax and rule structure
- Field names exist in the `coding_agent` source (catches typos like `tool.command` instead of `tool.input_command`)
- Condition expression syntax (operators, transformers, list/macro references)
- Output template field references

If validation passes, Falco exits 0. If it fails, the error message tells you exactly which rule and which field or expression has the problem.

### Common Validation Errors

| Error | Meaning |
|-------|---------|
| `LOAD_ERR_COMPILE_CONDITION` | Syntax error in condition — undefined macro, invalid field, bad operator |
| `LOAD_ERR_COMPILE_OUTPUT` | Invalid field reference in output template |
| `LOAD_ERR_YAML_VALIDATE` | YAML structure error — missing required field, wrong type |
| `LOAD_ERR_YAML_PARSE` | Malformed YAML — bad indentation, missing quotes, invalid syntax |
| `LOAD_UNKNOWN_FILTER` | Unknown field name — check spelling against the fields table |
| `LOAD_UNKNOWN_SOURCE` | Unknown event source — check for typos in `source:` (must be `coding_agent`) |
| `LOAD_UNUSED_MACRO` | Macro defined but not referenced by any rule or other macro |
| `LOAD_UNUSED_LIST` | List defined but not referenced by any rule, macro, or other list |

Warnings must also be fixed. If validation reports `LOAD_UNUSED_MACRO` or `LOAD_UNUSED_LIST`, remove the unused macro or list from the file. Do not ship rules with unused definitions.

### If Falco is not available

If neither the installed binary nor a development build is found, validate manually:
- `source: coding_agent` is set
- Field names match the table above exactly
- `val()` is used for field-to-field comparisons
- Tags are one of `coding_agent_deny`, `coding_agent_ask`, or empty `[]`
- Output starts with "Falco"

Flag to the user that the rule was not machine-validated.

## Common Mistakes

| Mistake | Why it's wrong | Fix |
|---------|---------------|-----|
| `tool.real_file_path startswith agent.real_cwd` | RHS is a literal string `"agent.real_cwd"`, not a field | Use `val()`: `startswith val(agent.real_cwd)` |
| `source: syscall` or missing `source:` | Wrong event source — defaults to syscall | Always set `source: coding_agent` |
| `output: "Denied cmd=%tool.input_command id=%correlation.id"` | Structured fields leak into user-facing message | Keep output clean; structured fields are in output_fields automatically |
| `tool.input_command contains "rm"` | Matches `rm`, but also `mkdir`, `chmod`, `arm64` | Use `startswith "rm "` or `startswith "rm -"` for precision |
| `tags: [deny]` | Wrong tag name — broker won't recognize it | Use `coding_agent_deny` or `coding_agent_ask` |
| Editing `rules/default/` or `seen.yaml` | Overwritten on upgrade / breaks verdict resolution | Write to `rules/user/`; use `override:` to modify defaults |
| Using `tool.input_command` without `tool.name = "Bash"` | `tool.input_command` is empty for non-Bash tools — condition silently never matches | Always guard with `tool.name = "Bash" and ...` |
| Creating a rule that overlaps with defaults | User gets unexpected double verdicts or confusion | Read `rules/default/` first; extend with `override:` or explain the interaction |

## Examples

### Deny: block destructive shell commands

```yaml
- rule: Deny destructive shell commands
  desc: >
    Blocks rm -rf, mkfs, dd, and other destructive commands that could
    cause irreversible damage to the filesystem.
  condition: >
    tool.name = "Bash"
    and (tool.input_command contains "rm -rf"
         or tool.input_command startswith "mkfs"
         or tool.input_command startswith "dd ")
  output: >
    Falco blocked a destructive command (%tool.input_command)
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
```

### Ask: confirm before running network commands

```yaml
- rule: Ask before network commands
  desc: >
    Requires user confirmation before the agent runs curl, wget, or
    similar network tools that could exfiltrate data.
  condition: >
    tool.name = "Bash"
    and (tool.input_command startswith "curl "
         or tool.input_command startswith "wget "
         or tool.input_command contains "| curl"
         or tool.input_command contains "| wget")
  output: >
    Falco requires confirmation for a network command (%tool.input_command)
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]
```

### Deny: block MCP tool calls to untrusted servers

```yaml
- list: trusted_mcp_servers
  items: [ide]

- rule: Deny untrusted MCP servers
  desc: >
    Blocks MCP tool calls to servers not in the trusted list.
  condition: >
    tool.mcp_server != ""
    and not tool.mcp_server in (trusted_mcp_servers)
  output: >
    Falco blocked an MCP call to untrusted server %tool.mcp_server
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
```

### Deny: prevent writing outside a project boundary

```yaml
- list: allowed_write_prefixes
  items:
    - /home/user/myproject/

- rule: Deny writes outside project
  desc: >
    Restricts file writes to a specific project directory.
  condition: >
    tool.name in ("Write", "Edit")
    and tool.real_file_path != ""
    and not tool.real_file_path pmatch (allowed_write_prefixes)
  output: >
    Falco blocked writing to %tool.real_file_path because it is outside the allowed project directory
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
```

## Common Patterns

**Match Bash commands by prefix** (safer than `contains` — avoids matching substrings):
```yaml
condition: tool.name = "Bash" and tool.input_command startswith "sudo "
```

**Match files by name regardless of directory** (use `real_file_path` so `basename()` works on Windows too):
```yaml
condition: basename(tool.real_file_path) = "Dockerfile"
```

**Match files inside the working directory** (use `val()` for field comparison):
```yaml
condition: tool.real_file_path startswith val(agent.real_cwd)
```

**Match files by extension** (use `endswith`):
```yaml
condition: tool.real_file_path endswith ".key" or tool.real_file_path endswith ".pem"
```

**Combine multiple tools**:
```yaml
condition: tool.name in ("Write", "Edit", "Read") and ...
```
