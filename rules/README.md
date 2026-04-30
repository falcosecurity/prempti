# Rules

Falco rules for Prempti. These rules define security policies that govern what coding agents can do.

## Structure

```
rules/
├── default/
│   └── coding_agents_rules.yaml   # Default ruleset shipped with the project
├── user/                           # Custom user rules
│   └── .gitkeep
├── seen.yaml                       # Catch-all rule (required, always loaded last)
└── README.md
```

### `default/coding_agents_rules.yaml`

The default security policies shipped with Prempti, organized into six sections: working-directory boundary, sensitive paths, sandbox disable, threats (credentials, dangerous commands, exfiltration, supply chain), MCP and skill content, and persistence vectors. The file also defines reusable lists (`sensitive_paths`, `sensitive_file_names`, `shell_startup_files`, `agent_instruction_files`, `env_file_names`, `registry_config_files`) and macros (`is_sensitive_path`, `is_outside_cwd`, `is_write_tool`, `contains_ioc_domain`, `cmd_contains_ioc_domain`) that user rules can extend via `override: append`.

This file is **overwritten on upgrade** — do not edit it directly. To customize behavior, add rules in the `user/` directory instead.

### `user/`

Place your custom rules here. Files in this directory are **preserved across upgrades**. You can:

- Add new rules for your specific needs
- Override default rules using Falco's `override` mechanism (append/replace conditions, change priorities)
- Add project-specific allow/deny lists

### `seen.yaml`

A mandatory catch-all rule that fires for every coding agent event. It signals to the plugin broker that rule evaluation is complete for a given tool call. **Do not remove or modify this file** — the verdict resolution mechanism depends on it.

This file must always be loaded **after** all other rule files. The loading order is configured in `falco.coding_agents_plugin.yaml`.

## Rule Tags

Rules use tags to communicate verdicts to the plugin broker:

| Tag | Effect |
|-----|--------|
| `coding_agent_deny` | Block the tool call |
| `coding_agent_ask` | Require user confirmation |
| `coding_agent_seen` | Signal evaluation complete (used only by `seen.yaml`) |

When multiple rules match the same event, verdict escalation applies: **deny > ask > allow**.

## Writing Rules

Rules use the standard [Falco rule language](https://falco.org/docs/rules/). Available fields:

| Field | Description |
|-------|-------------|
| `correlation.id` | Broker-assigned unique ID (used for verdict correlation) |
| `agent.name` | Coding agent identifier (e.g., `claude_code`) |
| `agent.os` | Host OS (`linux`, `macos`, `windows`, or `unknown`); static per build |
| `agent.session_id` | Session identifier |
| `agent.permission_mode` | Session permission mode (e.g. `default`, `acceptEdits`, `bypassPermissions`) |
| `agent.transcript_path` | Session transcript file path (empty when the agent reports `null`) |
| `agent.cwd` | Working directory (raw) |
| `agent.real_cwd` | Working directory (resolved, absolute) |
| `tool.use_id` | Unique identifier for this tool call |
| `tool.name` | Tool name (e.g., `Bash`, `Write`, `Edit`, `Read`) |
| `tool.input` | Full tool input as JSON |
| `tool.input_command` | Shell command (Bash only) |
| `tool.file_path` | Target file path (raw, Write/Edit/Read only) |
| `tool.real_file_path` | Target file path (resolved, absolute, Write/Edit/Read only) |

All rules must:
- Set `source: coding_agent`
- Use the appropriate verdict tag (`coding_agent_deny` or `coding_agent_ask`)
- Follow the output convention described below

### Output Convention

The rule `output:` field is an LLM-friendly sentence explaining what happened and why. It must start with "Falco" (e.g., "Falco blocked...", "Falco requires confirmation..."). Use resolved field values (e.g., `%tool.real_file_path`) so the message is informative. Avoid jargon or raw field names.

**Do not include structured key=value fields in the output.** The `append_output` config in `falco.coding_agents_plugin.yaml` automatically appends an AI agent instruction to every alert. The `correlation.id` field is a suggested output field (declared with `add_output()` in the plugin) and is always included in `output_fields`.

The catch-all seen rule (`seen.yaml`) includes all available fields in its output, providing a complete audit record for every event. Other rules only need the fields they reference in their message. Events can be correlated using `correlation.id`.

The broker passes the rendered message as the verdict reason, prefixed by the rule name: `"Rule Name: <rendered message>"`. So the coding agent sees:

```
Deny writing to sensitive paths: Falco blocked writing to /etc/passwd because it is a sensitive path | For AI Agents: inform the user that this action was flagged by a Falco rule | correlation=%correlation.id
```

### Example

A custom user rule that asks for confirmation before the agent edits a dependency lockfile (these files are produced by package managers — manual edits are usually a mistake worth confirming):

```yaml
- list: dependency_lockfiles
  items: [Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, go.sum, Pipfile.lock, poetry.lock]

- rule: Ask before modifying dependency lockfiles
  desc: Require confirmation before the agent edits a generated lockfile.
  condition: >
    tool.name in ("Write", "Edit")
    and tool.file_path != ""
    and basename(tool.file_path) in (dependency_lockfiles)
  output: >
    Falco requires confirmation before modifying dependency lockfile %tool.real_file_path
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]
```

### Tips

- Use `val()` for field-to-field comparisons: `tool.real_file_path startswith val(agent.real_cwd)`
- Use `basename()` to match file names: `basename(tool.file_path) = ".env"`
- Use `real_*` fields for policy matching (resolved paths)
- Use raw fields (`agent.cwd`, `tool.file_path`) for display and audit
