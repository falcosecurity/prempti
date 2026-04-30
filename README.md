# Prempti

[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope)
[![Sandbox](https://img.shields.io/badge/status-sandbox-red?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#sandbox)

[![License](https://img.shields.io/github/license/falcosecurity/prempti?style=flat-square)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)
![Architectures](https://img.shields.io/badge/arch-x86__64%20%7C%20aarch64-blueviolet?style=flat-square)

> **Experimental Preview** — This project is under active development and released as an early preview. Interfaces and behavior may change between releases. We welcome your [feedback](#feedback) to help shape its future.

## Falco meets AI Coding Agents

[![asciicast](demo.gif)](https://asciinema.org/a/lXqokxXVO4Q3IH3W)

**Prempti** brings [Falco](https://falco.org) to the world of AI coding agents. It gives you guardrails that can deny or ask for confirmation on unwanted behaviors, plus real-time visibility into every tool call your coding agent makes — shell commands, file writes, reads, API calls. Both are driven by [Falco rules](https://falco.org/docs/rules/) you can customize to fit your workflow.

By default, **Prempti** runs in **guardrails mode**: rules produce verdicts that shape what the agent does. When a tool call is blocked or flagged, the agent receives an LLM-friendly explanation of why and adapts — the policy guides behavior through feedback. If you prefer pure observation without intervention, switch to **monitor mode**: every tool call proceeds while rules still evaluate and log the activity.

Who is this for? Anyone using a coding agent daily — developers, product managers, designers, vibe coders, and anyone else who wants to see what their agent is doing on their machine and set sensible boundaries for it.

### What It Is — and What It Isn't

**It is** a cooperative policy and visibility layer at the tool-call level. It gives you an audit trail of agent activity, and guardrails the agent respects because it sees and understands them.

**It is not** a sandbox, OS-level security, or a substitute for least-privilege environments or system hardening. It does not contain a determined adversarial agent. Use it alongside containment techniques — it complements them, it does not replace them.

## Features

- **Real-time tool-call interception** — every shell command, file write/edit/read, web fetch, and MCP call is evaluated *before* it runs.
- **Allow / deny / ask verdicts** — block, prompt for confirmation, or let it through; agents receive LLM-friendly feedback on denials and adapt.
- **Two operational modes** — *guardrails* (verdicts enforced) and *monitor* (observe-only); switch any time with `premptictl mode`.
- **Customizable Falco rules** — standard YAML rules; a curated default ruleset ships with the project covering common attack surfaces (credentials, sandbox-disable attempts, exfiltration, persistence, MCP/skill poisoning, and more).
- **Full audit trail** — every tool call recorded with structured fields, correlatable across rule alerts.
- **Cross-platform** — Linux, macOS, and Windows on x86_64 and aarch64.
- **CLI included** — `premptictl` for status, health checks, mode switching, log streaming, and hook management.
- **Rule-authoring skill for Claude Code** — an interactive skill to draft and validate custom rules with the help of your agent.

## How It Works

When your coding agent tries to use a tool, **Prempti** intercepts the call *before* it executes, evaluates it against your rules, and produces a verdict:

| Verdict | What Happens |
|---------|-------------|
| **Allow** | The tool call proceeds normally |
| **Deny** | The tool call is blocked — the agent is told why |
| **Ask** | You are prompted to approve or reject the call |

Rules are standard [Falco rules](https://falco.org/docs/rules/) written in YAML. A sensible default ruleset ships with **Prempti**, and you can add your own to customize behavior for your workflow (see [Custom Rules](#custom-rules)).

### Modes

- **Guardrails mode** (default) — verdicts are enforced: `deny` blocks, `ask` prompts you, `allow` proceeds.
- **Monitor mode** — all tool calls proceed; verdicts are still evaluated and logged but never act on the agent. Useful for pure observation, auditing, and rule tuning.

Switch between modes at any time with `premptictl mode <guardrails|monitor>`.

## When It Makes Sense

- When you want to see what your coding agent is actually doing during a session, without reading every tool call by hand.
- When you want to set clear boundaries — don't touch `.env` files, don't push to remote, don't write outside the project directory, etc.
- When you're experimenting with a coding agent and want a safety net against accidental mistakes.
- When a team wants to standardize how agents behave across members, using shareable YAML rules.
- Best used alongside sandboxing, system hardening, or least-privilege environments.

## Quick Start

> [!IMPORTANT]
> **Migrating from `coding-agents-kit`?** Prempti does not migrate or remove existing `coding-agents-kit` installations. Uninstall `coding-agents-kit` first to avoid duplicate services or stale Claude Code hooks.

### macOS

Download the universal `.pkg` installer from the [latest release](https://github.com/falcosecurity/prempti/releases/latest) and open it:

```bash
open prempti-<version>-darwin-universal.pkg
```

The macOS Installer wizard guides you through the setup. The service starts immediately and on every subsequent login.

To install non-interactively (CI, scripted setup, SSH session):

```bash
installer -pkg prempti-<version>-darwin-universal.pkg \
          -target CurrentUserHomeDirectory
```

> [!NOTE]
> Since the binaries are not code-signed, macOS Gatekeeper may block them on first run.
> Go to **System Settings > Privacy & Security** and allow the blocked binary, or clear the quarantine attribute from the whole install tree (executables in `bin/` and the plugin library in `share/` can both be flagged):
> ```bash
> xattr -dr com.apple.quarantine ~/.prempti
> ```

### Linux

Download the package for your architecture from the [latest release](https://github.com/falcosecurity/prempti/releases/latest):

```bash
tar xzf prempti-<version>-linux-x86_64.tar.gz
cd prempti-<version>-linux-x86_64
bash install.sh
```

The installer copies all components to `~/.prempti/`, starts a systemd user service, and registers the hook automatically.

### Windows

From the [latest release](https://github.com/falcosecurity/prempti/releases/latest), download **both** the `.msi` for your CPU architecture and the `Install-Prempti.ps1` helper, then run:

```powershell
powershell -ExecutionPolicy Bypass -File Install-Prempti.ps1
```

The helper runs the MSI, deploys all components to `%LOCALAPPDATA%\prempti\`, adds `bin\` to your user `PATH`, registers the Claude Code hook, registers an auto-start entry for subsequent logins, and starts the service immediately so Claude Code is protected without any extra step.

> [!NOTE]
> Pick the MSI that matches your CPU: `prempti-<version>-windows-x64.msi` on Intel/AMD64, `prempti-<version>-windows-arm64.msi` on Windows ARM64. The x64 MSI can install under emulation on ARM64 hosts but prefer the native ARM64 MSI for best performance. See [`installers/windows/`](installers/windows/) for build prerequisites and details.


### Verify

**Linux / macOS**

```bash
~/.prempti/bin/premptictl status
~/.prempti/bin/premptictl hook status
~/.prempti/bin/premptictl health
```

> **Tip:** Add `export PATH="$HOME/.prempti/bin:$PATH"` to your shell profile to use `premptictl` without the full path.

**Windows**

The installer starts the service automatically. Open a **new** terminal (so the updated `PATH` is picked up) and verify:

```powershell
premptictl status
premptictl hook status
premptictl health
```

Expected `health` output: `OK: pipeline healthy (synthetic event → allow)`.

If the service is not running (rare — e.g. the post-install timed out), start it manually with `premptictl start`. Auto-start on every login is already registered.

## Managing

The installer adds `bin/` to your shell `PATH` on Windows automatically; on Linux/macOS add it to your shell profile (see [Verify](#verify)). Once `premptictl` is on your `PATH`, the commands below are the same on every platform:

```bash
# Check status
premptictl status

# Check pipeline health (sends a synthetic event through the full stack)
premptictl health

# Guardrails mode (default) — verdicts are enforced: deny blocks, ask prompts
premptictl mode guardrails

# Monitor mode — all tool calls proceed; verdicts are only logged
premptictl mode monitor

# View logs. Defaults to the last 100 lines; pass -f to follow, --tail=N to override.
premptictl logs

# Temporarily disable interception (tool calls proceed unmonitored)
premptictl hook remove

# Re-enable interception
premptictl hook add

# Stop / start the service
premptictl stop
premptictl start
```

### Uninstall

**Linux / macOS**

```bash
~/.prempti/bin/premptictl uninstall

# Keep your custom rules in rules/user/ for a future reinstall:
~/.prempti/bin/premptictl uninstall --keep-user-rules
```

**Windows**

Any of these paths works — they all run the same cleanup custom action:

- ```powershell
  powershell -ExecutionPolicy Bypass -File Uninstall-Prempti.ps1
  ```
  (bundled with the release),
- Apps & Features,
- `msiexec /x <product-code>`.

The MSI removes the Claude Code hook, the auto-start entry, and the `bin\` `PATH` entry before removing files, so Claude Code is not left in a fail-closed state.

## Default Rules

The project ships with a default ruleset organized into six sections covering common attack surfaces for AI coding agents:

| Section | Coverage |
|---------|----------|
| Working-directory boundary | Monitor and ask on file access outside the session's project directory |
| Sensitive paths | Deny reads and writes to `/etc/`, `~/.ssh/`, `~/.aws/`, cloud credentials, `.env` files, etc. |
| Sandbox disable | Detect attempts to disable the agent's own sandbox configuration (Claude Code, Codex, Gemini CLI) |
| Threats | Credential access, destructive commands, pipe-to-shell, encoded payloads, exfiltration, IMDS access, reverse shells, supply-chain installs from known-malicious hosts |
| MCP and skill content | MCP server config poisoning (`.mcp.json`) and slash-command file injection (`.claude/commands/`) |
| Persistence vectors | Hook injection, git hooks, package-registry redirects, AI API base-URL overrides, API keys leaking into env files |

See [`rules/default/coding_agents_rules.yaml`](rules/default/coding_agents_rules.yaml) for the full ruleset. The schema, available fields, and authoring conventions are documented in [`rules/README.md`](rules/README.md).

## Custom Rules

The default ruleset is deliberately generic — it catches obviously risky actions that apply to most workflows. To get the most out of **Prempti**, you'll typically want to write your own rules tailored to your specific work: the projects you edit, the remotes you push to, the files you treat as sensitive, the commands you never want your agent to run.

Add your own rules to `~/.prempti/rules/user/`. They are preserved across upgrades. You can write them by hand, or use the [rule-authoring skill](#rule-authoring-skill-for-claude-code) to have Claude Code draft and validate them for you interactively.

New or edited rules take effect on the next service start — restart the service with:

```bash
premptictl stop
premptictl start
```

Example — block piping content to shell interpreters:

```yaml
- rule: Deny pipe to shell
  desc: Block piping content to shell interpreters
  condition: >
    tool.name = "Bash"
    and (tool.input_command contains "| sh"
         or tool.input_command contains "| bash"
         or tool.input_command contains "| zsh")
  output: >
    Falco blocked piping to a shell interpreter (%tool.input_command)
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
```

Rules are written in the standard [Falco rule language](https://falco.org/docs/rules/) (YAML). See [`rules/README.md`](rules/README.md) for all available fields and examples.

### Rule Authoring Skill for Claude Code

A Claude Code [skill](https://github.com/anthropics/skills) is included to help you write custom rules interactively.

Register this repository as a Claude Code Plugin marketplace:

```
/plugin marketplace add falcosecurity/prempti
```

Then install the skill directly:

```
/plugin install prempti-falco-rules@prempti-skills
```

Or browse and install interactively:

1. Select `Browse and install plugins`
2. Select `prempti-skills`
3. Select `prempti-falco-rules`
4. Select `Install now`

Once installed, ask Claude Code things like:
- "Block the agent from running git push"
- "Deny any read outside the working directory"
- "Create a rule that requires confirmation before editing Dockerfiles"

The skill guides Claude through writing the rule, placing it in the right directory, and validating it with Falco.

## Supported Agents & Platforms

| Agent | Platform | Status |
|-------|----------|--------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | Linux (x86_64, aarch64) | Supported |
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | macOS (Apple Silicon, Intel) | Supported |
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | Windows (x86_64, ARM64) | Supported |
| [Codex](https://openai.com/index/codex/) | Linux, macOS | Planned |

We are actively working on expanding agent and platform support. [Codex](https://openai.com/index/codex/) integration is next on the roadmap.

## Building from Source

<details>
<summary><strong>Linux</strong></summary>

Requires: Rust (latest stable)

```bash
make linux              # Both architectures
make linux-x86_64       # x86_64 only
make linux-aarch64      # aarch64 only (requires cross toolchain)
```

Output: `build/prempti-<version>-linux-{arch}.tar.gz`

See [`installers/linux/`](installers/linux/) for details.

</details>

<details>
<summary><strong>macOS</strong></summary>

Requires: Rust (latest stable), CMake >= 3.24, Xcode Command Line Tools, OpenSSL via Homebrew

```bash
# Install prerequisites
xcode-select --install
brew install cmake openssl@3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
make macos              # Native architecture of the host
make macos-aarch64      # Apple Silicon
make macos-x86_64       # Intel (native on Intel, or Rosetta cross-compile on Apple Silicon)
make macos-universal    # Universal binary (requires Rosetta + x86_64 Homebrew)
```

Output: `build/prempti-<version>-darwin-<arch>.{tar.gz,pkg}`

Install the locally-built artifact with either:

```bash
open build/prempti-<version>-darwin-<arch>.pkg           # GUI wizard
# or, non-interactive:
installer -pkg build/prempti-<version>-darwin-<arch>.pkg \
          -target CurrentUserHomeDirectory
# or, from the tarball:
tar xzf build/prempti-<version>-darwin-<arch>.tar.gz -C /tmp
bash /tmp/prempti-<version>-darwin-<arch>/install.sh
```

> Falco does not ship pre-built macOS binaries. The first build compiles Falco from source (~5 min). Subsequent builds use the cached binary.

See [`installers/macos/`](installers/macos/) for details.

</details>

<details>
<summary><strong>Windows</strong></summary>

Requires: Rust (latest stable), Visual Studio 2022+ with C++ workload, CMake 3.24+, vcpkg with curl, .NET Runtime 9+, WiX Toolset v7.

```powershell
powershell -ExecutionPolicy Bypass -File installers\windows\package.ps1
```

Output: `build/out/prempti-<version>-windows-<arch>.msi` (plus `Install-Prempti.ps1` and `Uninstall-Prempti.ps1` helpers).

> Falco is built from source on the first run (~10 min). Subsequent builds use the cached binary.

See [`installers/windows/`](installers/windows/) for detailed prerequisites and build options.

</details>

<details>
<summary><strong>Individual Components</strong></summary>

```bash
make build                # All components (interceptor, plugin, CLI tool)
make build-interceptor    # Interceptor only
make build-plugin         # Falco plugin only
make build-ctl            # CLI tool only
make falco-macos          # Falco binary (macOS only)
```

</details>

## Architecture

```
┌──────────────┐      ┌──────────────┐      ┌────────────────────────────┐
│ Coding Agent │─────>│ Interceptor  │─────>│     Falco (nodriver)       │
│              │      │   (hook)     │      │  ┌───────────────────────┐ │
│              │<─────│              │<─────│  │  Plugin (src + extract│ │
│              │      │              │      │  │  + embedded broker)   │ │
└──────────────┘      └──────────────┘      │  └───────────────────────┘ │
                                            │  Rule Engine + Rules       │
                                            └────────────────────────────┘
```

1. The coding agent's hook fires before each tool call
2. The **interceptor** sends the event to the plugin's embedded broker via Unix socket
3. The **plugin** feeds the event to Falco's rule engine
4. Matching rules produce verdicts (deny/ask/allow)
5. The **interceptor** delivers the verdict back to the coding agent

For design decisions, component specs, and full architectural documentation, see [CLAUDE.md](CLAUDE.md).

## Known Limitations

### Hook-level interception

**Prempti** intercepts tool calls at the coding agent's hook API — it sees the commands the agent asks to run, not the side effects those commands produce on the system.

This means that if a coding agent embeds harmful logic in a source file, compiles it, and then runs the resulting binary, Falco can inspect the compile and run commands but cannot analyze what the compiled program actually does at runtime. The rules see `gcc main.c -o main` and `./main`, not the system calls that `./main` makes.

Coverage is therefore asymmetric:

- Strongest for structured tools such as `Write`, `Edit`, and `Read`, where the agent exposes first-class file semantics.
- Weaker for generic tools such as `Bash`, where rules evaluate the declared command rather than fully resolved shell behavior.
- Input-side only for external systems such as MCP, where **Prempti** can inspect the requested call but not the side effects the MCP server later performs.

In practice, guardrails mode can block many unsafe or out-of-policy tool calls, but it is not OS-level containment and should not be treated as a hard boundary. For deeper visibility — detecting what processes actually do at the syscall level — Falco's kernel instrumentation (eBPF/kmod) is the right tool (at least for Linux).

## Feedback

Policy and visibility for AI coding agents is new territory — we're learning alongside the community.

If you're using **Prempti**, we'd love to hear from you:

- **What works?** What rules have you written? What did you catch?
- **What's missing?** What agents or platforms do you need?
- **What broke?** What didn't work as expected?

Your experience directly shapes where this project goes next. Open an [issue](https://github.com/falcosecurity/prempti/issues), or reach out to the maintainers. Every bit of feedback helps.

## Credits

**Prempti** was built with significant assistance from [Claude Code](https://github.com/anthropics/claude-code).

Initial research and ideation by [Leonardo Grasso](https://github.com/leogr), [Loris Degioanni](https://github.com/ldegio), and [Michael Clark](https://github.com/MikeC-Sysdig).

Support and testing by [Alessandro Cannarella](https://github.com/c2ndev), [Iacopo Rozzo](https://github.com/irozzo-1a), and [Leonardo Di Giovanna](https://github.com/ekoops).

## License

Apache License 2.0. See [LICENSE](LICENSE).
