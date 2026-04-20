use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::interceptor;

/// E2E test harness managing a Falco process with the coding-agent plugin.
pub struct E2eHarness {
    falco: Child,
    pub socket_path: PathBuf,
    pub e2e_dir: PathBuf,
    pub http_port: u16,
}

/// Find the Falco binary from the project's own build output.
/// Does NOT use system Falco — only looks in known build directories
/// and the FALCO env var (for CI to point at the built binary).
pub fn find_falco() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FALCO") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let candidates: Vec<PathBuf> = if cfg!(windows) {
        vec![
            root.join("build/stage-windows-x64/bin/falco.exe"),
            root.join("build/stage-windows-arm64/bin/falco.exe"),
            root.join("build/falco-0.43.0-windows-x64/falco.exe"),
            root.join("build/falco-0.43.0-windows-arm64/falco.exe"),
        ]
    } else if cfg!(target_os = "macos") {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        vec![root.join(format!("build/falco-0.43.0-darwin-{arch}/falco"))]
    } else {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        vec![root.join(format!(
            "build/falco-0.43.0-{arch}/usr/bin/falco"
        ))]
    };
    for c in candidates {
        if c.exists() {
            return Some(c);
        }
    }
    None
}

/// Find the plugin shared library.
pub fn find_plugin_lib() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let (prefix, ext) = if cfg!(windows) {
        ("", "dll")
    } else if cfg!(target_os = "macos") {
        ("lib", "dylib")
    } else {
        ("lib", "so")
    };
    let name = format!("{prefix}coding_agent.{ext}");
    // Check the workspace target/ tree first (cargo workspace layout);
    // fall back to the legacy per-crate target/ for older checkouts.
    let candidates = [
        root.join("target/release").join(&name),
        root.join("plugins/coding-agent-plugin/target/release").join(&name),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Macro to skip a test if Falco or the plugin is not available.
#[macro_export]
macro_rules! skip_unless_falco {
    ($falco:ident, $plugin:ident) => {
        let Some($falco) = $crate::e2e::find_falco() else {
            eprintln!("SKIP: falco not found");
            return;
        };
        let Some($plugin) = $crate::e2e::find_plugin_lib() else {
            eprintln!("SKIP: plugin library not built");
            return;
        };
    };
}

impl E2eHarness {
    /// Start Falco with the plugin in the given mode.
    /// Returns `None` if Falco or the plugin is not available.
    pub fn start(mode: &str) -> Option<Self> {
        let falco_bin = find_falco()?;
        let plugin_lib = find_plugin_lib()?;
        let hook_bin = interceptor::interceptor_path();
        if !hook_bin.exists() {
            eprintln!("SKIP: interceptor binary not found");
            return None;
        }

        let pid = std::process::id();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let e2e_dir = root.join(format!("build/e2e-{pid}"));
        let _ = std::fs::create_dir_all(&e2e_dir);

        let rules_dir = e2e_dir.join("rules");
        let _ = std::fs::create_dir_all(&rules_dir);

        let socket_path = e2e_dir.join("broker.sock");
        let http_port = 19000 + (pid % 1000) as u16;

        // Write rules.
        write_rules(&rules_dir);

        // Write Falco config.
        let config_path = e2e_dir.join("falco.yaml");
        write_falco_config(
            &config_path,
            &plugin_lib,
            &socket_path,
            &rules_dir,
            http_port,
            mode,
        );

        // Start Falco.
        let falco_dir = falco_bin.parent().unwrap_or(Path::new("."));
        let mut cmd = Command::new(&falco_bin);
        cmd.arg("-U")
            .arg("-c")
            .arg(&config_path)
            .arg("--disable-source")
            .arg("syscall")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(falco_dir);

        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn falco at {}: {e}", falco_bin.display()));

        // Wait for broker socket to appear.
        let mut ready = false;
        for _ in 0..40 {
            if socket_path.exists() {
                ready = true;
                break;
            }
            if let Some(status) = child.try_wait().ok().flatten() {
                eprintln!("ERROR: Falco exited early with code {status}");
                // Drain stderr for diagnostics.
                if let Some(mut stderr) = child.stderr.take() {
                    let mut buf = String::new();
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut buf);
                    eprintln!("Falco stderr: {buf}");
                }
                return None;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        if !ready {
            eprintln!("ERROR: Falco broker socket not found after 8s: {}", socket_path.display());
            let _ = child.kill();
            return None;
        }

        // Extra wait for HTTP server.
        std::thread::sleep(Duration::from_millis(500));

        Some(E2eHarness {
            falco: child,
            socket_path,
            e2e_dir,
            http_port,
        })
    }

    /// Run a hook event through the interceptor against this Falco instance.
    pub fn run_hook(&self, input: &str) -> interceptor::InterceptorResult {
        interceptor::run_interceptor(input, &self.socket_path.to_string_lossy(), &[])
    }

    /// Build a hook JSON input string.
    pub fn make_input(
        tool_name: &str,
        tool_input: &str,
        cwd: &str,
        tool_use_id: &str,
    ) -> String {
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"{}","tool_input":{},"session_id":"e2e-test","cwd":"{}","tool_use_id":"{}"}}"#,
            tool_name, tool_input, cwd, tool_use_id
        )
    }
}

impl Drop for E2eHarness {
    fn drop(&mut self) {
        let _ = self.falco.kill();
        let _ = self.falco.wait();
        // Small delay to release file handles before cleanup.
        std::thread::sleep(Duration::from_millis(200));
        let _ = std::fs::remove_dir_all(&self.e2e_dir);
    }
}

fn to_forward_slashes(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn write_falco_config(
    config_path: &Path,
    plugin_lib: &Path,
    socket_path: &Path,
    rules_dir: &Path,
    http_port: u16,
    mode: &str,
) {
    let deny_rules = to_forward_slashes(&rules_dir.join("deny.yaml"));
    let seen_rules = to_forward_slashes(&rules_dir.join("seen.yaml"));
    let plugin_path = to_forward_slashes(plugin_lib);
    let sock_path = to_forward_slashes(socket_path);

    let config = format!(
        r#"engine:
  kind: nodriver
plugins:
  - name: coding_agent
    library_path: {plugin_path}
    init_config:
      socket_path: "{sock_path}"
      http_port: {http_port}
      mode: {mode}
load_plugins:
  - coding_agent
rules_files:
  - {deny_rules}
  - {seen_rules}
json_output: true
json_include_message_property: true
json_include_output_property: false
json_include_output_fields_property: true
json_include_tags_property: true
rule_matching: all
priority: debug
http_output:
  enabled: true
  url: http://127.0.0.1:{http_port}
stdout_output:
  enabled: false
syslog_output:
  enabled: false
"#
    );
    std::fs::write(config_path, config).expect("failed to write falco config");
}

fn write_rules(rules_dir: &Path) {
    // On macOS, /etc is a symlink to /private/etc. The plugin resolves paths
    // via canonicalize() when the file exists, but falls back to lexical
    // normalization when it doesn't (common in tests). Rules must match both
    // forms: /etc/... and /private/etc/...
    let sensitive_write_condition = if cfg!(windows) {
        r#"tool.name in ("Write", "Edit") and tool.real_file_path startswith "C:/Windows""#
    } else if cfg!(target_os = "macos") {
        r#"tool.name in ("Write", "Edit") and (tool.real_file_path startswith "/etc" or tool.real_file_path startswith "/private/etc")"#
    } else {
        r#"tool.name in ("Write", "Edit") and tool.real_file_path startswith "/etc""#
    };
    let sensitive_read_condition = if cfg!(windows) {
        r#"tool.name = "Read" and (tool.real_file_path startswith "C:/Windows" or tool.real_file_path contains ".ssh")"#
    } else if cfg!(target_os = "macos") {
        r#"tool.name = "Read" and (tool.real_file_path startswith "/etc" or tool.real_file_path startswith "/private/etc" or tool.real_file_path contains ".ssh" or tool.real_file_path contains ".aws")"#
    } else {
        r#"tool.name = "Read" and (tool.real_file_path startswith "/etc" or tool.real_file_path contains ".ssh" or tool.real_file_path contains ".aws")"#
    };

    let deny_rules = format!(
        r#"- rule: Deny rm -rf
  desc: Block dangerous rm -rf commands
  condition: tool.name = "Bash" and tool.input_command contains "rm -rf"
  output: "Falco blocked rm -rf: %tool.input_command | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writes to sensitive paths
  desc: Block writes to sensitive system directories
  condition: {sensitive_write_condition}
  output: "Falco blocked writing to %tool.real_file_path | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writing to ssh dir
  desc: Block writes to .ssh directories
  condition: tool.name in ("Write", "Edit") and tool.real_file_path contains "/.ssh/"
  output: "Falco blocked writing to %tool.real_file_path because .ssh is sensitive | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Ask write outside cwd
  desc: Require confirmation for writes outside working directory
  condition: tool.name in ("Write", "Edit") and not tool.real_file_path startswith val(agent.real_cwd)
  output: "Falco asks about writing to %tool.real_file_path outside %agent.real_cwd | correlation=%correlation.id"
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]

- rule: Deny reading sensitive paths
  desc: Block reads from sensitive paths
  condition: {sensitive_read_condition}
  output: "Falco blocked reading %tool.real_file_path | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Audit read outside cwd
  desc: Log reads outside working directory (monitor only, no enforcement)
  condition: tool.name = "Read" and not tool.real_file_path startswith val(agent.real_cwd)
  output: "Falco noticed read outside cwd %tool.real_file_path | correlation=%correlation.id"
  priority: NOTICE
  source: coding_agent
  tags: []
"#
    );
    std::fs::write(rules_dir.join("deny.yaml"), deny_rules).expect("failed to write deny rules");

    let seen_rule = r#"- rule: Coding Agent Event Seen
  desc: Catch-all rule signaling evaluation complete
  condition: correlation.id > 0
  output: "id=%correlation.id agent=%agent.name tool=%tool.name cwd=%agent.real_cwd path=%tool.real_file_path cmd=%tool.input_command"
  priority: DEBUG
  source: coding_agent
  tags: [coding_agent_seen]
"#;
    std::fs::write(rules_dir.join("seen.yaml"), seen_rule).expect("failed to write seen rule");
}
