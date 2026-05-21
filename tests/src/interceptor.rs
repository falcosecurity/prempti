use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::mock_broker::{self, MockBroker, MockMode};

/// Which interceptor binary to drive.
#[derive(Clone, Copy, Debug)]
pub enum AgentKind {
    Claude,
    Codex,
}

impl AgentKind {
    fn binary_name(self) -> &'static str {
        match self {
            AgentKind::Claude => {
                if cfg!(windows) {
                    "claude-interceptor.exe"
                } else {
                    "claude-interceptor"
                }
            }
            AgentKind::Codex => {
                if cfg!(windows) {
                    "codex-interceptor.exe"
                } else {
                    "codex-interceptor"
                }
            }
        }
    }

    fn legacy_per_crate_dir(self) -> &'static str {
        match self {
            AgentKind::Claude => "hooks/claude-code",
            AgentKind::Codex => "hooks/codex",
        }
    }

    fn env_override_var(self) -> &'static str {
        match self {
            AgentKind::Claude => "HOOK",
            AgentKind::Codex => "CODEX_HOOK",
        }
    }
}

/// Result of running the interceptor binary.
pub struct InterceptorResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Find the Claude Code interceptor binary. Preserved for back-compat with
/// existing call sites; prefer `interceptor_path_for(AgentKind::Claude)` in
/// new code.
pub fn interceptor_path() -> PathBuf {
    interceptor_path_for(AgentKind::Claude)
}

/// Find the interceptor binary for the given agent kind.
///
/// Resolution order:
/// 1. Per-agent env override (`HOOK` for claude, `CODEX_HOOK` for codex)
/// 2. Workspace `target/release/`
/// 3. Windows MSVC target dirs (release builds on Windows hosts)
/// 4. Legacy per-crate `target/release/` (older layouts)
pub fn interceptor_path_for(kind: AgentKind) -> PathBuf {
    if let Ok(p) = std::env::var(kind.env_override_var()) {
        return PathBuf::from(p);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let bin_name = kind.binary_name();
    let legacy_dir = kind.legacy_per_crate_dir();
    let candidates = [
        root.join("target/release").join(bin_name),
        root.join("target/x86_64-pc-windows-msvc/release").join(bin_name),
        root.join("target/aarch64-pc-windows-msvc/release").join(bin_name),
        root.join(legacy_dir).join("target/release").join(bin_name),
        root.join(legacy_dir)
            .join("target/x86_64-pc-windows-msvc/release")
            .join(bin_name),
        root.join(legacy_dir)
            .join("target/aarch64-pc-windows-msvc/release")
            .join(bin_name),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    // Default to the first candidate (will fail at spawn with a clear error).
    candidates[0].clone()
}

/// Run the Claude Code interceptor binary. Preserved for back-compat with
/// existing call sites; prefer `run_interceptor_for` in new code.
pub fn run_interceptor(
    input: &str,
    socket_path: &str,
    env_overrides: &[(&str, &str)],
) -> InterceptorResult {
    run_interceptor_for(AgentKind::Claude, input, socket_path, env_overrides)
}

/// Run the interceptor binary for the given agent kind with the given stdin
/// input and socket path.
pub fn run_interceptor_for(
    kind: AgentKind,
    input: &str,
    socket_path: &str,
    env_overrides: &[(&str, &str)],
) -> InterceptorResult {
    let hook = interceptor_path_for(kind);
    let mut cmd = Command::new(&hook);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PREMPTI_SOCKET", socket_path);
    for (k, v) in env_overrides {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn interceptor at {}: {}", hook.display(), e));

    // Write stdin and drop to signal EOF.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for interceptor");

    InterceptorResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    }
}

/// Run the Claude Code interceptor against a mock broker with the given mode.
pub fn run_with_mock(mode: MockMode, input: &str, label: &str) -> InterceptorResult {
    run_with_mock_for(AgentKind::Claude, mode, input, label)
}

/// Run the given agent's interceptor against a mock broker with the given mode.
pub fn run_with_mock_for(
    kind: AgentKind,
    mode: MockMode,
    input: &str,
    label: &str,
) -> InterceptorResult {
    let sock = mock_broker::temp_socket_path(label);
    let broker = MockBroker::start(&sock, mode);
    let result = run_interceptor_for(kind, input, &sock.to_string_lossy(), &[]);
    broker.stop();
    result
}

/// Assert the interceptor output contains the expected verdict decision.
/// Matches the Claude Code / Codex PreToolUse shape — both use the
/// `permissionDecision` field.
pub fn assert_decision(result: &InterceptorResult, expected: &str) {
    let needle = format!("\"permissionDecision\":\"{}\"", expected);
    assert!(
        result.stdout.contains(&needle),
        "expected decision={}, got stdout='{}' stderr='{}'",
        expected,
        result.stdout.trim(),
        result.stderr.trim()
    );
}

/// Assert the interceptor output reason contains the expected text.
pub fn assert_reason_contains(result: &InterceptorResult, needle: &str) {
    assert!(
        result.stdout.contains(needle),
        "expected reason to contain '{}', got stdout='{}' stderr='{}'",
        needle,
        result.stdout.trim(),
        result.stderr.trim()
    );
}

// ---------------------------------------------------------------------------
// Codex-specific assertion helpers
//
// Codex emits two distinct output shapes depending on hook_event_name:
//   PreToolUse        → hookSpecificOutput.permissionDecision
//   PermissionRequest → hookSpecificOutput.decision.behavior
//                     ± hookSpecificOutput.decision.message
// ---------------------------------------------------------------------------

fn parse_codex_stdout(result: &InterceptorResult) -> serde_json::Value {
    let trimmed = result.stdout.trim();
    serde_json::from_str::<serde_json::Value>(trimmed).unwrap_or_else(|e| {
        panic!(
            "invalid JSON stdout: {e}\n  stdout='{}'\n  stderr='{}'",
            trimmed,
            result.stderr.trim()
        )
    })
}

/// Assert the interceptor emitted a `PreToolUse` output with the expected
/// `permissionDecision`.
pub fn assert_codex_pretool_decision(result: &InterceptorResult, expected: &str) {
    let v = parse_codex_stdout(result);
    let event = &v["hookSpecificOutput"]["hookEventName"];
    assert_eq!(
        event, "PreToolUse",
        "expected hookEventName=PreToolUse, got {event} (full stdout: '{}')",
        result.stdout.trim()
    );
    let decision = &v["hookSpecificOutput"]["permissionDecision"];
    assert_eq!(
        decision, expected,
        "expected permissionDecision={expected}, got {decision} (full stdout: '{}')",
        result.stdout.trim()
    );
}

/// Assert the interceptor emitted a `PermissionRequest` output with the
/// expected `decision.behavior`.
pub fn assert_codex_permreq_behavior(result: &InterceptorResult, expected: &str) {
    let v = parse_codex_stdout(result);
    let event = &v["hookSpecificOutput"]["hookEventName"];
    assert_eq!(
        event, "PermissionRequest",
        "expected hookEventName=PermissionRequest, got {event} (full stdout: '{}')",
        result.stdout.trim()
    );
    let behavior = &v["hookSpecificOutput"]["decision"]["behavior"];
    assert_eq!(
        behavior, expected,
        "expected decision.behavior={expected}, got {behavior} (full stdout: '{}')",
        result.stdout.trim()
    );
}

/// Assert the interceptor's `PermissionRequest` deny message contains the
/// given substring.
pub fn assert_codex_permreq_message_contains(result: &InterceptorResult, needle: &str) {
    let v = parse_codex_stdout(result);
    let message = v["hookSpecificOutput"]["decision"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains(needle),
        "expected decision.message to contain '{needle}', got '{message}' (full stdout: '{}')",
        result.stdout.trim()
    );
}

/// Assert the interceptor's `PermissionRequest` output has no `message`
/// field (Codex's wire enum forbids it on `allow`).
pub fn assert_codex_permreq_no_message(result: &InterceptorResult) {
    let v = parse_codex_stdout(result);
    let has_message = v["hookSpecificOutput"]["decision"]
        .as_object()
        .map(|o| o.contains_key("message"))
        .unwrap_or(false);
    assert!(
        !has_message,
        "expected no message field on allow, got '{}'",
        result.stdout.trim()
    );
}
