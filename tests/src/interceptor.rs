use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::mock_broker::{self, MockBroker, MockMode};

/// Result of running the interceptor binary.
pub struct InterceptorResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Find the interceptor binary.
pub fn interceptor_path() -> PathBuf {
    if let Ok(p) = std::env::var("HOOK") {
        return PathBuf::from(p);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let bin_name = if cfg!(windows) {
        "claude-interceptor.exe"
    } else {
        "claude-interceptor"
    };
    // Check common build locations. Cargo workspace layout puts binaries at
    // the workspace root target/; legacy per-crate layout is kept for
    // backwards compatibility.
    let candidates = [
        root.join("target/release").join(bin_name),
        root.join("target/x86_64-pc-windows-msvc/release").join(bin_name),
        root.join("target/aarch64-pc-windows-msvc/release").join(bin_name),
        root.join("hooks/claude-code/target/release").join(bin_name),
        root.join("hooks/claude-code/target/x86_64-pc-windows-msvc/release")
            .join(bin_name),
        root.join("hooks/claude-code/target/aarch64-pc-windows-msvc/release")
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

/// Run the interceptor binary with the given stdin input and socket path.
pub fn run_interceptor(
    input: &str,
    socket_path: &str,
    env_overrides: &[(&str, &str)],
) -> InterceptorResult {
    let hook = interceptor_path();
    let mut cmd = Command::new(&hook);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CODING_AGENTS_KIT_SOCKET", socket_path);
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

/// Run the interceptor against a mock broker with the given mode.
pub fn run_with_mock(mode: MockMode, input: &str, label: &str) -> InterceptorResult {
    let sock = mock_broker::temp_socket_path(label);
    let broker = MockBroker::start(&sock, mode);
    let result = run_interceptor(input, &sock.to_string_lossy(), &[]);
    broker.stop();
    result
}

/// Assert the interceptor output contains the expected verdict decision.
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
