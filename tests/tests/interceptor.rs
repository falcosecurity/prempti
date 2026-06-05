use std::time::Duration;

use prempti_tests::interceptor::{
    assert_decision, assert_empty_stdout, assert_reason_contains, run_interceptor, run_with_mock,
};
use prempti_tests::mock_broker::{self, MockMode};

const SAMPLE: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"test-sess","cwd":"/tmp","tool_use_id":"toolu_test123"}"#;

#[test]
fn allow_verdict() {
    let r = run_with_mock(MockMode::Allow, SAMPLE, "allow");
    assert_decision(&r, "allow");
}

#[test]
fn deny_verdict() {
    let r = run_with_mock(MockMode::Deny, SAMPLE, "deny");
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "blocked by test rule");
}

#[test]
fn ask_verdict() {
    let r = run_with_mock(MockMode::Ask, SAMPLE, "ask");
    assert_decision(&r, "ask");
    assert_reason_contains(&r, "requires confirmation");
}

#[test]
fn defer_verdict_emits_empty_stdout() {
    // The `defer` no-match floor (default_action = defer, and monitor/
    // passthrough) renders as exit 0 with empty stdout, which Claude Code
    // treats as "no decision; the normal permission flow applies" — NOT a
    // forced allow, and NOT permissionDecision:"defer" (a -p/SDK-only value
    // that would pause the tool call).
    let r = run_with_mock(MockMode::Defer, SAMPLE, "defer");
    assert_empty_stdout(&r);
}

#[test]
fn broker_unreachable_fail_closed() {
    let sock = mock_broker::temp_socket_path("unreachable");
    // No broker started — socket doesn't exist.
    let r = run_interceptor(SAMPLE, &sock.to_string_lossy(), &[]);
    assert_decision(&r, "deny");
}

#[test]
fn bad_json_response() {
    let r = run_with_mock(MockMode::BadJson, SAMPLE, "badjson");
    assert_decision(&r, "deny");
}

#[test]
fn wrong_id_response() {
    let r = run_with_mock(MockMode::WrongId, SAMPLE, "wrongid");
    assert_decision(&r, "deny");
}

#[test]
fn timeout() {
    let sock = mock_broker::temp_socket_path("timeout");
    let broker = mock_broker::MockBroker::start(&sock, MockMode::Slow(Duration::from_secs(3)));
    let r = run_interceptor(
        SAMPLE,
        &sock.to_string_lossy(),
        &[("PREMPTI_TIMEOUT_MS", "200")],
    );
    assert_decision(&r, "deny");
    drop(broker);
}

#[test]
fn broker_closes_connection() {
    let r = run_with_mock(MockMode::Close, SAMPLE, "close");
    assert_decision(&r, "deny");
}

#[test]
fn empty_stdin() {
    let sock = mock_broker::temp_socket_path("empty");
    let r = run_interceptor("", &sock.to_string_lossy(), &[]);
    assert_eq!(r.exit_code, 2, "expected exit 2 for empty stdin, got {}", r.exit_code);
}

#[test]
fn malformed_json() {
    let sock = mock_broker::temp_socket_path("malformed");
    let r = run_interceptor("not json", &sock.to_string_lossy(), &[]);
    assert_eq!(r.exit_code, 2, "expected exit 2 for malformed JSON, got {}", r.exit_code);
}

#[test]
fn missing_tool_name_no_broker() {
    let sock = mock_broker::temp_socket_path("notool");
    // Valid JSON but no tool_name — interceptor proceeds but broker unreachable → deny.
    let r = run_interceptor(
        r#"{"hook_event_name":"PreToolUse","tool_input":{}}"#,
        &sock.to_string_lossy(),
        &[],
    );
    assert_decision(&r, "deny");
}

#[test]
fn write_tool_path() {
    let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/file.txt","content":"hello"},"session_id":"s1","cwd":"/tmp","tool_use_id":"t2"}"#;
    let r = run_with_mock(MockMode::Allow, input, "write");
    assert_decision(&r, "allow");
}

#[test]
fn mcp_tool() {
    let input = r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__github__create_issue","tool_input":{"title":"test"},"session_id":"s1","cwd":"/tmp","tool_use_id":"t3"}"#;
    let r = run_with_mock(MockMode::Allow, input, "mcp");
    assert_decision(&r, "allow");
}

#[test]
fn large_tool_input() {
    let large_cmd = "x".repeat(60000);
    let input = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{}"}},"session_id":"s1","cwd":"/tmp","tool_use_id":"t4"}}"#,
        large_cmd
    );
    let r = run_with_mock(MockMode::Allow, &input, "large");
    assert_decision(&r, "allow");
}

#[test]
fn nested_key_spoofing() {
    // tool_name at the top level should win; a nested tool_name should not be extracted.
    let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","nested":{"tool_name":"SPOOFED"}},"session_id":"s1","cwd":"/tmp","tool_use_id":"t5"}"#;
    let r = run_with_mock(MockMode::Allow, input, "spoof");
    assert_decision(&r, "allow");
}

#[test]
fn json_escape_in_command() {
    let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo \"hello world\""},"session_id":"s1","cwd":"/tmp","tool_use_id":"t6"}"#;
    let r = run_with_mock(MockMode::Allow, input, "escape");
    assert_decision(&r, "allow");
}

#[test]
fn path_traversal_normalization() {
    // The interceptor should pass this through; normalization happens in the plugin.
    let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/myproject/../../etc/passwd","content":"x"},"session_id":"s1","cwd":"/tmp/myproject","tool_use_id":"t7"}"#;
    let r = run_with_mock(MockMode::Allow, input, "traversal");
    assert_decision(&r, "allow");
}
