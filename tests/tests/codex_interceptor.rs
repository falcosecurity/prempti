use std::time::Duration;

use prempti_tests::interceptor::{
    assert_codex_permreq_behavior, assert_codex_permreq_message_contains,
    assert_codex_permreq_no_message, assert_codex_pretool_decision, assert_reason_contains,
    run_interceptor_for, run_with_mock_for, AgentKind,
};
use prempti_tests::mock_broker::{self, MockBroker, MockMode};

const CODEX: AgentKind = AgentKind::Codex;

// Canonical Codex PreToolUse input — matches the upstream schema fixture
// (codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json):
// all 10 required fields, snake_case, with tool_use_id present.
//
// Kept on a single line because the interceptor passes the raw event JSON
// through to the broker verbatim via `serde_json::value::RawValue`. The
// mock broker reads requests with `read_line`, so embedded newlines would
// truncate the wire request and cause an ID echo mismatch.
const PRE_TOOL_USE: &str = r#"{"session_id":"sess-codex-1","turn_id":"turn-1","transcript_path":null,"cwd":"/work","hook_event_name":"PreToolUse","model":"gpt-5-codex","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls -la"},"tool_use_id":"tu-1"}"#;

// Canonical Codex PermissionRequest input — same shape as PreToolUse but
// without tool_use_id (omitted per the upstream schema). Single-line for
// the same reason as PRE_TOOL_USE above.
const PERMISSION_REQUEST: &str = r#"{"session_id":"sess-codex-2","turn_id":"turn-7","transcript_path":null,"cwd":"/work","hook_event_name":"PermissionRequest","model":"gpt-5-codex","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;

// ---------------------------------------------------------------------------
// PreToolUse: verdict translation through the live binary
// ---------------------------------------------------------------------------

#[test]
fn pretool_allow_verdict() {
    let r = run_with_mock_for(CODEX, MockMode::Allow, PRE_TOOL_USE, "codex-pre-allow");
    assert_codex_pretool_decision(&r, "allow");
}

#[test]
fn pretool_deny_verdict() {
    let r = run_with_mock_for(CODEX, MockMode::Deny, PRE_TOOL_USE, "codex-pre-deny");
    assert_codex_pretool_decision(&r, "deny");
    assert_reason_contains(&r, "blocked by test rule");
}

#[test]
fn pretool_ask_passes_through_as_allow() {
    // Key UX test: PreToolUse cannot surface 'ask' to the user on Codex,
    // so the interceptor returns allow and lets the tool call proceed into
    // Codex's approval flow (where PermissionRequest fires instead).
    let r = run_with_mock_for(CODEX, MockMode::Ask, PRE_TOOL_USE, "codex-pre-ask");
    assert_codex_pretool_decision(&r, "allow");
}

// ---------------------------------------------------------------------------
// PreToolUse: broker error paths (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn pretool_broker_unreachable_fail_closed() {
    let sock = mock_broker::temp_socket_path("codex-pre-unreach");
    let r = run_interceptor_for(CODEX, PRE_TOOL_USE, &sock.to_string_lossy(), &[]);
    assert_codex_pretool_decision(&r, "deny");
}

#[test]
fn pretool_bad_json_response() {
    let r = run_with_mock_for(CODEX, MockMode::BadJson, PRE_TOOL_USE, "codex-pre-badjson");
    assert_codex_pretool_decision(&r, "deny");
}

#[test]
fn pretool_wrong_id_response() {
    let r = run_with_mock_for(CODEX, MockMode::WrongId, PRE_TOOL_USE, "codex-pre-wrongid");
    assert_codex_pretool_decision(&r, "deny");
}

#[test]
fn pretool_timeout_fail_closed() {
    let sock = mock_broker::temp_socket_path("codex-pre-timeout");
    let broker = MockBroker::start(&sock, MockMode::Slow(Duration::from_secs(3)));
    let r = run_interceptor_for(
        CODEX,
        PRE_TOOL_USE,
        &sock.to_string_lossy(),
        &[("PREMPTI_TIMEOUT_MS", "200")],
    );
    assert_codex_pretool_decision(&r, "deny");
    drop(broker);
}

#[test]
fn pretool_broker_closes_connection() {
    let r = run_with_mock_for(CODEX, MockMode::Close, PRE_TOOL_USE, "codex-pre-close");
    assert_codex_pretool_decision(&r, "deny");
}

// ---------------------------------------------------------------------------
// PreToolUse: fail-open env override
// ---------------------------------------------------------------------------

#[test]
fn pretool_fail_open_yields_allow_when_broker_unreachable() {
    let sock = mock_broker::temp_socket_path("codex-pre-failopen");
    let r = run_interceptor_for(
        CODEX,
        PRE_TOOL_USE,
        &sock.to_string_lossy(),
        &[("PREMPTI_FAIL_OPEN", "1")],
    );
    assert_codex_pretool_decision(&r, "allow");
}

// ---------------------------------------------------------------------------
// PermissionRequest: verdict translation through the live binary
// ---------------------------------------------------------------------------

#[test]
fn permreq_allow_omits_message_field() {
    let r = run_with_mock_for(CODEX, MockMode::Allow, PERMISSION_REQUEST, "codex-pr-allow");
    assert_codex_permreq_behavior(&r, "allow");
    // Codex's wire enum has `behavior: "allow"` with no message field —
    // emitting one would be schema-invalid.
    assert_codex_permreq_no_message(&r);
}

#[test]
fn permreq_deny_includes_reason_as_message() {
    let r = run_with_mock_for(CODEX, MockMode::Deny, PERMISSION_REQUEST, "codex-pr-deny");
    assert_codex_permreq_behavior(&r, "deny");
    assert_codex_permreq_message_contains(&r, "blocked by test rule");
}

#[test]
fn permreq_ask_becomes_deny_with_reason() {
    // Key UX test: PermissionRequest is the mount point where ask
    // semantics are preserved. Falco's ask is rendered as Codex deny so
    // the user actually sees the rule reason in Codex's approval UX.
    let r = run_with_mock_for(CODEX, MockMode::Ask, PERMISSION_REQUEST, "codex-pr-ask");
    assert_codex_permreq_behavior(&r, "deny");
    assert_codex_permreq_message_contains(&r, "requires confirmation");
}

// ---------------------------------------------------------------------------
// PermissionRequest: broker error paths (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn permreq_broker_unreachable_fail_closed() {
    let sock = mock_broker::temp_socket_path("codex-pr-unreach");
    let r = run_interceptor_for(CODEX, PERMISSION_REQUEST, &sock.to_string_lossy(), &[]);
    assert_codex_permreq_behavior(&r, "deny");
    // Fail-closed reason surfaces to the user via Codex's approval UX, so
    // it had better mention what went wrong rather than emitting an empty
    // string.
    assert_codex_permreq_message_contains(&r, "broker");
}

#[test]
fn permreq_fail_open_yields_allow_when_broker_unreachable() {
    let sock = mock_broker::temp_socket_path("codex-pr-failopen");
    let r = run_interceptor_for(
        CODEX,
        PERMISSION_REQUEST,
        &sock.to_string_lossy(),
        &[("PREMPTI_FAIL_OPEN", "1")],
    );
    assert_codex_permreq_behavior(&r, "allow");
    assert_codex_permreq_no_message(&r);
}

// ---------------------------------------------------------------------------
// PermissionRequest: correlation via turn_id (no tool_use_id available)
// ---------------------------------------------------------------------------

#[test]
fn permreq_without_tool_use_id_still_completes() {
    // Smoke test that the interceptor's tool_use_id → turn_id → "unknown"
    // fallback chain handles a real PermissionRequest input (which the
    // upstream schema does not include tool_use_id for). Failure here would
    // mean the broker received a request whose id couldn't be echoed back
    // and the interceptor rejected it as a mismatch.
    let r = run_with_mock_for(CODEX, MockMode::Allow, PERMISSION_REQUEST, "codex-pr-noid");
    assert_codex_permreq_behavior(&r, "allow");
}

// ---------------------------------------------------------------------------
// Input validation (no broker needed; exit 2 = block on Codex)
// ---------------------------------------------------------------------------

#[test]
fn empty_stdin_exits_two() {
    let sock = mock_broker::temp_socket_path("codex-empty");
    let r = run_interceptor_for(CODEX, "", &sock.to_string_lossy(), &[]);
    assert_eq!(
        r.exit_code, 2,
        "expected exit 2 for empty stdin, got {} stderr='{}'",
        r.exit_code,
        r.stderr.trim()
    );
}

#[test]
fn malformed_json_exits_two() {
    let sock = mock_broker::temp_socket_path("codex-malformed");
    let r = run_interceptor_for(CODEX, "not json", &sock.to_string_lossy(), &[]);
    assert_eq!(
        r.exit_code, 2,
        "expected exit 2 for malformed JSON, got {} stderr='{}'",
        r.exit_code,
        r.stderr.trim()
    );
}

#[test]
fn unsupported_event_exits_two() {
    // Codex has 10 hook events; the interceptor handles two. Registering
    // it for PostToolUse / SubagentStart / etc. is a configuration error
    // and must fail loudly rather than silently allowing.
    let sock = mock_broker::temp_socket_path("codex-post");
    let input = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{}}"#;
    let r = run_interceptor_for(CODEX, input, &sock.to_string_lossy(), &[]);
    assert_eq!(
        r.exit_code, 2,
        "expected exit 2 for unsupported event, got {} stderr='{}'",
        r.exit_code,
        r.stderr.trim()
    );
    assert!(
        r.stderr.contains("unsupported hook_event_name"),
        "expected stderr to explain the rejection, got '{}'",
        r.stderr.trim()
    );
}

#[test]
fn missing_event_name_exits_two() {
    let sock = mock_broker::temp_socket_path("codex-noevent");
    // Valid JSON, missing hook_event_name → unsupported (parses as "").
    let r = run_interceptor_for(
        CODEX,
        r#"{"tool_name":"Bash","tool_input":{}}"#,
        &sock.to_string_lossy(),
        &[],
    );
    assert_eq!(r.exit_code, 2);
}

// ---------------------------------------------------------------------------
// PreToolUse: tool-input shape variants the interceptor should pass through
// ---------------------------------------------------------------------------

#[test]
fn apply_patch_tool_passes_through() {
    // Codex's file-write tool. The interceptor doesn't care about the
    // tool name; it just forwards to the broker. Path-resolution gaps
    // are a plugin-layer concern, not an interceptor concern.
    let input = r#"{"session_id":"s","turn_id":"t","transcript_path":null,"cwd":"/work","hook_event_name":"PreToolUse","model":"x","permission_mode":"default","tool_name":"apply_patch","tool_input":{"input":"diff content"},"tool_use_id":"tu-apply"}"#;
    let r = run_with_mock_for(CODEX, MockMode::Allow, input, "codex-apply-patch");
    assert_codex_pretool_decision(&r, "allow");
}

#[test]
fn mcp_tool_passes_through() {
    let input = r#"{"session_id":"s","turn_id":"t","transcript_path":null,"cwd":"/work","hook_event_name":"PreToolUse","model":"x","permission_mode":"default","tool_name":"mcp__github__create_issue","tool_input":{"title":"test"},"tool_use_id":"tu-mcp"}"#;
    let r = run_with_mock_for(CODEX, MockMode::Allow, input, "codex-mcp");
    assert_codex_pretool_decision(&r, "allow");
}

#[test]
fn dont_ask_permission_mode_passes_through() {
    // Codex-only permission_mode value. Interceptor must not reject it.
    let input = r#"{"session_id":"s","turn_id":"t","transcript_path":null,"cwd":"/work","hook_event_name":"PreToolUse","model":"x","permission_mode":"dontAsk","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"tu-da"}"#;
    let r = run_with_mock_for(CODEX, MockMode::Allow, input, "codex-dontask");
    assert_codex_pretool_decision(&r, "allow");
}
