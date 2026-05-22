// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 The Falco Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Codex CLI interceptor — thin bridge between Codex's hook events and the
//! Prempti plugin broker.
//!
//! Mounts on two Codex hook events:
//! - `PreToolUse`: broker `deny` → Codex `deny`; broker `ask` → Codex `allow`
//!   (let through to the approval flow); broker `allow` → Codex `allow`.
//! - `PermissionRequest`: broker `deny` → Codex `deny`; broker `ask` → Codex
//!   `deny` with the rule reason as the message (user sees it via Codex's
//!   approval UX); broker `allow` → Codex `allow`.
//!
//! Codex's hook input is snake_case; its hook output is camelCase. The
//! interceptor does not interpret the input — it forwards the raw bytes to
//! the broker via the same wire envelope as the Claude Code interceptor.

use serde::{Deserialize, Serialize};
use std::env;
use std::io::{self, BufRead, Read, Write};
#[cfg(unix)]
use std::net::Shutdown;
use std::process;
use std::time::Duration;

mod proc_lineage;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Minimal parse of stdin — extract just enough to route + correlate.
/// All other fields are passed through as raw JSON in the envelope.
#[derive(Deserialize)]
struct HookInputMinimal {
    #[serde(default)]
    hook_event_name: String,
    /// Present on PreToolUse, absent on PermissionRequest.
    #[serde(default)]
    tool_use_id: String,
    /// Codex-only field; finer correlation than session_id. Used as the
    /// echo ID when tool_use_id is absent (PermissionRequest).
    #[serde(default)]
    turn_id: String,
}

/// Wire protocol request (interceptor → broker). Identical envelope to the
/// Claude Code interceptor; `agent_name` is the only routing distinction.
#[derive(Serialize)]
struct Request<'a> {
    version: u32,
    id: &'a str,
    agent_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_pid: Option<u64>,
    event: &'a serde_json::value::RawValue,
}

/// Wire protocol response (broker → interceptor).
#[derive(Deserialize)]
struct Response {
    id: String,
    decision: String,
    #[serde(default)]
    reason: String,
}

// --- Codex PreToolUse output -----------------------------------------------

#[derive(Serialize)]
struct PreToolUseOutput<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: PreToolUseHookSpecificOutput<'a>,
}

#[derive(Serialize)]
struct PreToolUseHookSpecificOutput<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

// --- Codex PermissionRequest output ----------------------------------------

#[derive(Serialize)]
struct PermissionRequestOutput<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: PermissionRequestHookSpecificOutput<'a>,
}

#[derive(Serialize)]
struct PermissionRequestHookSpecificOutput<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    decision: PermissionRequestDecision<'a>,
}

#[derive(Serialize)]
struct PermissionRequestDecision<'a> {
    behavior: &'a str,
    /// Only present on deny; omitted on allow per Codex's wire enum
    /// (`PermissionRequestBehaviorWire` in `codex-rs/hooks/src/schema.rs`).
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS: u64 = 5000;
const TIMEOUT_MIN_MS: u64 = 100;
const TIMEOUT_MAX_MS: u64 = 30000;
#[cfg(unix)]
const SOCKET_SUFFIX: &str = "/.prempti/run/broker.sock";
const INPUT_MAX: usize = 64 * 1024;
const RESPONSE_MAX: u64 = 64 * 1024;

const EVENT_PRE_TOOL_USE: &str = "PreToolUse";
const EVENT_PERMISSION_REQUEST: &str = "PermissionRequest";

const FALLBACK_DENY_PRE_TOOL_USE: &[u8] = b"{\"hookSpecificOutput\":{\
    \"hookEventName\":\"PreToolUse\",\
    \"permissionDecision\":\"deny\",\
    \"permissionDecisionReason\":\"internal serialization error\"}}\n";

const FALLBACK_DENY_PERMISSION_REQUEST: &[u8] = b"{\"hookSpecificOutput\":{\
    \"hookEventName\":\"PermissionRequest\",\
    \"decision\":{\"behavior\":\"deny\",\
    \"message\":\"internal serialization error\"}}}\n";

// ---------------------------------------------------------------------------
// Verdict translation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodexEvent {
    PreToolUse,
    PermissionRequest,
}

impl CodexEvent {
    fn parse(name: &str) -> Option<Self> {
        match name {
            EVENT_PRE_TOOL_USE => Some(Self::PreToolUse),
            EVENT_PERMISSION_REQUEST => Some(Self::PermissionRequest),
            _ => None,
        }
    }

    fn fallback_deny_literal(self) -> &'static [u8] {
        match self {
            Self::PreToolUse => FALLBACK_DENY_PRE_TOOL_USE,
            Self::PermissionRequest => FALLBACK_DENY_PERMISSION_REQUEST,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerDecision {
    Allow,
    Deny,
    Ask,
}

impl BrokerDecision {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "ask" => Some(Self::Ask),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodexVerdict {
    Allow,
    Deny,
}

/// Map (Codex event, broker decision) → Codex verdict.
///
/// Codex's hook contract is binary allow/deny on both mount points — there
/// is no equivalent of Claude's per-call "ask the user" UX. An earlier design
/// tried to preserve ask semantics by routing PreToolUse `ask` → `allow` and
/// catching it downstream at `PermissionRequest`, but `PermissionRequest`
/// only fires when Codex's own `permission_mode` would have prompted (so
/// `bypassPermissions`, `dontAsk`, and `--ask-for-approval never` silently
/// allow). The only correct mapping is to deny at the earliest mount point
/// with the rule reason surfaced as the deny message, on both mounts.
///
/// The `event` parameter is kept in the signature so the matrix is explicit
/// for future Codex events that may differentiate; today every `(event,
/// Ask)` cell resolves the same way.
fn translate_verdict(_event: CodexEvent, broker: BrokerDecision) -> CodexVerdict {
    match broker {
        BrokerDecision::Allow => CodexVerdict::Allow,
        BrokerDecision::Deny | BrokerDecision::Ask => CodexVerdict::Deny,
    }
}

// ---------------------------------------------------------------------------
// Verdict output
// ---------------------------------------------------------------------------

fn render_pre_tool_use(verdict: CodexVerdict, reason: &str) -> Result<String, serde_json::Error> {
    let decision_str = match verdict {
        CodexVerdict::Allow => "allow",
        CodexVerdict::Deny => "deny",
    };
    let output = PreToolUseOutput {
        hook_specific_output: PreToolUseHookSpecificOutput {
            hook_event_name: EVENT_PRE_TOOL_USE,
            permission_decision: decision_str,
            permission_decision_reason: reason,
        },
    };
    serde_json::to_string(&output)
}

fn render_permission_request(
    verdict: CodexVerdict,
    reason: &str,
) -> Result<String, serde_json::Error> {
    let (behavior, message) = match verdict {
        CodexVerdict::Allow => ("allow", None),
        CodexVerdict::Deny => ("deny", Some(reason)),
    };
    let output = PermissionRequestOutput {
        hook_specific_output: PermissionRequestHookSpecificOutput {
            hook_event_name: EVENT_PERMISSION_REQUEST,
            decision: PermissionRequestDecision { behavior, message },
        },
    };
    serde_json::to_string(&output)
}

/// Write a verdict JSON to stdout. If serialization or write fails, falls back
/// to a hardcoded deny literal — Codex treats empty stdout as allow, which is
/// the wrong fail-safe direction.
fn write_verdict(event: CodexEvent, verdict: CodexVerdict, reason: &str) {
    let rendered = match event {
        CodexEvent::PreToolUse => render_pre_tool_use(verdict, reason),
        CodexEvent::PermissionRequest => render_permission_request(verdict, reason),
    };

    match rendered {
        Ok(json) => {
            if writeln!(io::stdout(), "{json}").is_err() {
                process::exit(2);
            }
        }
        Err(_) => {
            if io::stdout()
                .write_all(event.fallback_deny_literal())
                .is_err()
            {
                process::exit(2);
            }
        }
    }
}

fn verdict_deny(event: CodexEvent, reason: &str) -> ! {
    write_verdict(event, CodexVerdict::Deny, reason);
    process::exit(0);
}

/// Broker communication failure — deny by default (fail-closed).
///
/// Upstream interceptor semantics remain fail-closed unless an integration
/// explicitly opts into fail-open via `PREMPTI_FAIL_OPEN=1`. This keeps the
/// standalone/default behavior consistent with the Claude Code interceptor.
fn verdict_on_error(event: CodexEvent, reason: &str) -> ! {
    if env_bool("PREMPTI_FAIL_OPEN") {
        write_verdict(event, CodexVerdict::Allow, reason);
        process::exit(0);
    } else {
        verdict_deny(event, reason);
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Parse a project env var as boolean. Returns true when the var is set to one
/// of: 1, true, yes, on (case-insensitive, surrounding whitespace ignored).
/// Returns false otherwise, including when the var is unset or set to an empty
/// string.
fn env_bool(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| {
            let s = v.trim();
            s.eq_ignore_ascii_case("1")
                || s.eq_ignore_ascii_case("true")
                || s.eq_ignore_ascii_case("yes")
                || s.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn get_socket_path() -> String {
    if let Ok(v) = env::var("PREMPTI_SOCKET") {
        if !v.is_empty() {
            return v;
        }
    }
    #[cfg(unix)]
    {
        let home = env::var("HOME").unwrap_or_default();
        if home.is_empty() {
            return String::new();
        }
        format!("{home}{SOCKET_SUFFIX}")
    }
    #[cfg(windows)]
    {
        let base = env::var("LOCALAPPDATA").unwrap_or_default();
        if base.is_empty() {
            return String::new();
        }
        format!("{}/prempti/run/broker.sock", base.replace('\\', "/"))
    }
}

fn get_timeout() -> Duration {
    let ms = env::var("PREMPTI_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(TIMEOUT_MIN_MS, TIMEOUT_MAX_MS))
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    Duration::from_millis(ms)
}

// ---------------------------------------------------------------------------
// Socket communication
// ---------------------------------------------------------------------------

/// Translate a `shutdown(Write)` result into the interceptor's String error.
/// Tolerates the "peer already disconnected" family because a fast broker
/// can read the newline-terminated request, write its response, and drop
/// the stream before our shutdown call lands. Mirrors the Claude Code
/// interceptor's behavior — see its tolerate_disconnected_shutdown for the
/// macOS/BSD race details.
#[cfg(unix)]
fn tolerate_disconnected_shutdown(result: io::Result<()>) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => match e.kind() {
            io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset => Ok(()),
            _ => Err(format!("broker shutdown failed: {e}")),
        },
    }
}

/// Connect to broker, send request, receive response.
fn communicate(socket_path: &str, request: &[u8], timeout: Duration) -> Result<Response, String> {
    #[cfg(unix)]
    let stream = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|e| format!("broker unavailable: {e}"))?;
    #[cfg(windows)]
    let stream = uds_windows::UnixStream::connect(socket_path)
        .map_err(|e| format!("broker unavailable: {e}"))?;

    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {e}"))?;

    (&stream)
        .write_all(request)
        .map_err(|e| format!("broker write failed: {e}"))?;

    #[cfg(unix)]
    tolerate_disconnected_shutdown(stream.shutdown(Shutdown::Write))?;

    let mut line = String::new();
    io::BufReader::new((&stream).take(RESPONSE_MAX))
        .read_line(&mut line)
        .map_err(|e| format!("broker response timeout: {e}"))?;

    if line.is_empty() {
        return Err("broker closed connection".into());
    }

    serde_json::from_str::<Response>(&line).map_err(|e| format!("malformed broker response: {e}"))
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

enum Error {
    /// Critical input error — exit code 2.
    InputError(String),
    /// Broker/infrastructure error — apply fail-open/closed policy.
    /// Carries the event so the fail path emits the right output shape.
    BrokerError { event: CodexEvent, reason: String },
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn run() -> Result<(), Error> {
    // Step 1: Read stdin (up to INPUT_MAX + 1 to detect overflow).
    let mut input = Vec::with_capacity(INPUT_MAX);
    let bytes_read = io::stdin()
        .take((INPUT_MAX + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|e| Error::InputError(format!("failed to read stdin: {e}")))?;

    if bytes_read == 0 {
        return Err(Error::InputError("empty stdin".into()));
    }
    if bytes_read > INPUT_MAX {
        return Err(Error::InputError("input too large (max 64KB)".into()));
    }

    // Step 2: Extract event type + correlation hint (minimal parse).
    let minimal: HookInputMinimal = serde_json::from_slice(&input)
        .map_err(|e| Error::InputError(format!("malformed input JSON: {e}")))?;

    let event = CodexEvent::parse(&minimal.hook_event_name).ok_or_else(|| {
        Error::InputError(format!(
            "unsupported hook_event_name: {:?} (interceptor handles PreToolUse and PermissionRequest)",
            minimal.hook_event_name
        ))
    })?;

    // PreToolUse carries tool_use_id; PermissionRequest does not — fall back
    // to turn_id (Codex's finer-than-session correlator). "unknown" is a last
    // resort that matches the Claude Code interceptor's behavior.
    let correlation_id = if !minimal.tool_use_id.is_empty() {
        minimal.tool_use_id.as_str()
    } else if !minimal.turn_id.is_empty() {
        minimal.turn_id.as_str()
    } else {
        "unknown"
    };

    // Step 3: Build wire-protocol request with raw event passthrough.
    let raw_event = serde_json::value::RawValue::from_string(
        String::from_utf8(input).map_err(|e| Error::InputError(format!("invalid UTF-8: {e}")))?,
    )
    .map_err(|e| Error::InputError(format!("malformed input JSON: {e}")))?;

    let request = Request {
        version: 1,
        id: correlation_id,
        agent_name: "codex",
        agent_pid: proc_lineage::agent_pid(),
        event: &raw_event,
    };

    let mut request_bytes = serde_json::to_vec(&request).map_err(|e| Error::BrokerError {
        event,
        reason: format!("failed to serialize request: {e}"),
    })?;
    request_bytes.push(b'\n');

    // Step 4: Configuration.
    let socket_path = get_socket_path();
    if socket_path.is_empty() {
        #[cfg(unix)]
        let msg = "HOME not set, cannot locate broker socket";
        #[cfg(windows)]
        let msg = "LOCALAPPDATA not set, cannot locate broker socket";
        return Err(Error::BrokerError {
            event,
            reason: msg.into(),
        });
    }
    let timeout = get_timeout();

    // Step 5: Communicate with broker.
    let response = communicate(&socket_path, &request_bytes, timeout).map_err(|reason| {
        Error::BrokerError { event, reason }
    })?;

    // Step 6: Validate response.
    if response.id != correlation_id {
        return Err(Error::BrokerError {
            event,
            reason: "broker response ID mismatch".into(),
        });
    }

    let broker_decision = BrokerDecision::parse(&response.decision).ok_or_else(|| {
        Error::BrokerError {
            event,
            reason: format!("invalid broker decision: {:?}", response.decision),
        }
    })?;

    // Step 7: Translate + write verdict.
    let codex_verdict = translate_verdict(event, broker_decision);
    write_verdict(event, codex_verdict, &response.reason);
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(Error::InputError(msg)) => {
            eprintln!("codex-interceptor: {msg}");
            process::exit(2);
        }
        Err(Error::BrokerError { event, reason }) => {
            verdict_on_error(event, &reason);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------- verdict translation table -----------------------------------

    #[test]
    fn pre_tool_use_allow_passes_through() {
        assert_eq!(
            translate_verdict(CodexEvent::PreToolUse, BrokerDecision::Allow),
            CodexVerdict::Allow
        );
    }

    #[test]
    fn pre_tool_use_deny_passes_through() {
        assert_eq!(
            translate_verdict(CodexEvent::PreToolUse, BrokerDecision::Deny),
            CodexVerdict::Deny
        );
    }

    #[test]
    fn pre_tool_use_ask_becomes_deny() {
        // Codex has no per-call user-confirmation UX at the hook layer.
        // Returning allow and hoping PermissionRequest catches it silently
        // allows when Codex's permission_mode wouldn't prompt downstream
        // (bypassPermissions, dontAsk, --ask-for-approval never). Deny at
        // the earliest mount point with the rule reason as the message is
        // the only safe mapping.
        assert_eq!(
            translate_verdict(CodexEvent::PreToolUse, BrokerDecision::Ask),
            CodexVerdict::Deny
        );
    }

    #[test]
    fn permission_request_allow_passes_through() {
        assert_eq!(
            translate_verdict(CodexEvent::PermissionRequest, BrokerDecision::Allow),
            CodexVerdict::Allow
        );
    }

    #[test]
    fn permission_request_deny_passes_through() {
        assert_eq!(
            translate_verdict(CodexEvent::PermissionRequest, BrokerDecision::Deny),
            CodexVerdict::Deny
        );
    }

    #[test]
    fn permission_request_ask_becomes_deny() {
        // Surfaces the rule reason via Codex's approval UX.
        assert_eq!(
            translate_verdict(CodexEvent::PermissionRequest, BrokerDecision::Ask),
            CodexVerdict::Deny
        );
    }

    // -------- event parsing -----------------------------------------------

    #[test]
    fn parses_known_events() {
        assert_eq!(
            CodexEvent::parse("PreToolUse"),
            Some(CodexEvent::PreToolUse)
        );
        assert_eq!(
            CodexEvent::parse("PermissionRequest"),
            Some(CodexEvent::PermissionRequest)
        );
    }

    #[test]
    fn rejects_unknown_events() {
        // Codex has 10 events; we only handle two. Anything else is rejected
        // so the user gets a clear error rather than a silent allow.
        for name in [
            "PostToolUse",
            "PreCompact",
            "SessionStart",
            "SubagentStart",
            "UserPromptSubmit",
            "Stop",
            "",
            "pretooluse", // case-sensitive
        ] {
            assert_eq!(CodexEvent::parse(name), None, "{name:?} should not parse");
        }
    }

    // -------- broker decision parsing -------------------------------------

    #[test]
    fn parses_known_broker_decisions() {
        assert_eq!(BrokerDecision::parse("allow"), Some(BrokerDecision::Allow));
        assert_eq!(BrokerDecision::parse("deny"), Some(BrokerDecision::Deny));
        assert_eq!(BrokerDecision::parse("ask"), Some(BrokerDecision::Ask));
    }

    #[test]
    fn rejects_unknown_broker_decisions() {
        for s in ["ALLOW", "Deny", "maybe", ""] {
            assert_eq!(BrokerDecision::parse(s), None, "{s:?} should not parse");
        }
    }

    // -------- output JSON shape -------------------------------------------

    #[test]
    fn pre_tool_use_allow_output_shape() {
        let json = render_pre_tool_use(CodexVerdict::Allow, "").expect("render");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "");
    }

    #[test]
    fn pre_tool_use_deny_output_shape() {
        let json = render_pre_tool_use(CodexVerdict::Deny, "rule X: blocked").expect("render");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "rule X: blocked"
        );
    }

    #[test]
    fn permission_request_allow_omits_message() {
        // Codex's wire enum has `behavior: "allow"` with no message field.
        // Emitting message on allow would be schema-invalid.
        let json = render_permission_request(CodexVerdict::Allow, "ignored").expect("render");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "allow");
        assert!(
            v["hookSpecificOutput"]["decision"].get("message").is_none(),
            "message must not be serialized for allow"
        );
    }

    #[test]
    fn permission_request_deny_includes_message() {
        let json = render_permission_request(CodexVerdict::Deny, "rule Y: ask").expect("render");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["decision"]["message"],
            "rule Y: ask"
        );
    }

    #[test]
    fn permission_request_deny_with_empty_reason_still_emits_message_field() {
        // If the broker returns deny with an empty reason, we still emit the
        // message field (empty string) so the deny shape stays well-formed.
        let json = render_permission_request(CodexVerdict::Deny, "").expect("render");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(v["hookSpecificOutput"]["decision"]["message"], "");
    }

    // -------- fallback literals are valid JSON ----------------------------

    #[test]
    fn fallback_pre_tool_use_is_valid_json() {
        let s = std::str::from_utf8(FALLBACK_DENY_PRE_TOOL_USE).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(s.trim_end()).expect("parse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn fallback_permission_request_is_valid_json() {
        let s = std::str::from_utf8(FALLBACK_DENY_PERMISSION_REQUEST).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(s.trim_end()).expect("parse");
        assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["decision"]["message"],
            "internal serialization error"
        );
    }

    // -------- shutdown tolerance (Unix-only, mirrors claude-code) ---------

    #[cfg(unix)]
    #[test]
    fn tolerate_disconnected_shutdown_passes_ok_through() {
        assert!(tolerate_disconnected_shutdown(Ok(())).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn tolerate_disconnected_shutdown_swallows_peer_gone_errors() {
        for kind in [
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
        ] {
            let r = tolerate_disconnected_shutdown(Err(io::Error::new(kind, "test")));
            assert!(r.is_ok(), "{kind:?} should be tolerated, got {r:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn tolerate_disconnected_shutdown_propagates_other_errors() {
        let r = tolerate_disconnected_shutdown(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test",
        )));
        assert!(r.is_err(), "non-disconnect errors should not be swallowed");
        let msg = r.unwrap_err();
        assert!(msg.contains("broker shutdown failed"), "got: {msg}");
    }

    // -------- env_bool (mirrors claude-code; uses unique var names) -------

    #[test]
    fn env_bool_unset_is_false() {
        let name = "CODEX_TEST_ENV_BOOL_UNSET";
        env::remove_var(name);
        assert!(!env_bool(name));
    }

    #[test]
    fn env_bool_one_is_true() {
        let name = "CODEX_TEST_ENV_BOOL_ONE";
        env::set_var(name, "1");
        assert!(env_bool(name));
        env::remove_var(name);
    }

    #[test]
    fn env_bool_true_case_insensitive() {
        let name = "CODEX_TEST_ENV_BOOL_TRUE";
        for v in ["true", "TRUE", "True"] {
            env::set_var(name, v);
            assert!(env_bool(name), "{v} should be truthy");
        }
        env::remove_var(name);
    }

    #[test]
    fn env_bool_trims_whitespace() {
        let name = "CODEX_TEST_ENV_BOOL_WS";
        env::set_var(name, " 1 ");
        assert!(env_bool(name));
        env::remove_var(name);
    }

    #[test]
    fn env_bool_falsy_values() {
        let name = "CODEX_TEST_ENV_BOOL_FALSY";
        for v in ["0", "", "no", "off", "false", "anything"] {
            env::set_var(name, v);
            assert!(!env_bool(name), "{v:?} should be falsy");
        }
        env::remove_var(name);
    }

    // -------- HookInputMinimal parsing ------------------------------------

    #[test]
    fn parses_pre_tool_use_input() {
        let input = r#"{
            "session_id": "s1",
            "turn_id": "t1",
            "transcript_path": null,
            "cwd": "/work",
            "hook_event_name": "PreToolUse",
            "model": "gpt-5-codex",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "tu-1"
        }"#;
        let parsed: HookInputMinimal = serde_json::from_str(input).expect("parse");
        assert_eq!(parsed.hook_event_name, "PreToolUse");
        assert_eq!(parsed.tool_use_id, "tu-1");
        assert_eq!(parsed.turn_id, "t1");
    }

    #[test]
    fn parses_permission_request_input_without_tool_use_id() {
        // PermissionRequest's schema does not include tool_use_id.
        let input = r#"{
            "session_id": "s1",
            "turn_id": "t2",
            "transcript_path": null,
            "cwd": "/work",
            "hook_event_name": "PermissionRequest",
            "model": "gpt-5-codex",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        }"#;
        let parsed: HookInputMinimal = serde_json::from_str(input).expect("parse");
        assert_eq!(parsed.hook_event_name, "PermissionRequest");
        assert_eq!(parsed.tool_use_id, "");
        assert_eq!(parsed.turn_id, "t2");
    }
}
