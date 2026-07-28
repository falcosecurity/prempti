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

//! Copilot CLI interceptor — thin bridge between Copilot's hook events and the
//! Prempti plugin broker.
//!
//! Mounts on two Copilot hook events:
//! - `preToolUse`: broker `deny`/`ask` → Copilot `deny` with reason; `allow` →
//!   `allow`; `ask` → `ask` (Copilot CLI supports ask in preToolUse).
//! - `permissionRequest`: broker `deny`/`ask` → `deny` with reason; `allow` →
//!   `allow` (short-circuits Copilot's permission flow); `defer` → no output
//!   (falls through to Copilot's own approval flow).
//!
//! Copilot's input uses camelCase field names (`sessionId`, `toolName`, `hookName`,
//! `toolArgs`, `toolInput`). The interceptor normalizes these to the wire format's
//! snake_case (`session_id`, `tool_name`, `hook_event_name`, `tool_input`) expected
//! by the Prempti plugin.

use serde::{Deserialize, Serialize};
use serde_json::json;
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

/// Wire protocol request (interceptor → broker).
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

// --- Copilot PreToolUse output -----------------------------------------------

#[derive(Serialize)]
struct PreToolUseOutput<'a> {
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

// --- Copilot PermissionRequest output ----------------------------------------

#[derive(Serialize)]
struct PermissionRequestOutput<'a> {
    behavior: &'a str,
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
const INPUT_MAX_DEFAULT: usize = 4 * 1024 * 1024;
const INPUT_MAX_MIN: usize = 4 * 1024;
const INPUT_MAX_CEILING: usize = 64 * 1024 * 1024;
const RESPONSE_MAX: u64 = 64 * 1024;

// Fallback deny literals for when JSON serialization fails.
const FALLBACK_DENY_PRE_TOOL_USE: &[u8] = b"{\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"internal serialization error\"}\n";
const FALLBACK_DENY_PERMISSION_REQUEST: &[u8] = b"{\"behavior\":\"deny\",\"message\":\"internal serialization error\"}\n";

// ---------------------------------------------------------------------------
// Event and Verdict types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CopilotEvent {
    PreToolUse,
    PermissionRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CopilotVerdict {
    Allow,
    Deny,
    Ask,
    Defer,
}

// ---------------------------------------------------------------------------
// Verdict output
// ---------------------------------------------------------------------------

/// Write verdict for preToolUse: {"permissionDecision":"...","permissionDecisionReason":"..."}
fn write_pre_tool_use_verdict(decision: &str, reason: &str) {
    let output = PreToolUseOutput {
        permission_decision: decision,
        permission_decision_reason: reason,
    };
    match serde_json::to_string(&output) {
        Ok(json) => {
            if writeln!(io::stdout(), "{json}").is_err() {
                process::exit(2);
            }
        }
        Err(_) => {
            if io::stdout().write_all(FALLBACK_DENY_PRE_TOOL_USE).is_err() {
                process::exit(2);
            }
        }
    }
}

/// Write verdict for permissionRequest: {"behavior":"...","message":"..."}
/// Note: message is omitted for allow per Copilot's wire spec.
fn write_permission_request_verdict(decision: &str, reason: &str) {
    let message = if decision == "allow" {
        None
    } else {
        Some(reason)
    };
    let output = PermissionRequestOutput {
        behavior: decision,
        message,
    };
    match serde_json::to_string(&output) {
        Ok(json) => {
            if writeln!(io::stdout(), "{json}").is_err() {
                process::exit(2);
            }
        }
        Err(_) => {
            if io::stdout().write_all(FALLBACK_DENY_PERMISSION_REQUEST).is_err() {
                process::exit(2);
            }
        }
    }
}

/// Map (event, broker_decision) -> CopilotVerdict
fn translate_verdict(event: CopilotEvent, broker_decision: &str) -> CopilotVerdict {
    match broker_decision {
        "allow" => CopilotVerdict::Allow,
        "deny" => CopilotVerdict::Deny,
        "ask" => {
            // preToolUse supports "ask"; permissionRequest does not, so map to deny
            if matches!(event, CopilotEvent::PreToolUse) {
                CopilotVerdict::Ask
            } else {
                CopilotVerdict::Deny
            }
        }
        "defer" => CopilotVerdict::Defer,
        _ => unreachable!(), // Already validated by broker
    }
}

/// Write the final verdict to stdout. Empty stdout for Defer.
fn write_verdict(event: CopilotEvent, verdict: CopilotVerdict, reason: &str) {
    match (event, verdict) {
        // Defer: empty stdout for both hooks (fall through to Copilot's flow)
        (_, CopilotVerdict::Defer) => {},

        // preToolUse: direct mapping
        (CopilotEvent::PreToolUse, CopilotVerdict::Allow) => {
            write_pre_tool_use_verdict("allow", "")
        }
        (CopilotEvent::PreToolUse, CopilotVerdict::Deny) => {
            write_pre_tool_use_verdict("deny", reason)
        }
        (CopilotEvent::PreToolUse, CopilotVerdict::Ask) => {
            write_pre_tool_use_verdict("ask", reason)
        }

        // permissionRequest: allow/deny (ask is already mapped to deny in translate_verdict)
        (CopilotEvent::PermissionRequest, CopilotVerdict::Allow) => {
            write_permission_request_verdict("allow", reason)
        }
        (CopilotEvent::PermissionRequest, CopilotVerdict::Deny) => {
            write_permission_request_verdict("deny", reason)
        }
        // Ask for PermissionRequest is mapped to Deny by translate_verdict,
        // but the compiler can't see through the function call. This arm is
        // unreachable in practice but needed for exhaustiveness.
        (CopilotEvent::PermissionRequest, CopilotVerdict::Ask) => {
            write_permission_request_verdict("deny", reason)
        }
    }
}

fn verdict_deny(event: CopilotEvent, reason: &str) -> ! {
    write_verdict(event, CopilotVerdict::Deny, reason);
    process::exit(0);
}

/// Broker communication failure — deny by default (fail-closed).
/// With PREMPTI_FAIL_OPEN=1, emit empty stdout (defer) to fall through.
fn verdict_on_error(event: CopilotEvent, reason: &str) -> ! {
    if env_bool("PREMPTI_FAIL_OPEN") {
        // Fail-open: defer (empty stdout) lets Copilot's normal flow decide.
        // We do NOT emit allow here to avoid actively approving when the
        // policy engine is down.
        process::exit(0);
    } else {
        verdict_deny(event, reason);
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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
        format!(
            "{}/prempti/run/broker.sock",
            base.replace('\\', "/")
        )
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

fn get_input_max() -> usize {
    parse_input_max(env::var("PREMPTI_INPUT_MAX_BYTES").ok().as_deref())
}

fn parse_input_max(raw: Option<&str>) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(INPUT_MAX_MIN, INPUT_MAX_CEILING))
        .unwrap_or(INPUT_MAX_DEFAULT)
}

// ---------------------------------------------------------------------------
// Socket communication
// ---------------------------------------------------------------------------

/// Translate a `shutdown(Write)` result into the interceptor's String error.
/// Tolerates the "peer already disconnected" family because a fast broker
/// can read the newline-terminated request, write its response, and drop
/// the stream before our shutdown call lands.
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
    BrokerError { event: CopilotEvent, reason: String },
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn run() -> Result<(), Error> {
    // Step 1: Read stdin (up to input_max + 1 to detect overflow).
    let input_max = get_input_max();
    let mut input = Vec::with_capacity(input_max.min(64 * 1024));
    let bytes_read = io::stdin()
        .take((input_max + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|e| Error::InputError(format!("failed to read stdin: {e}")))?;

    if bytes_read == 0 {
        return Err(Error::InputError("empty stdin".into()));
    }

    if bytes_read > input_max {
        return Err(Error::InputError(format!(
            "input too large (max {} bytes; raise PREMPTI_INPUT_MAX_BYTES if intended)",
            input_max
        )));
    }

    // Step 2: Parse full input to extract and normalize all fields.
    let copilot_input: serde_json::Value = serde_json::from_slice(&input)
        .map_err(|e| Error::InputError(format!("malformed input JSON: {e}")))?;

    // Extract fields with Copilot's camelCase names, map to wire format snake_case.
    let hook_name = copilot_input.get("hookName").and_then(|v| v.as_str());
    let session_id = copilot_input
        .get("sessionId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tool_name = copilot_input
        .get("toolName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tool_input = copilot_input.get("toolInput").cloned();
    let tool_args = copilot_input.get("toolArgs").cloned();
    let cwd = copilot_input
        .get("cwd")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Detect hook type: permissionRequest has hookName, preToolUse does not.
    let event = match hook_name {
        Some("permissionRequest") => CopilotEvent::PermissionRequest,
        None => CopilotEvent::PreToolUse,
        Some(other) => {
            return Err(Error::InputError(format!(
                "unsupported hookName: {:?} (only preToolUse and permissionRequest are supported)",
                other
            )));
        }
    };

    // Correlation ID.
    let correlation_id = if session_id.is_empty() {
        "unknown"
    } else {
        session_id
    };

    // Step 3: Build normalized event for wire protocol.
    // Map Copilot's camelCase to the wire format's snake_case that the plugin expects.
    let normalized_event = json!({
        "hook_event_name": match event {
            CopilotEvent::PreToolUse => "PreToolUse",
            CopilotEvent::PermissionRequest => "PermissionRequest",
        },
        "session_id": session_id,
        "tool_name": tool_name,
        // For preToolUse, toolArgs is a JSON string; for permissionRequest, toolInput is an object.
        // Normalize both to tool_input as a Value.
        "tool_input": match event {
            CopilotEvent::PreToolUse => {
                // toolArgs is a JSON-encoded string from Copilot; parse it if possible
                if let Some(serde_json::Value::String(args_str)) = tool_args {
                    serde_json::from_str(&args_str).unwrap_or(serde_json::Value::String(args_str))
                } else {
                    tool_args.unwrap_or(serde_json::Value::Null)
                }
            }
            CopilotEvent::PermissionRequest => {
                tool_input.unwrap_or(serde_json::Value::Null)
            }
        },
        "cwd": cwd,
        // Permission mode: Copilot doesn't provide this; leave empty for now.
        "permission_mode": "",
        // No tool_use_id in Copilot; leave empty.
        "tool_use_id": "",
    });

    // Serialize normalized event to RawValue for wire protocol.
    let raw_event = serde_json::value::RawValue::from_string(
        serde_json::to_string(&normalized_event)
            .map_err(|e| Error::InputError(format!("failed to normalize event: {e}")))?,
    )
    .map_err(|e| Error::InputError(format!("malformed normalized JSON: {e}")))?;

    let request = Request {
        version: 1,
        id: correlation_id,
        agent_name: "copilot",
        agent_pid: proc_lineage::agent_pid(),
        event: &raw_event,
    };

    let mut request_bytes = serde_json::to_vec(&request)
        .map_err(|e| Error::BrokerError {
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
    let response = communicate(&socket_path, &request_bytes, timeout)
        .map_err(|reason| Error::BrokerError { event, reason })?;

    // Step 6: Validate response.
    if response.id != correlation_id {
        return Err(Error::BrokerError {
            event,
            reason: "broker response ID mismatch".into(),
        });
    }

    // Step 7: Validate broker decision.
    if !matches!(
        response.decision.as_str(),
        "allow" | "deny" | "ask" | "defer"
    ) {
        return Err(Error::BrokerError {
            event,
            reason: format!("invalid broker decision: {:?}", response.decision),
        });
    }

    // Step 8: Translate + write verdict.
    let verdict = translate_verdict(event, &response.decision);
    write_verdict(event, verdict, &response.reason);
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(Error::InputError(msg)) => {
            eprintln!("copilot-interceptor: {msg}");
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

    // -------- verdict translation -------------------------------------------

    #[test]
    fn pre_tool_use_allow_passes_through() {
        assert_eq!(
            translate_verdict(CopilotEvent::PreToolUse, "allow"),
            CopilotVerdict::Allow
        );
    }

    #[test]
    fn pre_tool_use_deny_passes_through() {
        assert_eq!(
            translate_verdict(CopilotEvent::PreToolUse, "deny"),
            CopilotVerdict::Deny
        );
    }

    #[test]
    fn pre_tool_use_ask_passes_through() {
        // Copilot CLI supports ask in preToolUse.
        assert_eq!(
            translate_verdict(CopilotEvent::PreToolUse, "ask"),
            CopilotVerdict::Ask
        );
    }

    #[test]
    fn pre_tool_use_defer_passes_through() {
        assert_eq!(
            translate_verdict(CopilotEvent::PreToolUse, "defer"),
            CopilotVerdict::Defer
        );
    }

    #[test]
    fn permission_request_allow_passes_through() {
        assert_eq!(
            translate_verdict(CopilotEvent::PermissionRequest, "allow"),
            CopilotVerdict::Allow
        );
    }

    #[test]
    fn permission_request_deny_passes_through() {
        assert_eq!(
            translate_verdict(CopilotEvent::PermissionRequest, "deny"),
            CopilotVerdict::Deny
        );
    }

    #[test]
    fn permission_request_ask_maps_to_deny() {
        // permissionRequest does not support ask; map to deny.
        assert_eq!(
            translate_verdict(CopilotEvent::PermissionRequest, "ask"),
            CopilotVerdict::Deny
        );
    }

    #[test]
    fn permission_request_defer_passes_through() {
        assert_eq!(
            translate_verdict(CopilotEvent::PermissionRequest, "defer"),
            CopilotVerdict::Defer
        );
    }

    // -------- shutdown tolerance (Unix-only) ---------------------------------

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

    // -------- env_bool -----------------------------------------------------

    #[test]
    fn env_bool_unset_is_false() {
        let name = "COPILOT_TEST_ENV_BOOL_UNSET";
        env::remove_var(name);
        assert!(!env_bool(name));
    }

    #[test]
    fn env_bool_one_is_true() {
        let name = "COPILOT_TEST_ENV_BOOL_ONE";
        env::set_var(name, "1");
        assert!(env_bool(name));
        env::remove_var(name);
    }

    #[test]
    fn env_bool_true_case_insensitive() {
        let name = "COPILOT_TEST_ENV_BOOL_TRUE";
        for v in ["true", "TRUE", "True"] {
            env::set_var(name, v);
            assert!(env_bool(name), "{v} should be truthy");
        }
        env::remove_var(name);
    }

    #[test]
    fn env_bool_trims_whitespace() {
        let name = "COPILOT_TEST_ENV_BOOL_WS";
        env::set_var(name, " 1 ");
        assert!(env_bool(name));
        env::remove_var(name);
    }

    #[test]
    fn env_bool_falsy_values() {
        let name = "COPILOT_TEST_ENV_BOOL_FALSY";
        for v in ["0", "", "no", "off", "false", "anything"] {
            env::set_var(name, v);
            assert!(!env_bool(name), "{v:?} should be falsy");
        }
        env::remove_var(name);
    }

    // -------- parse_input_max -----------------------------------------------

    #[test]
    fn parse_input_max_unset_returns_default() {
        assert_eq!(parse_input_max(None), INPUT_MAX_DEFAULT);
    }

    #[test]
    fn parse_input_max_typo_falls_back_to_default() {
        assert_eq!(parse_input_max(Some("not-a-number")), INPUT_MAX_DEFAULT);
        assert_eq!(parse_input_max(Some("")), INPUT_MAX_DEFAULT);
    }

    #[test]
    fn parse_input_max_clamps_below_min() {
        assert_eq!(parse_input_max(Some("0")), INPUT_MAX_MIN);
        assert_eq!(parse_input_max(Some("1")), INPUT_MAX_MIN);
    }

    #[test]
    fn parse_input_max_clamps_above_ceiling() {
        let huge = format!("{}", INPUT_MAX_CEILING * 8);
        assert_eq!(parse_input_max(Some(&huge)), INPUT_MAX_CEILING);
    }

    #[test]
    fn parse_input_max_honors_in_range_value() {
        let target = 8 * 1024 * 1024; // 8 MiB
        let s = format!("{target}");
        assert_eq!(parse_input_max(Some(&s)), target);
    }

    #[test]
    fn parse_input_max_trims_whitespace() {
        let s = format!("  {}  ", 8 * 1024 * 1024);
        assert_eq!(parse_input_max(Some(&s)), 8 * 1024 * 1024);
    }

    // -------- fallback literals are valid JSON -----------------------------

    #[test]
    fn fallback_pre_tool_use_is_valid_json() {
        let s = std::str::from_utf8(FALLBACK_DENY_PRE_TOOL_USE).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(s.trim_end()).expect("parse");
        assert_eq!(v["permissionDecision"], "deny");
        assert_eq!(
            v["permissionDecisionReason"],
            "internal serialization error"
        );
    }

    #[test]
    fn fallback_permission_request_is_valid_json() {
        let s = std::str::from_utf8(FALLBACK_DENY_PERMISSION_REQUEST).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(s.trim_end()).expect("parse");
        assert_eq!(v["behavior"], "deny");
        assert_eq!(v["message"], "internal serialization error");
    }
}
