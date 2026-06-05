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

//! Claude Code interceptor — thin bridge between Claude Code's PreToolUse hook
//! and the Prempti plugin broker.
//!
//! The interceptor does NOT interpret tool call content. It reads the hook JSON
//! from stdin, wraps it in a wire-protocol envelope, sends it to the broker,
//! and maps the broker's verdict back to Claude Code's hook response format.
//! All field extraction and policy evaluation happens in the plugin broker.

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

/// Minimal parse of stdin — only extract tool_use_id for correlation.
/// All other fields are passed through as raw JSON.
#[derive(Deserialize)]
struct HookInputMinimal {
    #[serde(default)]
    tool_use_id: String,
}

/// Wire protocol request (interceptor → broker).
#[derive(Serialize)]
struct Request<'a> {
    version: u32,
    id: &'a str,
    agent_name: &'static str,
    /// PID of the agent process that invoked the hook (the interceptor's
    /// immediate parent). `None` when the platform lookup fails; serde
    /// omits the field rather than writing `null`, keeping older brokers
    /// happy. `u64` for alignment with the `agent.pid` Falco field type
    /// (the `falco_plugin` SDK only exposes `u64` as the numeric extract
    /// scalar — there's no `u32` variant).
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

/// Claude Code hook output (stdout).
#[derive(Serialize)]
struct HookOutput<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput<'a>,
}

#[derive(Serialize)]
struct HookSpecificOutput<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS: u64 = 5000;
const TIMEOUT_MIN_MS: u64 = 100;
const TIMEOUT_MAX_MS: u64 = 30000;
#[cfg(unix)]
const SOCKET_SUFFIX: &str = "/.prempti/run/broker.sock";
/// Default cap on stdin bytes read from the agent. 4 MiB comfortably covers
/// realistic tool calls. Overridable via `PREMPTI_INPUT_MAX_BYTES`. The
/// matching broker-side cap is `max_request_bytes` in the plugin config.
const INPUT_MAX_DEFAULT: usize = 4 * 1024 * 1024;
const INPUT_MAX_MIN: usize = 4 * 1024;
const INPUT_MAX_CEILING: usize = 64 * 1024 * 1024;
const RESPONSE_MAX: u64 = 64 * 1024;

// ---------------------------------------------------------------------------
// Verdict output
// ---------------------------------------------------------------------------

/// Write a verdict JSON to stdout. If serialization or write fails, falls back
/// to a hardcoded deny literal — fail-closed. Empty stdout is deliberately not
/// the fallback here: Claude Code treats exit 0 with no output as "no decision;
/// the normal permission flow applies" (per the hooks docs), not as deny. The
/// only place we emit empty stdout on purpose is the `defer` verdict in `run`.
fn write_verdict(decision: &str, reason: &str) {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: decision,
            permission_decision_reason: reason,
        },
    };
    match serde_json::to_string(&output) {
        Ok(json) => {
            if writeln!(io::stdout(), "{json}").is_err() {
                process::exit(2);
            }
        }
        Err(_) => {
            if io::stdout()
                .write_all(
                    b"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\
                      \"permissionDecision\":\"deny\",\
                      \"permissionDecisionReason\":\"internal serialization error\"}}\n",
                )
                .is_err()
            {
                process::exit(2);
            }
        }
    }
}

fn verdict_deny(reason: &str) -> ! {
    write_verdict("deny", reason);
    process::exit(0);
}

/// Broker communication failure — deny by default (fail-closed).
///
/// Upstream interceptor semantics remain fail-closed unless an integration
/// explicitly opts into fail-open via PREMPTI_FAIL_OPEN=1.
///
/// This keeps the standalone/default behavior unchanged while allowing
/// embedding environments to continue operating when the broker is
/// unavailable, at the cost of losing observability for that interval.
fn verdict_on_error(reason: &str) -> ! {
    if env_bool("PREMPTI_FAIL_OPEN") {
        write_verdict("allow", reason);
        process::exit(0);
    } else {
        verdict_deny(reason);
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
        // MSI installs to %LOCALAPPDATA%\prempti (not %USERPROFILE%)
        let base = env::var("LOCALAPPDATA").unwrap_or_default();
        if base.is_empty() {
            return String::new();
        }
        // Use forward slashes — YAML configs and AF_UNIX paths must match exactly.
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

/// Resolve the stdin read cap. Defaults to 4 MiB; overridable via
/// `PREMPTI_INPUT_MAX_BYTES`. Unparseable values fall back to the default
/// silently (rather than failing closed) so a typo in the env var never
/// hard-blocks tool calls. Clamped to `[INPUT_MAX_MIN, INPUT_MAX_CEILING]`.
fn get_input_max() -> usize {
    parse_input_max(env::var("PREMPTI_INPUT_MAX_BYTES").ok().as_deref())
}

/// Pure-function form of `get_input_max` for testing. Accepts the raw
/// env value (None = unset) and returns the resolved, clamped cap.
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
/// the stream before our shutdown call lands. On macOS/BSD the kernel then
/// reports ENOTCONN / EPIPE here, but the response is already queued for
/// us to read. The half-close is purely advisory — the `\n` in the request
/// is what really terminates it for the broker — so any "peer is gone"
/// error here is harmless. Anything else (EBADF, etc.) is still surfaced.
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

    // Set both timeouts on the freshly-connected socket BEFORE any I/O.
    // macOS rejects setsockopt(SO_*TIMEO) with EINVAL once the peer has
    // closed: xnu's unp_disconnect calls soisdisconnected on us, which
    // sets SS_CANTRCVMORE | SS_CANTSENDMORE, and sosetoptlock then
    // refuses any further setsockopt. Under load the broker's
    // resolve → shutdown(Both) → drop sequence can land before the
    // interceptor reaches a post-write set_read_timeout, which is what
    // produced the `set timeout: Invalid argument (os error 22)`
    // failures observed in production.
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {e}"))?;

    (&stream)
        .write_all(request)
        .map_err(|e| format!("broker write failed: {e}"))?;

    // Signal end-of-write so the broker's read_line can detect EOF alongside
    // the \n delimiter. Skipped on Windows: shutdown(SD_SEND) on AF_UNIX
    // resets the connection on some Windows builds, preventing the broker
    // from writing the verdict back to the interceptor.
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
    BrokerError(String),
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn run() -> Result<(), Error> {
    // Step 1: Read stdin (up to input_max + 1 to detect overflow).
    let input_max = get_input_max();
    // Cap the initial allocation at 64 KiB regardless of the configured
    // limit — most events are tiny, and we don't want to allocate
    // multi-megabyte buffers eagerly. `read_to_end` grows the Vec as
    // needed for the rare large patches.
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

    // Step 2: Extract correlation ID (minimal parse — only tool_use_id).
    let minimal: HookInputMinimal = serde_json::from_slice(&input)
        .map_err(|e| Error::InputError(format!("malformed input JSON: {e}")))?;

    let correlation_id = if minimal.tool_use_id.is_empty() {
        "unknown"
    } else {
        &minimal.tool_use_id
    };

    // Step 3: Build wire-protocol request with raw event passthrough.
    let raw_event = serde_json::value::RawValue::from_string(
        String::from_utf8(input).map_err(|e| Error::InputError(format!("invalid UTF-8: {e}")))?,
    )
    .map_err(|e| Error::InputError(format!("malformed input JSON: {e}")))?;

    let request = Request {
        version: 1,
        id: correlation_id,
        agent_name: "claude_code",
        agent_pid: proc_lineage::agent_pid(),
        event: &raw_event,
    };

    let mut request_bytes = serde_json::to_vec(&request)
        .map_err(|e| Error::BrokerError(format!("failed to serialize request: {e}")))?;
    request_bytes.push(b'\n');

    // Step 4: Configuration.
    let socket_path = get_socket_path();
    if socket_path.is_empty() {
        #[cfg(unix)]
        let msg = "HOME not set, cannot locate broker socket";
        #[cfg(windows)]
        let msg = "LOCALAPPDATA not set, cannot locate broker socket";
        return Err(Error::BrokerError(msg.into()));
    }
    let timeout = get_timeout();

    // Step 5: Communicate with broker.
    let response =
        communicate(&socket_path, &request_bytes, timeout).map_err(Error::BrokerError)?;

    // Step 6: Validate response.
    if response.id != correlation_id {
        return Err(Error::BrokerError("broker response ID mismatch".into()));
    }

    if !matches!(response.decision.as_str(), "allow" | "deny" | "ask" | "defer") {
        return Err(Error::BrokerError("invalid broker decision".into()));
    }

    // Step 7: Write verdict.
    //
    // `defer` is the no-rule-match "step aside" floor: emit no decision and
    // exit 0, which Claude Code treats as "no decision; the normal permission
    // flow applies" — its allowlist/settings decide and it prompts if it
    // normally would. This is deliberately NOT `permissionDecision: "defer"`:
    // that value is a `-p`/Agent SDK feature that pauses the tool call for a
    // wrapper to resume, and would hang an interactive session. Empty stdout
    // is the documented fall-through.
    if response.decision == "defer" {
        return Ok(());
    }
    write_verdict(&response.decision, &response.reason);
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(Error::InputError(msg)) => {
            eprintln!("claude-interceptor: {msg}");
            process::exit(2);
        }
        Err(Error::BrokerError(reason)) => {
            verdict_on_error(&reason);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn tolerate_disconnected_shutdown_passes_ok_through() {
        assert!(tolerate_disconnected_shutdown(Ok(())).is_ok());
    }

    #[test]
    fn tolerate_disconnected_shutdown_swallows_peer_gone_errors() {
        // These four kinds all mean "peer already closed, no point
        // half-closing our side". Any of them is a non-fatal race that
        // happens when a fast broker writes its response and drops the
        // stream before our shutdown(Write) call lands.
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

    /// Reproduces the BSD-style race: peer drops its end (closing the
    /// AF_UNIX connection) before we try to half-close ours. macOS reports
    /// ENOTCONN here; Linux generally accepts the shutdown silently. Either
    /// way, our wrapper returns Ok.
    ///
    /// Skips on EPERM: sandboxed test environments (Landlock, restricted
    /// seccomp) may refuse `socketpair()` or `write()` on AF_UNIX. The
    /// pure-logic tests above already exercise the wrapper for every
    /// tolerated `ErrorKind`; this one is just real-OS confirmation.
    #[test]
    fn shutdown_on_disconnected_unix_pair_is_tolerated() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (a, b) = match UnixStream::pair() {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "[skip shutdown_on_disconnected_unix_pair_is_tolerated] \
                     AF_UNIX pair denied: {e}"
                );
                return;
            }
            Err(e) => panic!("UnixStream::pair: {e}"),
        };
        // Write something so the response is buffered on `a`'s read side
        // even after `b` is gone — mirrors the production race.
        if let Err(e) = (&b).write_all(b"hello\n") {
            if e.kind() == io::ErrorKind::PermissionDenied {
                eprintln!(
                    "[skip shutdown_on_disconnected_unix_pair_is_tolerated] \
                     AF_UNIX write denied: {e}"
                );
                return;
            }
            panic!("write_all: {e}");
        }
        drop(b);
        let r = tolerate_disconnected_shutdown(a.shutdown(Shutdown::Write));
        assert!(r.is_ok(), "expected tolerance, got {r:?}");
    }

    // env_bool is process-global through std::env::var. Each test below uses a
    // unique var name to avoid racing with other tests running in parallel,
    // and removes the var at the end so reruns are clean.

    #[test]
    fn env_bool_unset_is_false() {
        let name = "PREMPTI_TEST_ENV_BOOL_UNSET";
        env::remove_var(name);
        assert!(!env_bool(name));
    }

    #[test]
    fn env_bool_one_is_true() {
        let name = "PREMPTI_TEST_ENV_BOOL_ONE";
        env::set_var(name, "1");
        assert!(env_bool(name));
        env::remove_var(name);
    }

    #[test]
    fn env_bool_true_case_insensitive() {
        let name = "PREMPTI_TEST_ENV_BOOL_TRUE";
        for v in ["true", "TRUE", "True"] {
            env::set_var(name, v);
            assert!(env_bool(name), "{v} should be truthy");
        }
        env::remove_var(name);
    }

    #[test]
    fn env_bool_trims_whitespace() {
        let name = "PREMPTI_TEST_ENV_BOOL_WS";
        env::set_var(name, " 1 ");
        assert!(env_bool(name));
        env::remove_var(name);
    }

    #[test]
    fn env_bool_falsy_values() {
        let name = "PREMPTI_TEST_ENV_BOOL_FALSY";
        for v in ["0", "", "no", "off", "false", "anything"] {
            env::set_var(name, v);
            assert!(!env_bool(name), "{v:?} should be falsy");
        }
        env::remove_var(name);
    }

    // ------------------------------------------------------------------
    // parse_input_max: env-driven stdin cap with clamping
    // ------------------------------------------------------------------

    #[test]
    fn parse_input_max_unset_returns_default() {
        assert_eq!(parse_input_max(None), INPUT_MAX_DEFAULT);
    }

    #[test]
    fn parse_input_max_typo_falls_back_to_default() {
        // Garbage in the env var must NOT hard-block tool calls; falling
        // back to the default keeps standalone users out of a typo trap.
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
}
