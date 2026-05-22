use falco_event::fields::{FromBytes, FromBytesError, ToBytes};
use falco_plugin::event::EventSource;
use serde::Deserialize;
use std::io::Write as IoWrite;
use std::path::{Component, Path, PathBuf};

/// Custom event payload type that declares "coding_agent" as the event source.
/// This restricts the ExtractPlugin to only extract from our plugin's events,
/// preventing it from being called on syscall events.
pub struct CodingAgentPayload<'a>(pub &'a [u8]);

impl EventSource for CodingAgentPayload<'_> {
    const SOURCE: Option<&'static str> = Some("coding_agent");
}

impl<'a> FromBytes<'a> for CodingAgentPayload<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        Ok(CodingAgentPayload(std::mem::take(buf)))
    }
}

impl ToBytes for CodingAgentPayload<'_> {
    fn binary_size(&self) -> usize {
        self.0.len()
    }

    fn write<W: IoWrite>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.0)
    }

    fn default_repr() -> impl ToBytes {
        &[] as &[u8]
    }
}

/// Wire protocol request from the interceptor.
#[derive(Deserialize)]
pub struct InterceptorRequest {
    #[allow(dead_code)]
    pub version: u32,
    pub id: String,
    pub agent_name: String,
    /// PID of the agent process that invoked the hook. Optional on the
    /// wire so older interceptors (without this field) keep working.
    /// `u64` matches the `agent.pid` Falco field type.
    #[serde(default)]
    pub agent_pid: Option<u64>,
    pub event: serde_json::Value,
}

/// Parsed event data queued for Falco.
pub struct EventData {
    /// Broker-assigned correlation ID (monotonic counter, always > 0).
    pub correlation_id: u64,
    /// Agent name (e.g., "claude_code").
    pub agent_name: String,
    /// PID of the agent process that invoked the hook. `0` = unknown.
    pub agent_pid: u64,
    /// Raw event JSON bytes (the Claude Code hook input).
    pub raw_event: Vec<u8>,
}

/// Cached parsed event fields for extraction. Populated lazily on first field access.
#[derive(Default)]
pub struct ParsedEvent {
    parsed: Option<ParsedFields>,
}

struct ParsedFields {
    agent_name: String,
    correlation_id: u64,
    agent_pid: u64,
    tool_use_id: String,
    hook_event_name: String,
    session_id: String,
    permission_mode: String,
    transcript_path: String,
    // Codex-only fields (empty for Claude Code).
    agent_model: String,
    agent_turn_id: String,
    // Raw paths (as reported by Claude Code)
    cwd: String,
    file_path: String,
    // Resolved paths (canonicalized or lexically normalized)
    real_cwd: String,
    real_file_path: String,
    // Other fields
    tool_name: String,
    tool_input: serde_json::Value,
    tool_input_command: String,
}

/// Number of `\n` separators in the on-wire payload format. Kept in sync
/// with the section count in `encode_payload` / `decode_payload`.
const NEWLINE_COUNT: usize = 3;

/// The event payload stored in Falco events. Contains the correlation ID,
/// agent name, agent PID, and the raw Claude Code hook JSON separated by
/// newlines.
///
/// Format: `<correlation_id>\n<agent_name>\n<agent_pid>\n<raw_event_json>`
pub fn encode_payload(data: &EventData) -> Vec<u8> {
    let id_str = data.correlation_id.to_string();
    let pid_str = data.agent_pid.to_string();
    let mut payload = Vec::with_capacity(
        id_str.len()
            + data.agent_name.len()
            + pid_str.len()
            + data.raw_event.len()
            + NEWLINE_COUNT,
    );
    payload.extend_from_slice(id_str.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(data.agent_name.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(pid_str.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(&data.raw_event);
    payload
}

/// Borrowed view over a decoded wire-format payload. Each field points
/// into the original payload buffer; see `encode_payload` for the layout.
struct DecodedPayload<'a> {
    correlation_id: &'a str,
    agent_name: &'a str,
    agent_pid: &'a str,
    raw_event: &'a [u8],
}

/// Decode the payload back into its sections.
fn decode_payload(payload: &[u8]) -> Option<DecodedPayload<'_>> {
    let first_nl = payload.iter().position(|&b| b == b'\n')?;
    let after_first = &payload[first_nl + 1..];
    let second_nl = after_first.iter().position(|&b| b == b'\n')?;
    let after_second = &after_first[second_nl + 1..];
    let third_nl = after_second.iter().position(|&b| b == b'\n')?;

    Some(DecodedPayload {
        correlation_id: std::str::from_utf8(&payload[..first_nl]).ok()?,
        agent_name: std::str::from_utf8(&after_first[..second_nl]).ok()?,
        agent_pid: std::str::from_utf8(&after_second[..third_nl]).ok()?,
        raw_event: &after_second[third_nl + 1..],
    })
}

impl ParsedEvent {
    /// Parse the event payload and cache the result.
    fn ensure_parsed(&mut self, payload: &[u8]) -> Option<&ParsedFields> {
        if self.parsed.is_none() {
            self.parsed = Self::parse(payload);
        }
        self.parsed.as_ref()
    }

    fn parse(payload: &[u8]) -> Option<ParsedFields> {
        let decoded = decode_payload(payload)?;
        let correlation_id: u64 = decoded.correlation_id.parse().ok()?;
        let agent_pid: u64 = decoded.agent_pid.parse().ok()?;
        let event: serde_json::Value = serde_json::from_slice(decoded.raw_event).ok()?;

        let tool_use_id = event
            .get("tool_use_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hook_event_name = event
            .get("hook_event_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let session_id = event
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let permission_mode = event
            .get("permission_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let transcript_path = event
            .get("transcript_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Codex emits `model` and `turn_id` in every PreToolUse / PermissionRequest
        // payload; Claude Code does not. Default to empty when absent.
        let agent_model = event
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let agent_turn_id = event
            .get("turn_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool_name = event
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool_input = event
            .get("tool_input")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        // Raw paths — exactly as reported by Claude Code.
        let cwd = event
            .get("cwd")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let file_path = extract_raw_file_path(&tool_name, &tool_input);

        // Resolved paths — canonicalized with lexical normalization fallback.
        let real_cwd = resolve_path(&cwd);
        let real_file_path = resolve_file_path(&file_path, &real_cwd);

        let tool_input_command = extract_command(&tool_name, &tool_input);

        Some(ParsedFields {
            agent_name: decoded.agent_name.to_string(),
            correlation_id,
            agent_pid,
            tool_use_id,
            hook_event_name,
            session_id,
            permission_mode,
            transcript_path,
            agent_model,
            agent_turn_id,
            cwd,
            file_path,
            real_cwd,
            real_file_path,
            tool_name,
            tool_input,
            tool_input_command,
        })
    }

    pub fn agent_name(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload).map(|f| f.agent_name.as_str())
    }

    pub fn correlation_id(&mut self, payload: &[u8]) -> Option<u64> {
        self.ensure_parsed(payload).map(|f| f.correlation_id)
    }

    pub fn agent_pid(&mut self, payload: &[u8]) -> Option<u64> {
        self.ensure_parsed(payload).map(|f| f.agent_pid)
    }

    pub fn tool_use_id(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.tool_use_id.as_str())
    }

    pub fn hook_event_name(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.hook_event_name.as_str())
    }

    pub fn session_id(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload).map(|f| f.session_id.as_str())
    }

    pub fn permission_mode(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.permission_mode.as_str())
    }

    pub fn transcript_path(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.transcript_path.as_str())
    }

    pub fn agent_model(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.agent_model.as_str())
    }

    pub fn agent_turn_id(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.agent_turn_id.as_str())
    }

    pub fn cwd(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload).map(|f| f.cwd.as_str())
    }

    pub fn real_cwd(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload).map(|f| f.real_cwd.as_str())
    }

    pub fn tool_name(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload).map(|f| f.tool_name.as_str())
    }

    pub fn tool_input(&mut self, payload: &[u8]) -> Option<String> {
        self.ensure_parsed(payload)
            .map(|f| serde_json::to_string(&f.tool_input).unwrap_or_default())
    }

    pub fn tool_input_command(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.tool_input_command.as_str())
    }

    pub fn file_path(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload).map(|f| f.file_path.as_str())
    }

    pub fn real_file_path(&mut self, payload: &[u8]) -> Option<&str> {
        self.ensure_parsed(payload)
            .map(|f| f.real_file_path.as_str())
    }

}

// ---------------------------------------------------------------------------
// Field extraction helpers
// ---------------------------------------------------------------------------

fn extract_command(tool_name: &str, tool_input: &serde_json::Value) -> String {
    if tool_name != "Bash" {
        return String::new();
    }
    tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extract the raw file_path from tool_input (Write/Edit/Read only).
fn extract_raw_file_path(tool_name: &str, tool_input: &serde_json::Value) -> String {
    if !matches!(tool_name, "Write" | "Edit" | "Read") {
        return String::new();
    }
    tool_input
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Normalize a path lexically: resolve `.` and `..` without touching the filesystem.
/// Never pops past the root (/ on Unix, C:\ on Windows) — mirrors filesystem behavior.
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // file_name() returns None for root paths and empty paths,
                // preventing `..` from erasing the drive letter or root.
                if result.file_name().is_some() {
                    result.pop();
                }
            }
            Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

/// Normalize path separators to forward slashes for cross-platform rule portability.
/// On Windows, `canonicalize` and `PathBuf::to_string_lossy` produce backslashes,
/// but Falco rules should use forward slashes consistently.
fn normalize_separators(path: String) -> String {
    #[cfg(windows)]
    {
        // Strip \\?\ prefix that Windows canonicalize may add.
        let stripped = path
            .strip_prefix(r"\\?\")
            .unwrap_or(&path)
            .to_string();
        stripped.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        path
    }
}

/// Resolve a single path: canonicalize if possible, otherwise lexically normalize.
fn resolve_path(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    // Try filesystem canonicalization first (resolves symlinks).
    if let Ok(resolved) = std::fs::canonicalize(raw) {
        return normalize_separators(resolved.to_string_lossy().into_owned());
    }
    // Fallback: lexical normalization only.
    normalize_separators(normalize_path(Path::new(raw)).to_string_lossy().into_owned())
}

/// Resolve a file path: if relative, join with cwd first, then resolve.
fn resolve_file_path(file_path: &str, resolved_cwd: &str) -> String {
    if file_path.is_empty() {
        return String::new();
    }
    let path = Path::new(file_path);
    let abs = if path.is_absolute() {
        PathBuf::from(file_path)
    } else {
        let mut p = PathBuf::from(resolved_cwd);
        p.push(file_path);
        p
    };
    // Try filesystem canonicalization first.
    if let Ok(resolved) = std::fs::canonicalize(&abs) {
        return normalize_separators(resolved.to_string_lossy().into_owned());
    }
    // Fallback: lexical normalization.
    normalize_separators(normalize_path(&abs).to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_relative() {
        assert_eq!(normalize_path(Path::new("foo/bar/../baz")), PathBuf::from("foo/baz"));
    }

    #[test]
    fn normalize_path_empty() {
        assert_eq!(normalize_path(Path::new("")), PathBuf::from(""));
    }

    #[test]
    fn normalize_path_unix_root_not_erased() {
        // /foo/../.. must stop at /, not produce an empty path.
        assert_eq!(normalize_path(Path::new("/foo/../..")), PathBuf::from("/"));
    }

    #[test]
    fn normalize_path_unix_root_stays() {
        assert_eq!(normalize_path(Path::new("/..")), PathBuf::from("/"));
    }

    #[test]
    fn normalize_path_dot_only() {
        assert_eq!(normalize_path(Path::new("./foo/./bar")), PathBuf::from("foo/bar"));
    }

    #[cfg(windows)]
    #[test]
    fn normalize_path_windows_drive_not_erased() {
        // C:\foo\..\.. must stop at C:\, not produce bare "bar" or empty.
        assert_eq!(
            normalize_path(Path::new(r"C:\foo\..\..\bar")),
            PathBuf::from(r"C:\bar")
        );
    }

    #[cfg(windows)]
    #[test]
    fn normalize_path_windows_drive_root_stays() {
        assert_eq!(normalize_path(Path::new(r"C:\..")), PathBuf::from(r"C:\"));
    }

    #[test]
    fn normalize_path_consecutive_dotdot_from_root() {
        assert_eq!(normalize_path(Path::new("/../../..")), PathBuf::from("/"));
    }

    #[test]
    fn normalize_path_relative_dotdot_past_start() {
        // Relative ../ past start can't be resolved lexically — discarded.
        assert_eq!(normalize_path(Path::new("../../foo")), PathBuf::from("foo"));
    }

    #[test]
    fn normalize_path_single_dotdot() {
        assert_eq!(normalize_path(Path::new("..")), PathBuf::from(""));
    }

    #[cfg(windows)]
    #[test]
    fn normalize_path_windows_unc_root_not_erased() {
        // UNC root must be preserved: \\server\share\..\.. stops at \\server\.
        let result = normalize_path(Path::new(r"\\server\share\..\.."));
        // After popping share and attempting to pop past UNC root,
        // the root component is preserved.
        assert!(result.to_string_lossy().starts_with(r"\\server"));
    }

    fn payload_with(event_json: &str) -> Vec<u8> {
        payload_with_pid(event_json, 0)
    }

    fn payload_with_pid(event_json: &str, agent_pid: u64) -> Vec<u8> {
        format!("1\nclaude_code\n{}\n{}", agent_pid, event_json).into_bytes()
    }

    #[test]
    fn parses_permission_mode_when_present() {
        let p = payload_with(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","permission_mode":"bypassPermissions","session_id":"s"}"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.permission_mode(&p), Some("bypassPermissions"));
    }

    #[test]
    fn permission_mode_empty_when_missing() {
        let p = payload_with(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.permission_mode(&p), Some(""));
    }

    #[test]
    fn permission_mode_empty_when_wrong_type() {
        // Non-string value (e.g., a number) must degrade to empty, not panic.
        let p = payload_with(r#"{"permission_mode":42}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.permission_mode(&p), Some(""));
    }

    #[test]
    fn parses_transcript_path_when_present() {
        let p = payload_with(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","transcript_path":"/tmp/t.jsonl"}"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.transcript_path(&p), Some("/tmp/t.jsonl"));
    }

    #[test]
    fn transcript_path_empty_when_null() {
        // Codex may emit null for transcript_path.
        let p = payload_with(r#"{"transcript_path":null}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.transcript_path(&p), Some(""));
    }

    #[test]
    fn transcript_path_empty_when_missing() {
        let p = payload_with(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.transcript_path(&p), Some(""));
    }

    // ------------------------------------------------------------------
    // extract_command / extract_raw_file_path
    // ------------------------------------------------------------------

    #[test]
    fn tool_input_command_populated_for_bash() {
        let p = payload_with(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.tool_input_command(&p), Some("ls -la"));
    }

    #[test]
    fn tool_input_command_empty_for_non_bash() {
        let p = payload_with(
            r#"{"tool_name":"Write","tool_input":{"command":"echo hi"}}"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.tool_input_command(&p), Some(""));
    }

    #[test]
    fn tool_input_command_empty_when_command_missing() {
        let p = payload_with(r#"{"tool_name":"Bash","tool_input":{}}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.tool_input_command(&p), Some(""));
    }

    #[test]
    fn file_path_populated_for_write_edit_read() {
        for tool in ["Write", "Edit", "Read"] {
            let json = format!(
                r#"{{"tool_name":"{}","tool_input":{{"file_path":"/tmp/f"}}}}"#,
                tool
            );
            let p = payload_with(&json);
            let mut pe = ParsedEvent::default();
            assert_eq!(pe.file_path(&p), Some("/tmp/f"), "tool={}", tool);
        }
    }

    #[test]
    fn file_path_empty_for_other_tools() {
        for tool in ["Bash", "Glob", "Grep", "Agent"] {
            let json = format!(
                r#"{{"tool_name":"{}","tool_input":{{"file_path":"/tmp/f"}}}}"#,
                tool
            );
            let p = payload_with(&json);
            let mut pe = ParsedEvent::default();
            assert_eq!(pe.file_path(&p), Some(""), "tool={}", tool);
        }
    }

    // ------------------------------------------------------------------
    // resolve_path / resolve_file_path
    // ------------------------------------------------------------------

    #[test]
    fn resolve_path_canonicalizes_existing() {
        // /tmp exists on every Unix. On macOS it's a symlink to /private/tmp —
        // just assert the result is absolute and non-empty.
        let resolved = resolve_path("/tmp");
        assert!(!resolved.is_empty());
        #[cfg(unix)]
        assert!(resolved.starts_with('/'));
    }

    #[test]
    fn resolve_path_lexical_fallback_for_nonexistent() {
        let resolved =
            resolve_path("/definitely/does/not/exist/foo/../bar");
        // Lexical normalization: foo/.. pops, leaving /.../exist/bar.
        assert_eq!(resolved, "/definitely/does/not/exist/bar");
    }

    #[test]
    fn resolve_path_empty_returns_empty() {
        assert_eq!(resolve_path(""), "");
    }

    #[test]
    fn resolve_file_path_joins_relative_to_cwd() {
        // Use a non-existent cwd so we exercise the lexical path.
        let resolved =
            resolve_file_path("foo/bar", "/nonexistent-cwd-1234");
        assert_eq!(resolved, "/nonexistent-cwd-1234/foo/bar");
    }

    #[test]
    fn resolve_file_path_preserves_absolute() {
        let resolved = resolve_file_path("/abs/path", "/some/cwd");
        assert_eq!(resolved, "/abs/path");
    }

    #[test]
    fn resolve_file_path_empty_returns_empty() {
        assert_eq!(resolve_file_path("", "/cwd"), "");
    }

    #[test]
    fn resolve_file_path_lexical_collapses_dotdot() {
        let resolved =
            resolve_file_path("../sibling/file", "/nonexistent/a/b");
        assert_eq!(resolved, "/nonexistent/a/sibling/file");
    }

    // ------------------------------------------------------------------
    // ParsedEvent end-to-end: every accessor
    // ------------------------------------------------------------------

    #[test]
    fn parsed_event_all_fields_populated() {
        let p = payload_with(
            r#"{
                "hook_event_name":"PreToolUse",
                "session_id":"sess-1",
                "permission_mode":"default",
                "transcript_path":"/tmp/t.jsonl",
                "cwd":"/nonexistent-cwd-999",
                "tool_use_id":"call-1",
                "tool_name":"Write",
                "tool_input":{"file_path":"out.txt","content":"hi"}
            }"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_name(&p), Some("claude_code"));
        assert_eq!(pe.correlation_id(&p), Some(1));
        assert_eq!(pe.agent_pid(&p), Some(0));
        assert_eq!(pe.tool_use_id(&p), Some("call-1"));
        assert_eq!(pe.hook_event_name(&p), Some("PreToolUse"));
        assert_eq!(pe.session_id(&p), Some("sess-1"));
        assert_eq!(pe.permission_mode(&p), Some("default"));
        assert_eq!(pe.transcript_path(&p), Some("/tmp/t.jsonl"));
        // Claude Code does not emit model / turn_id — both default to empty.
        assert_eq!(pe.agent_model(&p), Some(""));
        assert_eq!(pe.agent_turn_id(&p), Some(""));
        assert_eq!(pe.cwd(&p), Some("/nonexistent-cwd-999"));
        assert_eq!(pe.real_cwd(&p), Some("/nonexistent-cwd-999"));
        assert_eq!(pe.tool_name(&p), Some("Write"));
        assert_eq!(pe.file_path(&p), Some("out.txt"));
        assert_eq!(
            pe.real_file_path(&p),
            Some("/nonexistent-cwd-999/out.txt")
        );
        assert_eq!(pe.tool_input_command(&p), Some(""));

        // tool_input round-trips as JSON string.
        let input = pe.tool_input(&p).expect("tool_input");
        let parsed: serde_json::Value =
            serde_json::from_str(&input).expect("parse tool_input JSON");
        assert_eq!(parsed["file_path"], "out.txt");
        assert_eq!(parsed["content"], "hi");
    }

    #[test]
    fn parsed_event_fields_default_to_empty_when_missing() {
        let p = payload_with(r#"{}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_pid(&p), Some(0));
        assert_eq!(pe.tool_use_id(&p), Some(""));
        assert_eq!(pe.hook_event_name(&p), Some(""));
        assert_eq!(pe.session_id(&p), Some(""));
        assert_eq!(pe.permission_mode(&p), Some(""));
        assert_eq!(pe.transcript_path(&p), Some(""));
        assert_eq!(pe.agent_model(&p), Some(""));
        assert_eq!(pe.agent_turn_id(&p), Some(""));
        assert_eq!(pe.cwd(&p), Some(""));
        assert_eq!(pe.real_cwd(&p), Some(""));
        assert_eq!(pe.tool_name(&p), Some(""));
        assert_eq!(pe.file_path(&p), Some(""));
        assert_eq!(pe.real_file_path(&p), Some(""));
        assert_eq!(pe.tool_input_command(&p), Some(""));
        // tool_input with no field serializes to the default empty object.
        assert_eq!(pe.tool_input(&p), Some("{}".to_string()));
    }

    #[test]
    fn parsed_event_caches_after_first_access() {
        // Second access of a field must not re-parse (and must not silently
        // diverge from the first call).
        let p = payload_with(
            r#"{"session_id":"abc","tool_name":"Bash","tool_input":{"command":"x"}}"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.session_id(&p), Some("abc"));
        assert_eq!(pe.tool_input_command(&p), Some("x"));
        assert_eq!(pe.session_id(&p), Some("abc"));
    }

    #[test]
    fn parsed_event_tool_input_preserves_nested_json() {
        let p = payload_with(
            r#"{"tool_name":"Edit","tool_input":{"file_path":"/a","edits":[{"old":"x","new":"y"}]}}"#,
        );
        let mut pe = ParsedEvent::default();
        let s = pe.tool_input(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["edits"][0]["old"], "x");
        assert_eq!(v["edits"][0]["new"], "y");
    }

    #[test]
    fn parsed_event_malformed_payload_returns_none() {
        // Payload with only one newline (missing agent_name section).
        let bad = b"1\njust-one-line".to_vec();
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_name(&bad), None);
    }

    #[test]
    fn parsed_event_missing_agent_pid_section_returns_none() {
        // Old wire format (correlation_id\nagent_name\nevent) without the
        // agent_pid section. decode_payload requires three newlines now.
        let bad = b"1\nclaude_code\n{}".to_vec();
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_name(&bad), None);
    }

    #[test]
    fn parsed_event_invalid_event_json_returns_none() {
        let bad = b"1\nclaude_code\n0\n{this is not json".to_vec();
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_name(&bad), None);
    }

    #[test]
    fn parsed_event_agent_pid_round_trips() {
        let p = payload_with_pid(r#"{"tool_name":"Bash"}"#, 12345);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_pid(&p), Some(12345));
    }

    #[test]
    fn parsed_event_agent_pid_zero_means_unknown() {
        let p = payload_with(r#"{"tool_name":"Bash"}"#);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_pid(&p), Some(0));
    }

    #[test]
    fn parsed_event_agent_pid_invalid_number_returns_none() {
        // Non-numeric agent_pid section should fail the parse.
        let bad = b"1\nclaude_code\nnotanumber\n{}".to_vec();
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_pid(&bad), None);
    }

    #[test]
    fn encode_decode_payload_round_trip() {
        let data = EventData {
            correlation_id: 42,
            agent_name: "claude_code".to_string(),
            agent_pid: 9999,
            raw_event: br#"{"tool_name":"Bash"}"#.to_vec(),
        };
        let encoded = encode_payload(&data);
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.correlation_id(&encoded), Some(42));
        assert_eq!(pe.agent_name(&encoded), Some("claude_code"));
        assert_eq!(pe.agent_pid(&encoded), Some(9999));
        assert_eq!(pe.tool_name(&encoded), Some("Bash"));
    }

    // ------------------------------------------------------------------
    // Codex-shaped event payloads. These are regression guards: Codex's
    // hook JSON is snake_case (same as Claude Code), but the tool names
    // and field set differ. If a future event.rs refactor accidentally
    // assumes Claude Code shape, these tests catch it.
    // ------------------------------------------------------------------

    fn codex_payload(event_json: &str) -> Vec<u8> {
        format!("1\ncodex\n0\n{}", event_json).into_bytes()
    }

    #[test]
    fn parses_codex_pre_tool_use_bash_payload() {
        // Full Codex PreToolUse JSON shape per codex-rs/hooks/schema/
        // generated/pre-tool-use.command.input.schema.json. Required fields:
        // session_id, turn_id, transcript_path, cwd, hook_event_name, model,
        // permission_mode, tool_name, tool_input, tool_use_id.
        let p = codex_payload(
            r#"{
                "session_id": "sess-codex-1",
                "turn_id": "turn-1",
                "transcript_path": null,
                "cwd": "/work",
                "hook_event_name": "PreToolUse",
                "model": "gpt-5-codex",
                "permission_mode": "default",
                "tool_name": "Bash",
                "tool_input": {"command": "ls -la"},
                "tool_use_id": "tu-1"
            }"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.agent_name(&p), Some("codex"));
        assert_eq!(pe.hook_event_name(&p), Some("PreToolUse"));
        assert_eq!(pe.session_id(&p), Some("sess-codex-1"));
        assert_eq!(pe.permission_mode(&p), Some("default"));
        assert_eq!(pe.transcript_path(&p), Some(""));
        assert_eq!(pe.tool_use_id(&p), Some("tu-1"));
        assert_eq!(pe.tool_name(&p), Some("Bash"));
        assert_eq!(pe.tool_input_command(&p), Some("ls -la"));
        // Codex-only fields populated.
        assert_eq!(pe.agent_model(&p), Some("gpt-5-codex"));
        assert_eq!(pe.agent_turn_id(&p), Some("turn-1"));
    }

    #[test]
    fn parses_codex_permission_request_without_tool_use_id() {
        // PermissionRequest's schema omits tool_use_id — defaults to empty.
        let p = codex_payload(
            r#"{
                "session_id": "sess-codex-2",
                "turn_id": "turn-7",
                "transcript_path": null,
                "cwd": "/work",
                "hook_event_name": "PermissionRequest",
                "model": "gpt-5-codex",
                "permission_mode": "default",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"}
            }"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.hook_event_name(&p), Some("PermissionRequest"));
        assert_eq!(pe.tool_use_id(&p), Some(""));
        assert_eq!(pe.tool_input_command(&p), Some("rm -rf /"));
        // PermissionRequest also carries model + turn_id.
        assert_eq!(pe.agent_model(&p), Some("gpt-5-codex"));
        assert_eq!(pe.agent_turn_id(&p), Some("turn-7"));
    }

    #[test]
    fn codex_apply_patch_yields_empty_file_path() {
        // Codex uses tool_name = "apply_patch" for file writes. Our parser
        // only extracts file_path for Claude Code's Write/Edit/Read tools,
        // so apply_patch produces an empty file_path until path resolution
        // for patch-based inputs lands (v1 limitation).
        let p = codex_payload(
            r#"{
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": {"input": "diff content here"}
            }"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.tool_name(&p), Some("apply_patch"));
        assert_eq!(pe.file_path(&p), Some(""));
        assert_eq!(pe.real_file_path(&p), Some(""));
    }

    #[test]
    fn codex_dont_ask_permission_mode_passes_through() {
        // dontAsk is a Codex-only permission_mode value; the parser must not
        // reject it (it's an opaque string at the plugin layer).
        let p = codex_payload(
            r#"{"hook_event_name":"PreToolUse","permission_mode":"dontAsk"}"#,
        );
        let mut pe = ParsedEvent::default();
        assert_eq!(pe.permission_mode(&p), Some("dontAsk"));
    }
}
