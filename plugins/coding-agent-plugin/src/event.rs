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
    pub event: serde_json::Value,
}

/// Parsed event data queued for Falco.
pub struct EventData {
    /// Broker-assigned correlation ID (monotonic counter, always > 0).
    pub correlation_id: u64,
    /// Agent name (e.g., "claude_code").
    pub agent_name: String,
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
    tool_use_id: String,
    hook_event_name: String,
    session_id: String,
    permission_mode: String,
    transcript_path: String,
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

/// The event payload stored in Falco events. Contains the correlation ID, agent name,
/// and the raw Claude Code hook JSON separated by newlines.
///
/// Format: `<correlation_id>\n<agent_name>\n<raw_event_json>`
pub fn encode_payload(data: &EventData) -> Vec<u8> {
    let id_str = data.correlation_id.to_string();
    let mut payload = Vec::with_capacity(
        id_str.len() + data.agent_name.len() + data.raw_event.len() + 2,
    );
    payload.extend_from_slice(id_str.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(data.agent_name.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(&data.raw_event);
    payload
}

/// Decode the payload back into parts.
fn decode_payload(payload: &[u8]) -> Option<(&str, &str, &[u8])> {
    let first_nl = payload.iter().position(|&b| b == b'\n')?;
    let rest = &payload[first_nl + 1..];
    let second_nl = rest.iter().position(|&b| b == b'\n')?;

    let correlation_id = std::str::from_utf8(&payload[..first_nl]).ok()?;
    let agent_name = std::str::from_utf8(&rest[..second_nl]).ok()?;
    let raw_event = &rest[second_nl + 1..];
    Some((correlation_id, agent_name, raw_event))
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
        let (correlation_id_str, agent_name, raw_event) = decode_payload(payload)?;
        let correlation_id: u64 = correlation_id_str.parse().ok()?;
        let event: serde_json::Value = serde_json::from_slice(raw_event).ok()?;

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
            agent_name: agent_name.to_string(),
            correlation_id,
            tool_use_id,
            hook_event_name,
            session_id,
            permission_mode,
            transcript_path,
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
        format!("1\nclaude_code\n{}", event_json).into_bytes()
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
}
