// Pretty renderer for `coding-agents-kit-ctl logs`.
//
// Buffers all alerts for a given correlation.id until the catch-all `seen`
// alert arrives, then renders one block per event. The seen alert carries
// every output_field, so we can produce a Tool(...) body even when the
// matching deny/ask rule's own output template references only a subset of
// fields.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use serde_json::Value;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PrettyOpts {
    pub color: bool,
    pub stats: bool,
    pub follow: bool,
    pub show: ShowMask,
    pub term_cols: usize,
}

pub const SHOW_DENY: u8 = 1 << 0;
pub const SHOW_ASK: u8 = 1 << 1;
pub const SHOW_ALLOW: u8 = 1 << 2;
pub const SHOW_SEEN: u8 = 1 << 3;
pub const SHOW_DEFAULT: u8 = SHOW_DENY | SHOW_ASK | SHOW_ALLOW;
pub const SHOW_ALL: u8 = SHOW_DENY | SHOW_ASK | SHOW_ALLOW | SHOW_SEEN;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShowMask(pub u8);

impl ShowMask {
    pub fn default_mask() -> Self {
        ShowMask(SHOW_DEFAULT)
    }
    pub fn contains(self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut mask: u8 = 0;
        for raw in s.split(',') {
            let token = raw.trim().to_ascii_lowercase();
            if token.is_empty() {
                continue;
            }
            mask |= match token.as_str() {
                "deny" => SHOW_DENY,
                "ask" => SHOW_ASK,
                "allow" => SHOW_ALLOW,
                "seen" => SHOW_SEEN,
                "all" => SHOW_ALL,
                "none" => 0,
                _ => return Err(format!("invalid --show value: {}", token)),
            };
        }
        Ok(ShowMask(mask))
    }
}

pub trait SessionNameResolver {
    fn resolve(&mut self, transcript_path: &str) -> Option<String>;
}

#[derive(Default)]
struct ResolverEntry {
    /// Bytes already consumed from the file. Lets repeat calls re-scan only
    /// the new (appended) tail of the transcript.
    last_pos: u64,
    /// Most recent {"type":"custom-title"} value seen so far. Wins over the
    /// first user message — Claude Code writes this on `/rename`.
    custom_title: Option<String>,
    /// First {"type":"user"} message text. Used only when no custom title
    /// has ever been seen.
    first_user_message: Option<String>,
}

impl ResolverEntry {
    fn current(&self) -> Option<String> {
        self.custom_title
            .clone()
            .or_else(|| self.first_user_message.clone())
    }
}

#[derive(Default)]
pub struct FsSessionNameResolver {
    cache: HashMap<String, ResolverEntry>,
}

impl SessionNameResolver for FsSessionNameResolver {
    fn resolve(&mut self, transcript_path: &str) -> Option<String> {
        if transcript_path.is_empty() {
            return None;
        }
        let cur_size = std::fs::metadata(transcript_path).ok().map(|m| m.len());
        let entry = self.cache.entry(transcript_path.to_string()).or_default();

        if let Some(size) = cur_size {
            // Detect truncation/rotation: file shrank → restart scan.
            if size < entry.last_pos {
                *entry = ResolverEntry::default();
            }
            if size > entry.last_pos {
                scan_transcript_incremental(transcript_path, entry);
                entry.last_pos = size;
            }
        }
        entry.current()
    }
}

fn scan_transcript_incremental(path: &str, entry: &mut ResolverEntry) {
    use std::io::{Seek, SeekFrom};
    let f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut reader = BufReader::new(f);
    if entry.last_pos > 0 && reader.seek(SeekFrom::Start(entry.last_pos)).is_err() {
        return;
    }
    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end();
        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match v.get("type").and_then(|t| t.as_str()) {
            Some("custom-title") => {
                if let Some(t) = v.get("customTitle").and_then(|t| t.as_str()) {
                    entry.custom_title = Some(condense_session_name(t));
                }
            }
            Some("user") => {
                if entry.first_user_message.is_none() {
                    if let Some(text) = extract_user_message_text(&v) {
                        entry.first_user_message = Some(condense_session_name(&text));
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_user_message_text(v: &Value) -> Option<String> {
    let msg = v.get("message")?;
    if msg.get("role").and_then(|r| r.as_str()) != Some("user") {
        return None;
    }
    let content = msg.get("content")?;
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(arr) => arr.iter().find_map(|el| {
            if el.get("type").and_then(|t| t.as_str()) == Some("text") {
                el.get("text").and_then(|t| t.as_str()).map(String::from)
            } else {
                None
            }
        }),
        _ => None,
    }
}

fn condense_session_name(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if (c as u32) < 0x20 => ' ',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim();
    let truncated = take_chars(trimmed, 50);
    if truncated.chars().count() < trimmed.chars().count() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

fn take_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// ---------------------------------------------------------------------------
// Counters & state
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct Counters {
    pub events: u64,
    pub allow: u64,
    pub ask: u64,
    pub deny: u64,
    pub sessions: u64,
}

#[derive(Default)]
struct EventBuffer {
    /// Verdict alerts seen so far for this correlation.
    verdicts: Vec<VerdictAlert>,
}

struct VerdictAlert {
    kind: VerdictKind,
    rule_name: String,
    priority: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerdictKind {
    Deny,
    Ask,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalVerdict {
    Deny,
    Ask,
    Allow,
}

struct SessionState {
    color_code: u8,
    /// Title last emitted to the user (in banner or rename notice). When the
    /// resolver returns something different on a later event, we emit a
    /// notice line so the rename is visible.
    last_title: Option<String>,
}

/// Trim a session_id for display. UUIDs (36 chars) collapse to 8-char prefix
/// — recognizable like a git short SHA, no ellipsis. Anything ≤ 12 chars is
/// shown in full. Empty input yields `?`.
fn short_session_id(session_id: &str) -> String {
    if session_id.is_empty() {
        return "?".to_string();
    }
    if session_id.chars().count() <= 12 {
        return session_id.to_string();
    }
    take_chars(session_id, 8)
}

// ---------------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------------

pub struct Formatter<R: SessionNameResolver> {
    opts: PrettyOpts,
    home: String,
    sessions: HashMap<String, SessionState>,
    last_session_id: Option<String>,
    last_emitted_cwd: Option<String>,
    in_flight: HashMap<u64, EventBuffer>,
    counters: Counters,
    resolver: R,
}

impl<R: SessionNameResolver> Formatter<R> {
    pub fn new(opts: PrettyOpts, home: String, resolver: R) -> Self {
        Self {
            opts,
            home,
            sessions: HashMap::new(),
            last_session_id: None,
            last_emitted_cwd: None,
            in_flight: HashMap::new(),
            counters: Counters::default(),
            resolver,
        }
    }

    #[cfg(test)]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Process one input log line. Returns the lines (without trailing
    /// newlines) that should be written to the terminal as a result.
    pub fn process_line(&mut self, line: &str) -> Vec<String> {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            return Vec::new();
        }
        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return vec![self.paint(trimmed, ANSI_DIM)],
        };
        if v.get("source").and_then(|s| s.as_str()) != Some("coding_agent") {
            return vec![self.paint(trimmed, ANSI_DIM)];
        }

        let tags: Vec<String> = v
            .get("tags")
            .and_then(|t| t.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let cid = v
            .get("output_fields")
            .and_then(|of| of.get("correlation.id"))
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        let is_seen = tags.iter().any(|t| t == "coding_agent_seen");
        if is_seen {
            self.finalize(cid, &v)
        } else {
            self.buffer_verdict(cid, &v, &tags);
            Vec::new()
        }
    }

    fn buffer_verdict(&mut self, cid: u64, v: &Value, tags: &[String]) {
        let kind = if tags.iter().any(|t| t == "coding_agent_deny") {
            VerdictKind::Deny
        } else if tags.iter().any(|t| t == "coding_agent_ask") {
            VerdictKind::Ask
        } else {
            VerdictKind::Other
        };
        let rule_name = v
            .get("rule")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        let priority = v
            .get("priority")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let entry = self.in_flight.entry(cid).or_default();
        entry.verdicts.push(VerdictAlert { kind, rule_name, priority });
    }

    fn finalize(&mut self, cid: u64, seen: &Value) -> Vec<String> {
        let buf = self.in_flight.remove(&cid).unwrap_or_default();
        let final_v = if buf.verdicts.iter().any(|x| x.kind == VerdictKind::Deny) {
            FinalVerdict::Deny
        } else if buf.verdicts.iter().any(|x| x.kind == VerdictKind::Ask) {
            FinalVerdict::Ask
        } else {
            FinalVerdict::Allow
        };

        self.counters.events += 1;
        match final_v {
            FinalVerdict::Allow => self.counters.allow += 1,
            FinalVerdict::Ask => self.counters.ask += 1,
            FinalVerdict::Deny => self.counters.deny += 1,
        }

        let render_verdict = match final_v {
            FinalVerdict::Deny => self.opts.show.contains(SHOW_DENY),
            FinalVerdict::Ask => self.opts.show.contains(SHOW_ASK),
            FinalVerdict::Allow => self.opts.show.contains(SHOW_ALLOW),
        };
        let render_seen = self.opts.show.contains(SHOW_SEEN);
        if !render_verdict && !render_seen {
            return Vec::new();
        }

        let fields = seen.get("output_fields");
        let session_id = field_str(fields, "agent.session_id").unwrap_or_default();
        let cwd = field_str(fields, "agent.real_cwd")
            .or_else(|| field_str(fields, "agent.cwd"))
            .unwrap_or_default();
        let transcript_path = field_str(fields, "agent.transcript_path").unwrap_or_default();
        let time_str = clock_time_from_alert(seen);

        let mut out = Vec::new();
        let mut new_session = false;
        if !self.sessions.contains_key(&session_id) {
            let color_code = pick_session_color(&session_id);
            self.sessions.insert(
                session_id.clone(),
                SessionState { color_code, last_title: None },
            );
            self.counters.sessions += 1;
            new_session = true;
        }
        let color_code = self.sessions.get(&session_id).unwrap().color_code;

        // Resolve title up front so we can both emit the banner and detect
        // mid-stream rename. Resolver re-scans the transcript incrementally.
        let resolved_title = self.resolver.resolve(&transcript_path);
        if new_session {
            let banner = self.format_banner(&session_id, color_code, resolved_title.as_deref());
            out.push(banner);
            if let Some(state) = self.sessions.get_mut(&session_id) {
                state.last_title = resolved_title.clone();
            }
        } else {
            // Existing session — emit a notice if /rename happened since
            // the banner was shown.
            let prev = self
                .sessions
                .get(&session_id)
                .and_then(|s| s.last_title.clone());
            if resolved_title != prev && resolved_title.is_some() {
                out.push(self.format_banner(
                    &session_id,
                    color_code,
                    resolved_title.as_deref(),
                ));
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.last_title = resolved_title.clone();
                }
            }
        }

        let need_cwd_line =
            new_session || self.last_emitted_cwd.as_deref() != Some(cwd.as_str());
        if need_cwd_line && !cwd.is_empty() {
            out.push(self.format_cwd_line(&time_str, &session_id, color_code, &cwd));
            self.last_emitted_cwd = Some(cwd.clone());
        }

        if render_verdict {
            let event_line = self.format_event_line(&time_str, &session_id, color_code, final_v, fields);
            out.push(event_line);
            for va in buf.verdicts.iter() {
                if (va.kind == VerdictKind::Deny && final_v == FinalVerdict::Deny)
                    || (va.kind == VerdictKind::Ask && final_v == FinalVerdict::Ask)
                {
                    out.push(self.format_detail_line(&va.priority, &va.rule_name));
                }
            }
        }

        if render_seen {
            out.push(self.format_seen_event_line(&time_str, &session_id, color_code, fields));
        }

        self.last_session_id = Some(session_id);
        out
    }

    fn format_banner(
        &self,
        session_id: &str,
        color_code: u8,
        name: Option<&str>,
    ) -> String {
        let label = short_session_id(session_id);
        let label_painted = self.paint(&label, &session_color_code(color_code));

        let dim_dashes_left = self.paint("──", ANSI_DIM);
        let dim_sep = self.paint(" · ", ANSI_DIM);

        let mut middle = format!("{dim_dashes_left} {label_painted}");
        let mut visible_w = 2 + 1 + display_width(&label);
        if let Some(n) = name {
            if !n.is_empty() {
                let quoted = format!("\"{n}\"");
                middle.push_str(&dim_sep);
                middle.push_str(&self.paint(&quoted, ANSI_DIM));
                visible_w += 3 + display_width(&quoted);
            }
        }
        let term = self.opts.term_cols.max(40);
        let pad_w = term.saturating_sub(visible_w + 1); // +1 for trailing space
        let dashes: String = "─".repeat(pad_w);
        let dashes_painted = self.paint(&dashes, ANSI_DIM);
        format!("{middle} {dashes_painted}")
    }

    fn format_cwd_line(&self, time_str: &str, session_id: &str, color_code: u8, cwd: &str) -> String {
        let abbrev = shorten_path(cwd, &self.home, 60);
        let label = self.format_session_label(session_id, color_code);
        let arrow = self.paint("▸", ANSI_DIM);
        format!(
            "{time}  {label}  {arrow} {path}",
            time = self.paint(time_str, ANSI_DIM),
            label = label,
            arrow = arrow,
            path = self.paint(&abbrev, ANSI_DIM),
        )
    }

    fn format_event_line(
        &self,
        time_str: &str,
        session_id: &str,
        color_code: u8,
        verdict: FinalVerdict,
        fields: Option<&Value>,
    ) -> String {
        let bullet = self.paint(verdict_bullet(verdict), verdict_color(verdict));
        let label = self.format_session_label(session_id, color_code);
        let body = self.render_tool_body(fields);
        format!(
            "{time}  {label}  {bullet}  {body}",
            time = self.paint(time_str, ANSI_DIM),
            label = label,
            bullet = bullet,
            body = body,
        )
    }

    fn format_seen_event_line(
        &self,
        time_str: &str,
        session_id: &str,
        color_code: u8,
        fields: Option<&Value>,
    ) -> String {
        let bullet = self.paint("·", ANSI_DIM);
        let label = self.format_session_label(session_id, color_code);
        let body = self.render_tool_body(fields);
        format!(
            "{time}  {label}  {bullet}  {body}",
            time = self.paint(time_str, ANSI_DIM),
            label = label,
            bullet = bullet,
            body = self.paint(&strip_ansi(&body), ANSI_DIM),
        )
    }

    fn format_detail_line(&self, priority: &str, rule_name: &str) -> String {
        // Indented to align under the tool body.
        let prio_token = priority.to_ascii_uppercase();
        let prio_color = match prio_token.as_str() {
            "CRITICAL" | "ERROR" | "EMERGENCY" | "ALERT" => ANSI_FG_RED,
            "WARNING" => ANSI_FG_YELLOW,
            _ => ANSI_DIM,
        };
        let prio = self.paint(&prio_token, prio_color);
        let arrow = self.paint("↳", ANSI_DIM);
        format!("                   {arrow} {prio}  {rule_name}")
    }

    fn format_session_label(&self, session_id: &str, color_code: u8) -> String {
        let raw = format!("[{}]", short_session_id(session_id));
        self.paint(&raw, &session_color_code(color_code))
    }

    fn render_tool_body(&self, fields: Option<&Value>) -> String {
        let tool = field_str(fields, "tool.name").unwrap_or_else(|| "?".to_string());
        let body = self.tool_body_content(&tool, fields);
        let tool_styled = self.paint(&tool, ANSI_BOLD);
        let lparen = self.paint("(", ANSI_DIM);
        let rparen = self.paint(")", ANSI_DIM);
        format!("{tool_styled}{lparen}{body}{rparen}")
    }

    fn tool_body_content(&self, tool: &str, fields: Option<&Value>) -> String {
        let max = 80usize;
        let raw = match tool {
            "Bash" => field_str(fields, "tool.input_command")
                .or_else(|| input_value_string(fields, "command"))
                .unwrap_or_default(),
            "Read" | "Edit" | "Write" => {
                let p = field_str(fields, "tool.real_file_path")
                    .filter(|s| !s.is_empty())
                    .or_else(|| field_str(fields, "tool.file_path"))
                    .or_else(|| input_value_string(fields, "file_path"))
                    .unwrap_or_default();
                shorten_path(&p, &self.home, max)
            }
            "Grep" => input_value_string(fields, "pattern")
                .or_else(|| stringify_input(fields))
                .unwrap_or_default(),
            "Glob" => input_value_string(fields, "pattern")
                .or_else(|| stringify_input(fields))
                .unwrap_or_default(),
            "WebFetch" => input_value_string(fields, "url").unwrap_or_default(),
            "WebSearch" => input_value_string(fields, "query").unwrap_or_default(),
            "Task" | "Agent" => input_value_string(fields, "description")
                .or_else(|| input_value_string(fields, "prompt"))
                .unwrap_or_default(),
            _ => stringify_input(fields).unwrap_or_default(),
        };
        truncate_for_display(&raw, max)
    }

    /// Footer shown at the bottom of the output: blank line, grey rule, and
    /// the counters in grey with verdict bullets in their colors. Three
    /// lines, no trailing newline on the last one (the runner appends it).
    pub fn status_footer(&self) -> Vec<String> {
        let term = self.opts.term_cols.max(40);
        let blank = String::new();
        let rule = self.paint(&"─".repeat(term), ANSI_GREY);
        let body = self.format_status_body();
        vec![blank, rule, body]
    }

    fn format_status_body(&self) -> String {
        let c = self.counters;
        if !self.opts.color {
            return format!(
                " coding-agents-kit: sessions {} · events {} (● allow {} · ⊙ ask {} · ⊘ deny {})",
                c.sessions, c.events, c.allow, c.ask, c.deny
            );
        }
        // Resume grey after each colored bullet so the row stays in the
        // same tone as the rule line above it.
        format!(
            "{grey} coding-agents-kit: sessions {sessions} · events {events} ({green}●{grey} allow {allow} · {yellow}⊙{grey} ask {ask} · {red}⊘{grey} deny {deny}){reset}",
            grey = ANSI_GREY,
            sessions = c.sessions,
            events = c.events,
            green = ANSI_FG_GREEN,
            allow = c.allow,
            yellow = ANSI_FG_YELLOW,
            ask = c.ask,
            red = ANSI_FG_RED,
            deny = c.deny,
            reset = ANSI_RESET,
        )
    }

    /// Snapshot-mode summary — same content as the live footer, joined with
    /// newlines so callers can `writeln!` it once at end-of-input.
    pub fn summary(&self) -> String {
        self.status_footer().join("\n")
    }

    fn paint(&self, s: &str, code: &str) -> String {
        if self.opts.color && !code.is_empty() {
            format!("{code}{s}{ANSI_RESET}")
        } else {
            s.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level runner
// ---------------------------------------------------------------------------

pub fn run<RD: BufRead, W: Write, RS: SessionNameResolver>(
    reader: RD,
    writer: &mut W,
    opts: PrettyOpts,
    resolver: RS,
) -> std::io::Result<()> {
    let with_status = opts.stats && opts.follow && opts.color;
    let final_summary = opts.stats && !opts.follow;
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let mut formatter = Formatter::new(opts, home, resolver);
    let mut status_drawn = false;

    for line in reader.lines() {
        let line = line?;
        let display = formatter.process_line(&line);
        if display.is_empty() {
            continue;
        }
        if with_status && status_drawn {
            erase_footer(writer, 3)?;
        }
        for dl in display {
            writeln!(writer, "{dl}")?;
        }
        if with_status {
            write_footer(writer, &formatter.status_footer())?;
            writer.flush()?;
            status_drawn = true;
        }
    }

    if with_status && status_drawn {
        // Park the cursor on a fresh line below the footer.
        writeln!(writer)?;
    } else if final_summary {
        writeln!(writer, "{}", formatter.summary())?;
    }
    Ok(())
}

/// Erase a multi-line trailing status footer from the terminal.
/// Cursor is assumed to be at the end of the last footer line (the body).
/// After this call, the cursor sits at the start of the line where the
/// footer's first line used to be — ready to be overwritten.
fn erase_footer<W: Write>(writer: &mut W, lines: usize) -> std::io::Result<()> {
    if lines == 0 {
        return Ok(());
    }
    write!(writer, "\r\x1b[K")?;
    for _ in 1..lines {
        write!(writer, "\x1b[1A\r\x1b[K")?;
    }
    Ok(())
}

fn write_footer<W: Write>(writer: &mut W, lines: &[String]) -> std::io::Result<()> {
    let last = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        if i == last {
            // No trailing newline so the cursor parks on the body line —
            // the next iteration's erase_footer call works against this.
            write!(writer, "{line}")?;
        } else {
            writeln!(writer, "{line}")?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn field_str(fields: Option<&Value>, key: &str) -> Option<String> {
    fields?.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn input_value_string(fields: Option<&Value>, key: &str) -> Option<String> {
    let raw = fields?.get("tool.input")?.as_str()?;
    let parsed: Value = serde_json::from_str(raw).ok()?;
    parsed.get(key).map(|v| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

fn stringify_input(fields: Option<&Value>) -> Option<String> {
    let raw = fields?.get("tool.input")?.as_str()?;
    let parsed: Value = serde_json::from_str(raw).ok()?;
    let obj = parsed.as_object()?;
    if obj.is_empty() {
        return Some(String::new());
    }
    let mut parts = Vec::new();
    for (k, v) in obj {
        let s = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        parts.push(format!("{k}={s}"));
    }
    Some(parts.join(" "))
}

pub fn shorten_path(p: &str, home: &str, max: usize) -> String {
    if p.is_empty() {
        return String::new();
    }
    let with_tilde = if !home.is_empty() && p.starts_with(home) {
        let tail = &p[home.len()..];
        if tail.is_empty() {
            "~".to_string()
        } else if tail.starts_with('/') || tail.starts_with('\\') {
            format!("~{}", tail)
        } else {
            p.to_string()
        }
    } else {
        p.to_string()
    };
    if display_width(&with_tilde) <= max {
        return with_tilde;
    }
    // Ellipsis-middle: keep the first segment and the basename.
    let parts: Vec<&str> = with_tilde.split('/').collect();
    if parts.len() < 3 {
        return truncate_for_display(&with_tilde, max);
    }
    let first = parts.first().copied().unwrap_or("");
    let last = parts.last().copied().unwrap_or("");
    let candidate = if first.is_empty() {
        format!("/.../{}", last)
    } else {
        format!("{}/.../{}", first, last)
    };
    if display_width(&candidate) <= max {
        candidate
    } else {
        truncate_for_display(&candidate, max)
    }
}

fn truncate_for_display(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

/// Extract a `HH:MM:SS` clock time from a Falco alert, in the user's local
/// timezone. Prefers `evt.time` (epoch nanoseconds — exact) and falls back
/// to the ISO `time` field rendered as UTC if conversion fails.
pub fn clock_time_from_alert(alert: &Value) -> String {
    let secs = alert
        .get("output_fields")
        .and_then(|of| of.get("evt.time"))
        .and_then(|t| t.as_u64())
        .map(|ns| (ns / 1_000_000_000) as i64);
    if let Some(s) = secs {
        if let Some((h, m, sec)) = epoch_to_local_hms(s) {
            return format!("{:02}:{:02}:{:02}", h, m, sec);
        }
    }
    // Fallback: slice HH:MM:SS out of the ISO string (UTC). Better than
    // nothing on systems where libc's localtime fails.
    alert
        .get("time")
        .and_then(|t| t.as_str())
        .and_then(|t| {
            if t.len() >= 19 && t.as_bytes().get(10) == Some(&b'T') {
                Some(t[11..19].to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "        ".to_string())
}

#[cfg(unix)]
fn epoch_to_local_hms(secs: i64) -> Option<(u32, u32, u32)> {
    // libc's `struct tm` has 9 ints on POSIX, plus GNU extensions
    // (tm_gmtoff, tm_zone) on Linux. We over-allocate to be safe across
    // glibc/musl/macOS.
    #[repr(C)]
    struct CTm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        _pad: [u64; 4],
    }
    extern "C" {
        fn localtime_r(time: *const i64, result: *mut CTm) -> *mut CTm;
    }
    let mut tm = CTm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        _pad: [0; 4],
    };
    let ptr = unsafe { localtime_r(&secs, &mut tm) };
    if ptr.is_null() {
        return None;
    }
    Some((tm.tm_hour as u32, tm.tm_min as u32, tm.tm_sec as u32))
}

#[cfg(windows)]
fn epoch_to_local_hms(secs: i64) -> Option<(u32, u32, u32)> {
    #[repr(C)]
    struct CTm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
    }
    extern "C" {
        fn _localtime64_s(result: *mut CTm, time: *const i64) -> i32;
    }
    let mut tm = CTm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
    };
    let rc = unsafe { _localtime64_s(&mut tm, &secs) };
    if rc != 0 {
        return None;
    }
    Some((tm.tm_hour as u32, tm.tm_min as u32, tm.tm_sec as u32))
}

fn pick_session_color(session_id: &str) -> u8 {
    // Curated 256-color palette: skip red/green/yellow used for verdicts.
    const PALETTE: [u8; 8] = [33, 39, 45, 81, 99, 141, 177, 213];
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a 64-bit offset basis
    for byte in session_id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    PALETTE[(hash as usize) % PALETTE.len()]
}

fn display_width(s: &str) -> usize {
    // Strip ANSI escapes and count characters (good enough for our ASCII +
    // a handful of single-width Unicode glyphs).
    strip_ansi(s).chars().count()
}

pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until alphabetic byte (end of CSI sequence).
            for nx in chars.by_ref() {
                if nx.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// ANSI palette
// ---------------------------------------------------------------------------

pub const ANSI_RESET: &str = "\x1b[0m";
pub const ANSI_BOLD: &str = "\x1b[1m";
pub const ANSI_DIM: &str = "\x1b[2m";

/// Verdict colors — truecolor RGB so the rendering is identical across
/// terminals regardless of how the user's palette maps standard ANSI 31/32/33.
/// Tuned to match the saturated greens/reds Claude Code uses for tool
/// status indicators (Tailwind-ish 500-weight tones).
pub const ANSI_FG_GREEN: &str = "\x1b[38;2;34;197;94m"; // #22c55e
pub const ANSI_FG_YELLOW: &str = "\x1b[38;2;234;179;8m"; // #eab308
pub const ANSI_FG_RED: &str = "\x1b[38;2;239;68;68m"; // #ef4444

/// Medium grey — Claude Code uses this for the metadata footer
/// (token counts, durations). Used here for the status footer.
pub const ANSI_GREY: &str = "\x1b[38;5;245m";

/// Format a 256-color foreground escape from a palette index.
fn session_color_code(idx: u8) -> String {
    format!("\x1b[38;5;{}m", idx)
}

fn verdict_bullet(v: FinalVerdict) -> &'static str {
    match v {
        FinalVerdict::Allow => "●",
        FinalVerdict::Ask => "⊙",
        FinalVerdict::Deny => "⊘",
    }
}

fn verdict_color(v: FinalVerdict) -> &'static str {
    match v {
        FinalVerdict::Allow => ANSI_FG_GREEN,
        FinalVerdict::Ask => ANSI_FG_YELLOW,
        FinalVerdict::Deny => ANSI_FG_RED,
    }
}

// ---------------------------------------------------------------------------
// Windows: enable VT processing on stdout so ANSI escapes render.
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub fn enable_vt_mode() {
    use std::io::stdout;
    use std::os::windows::io::AsRawHandle;
    extern "system" {
        fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut std::ffi::c_void, mode: u32) -> i32;
    }
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    let h = stdout().as_raw_handle() as *mut std::ffi::c_void;
    let mut mode: u32 = 0;
    unsafe {
        if GetConsoleMode(h, &mut mode) != 0 {
            let _ = SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#[cfg(not(windows))]
pub fn enable_vt_mode() {}

// ---------------------------------------------------------------------------
// Terminal size detection (best-effort).
// ---------------------------------------------------------------------------

pub fn detect_term_cols() -> usize {
    if let Ok(s) = std::env::var("COLUMNS") {
        if let Ok(n) = s.parse::<usize>() {
            if n > 20 {
                return n;
            }
        }
    }
    #[cfg(unix)]
    {
        use std::mem::MaybeUninit;
        #[repr(C)]
        struct Winsize {
            ws_row: u16,
            ws_col: u16,
            ws_xpixel: u16,
            ws_ypixel: u16,
        }
        extern "C" {
            fn ioctl(fd: i32, request: usize, ...) -> i32;
        }
        const TIOCGWINSZ: usize = 0x5413;
        let mut ws: MaybeUninit<Winsize> = MaybeUninit::zeroed();
        unsafe {
            if ioctl(1, TIOCGWINSZ, ws.as_mut_ptr()) == 0 {
                let ws = ws.assume_init();
                if ws.ws_col > 20 {
                    return ws.ws_col as usize;
                }
            }
        }
    }
    80
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct StubResolver(HashMap<String, String>);
    impl SessionNameResolver for StubResolver {
        fn resolve(&mut self, transcript_path: &str) -> Option<String> {
            self.0.get(transcript_path).cloned()
        }
    }

    fn opts_no_color() -> PrettyOpts {
        PrettyOpts {
            color: false,
            stats: false,
            follow: false,
            show: ShowMask(SHOW_DEFAULT),
            term_cols: 80,
        }
    }

    fn make_seen(cid: u64, session: &str, cwd: &str, tool: &str, body_field: &str, body: &str) -> String {
        let input_json = if tool == "Read" || tool == "Edit" || tool == "Write" {
            format!("{{\"file_path\":\"{body}\"}}")
        } else if tool == "Bash" {
            format!("{{\"command\":\"{body}\"}}")
        } else if tool == "Grep" {
            format!("{{\"pattern\":\"{body}\"}}")
        } else {
            "{}".to_string()
        };
        let (file_path, cmd) = match body_field {
            "file" => (body.to_string(), String::new()),
            "command" => (String::new(), body.to_string()),
            _ => (String::new(), String::new()),
        };
        format!(
            "{{\"hostname\":\"x\",\"message\":\"\",\"output_fields\":{{\"agent.cwd\":\"{cwd}\",\"agent.real_cwd\":\"{cwd}\",\"agent.session_id\":\"{session}\",\"agent.transcript_path\":\"\",\"correlation.id\":{cid},\"tool.file_path\":\"{file_path}\",\"tool.real_file_path\":\"{file_path}\",\"tool.input\":{input_json:?},\"tool.input_command\":\"{cmd}\",\"tool.name\":\"{tool}\"}},\"priority\":\"Debug\",\"rule\":\"Coding Agent Event Seen\",\"source\":\"coding_agent\",\"tags\":[\"coding_agent_seen\"],\"time\":\"2026-04-29T12:16:05.365824000Z\"}}"
        )
    }

    fn make_deny(cid: u64, rule: &str, message: &str, priority: &str) -> String {
        format!(
            "{{\"hostname\":\"x\",\"message\":\"{message}\",\"output_fields\":{{\"correlation.id\":{cid}}},\"priority\":\"{priority}\",\"rule\":\"{rule}\",\"source\":\"coding_agent\",\"tags\":[\"coding_agent_deny\"],\"time\":\"2026-04-29T12:16:13.000000000Z\"}}"
        )
    }

    fn make_ask(cid: u64, rule: &str, message: &str, priority: &str) -> String {
        format!(
            "{{\"hostname\":\"x\",\"message\":\"{message}\",\"output_fields\":{{\"correlation.id\":{cid}}},\"priority\":\"{priority}\",\"rule\":\"{rule}\",\"source\":\"coding_agent\",\"tags\":[\"coding_agent_ask\"],\"time\":\"2026-04-29T12:16:20.000000000Z\"}}"
        )
    }

    #[test]
    fn parses_show_default_and_aliases() {
        assert_eq!(ShowMask::parse("deny,ask,allow").unwrap().0, SHOW_DEFAULT);
        assert_eq!(ShowMask::parse("all").unwrap().0, SHOW_ALL);
        assert_eq!(ShowMask::parse("seen").unwrap().0, SHOW_SEEN);
        assert_eq!(ShowMask::parse("deny, ask").unwrap().0, SHOW_DENY | SHOW_ASK);
        assert!(ShowMask::parse("bogus").is_err());
    }

    #[test]
    fn allow_event_renders_after_seen() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let seen = make_seen(1, "abc123", "/home/u/proj", "Bash", "command", "ls -la");
        let out = f.process_line(&seen);
        let joined = out.join("\n");
        assert!(joined.contains("[abc123]"));
        assert!(joined.contains("●"));
        assert!(joined.contains("Bash(ls -la)"));
        assert!(joined.contains("~/proj"));
        let c = f.counters();
        assert_eq!(c.events, 1);
        assert_eq!(c.allow, 1);
        assert_eq!(c.deny, 0);
        assert_eq!(c.ask, 0);
        assert_eq!(c.sessions, 1);
    }

    #[test]
    fn deny_event_buffers_until_seen() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let deny1 = make_deny(7, "Deny dangerous", "Falco blocked rm -rf", "Critical");
        let out1 = f.process_line(&deny1);
        assert!(out1.is_empty(), "deny without seen should not render yet");
        let seen = make_seen(7, "abc", "/home/u/proj", "Bash", "command", "rm -rf /");
        let out2 = f.process_line(&seen);
        let joined = out2.join("\n");
        assert!(joined.contains("⊘"), "deny bullet expected: {joined}");
        assert!(joined.contains("Bash(rm -rf /)"));
        assert!(joined.contains("CRITICAL  Deny dangerous"));
        let c = f.counters();
        assert_eq!(c.deny, 1);
        assert_eq!(c.allow, 0);
        assert_eq!(c.events, 1);
    }

    #[test]
    fn multiple_deny_alerts_count_once() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        f.process_line(&make_deny(3, "Rule A", "msg", "Critical"));
        f.process_line(&make_deny(3, "Rule B", "msg", "Critical"));
        let out = f.process_line(&make_seen(3, "s", "/home/u", "Bash", "command", "x"));
        let joined = out.join("\n");
        assert!(joined.matches("⊘").count() >= 1);
        let detail_count = joined.matches("↳").count();
        assert_eq!(detail_count, 2, "two deny rules → two detail lines");
        assert_eq!(f.counters().deny, 1);
    }

    #[test]
    fn ask_event_renders_with_warning() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        f.process_line(&make_ask(11, "Sensitive write", "Falco asks", "Warning"));
        let out = f.process_line(&make_seen(11, "s", "/home/u", "Edit", "file", "/etc/passwd"));
        let joined = out.join("\n");
        assert!(joined.contains("⊙"));
        assert!(joined.contains("WARNING  Sensitive write"));
        assert!(joined.contains("Edit(/etc/passwd)"));
        assert_eq!(f.counters().ask, 1);
    }

    #[test]
    fn cwd_line_emits_only_on_change() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out1 = f.process_line(&make_seen(1, "s1", "/home/u/a", "Bash", "command", "x"));
        let out2 = f.process_line(&make_seen(2, "s1", "/home/u/a", "Bash", "command", "y"));
        let out3 = f.process_line(&make_seen(3, "s1", "/home/u/b", "Bash", "command", "z"));
        let joined1 = out1.join("\n");
        let joined2 = out2.join("\n");
        let joined3 = out3.join("\n");
        assert!(joined1.contains("▸ ~/a"), "first event has cwd: {joined1}");
        assert!(!joined2.contains("▸"), "same cwd → no cwd line: {joined2}");
        assert!(joined3.contains("▸ ~/b"), "cwd changed → emit: {joined3}");
    }

    #[test]
    fn new_session_emits_banner_and_cwd() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(1, "abc", "/home/u/proj", "Bash", "command", "ls"));
        let joined = out.join("\n");
        assert!(joined.contains("── abc"), "banner expected: {joined}");
        assert!(joined.contains("[abc]"), "label in event line: {joined}");
        assert!(joined.contains("▸ ~/proj"));
    }

    #[test]
    fn cwd_line_includes_time_and_label() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(1, "abc", "/home/u/proj", "Bash", "command", "ls"));
        let cwd_line = out
            .iter()
            .find(|l| l.contains("▸"))
            .expect("cwd line present");
        // time appears in the same line as ▸ and the [label].
        assert!(cwd_line.contains("[abc]"), "label on cwd line: {cwd_line}");
        assert!(cwd_line.contains("▸ ~/proj"), "path follows ▸: {cwd_line}");
        // The cwd line precedes the event line.
        let cwd_idx = out.iter().position(|l| l.contains("▸")).unwrap();
        let evt_idx = out.iter().position(|l| l.contains("●")).unwrap();
        assert!(cwd_idx < evt_idx);
    }

    #[test]
    fn short_session_id_truncates_long_ids() {
        assert_eq!(short_session_id("abc"), "abc");
        assert_eq!(short_session_id(""), "?");
        assert_eq!(short_session_id("twelve_chars"), "twelve_chars");
        assert_eq!(
            short_session_id("ea56c92a-4fb4-4e4c-827e-8571b6c1224b"),
            "ea56c92a"
        );
    }

    #[test]
    fn status_footer_layout() {
        let f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let footer = f.status_footer();
        assert_eq!(footer.len(), 3, "blank + rule + body");
        assert!(footer[0].is_empty());
        assert!(footer[1].contains("─"));
        let body = &footer[2];
        // Form: "coding-agents-kit: sessions N · events N (● allow N · ⊙ ask N · ⊘ deny N)"
        assert!(body.contains("coding-agents-kit:"), "tool prefix: {body}");
        assert!(body.contains("sessions "));
        assert!(body.contains("events "));
        assert!(body.contains("(● allow "));
        assert!(body.contains("⊙ ask "));
        assert!(body.contains("⊘ deny "));
        assert!(body.trim_end().ends_with(')'));
        let s_pos = body.find("sessions").unwrap();
        let e_pos = body.find("events").unwrap();
        let a_pos = body.find("allow").unwrap();
        let k_pos = body.find("ask").unwrap();
        let d_pos = body.find("deny").unwrap();
        assert!(s_pos < e_pos);
        assert!(e_pos < a_pos);
        assert!(a_pos < k_pos);
        assert!(k_pos < d_pos);
    }

    #[test]
    fn rename_emits_inline_banner_notice() {
        // First event: no title → no name in banner. Second event after a
        // /rename: resolver returns a title → notice line emitted.
        let mut resolver_map = HashMap::new();
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(resolver_map.clone()),
        );
        let _ = f.process_line(&make_seen(1, "abc", "/home/u", "Bash", "command", "ls"));
        // Inject the renamed title into the resolver and feed another event.
        resolver_map.insert(String::new(), "renamed".to_string());
        f.resolver = StubResolver(resolver_map);
        let out = f.process_line(&make_seen(2, "abc", "/home/u", "Bash", "command", "pwd"));
        let joined = out.join("\n");
        assert!(
            joined.contains("\"renamed\""),
            "rename notice expected in output: {joined}"
        );
    }

    #[test]
    fn clock_time_uses_evt_time_when_available() {
        // 1700000000 = 2023-11-14 22:13:20 UTC. Local will vary by tz; just
        // assert format HH:MM:SS.
        let v = serde_json::json!({
            "output_fields": {"evt.time": 1700000000_000_000_000u64},
            "time": "2023-11-14T22:13:20.000000000Z"
        });
        let s = clock_time_from_alert(&v);
        assert_eq!(s.len(), 8, "HH:MM:SS format: {s}");
        assert_eq!(s.as_bytes()[2], b':');
        assert_eq!(s.as_bytes()[5], b':');
    }

    #[test]
    fn seen_filtered_by_default() {
        // With default mask, allow events render, seen lines do not.
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(1, "s", "/home/u", "Bash", "command", "ls"));
        let joined = out.join("\n");
        // Must contain allow bullet exactly once (from the allow render),
        // not two (one allow + one seen).
        assert_eq!(joined.matches("●").count(), 1);
        assert!(!joined.contains("·  Bash"), "no seen audit line by default");
    }

    #[test]
    fn show_seen_renders_audit_line() {
        let mut opts = opts_no_color();
        opts.show = ShowMask(SHOW_SEEN);
        let mut f = Formatter::new(
            opts,
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(1, "s", "/home/u", "Bash", "command", "ls"));
        let joined = out.join("\n");
        assert!(!joined.contains("●"), "no allow bullet when SHOW_ALLOW unset");
        assert!(joined.contains("·"), "seen audit bullet expected");
        // Counter still increments.
        assert_eq!(f.counters().events, 1);
        assert_eq!(f.counters().allow, 1);
    }

    #[test]
    fn shorten_path_uses_tilde() {
        assert_eq!(shorten_path("/home/u/proj", "/home/u", 60), "~/proj");
        assert_eq!(shorten_path("/etc/passwd", "/home/u", 60), "/etc/passwd");
    }

    #[test]
    fn shorten_path_ellipsis_when_too_long() {
        let long = "/home/u/very/deep/nested/path/leaf";
        let out = shorten_path(long, "/home/u", 18);
        assert!(out.contains("…") || out.contains("..."), "out={out}");
        assert!(display_width(&out) <= 18 + 1);
    }

    #[test]
    fn render_tool_body_per_tool() {
        let f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let bash = serde_json::json!({"tool.name":"Bash","tool.input_command":"ls -la","tool.input":"{\"command\":\"ls -la\"}"});
        let read = serde_json::json!({"tool.name":"Read","tool.real_file_path":"/home/u/x.rs","tool.file_path":"/home/u/x.rs","tool.input":"{\"file_path\":\"/home/u/x.rs\"}"});
        let grep = serde_json::json!({"tool.name":"Grep","tool.input":"{\"pattern\":\"foo|bar\"}"});
        let webfetch = serde_json::json!({"tool.name":"WebFetch","tool.input":"{\"url\":\"https://example.com\"}"});
        let task = serde_json::json!({"tool.name":"Task","tool.input":"{\"description\":\"do thing\"}"});
        assert_eq!(f.render_tool_body(Some(&bash)), "Bash(ls -la)");
        assert_eq!(f.render_tool_body(Some(&read)), "Read(~/x.rs)");
        assert_eq!(f.render_tool_body(Some(&grep)), "Grep(foo|bar)");
        assert_eq!(f.render_tool_body(Some(&webfetch)), "WebFetch(https://example.com)");
        assert_eq!(f.render_tool_body(Some(&task)), "Task(do thing)");
    }

    #[test]
    fn render_tool_body_truncates_long_content() {
        let f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let cmd = "x".repeat(200);
        let raw = format!("{{\"tool.name\":\"Bash\",\"tool.input_command\":\"{cmd}\",\"tool.input\":\"{{}}\"}}");
        let v: Value = serde_json::from_str(&raw).unwrap();
        let body = f.render_tool_body(Some(&v));
        // Body width inside parens is bounded.
        assert!(body.ends_with("…)") || body.contains("…)"), "body={body}");
    }

    #[test]
    fn non_json_passes_through_dimmed() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line("Hook registered in /home/u/.claude/settings.json");
        assert_eq!(out, vec!["Hook registered in /home/u/.claude/settings.json".to_string()]);
    }

    #[test]
    fn condense_session_name_strips_newlines_and_truncates() {
        let s = "Line one\nLine two\twith tabs and a very long body that goes on and on and on and on";
        let out = condense_session_name(s);
        assert!(!out.contains('\n'));
        assert!(!out.contains('\t'));
        assert!(out.chars().count() <= 51);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn strip_ansi_removes_csi() {
        let s = "\x1b[31mred\x1b[0m";
        assert_eq!(strip_ansi(s), "red");
    }
}
