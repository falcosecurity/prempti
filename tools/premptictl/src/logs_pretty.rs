// Pretty renderer for `premptictl logs`.
//
// Buffers all alerts for a given correlation.id until the catch-all `seen`
// alert arrives, then renders one block per event. The seen alert carries
// every output_field, so we can produce a Tool(...) body even when the
// matching deny/ask rule's own output template references only a subset of
// fields.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
    /// Command-line label shown in the status footer
    /// (e.g. `premptictl logs -f`).
    pub cmd_label: String,
}

pub const SHOW_DENY: u8 = 1 << 0;
pub const SHOW_ASK: u8 = 1 << 1;
pub const SHOW_ALLOW: u8 = 1 << 2;
pub const SHOW_PASS: u8 = 1 << 3;
pub const SHOW_DEFAULT: u8 = SHOW_DENY | SHOW_ASK | SHOW_ALLOW | SHOW_PASS;
pub const SHOW_ALL: u8 = SHOW_DEFAULT;

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
                "pass" => SHOW_PASS,
                // `seen` is the protocol-level term for the catch-all
                // (rule file, tag, plugin config). Accepted as a quiet
                // alias for `pass` so existing scripts keep working.
                "seen" => SHOW_PASS,
                "all" => SHOW_ALL,
                "none" => 0,
                _ => return Err(format!("invalid --show value: {}", token)),
            };
        }
        Ok(ShowMask(mask))
    }

    /// Render the mask back to a comma-separated label like `deny,ask` so it
    /// can be echoed in the status footer's command line.
    pub fn label(self) -> String {
        if self.0 == SHOW_ALL {
            return "all".to_string();
        }
        if self.0 == 0 {
            return "none".to_string();
        }
        let mut parts = Vec::new();
        if self.contains(SHOW_DENY) {
            parts.push("deny");
        }
        if self.contains(SHOW_ASK) {
            parts.push("ask");
        }
        if self.contains(SHOW_ALLOW) {
            parts.push("allow");
        }
        if self.contains(SHOW_PASS) {
            parts.push("pass");
        }
        parts.join(",")
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

/// Flatten a multi-line tool input to a single line: replace control chars
/// with spaces, collapse runs of whitespace, and trim. Used for the inline
/// body of `Pass` events where the column layout requires a single line
/// per event.
fn flatten_inline(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if (c as u32) < 0x20 => ' ',
            c => c,
        })
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    let mut prev_space = false;
    for c in cleaned.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out.trim().to_string()
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
    /// Events that triggered only the catch-all rule — no specific rule
    /// fired. Rendered with `●`.
    pub pass: u64,
    /// Events where a rule fired but did not request deny/ask (matched-
    /// allow). Rendered with `◉`.
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
    /// A rule fired with no deny/ask tag — matched-allow. Rendered with
    /// the same full block (tool name + content + detail line) as
    /// `Deny`/`Ask` but with the `◉` green bullet.
    Allow,
    /// Only the catch-all `seen` rule fired — no specific rule had
    /// anything to say. Rendered as a single truncated line with `●`.
    Pass,
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

/// Metadata for re-rendering a banner at a different terminal width on
/// resize. The runner pairs these with their position in the most-recent
/// `process_line` output (see `Formatter::last_banner_meta`) and stores
/// them in the event buffer; on full repaint, banners are regenerated via
/// `Formatter::format_banner` so the trailing dashes track the live width
/// instead of replaying stale padding.
#[derive(Clone, Debug)]
pub struct BannerMeta {
    pub session_id: String,
    pub color_code: u8,
    pub name: Option<String>,
}

pub struct Formatter<R: SessionNameResolver> {
    opts: PrettyOpts,
    home: String,
    sessions: HashMap<String, SessionState>,
    last_session_id: Option<String>,
    last_emitted_cwd: Option<String>,
    in_flight: HashMap<u64, EventBuffer>,
    counters: Counters,
    /// Unix-ms timestamp of the first event we counted. Used to render
    /// `· since <date>` in the status footer.
    first_event_unix_ms: Option<u64>,
    resolver: R,
    /// `(line_index, BannerMeta)` pairs for banners emitted by the most
    /// recent `process_line` call. Indices are positions in the returned
    /// `Vec<String>`. The runner reads this side-channel to associate
    /// banner regeneration metadata with each buffered line — without it,
    /// repainting after a resize would replay the stale-width banner text.
    last_banner_meta: Vec<(usize, BannerMeta)>,
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
            first_event_unix_ms: None,
            resolver,
            last_banner_meta: Vec::new(),
        }
    }

    /// Banner metadata captured during the last `process_line` call.
    /// Empty when that call emitted no banner.
    pub fn last_banner_meta(&self) -> &[(usize, BannerMeta)] {
        &self.last_banner_meta
    }

    /// Render a banner at the current terminal width. Used on full repaint
    /// to regenerate buffered banners so their trailing dashes match the
    /// current viewport instead of replaying the width they were first
    /// written at.
    pub fn render_banner(&self, meta: &BannerMeta) -> String {
        self.format_banner(&meta.session_id, meta.color_code, meta.name.as_deref())
    }

    #[cfg(test)]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Process one input log line. Returns the lines (without trailing
    /// newlines) that should be written to the terminal as a result.
    /// Banner metadata for repaint is also captured into
    /// `self.last_banner_meta` — readable via [`Formatter::last_banner_meta`].
    pub fn process_line(&mut self, line: &str) -> Vec<String> {
        self.last_banner_meta.clear();
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
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
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
        entry.verdicts.push(VerdictAlert {
            kind,
            rule_name,
            priority,
        });
    }

    fn finalize(&mut self, cid: u64, seen: &Value) -> Vec<String> {
        let buf = self.in_flight.remove(&cid).unwrap_or_default();
        // Resolution: deny > ask > matched-allow (any non-deny/non-ask
        // alert) > pass (only the catch-all fired).
        let final_v = if buf.verdicts.iter().any(|x| x.kind == VerdictKind::Deny) {
            FinalVerdict::Deny
        } else if buf.verdicts.iter().any(|x| x.kind == VerdictKind::Ask) {
            FinalVerdict::Ask
        } else if buf.verdicts.iter().any(|x| x.kind == VerdictKind::Other) {
            FinalVerdict::Allow
        } else {
            FinalVerdict::Pass
        };

        self.counters.events += 1;
        match final_v {
            FinalVerdict::Pass => self.counters.pass += 1,
            FinalVerdict::Allow => self.counters.allow += 1,
            FinalVerdict::Ask => self.counters.ask += 1,
            FinalVerdict::Deny => self.counters.deny += 1,
        }
        if self.first_event_unix_ms.is_none() {
            self.first_event_unix_ms = event_unix_ms_from_alert(seen);
        }

        let render_verdict = match final_v {
            FinalVerdict::Deny => self.opts.show.contains(SHOW_DENY),
            FinalVerdict::Ask => self.opts.show.contains(SHOW_ASK),
            FinalVerdict::Allow => self.opts.show.contains(SHOW_ALLOW),
            FinalVerdict::Pass => self.opts.show.contains(SHOW_PASS),
        };
        if !render_verdict {
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
                SessionState {
                    color_code,
                    last_title: None,
                },
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
            self.last_banner_meta.push((
                out.len(),
                BannerMeta {
                    session_id: session_id.clone(),
                    color_code,
                    name: resolved_title.clone(),
                },
            ));
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
                self.last_banner_meta.push((
                    out.len(),
                    BannerMeta {
                        session_id: session_id.clone(),
                        color_code,
                        name: resolved_title.clone(),
                    },
                ));
                out.push(self.format_banner(&session_id, color_code, resolved_title.as_deref()));
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.last_title = resolved_title.clone();
                }
            }
        }

        let need_cwd_line = new_session || self.last_emitted_cwd.as_deref() != Some(cwd.as_str());
        if need_cwd_line && !cwd.is_empty() {
            out.push(self.format_cwd_line(&time_str, &session_id, color_code, &cwd));
            self.last_emitted_cwd = Some(cwd.clone());
        }

        let (event_lines, body_col) =
            self.format_event_line(&time_str, &session_id, color_code, final_v, fields);
        out.extend(event_lines);
        for va in buf.verdicts.iter() {
            let matches = matches!(
                (va.kind, final_v),
                (VerdictKind::Deny, FinalVerdict::Deny)
                    | (VerdictKind::Ask, FinalVerdict::Ask)
                    | (VerdictKind::Other, FinalVerdict::Allow)
            );
            if matches {
                out.push(self.format_detail_line(body_col, &va.priority, &va.rule_name));
            }
        }

        self.last_session_id = Some(session_id);
        out
    }

    fn format_banner(&self, session_id: &str, color_code: u8, name: Option<&str>) -> String {
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

    fn format_cwd_line(
        &self,
        time_str: &str,
        session_id: &str,
        color_code: u8,
        cwd: &str,
    ) -> String {
        let abbrev = shorten_path(cwd, &self.home, 60);
        let (label, _) = self.format_session_label(session_id, color_code);
        let arrow = self.paint("❯", ANSI_DIM);
        format!(
            "{time}  {label}  {arrow} {path}",
            time = self.paint(time_str, ANSI_DIM),
            label = label,
            arrow = arrow,
            path = self.paint(&abbrev, ANSI_DIM),
        )
    }

    /// Format the event lines and return the body column (1-indexed-ish:
    /// the visible width of the prefix `time + ws + label + ws + bullet +
    /// ws`). The caller uses that width as left padding for sub-lines so
    /// the rule name aligns under the tool name.
    ///
    /// For `Pass` verdicts the result is a single line with a truncated
    /// body, matching the streaming-friendly default. For `Allow`, `Ask`
    /// and `Deny` (i.e. any event where a specific rule fired) the tool
    /// name lands on the event line and the full untruncated content is
    /// emitted on subsequent lines, indented to the body column behind a
    /// dim `│` rule so the audit block stays visually distinct.
    fn format_event_line(
        &self,
        time_str: &str,
        session_id: &str,
        color_code: u8,
        verdict: FinalVerdict,
        fields: Option<&Value>,
    ) -> (Vec<String>, usize) {
        let bullet = self.paint(verdict_bullet(verdict), verdict_color(verdict));
        let (label, label_w) = self.format_session_label(session_id, color_code);
        let body_col = display_width(time_str) + 2 + label_w + 2 + 1 + 2;
        let prefix = format!(
            "{time}  {label}  {bullet}  ",
            time = self.paint(time_str, ANSI_DIM),
            label = label,
            bullet = bullet,
        );

        match verdict {
            FinalVerdict::Pass => {
                let body = self.render_tool_body(fields);
                (vec![format!("{prefix}{body}")], body_col)
            }
            FinalVerdict::Allow | FinalVerdict::Deny | FinalVerdict::Ask => {
                let tool = field_str(fields, "tool.name").unwrap_or_else(|| "?".to_string());
                let tool_styled = self.paint(&tool, ANSI_BOLD);
                let mut lines = vec![format!("{prefix}{tool_styled}")];
                let content = self.tool_full_content(&tool, fields);
                if !content.is_empty() {
                    let pad = " ".repeat(body_col);
                    let rule = self.paint("│", ANSI_DIM);
                    for content_line in content.lines() {
                        if content_line.is_empty() {
                            lines.push(format!("{pad}{rule}"));
                        } else {
                            lines.push(format!("{pad}{rule} {content_line}"));
                        }
                    }
                }
                (lines, body_col)
            }
        }
    }

    /// Sub-line under an event line. `body_col` is the visible column where
    /// the tool name starts; the arrow and rule text both land there so
    /// the sub-line reads cleanly under the event body.
    fn format_detail_line(&self, body_col: usize, priority: &str, rule_name: &str) -> String {
        let prio_token = priority.to_ascii_uppercase();
        let prio_color = match prio_token.as_str() {
            "CRITICAL" | "ERROR" | "EMERGENCY" | "ALERT" => ANSI_FG_RED,
            "WARNING" => ANSI_FG_YELLOW,
            _ => ANSI_DIM,
        };
        let prio = self.paint(&prio_token, prio_color);
        // `╰` shares the Box Drawing block with the continuation `│`, so
        // the two glyphs render with identical cell width and font
        // metrics. Plain arrows like `↳` (Arrows block) drift visually in
        // some fonts/terminals even when their reported display width is
        // the same.
        let arrow = self.paint("╰", ANSI_DIM);
        let pad = " ".repeat(body_col);
        format!("{pad}{arrow} {prio}  {rule_name}")
    }

    /// Build the per-line session label `[<short-id> · "<title…>"]`.
    /// Returns `(painted, visible_width)` so callers can compute the body
    /// column for sub-line alignment without re-stripping ANSI.
    fn format_session_label(&self, session_id: &str, color_code: u8) -> (String, usize) {
        const TITLE_MAX_CHARS: usize = 24;
        // '[' + 8-char sid + ']' + ' ' + (24 + '…') = 36 chars.
        // Pad shorter labels to this width so per-line columns align across sessions.
        const LABEL_TARGET_WIDTH: usize = 36;
        let sid = short_session_id(session_id);
        let title = self
            .sessions
            .get(session_id)
            .and_then(|s| s.last_title.as_deref())
            .filter(|t| !t.is_empty());

        let id_part = format!("[{sid}]");
        let id_painted = self.paint(&id_part, &session_color_code(color_code));

        let mut title_part = String::new();
        if let Some(t) = title {
            let total = t.chars().count();
            title_part.push(' ');
            if total > TITLE_MAX_CHARS {
                title_part.push_str(&take_chars(t, TITLE_MAX_CHARS));
                title_part.push('…');
            } else {
                title_part.push_str(t);
            }
        }
        let title_painted = if title_part.is_empty() {
            String::new()
        } else {
            self.paint(&title_part, ANSI_DIM)
        };

        let visible_width = id_part.chars().count() + title_part.chars().count();
        let pad_n = LABEL_TARGET_WIDTH.saturating_sub(visible_width);
        let final_width = visible_width + pad_n;
        let pad = " ".repeat(pad_n);

        (format!("{id_painted}{title_painted}{pad}"), final_width)
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
        truncate_for_display(&flatten_inline(&raw), max)
    }

    /// Same content sources as [`Self::tool_body_content`], but without
    /// length truncation. Path tools still get the home-directory tilde
    /// substitution applied for readability.
    fn tool_full_content(&self, tool: &str, fields: Option<&Value>) -> String {
        match tool {
            "Bash" => field_str(fields, "tool.input_command")
                .or_else(|| input_value_string(fields, "command"))
                .unwrap_or_default(),
            "Read" | "Edit" | "Write" => {
                let p = field_str(fields, "tool.real_file_path")
                    .filter(|s| !s.is_empty())
                    .or_else(|| field_str(fields, "tool.file_path"))
                    .or_else(|| input_value_string(fields, "file_path"))
                    .unwrap_or_default();
                shorten_path(&p, &self.home, usize::MAX)
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
        }
    }

    /// Footer shown at the bottom of the output: blank line, grey rule, and
    /// the counters in grey with verdict bullets in their colors. Three
    /// lines, no trailing newline on the last one (the runner appends it).
    ///
    /// The rule spans the full terminal width. The runner re-detects the
    /// terminal size before each redraw and a watcher thread refreshes the
    /// footer when the window is resized between events, so the rule always
    /// matches the current viewport.
    pub fn status_footer(&self) -> Vec<String> {
        let term = self.opts.term_cols.max(40);
        let blank = String::new();
        let rule = self.paint(&"─".repeat(term), ANSI_GREY);
        let body = self.format_status_body();
        vec![blank, rule, body]
    }

    /// Update the cached terminal width used by the next render. Invoked
    /// from the runner before each redraw so the banner padding and footer
    /// rule track the live viewport instead of the size captured at startup.
    pub fn set_term_cols(&mut self, cols: usize) {
        self.opts.term_cols = cols;
    }

    fn format_status_body(&self) -> String {
        let c = self.counters;
        let cmd = self.opts.cmd_label.as_str();
        let since_suffix = self
            .first_event_unix_ms
            .and_then(|ms| format_since(ms))
            .map(|s| format!(" · since {s}"))
            .unwrap_or_default();
        if !self.opts.color {
            return format!(
                " {cmd}: sessions {} · events {} (● pass {} · ◉ allow {} · ⊙ ask {} · ⊘ deny {}){since_suffix}",
                c.sessions, c.events, c.pass, c.allow, c.ask, c.deny
            );
        }
        // Resume grey after each colored bullet so the row stays in the
        // same tone as the rule line above it.
        format!(
            "{grey} {cmd}: sessions {sessions} · events {events} ({green}●{grey} pass {pass} · {green}◉{grey} allow {allow} · {yellow}⊙{grey} ask {ask} · {red}⊘{grey} deny {deny}){since_suffix}{reset}",
            grey = ANSI_GREY,
            cmd = cmd,
            sessions = c.sessions,
            events = c.events,
            green = ANSI_FG_GREEN,
            pass = c.pass,
            allow = c.allow,
            yellow = ANSI_FG_YELLOW,
            ask = c.ask,
            red = ANSI_FG_RED,
            deny = c.deny,
            since_suffix = since_suffix,
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

/// Number of visual rows reserved for the status footer at the bottom of
/// the screen: a blank spacer, the rule, and the body line.
pub const FOOTER_LINES: usize = 3;

/// Polling interval for the resize watcher. Short enough that resizes feel
/// "live" without burning measurable CPU when idle.
const RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Bottom row (1-indexed, inclusive) of the events scrolling region — i.e.
/// the row that a `writeln!` will print into and trigger a scroll from.
/// Always at least 1 so even degenerate "smaller than the footer" terminals
/// produce a valid `ESC[1;Nr` setup.
fn events_region_bottom(rows: usize) -> usize {
    rows.saturating_sub(FOOTER_LINES).max(1)
}

/// First (top) row of the footer area — i.e. where the footer's blank
/// spacer line lives. Anchored to the bottom: `rows - FOOTER_LINES + 1`.
fn footer_top_row(rows: usize) -> usize {
    rows.saturating_sub(FOOTER_LINES - 1).max(1)
}

/// Reset the scrolling region to the whole screen and park the cursor at
/// the bottom — used at exit so the user's shell prompt appears below the
/// footer instead of overwriting it.
fn leave_split_layout<W: Write>(writer: &mut W, rows: usize) -> io::Result<()> {
    write!(writer, "\x1b[r")?;
    write!(writer, "\x1b[{};1H", rows.max(1))?;
    Ok(())
}

/// Render the footer at the absolute bottom of the screen. Erases the entire
/// footer area first (clear-to-end-of-screen from the footer's top row), so
/// any leftovers from a previous render at a different size are wiped.
/// Autowrap is disabled while writing so each line is exactly one visual row.
/// On return, the cursor is parked at the bottom of the events scrolling
/// region — ready for the next event-line writeln to scroll naturally.
fn render_footer_at_bottom<W: Write>(
    writer: &mut W,
    footer: &[String],
    rows: usize,
) -> io::Result<()> {
    let top = footer_top_row(rows);
    write!(writer, "\x1b[{};1H", top)?;
    write!(writer, "\x1b[J")?;
    write!(writer, "\x1b[?7l")?;
    let last = footer.len().saturating_sub(1);
    for (i, line) in footer.iter().enumerate() {
        if i == last {
            write!(writer, "{line}")?;
        } else {
            writeln!(writer, "{line}")?;
        }
    }
    write!(writer, "\x1b[?7h")?;
    let bottom = events_region_bottom(rows);
    write!(writer, "\x1b[{};1H", bottom)?;
    Ok(())
}

/// One line of buffered event output. `Plain` is written verbatim;
/// `Banner` is regenerated against the live `term_cols` on full repaint
/// so the trailing dashes track the current viewport.
#[derive(Clone)]
enum BufferedLine {
    Plain(String),
    Banner(BannerMeta),
}

/// Maximum number of recent display lines retained for repaint. Sized to
/// comfortably exceed any reasonable `events_region_bottom`, so the visible
/// portion of the screen can always be reconstructed from buffer alone.
const EVENT_BUFFER_CAPACITY: usize = 1024;

/// State shared between the main read loop and the resize watcher.
/// Both grab the `Mutex` first, then acquire stdout — keeping the lock
/// order consistent prevents deadlocks against `println!` and friends.
struct SharedState<RS: SessionNameResolver> {
    formatter: Formatter<RS>,
    /// True once any output has been emitted, i.e. the screen has state
    /// the watcher might need to refresh.
    status_drawn: bool,
    /// `(cols, rows)` the layout was last rendered against. `None` until
    /// the first render; the watcher uses this to decide whether a full
    /// repaint is needed.
    footer_size: Option<(usize, usize)>,
    /// Ring buffer of recent display lines (post-formatter). Used to
    /// repaint the events region from scratch on resize so reflowed
    /// orphans from the previous terminal layout don't accumulate.
    event_buffer: VecDeque<BufferedLine>,
}

impl<RS: SessionNameResolver> SharedState<RS> {
    /// Append the lines emitted by a single `process_line` call to the
    /// buffer, attaching banner regeneration metadata to the lines that
    /// `Formatter` flagged as banners. Caps at `EVENT_BUFFER_CAPACITY`.
    fn record_lines(&mut self, lines: &[String]) {
        let banners: HashMap<usize, BannerMeta> = self
            .formatter
            .last_banner_meta()
            .iter()
            .cloned()
            .collect();
        for (i, line) in lines.iter().enumerate() {
            let entry = match banners.get(&i) {
                Some(meta) => BufferedLine::Banner(meta.clone()),
                None => BufferedLine::Plain(line.clone()),
            };
            self.event_buffer.push_back(entry);
        }
        while self.event_buffer.len() > EVENT_BUFFER_CAPACITY {
            self.event_buffer.pop_front();
        }
    }

    /// Render a single buffered line at the current terminal width.
    /// Banners are regenerated; plain lines are written verbatim.
    fn render_buffered(&self, line: &BufferedLine) -> String {
        match line {
            BufferedLine::Plain(s) => s.clone(),
            BufferedLine::Banner(meta) => self.formatter.render_banner(meta),
        }
    }

    /// Full screen repaint: clear, set scroll region, redraw the most
    /// recent events that fit in the events region, then render the footer
    /// at the bottom. Used on resize and on the very first render — the
    /// only time we're guaranteed clean state. Banners are regenerated
    /// here (via `render_buffered`) at the live `cols` so resize never
    /// leaves stretched-padding banners behind.
    fn full_repaint<W: Write>(
        &mut self,
        writer: &mut W,
        cols: usize,
        rows: usize,
    ) -> io::Result<()> {
        self.formatter.set_term_cols(cols);
        // Clear the whole screen and reset the scroll region — this is the
        // big hammer that wipes anything reflowed by the terminal during a
        // resize, including content that drifted out of the footer area.
        write!(writer, "\x1b[2J")?;
        let region_bottom = events_region_bottom(rows);
        write!(writer, "\x1b[1;{}r", region_bottom)?;
        // Render the most recent N events, anchored to the bottom of the
        // events region so the latest line sits just above the footer.
        let n = self.event_buffer.len().min(region_bottom);
        if n > 0 {
            let start_row = region_bottom - n + 1;
            write!(writer, "\x1b[{};1H", start_row)?;
            // Autowrap off while we lay events down: each buffered line is
            // exactly one visual row, so events stack predictably and the
            // events_region_bottom math stays accurate even for lines wider
            // than the current width.
            write!(writer, "\x1b[?7l")?;
            let start_idx = self.event_buffer.len() - n;
            for (i, entry) in self.event_buffer.iter().enumerate().skip(start_idx) {
                let rendered = self.render_buffered(entry);
                if i + 1 == self.event_buffer.len() {
                    write!(writer, "{rendered}")?;
                } else {
                    writeln!(writer, "{rendered}")?;
                }
            }
            write!(writer, "\x1b[?7h")?;
        }
        render_footer_at_bottom(writer, &self.formatter.status_footer(), rows)?;
        writer.flush()?;
        self.footer_size = Some((cols, rows));
        self.status_drawn = true;
        Ok(())
    }
}

pub fn run<RD, RS>(reader: RD, opts: PrettyOpts, resolver: RS) -> io::Result<()>
where
    RD: BufRead,
    RS: SessionNameResolver + Send + 'static,
{
    let with_status = opts.stats && opts.follow && opts.color;
    let final_summary = opts.stats && !opts.follow;
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let formatter = Formatter::new(opts, home, resolver);
    let state = Arc::new(Mutex::new(SharedState {
        formatter,
        status_drawn: false,
        footer_size: None,
        event_buffer: VecDeque::new(),
    }));

    if with_status {
        let (cols, rows) = detect_term_size();
        let mut s = state.lock().expect("render state poisoned");
        let stdout = io::stdout();
        let mut out = stdout.lock();
        // First render goes through full_repaint too — this gives us a
        // single code path for "set up the layout from scratch" which the
        // resize watcher reuses on every size change.
        s.full_repaint(&mut out, cols, rows)?;
    }

    // Watcher only matters when a footer is being maintained. Snapshot
    // mode (no `with_status`) renders once and exits — no resize to chase.
    let stop = Arc::new(AtomicBool::new(false));
    let watcher_handle = if with_status {
        let state_w = Arc::clone(&state);
        let stop_w = Arc::clone(&stop);
        Some(thread::spawn(move || resize_watcher(state_w, stop_w)))
    } else {
        None
    };

    let mut deferred: io::Result<()> = Ok(());
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                deferred = Err(e);
                break;
            }
        };
        let (cols, rows) = detect_term_size();
        let mut s = state.lock().expect("render state poisoned");
        s.formatter.set_term_cols(cols);
        let display = s.formatter.process_line(&line);
        if display.is_empty() {
            continue;
        }
        // Buffer regardless of mode so the watcher always has fresh data
        // to repaint from. Cheap (a clone per line, capped at 1024).
        s.record_lines(&display);
        let stdout = io::stdout();
        let mut out = stdout.lock();
        if with_status {
            // If the terminal resized since the last render, do a clean
            // full repaint — the cheaper incremental path can leak
            // orphans from reflowed previous content (the bug we're
            // fixing). Otherwise, append the new lines incrementally.
            if s.footer_size != Some((cols, rows)) {
                s.full_repaint(&mut out, cols, rows)?;
            } else {
                let bottom = events_region_bottom(rows);
                write!(out, "\x1b[{};1H", bottom)?;
                for dl in display {
                    // `\n` at the bottom of the scroll region scrolls the
                    // events area by one row per line — the only place
                    // we still rely on terminal-managed scrolling, and
                    // it's safe because the region is well-defined and
                    // has just been confirmed unchanged from last render.
                    write!(out, "{dl}\n")?;
                }
                render_footer_at_bottom(&mut out, &s.formatter.status_footer(), rows)?;
                out.flush()?;
                s.status_drawn = true;
            }
        } else {
            for dl in display {
                writeln!(out, "{dl}")?;
            }
        }
    }

    // Stop the watcher before tearing down the layout so it can't race the
    // final reset.
    stop.store(true, Ordering::SeqCst);
    if let Some(h) = watcher_handle {
        let _ = h.join();
    }

    let s = state.lock().expect("render state poisoned");
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if with_status && s.status_drawn {
        let rows = s.footer_size.map(|(_, r)| r).unwrap_or_else(|| detect_term_size().1);
        leave_split_layout(&mut out, rows)?;
        writeln!(out)?;
    } else if final_summary {
        writeln!(out, "{}", s.formatter.summary())?;
    }
    out.flush()?;
    deferred
}

fn resize_watcher<RS: SessionNameResolver>(
    state: Arc<Mutex<SharedState<RS>>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        thread::sleep(RESIZE_POLL_INTERVAL);
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let (cols, rows) = detect_term_size();
        let mut s = match state.lock() {
            Ok(g) => g,
            Err(_) => break, // poisoned — main thread crashed; bail out.
        };
        // Skip if nothing's been drawn yet, or if we already redrew at
        // this size on the last main-thread render.
        if !s.status_drawn || s.footer_size == Some((cols, rows)) {
            continue;
        }
        let stdout = io::stdout();
        let mut out = stdout.lock();
        // Drop write errors silently — the main loop will surface its own.
        let _ = s.full_repaint(&mut out, cols, rows);
    }
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
    middle_ellipsis(&with_tilde, max)
}

/// Drop characters from the middle of a string, keeping as much of both
/// ends as possible. Used to truncate long paths so the user sees the
/// leading prefix (`~/code/github.com/...`) AND the basename, not just the
/// first and last path segments.
fn middle_ellipsis(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return "…".to_string();
    }
    let keep = max - 1; // 1 char for the ellipsis itself
                        // Bias the right side slightly larger so the basename / suffix stays
                        // visible — that's where readers look first.
    let right_keep = keep / 2 + keep % 2;
    let left_keep = keep - right_keep;
    let chars: Vec<char> = s.chars().collect();
    let left: String = chars.iter().take(left_keep).collect();
    let right: String = chars.iter().skip(count - right_keep).collect();
    format!("{left}…{right}")
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

struct LocalTime {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

fn epoch_to_local_hms(secs: i64) -> Option<(u32, u32, u32)> {
    epoch_to_local(secs).map(|t| (t.hour, t.minute, t.second))
}

#[cfg(unix)]
fn epoch_to_local(secs: i64) -> Option<LocalTime> {
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
    Some(LocalTime {
        year: tm.tm_year + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
        second: tm.tm_sec as u32,
    })
}

#[cfg(windows)]
fn epoch_to_local(secs: i64) -> Option<LocalTime> {
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
    Some(LocalTime {
        year: tm.tm_year + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
        second: tm.tm_sec as u32,
    })
}

/// Pull the `evt.time` (epoch nanoseconds) out of an alert and convert to
/// unix milliseconds. Returns `None` when the field is missing/invalid;
/// callers fall back to omitting `since` from the status line.
fn event_unix_ms_from_alert(alert: &Value) -> Option<u64> {
    alert
        .get("output_fields")
        .and_then(|of| of.get("evt.time"))
        .and_then(|t| t.as_u64())
        .map(|ns| ns / 1_000_000)
}

/// Render a unix-ms timestamp as `YYYY-MM-DD HH:MM:SS` in local time, or
/// `None` if libc localtime fails.
fn format_since(unix_ms: u64) -> Option<String> {
    let secs = (unix_ms / 1000) as i64;
    epoch_to_local(secs).map(|t| {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        )
    })
}

fn pick_session_color(session_id: &str) -> u8 {
    // Curated 256-color palette: skip red/green/yellow used for verdicts.
    // Spread across blue → cyan → purple → magenta → pink for visual variety.
    const PALETTE: [u8; 12] = [27, 33, 39, 45, 51, 87, 99, 135, 141, 165, 177, 213];
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
        FinalVerdict::Pass => "●",
        FinalVerdict::Allow => "◉",
        FinalVerdict::Ask => "⊙",
        FinalVerdict::Deny => "⊘",
    }
}

fn verdict_color(v: FinalVerdict) -> &'static str {
    match v {
        FinalVerdict::Pass => ANSI_FG_GREEN,
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
    detect_term_size().0
}

/// Best-effort `(cols, rows)` for the controlling terminal. Falls back to
/// `(80, 24)` when detection fails (e.g. piped output, container with no
/// real TTY, or a platform we don't have a probe for).
///
/// Used by the live `logs -f` renderer to position the footer at an absolute
/// bottom-of-screen row and to size the DEC scrolling region above it. The
/// hand-rolled `TIOCGWINSZ = 0x5413` constant that previously lived here
/// worked on Linux but failed silently on macOS (real value `0x40087468`),
/// collapsing the width to 80 — which is why the rule used to "stop in the
/// middle of nowhere" on macOS terminals.
pub fn detect_term_size() -> (usize, usize) {
    let mut cols: Option<usize> = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n: &usize| *n > 20);
    let mut rows: Option<usize> = std::env::var("LINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n: &usize| *n > FOOTER_LINES);

    #[cfg(unix)]
    {
        if cols.is_none() || rows.is_none() {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            let r = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
            if r == 0 {
                if cols.is_none() && ws.ws_col > 20 {
                    cols = Some(ws.ws_col as usize);
                }
                if rows.is_none() && ws.ws_row > FOOTER_LINES as u16 {
                    rows = Some(ws.ws_row as usize);
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if cols.is_none() || rows.is_none() {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::Console::{
                GetConsoleScreenBufferInfo, CONSOLE_SCREEN_BUFFER_INFO,
            };
            let h = std::io::stdout().as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
            let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
            if unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0 {
                // srWindow is the visible viewport — Right/Bottom are
                // inclusive, so width = Right - Left + 1, height likewise.
                if cols.is_none() {
                    let c = info.srWindow.Right as i32 - info.srWindow.Left as i32 + 1;
                    if c > 20 {
                        cols = Some(c as usize);
                    }
                }
                if rows.is_none() {
                    let r = info.srWindow.Bottom as i32 - info.srWindow.Top as i32 + 1;
                    if r > FOOTER_LINES as i32 {
                        rows = Some(r as usize);
                    }
                }
            }
        }
    }
    (cols.unwrap_or(80), rows.unwrap_or(24))
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
            cmd_label: "premptictl".to_string(),
        }
    }

    fn make_seen(
        cid: u64,
        session: &str,
        cwd: &str,
        tool: &str,
        body_field: &str,
        body: &str,
    ) -> String {
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
        // evt.time matches the ISO `time` field below — real Falco alerts
        // always include both, and the formatter's `since` line depends on
        // evt.time being present in output_fields.
        format!(
            "{{\"hostname\":\"x\",\"message\":\"\",\"output_fields\":{{\"agent.cwd\":\"{cwd}\",\"agent.real_cwd\":\"{cwd}\",\"agent.session_id\":\"{session}\",\"agent.transcript_path\":\"\",\"correlation.id\":{cid},\"evt.time\":1777000000000000000,\"tool.file_path\":\"{file_path}\",\"tool.real_file_path\":\"{file_path}\",\"tool.input\":{input_json:?},\"tool.input_command\":\"{cmd}\",\"tool.name\":\"{tool}\"}},\"priority\":\"Debug\",\"rule\":\"Coding Agent Event Seen\",\"source\":\"coding_agent\",\"tags\":[\"coding_agent_seen\"],\"time\":\"2026-04-29T12:16:05.365824000Z\"}}"
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

    /// A rule that fired but carries neither the deny nor the ask tag —
    /// the matched-allow case (`◉`).
    fn make_other(cid: u64, rule: &str, message: &str, priority: &str) -> String {
        format!(
            "{{\"hostname\":\"x\",\"message\":\"{message}\",\"output_fields\":{{\"correlation.id\":{cid}}},\"priority\":\"{priority}\",\"rule\":\"{rule}\",\"source\":\"coding_agent\",\"tags\":[],\"time\":\"2026-04-29T12:16:25.000000000Z\"}}"
        )
    }

    #[test]
    fn parses_show_default_and_aliases() {
        assert_eq!(
            ShowMask::parse("deny,ask,allow,pass").unwrap().0,
            SHOW_DEFAULT
        );
        assert_eq!(ShowMask::parse("all").unwrap().0, SHOW_ALL);
        // `seen` is a backward-compat alias for `pass` (the user-facing
        // category label), since the protocol-level term is `seen` but the
        // log category renamed to `pass`.
        assert_eq!(ShowMask::parse("seen").unwrap().0, SHOW_PASS);
        assert_eq!(ShowMask::parse("pass").unwrap().0, SHOW_PASS);
        assert_eq!(
            ShowMask::parse("deny, ask").unwrap().0,
            SHOW_DENY | SHOW_ASK
        );
        assert!(ShowMask::parse("bogus").is_err());
    }

    #[test]
    fn pass_event_renders_after_seen() {
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
        assert!(!joined.contains("◉"), "pass must not use the allow bullet: {joined}");
        assert!(joined.contains("Bash(ls -la)"));
        assert!(joined.contains("~/proj"));
        let c = f.counters();
        assert_eq!(c.events, 1);
        assert_eq!(c.pass, 1);
        assert_eq!(c.allow, 0);
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
        assert!(joined.contains("Bash"), "tool name on event line: {joined}");
        assert!(
            joined.contains("│ rm -rf /"),
            "command on continuation line: {joined}"
        );
        assert!(joined.contains("CRITICAL  Deny dangerous"));
        let c = f.counters();
        assert_eq!(c.deny, 1);
        assert_eq!(c.pass, 0);
        assert_eq!(c.allow, 0);
        assert_eq!(c.events, 1);
    }

    #[test]
    fn matched_allow_event_renders_with_circled_bullet() {
        // A rule with no deny/ask tag fires for the event. The verdict is
        // matched-allow: ◉ green bullet, full block (bold tool name +
        // continuation lines + ╰ rule detail line).
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let other = make_other(
            5,
            "Monitor activity outside working directory",
            "Falco detected access outside cwd",
            "Notice",
        );
        let out_pre = f.process_line(&other);
        assert!(
            out_pre.is_empty(),
            "non-seen alert must not render before seen"
        );
        let seen = make_seen(5, "abc", "/home/u/proj", "Read", "file", "/etc/hosts");
        let out = f.process_line(&seen);
        let joined = out.join("\n");
        assert!(joined.contains("◉"), "matched-allow bullet expected: {joined}");
        assert!(!joined.contains("●"), "must not use the pass bullet: {joined}");
        assert!(joined.contains("Read"), "tool name on event line: {joined}");
        assert!(
            joined.contains("│ /etc/hosts"),
            "path on continuation line: {joined}"
        );
        assert!(
            joined.contains("NOTICE  Monitor activity outside working directory"),
            "rule name on detail line: {joined}"
        );
        let c = f.counters();
        assert_eq!(c.events, 1);
        assert_eq!(c.allow, 1);
        assert_eq!(c.pass, 0);
        assert_eq!(c.deny, 0);
        assert_eq!(c.ask, 0);
    }

    #[test]
    fn deny_wins_over_other() {
        // When a deny rule and a non-deny/non-ask rule both match the
        // same event, the final verdict is deny and only the deny detail
        // line shows up (the other rule's detail is suppressed because
        // its kind doesn't match the final verdict).
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        f.process_line(&make_other(9, "Audit something", "noted", "Notice"));
        f.process_line(&make_deny(9, "Deny dangerous", "blocked", "Critical"));
        let out = f.process_line(&make_seen(9, "s", "/home/u", "Bash", "command", "x"));
        let joined = out.join("\n");
        assert!(joined.contains("⊘"), "deny bullet: {joined}");
        assert!(!joined.contains("◉"), "no allow bullet: {joined}");
        assert!(joined.contains("CRITICAL  Deny dangerous"));
        assert!(
            !joined.contains("Audit something"),
            "matched-allow detail must be hidden on deny: {joined}"
        );
        let c = f.counters();
        assert_eq!(c.deny, 1);
        assert_eq!(c.allow, 0);
        assert_eq!(c.pass, 0);
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
        let detail_count = joined.matches("╰").count();
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
        let out = f.process_line(&make_seen(
            11,
            "s",
            "/home/u",
            "Edit",
            "file",
            "/etc/passwd",
        ));
        let joined = out.join("\n");
        assert!(joined.contains("⊙"));
        assert!(joined.contains("WARNING  Sensitive write"));
        assert!(joined.contains("Edit"), "tool name on event line: {joined}");
        assert!(
            joined.contains("│ /etc/passwd"),
            "path on continuation line: {joined}"
        );
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
        assert!(joined1.contains("❯ ~/a"), "first event has cwd: {joined1}");
        assert!(!joined2.contains("❯"), "same cwd → no cwd line: {joined2}");
        assert!(joined3.contains("❯ ~/b"), "cwd changed → emit: {joined3}");
    }

    #[test]
    fn new_session_emits_banner_and_cwd() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(
            1,
            "abc",
            "/home/u/proj",
            "Bash",
            "command",
            "ls",
        ));
        let joined = out.join("\n");
        assert!(joined.contains("── abc"), "banner expected: {joined}");
        assert!(joined.contains("[abc]"), "label in event line: {joined}");
        assert!(joined.contains("❯ ~/proj"));
    }

    #[test]
    fn cwd_line_includes_time_and_label() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(
            1,
            "abc",
            "/home/u/proj",
            "Bash",
            "command",
            "ls",
        ));
        let cwd_line = out
            .iter()
            .find(|l| l.contains("❯"))
            .expect("cwd line present");
        // time appears in the same line as ❯ and the [label].
        assert!(cwd_line.contains("[abc]"), "label on cwd line: {cwd_line}");
        assert!(cwd_line.contains("❯ ~/proj"), "path follows ❯: {cwd_line}");
        // The cwd line precedes the event line.
        let cwd_idx = out.iter().position(|l| l.contains("❯")).unwrap();
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
        // Form: "premptictl: sessions N · events N (● pass N · ◉ allow N · ⊙ ask N · ⊘ deny N)"
        assert!(body.contains("premptictl:"), "tool prefix: {body}");
        assert!(body.contains("sessions "));
        assert!(body.contains("events "));
        assert!(body.contains("(● pass "));
        assert!(body.contains("◉ allow "));
        assert!(body.contains("⊙ ask "));
        assert!(body.contains("⊘ deny "));
        assert!(body.trim_end().ends_with(')'));
        let s_pos = body.find("sessions").unwrap();
        let e_pos = body.find("events").unwrap();
        let p_pos = body.find("pass").unwrap();
        let a_pos = body.find("allow").unwrap();
        let k_pos = body.find("ask").unwrap();
        let d_pos = body.find("deny").unwrap();
        assert!(s_pos < e_pos);
        assert!(e_pos < p_pos);
        assert!(p_pos < a_pos);
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
    fn pass_rendered_by_default() {
        // With default mask, pass events render with the green ● bullet.
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(1, "s", "/home/u", "Bash", "command", "ls"));
        let joined = out.join("\n");
        // Exactly one bullet — the pass render. There is no separate
        // dim audit line in the new design.
        assert_eq!(joined.matches("●").count(), 1);
    }

    #[test]
    fn pass_filtered_when_pass_bit_unset() {
        // With pass off (only deny/ask/allow shown), a catch-all-only
        // event produces no output but still counts.
        let mut opts = opts_no_color();
        opts.show = ShowMask(SHOW_DENY | SHOW_ASK | SHOW_ALLOW);
        let mut f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let out = f.process_line(&make_seen(1, "s", "/home/u", "Bash", "command", "ls"));
        assert!(out.is_empty(), "no rendering when pass is suppressed");
        assert_eq!(f.counters().events, 1);
        assert_eq!(f.counters().pass, 1);
    }

    #[test]
    fn seen_token_is_alias_for_pass() {
        // `--show seen` keeps working as an alias for `--show pass`.
        let mut opts = opts_no_color();
        opts.show = ShowMask::parse("seen").unwrap();
        let mut f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let out = f.process_line(&make_seen(1, "s", "/home/u", "Bash", "command", "ls"));
        let joined = out.join("\n");
        assert!(joined.contains("●"), "pass bullet expected via seen alias: {joined}");
        assert_eq!(f.counters().pass, 1);
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
        assert!(out.contains("…"), "out={out}");
        assert!(!out.contains("..."), "must use single-char ellipsis: {out}");
        assert!(display_width(&out) <= 18 + 1);
    }

    #[test]
    fn shorten_path_keeps_more_than_first_and_last_segment() {
        // The pre-supervisor truncation collapsed everything to
        // `~/.../basename`; the new middle-ellipsis should retain meaningful
        // context from the leading prefix as well.
        let long = "/home/u/code/github.com/org/repo/src/sub/file.rs";
        let out = shorten_path(long, "/home/u", 30);
        assert!(out.contains("…"), "out={out}");
        assert!(out.starts_with("~/code"), "prefix lost: {out}");
        assert!(out.ends_with("file.rs"), "basename lost: {out}");
    }

    #[test]
    fn middle_ellipsis_balances_both_ends() {
        let s = "abcdefghijklmnopqrstuvwxyz";
        let out = middle_ellipsis(s, 9);
        assert!(out.starts_with("abcd"), "left side too short: {out}");
        assert!(out.ends_with("xyz"), "right side too short: {out}");
        assert!(out.contains('…'));
    }

    #[test]
    fn label_includes_title_when_known() {
        let mut resolver = HashMap::new();
        resolver.insert(
            "/home/u/.claude/projects/x/abc.jsonl".to_string(),
            "prettify ctl".to_string(),
        );
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(resolver),
        );
        // 8-char session_id so short_session_id() returns it verbatim, and
        // the assertion below can match the full label.
        let raw = format!(
            "{{\"source\":\"coding_agent\",\"tags\":[\"coding_agent_seen\"],\
             \"rule\":\"Coding Agent Event Seen\",\"priority\":\"Debug\",\
             \"output_fields\":{{\"correlation.id\":1,\
             \"agent.session_id\":\"ea56c92a\",\
             \"agent.cwd\":\"/home/u\",\"agent.real_cwd\":\"/home/u\",\
             \"agent.transcript_path\":\"/home/u/.claude/projects/x/abc.jsonl\",\
             \"tool.name\":\"Bash\",\"tool.input_command\":\"ls\",\
             \"tool.input\":\"{{}}\",\"evt.time\":1777000000000000000}},\
             \"time\":\"2026-04-29T12:16:05.000000000Z\"}}"
        );
        let out = f.process_line(&raw);
        let joined = out.join("\n");
        assert!(
            joined.contains("[ea56c92a] prettify ctl"),
            "label missing title: {joined}"
        );
    }

    #[test]
    fn label_omits_title_when_unknown() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let out = f.process_line(&make_seen(
            1, "ea56c92a", "/home/u", "Bash", "command", "ls",
        ));
        let joined = out.join("\n");
        assert!(
            joined.contains("[ea56c92a]"),
            "expected bare label when no title: {joined}"
        );
        // No title resolved → after the id we should see only padding (spaces),
        // never any non-space character before the bullet/❯ marker.
        let after = joined.split_once("[ea56c92a]").unwrap().1;
        let next_char = after.chars().find(|c| !c.is_whitespace()).unwrap_or(' ');
        assert!(
            "❯●◉⊙⊘".contains(next_char),
            "first non-space after [id] should be a marker, got {next_char:?}: {joined}"
        );
    }

    /// Visible character column at which `needle` first appears in a line,
    /// after stripping ANSI. Returns None if the needle is missing.
    fn char_col(line: &str, needle: char) -> Option<usize> {
        strip_ansi(line).chars().position(|c| c == needle)
    }

    #[test]
    fn detail_line_aligns_with_tool_name() {
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let _ = f.process_line(&make_deny(
            7,
            "Deny reading sensitive paths",
            "blocked",
            "Critical",
        ));
        let seen = make_seen(7, "ea56c92a", "/home/u", "Read", "file_path", "/etc/passwd");
        let out = f.process_line(&seen);
        let event_line = out
            .iter()
            .find(|l| l.contains("⊘") && l.contains("Read"))
            .expect("event line missing");
        let detail_line = out
            .iter()
            .find(|l| l.contains("╰"))
            .expect("detail line missing");
        let event_tool_col = char_col(event_line, 'R').expect("R not found in event");
        let detail_arrow_col = char_col(detail_line, '╰').expect("╰ not found in detail");
        assert_eq!(
            event_tool_col, detail_arrow_col,
            "tool name and ╰ must share a column.\nevent: {event_line}\ndetail: {detail_line}"
        );
    }

    #[test]
    fn continuation_and_detail_share_column() {
        // `│` (continuation) and `╰` (detail) live in the same Box
        // Drawing block so their visual cell metrics line up. Numerical
        // equality is the structural invariant: both must sit at body_col.
        let mut f = Formatter::new(
            opts_no_color(),
            "/home/u".to_string(),
            StubResolver(HashMap::new()),
        );
        let _ = f.process_line(&make_deny(7, "Deny dangerous", "blocked", "Critical"));
        let seen = make_seen(7, "abc", "/home/u/proj", "Bash", "command", "rm -rf /");
        let out = f.process_line(&seen);
        let cont_line = out
            .iter()
            .find(|l| l.contains("│"))
            .expect("continuation line missing");
        let detail_line = out
            .iter()
            .find(|l| l.contains("╰"))
            .expect("detail line missing");
        let cont_col = char_col(cont_line, '│').expect("│ not found in continuation");
        let detail_col = char_col(detail_line, '╰').expect("╰ not found in detail");
        assert_eq!(
            cont_col, detail_col,
            "│ and ╰ must share a column.\ncont: {cont_line}\ndetail: {detail_line}"
        );
    }

    #[test]
    fn status_footer_uses_cmd_label_and_since_when_known() {
        let mut opts = opts_no_color();
        opts.cmd_label = "premptictl logs -f".to_string();
        let mut f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let _ = f.process_line(&make_seen(1, "s", "/home/u", "Bash", "command", "ls"));
        let body = f.status_footer().last().unwrap().clone();
        assert!(body.contains("premptictl logs -f:"), "body={body}");
        assert!(body.contains(" · since "), "missing since: {body}");
    }

    #[test]
    fn status_footer_rule_matches_term_cols() {
        // The rule is full-width decoration: it spans the terminal so the
        // resize watcher can keep it flush against the right edge.
        let mut opts = opts_no_color();
        opts.term_cols = 120;
        let f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let rule = f.status_footer()[1].clone();
        assert_eq!(display_width(&rule), 120, "rule width != term_cols: {rule:?}");
    }

    #[test]
    fn status_footer_rule_floors_at_40() {
        // Clamp protects against pathologically narrow terminals (and the
        // 0-cols edge case when detection fails completely).
        let mut opts = opts_no_color();
        opts.term_cols = 10;
        let f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let rule = f.status_footer()[1].clone();
        assert_eq!(display_width(&rule), 40);
    }

    #[test]
    fn set_term_cols_changes_subsequent_rule_width() {
        // The runner / watcher both call set_term_cols before redrawing —
        // it must take effect on the next status_footer() call.
        let mut opts = opts_no_color();
        opts.term_cols = 80;
        let mut f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let before = display_width(&f.status_footer()[1]);
        f.set_term_cols(160);
        let after = display_width(&f.status_footer()[1]);
        assert_eq!(before, 80);
        assert_eq!(after, 160);
    }

    #[test]
    fn footer_top_row_is_three_from_bottom() {
        assert_eq!(footer_top_row(30), 28); // blank=28, rule=29, body=30
        assert_eq!(footer_top_row(10), 8);
    }

    #[test]
    fn footer_top_row_clamps_at_one() {
        // Pathologically small terminals (smaller than the footer) still
        // produce a valid 1-indexed row so `\x1b[<row>;1H` is well-formed.
        assert_eq!(footer_top_row(2), 1);
        assert_eq!(footer_top_row(0), 1);
    }

    #[test]
    fn events_region_bottom_is_above_footer() {
        // For 30 rows: events region 1..27 (bottom=27), footer at 28-30.
        assert_eq!(events_region_bottom(30), 27);
        assert_eq!(events_region_bottom(10), 7);
    }

    #[test]
    fn events_region_bottom_clamps_at_one() {
        // Tiny terminals still get a valid scroll-region bottom.
        assert_eq!(events_region_bottom(3), 1);
        assert_eq!(events_region_bottom(0), 1);
    }

    #[test]
    fn leave_split_layout_resets_region() {
        let mut buf: Vec<u8> = Vec::new();
        leave_split_layout(&mut buf, 30).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Reset DECSTBM (`ESC[r`) and park cursor at the bottom row so a
        // shell prompt appears below the (now-static) footer.
        assert!(out.contains("\x1b[r"), "missing region reset: {out:?}");
        assert!(out.contains("\x1b[30;1H"), "missing bottom-row park: {out:?}");
    }

    #[test]
    fn render_footer_at_bottom_uses_absolute_position() {
        // The whole point of this refactor: anchor the footer with absolute
        // CUP rather than relative cursor motion, so resize-driven scrolls
        // can't orphan the previous render.
        let mut buf: Vec<u8> = Vec::new();
        let footer = vec!["".to_string(), "rule".to_string(), "body".to_string()];
        render_footer_at_bottom(&mut buf, &footer, 30).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Cursor jumps to the footer top (rows-2 = 28) and clears to EOS.
        assert!(
            out.starts_with("\x1b[28;1H\x1b[J"),
            "must absolute-position then clear: {out:?}"
        );
        // Autowrap is toggled around the lines so each is exactly one row.
        let off = out.find("\x1b[?7l").expect("autowrap-off present");
        let on = out.find("\x1b[?7h").expect("autowrap-on present");
        let body = out.find("body").expect("body present");
        assert!(off < body && body < on, "toggle must bracket body: {out:?}");
        // Cursor parks at the events-region bottom (27) so the next event
        // writeln scrolls naturally.
        assert!(out.ends_with("\x1b[27;1H"), "must park at events bottom: {out:?}");
    }

    fn make_state(cols: usize) -> SharedState<StubResolver> {
        let mut opts = opts_no_color();
        opts.term_cols = cols;
        let formatter = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        SharedState {
            formatter,
            status_drawn: false,
            footer_size: None,
            event_buffer: VecDeque::new(),
        }
    }

    #[test]
    fn full_repaint_clears_screen_and_renders_footer() {
        let mut state = make_state(160);
        let mut buf: Vec<u8> = Vec::new();
        state.full_repaint(&mut buf, 160, 50).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Whole-screen clear is the big hammer that wipes any reflowed
        // orphans from the previous terminal layout — without it, resize
        // leaves stripes of stale rules and bodies behind.
        assert!(out.contains("\x1b[2J"), "missing screen clear: {out:?}");
        // Scroll region established for the new height.
        assert!(out.contains("\x1b[1;47r"), "missing scroll region: {out:?}");
        // Footer absolute-positioned at the new bottom.
        assert!(out.contains("\x1b[48;1H"), "missing footer top CUP: {out:?}");
        // Rule sized to the new width.
        let rule_chars = out.matches('─').count();
        assert!(rule_chars >= 160, "rule sized to new width: {rule_chars}");
        assert_eq!(state.footer_size, Some((160, 50)));
        assert!(state.status_drawn);
    }

    #[test]
    fn full_repaint_renders_buffered_events_above_footer() {
        // Buffered events must show up on screen — that's what makes the
        // resize repaint preserve the recently-seen log content instead of
        // wiping it. Anchored to the bottom of the events region so the
        // most recent line sits just above the footer.
        let mut state = make_state(120);
        for i in 0..3 {
            state
                .event_buffer
                .push_back(BufferedLine::Plain(format!("event-{i}")));
        }
        let mut buf: Vec<u8> = Vec::new();
        state.full_repaint(&mut buf, 120, 30).unwrap();
        let out = String::from_utf8(buf).unwrap();
        for i in 0..3 {
            assert!(out.contains(&format!("event-{i}")), "missing buffered line {i}: {out:?}");
        }
        // Most recent event right above the events region bottom (rows-3 = 27).
        // 3 events anchored to bottom: rows 25, 26, 27. Cursor jumps to row 25.
        assert!(out.contains("\x1b[25;1H"), "events should anchor at row 25: {out:?}");
    }

    #[test]
    fn full_repaint_caps_buffered_events_to_visible_region() {
        // If the buffer holds more events than fit, only the most recent
        // ones are repainted — older ones scroll off (no terminal-managed
        // scrollback inside a DEC scroll region anyway).
        let mut state = make_state(120);
        for i in 0..50 {
            state
                .event_buffer
                .push_back(BufferedLine::Plain(format!("event-{i:03}")));
        }
        let mut buf: Vec<u8> = Vec::new();
        // 10 rows total → events region 1..7, so 7 events fit. Most recent
        // visible should be event-049; oldest visible event-043; older
        // events excluded.
        state.full_repaint(&mut buf, 120, 10).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("event-049"), "most recent must render: {out:?}");
        assert!(out.contains("event-043"), "oldest visible must render: {out:?}");
        assert!(!out.contains("event-042"), "off-screen oldest must NOT render: {out:?}");
    }

    #[test]
    fn full_repaint_regenerates_banner_at_current_width() {
        // The whole point of buffering banners as metadata: on resize the
        // trailing dashes need to track the new width, not replay the width
        // they were originally written at.
        let mut state = make_state(120);
        state.event_buffer.push_back(BufferedLine::Banner(BannerMeta {
            session_id: "abcdef12".to_string(),
            color_code: 1,
            name: None,
        }));
        let mut buf: Vec<u8> = Vec::new();
        state.full_repaint(&mut buf, 200, 30).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Count consecutive ─ runs — there's a leading `──` and the
        // trailing pad. Total visible ─ count should be ≥ 200 (the new
        // width) since the banner extends to the new viewport.
        let dashes = out.matches('─').count();
        assert!(dashes >= 200, "banner should regenerate to new width: {dashes}");
    }

    #[test]
    fn record_lines_attaches_banner_meta() {
        // Sanity: when a banner is in the formatter's last_banner_meta,
        // record_lines stores it as a Banner entry, not Plain — otherwise
        // resize repaint can't regenerate it.
        let mut state = make_state(80);
        let lines = vec!["── abc · banner ──".to_string(), "plain event".to_string()];
        state.formatter.last_banner_meta.push((
            0,
            BannerMeta {
                session_id: "abc".to_string(),
                color_code: 1,
                name: None,
            },
        ));
        state.record_lines(&lines);
        assert_eq!(state.event_buffer.len(), 2);
        assert!(matches!(state.event_buffer[0], BufferedLine::Banner(_)));
        assert!(matches!(state.event_buffer[1], BufferedLine::Plain(_)));
    }

    #[test]
    fn record_lines_caps_at_capacity() {
        let mut state = make_state(80);
        let burst: Vec<String> = (0..(EVENT_BUFFER_CAPACITY + 100))
            .map(|i| format!("e{i}"))
            .collect();
        state.record_lines(&burst);
        assert_eq!(state.event_buffer.len(), EVENT_BUFFER_CAPACITY);
        // Oldest 100 entries should have been evicted; first remaining is e100.
        match &state.event_buffer[0] {
            BufferedLine::Plain(s) => assert_eq!(s, "e100"),
            _ => panic!("expected Plain"),
        }
    }

    #[test]
    fn banner_rule_extends_to_term_cols() {
        // Pinning the macOS-fix outcome: the banner trailing dashes pad to
        // the terminal width. Previously the hand-rolled TIOCGWINSZ
        // collapsed to 80 on macOS, leaving the banner ending mid-screen.
        let mut opts = opts_no_color();
        opts.term_cols = 200;
        let f = Formatter::new(opts, "/home/u".to_string(), StubResolver(HashMap::new()));
        let banner = f.format_banner("abcdef12", 1, None);
        assert_eq!(
            display_width(&banner),
            200,
            "banner should fill the row: {banner:?}"
        );
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
        let task =
            serde_json::json!({"tool.name":"Task","tool.input":"{\"description\":\"do thing\"}"});
        assert_eq!(f.render_tool_body(Some(&bash)), "Bash(ls -la)");
        assert_eq!(f.render_tool_body(Some(&read)), "Read(~/x.rs)");
        assert_eq!(f.render_tool_body(Some(&grep)), "Grep(foo|bar)");
        assert_eq!(
            f.render_tool_body(Some(&webfetch)),
            "WebFetch(https://example.com)"
        );
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
        let raw = format!(
            "{{\"tool.name\":\"Bash\",\"tool.input_command\":\"{cmd}\",\"tool.input\":\"{{}}\"}}"
        );
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
        assert_eq!(
            out,
            vec!["Hook registered in /home/u/.claude/settings.json".to_string()]
        );
    }

    #[test]
    fn condense_session_name_strips_newlines_and_truncates() {
        let s =
            "Line one\nLine two\twith tabs and a very long body that goes on and on and on and on";
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
