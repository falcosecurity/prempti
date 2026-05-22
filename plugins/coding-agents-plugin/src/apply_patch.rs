//! Parser for Codex's `apply_patch` envelope syntax.
//!
//! Codex's `apply_patch` tool declares its grammar as a Lark file shipped in
//! the upstream repo (`codex-rs/core/src/tools/handlers/apply_patch.lark`).
//! The model is constrained to emit text matching that grammar; the PreToolUse
//! hook receives the entire patch body as a single string in
//! `tool_input.command`.
//!
//! The plugin needs to extract the set of `(operation, path)` tuples the patch
//! will apply to so it can multiplex one apply_patch hook invocation into N
//! synthetic Falco events — one per touched path. This module implements that
//! extraction by scanning for the header lines defined by the grammar.
//!
//! Grammar (verbatim from upstream):
//! ```text
//! start: begin_patch hunk+ end_patch
//! begin_patch: "*** Begin Patch" LF
//! end_patch: "*** End Patch" LF?
//! hunk: add_hunk | delete_hunk | update_hunk
//! add_hunk: "*** Add File: " filename LF add_line+
//! delete_hunk: "*** Delete File: " filename LF
//! update_hunk: "*** Update File: " filename LF change_move? change?
//! filename: /(.+)/
//! change_move: "*** Move to: " filename LF
//! ```
//!
//! On any structural deviation the parser fails. The caller (socket_server)
//! maps any `ParseError` to a fail-closed deny.

use std::fmt;

/// File operation type derived from an apply_patch hunk header.
///
/// `Move` is the rename target of an `Update File:` hunk that carries a
/// `*** Move to:` line — so a single Update hunk with rename produces two
/// entries: `(Update, source)` and `(Move, target)`. This means rules can
/// gate the destination of a rename independently of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    Add,
    Update,
    Delete,
    Move,
}

impl PatchOp {
    /// Stable string form used on the wire and in Falco rule conditions.
    pub fn as_str(self) -> &'static str {
        match self {
            PatchOp::Add => "Add",
            PatchOp::Update => "Update",
            PatchOp::Delete => "Delete",
            PatchOp::Move => "Move",
        }
    }
}

impl fmt::Display for PatchOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reasons the apply_patch envelope can fail to parse. All map to fail-closed
/// deny at the caller.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The body never contained a `*** Begin Patch` line.
    MissingBeginPatch,
    /// The body contained `*** Begin Patch` but never `*** End Patch`.
    MissingEndPatch,
    /// Envelope was structurally valid but contained zero hunks. The Lark
    /// grammar requires `hunk+` so any envelope without hunks is malformed.
    NoHunks,
    /// A hunk header had an empty file path (e.g. "*** Add File: \n").
    EmptyPath,
    /// A `*** Move to:` line appeared without a preceding `*** Update File:`.
    /// The grammar only allows `change_move` inside an `update_hunk`.
    OrphanMoveTo,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBeginPatch => f.write_str("missing '*** Begin Patch' header"),
            Self::MissingEndPatch => f.write_str("missing '*** End Patch' trailer"),
            Self::NoHunks => f.write_str("patch contains no file operations"),
            Self::EmptyPath => f.write_str("patch header has an empty file path"),
            Self::OrphanMoveTo => {
                f.write_str("'*** Move to:' line without a preceding '*** Update File:' header")
            }
        }
    }
}

impl std::error::Error for ParseError {}

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const ADD_FILE_PREFIX: &str = "*** Add File: ";
const DELETE_FILE_PREFIX: &str = "*** Delete File: ";
const UPDATE_FILE_PREFIX: &str = "*** Update File: ";
const MOVE_TO_PREFIX: &str = "*** Move to: ";

/// One entry derived from the patch envelope: the (operation, path) pair the
/// caller acts on, plus the per-hunk text slice the caller can use to rewrite
/// downstream `tool_input.command` so rules matching on patch content only
/// see this file's changes, not the whole envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    pub op: PatchOp,
    pub path: String,
    /// The contiguous lines belonging to this entry's source hunk, including
    /// the hunk header and any body lines, joined with `\n` and terminated
    /// with `\n`. Does NOT include the surrounding `*** Begin Patch` /
    /// `*** End Patch` envelope — the caller wraps those.
    ///
    /// For an Update hunk with a `*** Move to:` line, the Update entry and
    /// the Move entry share the **same** `hunk_text` (they're two views of
    /// one change).
    pub hunk_text: String,
}

/// Internal representation of a hunk found in the envelope.
struct HunkSpan {
    primary_op: PatchOp,
    primary_path: String,
    /// Optional `*** Move to:` target found inside the hunk. Only valid on
    /// Update hunks.
    move_to: Option<String>,
    /// Inclusive line index of the hunk header in the source line vector.
    start_line: usize,
    /// Exclusive line index of where this hunk ends in the source line vector.
    /// Set to the start of the next hunk header, or to the End-Patch line.
    end_line: usize,
}

/// Extract the ordered `PatchEntry` list from an apply_patch envelope.
///
/// Each Add/Delete/Update hunk produces one entry. An Update hunk with a
/// `*** Move to:` line produces two entries in sequence: `(Update, source)`
/// followed by `(Move, target)`, both sharing the same `hunk_text`.
///
/// The `hunk_text` slice per entry is what the broker uses to rewrite
/// `tool_input.command` for the synthetic Falco event, so content-matching
/// rules see only the lines belonging to that hunk — not the whole patch
/// envelope, which would cross-contaminate content from one file's hunk
/// onto another file's per-event `tool.real_file_path`.
pub fn parse_apply_patch(text: &str) -> Result<Vec<PatchEntry>, ParseError> {
    // Split into lines, normalizing CRLF. The upstream Lark grammar only
    // specifies LF but Codex occasionally emits CRLF on Windows turns. We
    // keep ownership of each line as a `String` so the returned hunk_text
    // borrows are detached from the caller's input lifetime.
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim_end_matches('\r').to_string())
        .collect();

    // Phase 1: locate the envelope. The grammar requires Begin Patch and
    // End Patch as anchored markers on their own lines; lines before Begin
    // Patch (e.g. leading prose) are ignored.
    let begin_idx = lines
        .iter()
        .position(|l| l == BEGIN_PATCH)
        .ok_or(ParseError::MissingBeginPatch)?;
    let end_offset = lines[begin_idx + 1..]
        .iter()
        .position(|l| l == END_PATCH)
        .ok_or(ParseError::MissingEndPatch)?;
    let end_idx = begin_idx + 1 + end_offset;

    // Phase 2: scan body for hunk headers. Headers open new hunks; Move-to
    // attaches to the most recent Update hunk.
    let mut hunks: Vec<HunkSpan> = Vec::new();
    for i in (begin_idx + 1)..end_idx {
        let line = &lines[i];
        if let Some(path) = line.strip_prefix(ADD_FILE_PREFIX) {
            push_hunk(&mut hunks, PatchOp::Add, path, i)?;
        } else if let Some(path) = line.strip_prefix(DELETE_FILE_PREFIX) {
            push_hunk(&mut hunks, PatchOp::Delete, path, i)?;
        } else if let Some(path) = line.strip_prefix(UPDATE_FILE_PREFIX) {
            push_hunk(&mut hunks, PatchOp::Update, path, i)?;
        } else if let Some(target) = line.strip_prefix(MOVE_TO_PREFIX) {
            attach_move_to(&mut hunks, target)?;
        }
        // Other lines (`@@`, `+`, `-`, ` `, blank, `*** End of File`, etc.)
        // are hunk body and don't open new hunks.
    }

    if hunks.is_empty() {
        return Err(ParseError::NoHunks);
    }

    // Phase 3: compute each hunk's end line. A hunk ends where the next
    // hunk's header begins, or at End-Patch for the last hunk.
    let mut sentinel = end_idx;
    for h in hunks.iter_mut().rev() {
        h.end_line = sentinel;
        sentinel = h.start_line;
    }

    // Phase 4: materialize entries. Each Update hunk with a Move-to emits
    // both the Update (source) and the Move (target) entries, sharing the
    // hunk_text. The order in the returned Vec is: hunk-order × within-hunk
    // (Update before Move), which matches how synthetic events should be
    // emitted to Falco.
    let mut entries: Vec<PatchEntry> = Vec::with_capacity(hunks.len());
    for h in &hunks {
        let hunk_text = render_hunk_text(&lines, h.start_line, h.end_line);
        entries.push(PatchEntry {
            op: h.primary_op,
            path: h.primary_path.clone(),
            hunk_text: hunk_text.clone(),
        });
        if let Some(target) = &h.move_to {
            entries.push(PatchEntry {
                op: PatchOp::Move,
                path: target.clone(),
                hunk_text,
            });
        }
    }

    Ok(entries)
}

fn push_hunk(
    hunks: &mut Vec<HunkSpan>,
    op: PatchOp,
    path: &str,
    line_index: usize,
) -> Result<(), ParseError> {
    if path.is_empty() {
        return Err(ParseError::EmptyPath);
    }
    hunks.push(HunkSpan {
        primary_op: op,
        primary_path: path.to_string(),
        move_to: None,
        start_line: line_index,
        end_line: 0, // filled in Phase 3
    });
    Ok(())
}

fn attach_move_to(hunks: &mut [HunkSpan], target: &str) -> Result<(), ParseError> {
    let last = hunks.last_mut().ok_or(ParseError::OrphanMoveTo)?;
    if !matches!(last.primary_op, PatchOp::Update) {
        return Err(ParseError::OrphanMoveTo);
    }
    if last.move_to.is_some() {
        // Second `*** Move to:` for the same Update hunk is malformed per
        // grammar (`change_move?` allows zero or one).
        return Err(ParseError::OrphanMoveTo);
    }
    if target.is_empty() {
        return Err(ParseError::EmptyPath);
    }
    last.move_to = Some(target.to_string());
    Ok(())
}

fn render_hunk_text(lines: &[String], start: usize, end: usize) -> String {
    // Re-join the hunk's lines with LF and a trailing LF so the slice is a
    // self-contained chunk. The broker wraps this with `*** Begin Patch` /
    // `*** End Patch` markers when constructing the synthetic event's
    // `tool_input.command`.
    let mut s = String::new();
    for line in &lines[start..end] {
        s.push_str(line);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Project entries down to (op, path) for the bulk of the existing
    /// tests, which don't care about hunk_text. Per-hunk content has its
    /// own dedicated tests further down.
    fn op_paths(entries: &[PatchEntry]) -> Vec<(PatchOp, String)> {
        entries
            .iter()
            .map(|e| (e.op, e.path.clone()))
            .collect()
    }

    fn ops(items: &[(PatchOp, &str)]) -> Vec<(PatchOp, String)> {
        items
            .iter()
            .map(|(op, p)| (*op, (*p).to_string()))
            .collect()
    }

    // ------------------------------------------------------------------
    // Happy paths
    // ------------------------------------------------------------------

    #[test]
    fn parses_single_add() {
        let text = "*** Begin Patch
*** Add File: src/hello.rs
+fn main() {}
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Add, "src/hello.rs")])
        );
    }

    #[test]
    fn parses_single_delete() {
        let text = "*** Begin Patch
*** Delete File: src/dead.rs
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Delete, "src/dead.rs")])
        );
    }

    #[test]
    fn parses_single_update() {
        let text = "*** Begin Patch
*** Update File: src/lib.rs
@@
- old
+ new
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Update, "src/lib.rs")])
        );
    }

    #[test]
    fn update_with_move_yields_two_entries() {
        // The Update produces one entry for the source path; the Move
        // produces a second entry for the target path. Both share the
        // correlation id at the caller.
        let text = "*** Begin Patch
*** Update File: old/path.rs
*** Move to: new/path.rs
@@
- one
+ two
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[
                (PatchOp::Update, "old/path.rs"),
                (PatchOp::Move, "new/path.rs"),
            ])
        );
    }

    #[test]
    fn parses_multi_file_envelope() {
        let text = "*** Begin Patch
*** Add File: a.txt
+a
*** Delete File: b.txt
*** Update File: c.txt
@@
- c
+ C
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[
                (PatchOp::Add, "a.txt"),
                (PatchOp::Delete, "b.txt"),
                (PatchOp::Update, "c.txt"),
            ])
        );
    }

    #[test]
    fn tolerates_crlf_line_endings() {
        let text = "*** Begin Patch\r\n*** Add File: a\r\n+x\r\n*** End Patch\r\n";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Add, "a")])
        );
    }

    #[test]
    fn ignores_content_before_begin_patch() {
        // Some wire shapes may carry leading prose before the envelope. The
        // upstream parser ignores it; so do we.
        let text = "ignored line one
ignored line two
*** Begin Patch
*** Add File: a
+x
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Add, "a")])
        );
    }

    #[test]
    fn content_lines_with_header_lookalikes_do_not_match() {
        // Real header lines start at column 0. A patch context line that
        // happens to begin with '+' or '-' followed by header-like text
        // must NOT be parsed as a header.
        let text = "*** Begin Patch
*** Update File: src/lib.rs
@@
- *** Add File: evil.sh
+ *** Delete File: also_evil.sh
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Update, "src/lib.rs")])
        );
    }

    #[test]
    fn paths_with_spaces_are_preserved() {
        let text = "*** Begin Patch
*** Add File: dir with space/file name.txt
+x
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Add, "dir with space/file name.txt")])
        );
    }

    #[test]
    fn paths_with_header_lookalike_suffixes_are_preserved() {
        // The grammar's `filename: /(.+)/` is line-terminal, so anything
        // after the prefix and before the LF is part of the path —
        // including substrings that look like other markers.
        let text = "*** Begin Patch
*** Update File: weird-*** End Patch -is-not-the-end.txt
@@
- a
+ b
*** End Patch
";
        assert_eq!(
            op_paths(&parse_apply_patch(text).unwrap()),
            ops(&[(PatchOp::Update, "weird-*** End Patch -is-not-the-end.txt")])
        );
    }

    // ------------------------------------------------------------------
    // Error paths
    // ------------------------------------------------------------------

    #[test]
    fn missing_begin_patch_fails() {
        let text = "*** Add File: a
+x
*** End Patch
";
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::MissingBeginPatch
        );
    }

    #[test]
    fn missing_end_patch_fails() {
        let text = "*** Begin Patch
*** Add File: a
+x
";
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::MissingEndPatch
        );
    }

    #[test]
    fn empty_envelope_fails_with_no_hunks() {
        let text = "*** Begin Patch
*** End Patch
";
        assert_eq!(parse_apply_patch(text).unwrap_err(), ParseError::NoHunks);
    }

    #[test]
    fn empty_path_fails() {
        // "*** Add File: " with trailing space and an empty filename is what
        // the grammar's `filename: /(.+)/` rejects (one-or-more chars
        // required). The header prefix matches, but the path is empty.
        let text = "*** Begin Patch\n*** Add File: \n+x\n*** End Patch\n";
        assert_eq!(parse_apply_patch(text).unwrap_err(), ParseError::EmptyPath);
    }

    #[test]
    fn header_without_trailing_space_is_not_recognized() {
        // The grammar requires "*** Add File: " with the trailing space;
        // a line without it doesn't match the prefix and is therefore not
        // treated as a header. Since no hunks parsed, NoHunks fires.
        let text = "*** Begin Patch
*** Add File:
+x
*** End Patch
";
        assert_eq!(parse_apply_patch(text).unwrap_err(), ParseError::NoHunks);
    }

    #[test]
    fn orphan_move_to_without_update_fails() {
        let text = "*** Begin Patch
*** Move to: target.rs
*** End Patch
";
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::OrphanMoveTo
        );
    }

    #[test]
    fn move_to_after_add_fails_as_orphan() {
        // Move-to is only valid following Update File, not Add or Delete.
        let text = "*** Begin Patch
*** Add File: a
+x
*** Move to: b
*** End Patch
";
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::OrphanMoveTo
        );
    }

    #[test]
    fn second_move_to_after_one_update_fails_as_orphan() {
        // After the first Move-to consumes the Update's allowance, a second
        // Move-to is orphaned.
        let text = "*** Begin Patch
*** Update File: old
*** Move to: new1
*** Move to: new2
*** End Patch
";
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::OrphanMoveTo
        );
    }

    #[test]
    fn fully_empty_input_fails_missing_begin() {
        assert_eq!(
            parse_apply_patch("").unwrap_err(),
            ParseError::MissingBeginPatch
        );
    }

    // ------------------------------------------------------------------
    // Per-hunk content slicing — the load-bearing claim for downstream
    // rule isolation. Each entry must carry ONLY its hunk's lines, not
    // the whole envelope, so content-matching rules combined with a
    // per-event path don't cross-match across files in a multi-file
    // patch.
    // ------------------------------------------------------------------

    #[test]
    fn single_add_hunk_text_contains_header_and_body() {
        let text = "*** Begin Patch
*** Add File: a.txt
+marker-A
*** End Patch
";
        let entries = parse_apply_patch(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].hunk_text,
            "*** Add File: a.txt\n+marker-A\n"
        );
    }

    #[test]
    fn multi_file_hunk_texts_are_disjoint() {
        // Each entry's hunk_text must contain only its file's lines.
        // This is the test that pins the false-positive fix: hunk B's
        // content must not leak into hunk A's event, and vice versa.
        let text = "*** Begin Patch
*** Add File: a.txt
+marker-A
*** Add File: b.txt
+marker-B
*** End Patch
";
        let entries = parse_apply_patch(text).unwrap();
        assert_eq!(entries.len(), 2);

        let a = &entries[0];
        assert_eq!(a.path, "a.txt");
        assert!(a.hunk_text.contains("marker-A"));
        assert!(
            !a.hunk_text.contains("marker-B"),
            "hunk A's text leaked content from hunk B: {:?}",
            a.hunk_text
        );

        let b = &entries[1];
        assert_eq!(b.path, "b.txt");
        assert!(b.hunk_text.contains("marker-B"));
        assert!(
            !b.hunk_text.contains("marker-A"),
            "hunk B's text leaked content from hunk A: {:?}",
            b.hunk_text
        );
    }

    #[test]
    fn update_with_move_shares_one_hunk_text_across_two_entries() {
        // The Update and Move entries are two views of one change: both
        // should carry the same hunk_text including the Move-to line.
        let text = "*** Begin Patch
*** Update File: src.rs
*** Move to: dst.rs
@@
- old
+ new
*** End Patch
";
        let entries = parse_apply_patch(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].op, PatchOp::Update);
        assert_eq!(entries[1].op, PatchOp::Move);
        assert_eq!(entries[0].hunk_text, entries[1].hunk_text);
        // The shared text contains the Move-to line and the change body.
        assert!(entries[0].hunk_text.contains("*** Move to: dst.rs"));
        assert!(entries[0].hunk_text.contains("- old"));
        assert!(entries[0].hunk_text.contains("+ new"));
    }

    #[test]
    fn delete_hunk_text_contains_header_only() {
        // Delete hunks per the grammar carry no body — just the header.
        let text = "*** Begin Patch
*** Delete File: gone.txt
*** End Patch
";
        let entries = parse_apply_patch(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hunk_text, "*** Delete File: gone.txt\n");
    }

    #[test]
    fn three_file_envelope_each_entry_gets_only_its_lines() {
        let text = "*** Begin Patch
*** Add File: a
+only-A
*** Update File: b
@@
+only-B
*** Delete File: c
*** End Patch
";
        let entries = parse_apply_patch(text).unwrap();
        assert_eq!(entries.len(), 3);
        let a = &entries[0];
        let b = &entries[1];
        let c = &entries[2];

        assert!(a.hunk_text.contains("only-A") && !a.hunk_text.contains("only-B"));
        assert!(b.hunk_text.contains("only-B") && !b.hunk_text.contains("only-A"));
        // Delete c has only its header — no markers from a or b.
        assert!(!c.hunk_text.contains("only-A") && !c.hunk_text.contains("only-B"));
        assert_eq!(c.hunk_text, "*** Delete File: c\n");
    }

    // ------------------------------------------------------------------
    // Display impls
    // ------------------------------------------------------------------

    #[test]
    fn patch_op_display_matches_as_str() {
        for op in [
            PatchOp::Add,
            PatchOp::Update,
            PatchOp::Delete,
            PatchOp::Move,
        ] {
            assert_eq!(format!("{op}"), op.as_str());
        }
    }

    #[test]
    fn parse_error_display_is_non_empty() {
        for err in [
            ParseError::MissingBeginPatch,
            ParseError::MissingEndPatch,
            ParseError::NoHunks,
            ParseError::EmptyPath,
            ParseError::OrphanMoveTo,
        ] {
            let s = format!("{err}");
            assert!(!s.is_empty(), "{err:?} should have a non-empty display");
        }
    }
}
