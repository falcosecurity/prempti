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
            Self::OrphanMoveTo => f.write_str(
                "'*** Move to:' line without a preceding '*** Update File:' header",
            ),
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

/// Extract the ordered `(operation, path)` tuples from an apply_patch envelope.
///
/// Each Add/Delete/Update hunk produces one tuple. An Update hunk with a
/// `*** Move to:` line produces two tuples in sequence: `(Update, source)`
/// followed by `(Move, target)`. The caller can use the position in the
/// returned `Vec` plus the operation to disambiguate rename pairs if needed.
pub fn parse_apply_patch(text: &str) -> Result<Vec<(PatchOp, String)>, ParseError> {
    let mut ops: Vec<(PatchOp, String)> = Vec::new();
    let mut in_envelope = false;
    let mut saw_end = false;
    // `*** Move to:` is only valid as the immediate consequence of an Update
    // hunk, never on its own and never twice for one update. We track that
    // here rather than via grammar recursion.
    let mut last_op_was_update = false;

    for raw_line in text.lines() {
        // Tolerate CRLF by stripping a trailing '\r' before matching the
        // anchored marker text. The upstream Lark grammar only specifies LF,
        // but the model occasionally emits CRLF on Windows turns.
        let line = raw_line.trim_end_matches('\r');

        if line == BEGIN_PATCH {
            in_envelope = true;
            continue;
        }
        if line == END_PATCH {
            saw_end = true;
            break;
        }
        // Lines before Begin Patch (e.g. shell prompt prefix in the wire
        // input) are ignored. Once we hit Begin Patch, we scan headers
        // until End Patch — content lines (`+`, `-`, ` `, `@@`, etc.)
        // don't match any of our header prefixes and are silently skipped.
        if !in_envelope {
            continue;
        }

        if let Some(path) = line.strip_prefix(ADD_FILE_PREFIX) {
            push_op(&mut ops, PatchOp::Add, path)?;
            last_op_was_update = false;
        } else if let Some(path) = line.strip_prefix(DELETE_FILE_PREFIX) {
            push_op(&mut ops, PatchOp::Delete, path)?;
            last_op_was_update = false;
        } else if let Some(path) = line.strip_prefix(UPDATE_FILE_PREFIX) {
            push_op(&mut ops, PatchOp::Update, path)?;
            last_op_was_update = true;
        } else if let Some(path) = line.strip_prefix(MOVE_TO_PREFIX) {
            if !last_op_was_update {
                return Err(ParseError::OrphanMoveTo);
            }
            push_op(&mut ops, PatchOp::Move, path)?;
            last_op_was_update = false;
        }
    }

    if !in_envelope {
        return Err(ParseError::MissingBeginPatch);
    }
    if !saw_end {
        return Err(ParseError::MissingEndPatch);
    }
    if ops.is_empty() {
        return Err(ParseError::NoHunks);
    }
    Ok(ops)
}

fn push_op(ops: &mut Vec<(PatchOp, String)>, op: PatchOp, path: &str) -> Result<(), ParseError> {
    if path.is_empty() {
        return Err(ParseError::EmptyPath);
    }
    ops.push((op, path.to_string()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
            parse_apply_patch(text).unwrap(),
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
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::NoHunks
        );
    }

    #[test]
    fn empty_path_fails() {
        // "*** Add File: " with trailing space and an empty filename is what
        // the grammar's `filename: /(.+)/` rejects (one-or-more chars
        // required). The header prefix matches, but the path is empty.
        let text = "*** Begin Patch\n*** Add File: \n+x\n*** End Patch\n";
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::EmptyPath
        );
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
        assert_eq!(
            parse_apply_patch(text).unwrap_err(),
            ParseError::NoHunks
        );
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
    // Display impls
    // ------------------------------------------------------------------

    #[test]
    fn patch_op_display_matches_as_str() {
        for op in [PatchOp::Add, PatchOp::Update, PatchOp::Delete, PatchOp::Move] {
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
