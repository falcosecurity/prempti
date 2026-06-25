//! Codex CLI hook registration.
//!
//! Mirrors `hook.rs` (which manages Claude Code's `~/.claude/settings.json`),
//! but writes to `~/.codex/hooks.json` and registers BOTH the `PreToolUse`
//! and `PermissionRequest` event mounts the codex-interceptor binary handles.
//!
//! The two locations Codex recognises for hook config are:
//!   1. `~/.codex/hooks.json` (a dedicated file we manage here)
//!   2. an inline `[hooks]` block in `~/.codex/config.toml`
//!
//! We use (1) for installer-managed registration so the user's main
//! `config.toml` is never touched. Users who manually edit (2) for their own
//! hooks won't conflict with us; Codex loads both layers.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const PRE_TOOL_USE: &str = "PreToolUse";
const PERMISSION_REQUEST: &str = "PermissionRequest";

/// Marker file written under the install prefix to record that the user
/// has opted into the Codex hook. The supervisor (`daemon::run`) uses
/// presence of this file to decide whether to manage the Codex hook
/// lifecycle alongside Claude's: re-assert on start, remove on stop. The
/// marker survives stop/start cycles; the JSON hook does not, by design.
/// Removed by `premptictl hook remove codex` to fully disable.
const ENABLE_MARKER_BASENAME: &str = "codex-hook-enabled";

fn enable_marker_path(prefix: &Path) -> PathBuf {
    prefix.join("config").join(ENABLE_MARKER_BASENAME)
}

fn mark_enabled(prefix: &Path) -> Result<(), String> {
    let marker = enable_marker_path(prefix);
    if let Some(parent) = marker.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("error creating {}: {e}", parent.display()))?;
    }
    fs::write(&marker, b"").map_err(|e| format!("error writing marker {}: {e}", marker.display()))
}

fn mark_disabled(prefix: &Path) -> Result<(), String> {
    let marker = enable_marker_path(prefix);
    if !marker.exists() {
        return Ok(());
    }
    fs::remove_file(&marker).map_err(|e| format!("error removing {}: {e}", marker.display()))
}

/// Whether the user has opted into the Codex hook for this install
/// prefix. Read by the supervisor at start; the marker is created by
/// `cli_add` and removed by `cli_remove`.
pub fn is_enabled(prefix: &Path) -> bool {
    enable_marker_path(prefix).exists()
}
/// Matcher regex applied to `tool_name` per Codex's hook config schema.
/// The interceptor dispatches internally on `hook_event_name`, so we want
/// every tool to reach it.
const MATCHER: &str = ".*";
/// Per-hook timeout in seconds. Matches the docs' example; sub-second is
/// the norm for our interceptor so 30s is comfortable headroom for slow
/// brokers or fail-closed deny rendering.
const TIMEOUT_SEC: u64 = 30;

fn codex_hooks_path() -> PathBuf {
    // CODEX_HOME overrides the discovery root, mirroring Codex's own
    // behavior. Falls back to ~/.codex on Unix and %USERPROFILE%\.codex
    // on Windows.
    if let Ok(home) = env::var("CODEX_HOME") {
        return PathBuf::from(home).join("hooks.json");
    }
    #[cfg(unix)]
    {
        PathBuf::from(crate::home_dir()).join(".codex/hooks.json")
    }
    #[cfg(windows)]
    {
        let userprofile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
        PathBuf::from(userprofile).join(".codex/hooks.json")
    }
}

fn interceptor_command(prefix: &Path) -> String {
    let prefix_str = prefix.to_string_lossy();
    #[cfg(unix)]
    {
        let home = env::var("HOME").unwrap_or_default();
        let default = format!("{home}/.prempti");
        if prefix_str == default {
            "$HOME/.prempti/bin/codex-interceptor".to_string()
        } else {
            format!("{}/bin/codex-interceptor", prefix_str)
        }
    }
    #[cfg(windows)]
    {
        format!(
            "{}/bin/codex-interceptor.exe",
            prefix_str.replace('\\', "/")
        )
    }
}

/// Same intent as `hook::is_owned_interceptor_command`: only mark a command
/// as "ours" if it matches the exact registered command OR ends with a
/// well-known Prempti-owned suffix. Don't sweep arbitrary user hooks that
/// happen to contain the substring `codex-interceptor`.
fn is_owned_codex_interceptor_command(cmd: &str, expected: &str) -> bool {
    if cmd == expected {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        "/bin/codex-interceptor",
        "\\bin\\codex-interceptor",
        "/bin/codex-interceptor.exe",
        "\\bin\\codex-interceptor.exe",
    ];
    SUFFIXES.iter().any(|s| cmd.ends_with(s))
}

/// Owned interceptor commands registered under a single event
/// (`hooks.<event>[*].hooks[*]`). Empty when the event isn't present or holds
/// only foreign hooks.
fn owned_commands_for_event(
    settings: &serde_json::Value,
    event: &str,
    expected: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(groups) = settings
        .get("hooks")
        .and_then(|h| h.get(event))
        .and_then(|p| p.as_array())
    else {
        return out;
    };
    for group in groups {
        let Some(hooks) = group.get("hooks").and_then(|h| h.as_array()) else {
            continue;
        };
        for h in hooks {
            if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                if is_owned_codex_interceptor_command(cmd, expected) {
                    out.push(cmd.to_string());
                }
            }
        }
    }
    out
}

pub enum AddResult {
    Added(PathBuf),
    AlreadyRegistered,
}

pub enum RemoveResult {
    Removed(PathBuf),
    NotFound,
}

pub fn add(prefix: &Path) -> Result<AddResult, String> {
    let path = codex_hooks_path();
    let mut settings: serde_json::Value = if path.exists() {
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("error reading {}: {e}", path.display()))?;
        serde_json::from_str(&data).map_err(|e| format!("error parsing {}: {e}", path.display()))?
    } else {
        serde_json::json!({})
    };

    let hook_cmd = interceptor_command(prefix);
    // Per-event idempotency: if our hook is already in one event but not
    // the other (e.g. user manually trimmed half), add only the missing
    // half so repeated `add` calls converge on a fully-registered state.
    let added_pre = ensure_event_hook(&mut settings, PRE_TOOL_USE, &hook_cmd);
    let added_pr = ensure_event_hook(&mut settings, PERMISSION_REQUEST, &hook_cmd);

    if !added_pre && !added_pr {
        return Ok(AddResult::AlreadyRegistered);
    }

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let output = serde_json::to_string_pretty(&settings).unwrap();
    fs::write(&path, format!("{output}\n"))
        .map_err(|e| format!("error writing {}: {e}", path.display()))?;
    Ok(AddResult::Added(path))
}

/// Ensure our hook is registered under `hooks.<event>[].hooks[]`. Returns
/// true when a new entry was appended, false when our hook was already
/// present.
fn ensure_event_hook(settings: &mut serde_json::Value, event: &str, hook_cmd: &str) -> bool {
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let event_arr = hooks
        .as_object_mut()
        .unwrap()
        .entry(event)
        .or_insert_with(|| serde_json::json!([]));

    if let Some(arr) = event_arr.as_array() {
        for group in arr {
            if let Some(group_hooks) = group.get("hooks").and_then(|h| h.as_array()) {
                for h in group_hooks {
                    if h.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| is_owned_codex_interceptor_command(c, hook_cmd))
                    {
                        return false;
                    }
                }
            }
        }
    }

    event_arr.as_array_mut().unwrap().push(serde_json::json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": hook_cmd,
            "timeout": TIMEOUT_SEC
        }]
    }));
    true
}

pub fn remove(prefix: &Path) -> Result<RemoveResult, String> {
    let path = codex_hooks_path();
    if !path.exists() {
        return Ok(RemoveResult::NotFound);
    }

    let data =
        fs::read_to_string(&path).map_err(|e| format!("error reading {}: {e}", path.display()))?;
    let mut settings: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("error parsing {}: {e}", path.display()))?;

    let expected = interceptor_command(prefix);
    let removed = strip_owned_hooks(&mut settings, &expected);

    if !removed {
        return Ok(RemoveResult::NotFound);
    }

    // If our removal emptied the whole file (no other hooks, no other
    // top-level keys), delete it rather than leaving behind a stub.
    // Otherwise rewrite the trimmed JSON.
    let is_empty = settings.as_object().map(|o| o.is_empty()).unwrap_or(true);
    if is_empty {
        fs::remove_file(&path).map_err(|e| format!("error removing {}: {e}", path.display()))?;
    } else {
        let output = serde_json::to_string_pretty(&settings).unwrap();
        fs::write(&path, format!("{output}\n"))
            .map_err(|e| format!("error writing {}: {e}", path.display()))?;
    }
    Ok(RemoveResult::Removed(path))
}

/// Drop Prempti-owned entries from `hooks.PreToolUse[*].hooks[]` and
/// `hooks.PermissionRequest[*].hooks[]`. A group is only dropped when its
/// inner `hooks` array becomes empty after filtering. An event-key is
/// dropped when its array becomes empty. The whole `hooks` object is
/// dropped when both event keys are gone. Returns true iff at least one
/// entry was removed.
fn strip_owned_hooks(settings: &mut serde_json::Value, expected: &str) -> bool {
    let mut removed = false;
    let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return false;
    };
    for event in &[PRE_TOOL_USE, PERMISSION_REQUEST] {
        if let Some(arr) = hooks.get_mut(*event).and_then(|p| p.as_array_mut()) {
            arr.retain_mut(|group| {
                let Some(group_hooks) = group.get_mut("hooks").and_then(|h| h.as_array_mut())
                else {
                    return true;
                };
                let before = group_hooks.len();
                group_hooks.retain(|h| {
                    let owned = h
                        .get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| is_owned_codex_interceptor_command(c, expected));
                    !owned
                });
                if group_hooks.len() != before {
                    removed = true;
                }
                !group_hooks.is_empty()
            });
            if arr.is_empty() {
                hooks.remove(*event);
            }
        }
    }
    if hooks.is_empty() {
        settings.as_object_mut().unwrap().remove("hooks");
    }
    removed
}

pub fn print_warning() {
    eprintln!();
    eprintln!("  WARNING: The Codex interceptor runs in fail-closed mode. When the");
    eprintln!("  hook is registered, ALL Codex tool calls will be BLOCKED if the");
    eprintln!("  Prempti service is not running or temporarily unavailable.");
    eprintln!();
    eprintln!("  Codex hooks ALSO need explicit trust before they run. Either pass");
    eprintln!("  `--dangerously-bypass-hook-trust` on the codex command line, or use");
    eprintln!("  the `/hooks` slash command in interactive mode to trust them once.");
    eprintln!();
    eprintln!("  To unregister, run:");
    eprintln!("    premptictl hook remove codex");
}

pub fn cli_add(prefix: &Path) {
    match add(prefix) {
        Ok(AddResult::Added(path)) => {
            println!("Codex hook registered in {}", path.display());
            if let Err(e) = mark_enabled(prefix) {
                eprintln!("warning: hook registered but enable marker failed: {e}");
                eprintln!(
                    "         (the supervisor won't re-assert this hook across service restarts)"
                );
            }
            print_warning();
        }
        Ok(AddResult::AlreadyRegistered) => {
            println!("Codex hook already registered.");
            // Ensure the marker exists even if the JSON was already there —
            // covers the case of a stale install where the marker was
            // missed.
            if let Err(e) = mark_enabled(prefix) {
                eprintln!("warning: failed to record enable marker: {e}");
            }
        }
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    }
}

pub fn cli_remove(prefix: &Path) {
    // Drop the marker first so a racing supervisor start can't re-assert
    // the JSON hook between our two operations.
    if let Err(e) = mark_disabled(prefix) {
        eprintln!("warning: failed to remove enable marker: {e}");
    }
    match remove(prefix) {
        Ok(RemoveResult::Removed(path)) => {
            println!("Codex hook removed from {}", path.display());
        }
        Ok(RemoveResult::NotFound) => {
            println!("No Codex hook found to remove.");
        }
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    }
}

pub fn cli_status(prefix: &Path) {
    let path = codex_hooks_path();
    let enabled = is_enabled(prefix);

    if !path.exists() {
        if enabled {
            println!(
                "Codex hook: enable marker present but {} is missing (expected briefly between supervisor stop and next start).",
                path.display()
            );
        } else {
            println!("Codex hook: not registered.");
        }
        return;
    }

    let settings: serde_json::Value = match fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                println!("Codex hook: {} is not valid JSON ({e}).", path.display());
                return;
            }
        },
        Err(e) => {
            println!("Codex hook: cannot read {} ({e}).", path.display());
            return;
        }
    };

    let expected = interceptor_command(prefix);
    let pre = owned_commands_for_event(&settings, PRE_TOOL_USE, &expected);
    let pr = owned_commands_for_event(&settings, PERMISSION_REQUEST, &expected);

    if pre.is_empty() && pr.is_empty() {
        println!(
            "Codex hook: not registered (no Prempti interceptor in {}).",
            path.display()
        );
        return;
    }

    let marker = if enabled {
        "supervisor-managed"
    } else {
        "no enable marker — supervisor will not re-assert across restarts"
    };
    println!("Codex hook: registered in {} ({marker}).", path.display());

    for (event, cmds) in [(PRE_TOOL_USE, &pre), (PERMISSION_REQUEST, &pr)] {
        for cmd in cmds {
            let missing = if Path::new(&crate::hook::expand_home(cmd)).exists() {
                ""
            } else {
                "  [interceptor binary not found at this path]"
            };
            println!("    {event} → {cmd}{missing}");
        }
    }

    // Codex routes PreToolUse and PermissionRequest to the interceptor; a
    // half-registered state silently lets one class of calls bypass policy.
    if pre.is_empty() || pr.is_empty() {
        let missing_event = if pre.is_empty() {
            PRE_TOOL_USE
        } else {
            PERMISSION_REQUEST
        };
        println!(
            "    WARNING: only one event is hooked — {missing_event} is missing. Run `premptictl hook add codex` to repair."
        );
    }
    if pre.iter().chain(pr.iter()).any(|c| c != &expected) {
        println!("    note: a registered path differs from this install's prefix ({expected}).");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ----- ownership detection ---------------------------------------

    #[test]
    fn ownership_exact_match_on_expected_command() {
        let expected = "$HOME/.prempti/bin/codex-interceptor";
        assert!(is_owned_codex_interceptor_command(expected, expected));
    }

    #[test]
    fn ownership_path_suffix_matches_legacy_and_custom_prefixes() {
        let expected = "$HOME/.prempti/bin/codex-interceptor";
        assert!(is_owned_codex_interceptor_command(
            "/home/u/.coding-agents-kit/bin/codex-interceptor",
            expected
        ));
        assert!(is_owned_codex_interceptor_command(
            "/opt/prempti/bin/codex-interceptor",
            expected
        ));
        assert!(is_owned_codex_interceptor_command(
            "C:/Users/u/AppData/Local/prempti/bin/codex-interceptor.exe",
            expected
        ));
        assert!(is_owned_codex_interceptor_command(
            r"C:\Users\u\AppData\Local\prempti\bin\codex-interceptor.exe",
            expected
        ));
    }

    #[test]
    fn ownership_does_not_match_arbitrary_user_hooks() {
        let expected = "$HOME/.prempti/bin/codex-interceptor";
        assert!(!is_owned_codex_interceptor_command(
            "python my-codex-interceptor.py",
            expected
        ));
        assert!(!is_owned_codex_interceptor_command(
            "/usr/local/bin/some-other-tool",
            expected
        ));
        assert!(!is_owned_codex_interceptor_command(
            "echo codex-interceptor || true",
            expected
        ));
    }

    // ----- ensure_event_hook idempotency -----------------------------

    #[test]
    fn add_into_empty_settings_registers_both_events() {
        let mut settings = json!({});
        let added_pre = ensure_event_hook(
            &mut settings,
            PRE_TOOL_USE,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        let added_pr = ensure_event_hook(
            &mut settings,
            PERMISSION_REQUEST,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        assert!(added_pre);
        assert!(added_pr);
        assert!(settings["hooks"]["PreToolUse"].is_array());
        assert!(settings["hooks"]["PermissionRequest"].is_array());
    }

    #[test]
    fn add_when_already_registered_is_idempotent_no_op() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor", "timeout": 30}]
                }],
                "PermissionRequest": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor", "timeout": 30}]
                }]
            }
        });
        let added_pre = ensure_event_hook(
            &mut settings,
            PRE_TOOL_USE,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        let added_pr = ensure_event_hook(
            &mut settings,
            PERMISSION_REQUEST,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        assert!(!added_pre, "PreToolUse already had our hook");
        assert!(!added_pr, "PermissionRequest already had our hook");
    }

    #[test]
    fn add_does_not_treat_arbitrary_user_hook_as_registered() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "python my-codex-interceptor.py"}]
                }]
            }
        });
        let added_pre = ensure_event_hook(
            &mut settings,
            PRE_TOOL_USE,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        assert!(
            added_pre,
            "user hook name must not block Prempti registration"
        );

        let groups = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            groups.len(),
            2,
            "user hook group and Prempti hook group should coexist"
        );
        assert_eq!(
            groups[0]["hooks"][0]["command"].as_str().unwrap(),
            "python my-codex-interceptor.py"
        );
        assert_eq!(
            groups[1]["hooks"][0]["command"].as_str().unwrap(),
            "$HOME/.prempti/bin/codex-interceptor"
        );
    }

    #[test]
    fn add_recovers_partial_registration_state() {
        // Half-registered: PreToolUse has our hook, PermissionRequest doesn't.
        // ensure_event_hook should add the missing half without disturbing
        // the present one.
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"}]
                }]
            }
        });
        let added_pre = ensure_event_hook(
            &mut settings,
            PRE_TOOL_USE,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        let added_pr = ensure_event_hook(
            &mut settings,
            PERMISSION_REQUEST,
            "$HOME/.prempti/bin/codex-interceptor",
        );
        assert!(!added_pre);
        assert!(added_pr, "PermissionRequest was missing, should be added");
        assert!(settings["hooks"]["PermissionRequest"].is_array());
        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn registered_probe_ignores_arbitrary_user_hook_names() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [
                        {"type": "command", "command": "python my-codex-interceptor.py"},
                        {"type": "command", "command": "echo codex-interceptor || true"}
                    ]
                }]
            }
        });
        assert!(owned_commands_for_event(&settings, PRE_TOOL_USE, "").is_empty());
        assert!(owned_commands_for_event(&settings, PERMISSION_REQUEST, "").is_empty());
    }

    #[test]
    fn registered_probe_detects_owned_codex_hook() {
        let settings = json!({
            "hooks": {
                "PermissionRequest": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "/opt/prempti/bin/codex-interceptor"}]
                }]
            }
        });
        assert!(!owned_commands_for_event(&settings, PERMISSION_REQUEST, "").is_empty());
    }

    // ----- strip_owned_hooks: mixed-with-user preservation -----------

    #[test]
    fn strip_drops_only_owned_hook_in_mixed_group() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [
                        {"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"},
                        {"type": "command", "command": "python my-tool.py"}
                    ]
                }]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/codex-interceptor");
        assert!(removed);
        let remaining = settings["hooks"]["PreToolUse"][0]["hooks"]
            .as_array()
            .unwrap();
        assert_eq!(remaining.len(), 1, "user hook should survive: {settings}");
        assert_eq!(
            remaining[0]["command"].as_str().unwrap(),
            "python my-tool.py"
        );
    }

    #[test]
    fn strip_drops_group_when_empty_after_filter_and_clears_event_key() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [
                        {"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"}
                    ]
                }]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/codex-interceptor");
        assert!(removed);
        // PreToolUse array becomes empty → key dropped → hooks object empty → also dropped.
        assert!(
            settings.get("hooks").is_none(),
            "empty hooks object should be removed: {settings}"
        );
    }

    #[test]
    fn strip_clears_both_event_keys_independently() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"}]
                }],
                "PermissionRequest": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"}]
                }]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/codex-interceptor");
        assert!(removed);
        assert!(
            settings.get("hooks").is_none(),
            "both events should be empty: {settings}"
        );
    }

    #[test]
    fn strip_preserves_user_event_when_only_other_is_ours() {
        // User has their own PreToolUse hook AND our Codex hook in
        // PermissionRequest. Removal must keep the user's PreToolUse intact.
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "python my-pre-tool-rule.py"}]
                }],
                "PermissionRequest": [{
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"}]
                }]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/codex-interceptor");
        assert!(removed);
        // PermissionRequest key gone, PreToolUse user hook still there.
        assert!(settings["hooks"].get("PermissionRequest").is_none());
        let groups = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0]["hooks"][0]["command"].as_str().unwrap(),
            "python my-pre-tool-rule.py"
        );
    }

    // ----- enable marker lifecycle ------------------------------------

    fn temp_prefix(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "prempti-hookcodex-{}-{}-{}",
            std::process::id(),
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn enable_marker_path_is_under_config_dir() {
        let prefix = PathBuf::from("/some/install");
        let m = enable_marker_path(&prefix);
        assert_eq!(m, PathBuf::from("/some/install/config/codex-hook-enabled"));
    }

    #[test]
    fn is_enabled_false_when_prefix_missing() {
        let prefix = temp_prefix("absent");
        // Prefix dir doesn't exist; nothing to read.
        assert!(!is_enabled(&prefix));
    }

    #[test]
    fn mark_enabled_then_is_enabled_returns_true() {
        let prefix = temp_prefix("mark-enable");
        mark_enabled(&prefix).expect("mark_enabled");
        assert!(is_enabled(&prefix));
        // Cleanup.
        let _ = fs::remove_dir_all(&prefix);
    }

    #[test]
    fn mark_disabled_then_is_enabled_returns_false() {
        let prefix = temp_prefix("mark-disable");
        mark_enabled(&prefix).expect("mark_enabled");
        assert!(is_enabled(&prefix));
        mark_disabled(&prefix).expect("mark_disabled");
        assert!(!is_enabled(&prefix));
        let _ = fs::remove_dir_all(&prefix);
    }

    #[test]
    fn mark_disabled_is_idempotent_when_marker_absent() {
        let prefix = temp_prefix("disable-absent");
        // Never enabled; disabling should still succeed (no-op).
        mark_disabled(&prefix).expect("idempotent disable");
        assert!(!is_enabled(&prefix));
    }

    #[test]
    fn strip_returns_false_when_nothing_owned() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "python my-tool.py"}]
                }]
            }
        });
        let snapshot = settings.clone();
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/codex-interceptor");
        assert!(!removed);
        assert_eq!(settings, snapshot, "settings untouched");
    }

    #[test]
    fn owned_commands_lists_interceptor_per_event() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [{"matcher": ".*", "hooks": [
                    {"type": "command", "command": "$HOME/.prempti/bin/codex-interceptor"},
                    {"type": "command", "command": "python user.py"}
                ]}],
                "PermissionRequest": [{"matcher": ".*", "hooks": [
                    {"type": "command", "command": "/opt/prempti/bin/codex-interceptor"}
                ]}]
            }
        });
        let expected = "$HOME/.prempti/bin/codex-interceptor";
        assert_eq!(
            owned_commands_for_event(&settings, PRE_TOOL_USE, expected),
            vec!["$HOME/.prempti/bin/codex-interceptor".to_string()]
        );
        assert_eq!(
            owned_commands_for_event(&settings, PERMISSION_REQUEST, expected).len(),
            1
        );
        // Absent event → empty.
        assert!(owned_commands_for_event(&json!({"hooks": {}}), PRE_TOOL_USE, expected).is_empty());
    }
}
