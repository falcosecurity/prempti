//! Copilot CLI hook registration.
//!
//! Mirrors `hook.rs` (which manages Claude Code's `~/.claude/settings.json`)
//! and `hook_codex.rs` (which manages Codex's `~/.codex/hooks.json`),
//! but writes to `~/.copilot/hooks/prempti.json` and registers the `preToolUse`
//! and `permissionRequest` event mounts for the copilot-interceptor binary.
//!
//! The location Copilot recognizes for hook config is:
//!   1. `~/.copilot/hooks/prempti.json` (a dedicated file we manage here)
//!
//! Users who manually edit other config files won't conflict with us;
//! Copilot loads the hooks.json file specifically for interceptor mounts.

use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

/// Marker file written under the install prefix to record that the user
/// has opted into the Copilot hook. The supervisor (`daemon::run`) uses
/// presence of this file to decide whether to manage the Copilot hook
/// lifecycle alongside Claude's: re-assert on start, remove on stop. The
/// marker survives stop/start cycles; the JSON hook does not, by design.
/// Removed by `premptictl hook remove copilot` to fully disable.
const ENABLE_MARKER_BASENAME: &str = "copilot-hook-enabled";

fn enable_marker_path(prefix: &Path) -> PathBuf {
    prefix.join("config").join(ENABLE_MARKER_BASENAME)
}

fn mark_enabled(prefix: &Path) -> Result<(), String> {
    let marker = enable_marker_path(prefix);
    if let Some(parent) = marker.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("error creating {}: {e}", parent.display()))?;
    }
    fs::write(&marker, b"")
        .map_err(|e| format!("error writing marker {}: {e}", marker.display()))
}

fn mark_disabled(prefix: &Path) -> Result<(), String> {
    let marker = enable_marker_path(prefix);
    if !marker.exists() {
        return Ok(());
    }
    fs::remove_file(&marker).map_err(|e| format!("error removing {}: {e}", marker.display()))
}

/// Whether the user has opted into the Copilot hook for this install
/// prefix. Read by the supervisor at start; the marker is created by
/// `cli_add` and removed by `cli_remove`.
pub fn is_enabled(prefix: &Path) -> bool {
    enable_marker_path(prefix).exists()
}

/// Matcher regex applied to `tool_name` per Copilot's hook config schema.
/// The interceptor dispatches internally on `hook_event_name`, so we want
/// every tool to reach it.
const MATCHER: &str = ".*";
/// Per-hook timeout in seconds. Matches the docs' example; sub-second is
/// the norm for our interceptor so 30s is comfortable headroom for slow
/// brokers or fail-closed deny rendering.
const TIMEOUT_SEC: u64 = 30;

fn copilot_hooks_path() -> PathBuf {
    // COPILOT_HOME overrides the discovery root. Falls back to ~/.copilot on Unix
    // and %USERPROFILE%\.copilot on Windows.
    if let Ok(home) = env::var("COPILOT_HOME") {
        return PathBuf::from(home).join("hooks/prempti.json");
    }
    #[cfg(unix)]
    {
        PathBuf::from(crate::home_dir()).join(".copilot/hooks/prempti.json")
    }
    #[cfg(windows)]
    {
        let userprofile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
        PathBuf::from(userprofile).join(".copilot/hooks/prempti.json")
    }
}

fn interceptor_command(prefix: &Path) -> String {
    let prefix_str = prefix.to_string_lossy();
    #[cfg(unix)]
    {
        let home = env::var("HOME").unwrap_or_default();
        let default = format!("{home}/.prempti");
        if prefix_str == default {
            format!("{}/.prempti/bin/copilot-interceptor", home)
        } else {
            format!("{}/bin/copilot-interceptor", prefix_str)
        }
    }
    #[cfg(windows)]
    {
        format!(
            "{}/bin/copilot-interceptor.exe",
            prefix_str.replace('\\', "/")
        )
    }
}

/// Same intent as `hook::is_owned_interceptor_command`: only mark a command
/// as "ours" if it matches the exact registered command OR ends with a
/// well-known Prempti-owned suffix. Don't sweep arbitrary user hooks that
/// happen to contain the substring `copilot-interceptor`.
fn is_owned_copilot_interceptor_command(cmd: &str, expected: &str) -> bool {
    if cmd == expected {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        "/bin/copilot-interceptor",
        "\\bin\\copilot-interceptor",
        "/bin/copilot-interceptor.exe",
        "\\bin\\copilot-interceptor.exe",
    ];
    SUFFIXES.iter().any(|s| cmd.ends_with(s))
}

/// Both Copilot hook event names (camelCase, per Copilot's wire format).
const COPILOT_EVENTS: &[&str] = &["preToolUse", "permissionRequest"];

pub enum AddResult {
    Added(PathBuf),
    AlreadyRegistered,
}

pub enum RemoveResult {
    Removed(PathBuf),
    NotFound,
}

/// Build the hook entry JSON object for a single hook registration.
fn hook_entry(hook_cmd: &str) -> serde_json::Value {
    json!({
        "matcher": MATCHER,
        "type": "command",
        "command": hook_cmd,
        "timeoutSec": TIMEOUT_SEC
    })
}

pub fn add(prefix: &Path) -> Result<AddResult, String> {
    let path = copilot_hooks_path();
    let mut settings: serde_json::Value = if path.exists() {
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("error reading {}: {e}", path.display()))?;
        serde_json::from_str(&data).map_err(|e| format!("error parsing {}: {e}", path.display()))?
    } else {
        json!({})
    };

    let hook_cmd = interceptor_command(prefix);
    let entry = hook_entry(&hook_cmd);

    // Ensure version field exists
    if settings.get("version").is_none() {
        settings["version"] = json!(1);
    }

    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));

    let mut added = false;
    for event in COPILOT_EVENTS {
        added |= ensure_event_hook(hooks, *event, &entry);
    }

    if !added {
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

/// Ensure our hook is registered under `hooks.<event>[]`.
/// Returns true when a new entry was appended, false when our hook was already present.
fn ensure_event_hook(
    hooks: &mut serde_json::Value,
    event: &str,
    hook_entry: &serde_json::Value,
) -> bool {
    let event_arr = hooks
        .as_object_mut()
        .unwrap()
        .entry(event)
        .or_insert_with(|| json!([]));

    // Check if our command is already registered for this event
    if let Some(arr) = event_arr.as_array() {
        for existing in arr {
            if let (Some(existing_cmd), Some(hook_cmd)) = (
                existing.get("command").and_then(|c| c.as_str()),
                hook_entry.get("command").and_then(|c| c.as_str()),
            ) {
                if is_owned_copilot_interceptor_command(existing_cmd, hook_cmd) {
                    return false;
                }
            }
        }
    }

    event_arr.as_array_mut().unwrap().push(hook_entry.clone());
    true
}

/// Owned interceptor commands registered under a single event
/// (`hooks.<event>[]`). Empty when the event isn't present or holds
/// only foreign hooks.
fn owned_commands_for_event(
    settings: &serde_json::Value,
    event: &str,
    expected: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(arr) = settings
        .get("hooks")
        .and_then(|h| h.get(event))
        .and_then(|p| p.as_array())
    else {
        return out;
    };
    for hook in arr {
        if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
            if is_owned_copilot_interceptor_command(cmd, expected) {
                out.push(cmd.to_string());
            }
        }
    }
    out
}

pub fn remove(prefix: &Path) -> Result<RemoveResult, String> {
    let path = copilot_hooks_path();
    if !path.exists() {
        return Ok(RemoveResult::NotFound);
    }

    let data = fs::read_to_string(&path)
        .map_err(|e| format!("error reading {}: {e}", path.display()))?;
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
    let is_empty = settings
        .as_object()
        .map(|o| o.is_empty())
        .unwrap_or(true);
    if is_empty {
        fs::remove_file(&path)
            .map_err(|e| format!("error removing {}: {e}", path.display()))?;
    } else {
        let output = serde_json::to_string_pretty(&settings).unwrap();
        fs::write(&path, format!("{output}\n"))
            .map_err(|e| format!("error writing {}: {e}", path.display()))?;
    }
    Ok(RemoveResult::Removed(path))
}

/// Drop Prempti-owned entries from `hooks.<event>[]`.
/// Returns true iff at least one entry was removed.
fn strip_owned_hooks(settings: &mut serde_json::Value, expected: &str) -> bool {
    let mut removed = false;
    let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return false;
    };

    for event in COPILOT_EVENTS {
        if let Some(arr) = hooks.get_mut(*event).and_then(|p| p.as_array_mut()) {
            let before = arr.len();
            arr.retain(|hook| {
                let owned = hook
                    .get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| is_owned_copilot_interceptor_command(c, expected));
                !owned
            });
            if arr.len() != before {
                removed = true;
            }
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
    eprintln!("  WARNING: The Copilot interceptor runs in fail-closed mode. When the");
    eprintln!("  hook is registered, ALL Copilot tool calls will be BLOCKED if the");
    eprintln!("  Prempti service is not running or temporarily unavailable.");
    eprintln!();
    eprintln!("  To unregister, run:");
    eprintln!("    premptictl hook remove copilot");
}

pub fn cli_add(prefix: &Path) {
    match add(prefix) {
        Ok(AddResult::Added(path)) => {
            println!("Copilot hook registered in {}", path.display());
            if let Err(e) = mark_enabled(prefix) {
                eprintln!("warning: hook registered but enable marker failed: {e}");
                eprintln!("         (the supervisor won't re-assert this hook across service restarts)");
            }
            print_warning();
        }
        Ok(AddResult::AlreadyRegistered) => {
            println!("Copilot hook already registered.");
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
            println!("Copilot hook removed from {}", path.display());
        }
        Ok(RemoveResult::NotFound) => {
            println!("No Copilot hook found to remove.");
        }
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    }
}

pub fn cli_status(prefix: &Path) {
    let path = copilot_hooks_path();
    let enabled = is_enabled(prefix);

    if !path.exists() {
        if enabled {
            println!(
                "Copilot hook: enable marker present but {} is missing (expected briefly between supervisor stop and next start).",
                path.display()
            );
        } else {
            println!("Copilot hook: not registered.");
        }
        return;
    }

    let settings: serde_json::Value = match fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                println!("Copilot hook: {} is not valid JSON ({e}).", path.display());
                return;
            }
        },
        Err(e) => {
            println!("Copilot hook: cannot read {} ({e}).", path.display());
            return;
        }
    };

    let expected = interceptor_command(prefix);
    let pre = owned_commands_for_event(&settings, "preToolUse", &expected);
    let pr = owned_commands_for_event(&settings, "permissionRequest", &expected);

    if pre.is_empty() && pr.is_empty() {
        println!(
            "Copilot hook: not registered (no Prempti interceptor in {}).",
            path.display()
        );
        return;
    }

    let marker = if enabled {
        "supervisor-managed"
    } else {
        "no enable marker — supervisor will not re-assert across restarts"
    };
    println!("Copilot hook: registered in {} ({marker}).", path.display());

    for (event, cmds) in [("preToolUse", &pre), ("permissionRequest", &pr)] {
        for cmd in cmds {
            let missing = if Path::new(&crate::hook::expand_home(cmd)).exists() {
                ""
            } else {
                "  [interceptor binary not found at this path]"
            };
            println!("    {event} → {cmd}{missing}");
        }
    }

    // Copilot routes preToolUse and permissionRequest to the interceptor;
    // a half-registered state silently lets one class of calls bypass policy.
    if pre.is_empty() || pr.is_empty() {
        let missing_event = if pre.is_empty() {
            "preToolUse"
        } else {
            "permissionRequest"
        };
        println!(
            "    WARNING: only one event is hooked — {missing_event} is missing. Run `premptictl hook add copilot` to repair."
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
        let expected = "$HOME/.prempti/bin/copilot-interceptor";
        assert!(is_owned_copilot_interceptor_command(expected, expected));
    }

    #[test]
    fn ownership_path_suffix_matches_legacy_and_custom_prefixes() {
        let expected = "$HOME/.prempti/bin/copilot-interceptor";
        assert!(is_owned_copilot_interceptor_command(
            "/home/u/.coding-agents-kit/bin/copilot-interceptor",
            expected
        ));
        assert!(is_owned_copilot_interceptor_command(
            "/opt/prempti/bin/copilot-interceptor",
            expected
        ));
        assert!(is_owned_copilot_interceptor_command(
            "C:/Users/u/AppData/Local/prempti/bin/copilot-interceptor.exe",
            expected
        ));
        assert!(is_owned_copilot_interceptor_command(
            r"C:\Users\u\AppData\Local\prempti\bin\copilot-interceptor.exe",
            expected
        ));
    }

    #[test]
    fn ownership_does_not_match_arbitrary_user_hooks() {
        let expected = "$HOME/.prempti/bin/copilot-interceptor";
        assert!(!is_owned_copilot_interceptor_command(
            "python my-copilot-interceptor.py",
            expected
        ));
        assert!(!is_owned_copilot_interceptor_command(
            "/usr/local/bin/some-other-tool",
            expected
        ));
        assert!(!is_owned_copilot_interceptor_command(
            "echo copilot-interceptor || true",
            expected
        ));
    }

    // ----- ensure_event_hook idempotency -----------------------------

    #[test]
    fn add_into_empty_settings_registers_both_hooks() {
        let mut settings = json!({});
        let hook_cmd = "$HOME/.prempti/bin/copilot-interceptor";
        let entry = hook_entry(hook_cmd);

        let added_pre = ensure_event_hook(&mut settings, "preToolUse", &entry);
        let added_perm = ensure_event_hook(&mut settings, "permissionRequest", &entry);

        assert!(added_pre);
        assert!(added_perm);
        assert!(settings["preToolUse"].is_array());
        assert!(settings["permissionRequest"].is_array());
        assert_eq!(settings["preToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(settings["permissionRequest"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn add_when_already_registered_is_idempotent_no_op() {
        let hook_cmd = "$HOME/.prempti/bin/copilot-interceptor";
        let entry = hook_entry(hook_cmd);
        let mut settings = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [entry.clone()],
                "permissionRequest": [entry.clone()]
            }
        });
        let added_pre = ensure_event_hook(
            &mut settings["hooks"],
            "preToolUse",
            &entry
        );
        let added_perm = ensure_event_hook(
            &mut settings["hooks"],
            "permissionRequest",
            &entry
        );
        assert!(!added_pre, "preToolUse already had our hook");
        assert!(!added_perm, "permissionRequest already had our hook");
    }

    #[test]
    fn add_does_not_treat_arbitrary_user_hook_as_registered() {
        let mut settings = json!({
            "hooks": {
                "preToolUse": [{
                    "matcher": ".*",
                    "type": "command",
                    "command": "python my-copilot-interceptor.py",
                    "timeoutSec": 30
                }]
            }
        });
        let hook_cmd = "$HOME/.prempti/bin/copilot-interceptor";
        let entry = hook_entry(hook_cmd);
        let added = ensure_event_hook(
            &mut settings["hooks"],
            "preToolUse",
            &entry
        );
        assert!(added, "user hook name must not block Prempti registration");

        let entries = settings["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "should have two entries: one user hook, one Prempti hook"
        );
    }

    // ----- strip_owned_hooks -----------------------------------------

    #[test]
    fn strip_removes_our_hook_from_mixed_group() {
        let hook_cmd = "$HOME/.prempti/bin/copilot-interceptor";
        let entry = hook_entry(hook_cmd);
        let mut settings = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"matcher": ".*", "type": "command", "command": "python my-copilot-interceptor.py", "timeoutSec": 30},
                    entry.clone()
                ],
                "permissionRequest": [entry.clone()]
            }
        });
        let removed = strip_owned_hooks(&mut settings, hook_cmd);
        assert!(removed);
        assert!(settings["hooks"]["preToolUse"].is_array());
        let groups = settings["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "should have one entry remaining (user hook)");
        assert!(
            settings["hooks"].as_object().unwrap().contains_key("preToolUse"),
            "preToolUse key should remain"
        );
    }

    #[test]
    fn strip_removes_entire_events_when_only_our_hook() {
        let hook_cmd = "$HOME/.prempti/bin/copilot-interceptor";
        let entry = hook_entry(hook_cmd);
        let mut settings = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [entry.clone()],
                "permissionRequest": [entry.clone()]
            }
        });
        let removed = strip_owned_hooks(&mut settings, hook_cmd);
        assert!(removed);
        assert!(
            settings.get("hooks").is_none(),
            "both events should be empty: {settings}"
        );
    }

    // ----- owned_commands_for_event ----------------------------------

    #[test]
    fn owned_commands_for_event_detects_owned_hook() {
        let settings = json!({
            "hooks": {
                "preToolUse": [{"matcher": ".*", "type": "command", "command": "$HOME/.prempti/bin/copilot-interceptor", "timeoutSec": 30}]
            }
        });
        let result = owned_commands_for_event(&settings, "preToolUse", "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "$HOME/.prempti/bin/copilot-interceptor");
    }

    #[test]
    fn owned_commands_for_event_ignores_user_hooks() {
        let settings = json!({
            "hooks": {
                "preToolUse": [{"matcher": ".*", "type": "command", "command": "python my-copilot-interceptor.py", "timeoutSec": 30}]
            }
        });
        let result = owned_commands_for_event(&settings, "preToolUse", "");
        assert!(result.is_empty());
    }

    #[test]
    fn owned_commands_for_event_returns_empty_for_absent_event() {
        let settings = json!({"hooks": {}});
        let result = owned_commands_for_event(&settings, "preToolUse", "");
        assert!(result.is_empty());
    }

    #[test]
    fn owned_commands_for_event_returns_empty_for_absent_hooks() {
        let settings = json!({});
        let result = owned_commands_for_event(&settings, "preToolUse", "");
        assert!(result.is_empty());
    }

    #[test]
    fn owned_commands_for_event_detects_owned_hook_with_custom_prefix() {
        let settings = json!({
            "hooks": {
                "permissionRequest": [{"matcher": ".*", "type": "command", "command": "/opt/prempti/bin/copilot-interceptor", "timeoutSec": 30}]
            }
        });
        let result = owned_commands_for_event(&settings, "permissionRequest", "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "/opt/prempti/bin/copilot-interceptor");
    }

    // ----- cli_status end-to-end -------------------------------------

    #[test]
    fn cli_status_detects_owned_hook_in_config_file() {
        let path = copilot_hooks_path();
        let temp_path = path.clone();
        let _ = fs::create_dir_all(temp_path.parent().unwrap());
        let data = r#"{
            "version": 1,
            "hooks": {
                "preToolUse": [{"matcher": ".*", "type": "command", "command": "$HOME/.prempti/bin/copilot-interceptor", "timeoutSec": 30}],
                "permissionRequest": [{"matcher": ".*", "type": "command", "command": "$HOME/.prempti/bin/copilot-interceptor", "timeoutSec": 30}]
            }
        }"#;
        fs::write(&temp_path, data).unwrap();

        let settings = serde_json::from_str::<serde_json::Value>(data).unwrap();
        let expected = "$HOME/.prempti/bin/copilot-interceptor";
        let pre = owned_commands_for_event(&settings, "preToolUse", expected);
        let pr = owned_commands_for_event(&settings, "permissionRequest", expected);
        assert_eq!(pre.len(), 1);
        assert_eq!(pr.len(), 1);

        // Cleanup
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn cli_status_ignores_foreign_hooks_in_config_file() {
        let path = copilot_hooks_path();
        let temp_path = path.clone();
        let _ = fs::create_dir_all(temp_path.parent().unwrap());
        let data = r#"{
            "version": 1,
            "hooks": {
                "preToolUse": [{"matcher": ".*", "type": "command", "command": "python other-interceptor.py", "timeoutSec": 30}]
            }
        }"#;
        fs::write(&temp_path, data).unwrap();

        let settings = serde_json::from_str::<serde_json::Value>(data).unwrap();
        let pre = owned_commands_for_event(&settings, "preToolUse", "");
        let pr = owned_commands_for_event(&settings, "permissionRequest", "");
        assert!(pre.is_empty());
        assert!(pr.is_empty());

        // Cleanup
        let _ = fs::remove_file(temp_path);
    }

    // ----- enable marker lifecycle -----------------------------------

    fn temp_prefix(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "prempti-hookcopilot-{}-{}-{}",
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
        assert_eq!(m, PathBuf::from("/some/install/config/copilot-hook-enabled"));
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

    // ----- add recovers partial registration state -------------------

    #[test]
    fn add_recovers_partial_registration_state() {
        // Half-registered: preToolUse has our hook, permissionRequest doesn't.
        // add() should add the missing half without disturbing the present one.
        let path = copilot_hooks_path();
        let temp_path = path.clone();
        let _ = fs::create_dir_all(temp_path.parent().unwrap());
        let data = r#"{
            "version": 1,
            "hooks": {
                "preToolUse": [{"matcher": ".*", "type": "command", "command": "$HOME/.prempti/bin/copilot-interceptor", "timeoutSec": 30}]
            }
        }"#;
        fs::write(&temp_path, data).unwrap();

        let prefix = PathBuf::from("$HOME/.prempti");
        let result = add(&prefix);
        assert!(matches!(result, Ok(AddResult::Added(_))));

        let settings: serde_json::Value = serde_json::from_str(&fs::read_to_string(&temp_path).unwrap()).unwrap();
        // preToolUse should still have exactly one entry.
        assert_eq!(settings["hooks"]["preToolUse"].as_array().unwrap().len(), 1);
        // permissionRequest should now have our hook.
        assert!(settings["hooks"]["permissionRequest"].is_array());
        assert_eq!(settings["hooks"]["permissionRequest"].as_array().unwrap().len(), 1);
        assert_eq!(
            settings["hooks"]["permissionRequest"][0]["command"].as_str().unwrap(),
            "$HOME/.prempti/bin/copilot-interceptor"
        );

        // Cleanup
        let _ = fs::remove_file(temp_path);
    }
}
