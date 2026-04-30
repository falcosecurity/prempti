use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn claude_settings_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(crate::home_dir()).join(".claude/settings.json")
    }
    #[cfg(windows)]
    {
        let home = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
        PathBuf::from(home).join(".claude/settings.json")
    }
}

fn interceptor_command(prefix: &Path) -> String {
    let prefix_str = prefix.to_string_lossy();
    #[cfg(unix)]
    {
        let home = env::var("HOME").unwrap_or_default();
        let default = format!("{home}/.prempti");
        if prefix_str == default {
            "$HOME/.prempti/bin/claude-interceptor".to_string()
        } else {
            format!("{}/bin/claude-interceptor", prefix_str)
        }
    }
    #[cfg(windows)]
    {
        format!(
            "{}/bin/claude-interceptor.exe",
            prefix_str.replace('\\', "/")
        )
    }
}

/// Decide whether a hook command in `~/.claude/settings.json` belongs to a
/// Prempti install. We match exactly against the command we'd write for the
/// current prefix, plus a handful of well-known path suffixes so that legacy
/// `coding-agents-kit` installs and non-default prefixes are still cleaned up
/// — without sweeping arbitrary user hooks that merely mention the substring
/// `claude-interceptor` (e.g. wrappers like `python my-claude-interceptor.py`).
fn is_owned_interceptor_command(cmd: &str, expected: &str) -> bool {
    if cmd == expected {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        "/bin/claude-interceptor",
        "\\bin\\claude-interceptor",
        "/bin/claude-interceptor.exe",
        "\\bin\\claude-interceptor.exe",
    ];
    SUFFIXES.iter().any(|s| cmd.ends_with(s))
}

pub enum AddResult {
    Added(PathBuf),
    AlreadyRegistered,
}

pub enum RemoveResult {
    Removed(PathBuf),
    NotFound,
}

pub fn is_registered() -> bool {
    let path = claude_settings_path();
    if !path.exists() {
        return false;
    }
    fs::read_to_string(&path)
        .map(|data| data.contains("claude-interceptor"))
        .unwrap_or(false)
}

pub fn add(prefix: &Path) -> Result<AddResult, String> {
    let path = claude_settings_path();
    let mut settings: serde_json::Value = if path.exists() {
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("error reading {}: {e}", path.display()))?;
        serde_json::from_str(&data).map_err(|e| format!("error parsing {}: {e}", path.display()))?
    } else {
        serde_json::json!({})
    };

    let hook_cmd = interceptor_command(prefix);
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let pre_tool = hooks
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));

    if let Some(arr) = pre_tool.as_array() {
        for group in arr {
            if let Some(group_hooks) = group.get("hooks").and_then(|h| h.as_array()) {
                for h in group_hooks {
                    if h.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| c.contains("claude-interceptor"))
                    {
                        return Ok(AddResult::AlreadyRegistered);
                    }
                }
            }
        }
    }

    pre_tool.as_array_mut().unwrap().push(serde_json::json!({
        "matcher": "",
        "hooks": [{"type": "command", "command": hook_cmd}]
    }));

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let output = serde_json::to_string_pretty(&settings).unwrap();
    fs::write(&path, format!("{output}\n"))
        .map_err(|e| format!("error writing {}: {e}", path.display()))?;
    Ok(AddResult::Added(path))
}

pub fn remove(prefix: &Path) -> Result<RemoveResult, String> {
    let path = claude_settings_path();
    if !path.exists() {
        return Ok(RemoveResult::NotFound);
    }

    let data =
        fs::read_to_string(&path).map_err(|e| format!("error reading {}: {e}", path.display()))?;
    let mut settings: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("error parsing {}: {e}", path.display()))?;

    let expected = interceptor_command(prefix);
    let removed = strip_owned_hooks(&mut settings, &expected);

    if removed {
        let output = serde_json::to_string_pretty(&settings).unwrap();
        fs::write(&path, format!("{output}\n"))
            .map_err(|e| format!("error writing {}: {e}", path.display()))?;
        Ok(RemoveResult::Removed(path))
    } else {
        Ok(RemoveResult::NotFound)
    }
}

/// Mutate `settings` in place, dropping any Prempti-owned hook entries from
/// `hooks.PreToolUse[*].hooks[]`. A group is only dropped when its inner
/// `hooks` array becomes empty after filtering — user-added hooks that share
/// a group with Prempti's hook are preserved. Returns `true` iff at least
/// one entry was removed.
fn strip_owned_hooks(settings: &mut serde_json::Value, expected: &str) -> bool {
    let mut removed = false;
    let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return false;
    };
    if let Some(pre_tool) = hooks.get_mut("PreToolUse").and_then(|p| p.as_array_mut()) {
        pre_tool.retain_mut(|group| {
            let Some(group_hooks) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
                return true;
            };
            let before = group_hooks.len();
            group_hooks.retain(|h| {
                let owned = h
                    .get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| is_owned_interceptor_command(c, expected));
                !owned
            });
            if group_hooks.len() != before {
                removed = true;
            }
            !group_hooks.is_empty()
        });
        if pre_tool.is_empty() {
            hooks.remove("PreToolUse");
        }
    }
    if hooks.is_empty() {
        settings.as_object_mut().unwrap().remove("hooks");
    }
    removed
}

pub fn print_warning() {
    eprintln!();
    eprintln!("  WARNING: The interceptor runs in fail-closed mode. When the hook is");
    eprintln!("  registered, ALL Claude Code tool calls will be BLOCKED if the");
    eprintln!("  Prempti service is not running or is temporarily unavailable");
    eprintln!("  (e.g., during a `ctl mode` restart or other service downtime).");
    eprintln!();
    eprintln!("  To unblock Claude Code, remove the hook:");
    eprintln!("    premptictl hook remove");
}

pub fn cli_add(prefix: &Path) {
    match add(prefix) {
        Ok(AddResult::Added(path)) => {
            println!("Hook registered in {}", path.display());
            print_warning();
        }
        Ok(AddResult::AlreadyRegistered) => {
            println!("Hook already registered.");
        }
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    }
}

pub fn cli_remove(prefix: &Path) {
    match remove(prefix) {
        Ok(RemoveResult::Removed(path)) => {
            println!("Hook removed from {}", path.display());
        }
        Ok(RemoveResult::NotFound) => {
            println!("No hook found to remove.");
        }
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    }
}

pub fn cli_status() {
    let path = claude_settings_path();
    if !path.exists() {
        println!("Not registered (no settings file).");
        return;
    }
    let data = fs::read_to_string(&path).unwrap_or_default();
    if data.contains("claude-interceptor") {
        println!("Registered.");
    } else {
        println!("Not registered.");
    }
}

pub fn warn_if_still_registered() {
    if is_registered() {
        eprintln!();
        eprintln!("  WARNING: The interceptor hook is still registered in Claude Code.");
        eprintln!("  With the service stopped, ALL tool calls will be BLOCKED.");
        eprintln!("  Remove the hook manually if needed:");
        eprintln!("    premptictl hook remove");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ownership_exact_match_on_expected_command() {
        let expected = "$HOME/.prempti/bin/claude-interceptor";
        assert!(is_owned_interceptor_command(expected, expected));
    }

    #[test]
    fn ownership_path_suffix_matches_legacy_and_custom_prefixes() {
        let expected = "$HOME/.prempti/bin/claude-interceptor";
        assert!(is_owned_interceptor_command(
            "/home/u/.coding-agents-kit/bin/claude-interceptor",
            expected
        ));
        assert!(is_owned_interceptor_command(
            "/opt/prempti/bin/claude-interceptor",
            expected
        ));
        assert!(is_owned_interceptor_command(
            "C:/Users/u/AppData/Local/prempti/bin/claude-interceptor.exe",
            expected
        ));
        assert!(is_owned_interceptor_command(
            r"C:\Users\u\AppData\Local\prempti\bin\claude-interceptor.exe",
            expected
        ));
    }

    #[test]
    fn ownership_does_not_match_arbitrary_user_hooks() {
        let expected = "$HOME/.prempti/bin/claude-interceptor";
        assert!(!is_owned_interceptor_command(
            "python my-claude-interceptor.py",
            expected
        ));
        assert!(!is_owned_interceptor_command(
            "/usr/local/bin/some-other-tool",
            expected
        ));
        assert!(!is_owned_interceptor_command(
            "echo claude-interceptor || true",
            expected
        ));
    }

    #[test]
    fn strip_drops_only_owned_hook_in_mixed_group() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [
                        {"type": "command", "command": "$HOME/.prempti/bin/claude-interceptor"},
                        {"type": "command", "command": "python my-tool.py"}
                    ]
                }]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/claude-interceptor");
        assert!(removed, "expected at least one removal");
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
    fn strip_drops_group_when_empty_after_filter() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [
                        {"type": "command", "command": "$HOME/.prempti/bin/claude-interceptor"}
                    ]
                }]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/claude-interceptor");
        assert!(removed);
        // PreToolUse becomes empty → key is dropped; hooks then empty → also dropped.
        assert!(
            settings.get("hooks").is_none(),
            "empty hooks object should be removed: {settings}"
        );
    }

    #[test]
    fn strip_preserves_unrelated_groups() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python my-tool.py"}]
                    },
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "$HOME/.prempti/bin/claude-interceptor"}]
                    }
                ]
            }
        });
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/claude-interceptor");
        assert!(removed);
        let groups = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "unrelated group should survive: {settings}");
        assert_eq!(groups[0]["matcher"].as_str().unwrap(), "Bash");
    }

    #[test]
    fn strip_returns_false_when_nothing_owned() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "python my-tool.py"}]
                }]
            }
        });
        let snapshot = settings.clone();
        let removed = strip_owned_hooks(&mut settings, "$HOME/.prempti/bin/claude-interceptor");
        assert!(!removed);
        assert_eq!(settings, snapshot, "settings should be untouched");
    }
}
