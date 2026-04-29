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
        let default = format!("{home}/.coding-agents-kit");
        if prefix_str == default {
            "$HOME/.coding-agents-kit/bin/claude-interceptor".to_string()
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
        serde_json::from_str(&data)
            .map_err(|e| format!("error parsing {}: {e}", path.display()))?
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

pub fn remove() -> Result<RemoveResult, String> {
    let path = claude_settings_path();
    if !path.exists() {
        return Ok(RemoveResult::NotFound);
    }

    let data = fs::read_to_string(&path)
        .map_err(|e| format!("error reading {}: {e}", path.display()))?;
    let mut settings: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("error parsing {}: {e}", path.display()))?;

    let mut removed = false;
    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(pre_tool) = hooks.get_mut("PreToolUse").and_then(|p| p.as_array_mut()) {
            pre_tool.retain(|group| {
                let dominated = group
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .is_some_and(|group_hooks| {
                        group_hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c.contains("claude-interceptor"))
                        })
                    });
                if dominated {
                    removed = true;
                }
                !dominated
            });
            if pre_tool.is_empty() {
                hooks.remove("PreToolUse");
            }
        }
        if hooks.is_empty() {
            settings.as_object_mut().unwrap().remove("hooks");
        }
    }

    if removed {
        let output = serde_json::to_string_pretty(&settings).unwrap();
        fs::write(&path, format!("{output}\n"))
            .map_err(|e| format!("error writing {}: {e}", path.display()))?;
        Ok(RemoveResult::Removed(path))
    } else {
        Ok(RemoveResult::NotFound)
    }
}

pub fn print_warning() {
    eprintln!();
    eprintln!("  WARNING: The interceptor runs in fail-closed mode. When the hook is");
    eprintln!("  registered, ALL Claude Code tool calls will be BLOCKED if the");
    eprintln!("  coding-agents-kit service is not running or is temporarily unavailable");
    eprintln!("  (e.g., during a `ctl mode` restart or other service downtime).");
    eprintln!();
    eprintln!("  To unblock Claude Code, remove the hook:");
    eprintln!("    coding-agents-kit-ctl hook remove");
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

pub fn cli_remove() {
    match remove() {
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
        eprintln!("    coding-agents-kit-ctl hook remove");
    }
}
