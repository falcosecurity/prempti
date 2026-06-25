use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

mod daemon;
mod hook;
mod hook_codex;
mod logs_pretty;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "prempti";

pub(crate) fn home_dir() -> String {
    #[cfg(unix)]
    {
        env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
    }
    #[cfg(windows)]
    {
        env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string()))
    }
}

fn default_prefix() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(home_dir()).join(".prempti")
    }
    #[cfg(windows)]
    {
        // Prefer deriving the prefix from the ctl's own location: if ctl
        // lives at `<prefix>\bin\premptictl.exe`, `<prefix>` is
        // the right answer regardless of what INSTALLDIR the MSI used. This
        // keeps ctl commands (enable/disable/start/stop) aligned with a
        // custom install path picked via WixUI_InstallDir. Fall back to
        // %LOCALAPPDATA%\prempti when current_exe isn't a `bin`
        // child (running from a dev target dir, or otherwise detached).
        if let Ok(exe) = env::current_exe() {
            if let Some(bin_dir) = exe.parent() {
                if bin_dir
                    .file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
                {
                    if let Some(prefix) = bin_dir.parent() {
                        return prefix.to_path_buf();
                    }
                }
            }
        }
        PathBuf::from(home_dir()).join("prempti")
    }
}

fn plugin_config_path(prefix: &PathBuf) -> PathBuf {
    prefix.join("config/falco.coding_agents_plugin.yaml")
}

fn print_restart_warning() {
    eprintln!();
    eprintln!("  WARNING: Applying this change requires stopping and starting the");
    eprintln!("  service. During the restart (a few seconds), the broker is");
    eprintln!("  unavailable and ALL Claude Code tool calls will be BLOCKED");
    eprintln!("  (fail-closed). This is expected and temporary.");
}

// ---------------------------------------------------------------------------
// Mode management
// ---------------------------------------------------------------------------

fn mode_get(prefix: &PathBuf) {
    let config_path = plugin_config_path(prefix);
    let data = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", config_path.display());
        process::exit(1);
    });

    // Simple YAML parsing: find the mode line under init_config.
    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("mode:") {
            let mode = trimmed.trim_start_matches("mode:").trim();
            println!("{mode}");
            return;
        }
    }
    println!("guardrails");
}

/// Parse the plugin config YAML for `mode`. Returns `None` when the file
/// is missing or unreadable so the caller can print "unknown" without
/// bailing the whole status command.
///
/// Default matches the plugin's serde default: `mode = "guardrails"` when
/// the key is absent.
fn parse_plugin_config_summary(data: &str) -> String {
    let mut mode = String::from("guardrails");
    for line in data.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("mode:") {
            let value = rest.trim();
            if !value.is_empty() {
                mode = value.trim_matches(|c| c == '"' || c == '\'').to_string();
            }
        }
    }
    mode
}

fn read_plugin_config_summary(prefix: &Path) -> Option<String> {
    let path = plugin_config_path(&prefix.to_path_buf());
    let data = fs::read_to_string(&path).ok()?;
    Some(parse_plugin_config_summary(&data))
}

/// Print the configured mode. Called by every platform's `service_status`
/// so operators can tell at a glance whether enforcement has been altered.
/// `passthrough` is annotated as Experimental wherever it appears.
fn print_plugin_config_summary(prefix: &Path) {
    match read_plugin_config_summary(prefix) {
        Some(mode) if mode == "passthrough" => {
            println!(
                "Mode: passthrough (Experimental — enforcement disabled; \
                 tool calls allowed immediately)"
            );
        }
        Some(mode) => {
            println!("Mode: {mode}");
        }
        None => {
            println!("Mode: unknown");
            println!("  (plugin config not readable)");
        }
    }
}

/// Rewrite the `mode:` line in a plugin-config YAML, preserving indentation
/// and comments. Returns `None` if no `mode:` line is found.
fn rewrite_mode_in_yaml(data: &str, mode: &str) -> Option<String> {
    let mut found = false;
    let mut out = String::with_capacity(data.len());
    let line_count = data.lines().count();
    for (idx, line) in data.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("mode:") {
            found = true;
            out.push_str(&line.replace(trimmed, &format!("mode: {mode}")));
        } else {
            out.push_str(line);
        }
        if idx + 1 < line_count {
            out.push('\n');
        }
    }
    // Preserve trailing newline (standard for config files; matches what
    // the previous implementation produced).
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if found {
        Some(out)
    } else {
        None
    }
}

fn mode_set(prefix: &PathBuf, mode: &str) {
    if mode != "guardrails" && mode != "monitor" && mode != "passthrough" {
        eprintln!("error: mode must be 'guardrails', 'monitor', or 'passthrough'");
        process::exit(1);
    }

    let config_path = plugin_config_path(prefix);
    let data = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", config_path.display());
        process::exit(1);
    });

    let new_data = rewrite_mode_in_yaml(&data, mode).unwrap_or_else(|| {
        eprintln!("error: 'mode:' not found in {}", config_path.display());
        process::exit(1);
    });

    // Snapshot service / hook state BEFORE rewriting so we know what to
    // restore after the restart cycle.
    let was_running = is_service_running();
    let hook_was_registered = hook::is_registered();
    let codex_hook_was_enabled = hook_codex::is_enabled(prefix);

    fs::write(&config_path, new_data).unwrap_or_else(|e| {
        eprintln!("error writing {}: {e}", config_path.display());
        process::exit(1);
    });

    if !was_running {
        println!("Mode set to: {mode}");
        println!("(Service is not running. Start it to apply: premptictl start)");
        return;
    }

    println!("Restarting service to apply mode change...");
    print_restart_warning();
    eprintln!();

    service_restart_inner(prefix, hook_was_registered, codex_hook_was_enabled);

    println!();
    println!("Mode set to: {mode}");
}

// ---------------------------------------------------------------------------
// Default action management (no-rule-match floor)
// ---------------------------------------------------------------------------

fn default_action_get(prefix: &PathBuf) {
    let config_path = plugin_config_path(prefix);
    let data = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", config_path.display());
        process::exit(1);
    });

    for line in data.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("default_action:") {
            let action = rest.trim();
            if !action.is_empty() {
                println!("{}", action.trim_matches(|c| c == '"' || c == '\''));
                return;
            }
        }
    }
    // Matches the plugin's serde default when the key is absent.
    println!("allow");
}

/// Rewrite the `default_action:` line in a plugin-config YAML, preserving
/// indentation. Returns `None` if no `default_action:` line is found. Mirrors
/// `rewrite_mode_in_yaml`; the inline-comment caveat documented there applies.
fn rewrite_default_action_in_yaml(data: &str, action: &str) -> Option<String> {
    let mut found = false;
    let mut out = String::with_capacity(data.len());
    let line_count = data.lines().count();
    for (idx, line) in data.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("default_action:") {
            found = true;
            out.push_str(&line.replace(trimmed, &format!("default_action: {action}")));
        } else {
            out.push_str(line);
        }
        if idx + 1 < line_count {
            out.push('\n');
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if found {
        Some(out)
    } else {
        None
    }
}

fn default_action_set(prefix: &PathBuf, action: &str) {
    if action != "allow" && action != "defer" {
        eprintln!("error: default-action must be 'allow' or 'defer'");
        process::exit(1);
    }

    let config_path = plugin_config_path(prefix);
    let data = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", config_path.display());
        process::exit(1);
    });

    let new_data = rewrite_default_action_in_yaml(&data, action).unwrap_or_else(|| {
        eprintln!(
            "error: 'default_action:' not found in {}",
            config_path.display()
        );
        process::exit(1);
    });

    // The floor is consulted only in guardrails mode; flag the no-op so the
    // user isn't surprised that nothing changed behaviorally.
    let mode = parse_plugin_config_summary(&data);
    if mode != "guardrails" {
        eprintln!(
            "note: default_action is ignored in {mode} mode (every request resolves as 'defer'); \
             it takes effect once you switch to guardrails mode."
        );
    }

    // Snapshot service / hook state BEFORE rewriting so we know what to
    // restore after the restart cycle (mirrors mode_set).
    let was_running = is_service_running();
    let hook_was_registered = hook::is_registered();
    let codex_hook_was_enabled = hook_codex::is_enabled(prefix);

    fs::write(&config_path, new_data).unwrap_or_else(|e| {
        eprintln!("error writing {}: {e}", config_path.display());
        process::exit(1);
    });

    if !was_running {
        println!("Default action set to: {action}");
        println!("(Service is not running. Start it to apply: premptictl start)");
        return;
    }

    println!("Restarting service to apply default-action change...");
    print_restart_warning();
    eprintln!();

    service_restart_inner(prefix, hook_was_registered, codex_hook_was_enabled);

    println!();
    println!("Default action set to: {action}");
}

/// Stop the service, re-register hooks to keep the gap fail-closed, then
/// start the service again. Shared by `ctl restart` and `ctl mode`.
fn service_restart_inner(prefix: &PathBuf, restore_hook: bool, restore_codex_hook: bool) {
    service_stop(false);

    // The supervisor removes the hook on stop; without re-adding it here,
    // the gap between stop and start would let tool calls through
    // unchecked. `hook::add` is idempotent. Mirror the same failsafe for
    // the Codex hook when the user has opted in (enable marker present).
    if restore_hook {
        if let Err(e) = hook::add(prefix) {
            eprintln!("warning: failed to re-register hook during restart: {e}");
        }
    }
    if restore_codex_hook {
        if let Err(e) = hook_codex::add(prefix) {
            eprintln!("warning: failed to re-register codex hook during restart: {e}");
        }
    }

    service_start(prefix);
}

fn service_restart(prefix: &PathBuf) {
    let restore_hook = hook::is_registered();
    let restore_codex_hook = hook_codex::is_enabled(prefix);
    println!("Restarting service...");
    eprintln!();
    service_restart_inner(prefix, restore_hook, restore_codex_hook);
    println!();
    println!("Service restarted.");
}

// ---------------------------------------------------------------------------
// Service management
// ---------------------------------------------------------------------------

// systemctl/launchctl return as soon as the supervisor accepts the process,
// but the plugin binds the broker socket later, after Falco's init_config.
#[cfg(unix)]
fn await_broker_ready(prefix: &PathBuf, timeout: std::time::Duration) -> bool {
    use std::os::unix::net::UnixStream;
    let socket = prefix.join("run/broker.sock");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if UnixStream::connect(&socket).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn report_start_result(broker_ready: bool) {
    if broker_ready {
        println!("Service started.");
    } else {
        println!("Service started, but broker socket is not accepting connections yet.");
        println!("Wait a moment and run `premptictl health` to verify.");
    }
}

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn is_service_running() -> bool {
    // `systemctl is-active --quiet` exits 0 when the unit is active.
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", SERVICE_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn service_start(prefix: &PathBuf) {
    if !systemctl(&["start", SERVICE_NAME]) {
        eprintln!("Failed to start service.");
        process::exit(1);
    }
    report_start_result(await_broker_ready(
        prefix,
        std::time::Duration::from_secs(5),
    ));
}

#[cfg(target_os = "linux")]
fn service_stop(warn_hook: bool) {
    if systemctl(&["stop", SERVICE_NAME]) {
        println!("Service stopped.");
        if warn_hook {
            hook::warn_if_still_registered();
        }
    } else {
        eprintln!("Failed to stop service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_enable() {
    if systemctl(&["enable", SERVICE_NAME]) {
        println!("Service enabled (auto-start on login).");
    } else {
        eprintln!("Failed to enable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_disable() {
    if systemctl(&["disable", SERVICE_NAME]) {
        println!("Service disabled.");
    } else {
        eprintln!("Failed to disable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_status() {
    let _ = Command::new("systemctl")
        .args(["--user", "status", SERVICE_NAME, "--no-pager"])
        .status();
    print_plugin_config_summary(&default_prefix());
}

#[cfg(target_os = "macos")]
const PLIST_LABEL: &str = "dev.falcosecurity.prempti";

#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{PLIST_LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn is_service_loaded() -> bool {
    Command::new("launchctl")
        .args(["list", PLIST_LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn is_service_running() -> bool {
    // launchctl-loaded with KeepAlive == "running" for our purposes.
    is_service_loaded()
}

#[cfg(target_os = "macos")]
fn service_start(prefix: &PathBuf) {
    let plist = plist_path();
    if !plist.exists() {
        eprintln!("Plist not found: {}", plist.display());
        eprintln!("Is Prempti installed?");
        process::exit(1);
    }
    if is_service_loaded() {
        println!("Service already running.");
        return;
    }
    // `-w` clears any persistent "disabled" override left behind by a prior
    // `disable` (which uses `launchctl unload -w`). Both `start` and `enable`
    // mean "want the agent running now" and must handle the disabled state.
    let ok = Command::new("launchctl")
        .args(["load", "-w", &plist.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("Failed to start service.");
        process::exit(1);
    }
    report_start_result(await_broker_ready(
        prefix,
        std::time::Duration::from_secs(5),
    ));
}

#[cfg(target_os = "macos")]
fn service_stop(warn_hook: bool) {
    if !is_service_loaded() {
        println!("Service not running.");
        return;
    }
    let plist = plist_path();
    // launchctl unload stops the process and removes it from launchd.
    // This is the only reliable way to stop with KeepAlive enabled.
    let ok = Command::new("launchctl")
        .args(["unload", &plist.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service stopped.");
        if warn_hook {
            hook::warn_if_still_registered();
        }
    } else {
        eprintln!("Failed to stop service.");
        process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn service_enable() {
    let plist = plist_path();
    if !plist.exists() {
        eprintln!("Plist not found: {}", plist.display());
        eprintln!("Is Prempti installed?");
        process::exit(1);
    }
    // On macOS, the plist has RunAtLoad=true, so loading it both
    // enables auto-start and starts the service immediately.
    // `-w` clears any persistent "disabled" override left behind by
    // `launchctl unload -w` (our `disable` command). Without `-w`,
    // a previously disabled agent would refuse to load with
    // "Load failed: 5: Input/output error".
    if !is_service_loaded() {
        let ok = Command::new("launchctl")
            .args(["load", "-w", &plist.to_string_lossy()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("Failed to enable service.");
            process::exit(1);
        }
    }
    println!("Service enabled (auto-start on login).");
}

#[cfg(target_os = "macos")]
fn service_disable() {
    let plist = plist_path();
    // -w writes a persistent override to not load at login.
    let ok = Command::new("launchctl")
        .args(["unload", "-w", &plist.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service disabled.");
    } else {
        eprintln!("Failed to disable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn service_status() {
    if is_service_loaded() {
        println!("Service running.");
        let _ = Command::new("launchctl")
            .args(["list", PLIST_LABEL])
            .status();
    } else {
        println!("Service not running.");
    }
    print_plugin_config_summary(&default_prefix());
}

// ---------------------------------------------------------------------------
// Windows service management
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(target_os = "windows")]
const RUN_VALUE_NAME: &str = "Prempti";

#[cfg(target_os = "windows")]
fn is_falco_running() -> bool {
    installed_falco_pids(&default_prefix()).is_some()
}

#[cfg(target_os = "windows")]
fn is_service_running() -> bool {
    is_falco_running()
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn installed_falco_path(prefix: &Path) -> PathBuf {
    prefix.join("bin").join("falco.exe")
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn normalize_windows_path_for_compare(path: &str) -> String {
    let mut normalized = path.replace('/', "\\");
    if let Some(rest) = normalized.strip_prefix(r"\\?\UNC\") {
        normalized = format!(r"\\{rest}");
    } else if let Some(rest) = normalized.strip_prefix(r"\\?\") {
        normalized = rest.to_string();
    }
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_paths_equal(candidate: &str, target: &Path) -> bool {
    let candidate = normalize_windows_path_for_compare(candidate);
    let target = normalize_windows_path_for_compare(&target.display().to_string());
    candidate.eq_ignore_ascii_case(&target)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn falco_pids_from_process_json(text: &str, target: &Path) -> Vec<u32> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };
    match value {
        serde_json::Value::Array(rows) => rows
            .iter()
            .filter_map(|row| falco_pid_from_process_json_value(row, target))
            .collect(),
        row => falco_pid_from_process_json_value(&row, target)
            .into_iter()
            .collect(),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn falco_pid_from_process_json_value(row: &serde_json::Value, target: &Path) -> Option<u32> {
    let pid = row.get("Id")?.as_u64()?;
    let pid = u32::try_from(pid).ok()?;
    let path = row.get("Path")?.as_str()?;
    windows_paths_equal(path, target).then_some(pid)
}

/// Return PIDs for the Falco binary installed under `prefix`, or `None` on
/// query error / no match. This deliberately scopes by executable path so the
/// fallback stop path does not kill unrelated Falco processes.
#[cfg(target_os = "windows")]
fn installed_falco_pids(prefix: &Path) -> Option<Vec<u32>> {
    let target = installed_falco_path(prefix);
    let script = r#"$ErrorActionPreference='SilentlyContinue'; @(Get-Process -Name falco -ErrorAction SilentlyContinue | ForEach-Object { try { if ($_.Path) { [pscustomobject]@{Id=$_.Id; Path=$_.Path} } } catch {} }) | ConvertTo-Json -Compress"#;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let pids = falco_pids_from_process_json(&String::from_utf8_lossy(&out.stdout), &target);
    if pids.is_empty() {
        None
    } else {
        Some(pids)
    }
}

/// Escape a string for inclusion in a PowerShell single-quoted literal.
/// PowerShell's only escape inside `'...'` is doubling the apostrophe:
/// `O'Brien` becomes `O''Brien`. Backslashes and double quotes are
/// preserved verbatim, which is what we want for Windows paths.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn ps_single_quote_escape(s: &str) -> String {
    s.replace('\'', "''")
}

/// Render the PowerShell `-Command` string used by `ctl start` on Windows.
///
/// `-Prefix` must be passed explicitly: the MSI supports a custom install
/// directory and `default_prefix()` derives that from the installed
/// ctl.exe location, but the launcher itself defaults to
/// `%LOCALAPPDATA%\prempti` when `-Prefix` is omitted, which
/// then fails to find ctl.exe under a non-default prefix.
///
/// Path arguments are pre-wrapped in `"..."` inside the single-quoted
/// array elements and any embedded `'` is doubled. Two layers of
/// PowerShell parsing apply: this whole format string is the value of
/// `powershell -Command`, and `Start-Process -ArgumentList` then joins
/// the array with bare spaces (it does NOT auto-quote elements
/// containing spaces). Without the outer single-quote escape, a path
/// like `C:\Users\O'Brien\bin\launcher.ps1` would terminate the
/// PowerShell literal early. Without the inner double quotes, a path
/// like `C:\Program Files\Foo\launcher.ps1` would be split on the
/// space by the receiving powershell.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn build_start_powershell_command(launcher: &Path, prefix: &Path) -> String {
    format!(
        "Start-Process -FilePath 'powershell.exe' -ArgumentList @(\
'-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden',\
'-File','\"{}\"','-Prefix','\"{}\"') -WindowStyle Hidden",
        ps_single_quote_escape(&launcher.display().to_string()),
        ps_single_quote_escape(&prefix.display().to_string()),
    )
}

/// Render the `REG_SZ` value written by `ctl enable` on Windows.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn build_run_key_value(launcher: &Path, prefix: &Path) -> String {
    format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden \
-File \"{}\" -Prefix \"{}\"",
        launcher.display(),
        prefix.display()
    )
}

#[cfg(target_os = "windows")]
fn service_start(prefix: &PathBuf) {
    if installed_falco_pids(prefix).is_some() {
        println!("Service already running.");
        return;
    }
    let launcher = prefix.join("bin").join("prempti-launcher.ps1");
    if !launcher.exists() {
        eprintln!("Launcher not found: {}", launcher.display());
        eprintln!("Is Prempti installed?");
        process::exit(1);
    }
    // Spawn the launcher via PowerShell's `Start-Process` rather than a
    // direct `CreateProcess`. `Start-Process` goes through the Windows Shell
    // (ShellExecute), which creates the new process entirely outside of our
    // console, job object and stdio chain — so a caller that captures our
    // stdout (a PS pipeline `& ctl start 2>&1`, bash `$(ctl start)`, …) is
    // released the moment ctl itself exits, instead of hanging on the
    // long-lived launcher's handles. Direct `CreateProcess` with
    // `CREATE_BREAKAWAY_FROM_JOB` is insufficient: PowerShell sessions do
    // not set `JOB_OBJECT_LIMIT_BREAKAWAY_OK`, so the flag is a no-op and
    // the launcher stays in the caller's job, keeping the pipeline open.
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let ps_cmd = build_start_powershell_command(&launcher, prefix);
    let ok = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps_cmd,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("Failed to start service.");
        process::exit(1);
    }
    // Poll up to 10s to verify Falco actually started.
    let mut started = false;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if installed_falco_pids(prefix).is_some() {
            started = true;
            break;
        }
    }
    if started {
        println!("Service started.");
    } else {
        eprintln!("Service did not start within 10 seconds.");
        eprintln!("Check logs:");
        eprintln!("  {}", prefix.join("log").join("supervisor.err").display());
        eprintln!("  {}", prefix.join("log").join("falco.err").display());
        process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn installed_falco_kill_fallback(prefix: &Path, warn_hook: bool) {
    if let Some(pids) = installed_falco_pids(prefix) {
        for pid in &pids {
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        println!("Service stopped (fallback).");
    } else {
        println!("Service not running.");
    }
    if warn_hook {
        hook::warn_if_still_registered();
    }
}

#[cfg(target_os = "windows")]
fn service_stop(warn_hook: bool) {
    let prefix = default_prefix();
    let sock = daemon::control::supervisor_socket_path(&prefix);

    // Treat the supervisor as live only if a STATUS round-trip works.
    // The socket file alone is not a reliable signal — the supervisor
    // can be SIGKILLed / TerminateProcess'd without running its Drop
    // path, leaving a stale `supervisor.sock` behind. Probing for an
    // actual listener (and parsing its pid out of the STATUS response)
    // is the only way to know we have something to send STOP to.
    let supervisor_pid = if sock.exists() {
        match daemon::control::send_command(&sock, "STATUS") {
            Ok(r) => daemon::control::parse_supervisor_pid(&r),
            Err(_) => {
                let _ = std::fs::remove_file(&sock);
                None
            }
        }
    } else {
        None
    };

    let Some(pid) = supervisor_pid else {
        // No supervisor (legacy install, or stale socket from a hard
        // kill). Fall back to a path-scoped taskkill for this install's
        // Falco binary.
        installed_falco_kill_fallback(&prefix, warn_hook);
        return;
    };

    // Live supervisor — ask it to shut down and wait for it to exit.
    // Cleanup (graceful Falco stop, drain pipes, hook remove, close
    // logs) runs inside the supervisor before its process exits.
    let stop_delivered = match daemon::control::send_command(&sock, "STOP") {
        Ok(_) => true,
        Err(e) => {
            eprintln!("warning: failed to send STOP to supervisor: {e}");
            false
        }
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut escalated = false;
    while daemon::process_alive(pid) {
        if std::time::Instant::now() >= deadline {
            eprintln!("supervisor did not exit in 30s; force killing pid {pid}");
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            escalated = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    if escalated || !stop_delivered {
        // The supervisor's graceful shutdown chain (graceful Falco stop,
        // drain pipes, hook remove) didn't run — either we had to
        // taskkill it after a 30s wait, or the STOP command never made
        // it to the listener (supervisor crashed/wedged between the
        // STATUS probe and the STOP call). Child Falco may be orphaned;
        // sweep up any leftover falco.exe from this install. Without
        // this, `Service stopped.` would be a lie and the next
        // `ctl start` would refuse because Falco is still bound.
        installed_falco_kill_fallback(&prefix, warn_hook);
        return;
    }

    println!("Service stopped.");
    if warn_hook {
        hook::warn_if_still_registered();
    }
}

#[cfg(target_os = "windows")]
fn service_enable() {
    let prefix = default_prefix();
    let launcher = prefix.join("bin").join("prempti-launcher.ps1");
    let cmd = build_run_key_value(&launcher, &prefix);
    let ok = Command::new("reg")
        .args([
            "add",
            RUN_KEY,
            "/v",
            RUN_VALUE_NAME,
            "/t",
            "REG_SZ",
            "/d",
            &cmd,
            "/f",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service enabled (auto-start on login).");
    } else {
        eprintln!("Failed to enable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn service_disable() {
    let ok = Command::new("reg")
        .args(["delete", RUN_KEY, "/v", RUN_VALUE_NAME, "/f"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service disabled.");
    } else {
        eprintln!("Failed to disable service (may not have been enabled).");
    }
}

/// Parse one CSV row from tasklist /V output into (PID, mem, cpu_time).
/// Falls back to `None` on any parse issue so localized Windows installs
/// don't break the `status` command.
#[cfg(target_os = "windows")]
fn parse_tasklist_row(row: &str) -> Option<(u32, String, String)> {
    // Fields: "Image Name","PID","Session","Session#","Mem","Status","User","CPU Time","Window Title"
    let unquoted: Vec<String> = row
        .split("\",\"")
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    if unquoted.len() < 8 {
        return None;
    }
    let pid: u32 = unquoted[1].parse().ok()?;
    Some((pid, unquoted[4].clone(), unquoted[7].clone()))
}

#[cfg(target_os = "windows")]
fn service_status() {
    let prefix = default_prefix();
    match installed_falco_pids(&prefix) {
        Some(pids) => {
            println!("Service running.");
            for pid in &pids {
                let row = Command::new("tasklist")
                    .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH", "/V"])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                match parse_tasklist_row(&row) {
                    Some((_, mem, cpu)) => println!("  PID {pid}  mem={mem}  cpu={cpu}"),
                    None => println!("  PID {pid}"),
                }
            }
        }
        None => println!("Service not running."),
    }
    // Surface whether the Run key is registered so users can tell at a
    // glance whether the service will come back on next login.
    let run_check = Command::new("reg")
        .args(["query", RUN_KEY, "/v", RUN_VALUE_NAME])
        .output();
    if let Ok(o) = run_check {
        if o.status.success() {
            println!("Auto-start: enabled (HKCU Run key {RUN_VALUE_NAME}).");
        } else {
            println!("Auto-start: disabled.");
        }
    }
    print_plugin_config_summary(&prefix);
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

/// Remove `p` regardless of whether it's a file, symlink, or directory.
/// `fs::remove_dir_all` errors out on regular files, which made
/// `rules/seen.yaml` silently survive `uninstall --keep-user-rules`.
fn remove_path(p: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(p)?;
    if meta.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

/// Cleanup pass for `uninstall --keep-user-rules`: drop everything under
/// `prefix` except `prefix/rules/user/`. Both passes use [`remove_path`] so
/// regular files (e.g. `rules/seen.yaml`, stray dotfiles) are removed too.
fn keep_user_rules_cleanup(prefix: &Path) {
    if let Ok(entries) = fs::read_dir(prefix) {
        for entry in entries.flatten() {
            if entry.file_name() != "rules" {
                let _ = remove_path(&entry.path());
            }
        }
    }
    let rules_dir = prefix.join("rules");
    if let Ok(entries) = fs::read_dir(&rules_dir) {
        for entry in entries.flatten() {
            if entry.file_name() != "user" {
                let _ = remove_path(&entry.path());
            }
        }
    }
}

fn uninstall(prefix: &PathBuf, keep_user_rules: bool) {
    println!("=== Uninstalling Prempti ===");
    println!("  Prefix: {}", prefix.display());
    println!();

    // 1. Stop the service.
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", SERVICE_NAME])
            .status();
        let _ = Command::new("systemctl")
            .args(["--user", "disable", SERVICE_NAME])
            .status();
        let service_file = PathBuf::from(env::var("HOME").unwrap_or_default())
            .join(".config/systemd/user/prempti.service");
        if service_file.exists() {
            println!("Removing systemd service...");
            let _ = fs::remove_file(&service_file);
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let plist = plist_path();
        if is_service_loaded() {
            println!("Stopping service...");
            let _ = Command::new("launchctl")
                .args(["unload", &plist.to_string_lossy()])
                .status();
        }
        if plist.exists() {
            println!("Removing launchd plist...");
            let _ = fs::remove_file(&plist);
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Reuse service_stop so the launcher's `finally` block gets a chance
        // to run its own hook-remove before we take the belt-and-braces pass
        // below.
        if is_falco_running() {
            println!("Stopping service...");
            service_stop(false);
        }
        // Remove auto-start registry key.
        let _ = Command::new("reg")
            .args(["delete", RUN_KEY, "/v", RUN_VALUE_NAME, "/f"])
            .status();
    }

    // 2. Remove the hooks (safety net).
    // The service's ExecStopPost (Linux), launcher trap (macOS), or launcher
    // PowerShell `finally` block (Windows) should have removed the Claude
    // hook already. But if the service wasn't running or the stop hooks
    // didn't fire, the hook would stay registered and brick Claude Code.
    // The Codex hook gets the same treatment — plus removal of the enable
    // marker so uninstall is a full reset.
    println!("Removing Claude Code hook...");
    hook::cli_remove(prefix);
    println!("Removing Codex hook (if registered)...");
    hook_codex::cli_remove(prefix);

    // 3. Remove the installation directory.
    if prefix.exists() {
        if keep_user_rules {
            let user_rules = prefix.join("rules/user");
            if user_rules.is_dir() {
                println!("Preserving user rules: {}", user_rules.display());
                keep_user_rules_cleanup(prefix);
            }
        } else {
            println!("Removing {}...", prefix.display());
            let _ = fs::remove_dir_all(prefix);
        }
    }

    println!();
    println!("=== Uninstall complete ===");
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Classify the Claude interceptor's stdout (on exit 0) from the synthetic
/// health event into a health message. Pure so every branch — including the
/// `defer` empty-stdout case — is unit-testable without a live broker.
/// Returns `Ok(msg)` for a healthy pipeline, `Err(msg)` for a failure.
fn classify_health_stdout(stdout: &str) -> Result<String, String> {
    let trimmed = stdout.trim();

    // A `defer` verdict renders as empty stdout + exit 0. The broker resolves
    // a no-match event as defer in monitor mode, passthrough mode, and
    // guardrails + `default_action: defer` — so the synthetic health event
    // (which matches no deny/ask rule) lands here in those configurations.
    // The broker DID respond (a broker outage fails closed to an explicit
    // deny, not empty stdout), so the pipeline is healthy: Prempti chose to
    // step aside.
    if trimmed.is_empty() {
        return Ok("OK: pipeline healthy (synthetic event → defer / no decision)".to_string());
    }

    let parsed: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            return Err(format!(
                "FAIL: interceptor returned malformed JSON\n  Output: {trimmed}"
            ));
        }
    };

    let decision = parsed
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let reason = parsed
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if decision.is_empty() {
        return Err(format!(
            "FAIL: interceptor returned unexpected output\n  Output: {trimmed}"
        ));
    }

    // Denies caused by infrastructure failure (not real rule matches) indicate
    // a broken pipeline. Detect both forms of broker failure:
    // - "broker response timeout": socket connected but no verdict arrived
    // - "broker unavailable": connection refused (service not running)
    if decision == "deny"
        && (reason.contains("broker response timeout") || reason.contains("broker unavailable"))
    {
        return Err(format!(
            "FAIL: broker unreachable or timed out while waiting for verdict\n  Reason: {reason}"
        ));
    }

    Ok(match decision {
        "allow" => "OK: pipeline healthy (synthetic event → allow)".to_string(),
        "deny" => "OK: pipeline healthy (synthetic event → deny)\n  \
                   Note: a deny rule matched the health-check event.\n  \
                   This is expected if you have rules matching Bash commands."
            .to_string(),
        "ask" => "OK: pipeline healthy (synthetic event → ask)".to_string(),
        _ => format!("OK: pipeline responded (unexpected verdict)\n  Response: {trimmed}"),
    })
}

fn health(prefix: &PathBuf) {
    #[cfg(unix)]
    let interceptor = prefix.join("bin/claude-interceptor");
    #[cfg(windows)]
    let interceptor = prefix.join("bin/claude-interceptor.exe");

    // Socket path must use forward slashes on Windows — AF_UNIX treats the path
    // as an opaque address, so it must match exactly what the plugin binds to.
    let socket = {
        let raw = prefix.join("run/broker.sock");
        #[cfg(windows)]
        {
            std::path::PathBuf::from(raw.to_string_lossy().replace('\\', "/"))
        }
        #[cfg(unix)]
        {
            raw
        }
    };

    // Check interceptor binary exists.
    if !interceptor.exists() {
        eprintln!("FAIL: interceptor not found at {}", interceptor.display());
        process::exit(1);
    }

    // Check broker socket exists.
    if !socket.exists() {
        eprintln!("FAIL: broker socket not found at {}", socket.display());
        eprintln!("Is the service running?");
        process::exit(1);
    }

    // Send a synthetic event through the full pipeline. Uses a harmless Bash
    // "echo" command that matches no deny/ask rule, so it resolves via the
    // no-match floor: allow (permissionDecision JSON) under guardrails +
    // default_action: allow, or defer (empty stdout) under monitor /
    // passthrough / default_action: defer. Both mean the pipeline is healthy.
    let test_event = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo health-check"},"session_id":"health-check","cwd":"/tmp","tool_use_id":"health-check"}"#;

    let output = Command::new(&interceptor)
        .env("PREMPTI_SOCKET", &socket)
        .env("PREMPTI_TIMEOUT_MS", "5000")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(test_event.as_bytes());
            }
            drop(child.stdin.take());
            child.wait_with_output()
        });

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            match classify_health_stdout(&stdout) {
                Ok(msg) => println!("{msg}"),
                Err(msg) => {
                    eprintln!("{msg}");
                    process::exit(1);
                }
            }
        }
        Ok(out) => {
            eprintln!("FAIL: interceptor exited with code {}", out.status);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.is_empty() {
                eprintln!("  Stderr: {}", stderr.trim());
            }
            process::exit(1);
        }
        Err(e) => {
            eprintln!("FAIL: could not run interceptor: {e}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

struct LogsOpts {
    stderr: bool,
    follow: bool,
    tail: Option<u64>,
    raw: bool,
    no_color: bool,
    no_stats: bool,
    show: Option<logs_pretty::ShowMask>,
}

fn parse_logs_args(args: &[&str]) -> Result<LogsOpts, String> {
    let mut opts = LogsOpts {
        stderr: false,
        follow: false,
        tail: None,
        raw: false,
        no_color: false,
        no_stats: false,
        show: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        match a {
            "--err" => opts.stderr = true,
            "-f" | "--follow" => opts.follow = true,
            "--raw" => opts.raw = true,
            "--no-color" => opts.no_color = true,
            "--no-stats" => opts.no_stats = true,
            "--tail" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| "--tail requires a value".to_string())?;
                opts.tail = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --tail value: {}", v))?,
                );
            }
            _ if a.starts_with("--tail=") => {
                let v = &a["--tail=".len()..];
                opts.tail = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --tail value: {}", v))?,
                );
            }
            "--show" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| "--show requires a value".to_string())?;
                opts.show = Some(logs_pretty::ShowMask::parse(v)?);
            }
            _ if a.starts_with("--show=") => {
                let v = &a["--show=".len()..];
                opts.show = Some(logs_pretty::ShowMask::parse(v)?);
            }
            _ => return Err(format!("unknown logs flag: {}", a)),
        }
        i += 1;
    }
    Ok(opts)
}

/// Build a single coalesced warning if pretty-only flags are combined with
/// raw-implying flags (--raw or --err). Returns an empty string when there
/// is nothing to warn about. The caller prints this to stderr at startup.
fn logs_conflict_warning(opts: &LogsOpts) -> String {
    let raw_mode = opts.raw || opts.stderr;
    if !raw_mode {
        return String::new();
    }
    let mut ignored: Vec<&str> = Vec::new();
    if opts.show.is_some() {
        ignored.push("--show");
    }
    if opts.no_color {
        ignored.push("--no-color");
    }
    if opts.no_stats {
        ignored.push("--no-stats");
    }
    if ignored.is_empty() {
        return String::new();
    }
    let with = if opts.raw {
        "--raw"
    } else {
        "--err (stderr is plain text)"
    };
    format!("warning: {} ignored with {}", ignored.join(", "), with)
}

fn logs(prefix: &PathBuf, opts: &LogsOpts) {
    let file = if opts.stderr {
        "falco.err"
    } else {
        "falco.log"
    };
    let path = prefix.join("log").join(file);
    if !path.exists() {
        eprintln!("Log file not found: {}", path.display());
        eprintln!("Is the service running?");
        process::exit(1);
    }

    let warning = logs_conflict_warning(opts);
    if !warning.is_empty() {
        eprintln!("{warning}");
    }

    // --raw and --err both bypass the pretty path: --raw because the user
    // asked for it, --err because Falco's stderr is plain text, not JSON.
    if opts.raw || opts.stderr {
        run_logs_raw(&path, opts);
    } else {
        run_logs_pretty(&path, opts);
    }
}

/// Default number of lines to keep when `--tail=N` is not given.
const DEFAULT_TAIL_LINES: u64 = 100;

/// Last-resort name when neither `argv[0]` nor `current_exe()` is usable.
const FALLBACK_BINARY_NAME: &str = "premptictl";

/// Best-effort look-up of the invoked binary name. Tries `argv[0]` first
/// (preserves whatever name the user typed — useful when the binary is
/// symlinked or aliased), falls back to the on-disk file name, and finally
/// to `FALLBACK_BINARY_NAME`. The `.exe` suffix is stripped on Windows so
/// the label reads identically across platforms.
fn invoked_binary_name() -> String {
    fn from_path(path: &Path) -> Option<String> {
        path.file_name().map(|n| {
            let s = n.to_string_lossy();
            s.strip_suffix(".exe")
                .or_else(|| s.strip_suffix(".EXE"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| s.into_owned())
        })
    }
    if let Some(arg0) = env::args().next() {
        if !arg0.is_empty() {
            if let Some(name) = from_path(Path::new(&arg0)) {
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(name) = from_path(&exe) {
            if !name.is_empty() {
                return name;
            }
        }
    }
    FALLBACK_BINARY_NAME.to_string()
}

/// Reconstruct the command-line label shown in the status footer. Mirrors
/// the flags actually applied to the pretty path (snapshot/follow/show/...)
/// so the user can read off the mode at a glance, e.g.
/// `premptictl logs -f`. The binary name is taken from argv[0] (the
/// way the user actually invoked it), falling back to the on-disk exe name
/// and finally a hardcoded default — never panics.
fn build_logs_cmd_label(opts: &LogsOpts) -> String {
    build_logs_cmd_label_with_bin(&invoked_binary_name(), opts)
}

/// Same as `build_logs_cmd_label` but takes the binary name as a parameter
/// so the body can be unit-tested deterministically (without depending on
/// `argv[0]` / `current_exe()`).
fn build_logs_cmd_label_with_bin(bin: &str, opts: &LogsOpts) -> String {
    let mut s = String::with_capacity(bin.len() + 16);
    s.push_str(bin);
    s.push_str(" logs");
    if opts.follow {
        s.push_str(" -f");
    }
    if let Some(n) = opts.tail {
        s.push_str(&format!(" --tail={n}"));
    }
    if let Some(mask) = opts.show {
        if mask != logs_pretty::ShowMask::default_mask() {
            s.push_str(&format!(" --show={}", mask.label()));
        }
    }
    if opts.no_color {
        s.push_str(" --no-color");
    }
    if opts.no_stats {
        s.push_str(" --no-stats");
    }
    s
}

fn effective_tail(opts: &LogsOpts) -> u64 {
    opts.tail.unwrap_or(DEFAULT_TAIL_LINES)
}

fn build_tail_command(path: &PathBuf, opts: &LogsOpts) -> Command {
    let n = effective_tail(opts);
    #[cfg(unix)]
    {
        let mut cmd = Command::new("tail");
        cmd.args(["-n", &n.to_string()]);
        if opts.follow {
            cmd.arg("-f");
        }
        cmd.arg(path);
        cmd
    }
    #[cfg(windows)]
    {
        let mut ps_cmd = format!("Get-Content -Path '{}' -Tail {}", path.display(), n);
        if opts.follow {
            ps_cmd.push_str(" -Wait");
        }
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", &ps_cmd]);
        cmd
    }
}

fn run_logs_raw(path: &PathBuf, opts: &LogsOpts) {
    let mut cmd = build_tail_command(path, opts);
    match cmd.status() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to tail log: {e}");
            process::exit(1);
        }
    }
}

fn run_logs_pretty(path: &PathBuf, opts: &LogsOpts) {
    use std::io::{BufReader, IsTerminal};
    use std::process::Stdio;

    let stdout_is_tty = std::io::stdout().is_terminal();
    let no_color_env = std::env::var("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let color = !opts.no_color && !no_color_env && stdout_is_tty;
    let stats = !opts.no_stats && stdout_is_tty;
    let show = opts
        .show
        .unwrap_or_else(logs_pretty::ShowMask::default_mask);

    if color {
        logs_pretty::enable_vt_mode();
    }

    let pretty_opts = logs_pretty::PrettyOpts {
        color,
        stats,
        follow: opts.follow,
        show,
        term_cols: logs_pretty::detect_term_cols(),
        cmd_label: build_logs_cmd_label(opts),
    };

    let mut cmd = build_tail_command(path, opts);
    cmd.stdout(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to tail log: {e}");
            process::exit(1);
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            eprintln!("Failed to capture tail stdout");
            let _ = child.wait();
            process::exit(1);
        }
    };
    let reader = BufReader::new(stdout);
    let resolver = logs_pretty::FsSessionNameResolver::default();
    if let Err(e) = logs_pretty::run(reader, pretty_opts, resolver) {
        // BrokenPipe is expected when the consumer (e.g., `head`) closes the
        // pipe — exit silently rather than printing an error.
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("logs: {e}");
        }
    }
    let _ = child.wait();
}

#[cfg(test)]
mod logs_tests {
    use super::*;

    #[test]
    fn defaults() {
        let opts = parse_logs_args(&[]).unwrap();
        assert!(!opts.stderr);
        assert!(!opts.follow);
        assert!(opts.tail.is_none());
        assert!(!opts.raw);
        assert!(!opts.no_color);
        assert!(!opts.no_stats);
        assert!(opts.show.is_none());
    }

    #[test]
    fn raw_flag_parsed() {
        assert!(parse_logs_args(&["--raw"]).unwrap().raw);
    }

    #[test]
    fn no_color_and_no_stats_parsed() {
        let opts = parse_logs_args(&["--no-color", "--no-stats"]).unwrap();
        assert!(opts.no_color);
        assert!(opts.no_stats);
    }

    #[test]
    fn show_flag_space_and_equals_form() {
        let opts1 = parse_logs_args(&["--show", "deny,ask"]).unwrap();
        let opts2 = parse_logs_args(&["--show=deny,ask"]).unwrap();
        assert_eq!(opts1.show, opts2.show);
        assert!(opts1.show.is_some());
    }

    #[test]
    fn show_invalid_value_errors() {
        assert!(parse_logs_args(&["--show", "bogus"]).is_err());
        assert!(parse_logs_args(&["--show=bogus"]).is_err());
    }

    #[test]
    fn show_missing_value_errors() {
        assert!(parse_logs_args(&["--show"]).is_err());
    }

    #[test]
    fn conflict_warning_empty_when_no_conflict() {
        let opts = parse_logs_args(&["-f"]).unwrap();
        assert_eq!(logs_conflict_warning(&opts), "");
        let opts = parse_logs_args(&["--show", "deny"]).unwrap();
        assert_eq!(logs_conflict_warning(&opts), "");
    }

    #[test]
    fn conflict_warning_lists_ignored_flags_with_raw() {
        let opts = parse_logs_args(&["--raw", "--show", "deny", "--no-color"]).unwrap();
        let w = logs_conflict_warning(&opts);
        assert!(w.contains("--show"), "got: {w}");
        assert!(w.contains("--no-color"), "got: {w}");
        assert!(w.contains("--raw"), "got: {w}");
    }

    #[test]
    fn conflict_warning_with_err_mentions_stderr() {
        let opts = parse_logs_args(&["--err", "--show", "deny"]).unwrap();
        let w = logs_conflict_warning(&opts);
        assert!(w.contains("--show"));
        assert!(w.contains("--err"));
        assert!(w.contains("stderr is plain text"));
    }

    #[test]
    fn raw_alone_does_not_warn() {
        let opts = parse_logs_args(&["--raw"]).unwrap();
        assert_eq!(logs_conflict_warning(&opts), "");
    }

    #[test]
    fn err_flag() {
        let opts = parse_logs_args(&["--err"]).unwrap();
        assert!(opts.stderr);
    }

    #[test]
    fn follow_short_and_long() {
        assert!(parse_logs_args(&["-f"]).unwrap().follow);
        assert!(parse_logs_args(&["--follow"]).unwrap().follow);
    }

    #[test]
    fn tail_equals_form() {
        assert_eq!(parse_logs_args(&["--tail=50"]).unwrap().tail, Some(50));
    }

    #[test]
    fn tail_space_form() {
        assert_eq!(parse_logs_args(&["--tail", "100"]).unwrap().tail, Some(100));
    }

    #[test]
    fn combined_flags_any_order() {
        let opts = parse_logs_args(&["-f", "--tail=20", "--err"]).unwrap();
        assert!(opts.follow);
        assert!(opts.stderr);
        assert_eq!(opts.tail, Some(20));
    }

    #[test]
    fn tail_missing_value() {
        assert!(parse_logs_args(&["--tail"]).is_err());
    }

    #[test]
    fn tail_invalid_value() {
        assert!(parse_logs_args(&["--tail=abc"]).is_err());
        assert!(parse_logs_args(&["--tail", "-1"]).is_err());
    }

    #[test]
    fn unknown_flag() {
        assert!(parse_logs_args(&["--bogus"]).is_err());
    }

    #[test]
    fn cmd_label_includes_logs_subcommand() {
        let opts = parse_logs_args(&[]).unwrap();
        assert_eq!(
            build_logs_cmd_label_with_bin("premptictl", &opts),
            "premptictl logs"
        );
    }

    #[test]
    fn cmd_label_appends_follow() {
        let opts = parse_logs_args(&["-f"]).unwrap();
        assert_eq!(
            build_logs_cmd_label_with_bin("premptictl", &opts),
            "premptictl logs -f"
        );
    }

    #[test]
    fn cmd_label_appends_tail() {
        let opts = parse_logs_args(&["--tail=50"]).unwrap();
        assert_eq!(
            build_logs_cmd_label_with_bin("premptictl", &opts),
            "premptictl logs --tail=50"
        );
    }

    #[test]
    fn cmd_label_appends_non_default_show() {
        let opts = parse_logs_args(&["--show", "deny,ask"]).unwrap();
        let label = build_logs_cmd_label_with_bin("premptictl", &opts);
        assert!(label.starts_with("premptictl logs "), "got: {label}");
        assert!(label.contains("--show=deny,ask"), "got: {label}");
    }

    #[test]
    fn cmd_label_omits_show_when_default_mask() {
        // Explicit but identical-to-default mask should not echo --show, since
        // the user wouldn't have noticed any change in behavior.
        let opts = parse_logs_args(&["--show=deny,ask,allow,pass"]).unwrap();
        let label = build_logs_cmd_label_with_bin("premptictl", &opts);
        assert!(!label.contains("--show"), "got: {label}");
    }

    #[test]
    fn cmd_label_appends_no_color_and_no_stats() {
        let opts = parse_logs_args(&["--no-color", "--no-stats"]).unwrap();
        let label = build_logs_cmd_label_with_bin("premptictl", &opts);
        assert!(label.contains(" --no-color"), "got: {label}");
        assert!(label.contains(" --no-stats"), "got: {label}");
    }

    #[test]
    fn cmd_label_preserves_argv0_binary_name() {
        // Symlinked / aliased invocations should keep whatever name the user
        // typed, with `logs` placed immediately after it.
        let opts = parse_logs_args(&["-f"]).unwrap();
        assert_eq!(build_logs_cmd_label_with_bin("pctl", &opts), "pctl logs -f");
    }

    #[test]
    fn cmd_label_combined_flags_order() {
        // Flags should appear in this order: -f, --tail, --show, --no-color,
        // --no-stats. Stable ordering keeps the footer easy to skim.
        let opts = parse_logs_args(&["-f", "--tail=20", "--show=deny", "--no-color", "--no-stats"])
            .unwrap();
        assert_eq!(
            build_logs_cmd_label_with_bin("premptictl", &opts),
            "premptictl logs -f --tail=20 --show=deny --no-color --no-stats"
        );
    }
}

#[cfg(test)]
mod mode_tests {
    use super::rewrite_mode_in_yaml;

    #[test]
    fn flips_mode_value_preserving_indent() {
        let yaml = "plugins:\n  - name: coding_agent\n    init_config:\n      mode: guardrails\n      http_port: 2802\n";
        let out = rewrite_mode_in_yaml(yaml, "monitor").expect("mode line found");
        assert!(
            out.contains("      mode: monitor\n"),
            "indent preserved: {out}"
        );
        // Other lines untouched.
        assert!(out.contains("plugins:\n"));
        assert!(out.contains("      http_port: 2802\n"));
    }

    #[test]
    fn preserves_trailing_comments() {
        let yaml = "init_config:\n  mode: guardrails  # active mode\n  http_port: 2802\n";
        let out = rewrite_mode_in_yaml(yaml, "monitor").unwrap();
        // The `mode:` line is rewritten in full, so the inline comment is
        // dropped — document this behavior. (Keeping the comment would
        // require a smarter rewriter; not worth the complexity for a config
        // line that shouldn't carry inline comments anyway.)
        assert!(out.contains("  mode: monitor\n"));
        assert!(out.contains("  http_port: 2802\n"));
    }

    #[test]
    fn returns_none_when_mode_absent() {
        let yaml = "init_config:\n  http_port: 2802\n";
        assert!(rewrite_mode_in_yaml(yaml, "monitor").is_none());
    }

    #[test]
    fn keeps_other_yaml_structure_intact() {
        let yaml = "# Comment header\nplugins:\n  - name: coding_agent\n    init_config:\n      mode: monitor\n      socket_path: /tmp/x\nrules_files:\n  - /tmp/r.yaml\n";
        let out = rewrite_mode_in_yaml(yaml, "guardrails").unwrap();
        assert!(out.starts_with("# Comment header\n"));
        assert!(out.ends_with("- /tmp/r.yaml\n"));
        assert!(out.contains("      mode: guardrails\n"));
        assert!(out.contains("      socket_path: /tmp/x\n"));
    }

    #[test]
    fn preserves_no_trailing_newline_input_by_adding_one() {
        // Input without trailing newline gets one (matches previous behavior).
        let yaml = "init_config:\n  mode: guardrails";
        let out = rewrite_mode_in_yaml(yaml, "monitor").unwrap();
        assert!(out.ends_with("  mode: monitor\n"));
    }

    #[test]
    fn matches_indented_or_non_indented_mode() {
        // `mode:` at column 0 (unusual but legal in YAML) is also rewritten.
        let yaml = "mode: guardrails\nother: thing\n";
        let out = rewrite_mode_in_yaml(yaml, "monitor").unwrap();
        assert!(out.contains("mode: monitor\n"));
    }

    #[test]
    fn rewrites_to_passthrough() {
        // `passthrough` is the third accepted mode value; round-trip it both
        // ways to confirm the rewriter is mode-string agnostic.
        let yaml = "init_config:\n  mode: guardrails\n  http_port: 2802\n";
        let out = rewrite_mode_in_yaml(yaml, "passthrough").unwrap();
        assert!(out.contains("  mode: passthrough\n"), "got: {out}");
        let back = rewrite_mode_in_yaml(&out, "guardrails").unwrap();
        assert!(back.contains("  mode: guardrails\n"), "got: {back}");
    }
}

#[cfg(test)]
mod default_action_tests {
    use super::rewrite_default_action_in_yaml;

    #[test]
    fn flips_value_preserving_indent() {
        let yaml = "plugins:\n  - name: coding_agent\n    init_config:\n      mode: guardrails\n      default_action: allow\n      http_port: 2802\n";
        let out = rewrite_default_action_in_yaml(yaml, "defer").expect("default_action line found");
        assert!(
            out.contains("      default_action: defer\n"),
            "indent preserved: {out}"
        );
        assert!(out.contains("      http_port: 2802\n"));
    }

    #[test]
    fn returns_none_when_absent() {
        let yaml = "init_config:\n  mode: guardrails\n";
        assert!(rewrite_default_action_in_yaml(yaml, "defer").is_none());
    }

    #[test]
    fn round_trips_allow_and_defer() {
        let yaml = "init_config:\n  default_action: allow\n";
        let out = rewrite_default_action_in_yaml(yaml, "defer").unwrap();
        assert!(out.contains("  default_action: defer\n"), "got: {out}");
        let back = rewrite_default_action_in_yaml(&out, "allow").unwrap();
        assert!(back.contains("  default_action: allow\n"), "got: {back}");
    }

    #[test]
    fn targets_only_default_action_not_mode() {
        // Both keys carry scalar values; the rewriter must touch only
        // `default_action:` and leave `mode:` intact.
        let yaml = "init_config:\n  mode: monitor\n  default_action: allow\n";
        let out = rewrite_default_action_in_yaml(yaml, "defer").unwrap();
        assert!(out.contains("  mode: monitor\n"), "mode preserved: {out}");
        assert!(out.contains("  default_action: defer\n"));
    }
}

#[cfg(test)]
mod health_tests {
    use super::classify_health_stdout;

    #[test]
    fn allow_is_healthy() {
        let out = classify_health_stdout(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":""}}"#,
        )
        .expect("allow is healthy");
        assert!(out.contains("allow"), "got: {out}");
    }

    #[test]
    fn defer_empty_stdout_is_healthy() {
        // Regression guard: a `defer` verdict renders as empty stdout, which
        // must read as healthy (Prempti stepped aside), not malformed JSON.
        // Whitespace-only counts as empty.
        let out = classify_health_stdout("").expect("empty stdout is healthy defer");
        assert!(out.contains("defer"), "got: {out}");
        let out_ws = classify_health_stdout("  \n").expect("whitespace stdout is healthy defer");
        assert!(out_ws.contains("defer"), "got: {out_ws}");
    }

    #[test]
    fn ask_is_healthy() {
        let out = classify_health_stdout(
            r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"confirm"}}"#,
        )
        .expect("ask is healthy");
        assert!(out.contains("ask"), "got: {out}");
    }

    #[test]
    fn rule_deny_is_healthy() {
        // A real rule-match deny means the pipeline works end to end.
        let out = classify_health_stdout(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Deny rm -rf: blocked"}}"#,
        )
        .expect("rule deny is healthy");
        assert!(out.contains("deny"), "got: {out}");
    }

    #[test]
    fn infra_deny_is_failure() {
        // A fail-closed deny caused by a broker outage must report FAIL.
        let err = classify_health_stdout(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"broker unavailable"}}"#,
        )
        .expect_err("infra deny is failure");
        assert!(err.contains("broker unreachable"), "got: {err}");
    }

    #[test]
    fn malformed_json_is_failure() {
        let err = classify_health_stdout("this is not json").expect_err("malformed is failure");
        assert!(err.contains("malformed JSON"), "got: {err}");
    }

    #[test]
    fn json_without_decision_is_failure() {
        let err = classify_health_stdout(r#"{"hookSpecificOutput":{}}"#)
            .expect_err("missing decision is failure");
        assert!(err.contains("unexpected output"), "got: {err}");
    }
}

#[cfg(test)]
mod plugin_config_summary_tests {
    use super::{parse_plugin_config_summary, read_plugin_config_summary};
    use std::path::Path;

    #[test]
    fn defaults_to_guardrails_when_mode_absent() {
        let yaml = "init_config:\n  socket_path: /tmp/x\n";
        assert_eq!(parse_plugin_config_summary(yaml), "guardrails");
    }

    #[test]
    fn parses_monitor_mode() {
        let yaml = "init_config:\n  mode: monitor\n";
        assert_eq!(parse_plugin_config_summary(yaml), "monitor");
    }

    #[test]
    fn parses_passthrough_mode() {
        let yaml = "init_config:\n  mode: passthrough\n";
        assert_eq!(parse_plugin_config_summary(yaml), "passthrough");
    }

    #[test]
    fn tolerates_quoted_scalar() {
        // Users may quote scalars; quotes are stripped so the value matches
        // what the plugin's serde deserializer accepts.
        let yaml = "init_config:\n  mode: \"monitor\"\n";
        assert_eq!(parse_plugin_config_summary(yaml), "monitor");
    }

    #[test]
    fn missing_file_returns_none() {
        // The caller prints "unknown" when None.
        let prefix = Path::new("/tmp/premptictl-tests-no-such-prefix-xyz");
        assert!(read_plugin_config_summary(prefix).is_none());
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!("premptictl — manage the Prempti service");
    eprintln!();
    eprintln!("Usage: premptictl <command>");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  hook add [claude|codex]      Register the interceptor hook (default: claude)");
    eprintln!("  hook remove [claude|codex]   Remove the interceptor hook (default: claude)");
    eprintln!("  hook status [claude|codex]   Check if the hook is registered (default: claude)");
    eprintln!();
    eprintln!("  mode              Show current operational mode");
    eprintln!("  mode guardrails   Switch to guardrails mode (deny/ask enforced)");
    eprintln!("  mode monitor      Switch to monitor mode (all verdicts allow, alerts logged)");
    eprintln!("  mode passthrough  Switch to passthrough mode (Experimental, embedding-only:");
    eprintln!("                    instant allow, no rule-eval wait; events still enqueued)");
    eprintln!();
    eprintln!("  default-action          Show the no-rule-match floor (guardrails mode)");
    eprintln!("  default-action allow    No matching rule → Prempti approves (skips agent prompt)");
    eprintln!(
        "  default-action defer    No matching rule → defer to the agent's own permission flow"
    );
    eprintln!();
    eprintln!("  start            Start the service");
    eprintln!("  stop             Stop the service");
    eprintln!("  restart          Stop and start the service (use after editing config files)");
    eprintln!("  enable           Enable service auto-start on login");
    eprintln!("  disable          Disable service auto-start");
    eprintln!("  status           Show service status");
    eprintln!("  health           Check pipeline health (send synthetic event)");
    eprintln!("  logs [flags]     Print Falco stdout logs (last 100 lines by default)");
    eprintln!("                     -f, --follow    stream new output");
    eprintln!("                     --tail=N        print last N lines (default: 100)");
    eprintln!("                     --err           target stderr log instead (forces raw)");
    eprintln!("                     --raw           print raw JSON (disable pretty formatting)");
    eprintln!("                     --show LIST     verdicts to render: pass,allow,ask,deny,all");
    eprintln!("                                     default: all");
    eprintln!("                     --no-color      pretty layout without ANSI colors");
    eprintln!("                     --no-stats      pretty layout without status line");
    eprintln!();
    eprintln!("  daemon [flags]   Run the supervisor (spawns Falco, owns logs and rotation,");
    eprintln!("                   owns the hook lifecycle). Normally invoked by the platform");
    eprintln!("                   service; advanced users can run it manually.");
    eprintln!(
        "                     --prefix PATH              install prefix (default: ~/.prempti)"
    );
    eprintln!("                     --config PATH              supervisor config (default: <prefix>/config/supervisor.yaml)");
    eprintln!(
        "                     --log-rotate-bytes N       override config: rotation size threshold"
    );
    eprintln!("                     --log-rotate-keep N        override config: archives to keep");
    eprintln!(
        "                     --stop-timeout-secs N      override config: graceful stop timeout"
    );
    eprintln!();
    eprintln!("  uninstall        Remove Prempti completely");
    eprintln!("  uninstall --keep-user-rules  Uninstall but preserve custom rules");
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  -V, --version    Print version and exit");
    eprintln!("  -h, --help       Print this help and exit");
}

fn next_flag_value<'a>(args: &'a [&str], i: &mut usize, name: &str) -> Result<&'a str, String> {
    let arg = args[*i];
    let prefix = format!("{name}=");
    if let Some(suffix) = arg.strip_prefix(&prefix) {
        return Ok(suffix);
    }
    *i += 1;
    args.get(*i)
        .copied()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn parse_daemon_args(args: &[&str], default_prefix: PathBuf) -> Result<daemon::DaemonOpts, String> {
    let mut opts = daemon::DaemonOpts {
        prefix: default_prefix,
        config_path: None,
        log_rotate_bytes: None,
        log_rotate_keep: None,
        stop_timeout_secs: None,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        let name = arg.split('=').next().unwrap_or(arg);
        match name {
            "--prefix" => opts.prefix = PathBuf::from(next_flag_value(args, &mut i, "--prefix")?),
            "--config" => {
                opts.config_path = Some(PathBuf::from(next_flag_value(args, &mut i, "--config")?));
            }
            "--log-rotate-bytes" => {
                let v = next_flag_value(args, &mut i, "--log-rotate-bytes")?;
                opts.log_rotate_bytes = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --log-rotate-bytes: {v}"))?,
                );
            }
            "--log-rotate-keep" => {
                let v = next_flag_value(args, &mut i, "--log-rotate-keep")?;
                opts.log_rotate_keep = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --log-rotate-keep: {v}"))?,
                );
            }
            "--stop-timeout-secs" => {
                let v = next_flag_value(args, &mut i, "--stop-timeout-secs")?;
                opts.stop_timeout_secs = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --stop-timeout-secs: {v}"))?,
                );
            }
            _ => return Err(format!("unknown daemon flag: {arg}")),
        }
        i += 1;
    }
    Ok(opts)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prefix = default_prefix();
    let mut cmd_args: Vec<&str> = Vec::new();

    // Parse global flags.
    for arg in &args[1..] {
        if arg == "--help" || arg == "-h" {
            print_usage();
            process::exit(0);
        } else if arg == "--version" || arg == "-V" {
            println!("premptictl {}", env!("CARGO_PKG_VERSION"));
            process::exit(0);
        } else {
            cmd_args.push(arg);
        }
    }

    if cmd_args.is_empty() {
        print_usage();
        process::exit(1);
    }

    match cmd_args.as_slice() {
        ["hook", "add"] | ["hook", "add", "claude"] => hook::cli_add(&prefix),
        ["hook", "remove"] | ["hook", "remove", "claude"] => hook::cli_remove(&prefix),
        ["hook", "status"] | ["hook", "status", "claude"] => hook::cli_status(&prefix),
        ["hook", "add", "codex"] => hook_codex::cli_add(&prefix),
        ["hook", "remove", "codex"] => hook_codex::cli_remove(&prefix),
        ["hook", "status", "codex"] => hook_codex::cli_status(&prefix),
        ["mode"] => mode_get(&prefix),
        ["mode", mode] => mode_set(&prefix, mode),
        ["default-action"] => default_action_get(&prefix),
        ["default-action", action] => default_action_set(&prefix, action),
        ["start"] => service_start(&prefix),
        ["stop"] => service_stop(true),
        ["restart"] => service_restart(&prefix),
        ["enable"] => service_enable(),
        ["disable"] => service_disable(),
        ["status"] => service_status(),
        ["health"] => health(&prefix),
        ["daemon", rest @ ..] => match parse_daemon_args(rest, prefix.clone()) {
            Ok(opts) => match daemon::run(opts) {
                Ok(code) => process::exit(code),
                Err(e) => {
                    eprintln!("supervisor: {e}");
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("{e}");
                eprintln!();
                print_usage();
                process::exit(2);
            }
        },
        ["logs", rest @ ..] => match parse_logs_args(rest) {
            Ok(opts) => logs(&prefix, &opts),
            Err(e) => {
                eprintln!("{e}");
                eprintln!();
                print_usage();
                process::exit(2);
            }
        },
        ["uninstall"] => uninstall(&prefix, false),
        ["uninstall", "--keep-user-rules"] => uninstall(&prefix, true),
        _ => {
            eprintln!("Unknown command: {}", cmd_args.join(" "));
            eprintln!();
            print_usage();
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod daemon_arg_tests {
    use super::*;
    use std::path::PathBuf;

    fn pfx() -> PathBuf {
        PathBuf::from("/tmp/prempti-test")
    }

    #[test]
    fn defaults_when_no_flags() {
        let opts = parse_daemon_args(&[], pfx()).unwrap();
        assert_eq!(opts.prefix, pfx());
        assert!(opts.config_path.is_none());
        assert!(opts.log_rotate_bytes.is_none());
        assert!(opts.log_rotate_keep.is_none());
        assert!(opts.stop_timeout_secs.is_none());
    }

    #[test]
    fn prefix_space_form() {
        let opts = parse_daemon_args(&["--prefix", "/opt/prempti"], pfx()).unwrap();
        assert_eq!(opts.prefix, PathBuf::from("/opt/prempti"));
    }

    #[test]
    fn prefix_equals_form() {
        let opts = parse_daemon_args(&["--prefix=/opt/prempti"], pfx()).unwrap();
        assert_eq!(opts.prefix, PathBuf::from("/opt/prempti"));
    }

    #[test]
    fn all_overrides_parsed() {
        let opts = parse_daemon_args(
            &[
                "--config",
                "/etc/sv.yaml",
                "--log-rotate-bytes",
                "1048576",
                "--log-rotate-keep",
                "7",
                "--stop-timeout-secs",
                "45",
            ],
            pfx(),
        )
        .unwrap();
        assert_eq!(opts.config_path, Some(PathBuf::from("/etc/sv.yaml")));
        assert_eq!(opts.log_rotate_bytes, Some(1_048_576));
        assert_eq!(opts.log_rotate_keep, Some(7));
        assert_eq!(opts.stop_timeout_secs, Some(45));
    }

    #[test]
    fn unknown_flag_errors() {
        assert!(parse_daemon_args(&["--bogus"], pfx()).is_err());
    }

    #[test]
    fn missing_value_errors() {
        assert!(parse_daemon_args(&["--prefix"], pfx()).is_err());
        assert!(parse_daemon_args(&["--log-rotate-bytes"], pfx()).is_err());
    }

    #[test]
    fn invalid_number_errors() {
        let err = parse_daemon_args(&["--log-rotate-bytes", "lots"], pfx()).unwrap_err();
        assert!(err.contains("invalid"), "got: {err}");
    }
}

#[cfg(test)]
mod windows_command_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn start_command_includes_file_and_prefix() {
        let launcher = PathBuf::from("C:/prempti/bin/prempti-launcher.ps1");
        let prefix = PathBuf::from("C:/prempti");
        let cmd = build_start_powershell_command(&launcher, &prefix);
        assert!(
            cmd.contains("'-File','\"C:/prempti/bin/prempti-launcher.ps1\"'"),
            "missing -File arg: {cmd}"
        );
        assert!(
            cmd.contains("'-Prefix','\"C:/prempti\"'"),
            "missing -Prefix arg: {cmd}"
        );
        assert!(cmd.starts_with("Start-Process "), "got: {cmd}");
    }

    #[test]
    fn start_command_quotes_paths_with_spaces() {
        // Start-Process -ArgumentList does not auto-quote elements that
        // contain spaces; without explicit "..." wrapping the receiving
        // powershell would split "Program Files" into two tokens.
        let launcher = PathBuf::from("C:/Program Files/Foo/launcher.ps1");
        let prefix = PathBuf::from("C:/Program Files/Foo");
        let cmd = build_start_powershell_command(&launcher, &prefix);
        assert!(
            cmd.contains("'-File','\"C:/Program Files/Foo/launcher.ps1\"'"),
            "path-with-spaces -File not quoted: {cmd}"
        );
        assert!(
            cmd.contains("'-Prefix','\"C:/Program Files/Foo\"'"),
            "path-with-spaces -Prefix not quoted: {cmd}"
        );
    }

    #[test]
    fn start_command_escapes_apostrophes_in_paths() {
        // PowerShell single-quoted strings escape `'` by doubling it.
        // A user named O'Brien (or an INSTALLDIR path containing `'`)
        // would otherwise terminate the surrounding `'...'` literal
        // before Start-Process ever runs.
        let launcher = PathBuf::from("C:/Users/O'Brien/bin/launcher.ps1");
        let prefix = PathBuf::from("C:/Users/O'Brien");
        let cmd = build_start_powershell_command(&launcher, &prefix);
        assert!(
            cmd.contains("'-File','\"C:/Users/O''Brien/bin/launcher.ps1\"'"),
            "apostrophe not escaped in -File: {cmd}"
        );
        assert!(
            cmd.contains("'-Prefix','\"C:/Users/O''Brien\"'"),
            "apostrophe not escaped in -Prefix: {cmd}"
        );
    }

    #[test]
    fn ps_single_quote_escape_doubles_apostrophes() {
        assert_eq!(ps_single_quote_escape(""), "");
        assert_eq!(ps_single_quote_escape("plain"), "plain");
        assert_eq!(ps_single_quote_escape("O'Brien"), "O''Brien");
        assert_eq!(ps_single_quote_escape("a'b'c"), "a''b''c");
        // Backslashes and double quotes are NOT special inside `'...'`.
        assert_eq!(
            ps_single_quote_escape(r#"C:\Users\test\"path\""#),
            r#"C:\Users\test\"path\""#
        );
    }

    #[test]
    fn windows_path_compare_handles_case_slashes_and_extended_prefix() {
        let target = PathBuf::from(r"C:\Users\Me\AppData\Local\prempti\bin\falco.exe");
        assert!(windows_paths_equal(
            "c:/users/me/appdata/local/prempti/bin/falco.exe",
            &target
        ));
        assert!(windows_paths_equal(
            r"\\?\C:\Users\Me\AppData\Local\prempti\bin\falco.exe",
            &target
        ));
        assert!(!windows_paths_equal(r"C:\Other\falco.exe", &target));
    }

    #[test]
    fn falco_process_json_filters_to_installed_path() {
        let target = PathBuf::from(r"C:\Users\Me\AppData\Local\prempti\bin\falco.exe");
        let json = serde_json::json!([
            {"Id": 101, "Path": r"C:\Other\falco.exe"},
            {"Id": 202, "Path": r"C:\Users\Me\AppData\Local\prempti\bin\falco.exe"},
            {"Id": 303, "Path": "C:/Users/Me/AppData/Local/prempti/bin/falco.exe"},
            {"Id": 404, "Path": r"\\?\C:\Users\Me\AppData\Local\prempti\bin\falco.exe"},
            {"Id": 505, "Path": serde_json::Value::Null},
            {"Id": "606", "Path": r"C:\Users\Me\AppData\Local\prempti\bin\falco.exe"}
        ])
        .to_string();
        assert_eq!(
            falco_pids_from_process_json(&json, &target),
            vec![202, 303, 404]
        );
    }

    #[test]
    fn falco_process_json_accepts_single_object() {
        let target = PathBuf::from(r"D:\prempti\bin\falco.exe");
        let json = serde_json::json!({"Id": 42, "Path": r"d:\PREMPTI\bin\falco.exe"}).to_string();
        assert_eq!(falco_pids_from_process_json(&json, &target), vec![42]);
    }

    #[test]
    fn run_key_value_includes_file_and_prefix() {
        let launcher = PathBuf::from("D:/install/bin/prempti-launcher.ps1");
        let prefix = PathBuf::from("D:/install");
        let cmd = build_run_key_value(&launcher, &prefix);
        assert!(
            cmd.contains("-File \"D:/install/bin/prempti-launcher.ps1\""),
            "missing -File: {cmd}"
        );
        assert!(
            cmd.contains("-Prefix \"D:/install\""),
            "missing -Prefix: {cmd}"
        );
        assert!(cmd.starts_with("powershell "), "got: {cmd}");
    }

    #[test]
    fn start_command_uses_hidden_window() {
        let cmd = build_start_powershell_command(Path::new("a/launcher.ps1"), Path::new("a"));
        assert!(cmd.contains("'-WindowStyle','Hidden'"));
        assert!(cmd.ends_with("-WindowStyle Hidden"));
    }
}

#[cfg(test)]
mod uninstall_tests {
    use super::{keep_user_rules_cleanup, remove_path};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn tmpdir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("prempti-uninstall-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(p: &Path, contents: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, contents).unwrap();
    }

    #[test]
    fn remove_path_handles_files_and_dirs() {
        let root = tmpdir("remove-path");
        let file = root.join("a.txt");
        let dir = root.join("d");
        write_file(&file, "x");
        write_file(&dir.join("nested.txt"), "y");

        remove_path(&file).unwrap();
        remove_path(&dir).unwrap();

        assert!(!file.exists());
        assert!(!dir.exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn keep_user_rules_cleanup_removes_seen_yaml_and_default_rules() {
        let root = tmpdir("keep-user-rules");

        // Mirror the installed layout that uninstall encounters.
        write_file(&root.join("bin/premptictl"), "");
        write_file(&root.join("config/falco.yaml"), "");
        write_file(&root.join("share/coding_agent.so"), "");
        write_file(&root.join("rules/seen.yaml"), "rules:\n");
        write_file(&root.join("rules/default/coding_agents_rules.yaml"), "");
        write_file(&root.join("rules/user/my_rule.yaml"), "preserve me");

        keep_user_rules_cleanup(&root);

        // Sibling dirs gone.
        assert!(!root.join("bin").exists(), "bin/ should be removed");
        assert!(!root.join("config").exists(), "config/ should be removed");
        assert!(!root.join("share").exists(), "share/ should be removed");

        // Inside rules/, only user/ survives.
        assert!(
            !root.join("rules/seen.yaml").exists(),
            "rules/seen.yaml must be removed (the bug this test guards)"
        );
        assert!(
            !root.join("rules/default").exists(),
            "rules/default/ should be removed"
        );
        assert!(
            root.join("rules/user/my_rule.yaml").exists(),
            "rules/user/* must survive"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn keep_user_rules_cleanup_tolerates_missing_rules_dir() {
        let root = tmpdir("missing-rules");
        write_file(&root.join("bin/premptictl"), "");

        // No rules/ at all — must not panic.
        keep_user_rules_cleanup(&root);

        assert!(!root.join("bin").exists());
        let _ = fs::remove_dir_all(&root);
    }
}
