use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

mod daemon;
mod hook;
mod logs_pretty;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "coding-agents-kit";

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
        PathBuf::from(home_dir()).join(".coding-agents-kit")
    }
    #[cfg(windows)]
    {
        // Prefer deriving the prefix from the ctl's own location: if ctl
        // lives at `<prefix>\bin\coding-agents-kit-ctl.exe`, `<prefix>` is
        // the right answer regardless of what INSTALLDIR the MSI used. This
        // keeps ctl commands (enable/disable/start/stop) aligned with a
        // custom install path picked via WixUI_InstallDir. Fall back to
        // %LOCALAPPDATA%\coding-agents-kit when current_exe isn't a `bin`
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
        PathBuf::from(home_dir()).join("coding-agents-kit")
    }
}

fn plugin_config_path(prefix: &PathBuf) -> PathBuf {
    prefix.join("config/falco.coding_agents_plugin.yaml")
}

fn print_restart_warning() {
    eprintln!();
    eprintln!("  WARNING: Applying a mode change requires stopping and starting the");
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
    if mode != "guardrails" && mode != "monitor" {
        eprintln!("error: mode must be 'guardrails' or 'monitor'");
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

    fs::write(&config_path, new_data).unwrap_or_else(|e| {
        eprintln!("error writing {}: {e}", config_path.display());
        process::exit(1);
    });

    if !was_running {
        println!("Mode set to: {mode}");
        println!("(Service is not running. Start it to apply: coding-agents-kit-ctl start)");
        return;
    }

    println!("Restarting service to apply mode change...");
    print_restart_warning();
    eprintln!();

    service_restart_inner(prefix, hook_was_registered);

    println!();
    println!("Mode set to: {mode}");
}

/// Stop the service, re-register the hook to keep the gap fail-closed, then
/// start the service again. Shared by `ctl restart` and `ctl mode`.
fn service_restart_inner(prefix: &PathBuf, restore_hook: bool) {
    service_stop(false);

    // The supervisor removes the hook on stop; without re-adding it here,
    // the gap between stop and start would let tool calls through
    // unchecked. `hook::add` is idempotent.
    if restore_hook {
        if let Err(e) = hook::add(prefix) {
            eprintln!("warning: failed to re-register hook during restart: {e}");
        }
    }

    service_start(prefix);
}

fn service_restart(prefix: &PathBuf) {
    let restore_hook = hook::is_registered();
    println!("Restarting service...");
    eprintln!();
    service_restart_inner(prefix, restore_hook);
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
        println!("Wait a moment and run `coding-agents-kit-ctl health` to verify.");
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
}

#[cfg(target_os = "macos")]
const PLIST_LABEL: &str = "dev.falcosecurity.coding-agents-kit";

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
        eprintln!("Is coding-agents-kit installed?");
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
        eprintln!("Is coding-agents-kit installed?");
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
}

// ---------------------------------------------------------------------------
// Windows service management
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(target_os = "windows")]
const RUN_VALUE_NAME: &str = "CodingAgentsKit";

#[cfg(target_os = "windows")]
fn is_falco_running() -> bool {
    falco_pids().is_some()
}

#[cfg(target_os = "windows")]
fn is_service_running() -> bool {
    is_falco_running()
}

/// Return the list of running `falco.exe` PIDs, or `None` on error / no match.
/// Uses CSV output (`/FO CSV /NH`) so the parser is robust against localized
/// header text in non-English Windows installations.
#[cfg(target_os = "windows")]
fn falco_pids() -> Option<Vec<u32>> {
    let out = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq falco.exe", "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Each line is: "falco.exe","<pid>","<session>","<session#>","<mem>"
    let pids: Vec<u32> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 2 {
                return None;
            }
            fields[1].trim_matches('"').parse::<u32>().ok()
        })
        .collect();
    if pids.is_empty() {
        None
    } else {
        Some(pids)
    }
}

/// Render the PowerShell `-Command` string used by `ctl start` on Windows.
///
/// `-Prefix` must be passed explicitly: the MSI supports a custom install
/// directory and `default_prefix()` derives that from the installed
/// ctl.exe location, but the launcher itself defaults to
/// `%LOCALAPPDATA%\coding-agents-kit` when `-Prefix` is omitted, which
/// then fails to find ctl.exe under a non-default prefix.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn build_start_powershell_command(launcher: &Path, prefix: &Path) -> String {
    format!(
        "Start-Process -FilePath 'powershell.exe' -ArgumentList @(\
'-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden',\
'-File','{}','-Prefix','{}') -WindowStyle Hidden",
        launcher.display(),
        prefix.display()
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
    if is_falco_running() {
        println!("Service already running.");
        return;
    }
    let launcher = prefix.join("bin").join("coding-agents-kit-launcher.ps1");
    if !launcher.exists() {
        eprintln!("Launcher not found: {}", launcher.display());
        eprintln!("Is coding-agents-kit installed?");
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
    // Poll briefly to verify Falco actually started.
    let mut started = false;
    for _ in 0..6 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if is_falco_running() {
            started = true;
            break;
        }
    }
    if started {
        println!("Service started.");
    } else {
        println!("Service starting (Falco not yet detected \u{2014} check logs).");
    }
}

#[cfg(target_os = "windows")]
fn legacy_falco_kill_fallback(warn_hook: bool) {
    if let Some(pids) = falco_pids() {
        for pid in &pids {
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        println!("Service stopped (legacy fallback).");
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
        // kill). Fall back to the old taskkill path — at least any
        // stray falco.exe from this install gets cleaned up.
        legacy_falco_kill_fallback(warn_hook);
        return;
    };

    // Live supervisor — ask it to shut down and wait for it to exit.
    // Cleanup (graceful Falco stop, drain pipes, hook remove, close
    // logs) runs inside the supervisor before its process exits.
    if let Err(e) = daemon::control::send_command(&sock, "STOP") {
        eprintln!("warning: failed to send STOP to supervisor: {e}");
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while daemon::process_alive(pid) {
        if std::time::Instant::now() >= deadline {
            eprintln!("supervisor did not exit in 30s; force killing pid {pid}");
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    println!("Service stopped.");
    if warn_hook {
        hook::warn_if_still_registered();
    }
}

#[cfg(target_os = "windows")]
fn service_enable() {
    let prefix = default_prefix();
    let launcher = prefix.join("bin").join("coding-agents-kit-launcher.ps1");
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
    match falco_pids() {
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
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

fn uninstall(prefix: &PathBuf, keep_user_rules: bool) {
    println!("=== Uninstalling coding-agents-kit ===");
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
            .join(".config/systemd/user/coding-agents-kit.service");
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

    // 2. Remove the hook (safety net).
    // The service's ExecStopPost (Linux), launcher trap (macOS), or launcher
    // PowerShell `finally` block (Windows) should have removed the hook
    // already. But if the service wasn't running or the stop hooks didn't
    // fire, the hook would stay registered and brick Claude Code.
    println!("Removing Claude Code hook...");
    hook::cli_remove();

    // 3. Remove the installation directory.
    if prefix.exists() {
        if keep_user_rules {
            let user_rules = prefix.join("rules/user");
            if user_rules.is_dir() {
                println!("Preserving user rules: {}", user_rules.display());
                // Remove everything except rules/user/.
                if let Ok(entries) = fs::read_dir(prefix) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        if name != "rules" {
                            let _ = fs::remove_dir_all(entry.path());
                        }
                    }
                }
                // Inside rules/, remove everything except user/.
                let rules_dir = prefix.join("rules");
                if let Ok(entries) = fs::read_dir(&rules_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        if name != "user" {
                            let _ = fs::remove_dir_all(entry.path());
                        }
                    }
                }
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

    // Send a synthetic event through the full pipeline.
    // Uses a harmless Bash "echo" command that should resolve as allow.
    let test_event = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo health-check"},"session_id":"health-check","cwd":"/tmp","tool_use_id":"health-check"}"#;

    let output = Command::new(&interceptor)
        .env("CODING_AGENTS_KIT_SOCKET", &socket)
        .env("CODING_AGENTS_KIT_TIMEOUT_MS", "5000")
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
            let parsed: serde_json::Value = match serde_json::from_str(stdout.trim()) {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("FAIL: interceptor returned malformed JSON");
                    eprintln!("  Output: {}", stdout.trim());
                    process::exit(1);
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
                eprintln!("FAIL: interceptor returned unexpected output");
                eprintln!("  Output: {}", stdout.trim());
                process::exit(1);
            }

            // Denies caused by infrastructure failure (not real rule matches)
            // indicate a broken pipeline. Detect both forms of broker failure:
            // - "broker response timeout": socket connected but no verdict arrived
            // - "broker unavailable": connection refused (service not running)
            if decision == "deny"
                && (reason.contains("broker response timeout")
                    || reason.contains("broker unavailable"))
            {
                eprintln!("FAIL: broker unreachable or timed out while waiting for verdict");
                eprintln!("  Reason: {}", reason);
                process::exit(1);
            }

            // Parse to show a cleaner message.
            if decision == "allow" {
                println!("OK: pipeline healthy (synthetic event → allow)");
            } else if decision == "deny" {
                println!("OK: pipeline healthy (synthetic event → deny)");
                println!("  Note: a deny rule matched the health-check event.");
                println!("  This is expected if you have rules matching Bash commands.");
            } else if decision == "ask" {
                println!("OK: pipeline healthy (synthetic event → ask)");
            } else {
                println!("OK: pipeline responded (unexpected verdict)");
                println!("  Response: {}", stdout.trim());
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
const FALLBACK_BINARY_NAME: &str = "coding-agents-kit-ctl";

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
/// `coding-agents-kit-ctl -f`. The binary name is taken from argv[0] (the
/// way the user actually invoked it), falling back to the on-disk exe name
/// and finally a hardcoded default — never panics.
fn build_logs_cmd_label(opts: &LogsOpts) -> String {
    let mut s = invoked_binary_name();
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
    use std::io::{BufReader, IsTerminal, Write};
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
    let stdout_lock = std::io::stdout();
    let mut writer = stdout_lock.lock();
    let resolver = logs_pretty::FsSessionNameResolver::default();
    if let Err(e) = logs_pretty::run(reader, &mut writer, pretty_opts, resolver) {
        // BrokenPipe is expected when the consumer (e.g., `head`) closes the
        // pipe — exit silently rather than printing an error.
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("logs: {e}");
        }
    }
    let _ = writer.flush();
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
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!("coding-agents-kit-ctl — manage the coding-agents-kit service");
    eprintln!();
    eprintln!("Usage: coding-agents-kit-ctl <command>");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  hook add         Register the interceptor hook in Claude Code");
    eprintln!("  hook remove      Remove the interceptor hook from Claude Code");
    eprintln!("  hook status      Check if the hook is registered");
    eprintln!();
    eprintln!("  mode             Show current operational mode");
    eprintln!("  mode guardrails  Switch to guardrails mode (deny/ask enforced)");
    eprintln!("  mode monitor     Switch to monitor mode (all verdicts allow, alerts logged)");
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
    eprintln!("                     --show LIST     verdicts to render: deny,ask,allow,seen,all");
    eprintln!("                                     default: deny,ask,allow (seen filtered)");
    eprintln!("                     --no-color      pretty layout without ANSI colors");
    eprintln!("                     --no-stats      pretty layout without status line");
    eprintln!();
    eprintln!("  daemon [flags]   Run the supervisor (spawns Falco, owns logs and rotation,");
    eprintln!("                   owns the hook lifecycle). Normally invoked by the platform");
    eprintln!("                   service; advanced users can run it manually.");
    eprintln!("                     --prefix PATH              install prefix (default: ~/.coding-agents-kit)");
    eprintln!("                     --config PATH              supervisor config (default: <prefix>/config/supervisor.yaml)");
    eprintln!(
        "                     --log-rotate-bytes N       override config: rotation size threshold"
    );
    eprintln!("                     --log-rotate-keep N        override config: archives to keep");
    eprintln!(
        "                     --stop-timeout-secs N      override config: graceful stop timeout"
    );
    eprintln!();
    eprintln!("  uninstall        Remove coding-agents-kit completely");
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
            println!("coding-agents-kit-ctl {}", env!("CARGO_PKG_VERSION"));
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
        ["hook", "add"] => hook::cli_add(&prefix),
        ["hook", "remove"] => hook::cli_remove(),
        ["hook", "status"] => hook::cli_status(),
        ["mode"] => mode_get(&prefix),
        ["mode", mode] => mode_set(&prefix, mode),
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
        PathBuf::from("/tmp/cak-test")
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
        let opts = parse_daemon_args(&["--prefix", "/opt/cak"], pfx()).unwrap();
        assert_eq!(opts.prefix, PathBuf::from("/opt/cak"));
    }

    #[test]
    fn prefix_equals_form() {
        let opts = parse_daemon_args(&["--prefix=/opt/cak"], pfx()).unwrap();
        assert_eq!(opts.prefix, PathBuf::from("/opt/cak"));
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
        let launcher = PathBuf::from("C:/cak/bin/coding-agents-kit-launcher.ps1");
        let prefix = PathBuf::from("C:/cak");
        let cmd = build_start_powershell_command(&launcher, &prefix);
        assert!(
            cmd.contains("'-File','C:/cak/bin/coding-agents-kit-launcher.ps1'"),
            "missing -File arg: {cmd}"
        );
        assert!(
            cmd.contains("'-Prefix','C:/cak'"),
            "missing -Prefix arg: {cmd}"
        );
        assert!(cmd.starts_with("Start-Process "), "got: {cmd}");
    }

    #[test]
    fn run_key_value_includes_file_and_prefix() {
        let launcher = PathBuf::from("D:/install/bin/coding-agents-kit-launcher.ps1");
        let prefix = PathBuf::from("D:/install");
        let cmd = build_run_key_value(&launcher, &prefix);
        assert!(
            cmd.contains("-File \"D:/install/bin/coding-agents-kit-launcher.ps1\""),
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
