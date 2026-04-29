pub mod config;
pub mod control;
pub mod pipe_drain;
pub mod rotate;
pub mod stop;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::hook;
use config::SupervisorConfig;
use control::{ControlEvent, SharedState};

/// Options parsed from the `ctl daemon` command line. Fields override the
/// supervisor config file when set.
#[derive(Debug)]
pub struct DaemonOpts {
    pub prefix: PathBuf,
    pub config_path: Option<PathBuf>,
    pub log_rotate_bytes: Option<u64>,
    pub log_rotate_keep: Option<u32>,
    pub stop_timeout_secs: Option<u64>,
}

/// Async-signal-safe shutdown flag. Set by the platform signal handler;
/// polled by the signal-watcher thread, which forwards a synchronous
/// ControlEvent into the main loop.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn run(opts: DaemonOpts) -> Result<i32, String> {
    let prefix = opts.prefix.clone();
    let cfg = resolve_config(&opts)?;
    let paths = ResolvedPaths::from_prefix(&prefix);

    preflight(&paths)?;

    let listener = control::bind(&paths.supervisor_sock)
        .map_err(|e| format!("failed to bind {}: {e}", paths.supervisor_sock.display()))?;

    match hook::add(&prefix) {
        Ok(hook::AddResult::Added(p)) => eprintln!("supervisor: hook registered in {}", p.display()),
        Ok(hook::AddResult::AlreadyRegistered) => {
            eprintln!("supervisor: hook already registered");
        }
        Err(e) => {
            cleanup_socket(&paths.supervisor_sock);
            return Err(format!("failed to register hook: {e}"));
        }
    }

    install_signal_handlers();

    let mut child = match spawn_falco(&paths) {
        Ok(c) => c,
        Err(e) => {
            let _ = hook::remove();
            cleanup_socket(&paths.supervisor_sock);
            return Err(e);
        }
    };

    let rotated = Arc::new(AtomicU32::new(0));
    let started_unix_ms = unix_ms_now();
    let state = Arc::new(SharedState {
        falco_pid: AtomicU32::new(child.id()),
        started_unix_ms,
        rotated: rotated.clone(),
    });

    let shutdown_listener = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = mpsc::channel::<ControlEvent>();

    let stdout = child.stdout.take().expect("Falco stdout piped");
    let stderr = child.stderr.take().expect("Falco stderr piped");

    let stdout_handle = spawn_drain(
        stdout,
        paths.falco_log.clone(),
        cfg.log_rotate_bytes,
        cfg.log_rotate_keep,
        rotated.clone(),
        "stdout",
    );
    let stderr_handle = spawn_drain(
        stderr,
        paths.falco_err.clone(),
        cfg.log_rotate_bytes,
        cfg.log_rotate_keep,
        rotated.clone(),
        "stderr",
    );

    let control_handle = control::start(
        listener,
        state.clone(),
        event_tx.clone(),
        shutdown_listener.clone(),
    )
    .map_err(|e| format!("failed to start control listener: {e}"))?;

    let signal_handle = spawn_signal_watcher(event_tx.clone());
    let waiter_handle = spawn_falco_waiter(child.id(), event_tx);

    eprintln!("supervisor: Falco running (pid {})", child.id());

    // Main loop: block until one of the watcher threads forwards an event,
    // then begin shutdown. Any event is a stop signal.
    let _ = event_rx.recv_timeout(Duration::from_secs(60 * 60 * 24 * 365));
    drain_pending_events(&event_rx);

    let exit_code = perform_shutdown(
        &mut child,
        Duration::from_secs(cfg.stop_timeout_secs),
    );

    // Stop accepting new control connections, then join helper threads.
    shutdown_listener.store(true, Ordering::Relaxed);
    let _ = control_handle.join();
    let _ = signal_handle.join();
    let _ = waiter_handle.join();
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    // Best-effort cleanup. None of these failing should mask the exit code.
    if let Err(e) = hook::remove() {
        eprintln!("supervisor: failed to remove hook: {e}");
    }
    cleanup_socket(&paths.supervisor_sock);

    Ok(exit_code)
}

struct ResolvedPaths {
    falco_bin: PathBuf,
    falco_config: PathBuf,
    falco_log: PathBuf,
    falco_err: PathBuf,
    supervisor_sock: PathBuf,
}

impl ResolvedPaths {
    fn from_prefix(prefix: &Path) -> Self {
        let log = prefix.join("log");
        Self {
            falco_bin: falco_bin_path(prefix),
            falco_config: prefix.join("config").join("falco.yaml"),
            falco_log: log.join("falco.log"),
            falco_err: log.join("falco.err"),
            supervisor_sock: prefix.join("run").join("supervisor.sock"),
        }
    }
}

fn falco_bin_path(prefix: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        prefix.join("bin").join("falco.exe")
    }
    #[cfg(unix)]
    {
        prefix.join("bin").join("falco")
    }
}

fn resolve_config(opts: &DaemonOpts) -> Result<SupervisorConfig, String> {
    let config_path = opts
        .config_path
        .clone()
        .unwrap_or_else(|| opts.prefix.join("config").join("supervisor.yaml"));
    let mut cfg = SupervisorConfig::load(&config_path)?;
    if let Some(v) = opts.log_rotate_bytes {
        cfg.log_rotate_bytes = v;
    }
    if let Some(v) = opts.log_rotate_keep {
        cfg.log_rotate_keep = v;
    }
    if let Some(v) = opts.stop_timeout_secs {
        cfg.stop_timeout_secs = v;
    }
    Ok(cfg)
}

fn preflight(paths: &ResolvedPaths) -> Result<(), String> {
    if !paths.falco_bin.exists() {
        return Err(format!(
            "Falco binary not found at {}",
            paths.falco_bin.display()
        ));
    }
    if !paths.falco_config.exists() {
        return Err(format!(
            "Falco config not found at {}",
            paths.falco_config.display()
        ));
    }
    if let Some(parent) = paths.falco_log.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create log dir {}: {e}", parent.display()))?;
    }
    // Open both log files for append to confirm we can write.
    for p in [&paths.falco_log, &paths.falco_err] {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map_err(|e| format!("failed to open {}: {e}", p.display()))?;
    }
    Ok(())
}

fn spawn_falco(paths: &ResolvedPaths) -> Result<std::process::Child, String> {
    Command::new(&paths.falco_bin)
        .args([
            "-U",
            "-c",
            &paths.falco_config.to_string_lossy(),
            "--disable-source",
            "syscall",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn Falco: {e}"))
}

fn spawn_drain<R: std::io::Read + Send + 'static>(
    source: R,
    log_path: PathBuf,
    max_bytes: u64,
    keep: u32,
    rotated: Arc<AtomicU32>,
    label: &'static str,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name(format!("cak-supervisor-{label}"))
        .spawn(move || {
            if let Err(e) = pipe_drain::drain(source, log_path.clone(), max_bytes, keep, rotated) {
                eprintln!(
                    "supervisor: {label} drain ended with error on {}: {e}",
                    log_path.display()
                );
            }
        })
        .expect("spawn drain thread")
}

fn spawn_signal_watcher(event_tx: Sender<ControlEvent>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("cak-supervisor-signal".to_string())
        .spawn(move || loop {
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                let _ = event_tx.send(ControlEvent::StopRequested);
                return;
            }
            thread::sleep(Duration::from_millis(200));
        })
        .expect("spawn signal watcher")
}

fn spawn_falco_waiter(pid: u32, event_tx: Sender<ControlEvent>) -> thread::JoinHandle<()> {
    // We can't move the Child handle here because the main thread owns it.
    // Instead, poll the OS via a platform-specific check. On Unix we use
    // libc::kill(pid, 0); on Windows we use OpenProcess + GetExitCodeProcess.
    thread::Builder::new()
        .name("cak-supervisor-waiter".to_string())
        .spawn(move || loop {
            if !process_alive(pid) {
                let _ = event_tx.send(ControlEvent::StopRequested);
                return;
            }
            thread::sleep(Duration::from_millis(500));
        })
        .expect("spawn falco waiter")
}

#[cfg(unix)]
pub(crate) fn process_alive(pid: u32) -> bool {
    // kill(pid, 0) returns 0 if the process exists and we have permission.
    // ESRCH means the process is gone; EPERM means it exists but we can't
    // signal it (still alive for our purposes).
    let rc = unsafe { libc::kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    err.raw_os_error() != Some(libc::ESRCH)
}

#[cfg(windows)]
pub(crate) fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if h.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE as u32
    }
}

fn drain_pending_events(rx: &mpsc::Receiver<ControlEvent>) {
    while rx.try_recv().is_ok() {}
}

fn perform_shutdown(child: &mut std::process::Child, timeout: Duration) -> i32 {
    // If Falco already exited (waiter thread fired), try_wait collects it.
    if let Ok(Some(status)) = child.try_wait() {
        return exit_code_from(status);
    }
    match stop::graceful_stop(child, timeout) {
        Ok(status) => exit_code_from(status),
        Err(e) => {
            eprintln!("supervisor: graceful_stop error: {e}");
            1
        }
    }
}

fn exit_code_from(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        // Killed by signal on Unix: report a non-zero code so init systems
        // can decide whether to restart based on Falco's exit reason.
        if status.success() {
            0
        } else {
            1
        }
    })
}

fn cleanup_socket(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Signal handlers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn install_signal_handlers() {
    extern "C" fn handler(_: libc::c_int) {
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }
    unsafe {
        let h = handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGHUP, h);
    }
}

#[cfg(windows)]
fn install_signal_handlers() {
    use windows_sys::Win32::Foundation::BOOL;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn handler(_: u32) -> BOOL {
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        1 // TRUE: handled
    }
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

