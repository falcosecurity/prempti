use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

const READ_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL: Duration = Duration::from_millis(200);
const MAX_REQUEST_BYTES: u64 = 256;

/// State exposed to the control listener for STATUS responses.
pub struct SharedState {
    pub falco_pid: AtomicU32,
    pub started_unix_ms: u64,
    pub rotated: Arc<AtomicU32>,
}

/// Stop reasons sent by the control listener to the supervisor's main loop.
pub enum ControlEvent {
    StopRequested,
}

/// Bind the supervisor socket. Mirrors `socket_server::prepare_listener`:
/// abort if a live peer answers (another supervisor is running for this
/// prefix), otherwise clear any stale file and rebind.
///
/// On Unix, the run directory is created mode 0700 and the socket is
/// chmod'd to 0600 after bind. Without this, another local user with
/// traversal access to the install prefix could connect and send `STOP`.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if has_live_peer(path) {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "supervisor socket {} is already in use by another \
                 Prempti daemon",
                path.display()
            ),
        ));
    }
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict_dir_mode(parent);
    }
    let listener = UnixListener::bind(path)?;
    restrict_socket_mode(path);
    Ok(listener)
}

#[cfg(unix)]
fn restrict_dir_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        eprintln!(
            "supervisor: warning: failed to chmod 0700 on {}: {e}",
            path.display()
        );
    }
}

#[cfg(unix)]
fn restrict_socket_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "supervisor: warning: failed to chmod 0600 on {}: {e}",
            path.display()
        );
    }
}

#[cfg(windows)]
fn restrict_dir_mode(_path: &Path) {
    // Windows: %LOCALAPPDATA% inherits per-user ACLs from the user profile,
    // which already excludes other local users by default.
}

#[cfg(windows)]
fn restrict_socket_mode(_path: &Path) {}

fn has_live_peer(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    UnixStream::connect(path).is_ok()
}

/// Run the listener loop in a background thread.
pub fn start(
    listener: UnixListener,
    state: Arc<SharedState>,
    event_tx: Sender<ControlEvent>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    listener.set_nonblocking(true)?;
    let handle = thread::Builder::new()
        .name("prempti-supervisor-ctrl".to_string())
        .spawn(move || run(listener, state, event_tx, shutdown))?;
    Ok(handle)
}

fn run(
    listener: UnixListener,
    state: Arc<SharedState>,
    event_tx: Sender<ControlEvent>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = handle_connection(stream, &state, &event_tx) {
                    eprintln!("supervisor: control connection error: {e}");
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(e) => {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                eprintln!("supervisor: control accept error: {e}");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    state: &SharedState,
    event_tx: &Sender<ControlEvent>,
) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_REQUEST_BYTES)).read_line(&mut line)?;
    let cmd = line.trim();
    let response = dispatch(cmd, state, event_tx);
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn dispatch(cmd: &str, state: &SharedState, event_tx: &Sender<ControlEvent>) -> String {
    match cmd {
        "STOP" => {
            // Best-effort: if the receiver is gone, the supervisor is
            // already shutting down — caller still gets OK.
            let _ = event_tx.send(ControlEvent::StopRequested);
            "OK\n".to_string()
        }
        "STATUS" => format_status(state),
        "" => "ERR empty\n".to_string(),
        _ => "ERR unknown\n".to_string(),
    }
}

fn format_status(state: &SharedState) -> String {
    let sup_pid = std::process::id();
    let falco_pid = state.falco_pid.load(Ordering::Relaxed);
    let started = state.started_unix_ms;
    let rotated = state.rotated.load(Ordering::Relaxed);
    format!("OK pid={sup_pid} falco_pid={falco_pid} started={started} rotated={rotated}\n")
}

/// Connect to a running supervisor and send a single command.
/// Returns the trimmed response line. Used by `ctl stop` on Windows
/// and for ad-hoc status queries.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn send_command(socket_path: &Path, cmd: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    stream.write_all(cmd.as_bytes())?;
    if !cmd.ends_with('\n') {
        stream.write_all(b"\n")?;
    }
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    Ok(response.trim_end_matches('\n').to_string())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn supervisor_socket_path(prefix: &Path) -> PathBuf {
    prefix.join("run").join("supervisor.sock")
}

/// Parse the `pid=N` field out of a STATUS response. Used by `ctl stop`
/// on Windows to locate the supervisor process for shutdown polling.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn parse_supervisor_pid(response: &str) -> Option<u32> {
    response
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("pid=")?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn fresh_state() -> Arc<SharedState> {
        Arc::new(SharedState {
            falco_pid: AtomicU32::new(12345),
            started_unix_ms: 1_700_000_000_000,
            rotated: Arc::new(AtomicU32::new(2)),
        })
    }

    #[test]
    fn stop_sends_event_and_returns_ok() {
        let state = fresh_state();
        let (tx, rx) = mpsc::channel();
        let resp = dispatch("STOP", &state, &tx);
        assert_eq!(resp, "OK\n");
        assert!(matches!(rx.try_recv(), Ok(ControlEvent::StopRequested)));
    }

    #[test]
    fn status_includes_pids_and_counters() {
        let state = fresh_state();
        let (tx, _rx) = mpsc::channel();
        let resp = dispatch("STATUS", &state, &tx);
        assert!(resp.starts_with("OK "), "got: {resp}");
        assert!(resp.contains("falco_pid=12345"), "got: {resp}");
        assert!(resp.contains("started=1700000000000"), "got: {resp}");
        assert!(resp.contains("rotated=2"), "got: {resp}");
        assert!(resp.ends_with('\n'));
    }

    #[test]
    fn parses_pid_from_status_response() {
        let resp = "OK pid=12345 falco_pid=67890 started=1700000000000 rotated=2";
        assert_eq!(parse_supervisor_pid(resp), Some(12345));
    }

    #[test]
    fn parse_pid_returns_none_when_absent() {
        assert_eq!(parse_supervisor_pid("ERR unknown"), None);
        assert_eq!(parse_supervisor_pid("OK falco_pid=42"), None);
    }

    #[test]
    fn unknown_command_returns_err() {
        let state = fresh_state();
        let (tx, _rx) = mpsc::channel();
        assert_eq!(dispatch("HELLO", &state, &tx), "ERR unknown\n");
        assert_eq!(dispatch("", &state, &tx), "ERR empty\n");
    }

    fn temp_socket_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "prempti-ctrl-{}-{label}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp socket dir");
        dir
    }

    /// Try to bind in `dir`, skipping the test (and printing why) if the
    /// environment refuses AF_UNIX bind there. Sandboxed CI runners
    /// (Landlock, restricted seccomp, certain container `/tmp` policies)
    /// can block bind with EPERM even though the path is writable.
    fn try_bind_or_skip(dir: &Path, label: &str) -> Option<(UnixListener, PathBuf)> {
        let sock = dir.join("supervisor.sock");
        match bind(&sock) {
            Ok(l) => Some((l, sock)),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "[skip {label}] cannot bind AF_UNIX in {}: {e}",
                    dir.display()
                );
                None
            }
            Err(e) => panic!("bind failed: {e}"),
        }
    }

    #[test]
    fn end_to_end_stop_round_trip() {
        let dir = temp_socket_dir("e2e-stop");
        let Some((listener, path)) = try_bind_or_skip(&dir, "e2e-stop") else {
            return;
        };
        let state = fresh_state();
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let handle = start(listener, state, tx, shutdown.clone()).unwrap();

        // Give the listener a moment to enter its loop.
        thread::sleep(Duration::from_millis(100));

        let resp = send_command(&path, "STOP").unwrap();
        assert_eq!(resp, "OK");
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)),
            Ok(ControlEvent::StopRequested)
        ));

        shutdown.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bind_chmods_socket_and_run_dir() {
        use std::os::unix::fs::PermissionsExt;
        let parent = std::env::temp_dir().join(format!(
            "prempti-bind-perms-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = parent.join("run");
        let sock = dir.join("supervisor.sock");
        std::fs::create_dir_all(&parent).unwrap();
        let listener = match bind(&sock) {
            Ok(l) => l,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "[skip bind_chmods_socket_and_run_dir] cannot bind AF_UNIX in {}: {e}",
                    parent.display()
                );
                let _ = std::fs::remove_dir_all(&parent);
                return;
            }
            Err(e) => panic!("bind failed: {e}"),
        };
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "run dir should be 0700");
        assert_eq!(sock_mode, 0o600, "socket should be 0600");
        drop(listener);
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn end_to_end_status_round_trip() {
        let dir = temp_socket_dir("e2e-status");
        let Some((listener, path)) = try_bind_or_skip(&dir, "e2e-status") else {
            return;
        };
        let state = fresh_state();
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = mpsc::channel();
        let handle = start(listener, state, tx, shutdown.clone()).unwrap();

        thread::sleep(Duration::from_millis(100));

        let resp = send_command(&path, "STATUS").unwrap();
        assert!(resp.starts_with("OK "), "got: {resp}");
        assert!(resp.contains("falco_pid=12345"));

        shutdown.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
