use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

use crossbeam_channel::Sender;

use crate::broker::{Broker, BrokerStream};
use crate::event::{EventData, InterceptorRequest};

/// Max request size from an interceptor (64KB + envelope overhead).
const MAX_REQUEST_SIZE: u64 = 128 * 1024;

/// Read timeout for interceptor connections (prevents slowloris).
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Accept timeout for the listener. The accept loop checks the broker's shutdown
/// flag after each timeout, enabling clean exit on `Plugin::Drop`.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

/// Probe the socket path to detect whether another process is already
/// listening on it. Returns `Ok(true)` when a live peer answered the
/// connection (safe to abort — don't touch the file), `Ok(false)` when
/// the file is missing or the peer is dead (safe to remove and rebind).
fn has_live_peer(socket_path: &str) -> std::io::Result<bool> {
    if !Path::new(socket_path).exists() {
        return Ok(false);
    }
    match UnixStream::connect(socket_path) {
        Ok(_) => Ok(true),
        // ConnectionRefused on Unix or the equivalent NotFound / BrokenPipe
        // on Windows AF_UNIX all mean "file exists but nobody is listening"
        // — i.e. a stale socket from a previous crash.
        Err(_) => Ok(false),
    }
}

/// Prepare the listener: abort if another server is live, otherwise remove
/// any stale socket file and bind a fresh listener. Returns an error that
/// `Plugin::new()` propagates to Falco so a second Falco instance cannot
/// clobber the running one's socket file.
///
/// Plugin lifecycle: `Plugin::new()` runs exactly once per Falco process
/// (config-driven hot-reload is disabled — see `configs/falco.yaml`). All
/// config changes go through `premptictl` as an explicit stop →
/// rewrite → start cycle, so by the time `prepare_listener` is called the
/// previous instance has already exited and released its listener.
///
/// Note: there is a narrow TOCTOU between `has_live_peer()` returning
/// `false` and `bind()` succeeding below. If a second instance were to come
/// up in that window we would clear its stale file and rebind, leaving the
/// race winner. That is the correct outcome for the collision-panic class
/// of bug this code exists to prevent; do not "fix" it by guarding with a
/// lock (e.g. `AlreadyExists`), which would turn legitimate stale-file
/// cleanup into a hard failure and reintroduce the panic risk.
fn prepare_listener(socket_path: &str) -> anyhow::Result<UnixListener> {
    if has_live_peer(socket_path).unwrap_or(false) {
        anyhow::bail!(
            "broker socket {socket_path} is already in use by another \
             Prempti Falco instance. Stop it first or set a \
             different `socket_path` in falco.coding_agents_plugin.yaml \
             (plugin init_config) before starting this one."
        );
    }

    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    UnixListener::bind(socket_path)
        .map_err(|e| anyhow::anyhow!("failed to bind Unix socket at {socket_path}: {e}"))
}

/// Start the broker socket server in a background thread.
///
/// Listens on a Unix domain socket at `socket_path` (all platforms).
/// On Windows, uses the `uds_windows` crate for AF_UNIX support.
///
/// Binding happens synchronously on the caller's thread so any address-in-use
/// error can be reported back to Falco as a clean plugin init failure.
pub fn start(
    socket_path: String,
    event_tx: Sender<EventData>,
    broker: Arc<Broker>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let listener = prepare_listener(&socket_path)?;
    log::info!("broker listening on {}", socket_path);

    std::thread::Builder::new()
        .name("prempti-socket-server".to_string())
        .spawn(move || run_server(listener, &socket_path, &event_tx, &broker))
        .map_err(|e| anyhow::anyhow!("failed to spawn socket server thread: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_socket_path(label: &str) -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("prempti-sock-{}-{}.sock", std::process::id(), label));
        path.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn prepare_listener_on_empty_path_succeeds() {
        let path = temp_socket_path("empty");
        let _ = std::fs::remove_file(&path);
        let listener = prepare_listener(&path).expect("bind should succeed");
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prepare_listener_rebinds_over_stale_socket_file() {
        let path = temp_socket_path("stale");
        // Simulate a leftover socket file from a previously crashed Falco.
        std::fs::write(&path, b"").expect("create stub file");
        // No process is listening, so prepare_listener should treat it as
        // stale and rebind cleanly.
        let listener = prepare_listener(&path).expect("stale file should be cleared");
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prepare_listener_refuses_to_clobber_live_peer() {
        // A different Falco process holding the socket must be refused so the
        // running server keeps working.
        let path = temp_socket_path("live");
        let _ = std::fs::remove_file(&path);
        let first = prepare_listener(&path).expect("first bind");
        let second = prepare_listener(&path);
        assert!(second.is_err(), "expected error when another server is live");
        let err = format!("{}", second.unwrap_err());
        assert!(
            err.contains("already in use"),
            "error should mention 'already in use', got: {err}"
        );
        // Sanity: the first listener is still usable — a client can connect.
        let _client = UnixStream::connect(&path).expect("original listener survived");
        drop(first);
        let _ = std::fs::remove_file(&path);
    }

    /// Pins the post-accept `set_nonblocking(false)` fix in `run_server`.
    ///
    /// macOS's `accept(2)` inherits the listener's `O_NONBLOCK` onto the
    /// accepted stream; Linux's does not, and Windows uses `uds_windows`
    /// which doesn't share the BSD inheritance behavior either. Without
    /// clearing the flag on the accepted side, `set_read_timeout` becomes
    /// a no-op against `WouldBlock` and the first read on a request whose
    /// bytes haven't fully landed in the kernel's 8 KB Unix-socket buffer
    /// fails immediately, dropping the stream. On the interceptor side
    /// this surfaced as "broker closed connection" / EPIPE / ENOTCONN
    /// under concurrent load with payloads larger than 8 KB.
    ///
    /// macOS-only: the test relies on the kernel's actual inheritance
    /// behavior rather than forcing it, so it would be testing nothing
    /// meaningful on the other targets.
    #[cfg(target_os = "macos")]
    #[test]
    fn accepted_stream_clears_inherited_nonblock_for_handle_connection_read() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::time::Duration;

        let path = temp_socket_path("nonblock-clear-macos");
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("bind");
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");

        let client_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut client = UnixStream::connect(&client_path).expect("connect");
            // Write the request in chunks with a pause between them so the
            // broker's BufReader::read_line is FORCED to do a follow-up
            // `fill_buf` against an empty kernel buffer. Without the fix
            // line, that follow-up returns WouldBlock immediately even
            // though set_read_timeout was set, because the accepted
            // stream inherited the listener's non-blocking flag and
            // SO_RCVTIMEO has no effect on a non-blocking socket.
            for _ in 0..4 {
                let chunk = vec![b'x'; 4 * 1024];
                client.write_all(&chunk).expect("client write_all chunk");
                std::thread::sleep(Duration::from_millis(50));
            }
            client.write_all(b"\n").expect("client write \\n");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("client shutdown WR");
            // Block until the broker side closes its end. We must NOT drop
            // here — if the writer's fd closes before the broker's
            // `set_read_timeout` runs, `soisdisconnected` propagates onto
            // the broker side and the setsockopt itself returns EINVAL on
            // macOS, which would mask what this test is meant to pin down.
            // The main thread drops its `stream` after the assertions so
            // this read returns Ok(0) and the thread exits cleanly.
            let _ = (&client).read(&mut [0u8; 1]);
        });

        // Poll-accept exactly like `run_server`'s loop.
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };

        // The fix: clear the flag macOS inherited from the listener.
        // Removing this line makes the `read_line` below fail with
        // `WouldBlock` (errno 35) immediately.
        stream
            .set_nonblocking(false)
            .expect("clear inherited non-blocking on accepted stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");

        let mut line = String::new();
        BufReader::new((&stream).take(64 * 1024))
            .read_line(&mut line)
            .expect("read_line should succeed on a blocking stream");
        assert_eq!(line.len(), 16 * 1024 + 1); // 4 × 4 KB chunks + '\n'
        assert!(line.ends_with('\n'));

        // Release the broker side so the writer's blocking read returns
        // Ok(0) and its thread can exit; otherwise `join` deadlocks.
        drop(stream);
        writer.join().expect("writer thread panicked");
        let _ = std::fs::remove_file(&path);
    }
}

/// Accept loop. Listener is already bound. Same implementation on Unix and
/// Windows — `UnixListener` is aliased per-target via the imports above.
fn run_server(
    listener: UnixListener,
    _socket_path: &str,
    event_tx: &Sender<EventData>,
    broker: &Broker,
) {
    // Non-blocking accept + short sleep on WouldBlock lets the loop check the
    // shutdown flag without an extra wake-up mechanism. `UnixListener` does
    // not expose `set_read_timeout`, so polling is the portable option.
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|e| log::warn!("failed to set non-blocking: {}", e));

    loop {
        if broker.is_shutdown() {
            log::info!("socket server shutting down");
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                // macOS (and BSDs) inherit the listener's O_NONBLOCK onto
                // accepted streams; Linux does not. Without this clear,
                // `set_read_timeout` below is a no-op against `WouldBlock`
                // and the first read of any request whose bytes haven't
                // fully landed in the kernel buffer yet fails immediately,
                // dropping the connection. This is what surfaced as
                // "broker closed connection" / EPIPE / ENOTCONN on the
                // interceptor side under load with payloads larger than
                // the 8 KB Unix-socket sndbuf default.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT));
                if let Err(e) = handle_connection(stream, event_tx, broker) {
                    log::warn!("connection error: {}", e);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_TIMEOUT);
            }
            Err(e) => {
                if broker.is_shutdown() {
                    break;
                }
                log::warn!("failed to accept connection: {}", e);
            }
        }
    }
}

fn handle_connection(
    stream: BrokerStream,
    event_tx: &Sender<EventData>,
    broker: &Broker,
) -> Result<(), String> {
    // Read one newline-terminated JSON request.
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_REQUEST_SIZE))
        .read_line(&mut line)
        .map_err(|e| format!("read error: {e}"))?;

    if line.is_empty() {
        return Err("empty request".into());
    }

    // Parse wire protocol request.
    let request: InterceptorRequest =
        serde_json::from_str(&line).map_err(|e| format!("malformed request: {e}"))?;

    // Validate: agent name must not contain newlines (used in payload encoding).
    if request.agent_name.contains('\n') {
        return Err("agent name contains newline".into());
    }

    let wire_id = request.id.clone();
    let agent_name = request.agent_name.clone();
    // Old interceptors don't send agent_pid; map None → 0 sentinel.
    let agent_pid = request.agent_pid.unwrap_or(0);

    // Broker assigns a unique correlation ID (monotonic u64 counter, always > 0).
    let correlation_id = broker.next_correlation_id();

    // Serialize the event field back to bytes for the Falco event payload.
    let raw_event = serde_json::to_vec(&request.event)
        .map_err(|e| format!("failed to serialize event: {e}"))?;

    let event_data = EventData {
        correlation_id,
        agent_name,
        agent_pid,
        raw_event,
    };

    // Register pending request BEFORE enqueuing the event. This ensures the broker
    // entry exists before Falco can process the event and send back an alert.
    // If enqueue fails, we remove the broker entry and deny.
    broker.register(correlation_id, wire_id, stream);

    if event_tx.try_send(event_data).is_err() {
        log::warn!("event queue full, denying event {}", correlation_id);
        broker.apply_deny(correlation_id, "event queue full".to_string());
        return Ok(());
    }

    Ok(())
}
