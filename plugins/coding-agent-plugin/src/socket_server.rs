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
/// flag after each timeout, enabling clean exit during config hot-reload.
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
/// Plugin::new() propagates to Falco so a second instance cannot clobber
/// the running one's socket file.
fn prepare_listener(socket_path: &str) -> anyhow::Result<UnixListener> {
    if has_live_peer(socket_path).unwrap_or(false) {
        anyhow::bail!(
            "broker socket {socket_path} is already in use by another \
             coding-agents-kit Falco instance. Stop it first or set a \
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
        .name("cak-socket-server".to_string())
        .spawn(move || run_server(listener, &socket_path, &event_tx, &broker))
        .map_err(|e| anyhow::anyhow!("failed to spawn socket server thread: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_socket_path(label: &str) -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cak-sock-{}-{}.sock", std::process::id(), label));
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
        let path = temp_socket_path("live");
        let _ = std::fs::remove_file(&path);
        // First bind succeeds.
        let first = prepare_listener(&path).expect("first bind");
        // Second attempt must fail WITHOUT removing the first socket file,
        // so the live server keeps working.
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

    // Broker assigns a unique correlation ID (monotonic u64 counter, always > 0).
    let correlation_id = broker.next_correlation_id();

    // Serialize the event field back to bytes for the Falco event payload.
    let raw_event = serde_json::to_vec(&request.event)
        .map_err(|e| format!("failed to serialize event: {e}"))?;

    let event_data = EventData {
        correlation_id,
        agent_name,
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
