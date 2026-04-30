use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(unix)]
type Listener = std::os::unix::net::UnixListener;
#[cfg(windows)]
type Listener = uds_windows::UnixListener;

#[cfg(unix)]
type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Stream = uds_windows::UnixStream;

/// Response mode for the mock broker.
#[derive(Clone)]
pub enum MockMode {
    Allow,
    Deny,
    Ask,
    Slow(Duration),
    Close,
    BadJson,
    WrongId,
}

/// A mock broker that listens on a Unix domain socket and responds to one request.
pub struct MockBroker {
    socket_path: PathBuf,
    thread: Option<JoinHandle<()>>,
}

impl MockBroker {
    /// Start a mock broker on the given socket path.
    /// Blocks until the listener is ready (bind + listen succeeded).
    pub fn start(socket_path: &Path, mode: MockMode) -> Self {
        let path = socket_path.to_path_buf();
        let path_for_thread = path.clone();

        // Readiness signal: thread sends () after bind+listen.
        let (tx, rx) = mpsc::channel();

        let thread = thread::Builder::new()
            .name("mock-broker".into())
            .spawn(move || run_broker(&path_for_thread, mode, tx))
            .expect("failed to spawn mock broker thread");

        // Wait for the broker to be ready (5s timeout).
        rx.recv_timeout(Duration::from_secs(5))
            .expect("mock broker did not become ready in time");

        MockBroker {
            socket_path: path,
            thread: Some(thread),
        }
    }

    /// Wait for the broker thread to finish.
    pub fn stop(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for MockBroker {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn run_broker(socket_path: &Path, mode: MockMode, ready_tx: mpsc::Sender<()>) {
    // Clean up stale socket.
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = Listener::bind(socket_path).expect("mock broker: bind failed");
    // Signal readiness.
    let _ = ready_tx.send(());

    // Accept one connection.
    let (stream, _) = listener.accept().expect("mock broker: accept failed");
    handle_connection(stream, &mode);
}

fn handle_connection(stream: Stream, mode: &MockMode) {
    // Read newline-terminated request.
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    let _ = reader.read_line(&mut line);

    if matches!(mode, MockMode::Close) {
        // Close without responding.
        return;
    }

    // Parse request ID.
    let req_id = serde_json::from_str::<serde_json::Value>(&line)
        .ok()
        .and_then(|v| v.get("id").and_then(|id| id.as_str().map(String::from)))
        .unwrap_or_else(|| "unknown".into());

    let response = match mode {
        MockMode::Allow => format!(
            r#"{{"id":"{}","decision":"allow","reason":""}}"#,
            req_id
        ),
        MockMode::Deny => format!(
            r#"{{"id":"{}","decision":"deny","reason":"blocked by test rule"}}"#,
            req_id
        ),
        MockMode::Ask => format!(
            r#"{{"id":"{}","decision":"ask","reason":"requires confirmation"}}"#,
            req_id
        ),
        MockMode::Slow(delay) => {
            thread::sleep(*delay);
            format!(r#"{{"id":"{}","decision":"allow","reason":""}}"#, req_id)
        }
        MockMode::BadJson => "this is not json".into(),
        MockMode::WrongId => r#"{"id":"wrong-id-xxx","decision":"allow","reason":""}"#.into(),
        MockMode::Close => unreachable!(),
    };

    let mut writer = stream;
    let _ = write!(writer, "{}\n", response);
}

/// Generate a unique socket path in the system temp directory.
pub fn temp_socket_path(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "prempti-test-{}-{}.sock",
        std::process::id(),
        label
    ));
    // Normalize to forward slashes on Windows for AF_UNIX compatibility.
    #[cfg(windows)]
    {
        PathBuf::from(path.to_string_lossy().replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        path
    }
}
