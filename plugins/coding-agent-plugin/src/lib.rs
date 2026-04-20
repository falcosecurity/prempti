use std::ffi::CStr;
use std::sync::Arc;

use anyhow::Error;
use crossbeam_channel::{bounded, Receiver, Sender};
use falco_plugin::base::{Json, Plugin};
use falco_plugin::tables::TablesInput;
use falco_plugin::{extract_plugin, plugin, source_plugin};

mod broker;
mod config;
mod event;
mod extract;
mod http_server;
mod socket_server;
mod source;
mod verdict;

use broker::Broker;
use config::CodingAgentConfig;
use event::EventData;

/// Default event queue capacity.
const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// The coding-agents-kit Falco plugin.
///
/// Capabilities: sourcing + extraction.
/// - Sourcing: receives events from interceptors via Unix socket,
///   queues them, and delivers to Falco via next_batch.
/// - Extraction: exposes agent.* and tool.* fields for Falco rules.
pub struct CodingAgentPlugin {
    #[allow(dead_code)]
    config: CodingAgentConfig,
    /// Channel receiver for events from interceptor connections.
    pub(crate) event_rx: Receiver<EventData>,
    /// Broker: tracks pending requests and resolves verdicts.
    /// Held here to keep the Arc alive for the socket/HTTP server threads.
    #[allow(dead_code)]
    pub(crate) broker: Arc<Broker>,
    /// Handle to the socket server background thread.
    #[allow(dead_code)]
    socket_thread: Option<std::thread::JoinHandle<()>>,
    /// Handle to the HTTP alert receiver (thread + server for shutdown).
    http_handle: Option<http_server::HttpServerHandle>,
    /// Handle to the pending request reaper thread.
    #[allow(dead_code)]
    reaper_thread: Option<std::thread::JoinHandle<()>>,
}

/// Plugin version pulled from `CARGO_PKG_VERSION` so the workspace `version`
/// is the single source of truth. The const match is evaluated at compile
/// time; a missing trailing NUL would be a build-time error, not a runtime
/// panic.
const PLUGIN_VERSION_CSTR: &CStr = {
    let bytes = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    match CStr::from_bytes_with_nul(bytes) {
        Ok(s) => s,
        Err(_) => panic!("CARGO_PKG_VERSION is not a valid C string"),
    }
};

impl Plugin for CodingAgentPlugin {
    const NAME: &'static CStr = c"coding_agent";
    const PLUGIN_VERSION: &'static CStr = PLUGIN_VERSION_CSTR;
    const DESCRIPTION: &'static CStr =
        c"coding-agents-kit - Runtime Security for AI Coding Agents with Falco";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/coding-agents-kit";

    type ConfigType = Json<CodingAgentConfig>;

    fn new(
        _input: Option<&TablesInput>,
        config: Self::ConfigType,
    ) -> Result<Self, Error> {
        let Json(config) = config;

        log::info!(
            "coding_agent plugin initialized (mode={}, socket_path={}, http_port={})",
            config.mode,
            config.socket_path,
            config.http_port,
        );

        let (event_tx, event_rx): (Sender<EventData>, Receiver<EventData>) =
            bounded(DEFAULT_QUEUE_CAPACITY);
        let broker = Arc::new(Broker::new());
        broker.set_monitor_mode(config.mode == "monitor");

        // Bring up the socket server first so its bind-time check cleanly
        // rejects a second Falco trying to share the same socket *before*
        // anything mutates shared state (stale socket file, HTTP port, etc).
        let socket_thread = Some(socket_server::start(
            config.socket_path.clone(),
            event_tx,
            Arc::clone(&broker),
        )?);

        // HTTP alert receiver. Port collisions surface as Err here rather
        // than a panic — Falco reports it as a clean plugin init failure.
        let http_handle = Some(http_server::start(&config, Arc::clone(&broker))?);

        // Pending request reaper (TTL cleanup). Thread-spawn failure here is
        // fatal — but it effectively never happens and the panic is isolated
        // because start_reaper uses the expect idiom inside the SDK path.
        let reaper_thread = Some(Broker::start_reaper(Arc::clone(&broker)));

        Ok(CodingAgentPlugin {
            config,
            event_rx,
            broker,
            socket_thread,
            http_handle,
            reaper_thread,
        })
    }

    // Note: set_config() is NOT called by Falco 0.43. The watch_config_files
    // mechanism performs a full restart (destroy + init), so config changes are
    // handled by new() being called again with the updated config.
}

impl Drop for CodingAgentPlugin {
    fn drop(&mut self) {
        log::info!("plugin shutting down, signaling background threads...");
        self.broker.shutdown();

        // Unblock the HTTP server so its thread can exit, then join it.
        // This releases the TCP port before the new plugin instance binds.
        if let Some(handle) = self.http_handle.take() {
            handle.unblock();
            let _ = handle.thread.join();
        }

        // Join the socket server thread (it checks shutdown flag via ACCEPT_TIMEOUT).
        if let Some(handle) = self.socket_thread.take() {
            let _ = handle.join();
        }

        // Join the reaper thread (it checks shutdown flag every REAPER_INTERVAL_SECS).
        if let Some(handle) = self.reaper_thread.take() {
            let _ = handle.join();
        }

        log::info!("plugin shutdown complete");
    }
}

// Register the plugin with Falco.
plugin!(CodingAgentPlugin);
source_plugin!(CodingAgentPlugin);
extract_plugin!(CodingAgentPlugin);

#[cfg(test)]
mod version_tests {
    use super::PLUGIN_VERSION_CSTR;

    #[test]
    fn plugin_version_matches_cargo_package_version() {
        let expected = env!("CARGO_PKG_VERSION");
        let reported = PLUGIN_VERSION_CSTR.to_str().expect("valid UTF-8");
        assert_eq!(
            reported, expected,
            "plugin version drifted from Cargo workspace version"
        );
    }
}
