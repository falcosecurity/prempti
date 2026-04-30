use std::ffi::{CStr, CString};
use std::time::Duration;

use anyhow::Error;
use falco_plugin::event::events::Event;
use falco_plugin::event::PluginEvent;
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::FailureReason;

use crate::event::{encode_payload, CodingAgentPayload};
use crate::CodingAgentPlugin;

/// How long next_batch waits for the first event before returning Timeout.
const BATCH_WAIT: Duration = Duration::from_millis(100);

/// Source plugin instance. Created by `open()`, destroyed by `close()`/Drop.
pub struct CodingAgentInstance;

impl SourcePlugin for CodingAgentPlugin {
    type Instance = CodingAgentInstance;

    const EVENT_SOURCE: &'static CStr = c"coding_agent";
    const PLUGIN_ID: u32 = 999; // Development ID. Register for production.

    type Event<'a> = Event<PluginEvent<CodingAgentPayload<'a>>>;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        log::info!("coding_agent source opened");
        Ok(CodingAgentInstance)
    }

    fn event_to_string(
        &mut self,
        event: &EventInput<Self::Event<'_>>,
    ) -> Result<CString, Error> {
        let plugin_event = event.event()?;
        let text = String::from_utf8_lossy(plugin_event.params.event_data.0);
        // Truncate for display if very long. Use floor_char_boundary to avoid
        // splitting multi-byte UTF-8 characters.
        let display = if text.len() > 256 {
            let boundary = text.floor_char_boundary(256);
            format!("{}...", &text[..boundary])
        } else {
            text.into_owned()
        };
        Ok(CString::new(display)?)
    }
}

impl SourcePluginInstance for CodingAgentInstance {
    type Plugin = CodingAgentPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        // Block until the first event arrives or timeout expires.
        // This is event-driven — wakes immediately when an event is sent,
        // no busy-polling or fixed sleep.
        let first = match plugin.event_rx.recv_timeout(BATCH_WAIT) {
            Ok(event_data) => event_data,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                return Err(anyhow::anyhow!("no events").context(FailureReason::Timeout));
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                return Err(anyhow::anyhow!("event channel closed").context(FailureReason::Eof));
            }
        };

        let payload = encode_payload(&first);
        let event = Self::plugin_event(&payload);
        batch.add(event)?;
        let mut added = 1;

        // Drain any additional queued events (non-blocking) up to batch limit.
        while added < 32 {
            match plugin.event_rx.try_recv() {
                Ok(event_data) => {
                    let payload = encode_payload(&event_data);
                    let event = Self::plugin_event(&payload);
                    batch.add(event)?;
                    added += 1;
                }
                Err(_) => break,
            }
        }

        Ok(())
    }
}
