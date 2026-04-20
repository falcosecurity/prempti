use std::io::Read;
use std::sync::Arc;

use crate::broker::Broker;
use crate::config::CodingAgentConfig;

/// Max HTTP request body size (1MB — Falco alerts are typically a few KB).
const MAX_BODY_SIZE: u64 = 1024 * 1024;

/// Falco JSON alert structure (subset of fields we need).
/// Uses `message` (rule output without timestamp prefix, requires
/// `json_include_message_property: true` in falco.yaml).
#[derive(serde::Deserialize)]
struct FalcoAlert {
    #[serde(default)]
    rule: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    output_fields: serde_json::Map<String, serde_json::Value>,
}

/// The verdict type determined from alert tags.
enum VerdictType {
    Deny,
    Ask,
    Seen,
    Unknown,
}

/// Handle to a running HTTP alert receiver (thread + server for shutdown).
pub struct HttpServerHandle {
    pub thread: std::thread::JoinHandle<()>,
    server: Arc<tiny_http::Server>,
}

impl HttpServerHandle {
    /// Unblock the HTTP server so the thread can exit.
    pub fn unblock(&self) {
        self.server.unblock();
    }
}

/// Start the HTTP alert receiver in a background thread.
/// Listens for Falco JSON alerts via http_output and resolves verdicts.
///
/// Returns an error if the port is already in use. Returning an error —
/// rather than panicking — lets Falco report a clean plugin init failure
/// without taking the host process down and without any side effects on
/// the existing (possibly-running) coding-agents-kit instance.
pub fn start(
    config: &CodingAgentConfig,
    broker: Arc<Broker>,
) -> anyhow::Result<HttpServerHandle> {
    let deny_tags = config.deny_tags.clone();
    let ask_tags = config.ask_tags.clone();
    let seen_tags = config.seen_tags.clone();
    let bind_addr = format!("127.0.0.1:{}", config.http_port);

    let server = Arc::new(tiny_http::Server::http(&bind_addr).map_err(|e| {
        anyhow::anyhow!(
            "failed to bind HTTP alert receiver on {bind_addr}: {e}. \
             Is another coding-agents-kit Falco instance already running? \
             Either stop it first or set a different `http_port` in \
             falco.coding_agents_plugin.yaml (plugin init_config)."
        )
    })?);

    log::info!(
        "HTTP alert receiver listening on {}",
        server.server_addr().to_ip().map_or_else(
            || bind_addr.to_string(),
            |addr| addr.to_string(),
        )
    );

    let server_clone = Arc::clone(&server);
    let thread = std::thread::Builder::new()
        .name("cak-http-server".to_string())
        .spawn(move || run_server(server_clone, &deny_tags, &ask_tags, &seen_tags, &broker))
        .map_err(|e| anyhow::anyhow!("failed to spawn HTTP server thread: {e}"))?;

    Ok(HttpServerHandle { thread, server })
}

fn run_server(
    server: Arc<tiny_http::Server>,
    deny_tags: &[String],
    ask_tags: &[String],
    seen_tags: &[String],
    broker: &Broker,
) {
    for mut request in server.incoming_requests() {
        // Respond 200 immediately to avoid blocking Falco's output worker.
        // Parse and process the alert asynchronously (in this same thread,
        // since tiny_http is synchronous and we process sequentially).
        let mut body = String::new();
        if let Err(e) = request.as_reader().take(MAX_BODY_SIZE).read_to_string(&mut body) {
            log::warn!("failed to read HTTP request body: {}", e);
            let response = tiny_http::Response::empty(200);
            let _ = request.respond(response);
            continue;
        }

        // Respond immediately before processing.
        let response = tiny_http::Response::empty(200);
        let _ = request.respond(response);

        // Parse the Falco alert JSON.
        let alert: FalcoAlert = match serde_json::from_str(&body) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("malformed Falco alert JSON: {}", e);
                continue;
            }
        };

        // Extract the broker-assigned correlation ID from output_fields.
        // Falco serializes u64 fields as JSON numbers.
        let correlation_id = match alert
            .output_fields
            .get("correlation.id")
            .and_then(|v| v.as_u64())
        {
            Some(id) if id > 0 => id,
            _ => {
                log::debug!(
                    "alert missing correlation.id in output_fields (rule={})",
                    alert.rule
                );
                continue;
            }
        };

        // Determine verdict type from tags.
        let verdict_type = classify_tags(&alert.tags, deny_tags, ask_tags, seen_tags);

        // Build reason string from rule name and message.
        // The message field contains the rule output without the timestamp prefix
        // (requires json_include_message_property: true in falco.yaml).
        let reason = if alert.message.is_empty() {
            alert.rule.clone()
        } else {
            format!("{}: {}", alert.rule, alert.message)
        };

        // Apply verdict to the broker.
        match verdict_type {
            VerdictType::Deny => {
                log::debug!("deny alert for {} (rule={})", correlation_id, alert.rule);
                broker.apply_deny(correlation_id, reason);
            }
            VerdictType::Ask => {
                log::debug!("ask alert for {} (rule={})", correlation_id, alert.rule);
                broker.apply_ask(correlation_id, reason);
            }
            VerdictType::Seen => {
                log::debug!("seen alert for {}", correlation_id);
                broker.apply_seen(correlation_id);
            }
            VerdictType::Unknown => {
                log::debug!(
                    "alert with unrecognized tags for {} (rule={}, tags={:?})",
                    correlation_id,
                    alert.rule,
                    alert.tags
                );
            }
        }
    }
}

/// Classify an alert's tags into a verdict type.
/// Priority: deny > ask > seen > unknown.
fn classify_tags(
    tags: &[String],
    deny_tags: &[String],
    ask_tags: &[String],
    seen_tags: &[String],
) -> VerdictType {
    let mut result = VerdictType::Unknown;

    for tag in tags {
        if deny_tags.contains(tag) {
            return VerdictType::Deny; // Deny wins immediately.
        }
        if ask_tags.contains(tag) {
            result = VerdictType::Ask;
        }
        if seen_tags.contains(tag) && matches!(result, VerdictType::Unknown) {
            result = VerdictType::Seen;
        }
    }

    result
}
