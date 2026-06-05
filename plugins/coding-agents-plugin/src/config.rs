use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;

/// Plugin configuration, received from falco.yaml `init_config`.
#[derive(Deserialize, JsonSchema, Clone)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct CodingAgentConfig {
    /// Operational mode. One of:
    /// - `guardrails` (default): verdicts enforced (deny / ask / allow).
    /// - `monitor`: rules are evaluated and logged, but all verdicts resolve
    ///   as `allow` after the synchronous rule-eval wait.
    /// - `passthrough` (Experimental): every interceptor request is resolved
    ///   as `allow` immediately at register, without waiting for rule
    ///   evaluation. Events are still enqueued so observability via
    ///   `http_output` / `falco.log` is preserved. Use only when embedding
    ///   Prempti inside a host agent that handles alerts through its own
    ///   pipeline.
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Action when a tool call matches no deny/ask rule (the "no-rule-match
    /// floor"). One of:
    /// - `allow` (default): Prempti actively approves, skipping the agent's
    ///   own permission prompt.
    /// - `defer`: Prempti steps aside; the agent's own permission system
    ///   decides (Claude Code's normal permission flow / Codex's
    ///   `PermissionRequest`), prompting if it normally would.
    ///
    /// Applies in `guardrails` mode only. In `monitor` and `passthrough`
    /// modes every request resolves as `defer` regardless of this setting.
    /// deny / ask verdicts are unaffected either way.
    #[serde(default = "default_default_action")]
    pub default_action: String,

    /// Broker listen address (Unix domain socket path on all platforms).
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Port for the HTTP alert receiver.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Tags that indicate a deny verdict.
    #[serde(default = "default_deny_tags")]
    pub deny_tags: Vec<String>,

    /// Tags that indicate an ask verdict.
    #[serde(default = "default_ask_tags")]
    pub ask_tags: Vec<String>,

    /// Tags that indicate evaluation is complete (seen).
    #[serde(default = "default_seen_tags")]
    pub seen_tags: Vec<String>,

    /// Maximum size in bytes of a single wire request the broker will read
    /// from an interceptor connection. Default 5 MiB (5 * 1024 * 1024).
    /// Raise this if you see deny responses with reason `"read error"` and
    /// the interceptor was forwarding a very large `apply_patch` envelope;
    /// the matching limit on the interceptor side is
    /// `PREMPTI_INPUT_MAX_BYTES`. Clamped to `[4 KiB, 64 MiB]` at use site
    /// so a typo can't break the broker.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: u64,
}

fn default_mode() -> String {
    "guardrails".to_string()
}

fn default_default_action() -> String {
    "allow".to_string()
}

fn default_socket_path() -> String {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            format!("{home}/.prempti/run/broker.sock")
        } else {
            "/tmp/prempti-broker.sock".to_string()
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            format!("{}/prempti/run/broker.sock", local.replace('\\', "/"))
        } else {
            "C:/prempti-broker.sock".to_string()
        }
    }
}

fn default_http_port() -> u16 {
    2802
}

fn default_deny_tags() -> Vec<String> {
    vec!["coding_agent_deny".to_string()]
}

fn default_ask_tags() -> Vec<String> {
    vec!["coding_agent_ask".to_string()]
}

fn default_seen_tags() -> Vec<String> {
    vec!["coding_agent_seen".to_string()]
}

fn default_max_request_bytes() -> u64 {
    // 5 MiB: comfortably covers realistic apply_patch multi-file refactors
    // (the largest captured Codex payloads in dev were ~1 KiB, but model-
    // generated patches can easily exceed 64 KiB on big refactors). Leaves
    // headroom over the interceptor's 4 MiB default to account for the
    // {version, id, agent_name, agent_pid, event} envelope overhead.
    5 * 1024 * 1024
}
