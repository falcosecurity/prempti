use std::ffi::CString;

use anyhow::Error;
use falco_plugin::event::events::Event;
use falco_plugin::event::PluginEvent;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};

use crate::event::{CodingAgentPayload, ParsedEvent};
use crate::CodingAgentPlugin;

/// Extractor methods. Each method corresponds to one Falco field.
impl CodingAgentPlugin {
    fn get_payload<'c>(
        &self,
        req: &mut ExtractRequest<'c, '_, '_, '_, Self>,
    ) -> Result<&'c [u8], Error> {
        let event: Event<PluginEvent<CodingAgentPayload<'c>>> = req.event.event()?;
        Ok(event.params.event_data.0)
    }

    fn extract_agent_name(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.agent_name(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    /// Operating system the plugin was compiled for. Static per build, not
    /// parsed from the event payload — there's a single Falco process per
    /// host, so the OS doesn't vary across events.
    fn extract_agent_os(
        &mut self,
        _req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let val = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "unknown"
        };
        Ok(CString::new(val)?)
    }

    fn extract_correlation_id(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<u64, Error> {
        let payload = self.get_payload(&mut req)?;
        Ok(req.context.correlation_id(payload).unwrap_or(0))
    }

    fn extract_agent_pid(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<u64, Error> {
        let payload = self.get_payload(&mut req)?;
        Ok(req.context.agent_pid(payload).unwrap_or(0))
    }

    fn extract_tool_use_id(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.tool_use_id(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_hook_event_name(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.hook_event_name(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_session_id(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.session_id(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_permission_mode(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.permission_mode(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_transcript_path(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.transcript_path(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_agent_model(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.agent_model(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_agent_turn_id(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.agent_turn_id(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_cwd(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.cwd(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_real_cwd(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.real_cwd(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_tool_name(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.tool_name(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_tool_input(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.tool_input(payload).unwrap_or_default();
        Ok(CString::new(val)?)
    }

    fn extract_tool_input_command(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.tool_input_command(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_file_path(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.file_path(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

    fn extract_real_file_path(
        &mut self,
        mut req: ExtractRequest<Self>,
    ) -> Result<CString, Error> {
        let payload = self.get_payload(&mut req)?;
        let val = req.context.real_file_path(payload).unwrap_or("");
        Ok(CString::new(val)?)
    }

}

impl ExtractPlugin for CodingAgentPlugin {
    type Event<'a> = Event<PluginEvent<CodingAgentPayload<'a>>>;
    type ExtractContext = ParsedEvent;

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("correlation.id", &Self::extract_correlation_id)
            .with_display("Correlation ID")
            .with_description("Broker-assigned unique ID for this event (used for verdict correlation)")
            .add_output(),
        field("agent.name", &Self::extract_agent_name)
            .with_display("Agent Name")
            .with_description("Coding agent identifier (e.g., claude_code)"),
        field("agent.os", &Self::extract_agent_os)
            .with_display("Operating System")
            .with_description("OS the plugin was compiled for: linux, macos, windows, or unknown"),
        field("agent.pid", &Self::extract_agent_pid)
            .with_display("Agent PID")
            .with_description("PID of the coding agent process that invoked the hook (0 when lookup fails)")
            .add_output(),
        field("tool.use_id", &Self::extract_tool_use_id)
            .with_display("Tool Use ID")
            .with_description("Tool call identifier from Claude Code (tool_use_id, raw value)"),
        field("agent.hook_event_name", &Self::extract_hook_event_name)
            .with_display("Hook Event")
            .with_description("Hook lifecycle point (e.g., PreToolUse)"),
        field("agent.session_id", &Self::extract_session_id)
            .with_display("Session ID")
            .with_description("Coding agent session identifier"),
        field("agent.permission_mode", &Self::extract_permission_mode)
            .with_display("Permission Mode")
            .with_description("Session permission mode reported by the coding agent (e.g., default, acceptEdits, bypassPermissions)"),
        field("agent.transcript_path", &Self::extract_transcript_path)
            .with_display("Transcript Path")
            .with_description("Path to the session transcript file (empty when the agent reports null)"),
        field("agent.model", &Self::extract_agent_model)
            .with_display("Model")
            .with_description("Model identifier reported by the coding agent (Codex-only; empty for Claude Code)"),
        field("agent.turn_id", &Self::extract_agent_turn_id)
            .with_display("Turn ID")
            .with_description("Turn identifier within a session (Codex-only; finer than session_id; empty for Claude Code)"),
        field("agent.cwd", &Self::extract_cwd)
            .with_display("Working Directory")
            .with_description("Working directory, raw from Claude Code JSON"),
        field("agent.real_cwd", &Self::extract_real_cwd)
            .with_display("Resolved Working Directory")
            .with_description("Working directory, resolved to absolute canonical path"),
        field("tool.name", &Self::extract_tool_name)
            .with_display("Tool Name")
            .with_description("Tool being invoked (e.g., Bash, Write, Edit)"),
        field("tool.input", &Self::extract_tool_input)
            .with_display("Tool Input")
            .with_description("Full tool input as JSON string"),
        field("tool.input_command", &Self::extract_tool_input_command)
            .with_display("Shell Command")
            .with_description("Shell command (Bash tool calls only)"),
        field("tool.file_path", &Self::extract_file_path)
            .with_display("File Path")
            .with_description("Target file path, raw from tool_input.file_path (Write/Edit/Read only)"),
        field("tool.real_file_path", &Self::extract_real_file_path)
            .with_display("Resolved File Path")
            .with_description("Target file path, resolved to absolute canonical path (Write/Edit/Read only)"),
    ];
}
