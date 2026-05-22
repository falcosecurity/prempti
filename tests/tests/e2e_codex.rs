//! Falco-driven E2E tests for the codex interceptor.
//!
//! Boots a real Falco with the coding-agent plugin, sends Codex-shaped hook
//! inputs through `codex-interceptor`, and asserts on the Codex output shape.
//! Mock-broker tests in `codex_interceptor.rs` cover wire boundaries; these
//! tests prove plugin field extraction, rule evaluation, alert routing, and
//! per-event verdict translation all hold together for `agent.name = "codex"`.

use prempti_tests::e2e::E2eHarness;
use prempti_tests::interceptor::{
    assert_codex_permreq_behavior, assert_codex_permreq_message_contains,
    assert_codex_pretool_decision, AgentKind,
};

macro_rules! require_falco {
    () => {
        match E2eHarness::start("guardrails") {
            Some(harness) => harness,
            None => {
                eprintln!("SKIP: falco or plugin not available");
                return;
            }
        }
    };
}

fn cwd() -> &'static str {
    if cfg!(windows) {
        "C:/Users/test/project"
    } else {
        "/tmp/myproject"
    }
}

// ---------------------------------------------------------------------------
// PreToolUse: agent-agnostic rules fire for Codex too
// ---------------------------------------------------------------------------

#[test]
fn codex_pretool_deny_rm_rf() {
    // The "Deny rm -rf" rule keys on tool.name = "Bash" + tool.input_command,
    // not on agent.name. It must fire for Codex unchanged. The interceptor
    // emits the Codex PreToolUse output shape (permissionDecision).
    let h = require_falco!();
    let input = E2eHarness::make_codex_pretool_input(
        "Bash",
        r#"{"command":"rm -rf /"}"#,
        cwd(),
        "codex-rm1",
    );
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
}

#[test]
fn codex_pretool_allow_safe_command() {
    let h = require_falco!();
    let input =
        E2eHarness::make_codex_pretool_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "codex-ls");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "allow");
}

// ---------------------------------------------------------------------------
// PermissionRequest: rule eval works, output shape switches per event
// ---------------------------------------------------------------------------

#[test]
fn codex_permreq_deny_rm_rf_uses_permission_request_shape() {
    // Same rule fires (rm -rf), but the interceptor emits the
    // PermissionRequest output shape: hookSpecificOutput.decision.behavior,
    // not permissionDecision. The rule reason is surfaced as decision.message.
    let h = require_falco!();
    let input =
        E2eHarness::make_codex_permreq_input("Bash", r#"{"command":"rm -rf /home"}"#, cwd());
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_permreq_behavior(&r, "deny");
    assert_codex_permreq_message_contains(&r, "Deny rm -rf");
}

// ---------------------------------------------------------------------------
// agent.name routing: rules conditioned on agent.name = "codex" must fire
// only for codex; same input from claude must not match the codex sentinel.
// ---------------------------------------------------------------------------

#[test]
fn codex_sentinel_rule_fires_for_codex_only() {
    let h = require_falco!();
    let input = E2eHarness::make_codex_pretool_input(
        "Bash",
        r#"{"command":"echo codex-e2e-deny-marker"}"#,
        cwd(),
        "codex-sentinel",
    );
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    // The sentinel rule's output is "Codex deny sentinel matched: …".
    assert!(
        r.stdout.contains("Codex deny sentinel matched"),
        "expected sentinel rule output in reason, got '{}'",
        r.stdout.trim()
    );
}

#[test]
fn codex_sentinel_rule_does_not_fire_for_claude() {
    // Same marker string, but sent from the Claude Code interceptor:
    // agent.name = "claude_code" → the sentinel's condition fails →
    // no deny rule matches → allow.
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"echo codex-e2e-deny-marker"}"#,
        cwd(),
        "claude-sentinel",
    );
    let r = h.run_hook(&input);
    // Existing claude assertion helpers parse the Claude/PreToolUse shape.
    prempti_tests::interceptor::assert_decision(&r, "allow");
}

// ---------------------------------------------------------------------------
// PermissionRequest + ask sentinel: the full ask-via-PermissionRequest mapping
// driven by a real Falco-fired alert (not just the mock-broker translation
// table).
// ---------------------------------------------------------------------------

#[test]
fn codex_permreq_ask_sentinel_surfaces_reason_as_deny_message() {
    // The sentinel ask rule fires for codex on this marker. The plugin's
    // verdict resolver maps ask -> "ask" on the wire; the codex interceptor
    // maps that to PermissionRequest deny with the rule's output text
    // surfaced as decision.message so the user sees it in Codex's
    // approval UX.
    let h = require_falco!();
    let input = E2eHarness::make_codex_permreq_input(
        "Bash",
        r#"{"command":"echo codex-e2e-ask-marker"}"#,
        cwd(),
    );
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_permreq_behavior(&r, "deny");
    assert_codex_permreq_message_contains(&r, "Codex ask sentinel matched");
}

#[test]
fn codex_pretool_ask_sentinel_becomes_deny_with_reason() {
    // PreToolUse maps Falco ask to Codex deny + reason. Codex's hook
    // contract is binary allow/deny on this mount and PermissionRequest
    // only fires for permission_modes that would prompt anyway — letting
    // ask pass through to allow at PreToolUse would silently allow when
    // it shouldn't. Deny + rule reason is the only safe mapping.
    let h = require_falco!();
    let input = E2eHarness::make_codex_pretool_input(
        "Bash",
        r#"{"command":"echo codex-e2e-ask-marker"}"#,
        cwd(),
        "codex-ask-pre",
    );
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("Codex ask sentinel matched"),
        "expected sentinel rule output surfaced as deny reason, got '{}'",
        r.stdout.trim()
    );
}

// ---------------------------------------------------------------------------
// agent.pid round-trip: the Codex interceptor must propagate its getppid
// the same way the Claude one does. The seen rule embeds agent.pid in its
// output, and rules with agent.pid in their output template also surface it.
// The "Deny rm -rf" rule's output includes agent_pid=%agent.pid.
// ---------------------------------------------------------------------------

#[test]
fn codex_agent_pid_round_trips() {
    let h = require_falco!();
    let input = E2eHarness::make_codex_pretool_input(
        "Bash",
        r#"{"command":"rm -rf /tmp/codex-pid-probe"}"#,
        cwd(),
        "codex-pid",
    );
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    // The interceptor's parent is the cargo test binary (this process).
    let expected = std::process::id();
    let needle = format!("agent_pid={expected}");
    assert!(
        r.stdout.contains(&needle),
        "expected agent_pid={expected} in reason, got stdout='{}'",
        r.stdout.trim()
    );
}

// ---------------------------------------------------------------------------
// apply_patch multi-file pipeline
//
// The broker parses the patch envelope from tool_input.command, emits one
// synthetic Falco event per (op, path) tuple, and waits for N seen alerts
// before resolving. Deny short-circuits — first deny wins. These tests prove
// the parser, the multiplex, the per-event field extraction, the seen
// counter, and the verdict escalation all hold together end-to-end.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn codex_apply_patch_single_add_to_sensitive_path_denies() {
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Add File: /etc/codex-e2e-evil
+evil
*** End Patch
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-1");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("Deny writes to sensitive paths"),
        "expected sensitive-path rule reason, got '{}'",
        r.stdout.trim()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn codex_apply_patch_single_delete_to_sensitive_path_denies() {
    // Pins the Delete-coverage fix: is_write_tool now includes patch_op
    // = "Delete", so deletions to /etc/* hit the same sensitive-path rule
    // that catches Add/Update/Move.
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Delete File: /etc/codex-e2e-evil
*** End Patch
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-2");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("Deny writes to sensitive paths"),
        "expected sensitive-path rule reason, got '{}'",
        r.stdout.trim()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn codex_apply_patch_multi_file_with_one_sensitive_denies() {
    // Multi-event multiplex: 2 synthetic events fire, one per path. Only
    // the sensitive one matches the deny rule; the broker resolves as deny
    // via escalation (deny > allow). The safe one's seen alert may arrive
    // before or after the deny but cannot reverse it.
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Add File: /tmp/myproject/safe.txt
+safe
*** Add File: /etc/codex-e2e-evil
+evil
*** End Patch
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-3");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("Deny writes to sensitive paths"),
        "expected sensitive-path rule reason, got '{}'",
        r.stdout.trim()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn codex_apply_patch_update_with_move_to_sensitive_target_denies() {
    // An Update hunk with a Move-to target produces TWO synthetic events:
    // (Update, source) and (Move, target). When the target is sensitive,
    // the Move event triggers the deny — even though the Update on the
    // source path would be allowed.
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Update File: /tmp/myproject/origin.txt
*** Move to: /etc/codex-e2e-evil
@@
- old
+ new
*** End Patch
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-4");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("Deny writes to sensitive paths"),
        "expected sensitive-path rule reason for the Move target, got '{}'",
        r.stdout.trim()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn codex_apply_patch_all_paths_inside_cwd_allows() {
    // All N events resolve as allow; the broker waits for N seens before
    // closing the interceptor's stream. Regression guard against the seen
    // counter resolving early after just one event.
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Add File: /tmp/myproject/safe1.txt
+x
*** Add File: /tmp/myproject/safe2.txt
+y
*** Add File: /tmp/myproject/safe3.txt
+z
*** End Patch
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-5");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "allow");
}

#[test]
fn codex_apply_patch_malformed_envelope_fails_closed() {
    // No `*** End Patch` trailer — parse_apply_patch returns MissingEndPatch.
    // The broker writes the deny response directly to the interceptor
    // stream without enqueuing any events; no broker entry is created.
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Add File: /tmp/myproject/safe.txt
+x
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-mal");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("apply_patch parse error"),
        "expected parse-error reason, got '{}'",
        r.stdout.trim()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn codex_apply_patch_ssh_path_denies() {
    // The ssh-dir rule's condition is `is_write_tool and tool.real_file_path
    // contains "/.ssh/"`. apply_patch with Add to a path containing /.ssh/
    // should hit this rule via the new patch_op-aware macro.
    let h = require_falco!();
    let patch = "\
*** Begin Patch
*** Add File: /home/test/.ssh/authorized_keys
+ssh-rsa AAAA
*** End Patch
";
    let input = E2eHarness::make_codex_apply_patch_input(patch, cwd(), "codex-ap-ssh");
    let r = h.run_hook_for(AgentKind::Codex, &input);
    assert_codex_pretool_decision(&r, "deny");
    assert!(
        r.stdout.contains("Deny writing to ssh dir"),
        "expected ssh-dir rule reason, got '{}'",
        r.stdout.trim()
    );
}
