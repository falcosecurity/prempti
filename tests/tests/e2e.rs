use cak_tests::e2e::E2eHarness;
use cak_tests::interceptor::{assert_decision, assert_reason_contains};

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

// --- Deny: dangerous shell commands ---

#[test]
fn deny_rm_rf() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm -rf /"}"#, cwd(), "e2e-rm1");
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "Deny rm -rf");
}

#[test]
fn deny_rm_rf_variant() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"sudo rm -rf /home"}"#,
        cwd(),
        "e2e-rm2",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

#[test]
fn allow_safe_command() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "e2e-ls");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn allow_echo_command() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"echo hello"}"#, cwd(), "e2e-echo");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- Deny: writes to sensitive paths ---

#[test]
fn deny_write_to_sensitive() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Windows/system32/drivers/etc/hosts"
    } else {
        "/etc/passwd"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "e2e-wsen",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "Deny writes to sensitive paths");
}

// --- Ask: writes outside cwd ---

#[test]
fn ask_write_outside_cwd() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/other/file.txt"
    } else {
        "/home/other/file.txt"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "e2e-wout",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "ask");
    assert_reason_contains(&r, "Ask write outside cwd");
}

// --- Allow: writes inside cwd ---

#[test]
fn allow_write_inside_cwd() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/test/project/file.txt"
    } else {
        "/tmp/myproject/file.txt"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "e2e-win",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- Read tool ---

#[test]
fn allow_read_tool() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/test/project/readme.txt"
    } else {
        "/tmp/myproject/readme.txt"
    };
    let input = E2eHarness::make_input(
        "Read",
        &format!(r#"{{"file_path":"{}"}}"#, path),
        cwd(),
        "e2e-read",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn deny_read_sensitive_path() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Windows/System32/config/SAM"
    } else {
        "/etc/shadow"
    };
    let input = E2eHarness::make_input(
        "Read",
        &format!(r#"{{"file_path":"{}"}}"#, path),
        cwd(),
        "e2e-rsen",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

#[test]
fn deny_read_ssh_key() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/test/.ssh/id_rsa"
    } else {
        "/home/user/.ssh/id_rsa"
    };
    let input = E2eHarness::make_input(
        "Read",
        &format!(r#"{{"file_path":"{}"}}"#, path),
        cwd(),
        "e2e-rssh",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

#[test]
fn allow_read_safe_file() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/test/project/data.txt"
    } else {
        "/tmp/myproject/data.txt"
    };
    let input = E2eHarness::make_input(
        "Read",
        &format!(r#"{{"file_path":"{}"}}"#, path),
        cwd(),
        "e2e-rsafe",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- Append output / correlation ---

#[test]
fn deny_has_append_output() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"rm -rf /tmp/nuke"}"#,
        cwd(),
        "e2e-append",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "correlation=");
}

// --- Verdict escalation ---

#[test]
fn deny_wins_over_ask() {
    let h = require_falco!();
    // Write to sensitive path from different cwd → both deny and ask rules match.
    // Deny should win.
    let path = if cfg!(windows) {
        "C:/Windows/system.ini"
    } else {
        "/etc/hosts"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "e2e-esc",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

// --- Edit tool ---

#[test]
fn deny_edit_sensitive() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Windows/win.ini"
    } else {
        "/etc/passwd"
    };
    let input = E2eHarness::make_input(
        "Edit",
        &format!(
            r#"{{"file_path":"{}","old_string":"a","new_string":"b"}}"#,
            path
        ),
        cwd(),
        "e2e-edsen",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

#[test]
fn ask_edit_outside_cwd() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/other/file.txt"
    } else {
        "/home/other/file.txt"
    };
    let input = E2eHarness::make_input(
        "Edit",
        &format!(
            r#"{{"file_path":"{}","old_string":"a","new_string":"b"}}"#,
            path
        ),
        cwd(),
        "e2e-edout",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "ask");
}

#[test]
fn allow_edit_inside_cwd() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/test/project/file.txt"
    } else {
        "/tmp/myproject/file.txt"
    };
    let input = E2eHarness::make_input(
        "Edit",
        &format!(
            r#"{{"file_path":"{}","old_string":"a","new_string":"b"}}"#,
            path
        ),
        cwd(),
        "e2e-edin",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- Sensitive dotfiles ---

#[test]
fn deny_write_ssh() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/test/.ssh/authorized_keys"
    } else {
        "/home/user/.ssh/authorized_keys"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "e2e-wssh",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

#[cfg(not(windows))]
#[test]
fn deny_read_aws_credentials() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Read",
        r#"{"file_path":"/home/user/.aws/credentials"}"#,
        cwd(),
        "e2e-raws",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

// --- Bash edge cases ---

#[test]
fn allow_rm_without_rf() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm file.txt"}"#, cwd(), "e2e-rm3");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn deny_rm_rf_in_chain() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"echo yes && rm -rf /tmp/target"}"#,
        cwd(),
        "e2e-rm4",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

// --- Other tools (no matching rules → allow) ---

#[test]
fn allow_agent_tool() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Agent", r#"{"prompt":"help me"}"#, cwd(), "e2e-agent");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn allow_glob_tool() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Glob", r#"{"pattern":"**/*.rs"}"#, cwd(), "e2e-glob");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn allow_websearch_tool() {
    let h = require_falco!();
    let input = E2eHarness::make_input("WebSearch", r#"{"query":"rust test"}"#, cwd(), "e2e-web");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- Path traversal ---

#[test]
#[cfg(not(windows))]
fn deny_path_traversal_to_sensitive() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Write",
        r#"{"file_path":"/tmp/myproject/../../etc/passwd","content":"x"}"#,
        cwd(),
        "e2e-trav",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
}

#[test]
fn allow_relative_path_inside_cwd() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "Write",
        r#"{"file_path":"src/main.rs","content":"x"}"#,
        cwd(),
        "e2e-rel",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- Monitor-only rule (NOTICE priority, no deny/ask tag) ---

#[test]
fn monitor_rule_does_not_block() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Users/other/data.txt"
    } else {
        "/tmp/other/data.txt"
    };
    let input = E2eHarness::make_input(
        "Read",
        &format!(r#"{{"file_path":"{}"}}"#, path),
        cwd(),
        "e2e-mon",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

// --- MCP tool ---

#[test]
fn allow_mcp_with_server_name() {
    let h = require_falco!();
    let input = E2eHarness::make_input(
        "mcp__ide__getDiagnostics",
        r#"{"uri":"file:///tmp/test.rs"}"#,
        cwd(),
        "e2e-mcp2",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}
