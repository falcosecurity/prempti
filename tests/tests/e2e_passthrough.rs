use prempti_tests::e2e::E2eHarness;
use prempti_tests::interceptor::assert_empty_stdout;

macro_rules! require_falco {
    () => {
        match E2eHarness::start("passthrough") {
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

// Passthrough short-circuits at register: every tool call resolves as
// `defer` immediately, without waiting for rule evaluation. For the Claude
// interceptor that renders as exit 0 with empty stdout (Claude's normal
// permission flow then applies). From the interceptor's POV the result is
// indistinguishable from monitor's defer; the unique broker behavior (no
// pending insert, no rule-eval wait) is covered by the unit tests in
// `plugins/coding-agents-plugin/src/broker.rs`. These tests just confirm the
// wire-level result.

#[test]
fn passthrough_rm_rf_deferred() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm -rf /"}"#, cwd(), "pt-rm");
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}

#[test]
fn passthrough_write_sensitive_deferred() {
    let h = require_falco!();
    let path = if cfg!(windows) {
        "C:/Windows/system.ini"
    } else {
        "/etc/passwd"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "pt-wsen",
    );
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}

#[test]
fn passthrough_write_outside_cwd_deferred() {
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
        "pt-wout",
    );
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}

#[test]
fn passthrough_safe_command_deferred() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "pt-ls");
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}
