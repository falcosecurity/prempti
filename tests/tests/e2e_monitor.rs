use prempti_tests::e2e::E2eHarness;
use prempti_tests::interceptor::assert_empty_stdout;

// Monitor mode evaluates and logs rules but enforces nothing: every verdict
// resolves as `defer` (Prempti steps aside) after the rule-eval wait. For the
// Claude interceptor that renders as exit 0 with empty stdout — Claude's normal
// permission flow then applies. Would-deny / would-ask still hit the Falco log.
macro_rules! require_falco {
    () => {
        match E2eHarness::start("monitor") {
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

#[test]
fn monitor_rm_rf_deferred() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm -rf /"}"#, cwd(), "mon-rm");
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}

#[test]
fn monitor_write_sensitive_deferred() {
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
        "mon-wsen",
    );
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}

#[test]
fn monitor_write_outside_cwd_deferred() {
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
        "mon-wout",
    );
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}

#[test]
fn monitor_safe_command_deferred() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "mon-ls");
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
}
