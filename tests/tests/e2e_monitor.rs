use prempti_tests::e2e::E2eHarness;
use prempti_tests::interceptor::assert_decision;

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
fn monitor_rm_rf_allowed() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm -rf /"}"#, cwd(), "mon-rm");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn monitor_write_sensitive_allowed() {
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
    assert_decision(&r, "allow");
}

#[test]
fn monitor_write_outside_cwd_allowed() {
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
    assert_decision(&r, "allow");
}

#[test]
fn monitor_safe_command_allowed() {
    let h = require_falco!();
    let input = E2eHarness::make_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "mon-ls");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}
