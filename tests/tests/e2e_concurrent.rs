//! Concurrent sessions E2E test: multiple interceptor processes in flight at once.
//!
//! These tests exercise the broker's correlation-ID routing under parallel load:
//! each thread spawns a fresh interceptor process that connects to the same broker.
//! If correlation IDs were swapped, responses would be misrouted and verdict assertions
//! would fail.

use std::thread;

use cak_tests::e2e::E2eHarness;
use cak_tests::interceptor::assert_decision;

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

const N: usize = 16;

#[test]
fn parallel_allows_all_resolve() {
    let h = require_falco!();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let harness = &h;
                scope.spawn(move || {
                    let input = E2eHarness::make_input(
                        "Bash",
                        r#"{"command":"echo hello"}"#,
                        cwd(),
                        &format!("concurrent-allow-{i}"),
                    );
                    harness.run_hook(&input)
                })
            })
            .collect();
        for handle in handles {
            let r = handle.join().expect("thread panicked");
            assert_decision(&r, "allow");
        }
    });
}

#[test]
fn parallel_denies_all_resolve() {
    let h = require_falco!();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let harness = &h;
                scope.spawn(move || {
                    let input = E2eHarness::make_input(
                        "Bash",
                        r#"{"command":"rm -rf /tmp/nuke"}"#,
                        cwd(),
                        &format!("concurrent-deny-{i}"),
                    );
                    harness.run_hook(&input)
                })
            })
            .collect();
        for handle in handles {
            let r = handle.join().expect("thread panicked");
            assert_decision(&r, "deny");
        }
    });
}

/// Mixed allow/deny requests: each response must match its own request's expectation.
/// If the broker's correlation-ID routing swapped two responses, the expected decision
/// for at least one thread would mismatch.
#[test]
fn parallel_mixed_routes_correctly() {
    let h = require_falco!();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let is_deny = i % 2 == 0;
                let harness = &h;
                scope.spawn(move || {
                    let cmd = if is_deny {
                        r#"{"command":"rm -rf /tmp/nuke"}"#
                    } else {
                        r#"{"command":"echo ok"}"#
                    };
                    let input = E2eHarness::make_input("Bash", cmd, cwd(), &format!("mixed-{i}"));
                    (is_deny, harness.run_hook(&input))
                })
            })
            .collect();
        for handle in handles {
            let (is_deny, r) = handle.join().expect("thread panicked");
            let expected = if is_deny { "deny" } else { "allow" };
            assert_decision(&r, expected);
        }
    });
}
