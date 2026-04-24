//! Config hot-reload E2E test.
//!
//! This test specifies the desired behavior: when the plugin's `init_config` is
//! modified (e.g., `mode: guardrails` → `mode: monitor`), Falco's
//! `watch_config_files` feature must trigger a full plugin re-init (destroy +
//! new) so subsequent tool calls observe the updated config.
//!
//! **Currently `#[ignore]`** — the test is a regression gate, not a passing
//! test, because the plugin has a race during hot-restart:
//!   1. Falco detects the config change and calls `Plugin::new()` for the new
//!      instance BEFORE (or concurrent with) dropping the old one.
//!   2. The old plugin's socket server thread is still inside `accept()` with
//!      a 1s timeout (`ACCEPT_TIMEOUT` in `socket_server.rs`) — its listener
//!      is still bound.
//!   3. The new `prepare_listener()` runs `has_live_peer()`, which
//!      successfully connects to the still-bound old listener and treats it
//!      as a live peer, aborting the bind with:
//!      "broker socket ... is already in use by another coding-agents-kit
//!      Falco instance."
//!   4. Falco reports `"hot restart failure"` and keeps the old instance
//!      running, so the config change is silently not applied.
//!
//! Falco also does not respond to SIGHUP in a way that triggers a reload,
//! and after a failed hot-restart it does not retry on subsequent config
//! changes — so there is no workaround at the test level.
//!
//! Un-ignore this test once the hot-reload race is fixed (see TODOs.md
//! "High Priority"). Run with `cargo test --test e2e_hot_reload -- --ignored`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cak_tests::e2e::E2eHarness;
use cak_tests::interceptor::{assert_decision, InterceptorResult};

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

fn config_path(h: &E2eHarness) -> PathBuf {
    h.e2e_dir.join("falco.yaml")
}

fn decision_is(result: &InterceptorResult, expected: &str) -> bool {
    let needle = format!("\"permissionDecision\":\"{}\"", expected);
    result.stdout.contains(&needle)
}

/// Poll the actual observable behavior until reload has taken effect.
fn wait_for_decision(
    h: &E2eHarness,
    input: &str,
    expected: &str,
    total: Duration,
) -> InterceptorResult {
    let start = Instant::now();
    loop {
        let result = h.run_hook(input);
        if decision_is(&result, expected) || start.elapsed() >= total {
            return result;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn rewrite_config(path: &Path, from: &str, to: &str) -> String {
    let current = std::fs::read_to_string(path).expect("read config");
    assert!(
        current.contains(from),
        "config did not contain expected substring: {from:?}"
    );
    let new = current.replace(from, to);
    std::fs::write(path, &new).expect("write config");
    new
}

/// Mode switch via config rewrite: Falco's `watch_config_files` detects the
/// change and performs a full plugin re-init. After reload, a previously-denied
/// rm -rf call must resolve as allow (monitor mode suppresses deny/ask verdicts).
#[ignore = "blocked on plugin hot-reload race — see module docs and TODOs.md"]
#[test]
fn mode_switch_hot_reload() {
    let h = require_falco!();

    // Baseline: guardrails mode denies rm -rf.
    let deny_input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"rm -rf /tmp/nuke"}"#,
        cwd(),
        "hotreload-phase1",
    );
    let r = h.run_hook(&deny_input);
    assert_decision(&r, "deny");

    // Flip the plugin's mode in the config file.
    // `watch_config_files: true` (set by the harness) should pick this up.
    let _ = rewrite_config(&config_path(&h), "mode: guardrails", "mode: monitor");

    // Same rm -rf call now allowed — monitor mode logs the deny rule match
    // but resolves every verdict as allow via the seen signal.
    let allow_input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"rm -rf /tmp/nuke"}"#,
        cwd(),
        "hotreload-phase2",
    );
    let r = wait_for_decision(&h, &allow_input, "allow", Duration::from_secs(15));
    assert_decision(&r, "allow");
}
