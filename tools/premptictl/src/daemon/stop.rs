use std::io;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// Try to stop Falco gracefully, escalating to a hard kill on timeout.
///
/// Unix: SIGTERM → wait → SIGKILL on timeout.
/// Windows: per the design (option `a`), no real graceful channel — we
/// `TerminateProcess` directly and wait. The cleanup chain around this
/// (drain pipes, hook remove, close logs) still runs gracefully, which
/// is the win over today's `taskkill /F /IM falco.exe`.
pub fn graceful_stop(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    request_graceful_stop(child)?;
    if let Some(status) = wait_with_timeout(child, timeout)? {
        return Ok(status);
    }
    eprintln!(
        "supervisor: Falco did not exit within {}s, escalating to forced termination",
        timeout.as_secs()
    );
    let _ = child.kill();
    child.wait()
}

#[cfg(unix)]
fn request_graceful_stop(child: &mut Child) -> io::Result<()> {
    let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) else {
        // PID 0 / invalid: a spawned Child should never have this; treat as
        // "already gone" for safety.
        return Ok(());
    };
    match rustix::process::kill_process(pid, rustix::process::Signal::TERM) {
        Ok(()) => Ok(()),
        // ESRCH means the process is already gone; that's fine.
        Err(e) if e == rustix::io::Errno::SRCH => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(windows)]
fn request_graceful_stop(child: &mut Child) -> io::Result<()> {
    // Decision (a): TerminateProcess. Std's `Child::kill` calls
    // TerminateProcess under the hood on Windows.
    match child.kill() {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()), // already exited
        Err(e) => Err(e),
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    let poll_interval = Duration::from_millis(50);
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(Some(status)),
            None => {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let remaining = deadline - now;
                std::thread::sleep(poll_interval.min(remaining));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Spawn a tiny child that exits immediately so we can exercise the
    /// stop path without depending on Falco.
    fn spawn_quick_exit() -> Child {
        #[cfg(unix)]
        {
            Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .spawn()
                .unwrap()
        }
        #[cfg(windows)]
        {
            Command::new("cmd").args(["/C", "exit 0"]).spawn().unwrap()
        }
    }

    /// A child that ignores SIGTERM and runs longer than the test timeout.
    /// Used to exercise the SIGKILL escalation path.
    #[cfg(unix)]
    fn spawn_term_ignorer() -> Child {
        Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; sleep 30"])
            .spawn()
            .unwrap()
    }

    #[test]
    fn graceful_stop_returns_quickly_when_child_already_exited() {
        let mut child = spawn_quick_exit();
        // Give the OS a moment to reap the process state.
        std::thread::sleep(Duration::from_millis(50));
        let status = graceful_stop(&mut child, Duration::from_secs(1)).unwrap();
        // Either success or "killed" — both are fine here.
        let _ = status;
    }

    #[cfg(unix)]
    #[test]
    fn escalates_to_kill_when_term_ignored() {
        let mut child = spawn_term_ignorer();
        // Let the shell start and install its TERM trap before we signal it.
        // Without this, SIGTERM can race the trap installation.
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let status = graceful_stop(&mut child, Duration::from_millis(200)).unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "expected escalation timeout to be observed, took {:?}",
            elapsed
        );
        assert!(elapsed < Duration::from_secs(2), "took {:?}", elapsed);
        assert!(!status.success(), "expected non-zero exit after SIGKILL");
    }
}
