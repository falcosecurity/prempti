//! Look up the PID of the parent process that invoked the interceptor.
//!
//! The PreToolUse hook fires synchronously from the coding agent, so the
//! interceptor's parent is the agent process itself. Capturing this PID
//! lets downstream consumers (e.g. a vanilla Falco running side-by-side
//! with the syscall driver) correlate a hook event with the syscall
//! events emitted by the same agent instance — the agent's children
//! inherit it as `proc.apid[]`.

/// PID of the agent process that invoked the interceptor, or `None` if
/// the platform lookup fails (or returns an unusable value like `0`/`1`).
///
/// Algorithm A: trust the immediate parent. We assume the agent's hook
/// dispatcher spawns the interceptor directly without an intermediate
/// shell. If a future change introduces a wrapper, the captured PID
/// would point at the wrapper instead of the agent — the verification
/// strategy is post-install field inspection, not runtime self-check.
pub fn agent_pid() -> Option<u32> {
    platform::agent_pid()
}

#[cfg(unix)]
mod platform {
    unsafe extern "C" {
        fn getppid() -> i32;
    }

    pub fn agent_pid() -> Option<u32> {
        // SAFETY: getppid is async-signal-safe and has no preconditions.
        let ppid = unsafe { getppid() };
        // 0 means error (per POSIX getppid never returns 0 on success, but
        // be defensive). 1 means our parent is PID 1 (init / launchd /
        // systemd), which is not the agent — happens if the agent died
        // before we ran and we got reparented.
        if ppid <= 1 {
            None
        } else {
            Some(ppid as u32)
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    /// `PROCESS_BASIC_INFORMATION` as documented by Microsoft for
    /// `NtQueryInformationProcess` with `ProcessBasicInformation` (class 0).
    /// `ULONG_PTR` is pointer-sized — `usize` on both x64 and ARM64.
    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process_handle: isize,
            process_information_class: i32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    /// Pseudo-handle for the current process. `GetCurrentProcess()` returns
    /// `(HANDLE)-1`; hardcoding avoids a kernel32 dependency for a constant.
    const CURRENT_PROCESS_PSEUDO_HANDLE: isize = -1;

    /// `ProcessBasicInformation` class index — stable since NT 4.
    const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;

    pub fn agent_pid() -> Option<u32> {
        // SAFETY: passing a properly-aligned PROCESS_BASIC_INFORMATION
        // buffer of the documented size. NtQueryInformationProcess writes
        // into it iff status >= 0.
        unsafe {
            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length: u32 = 0;
            let status = NtQueryInformationProcess(
                CURRENT_PROCESS_PSEUDO_HANDLE,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );
            // NTSTATUS: negative = error.
            if status < 0 {
                return None;
            }
            let ppid = pbi.inherited_from_unique_process_id;
            // Windows PIDs are DWORDs (32-bit). Anything beyond u32 means
            // the kernel handed us garbage. 0 means System Idle Process,
            // not a valid parent.
            if ppid == 0 || ppid > u32::MAX as usize {
                None
            } else {
                Some(ppid as u32)
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    pub fn agent_pid() -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Unix, `cargo test` runs each test in a thread of the test binary,
    /// whose parent is `cargo` (or the IDE / shell that spawned it).
    /// PPID is always > 1 in a normal test run.
    #[test]
    #[cfg(unix)]
    fn returns_some_when_parent_is_not_init() {
        let pid = agent_pid().expect("getppid should yield a non-init parent");
        assert!(pid > 1, "expected > 1, got {pid}");
    }

    /// On Windows, the test binary is launched by cargo/MSBuild, so the
    /// parent PID is a real process. We can't assert specific values, but
    /// we can assert the call doesn't fail in the standard test environment.
    #[test]
    #[cfg(windows)]
    fn returns_some_in_standard_test_environment() {
        let pid = agent_pid().expect("NtQueryInformationProcess should succeed for self");
        assert!(pid > 0, "expected > 0, got {pid}");
    }
}
