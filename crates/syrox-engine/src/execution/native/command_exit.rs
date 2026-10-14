use std::io;

/// Restores the signal's default disposition and delivers it to this worker.
/// A successful terminating signal does not return. An ignored signal returns
/// an error rather than pretending that normal exit reproduces signal status.
///
/// # Safety
/// The dedicated worker must have completed namespace/terminal cleanup and
/// relinquished every resource needing a destructor. No concurrent work may
/// depend on its signal dispositions or continued process lifetime.
pub unsafe fn reraise_shell_command_signal(signal: i32) -> io::Result<()> {
    validate_signal(signal)?;
    // SAFETY: initialized signal structures and live scalar destinations.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&raw mut mask) != 0 || libc::sigaddset(&raw mut mask, signal) != 0 {
            return Err(io::Error::last_os_error());
        }
        if signal != libc::SIGKILL {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            if libc::sigemptyset(&raw mut action.sa_mask) != 0
                || libc::sigaction(signal, &raw const action, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        if libc::sigprocmask(
            libc::SIG_UNBLOCK,
            &raw const mask,
            std::ptr::null_mut(),
        ) != 0
            || libc::kill(libc::getpid(), signal) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Err(io::Error::other(
        "command termination signal did not terminate worker",
    ))
}

fn validate_signal(signal: i32) -> io::Result<()> {
    if !(1..=64).contains(&signal)
        || matches!(
            signal,
            libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
        )
    {
        return Err(io::Error::other(
            "invalid command termination signal",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};

    const CHILD: &str = "SYROX_COMMAND_EXIT_CHILD";
    const FIXTURE: &str = "execution::native::command_exit::tests::signal_exit_child";

    #[test]
    #[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
    fn signal_exit_child() {
        let mode = std::env::var(CHILD).expect("parent test must supply the fixture environment");
        if mode == "exit137" {
            std::process::exit(137);
        }
        let signal: i32 = mode.parse().unwrap();
        // SAFETY: isolated reexec fixture, no namespace/terminal or resource owners.
        unsafe { reraise_shell_command_signal(signal) }.unwrap();
        panic!("terminating signal returned");
    }

    #[test]
    fn preserves_signal_kind_after_cleanup_boundary() {
        let launch = |mode: &str| {
            Command::new(crate::reexec_test_executable(FIXTURE, true))
                .args([
                    "--ignored",
                    "--exact",
                    FIXTURE,
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
        };
        let exited = launch("exit137");
        assert_eq!(exited.code(), Some(137));
        assert_eq!(exited.signal(), None);
        for signal in [
            libc::SIGKILL,
            libc::SIGINT,
            libc::SIGTERM,
        ] {
            let signaled = launch(&signal.to_string());
            assert_eq!(signaled.code(), None);
            assert_eq!(signaled.signal(), Some(signal));
        }
    }

    #[test]
    fn rejects_invalid_and_job_stop_signals_before_effects() {
        for signal in [
            0,
            -1,
            65,
            libc::SIGSTOP,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ] {
            // SAFETY: these invalid requests are rejected before signal effects.
            assert!(unsafe { reraise_shell_command_signal(signal) }.is_err());
        }
    }
}
