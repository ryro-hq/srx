use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

pub(in crate::execution::native) fn scrub_init_stdio() -> io::Result<()> {
    let null = crate::execution::native::environment::open_null()?;
    // SAFETY: duplicate the validated null device above standard descriptors,
    // even if the initial open occupied a previously closed standard slot.
    let raw = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a fresh owned descriptor.
    let pinned = unsafe { OwnedFd::from_raw_fd(raw) };
    drop(null);
    for target in 0..3 {
        // SAFETY: dedicated namespace init owns these standard descriptor slots;
        // explicit payload IO descriptors are distinct and retained above 2.
        crate::execution::native::checked(
            unsafe { libc::dup2(pinned.as_raw_fd(), target) }.into(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::fd::{
        self as linux_fd,
        terminal::{Pty, WindowSize},
    };
    use std::os::fd::AsFd as _;

    #[test]
    fn original_terminal_cannot_be_reopened_through_init_stdio_after_scrub() {
        // The fixture scrubs descriptors 0..2; restore the harness channels after
        // the assertions so its parent can require a positive libtest summary.
        struct HarnessStdio(Vec<OwnedFd>);
        impl Drop for HarnessStdio {
            fn drop(&mut self) {
                for (target, descriptor) in (0..3).zip(&self.0) {
                    // SAFETY: this isolated fixture owns every standard slot.
                    assert!(unsafe { libc::dup2(descriptor.as_raw_fd(), target) } >= 0);
                }
            }
        }
        if linux_fd::retention_fork_tests::isolate_test(
            "execution::native::proxy::stdio::tests::original_terminal_cannot_be_reopened_through_init_stdio_after_scrub",
            "SYROX_PROXY_INIT_STDIO_TEST",
        ) {
            return;
        }
        let _harness_stdio = HarnessStdio(
            (0..3)
                .map(|descriptor| {
                    // SAFETY: duplicate live harness channels above standard slots.
                    let raw = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
                    assert!(raw >= 0);
                    // SAFETY: fcntl returned a fresh owned descriptor.
                    unsafe { OwnedFd::from_raw_fd(raw) }
                })
                .collect(),
        );
        let terminal = Pty::open(
            WindowSize {
                rows: 24,
                columns: 80,
                x_pixels: 0,
                y_pixels: 0,
            },
            None,
        )
        .unwrap();
        let explicit = terminal.slave().try_clone_to_owned().unwrap();
        let original = linux_fd::metadata(explicit.as_fd())
            .unwrap()
            .identity();
        for target in 0..3 {
            // SAFETY: reexec-isolated test process, no other test owns its stdio.
            assert!(unsafe { libc::dup2(explicit.as_raw_fd(), target) } >= 0);
        }
        scrub_init_stdio().unwrap();
        for target in 0..3 {
            let reopened = std::fs::File::open(format!("/proc/self/fd/{target}")).unwrap();
            let metadata = linux_fd::metadata(reopened.as_fd()).unwrap();
            assert_ne!(metadata.identity(), original);
            assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFCHR);
            assert_eq!(
                (
                    libc::major(metadata.rdev()),
                    libc::minor(metadata.rdev())
                ),
                (1, 3)
            );
        }
        // The explicit payload role survives scrubbing: pre_exec can still
        // install its private PTY/redirects after PID1's originals were removed.
        assert_eq!(
            linux_fd::metadata(explicit.as_fd())
                .unwrap()
                .identity(),
            original
        );
    }
}
