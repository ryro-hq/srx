use super::{check, poll};
use crate::cancellation::Cancellation;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, FromRawFd as _};
use std::time::Instant;

const MAX_BYTES: usize = 4096;
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Status {
    Ready {},
    Failed {
        errno: i32,
        message: String,
    },
}
pub(in crate::execution::native) struct Sender(Option<File>);
pub(super) struct Receiver(File);
pub(super) fn pair() -> io::Result<(Receiver, Sender)> {
    let mut descriptors = [-1; 2];
    // SAFETY: writable pair; successful pipe2 transfers both owned descriptors.
    super::super::checked(
        unsafe {
            libc::pipe2(
                descriptors.as_mut_ptr(),
                libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        }
        .into(),
    )?;
    // SAFETY: the successful pipe2 returned two distinct new descriptors.
    let (receiver, sender) = unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    };
    Ok((Receiver(receiver), Sender(Some(sender))))
}
impl Sender {
    pub(in crate::execution::native) fn ready(&mut self) -> io::Result<()> {
        self.send(&Status::Ready {})
    }
    pub(in crate::execution::native) fn failed(&mut self, error: &io::Error) -> io::Result<()> {
        let mut message = error.to_string();
        // Account for worst-case JSON escaping, preserving UTF-8 boundaries.
        let mut length = message.len().min((MAX_BYTES - 128) / 6);
        while !message.is_char_boundary(length) {
            length -= 1;
        }
        message.truncate(length);
        self.send(&Status::Failed {
            errno: error.raw_os_error().unwrap_or(0),
            message,
        })
    }
    fn send(&mut self, status: &Status) -> io::Result<()> {
        let mut channel = self
            .0
            .take()
            .ok_or_else(|| io::Error::other("namespace preparation already reported"))?;
        let bytes = serde_json::to_vec(status).map_err(io::Error::other)?;
        if bytes.len() > MAX_BYTES {
            return Err(io::Error::other(
                "namespace preparation report exceeds bound",
            ));
        }
        // Single bounded nonblocking send; failure consumes the report. Closing
        // this writer terminates the frame even when the child is still alive.
        channel.write_all(&bytes)
    }
}
impl Receiver {
    pub(super) fn wait(
        mut self,
        deadline: Instant,
        cancellation: &Cancellation,
        mut check_owner: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            check(deadline, cancellation)?;
            check_owner()?;
            match self.0.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    if bytes.len() + length > MAX_BYTES {
                        return Err(io::Error::other(
                            "namespace preparation report exceeds bound",
                        ));
                    }
                    bytes.extend_from_slice(&buffer[..length]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    poll(&[self.0.as_fd()], 20)?;
                }
                Err(error) => return Err(error),
            }
        }
        let status: Status = serde_json::from_slice(&bytes).map_err(|_| {
            io::Error::other("namespace init ended without a valid preparation report")
        })?;
        check(deadline, cancellation)?;
        check_owner()?;
        match status {
            Status::Ready {} => Ok(()),
            Status::Failed {
                errno,
                message,
            } => Err(io::Error::other(format!(
                "namespace preparation failed (errno {errno}): {message}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[test]
    fn preparation_requires_one_complete_report_and_preserves_failure() {
        let cancel = Cancellation::default();
        let (receiver, mut sender) = pair().unwrap();
        sender.ready().unwrap();
        assert!(sender.ready().is_err());
        receiver
            .wait(deadline(), &cancel, || Ok(()))
            .unwrap();
        let (receiver, mut sender) = pair().unwrap();
        sender
            .failed(&io::Error::from_raw_os_error(libc::EPERM))
            .unwrap();
        let error = receiver
            .wait(deadline(), &cancel, || Ok(()))
            .unwrap_err();
        assert!(error.to_string().contains("errno 1"));
        assert!(
            error
                .to_string()
                .contains("Operation not permitted")
        );
    }

    #[test]
    fn closed_empty_truncated_unknown_and_oversized_reports_are_refused() {
        for bytes in [
            Vec::new(),
            b"{\"status\":".to_vec(),
            b"{\"status\":\"ready\",\"unknown\":true}".to_vec(),
            vec![b'x'; MAX_BYTES + 1],
        ] {
            let (receiver, sender) = pair().unwrap();
            sender.0.unwrap().write_all(&bytes).unwrap();
            assert!(
                receiver
                    .wait(deadline(), &Cancellation::default(), || Ok(()))
                    .is_err()
            );
        }
    }

    #[test]
    fn preparation_is_bounded_by_cancellation_and_deadline_without_ack() {
        let (receiver, _sender) = pair().unwrap();
        let cancel = Cancellation::default();
        cancel.cancel();
        let error = receiver
            .wait(deadline(), &cancel, || Ok(()))
            .unwrap_err();
        assert!(crate::cancellation::is_cancellation_io(&error));
        let (receiver, _sender) = pair().unwrap();
        assert!(
            receiver
                .wait(
                    Instant::now(),
                    &Cancellation::default(),
                    || Ok(())
                )
                .is_err()
        );
    }

    #[test]
    fn long_escaped_failure_remains_bounded_and_is_not_ready() {
        let (receiver, mut sender) = pair().unwrap();
        sender
            .failed(&io::Error::other("\0é".repeat(MAX_BYTES)))
            .unwrap();
        let error = receiver
            .wait(deadline(), &Cancellation::default(), || Ok(()))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("namespace preparation failed")
        );
    }

    #[test]
    fn owner_stop_interrupts_wait_and_is_rechecked_after_ready() {
        let (receiver, _sender) = pair().unwrap();
        let error = receiver
            .wait(deadline(), &Cancellation::default(), || {
                Err(io::Error::other("controlled owner stopped"))
            })
            .unwrap_err();
        assert!(error.to_string().contains("owner stopped"));

        let (receiver, mut sender) = pair().unwrap();
        sender.ready().unwrap();
        let mut observations = 0;
        let error = receiver
            .wait(deadline(), &Cancellation::default(), || {
                observations += 1;
                if observations >= 3 {
                    Err(io::Error::other(
                        "controlled stop after readiness",
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.to_string().contains("stop after readiness"));
    }
}
