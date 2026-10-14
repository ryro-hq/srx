use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Monitor,
    Signals,
    Mounts,
    Inputs,
    Verification,
    Privileges,
    Descriptors,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    stage: Stage,
    errno: Option<i32>,
    message: String,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "build namespace {:?}: {}",
            self.stage, self.message
        )
    }
}
impl std::error::Error for Failure {}

pub(super) fn send(writer: &mut UnixStream, stage: Stage, error: &io::Error) {
    let mut failure = Failure {
        stage,
        errno: error.raw_os_error(),
        message: error.to_string(),
    };
    while let Ok(bytes) = serde_json::to_vec(&failure) {
        if bytes.len() <= MAX_BYTES {
            let _ = writer.write_all(&bytes);
            return;
        }
        failure.message.pop();
    }
}

fn decode(bytes: &[u8]) -> io::Error {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return io::Error::other("build namespace failed without a bounded diagnostic");
    }
    match serde_json::from_slice::<Failure>(bytes) {
        Ok(failure) => {
            let kind = failure
                .errno
                .map_or(io::ErrorKind::Other, |errno| {
                    io::Error::from_raw_os_error(errno).kind()
                });
            io::Error::new(kind, failure)
        }
        Err(error) => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

pub(super) fn receive(
    reader: &mut UnixStream,
    cancellation: &crate::cancellation::Cancellation,
    deadline: Instant,
) -> io::Error {
    let mut bytes = Vec::new();
    let mut buffer = [0; 512];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return decode(&bytes),
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > MAX_BYTES {
                    return decode(&bytes);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Err(error) = super::check(cancellation, deadline) {
                    return error;
                }
                if let Err(error) = super::super::managed::poll(&[reader.as_fd()], 20) {
                    return error;
                }
            }
            Err(error) => return error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_preparation_stage_and_os_failure() {
        let bytes = serde_json::to_vec(&Failure {
            stage: Stage::Mounts,
            errno: Some(libc::EPERM),
            message: "operation not permitted (os error 1)".into(),
        })
        .unwrap();
        let error = decode(&bytes);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("Mounts"));
        assert!(error.to_string().contains("os error 1"));
    }

    #[test]
    fn eof_truncation_unknown_fields_and_excess_are_failures() {
        for bytes in [
            &b""[..],
            &b"{\"stage\":\"mounts\""[..],
            &b"{\"stage\":\"mounts\",\"errno\":null,\"message\":\"x\",\"authority\":true}"[..],
            &vec![b'x'; MAX_BYTES + 1][..],
        ] {
            assert!(!decode(bytes).to_string().is_empty());
        }
    }

    #[test]
    fn long_diagnostic_is_bounded_without_losing_valid_json() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        send(
            &mut writer,
            Stage::Inputs,
            &io::Error::other("🦀\n".repeat(5000)),
        );
        drop(writer);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(bytes.len() <= MAX_BYTES);
        assert!(
            decode(&bytes)
                .to_string()
                .starts_with("build namespace Inputs:")
        );
    }
}
