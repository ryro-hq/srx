use super::*;
use std::io::{Read as _, Seek as _, Write as _};

#[test]
fn snapshot_is_independent_readonly_bounded_and_close_on_exec() {
    let mut source = tempfile::tempfile().unwrap();
    source.write_all(b"original credential").unwrap();
    source.rewind().unwrap();
    let mut snapshot = snapshot_secret(source.try_clone().unwrap(), 19, || Ok(())).unwrap();
    source.rewind().unwrap();
    source.write_all(b"modified credential").unwrap();
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original credential");
    assert!(snapshot.write_all(b"change").is_err());
    assert!(snapshot.set_len(0).is_err());
    validate_secret(snapshot.as_fd()).unwrap();
    let owner = snapshot.metadata().unwrap().uid();
    validate_secret_owned(snapshot.as_fd(), owner).unwrap();
    assert!(validate_secret_owned(snapshot.as_fd(), owner.wrapping_add(1)).is_err());
    // SAFETY: fcntl only observes this live descriptor's flags and seals.
    unsafe {
        assert_ne!(
            libc::fcntl(snapshot.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            libc::fcntl(snapshot.as_raw_fd(), libc::F_GET_SEALS) & SEALS,
            SEALS
        );
    }
    snapshot
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    assert!(validate_secret(snapshot.as_fd()).is_err());
    let mut writable = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/fd/{}", snapshot.as_raw_fd()))
        .unwrap();
    snapshot
        .set_permissions(std::fs::Permissions::from_mode(0o400))
        .unwrap();
    assert!(writable.write_all(b"change").is_err());
    assert!(validate_secret(writable.as_fd()).is_err());
    validate_secret(snapshot.as_fd()).unwrap();
}

#[test]
fn admission_rejects_oversize_unsealed_and_cancelled_sources() {
    for (bytes, maximum, accepted) in [
        (0, 0, true),
        (1, 0, false),
        (65536, 65536, true),
        (65537, u64::MAX, false),
        (5, 4, false),
    ] {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![1; bytes]).unwrap();
        file.rewind().unwrap();
        assert!(validate_secret(file.as_fd()).is_err());
        assert_eq!(
            snapshot_secret(file, maximum, || Ok(())).is_ok(),
            accepted
        );
    }
    let error = snapshot_secret(tempfile::tempfile().unwrap(), 0, || {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "deadline",
        ))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn short_io_and_interrupted_retries_observe_cancellation() {
    struct Reader {
        interrupted: bool,
        bytes: &'static [u8],
    }
    impl io::Read for Reader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.interrupted {
                self.interrupted = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = self.bytes.len().min(bytes.len()).min(2);
            bytes[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }
    #[derive(Default)]
    struct Writer {
        interrupted: bool,
        bytes: Vec<u8>,
    }
    impl io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.interrupted {
                self.interrupted = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = bytes.len().min(1);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut reader = Reader {
        interrupted: true,
        bytes: b"credential",
    };
    let mut writer = Writer {
        interrupted: true,
        ..Writer::default()
    };
    copy(&mut reader, &mut writer, 10, &mut || Ok(())).unwrap();
    assert_eq!(writer.bytes, b"credential");
    let mut checks = 0;
    let error = copy(
        &mut Reader {
            interrupted: true,
            bytes: b"credential",
        },
        &mut Vec::new(),
        10,
        &mut || {
            checks += 1;
            if checks == 2 {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(checks, 2);
    let mut checks = 0;
    assert_eq!(
        write(
            &mut Writer {
                interrupted: true,
                ..Writer::default()
            },
            b"x",
            &mut || {
                checks += 1;
                if checks == 2 {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            }
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
}
