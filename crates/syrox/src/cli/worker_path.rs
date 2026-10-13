use std::fs::OpenOptions;
use std::io::{self, Read as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use syrox_engine::{cancellation::Cancellation, store::ContentDigest};

const MAX_WORKER_BYTES: u64 = 128 * 1024 * 1024;

/// Installed alongside srx; never resolve an execution helper through PATH.
pub(crate) fn installed() -> Result<PathBuf, String> {
    let worker = build_candidate()?;
    if !worker.is_file() {
        return Err(format!(
            "missing build worker {}; install srx and syrox-worker together",
            worker.display()
        ));
    }
    Ok(worker)
}

/// Supply the fixed `HostBootstrap` candidate without requiring it for Managed
/// or imported results. The engine opens it only when realizing a host build.
pub(crate) fn build_candidate() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map(|executable| executable.with_file_name("syrox-worker"))
        .map_err(|error| error.to_string())
}

/// Hash only this explicit candidate. No helper discovery or PATH lookup occurs.
pub(crate) fn digest(path: &Path, cancellation: &Cancellation) -> Result<ContentDigest, String> {
    cancellation
        .check()
        .map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot open worker candidate {}: {error}",
                path.display()
            )
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_WORKER_BYTES {
        return Err("worker candidate must be a regular file of at most 128 MiB".into());
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut length = 0u64;
    loop {
        cancellation
            .check()
            .map_err(|error| error.to_string())?;
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("cannot read worker candidate: {error}")),
        };
        if count == 0 {
            break;
        }
        length += count as u64;
        if length > MAX_WORKER_BYTES {
            return Err("worker candidate grew beyond 128 MiB".into());
        }
        hasher.update(&buffer[..count]);
    }
    cancellation
        .check()
        .map_err(|error| error.to_string())?;
    format!("{:x}", hasher.finalize())
        .parse()
        .map_err(|error| format!("invalid worker digest: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn hashes_exact_candidate_contents_across_multiple_chunks() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("candidate");
        for bytes in [
            vec![],
            b"worker bytes".to_vec(),
            vec![0xa5; 150_001],
        ] {
            fs::write(&path, &bytes).unwrap();
            assert_eq!(
                digest(&path, &Cancellation::default()).unwrap(),
                ContentDigest::sha256(&bytes)
            );
        }
    }

    #[test]
    fn cancelled_request_does_not_attempt_to_open_missing_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let cancellation = Cancellation::default();
        cancellation.cancel();
        assert_eq!(
            digest(&temp.path().join("absent"), &cancellation).unwrap_err(),
            "operation cancelled"
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn symlink_directory_and_sparse_oversized_file_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("candidate");
        fs::write(&path, b"worker").unwrap();
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        let cancel = Cancellation::default();
        assert!(digest(&link, &cancel).is_err());
        assert!(digest(temp.path(), &cancel).is_err());
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_WORKER_BYTES + 1)
            .unwrap();
        assert!(
            digest(&path, &cancel)
                .unwrap_err()
                .contains("at most 128 MiB")
        );
    }

    #[test]
    #[allow(unsafe_code)] // Linux fixture creation only; path is NUL-terminated and live.
    fn fifo_without_writer_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fifo");
        let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString supplies a valid NUL-terminated pathname for this call.
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = digest(&path, &Cancellation::default());
            sender.send(result).unwrap();
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("FIFO open must remain nonblocking")
                .is_err()
        );
        worker.join().unwrap();
    }
}
