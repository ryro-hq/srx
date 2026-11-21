use super::policy::refused;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use syrox_system::descriptor;

pub(super) struct Journal {
    pub directory: File,
    sequence: u32,
    pub released: bool,
}

impl Journal {
    // Only the validated recovery snapshot may resume an existing journal.
    pub fn resume(directory: File, sequence: u32) -> Self {
        Self {
            directory,
            sequence,
            released: false,
        }
    }

    pub fn create(state: &File, name: &str) -> io::Result<Self> {
        let directory = new_directory(state, name)?;
        state.sync_all()?;
        Ok(Self {
            directory,
            sequence: 0,
            released: false,
        })
    }

    pub fn record(&mut self, state: &'static str, details: serde_json::Value) -> io::Result<File> {
        let name = format!("{:04}-{state}.json", self.sequence);
        let mut file = new_file(&self.directory, &name)?;
        let record = serde_json::Map::from_iter([
            ("version".to_owned(), serde_json::Value::from(1)),
            ("state".to_owned(), serde_json::Value::from(state)),
            ("details".to_owned(), details),
        ]);
        let bytes = serde_json::to_vec(&record)?;
        if bytes.len() >= 65_536 {
            return Err(refused("helper journal record exceeds 64 KiB"));
        }
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        self.directory.sync_all()?;
        self.sequence += 1;
        if state == "released" {
            self.released = true;
        }
        descriptor::open_resolved(
            Some(self.directory.as_fd()),
            Path::new(&name),
            false,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
        )
    }
}

pub(super) fn new_directory(parent: &File, name: &str) -> io::Result<File> {
    let name = component(name)?;
    // SAFETY: validated single component and a live private parent descriptor.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = descriptor::open_resolved(
        Some(parent.as_fd()),
        Path::new(
            name.to_str()
                .expect("component was built from a validated &str"),
        ),
        true,
        libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    // An unusual administrator umask must not silently change the contract.
    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    directory.sync_all()?;
    parent.sync_all()?;
    Ok(directory)
}

pub(super) fn new_file(parent: &File, name: &str) -> io::Result<File> {
    let name = component(name)?;
    // SAFETY: fixed private regular file creation, never an existing resource.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor has no other Rust owner.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn component(name: &str) -> io::Result<CString> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(refused("invalid private helper component"));
    }
    CString::new(name).map_err(|_| refused("invalid helper component"))
}
