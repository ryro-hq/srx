use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};

pub(crate) const MAX_ARGUMENTS: usize = 256;
pub(crate) const MAX_ARGUMENT_BYTES: usize = 4096;
pub(crate) const MAX_ARGUMENT_TOTAL_BYTES: usize = 64 * 1024;
const MAX_CWD_BYTES: usize = 4096;
const MAX_CWD_DEPTH: usize = 32;
// JSON u8 arrays need at most four bytes per source byte, plus bounded framing.
pub(crate) const MAX_REQUEST_BYTES: usize =
    4 * (MAX_ARGUMENT_TOTAL_BYTES + MAX_CWD_BYTES) + MAX_ARGUMENTS * 3 + 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    version: u32,
    alias: String,
    arguments: Vec<Vec<u8>>,
    cwd: Vec<u8>,
}

pub(crate) struct ProxyRequest {
    alias: String,
    arguments: Vec<OsString>,
    cwd: PathBuf,
}

impl fmt::Debug for ProxyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyRequest")
            .field("argument_count", &self.arguments.len())
            .finish_non_exhaustive()
    }
}

impl ProxyRequest {
    pub(crate) fn new(alias: String, arguments: Vec<OsString>, cwd: PathBuf) -> io::Result<Self> {
        let request = Self {
            alias,
            arguments,
            cwd,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn alias(&self) -> &str {
        &self.alias
    }
    pub(crate) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd
    }

    fn validate(&self) -> io::Result<()> {
        if !valid_alias(&self.alias) || self.arguments.len() > MAX_ARGUMENTS {
            return Err(invalid());
        }
        let mut total = 0;
        for argument in &self.arguments {
            let bytes = argument.as_bytes();
            if bytes.len() > MAX_ARGUMENT_BYTES || bytes.contains(&0) {
                return Err(invalid());
            }
            total += bytes.len();
            if total > MAX_ARGUMENT_TOTAL_BYTES {
                return Err(invalid());
            }
        }
        let cwd = self.cwd.as_os_str().as_bytes();
        if cwd.is_empty() || cwd.len() > MAX_CWD_BYTES || cwd.contains(&0) {
            return Err(invalid());
        }
        if cwd != b"." {
            let mut depth = 0;
            for component in cwd.split(|byte| *byte == b'/') {
                depth += 1;
                if component.is_empty()
                    || matches!(component, b"." | b"..")
                    || depth > MAX_CWD_DEPTH
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let wire = WireRequest {
            version: 1,
            alias: self.alias.clone(),
            arguments: self
                .arguments
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
            cwd: self.cwd.as_os_str().as_bytes().to_vec(),
        };
        let mut bytes = b"syrox-shell-command-request-v1\n".to_vec();
        serde_json::to_writer(&mut bytes, &wire).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(invalid());
        }
        let body = bytes
            .strip_prefix(b"syrox-shell-command-request-v1\n")
            .ok_or_else(invalid)?;
        let wire: WireRequest = serde_json::from_slice(body).map_err(|_| invalid())?;
        if wire.version != 1 {
            return Err(invalid());
        }
        let request = Self::new(
            wire.alias,
            wire.arguments
                .into_iter()
                .map(OsString::from_vec)
                .collect(),
            PathBuf::from(OsString::from_vec(wire.cwd)),
        )?;
        if request.canonical_bytes()? != bytes {
            return Err(invalid());
        }
        Ok(request)
    }
}

pub(crate) fn alias_from_wrapper(path: &OsStr) -> io::Result<String> {
    let alias = path
        .as_bytes()
        .strip_prefix(b"/syrox/commands/bin/")
        .ok_or_else(invalid)?;
    let alias = std::str::from_utf8(alias).map_err(|_| invalid())?;
    if !valid_alias(alias) {
        return Err(invalid());
    }
    Ok(alias.into())
}

fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 128
        && alias != "."
        && alias != ".."
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(crate) struct AdmittedProxyRequest {
    request: ProxyRequest,
    descriptors: [OwnedFd; 4],
}

impl fmt::Debug for AdmittedProxyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedProxyRequest")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl AdmittedProxyRequest {
    pub(crate) fn validate(
        request: ProxyRequest,
        descriptors: Vec<OwnedFd>,
        authorized_cwd: BorrowedFd<'_>,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        check(cancel)?;
        request.validate()?;
        if descriptors.len() != 4 {
            return Err(invalid());
        }
        // Give the admitted set independent CLOEXEC descriptor numbers without
        // modifying shared open-file-description flags or offsets.
        let descriptors: [OwnedFd; 4] = descriptors
            .into_iter()
            .map(|descriptor| descriptor.as_fd().try_clone_to_owned())
            .collect::<io::Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| invalid())?;
        let admitted = Self {
            request,
            descriptors,
        };
        admitted.revalidate(authorized_cwd, cancel)?;
        Ok(admitted)
    }

    /// Repeat descriptor and relative-path checks at the execution boundary.
    /// This remains a local observation, not peer/session or terminal authority.
    pub(crate) fn revalidate(
        &self,
        authorized_cwd: BorrowedFd<'_>,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        check(cancel)?;
        self.request.validate()?;
        let expected = linux_fd::open_beneath_no_mounts(authorized_cwd, self.request.cwd(), true)
            .map_err(|_| invalid())?;
        let received = linux_fd::metadata(self.descriptors[0].as_fd())?;
        if received.file_type() != linux_fd::FileType::Directory
            || received.identity() != expected.metadata().identity()
        {
            return Err(invalid());
        }
        for (index, descriptor) in self.descriptors[1..].iter().enumerate() {
            validate_stdio(descriptor.as_fd(), index == 0)?;
        }
        check(cancel)?;
        let current = linux_fd::open_beneath_no_mounts(authorized_cwd, self.request.cwd(), true)
            .map_err(|_| invalid())?;
        if current.metadata().identity() != received.identity() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Transfer descriptor ownership after the caller's final `revalidate`.
    /// This adds no execution authority; the monitor must drop unused stdio
    /// copies after handoff so pipe writers do not delay EOF.
    pub(crate) fn into_parts(self) -> (ProxyRequest, OwnedFd, [OwnedFd; 3]) {
        let [cwd, stdin, stdout, stderr] = self.descriptors;
        (self.request, cwd, [stdin, stdout, stderr])
    }

    pub(crate) fn request(&self) -> &ProxyRequest {
        &self.request
    }
    pub(crate) fn cwd_descriptor(&self) -> BorrowedFd<'_> {
        self.descriptors[0].as_fd()
    }
    pub(crate) fn stdin(&self) -> BorrowedFd<'_> {
        self.descriptors[1].as_fd()
    }
    pub(crate) fn stdout(&self) -> BorrowedFd<'_> {
        self.descriptors[2].as_fd()
    }
    pub(crate) fn stderr(&self) -> BorrowedFd<'_> {
        self.descriptors[3].as_fd()
    }
}

pub(super) fn validate_stdio(descriptor: BorrowedFd<'_>, input: bool) -> io::Result<()> {
    let flags = linux_fd::status_flags(descriptor)?;
    let mode = flags & libc::O_ACCMODE;
    if !matches!(
        mode,
        libc::O_RDONLY | libc::O_WRONLY | libc::O_RDWR
    ) || flags & libc::O_PATH != 0
        || (input && mode == libc::O_WRONLY)
        || (!input && mode == libc::O_RDONLY)
    {
        return Err(invalid());
    }
    let metadata = linux_fd::metadata(descriptor)?;
    match metadata.mode() & libc::S_IFMT {
        libc::S_IFREG | libc::S_IFIFO | libc::S_IFSOCK => Ok(()),
        libc::S_IFCHR => {
            if libc::major(metadata.rdev()) == 1 && libc::minor(metadata.rdev()) == 3 {
                return Ok(());
            }
            linux_fd::terminal::TerminalAttributes::read(descriptor)
                .map(|_| ())
                .map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}

fn invalid() -> io::Error {
    io::Error::other("invalid command proxy request or descriptors")
}
fn check(cancel: &Cancellation) -> io::Result<()> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())
}

#[cfg(test)]
mod tests {
    use super::{
        AdmittedProxyRequest, MAX_REQUEST_BYTES, ProxyRequest, alias_from_wrapper, validate_stdio,
    };
    use crate::cancellation::Cancellation;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{OpenOptionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    fn request(arguments: Vec<OsString>, cwd: &Path) -> ProxyRequest {
        ProxyRequest::new("public-alias".into(), arguments, cwd.into()).unwrap()
    }

    fn descriptors(cwd: &Path) -> Vec<OwnedFd> {
        let cwd = File::open(cwd).unwrap();
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        [
            cwd.as_fd(),
            null.as_fd(),
            null.as_fd(),
            null.as_fd(),
        ]
        .into_iter()
        .map(|fd| fd.try_clone_to_owned().unwrap())
        .collect()
    }

    #[test]
    fn canonical_roundtrip_preserves_arbitrary_argument_bytes_without_interpretation() {
        let arguments = vec![
            OsString::from("literal; $(not-a-shell)"),
            OsString::from_vec(vec![255, 128, 42]),
            OsString::new(),
        ];
        let value = request(arguments.clone(), Path::new("nested/cwd"));
        let bytes = value.canonical_bytes().unwrap();
        let reopened = ProxyRequest::decode(&bytes).unwrap();
        assert_eq!(reopened.alias(), "public-alias");
        assert_eq!(reopened.arguments(), arguments);
        assert_eq!(reopened.cwd(), Path::new("nested/cwd"));
        assert!(!format!("{reopened:?}").contains("literal"));
        assert_eq!(bytes, reopened.canonical_bytes().unwrap());
    }

    #[test]
    fn request_limits_separate_count_single_argument_and_aggregate_bytes() {
        let cwd = PathBuf::from(".");
        assert!(
            ProxyRequest::new(
                "x".into(),
                vec![OsString::new(); 256],
                cwd.clone()
            )
            .is_ok()
        );
        assert!(
            ProxyRequest::new(
                "x".into(),
                vec![OsString::new(); 257],
                cwd.clone()
            )
            .is_err()
        );
        assert!(
            ProxyRequest::new(
                "x".into(),
                vec![OsString::from("x".repeat(4096))],
                cwd.clone()
            )
            .is_ok()
        );
        assert!(
            ProxyRequest::new(
                "x".into(),
                vec![OsString::from("x".repeat(4097))],
                cwd.clone()
            )
            .is_err()
        );
        let mut exact = vec![OsString::from_vec(vec![255; 4096]); 16];
        let value = ProxyRequest::new("x".into(), exact.clone(), cwd.clone()).unwrap();
        assert!(value.canonical_bytes().unwrap().len() <= MAX_REQUEST_BYTES);
        assert!(ProxyRequest::decode(&value.canonical_bytes().unwrap()).is_ok());
        exact.push("x".into());
        assert!(ProxyRequest::new("x".into(), exact, cwd.clone()).is_err());
        assert!(ProxyRequest::new("x".into(), vec![OsString::from_vec(vec![0])], cwd).is_err());
    }

    #[test]
    fn wrapper_and_cwd_paths_are_strict_and_do_not_normalize_escapes() {
        assert_eq!(
            alias_from_wrapper(OsStr::new("/syrox/commands/bin/tool-1.0")).unwrap(),
            "tool-1.0"
        );
        for path in [
            "tool",
            "/syrox/commands/bin/",
            "/syrox/commands/bin/../worker",
            "/syrox/commands/bin/x/y",
            "/syrox/commands/bin//x",
            "/syrox/commands/bin/.",
        ] {
            assert!(
                alias_from_wrapper(OsStr::new(path)).is_err(),
                "{path}"
            );
        }
        for cwd in [
            "", "/", "/tmp", "../x", "a/../b", "a/./b", "a//b", "a/",
        ] {
            assert!(
                ProxyRequest::new("x".into(), vec![], PathBuf::from(cwd)).is_err(),
                "{cwd}"
            );
        }
        assert!(
            ProxyRequest::new(
                "x".into(),
                vec![],
                PathBuf::from(vec!["x"; 32].join("/"))
            )
            .is_ok()
        );
        assert!(
            ProxyRequest::new(
                "x".into(),
                vec![],
                PathBuf::from(vec!["x"; 33].join("/"))
            )
            .is_err()
        );
    }

    #[test]
    fn wire_rejects_unknown_noncanonical_truncated_and_oversized_frames() {
        let bytes = request(vec![], Path::new("."))
            .canonical_bytes()
            .unwrap();
        for length in [0, 1, bytes.len() - 1, bytes.len() - 2] {
            assert!(ProxyRequest::decode(&bytes[..length]).is_err());
        }
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            ProxyRequest::decode(
                text.replace("\"version\":1", "\"version\":1,\"extra\":0")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            ProxyRequest::decode(
                text.replace("\"version\":1", "\"version\":2")
                    .as_bytes()
            )
            .is_err()
        );
        let mut extra = bytes;
        extra.push(b'\n');
        assert!(ProxyRequest::decode(&extra).is_err());
        assert!(ProxyRequest::decode(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
    }

    #[test]
    fn cwd_requires_exact_descendant_descriptor_and_refuses_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        let child = temp.path().join("child");
        fs::create_dir(&child).unwrap();
        let cancel = Cancellation::default();
        let admitted = AdmittedProxyRequest::validate(
            request(vec![], Path::new("child")),
            descriptors(&child),
            root.as_fd(),
            &cancel,
        )
        .unwrap();
        assert_eq!(admitted.request().cwd(), Path::new("child"));
        assert!(
            AdmittedProxyRequest::validate(
                request(vec![], Path::new("child")),
                descriptors(temp.path()),
                root.as_fd(),
                &cancel
            )
            .is_err()
        );
        symlink(&child, temp.path().join("alias")).unwrap();
        assert!(
            AdmittedProxyRequest::validate(
                request(vec![], Path::new("alias")),
                descriptors(&child),
                root.as_fd(),
                &cancel
            )
            .is_err()
        );
        assert!(
            AdmittedProxyRequest::validate(
                request(vec![], Path::new(".")),
                descriptors(temp.path()),
                root.as_fd(),
                &cancel
            )
            .is_ok()
        );
    }

    #[test]
    fn descriptor_count_directions_and_special_devices_are_admitted_explicitly() {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        let cancel = Cancellation::default();
        let mut extra = descriptors(temp.path());
        extra.push(root.as_fd().try_clone_to_owned().unwrap());
        assert!(
            AdmittedProxyRequest::validate(
                request(vec![], Path::new(".")),
                extra,
                root.as_fd(),
                &cancel
            )
            .is_err()
        );
        assert!(
            AdmittedProxyRequest::validate(
                request(vec![], Path::new(".")),
                vec![],
                root.as_fd(),
                &cancel
            )
            .is_err()
        );
        let read_only = File::open("/dev/null").unwrap();
        assert!(validate_stdio(read_only.as_fd(), true).is_ok());
        assert!(validate_stdio(read_only.as_fd(), false).is_err());
        let write_only = OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert!(validate_stdio(write_only.as_fd(), true).is_err());
        assert!(validate_stdio(write_only.as_fd(), false).is_ok());
        assert!(validate_stdio(root.as_fd(), true).is_err());
        let path_only = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open("/dev/null")
            .unwrap();
        assert!(validate_stdio(path_only.as_fd(), true).is_err());
        let zero = File::open("/dev/zero").unwrap();
        assert!(validate_stdio(zero.as_fd(), true).is_err());
        let (reader, writer) = std::io::pipe().unwrap();
        assert!(validate_stdio(reader.as_fd(), true).is_ok());
        assert!(validate_stdio(writer.as_fd(), false).is_ok());
        cancel.cancel();
        let error = AdmittedProxyRequest::validate(
            request(vec![], Path::new(".")),
            descriptors(temp.path()),
            root.as_fd(),
            &cancel,
        )
        .unwrap_err();
        assert!(crate::cancellation::is_cancellation_io(&error));
    }

    #[test]
    fn admitted_cwd_is_rechecked_instead_of_treating_old_observation_as_authority() {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        let child = temp.path().join("child");
        fs::create_dir(&child).unwrap();
        let cancel = Cancellation::default();
        let admitted = AdmittedProxyRequest::validate(
            request(vec![], Path::new("child")),
            descriptors(&child),
            root.as_fd(),
            &cancel,
        )
        .unwrap();
        admitted
            .revalidate(root.as_fd(), &cancel)
            .unwrap();
        fs::rename(&child, temp.path().join("previous")).unwrap();
        fs::create_dir(&child).unwrap();
        assert!(
            admitted
                .revalidate(root.as_fd(), &cancel)
                .is_err()
        );
        assert_ne!(
            crate::platform::linux::fd::metadata(admitted.cwd_descriptor())
                .unwrap()
                .identity(),
            crate::platform::linux::fd::metadata(File::open(&child).unwrap().as_fd())
                .unwrap()
                .identity()
        );
    }
}
