use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Instant;

use sha2::{Digest as _, Sha256};

use crate::execution::transport::Peer;
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, OpenedPath, PidfdNamespace};
use crate::{cancellation::Cancellation, store::ContentDigest};

const MAX_IMAGE_BYTES: usize = 128 * 1024 * 1024;
const MAX_PROC_BYTES: usize = 64 * 1024;

struct OwnedNamespace {
    init: OwnedFd,
    namespace: OwnedFd,
    identity: FileIdentity,
}

pub(crate) struct OwnedProxyNamespaces(Vec<OwnedNamespace>);
impl OwnedProxyNamespaces {
    /// Closed admission has no eligible namespaces; it grants no peer authority.
    pub(crate) fn closed_admission() -> Self {
        Self(Vec::new())
    }

    /// Only the monitor supplies already-owned root/sibling init pidfds here.
    /// Never call this with descriptors supplied by a wrapper. This constructor
    /// pins kernel identities; it does not establish ownership of an init.
    pub(crate) fn from_owned_inits(
        inits: &[BorrowedFd<'_>],
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        check(cancel, deadline)?;
        if inits.is_empty() || inits.len() > super::MAX_INVOCATIONS + 1 {
            return Err(invalid());
        }
        let mut entries: Vec<OwnedNamespace> = Vec::new();
        for init in inits {
            check(cancel, deadline)?;
            linux_fd::require_unique_pidfd(*init)?;
            if linux_fd::pidfd_exited(*init)? {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            let namespace = linux_fd::pidfd_namespace(*init, PidfdNamespace::Pid)?;
            let identity = linux_fd::metadata(namespace.as_fd())?.identity();
            if entries
                .iter()
                .any(|entry| entry.identity == identity)
            {
                return Err(invalid());
            }
            entries.push(OwnedNamespace {
                init: init.try_clone_to_owned()?,
                namespace,
                identity,
            });
        }
        Ok(Self(entries))
    }

    fn admits(
        &self,
        identity: FileIdentity,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        check(cancel, deadline)?;
        let entry = self
            .0
            .iter()
            .find(|entry| entry.identity == identity)
            .ok_or_else(invalid)?;
        alive(entry.init.as_fd())?;
        let current = linux_fd::pidfd_namespace(entry.init.as_fd(), PidfdNamespace::Pid)?;
        if linux_fd::metadata(current.as_fd())?.identity() != entry.identity
            || linux_fd::metadata(entry.namespace.as_fd())?.identity() != entry.identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) struct ProxyPeer {
    peer: Peer,
    pidfd: OwnedFd,
    proc: OpenedPath,
    process: OpenedPath,
    namespace: OwnedFd,
    namespace_identity: FileIdentity,
    start: u64,
    image: File,
    image_identity: FileIdentity,
    worker: ContentDigest,
}

impl ProxyPeer {
    pub(crate) fn authenticate(
        peer: Peer,
        worker: ContentDigest,
        allowed: &OwnedProxyNamespaces,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        check(cancel, deadline)?;
        if peer.pid == 0 || allowed.0.is_empty() {
            return Err(invalid());
        }
        let proc = linux_fd::open_top_directory(Path::new("/proc")).map_err(|_| invalid())?;
        if linux_fd::proc_self_pid(proc.fd())? != std::process::id() {
            return Err(invalid());
        }
        let pidfd = linux_fd::pidfd_open(peer.pid)?;
        linux_fd::require_unique_pidfd(pidfd.as_fd())?;
        alive(pidfd.as_fd())?;
        let process = linux_fd::open_beneath(proc.fd(), Path::new(&peer.pid.to_string()), true)
            .map_err(|_| invalid())?;
        let start = observe_process(&process, peer, cancel, deadline)?;
        let namespace = linux_fd::pidfd_namespace(pidfd.as_fd(), PidfdNamespace::Pid)?;
        let namespace_identity = linux_fd::metadata(namespace.as_fd())?.identity();
        allowed.admits(namespace_identity, cancel, deadline)?;
        let image = linux_fd::open_proc_executable(process.fd())?;
        let image_identity = linux_fd::metadata(image.as_fd())?.identity();
        let observed = Self {
            peer,
            pidfd,
            proc,
            process,
            namespace,
            namespace_identity,
            start,
            image,
            image_identity,
            worker,
        };
        observed.revalidate(allowed, cancel, deadline)?;
        Ok(observed)
    }

    /// Full current observation, required again before the execution gate. This
    /// does not authorize the alias or replace per-message SCM credentials.
    pub(crate) fn revalidate(
        &self,
        allowed: &OwnedProxyNamespaces,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        check(cancel, deadline)?;
        alive(self.pidfd.as_fd())?;
        if linux_fd::proc_self_pid(self.proc.fd())? != std::process::id() {
            return Err(invalid());
        }
        let current = linux_fd::open_beneath(
            self.proc.fd(),
            Path::new(&self.peer.pid.to_string()),
            true,
        )
        .map_err(|_| invalid())?;
        if current.metadata().identity() != self.process.metadata().identity()
            || observe_process(&self.process, self.peer, cancel, deadline)? != self.start
        {
            return Err(invalid());
        }
        self.namespace_matches(allowed, cancel, deadline)?;
        let image = linux_fd::open_proc_executable(self.process.fd())?;
        if linux_fd::metadata(image.as_fd())?.identity() != self.image_identity
            || linux_fd::metadata(self.image.as_fd())?.identity() != self.image_identity
        {
            return Err(invalid());
        }
        verify_image(image, self.worker, cancel, deadline)?;
        let after = linux_fd::open_proc_executable(self.process.fd())?;
        if linux_fd::metadata(after.as_fd())?.identity() != self.image_identity
            || observe_process(&self.process, self.peer, cancel, deadline)? != self.start
        {
            return Err(invalid());
        }
        self.namespace_matches(allowed, cancel, deadline)?;
        check(cancel, deadline)?;
        alive(self.pidfd.as_fd())
    }

    fn namespace_matches(
        &self,
        allowed: &OwnedProxyNamespaces,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        let current = linux_fd::pidfd_namespace(self.pidfd.as_fd(), PidfdNamespace::Pid)?;
        if linux_fd::metadata(current.as_fd())?.identity() != self.namespace_identity
            || linux_fd::metadata(self.namespace.as_fd())?.identity() != self.namespace_identity
        {
            return Err(invalid());
        }
        allowed.admits(self.namespace_identity, cancel, deadline)
    }

    pub(crate) const fn peer(&self) -> Peer {
        self.peer
    }
    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

fn observe_process(
    process: &OpenedPath,
    peer: Peer,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<u64> {
    let status = read_proc(process, "status", cancel, deadline)?;
    verify_status(&status, peer)?;
    start_time(
        &read_proc(process, "stat", cancel, deadline)?,
        peer.pid,
    )
}

fn read_proc(
    process: &OpenedPath,
    name: &str,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<String> {
    check(cancel, deadline)?;
    let opened =
        linux_fd::open_beneath(process.fd(), Path::new(name), false).map_err(|_| invalid())?;
    if linux_fd::filesystem_type(opened.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    let mut text = String::new();
    opened
        .into_file()
        .take(MAX_PROC_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    check(cancel, deadline)?;
    if text.len() > MAX_PROC_BYTES {
        return Err(invalid());
    }
    Ok(text)
}

fn verify_status(text: &str, peer: Peer) -> io::Result<()> {
    for (key, expected, count) in [
        ("Pid:", peer.pid, 1),
        ("Tgid:", peer.pid, 1),
        ("Uid:", peer.uid, 4),
        ("Gid:", peer.gid, 4),
    ] {
        let mut lines = text
            .lines()
            .filter_map(|line| line.strip_prefix(key));
        let line = lines.next().ok_or_else(invalid)?;
        if lines.next().is_some() {
            return Err(invalid());
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.len() != count
            || words
                .iter()
                .any(|word| *word != expected.to_string())
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn start_time(text: &str, pid: u32) -> io::Result<u64> {
    let prefix = format!("{pid} (");
    let body = text.strip_prefix(&prefix).ok_or_else(invalid)?;
    // comm may itself contain spaces and ')' bytes. Only the last ') ' precedes
    // the numeric stat fields; starttime is field22 (index19 after comm).
    let (_, fields) = body.rsplit_once(") ").ok_or_else(invalid)?;
    let value = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(invalid)?;
    let start: u64 = value.parse().map_err(|_| invalid())?;
    if start == 0 || start.to_string() != value {
        return Err(invalid());
    }
    Ok(start)
}

fn verify_image(
    mut image: File,
    worker: ContentDigest,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    let before = linux_fd::metadata(image.as_fd())?;
    if before.file_type() != linux_fd::FileType::Regular || before.size() > MAX_IMAGE_BYTES as u64 {
        return Err(invalid());
    }
    let mut hash = Sha256::new();
    let mut total = 0_usize;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        check(cancel, deadline)?;
        let count = image.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count;
        if total > MAX_IMAGE_BYTES {
            return Err(invalid());
        }
        hash.update(&buffer[..count]);
    }
    if total as u64 != before.size()
        || linux_fd::metadata(image.as_fd())? != before
        || ContentDigest::from_sha256_hash(hash.finalize().into()) != worker
    {
        return Err(invalid());
    }
    check(cancel, deadline)
}

fn alive(pidfd: BorrowedFd<'_>) -> io::Result<()> {
    if linux_fd::pidfd_exited(pidfd)? {
        return Err(invalid());
    }
    Ok(())
}
fn invalid() -> io::Error {
    io::Error::other("command wrapper identity refused")
}
fn check(cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "command peer observation timed out",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::{
        MAX_IMAGE_BYTES, OwnedProxyNamespaces, ProxyPeer, start_time, verify_image, verify_status,
    };
    use crate::execution::transport::Peer;
    use crate::{cancellation::Cancellation, store::ContentDigest};
    use std::fs::{self, File};
    use std::os::fd::AsFd as _;
    use std::time::{Duration, Instant};

    fn peer() -> Peer {
        Peer {
            pid: 123,
            uid: 1000,
            gid: 1001,
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn status() -> String {
        "Name:\twrapper\nPid:\t123\nTgid:\t123\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n".into()
    }

    #[test]
    fn process_credentials_require_exact_real_effective_saved_and_filesystem_ids() {
        verify_status(&status(), peer()).unwrap();
        for bad in [
            status().replace("Pid:\t123", "Pid:\t124"),
            status().replace("Tgid:\t123", "Tgid:\t124"),
            status().replace("1000\t1000\t1000\t1000", "1000\t0\t1000\t1000"),
            status().replace("1001\t1001\t1001\t1001", "1001\t1001\t1001\t0"),
            status().replace("Uid:\t", "Uid:\t1000\t"),
            format!("{}Uid:\t1000\t1000\t1000\t1000\n", status()),
            status().replace("Pid:\t123", "Pid:\t0123"),
        ] {
            assert!(verify_status(&bad, peer()).is_err());
        }
    }

    #[test]
    fn stat_starttime_does_not_confuse_parentheses_spaces_or_other_pid() {
        let fields = format!("S {} 12345 0 0\n", vec!["0"; 18].join(" "));
        let text = format!("123 (name with ) tricky ) chars) {fields}");
        assert_eq!(start_time(&text, 123).unwrap(), 12345);
        assert!(start_time(&text, 124).is_err());
        assert!(start_time("123 (short) S 0 0", 123).is_err());
        assert!(start_time(&text.replace("12345", "012345"), 123).is_err());
        assert!(start_time(&text.replace("12345", "0"), 123).is_err());
    }

    #[test]
    fn empty_foreign_authority_and_over_capacity_inputs_are_refused_without_kernel_claim() {
        let cancel = Cancellation::default();
        assert!(OwnedProxyNamespaces::from_owned_inits(&[], &cancel, deadline()).is_err());
        let file = File::open("/dev/null").unwrap();
        let too_many = vec![file.as_fd(); super::super::MAX_INVOCATIONS + 2];
        assert!(OwnedProxyNamespaces::from_owned_inits(&too_many, &cancel, deadline()).is_err());
        // Empty set is deliberately not an authorization constructor or test proof.
        let empty = OwnedProxyNamespaces(Vec::new());
        assert!(
            ProxyPeer::authenticate(
                peer(),
                ContentDigest::sha256(b"worker"),
                &empty,
                &cancel,
                deadline()
            )
            .is_err()
        );
    }

    #[test]
    fn cancellation_and_deadline_precede_proc_pidfd_and_namespace_inspection() {
        let cancel = Cancellation::default();
        cancel.cancel();
        let empty = OwnedProxyNamespaces(Vec::new());
        let error = ProxyPeer::authenticate(
            peer(),
            ContentDigest::sha256(b"worker"),
            &empty,
            &cancel,
            deadline(),
        )
        .err()
        .unwrap();
        assert!(crate::cancellation::is_cancellation_io(&error));
        let error =
            OwnedProxyNamespaces::from_owned_inits(&[], &Cancellation::default(), Instant::now())
                .err()
                .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn image_hash_is_bounded_and_does_not_accept_another_worker_pin() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("image");
        fs::write(&path, b"image identity fixture, never executed").unwrap();
        let bytes = fs::read(&path).unwrap();
        let cancel = Cancellation::default();
        verify_image(
            File::open(&path).unwrap(),
            ContentDigest::sha256(&bytes),
            &cancel,
            deadline(),
        )
        .unwrap();
        assert!(
            verify_image(
                File::open(&path).unwrap(),
                ContentDigest::sha256(b"different"),
                &cancel,
                deadline()
            )
            .is_err()
        );
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES as u64 + 1)
            .unwrap();
        assert!(
            verify_image(
                File::open(&path).unwrap(),
                ContentDigest::sha256(&bytes),
                &cancel,
                deadline()
            )
            .is_err()
        );
    }
}
