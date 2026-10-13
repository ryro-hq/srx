//! Diretório público dos aliases disponíveis na sessão Shell.
//!
//! O broker confere o contexto e o índice inteiro contra o consumer preparado
//! antes de executar um alias. Configuração, state, grants e descritores de secrets
//! ficam com a sessão. O diretório só descreve os comandos que podem ser pedidos.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::deployment::manifest::commands::PreparedCommandIndex;
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, OpenedPath};
use crate::{cancellation::Cancellation, store::ContentDigest};

pub(crate) const WRAPPER: &[u8] = b"#!/syrox/commands/worker __shell-command\n";
const MAX_WORKER_BYTES: usize = 128 * 1024 * 1024;

struct Entry {
    identity: FileIdentity,
    digest: ContentDigest,
    size: u64,
    mode: u32,
}

pub(crate) struct PreparedCommandDirectory {
    parent: OpenedPath,
    root: OpenedPath,
    bin: OpenedPath,
    parent_path: PathBuf,
    path: PathBuf,
    entries: BTreeMap<PathBuf, Entry>,
}

impl PreparedCommandDirectory {
    /// All validation of input bytes precedes filesystem creation. The private
    /// tree survives Drop or a partial publication; only explicit close removes
    /// exact owned entries, after the caller has established session settlement.
    pub(crate) fn prepare(
        index: &PreparedCommandIndex<'_>,
        parent: &Path,
        context: &crate::runtime::command_proxy::ProxyContext,
        worker: &[u8],
        worker_digest: ContentDigest,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        check(cancel)?;
        if context.index()? != index.digest() {
            return Err(invalid("command context index mismatch"));
        }
        if worker.len() > MAX_WORKER_BYTES || digest(worker, cancel)? != worker_digest {
            return Err(invalid("invalid command worker pin or size"));
        }
        crate::runtime::validate_static_worker_image(worker)
            .map_err(|_| invalid("command worker must be a static executable"))?;
        let context = context.canonical_bytes()?;
        check(cancel)?;
        let parent_path = parent.to_path_buf();
        if !parent_path.is_absolute() {
            return Err(invalid(
                "command directory parent must be absolute",
            ));
        }
        let parent = linux_fd::open_top_directory(parent).map_err(open_error)?;
        require_directory(&parent, 0o700)?;
        if linux_fd::directory_path(&parent)? != parent_path {
            return Err(invalid("command directory parent path changed"));
        }
        let temporary = tempfile::Builder::new()
            .prefix("commands-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(anchor(parent.fd()))?;
        let anchored_path = temporary.keep();
        let name = anchored_path
            .file_name()
            .expect("temporary directory name");
        let path = parent_path.join(name);
        let root =
            linux_fd::open_beneath(parent.fd(), Path::new(name), true).map_err(open_error)?;
        linux_fd::sync_directory(parent.fd())?;
        fs::create_dir(anchor(root.fd()).join("bin"))?;
        fs::set_permissions(
            anchor(root.fd()).join("bin"),
            fs::Permissions::from_mode(0o700),
        )?;
        let bin = linux_fd::open_beneath(root.fd(), Path::new("bin"), true).map_err(open_error)?;
        let mut prepared = Self {
            parent,
            root,
            bin,
            parent_path,
            path,
            entries: BTreeMap::new(),
        };
        prepared.write(Path::new("worker"), worker, 0o500, cancel)?;
        prepared.write(Path::new("context"), &context, 0o400, cancel)?;
        // Inert mountpoint: the validated socket replaces it only inside the
        // payload namespace, before sealing that namespace's command tree RO.
        prepared.write(Path::new("broker.sock"), b"", 0o400, cancel)?;
        for name in index.names() {
            prepared.write(
                &Path::new("bin").join(name),
                WRAPPER,
                0o500,
                cancel,
            )?;
        }
        for directory in [&prepared.bin, &prepared.root] {
            fs::set_permissions(
                anchor(directory.fd()),
                fs::Permissions::from_mode(0o500),
            )?;
            linux_fd::sync_directory(directory.fd())?;
        }
        linux_fd::sync_directory(prepared.parent.fd())?;
        prepared.revalidate(cancel)?;
        Ok(prepared)
    }

    pub(crate) fn directory(&self) -> BorrowedFd<'_> {
        self.root.fd()
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn write(
        &mut self,
        name: &Path,
        bytes: &[u8],
        mode: u32,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        check(cancel)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(anchor(self.root.fd()).join(name))?;
        for chunk in bytes.chunks(64 * 1024) {
            check(cancel)?;
            file.write_all(chunk)?;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        self.entries.insert(
            name.into(),
            Entry {
                identity: linux_fd::metadata(file.as_fd())?.identity(),
                digest: digest(bytes, cancel)?,
                size: bytes.len() as u64,
                mode,
            },
        );
        Ok(())
    }

    pub(crate) fn revalidate(&self, cancel: &Cancellation) -> io::Result<()> {
        check(cancel)?;
        let parent = linux_fd::open_top_directory(&self.parent_path).map_err(open_error)?;
        require_directory(&parent, 0o700)?;
        if parent.metadata().identity() != self.parent.metadata().identity()
            || linux_fd::directory_path(&self.root)? != self.path
        {
            return Err(invalid("command directory authority changed"));
        }
        let root = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        let bin = linux_fd::open_beneath_no_mounts(root.fd(), Path::new("bin"), true)
            .map_err(open_error)?;
        for (actual, expected) in [(&root, &self.root), (&bin, &self.bin)] {
            require_directory(actual, 0o500)?;
            if actual.metadata().identity() != expected.metadata().identity() {
                return Err(invalid("command directory identity changed"));
            }
        }
        exact_names(
            root.fd(),
            &[
                "bin",
                "broker.sock",
                "context",
                "worker",
            ],
        )?;
        let aliases = self
            .entries
            .keys()
            .filter_map(|name| name.strip_prefix("bin").ok())
            .map(|name| name.to_str().expect("validated alias"))
            .collect::<Vec<_>>();
        exact_names(bin.fd(), &aliases)?;
        for (name, expected) in &self.entries {
            check(cancel)?;
            verify_entry(root.fd(), name, expected, cancel)?;
        }
        let current_parent = linux_fd::open_top_directory(&self.parent_path).map_err(open_error)?;
        let current_root = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        require_directory(&current_parent, 0o700)?;
        require_directory(&current_root, 0o500)?;
        if current_parent.metadata().identity() != self.parent.metadata().identity()
            || current_root.metadata().identity() != self.root.metadata().identity()
            || linux_fd::directory_path(&self.root)? != self.path
        {
            return Err(invalid(
                "command authority changed during validation",
            ));
        }
        Ok(())
    }

    /// Requires the caller's positive settlement; never call merely on EOF.
    pub(crate) fn close(self, cancel: &Cancellation) -> io::Result<()> {
        self.revalidate(cancel)?;
        for directory in [&self.root, &self.bin] {
            fs::set_permissions(
                anchor(directory.fd()),
                fs::Permissions::from_mode(0o700),
            )?;
        }
        for (name, entry) in &self.entries {
            check(cancel)?;
            if let Ok(alias) = name.strip_prefix("bin") {
                linux_fd::unlink_opened(self.bin.fd(), alias, entry.identity)?;
            } else {
                linux_fd::unlink_opened(self.root.fd(), name, entry.identity)?;
            }
        }
        let bin = linux_fd::open_beneath_no_mounts(self.root.fd(), Path::new("bin"), true)
            .map_err(open_error)?;
        if bin.metadata().identity() != self.bin.metadata().identity() {
            return Err(invalid("command bin replaced during cleanup"));
        }
        fs::remove_dir(anchor(self.root.fd()).join("bin"))?;
        linux_fd::sync_directory(self.root.fd())?;
        let name = self.path.file_name().expect("owned name");
        let root = linux_fd::open_beneath_no_mounts(self.parent.fd(), Path::new(name), true)
            .map_err(open_error)?;
        if root.metadata().identity() != self.root.metadata().identity() {
            return Err(invalid("command root replaced during cleanup"));
        }
        fs::remove_dir(anchor(self.parent.fd()).join(name))?;
        linux_fd::sync_directory(self.parent.fd())
    }
}

fn verify_entry(
    root: BorrowedFd<'_>,
    name: &Path,
    expected: &Entry,
    cancel: &Cancellation,
) -> io::Result<()> {
    let opened = linux_fd::open_beneath_no_mounts(root, name, false).map_err(open_error)?;
    let before = opened.metadata();
    if !before.is_trusted_regular()
        || before.identity() != expected.identity
        || before.mode() & 0o7777 != expected.mode
        || before.size() != expected.size
    {
        return Err(invalid("command file metadata changed"));
    }
    let mut file = File::from(opened.fd().try_clone_to_owned()?);
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        check(cancel)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > expected.size {
            return Err(invalid("command file grew"));
        }
        hash.update(&buffer[..read]);
    }
    if total != expected.size
        || ContentDigest::from_sha256_hash(hash.finalize().into()) != expected.digest
        || linux_fd::metadata(opened.fd())? != before
    {
        return Err(invalid("command file bytes changed"));
    }
    let after = linux_fd::open_beneath_no_mounts(root, name, false).map_err(open_error)?;
    if after.metadata() != before {
        return Err(invalid("command file replaced"));
    }
    Ok(())
}

fn exact_names(directory: BorrowedFd<'_>, expected: &[&str]) -> io::Result<()> {
    let mut names = Vec::new();
    for entry in fs::read_dir(anchor(directory))? {
        if names.len() >= expected.len() {
            return Err(invalid("unexpected command directory entry"));
        }
        names.push(entry?.file_name());
    }
    names.sort();
    let mut expected = expected
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    expected.sort();
    if names != expected {
        return Err(invalid("command directory entries changed"));
    }
    Ok(())
}
fn require_directory(directory: &OpenedPath, mode: u32) -> io::Result<()> {
    if !directory.metadata().is_trusted_directory() || directory.metadata().mode() & 0o7777 != mode
    {
        return Err(invalid(
            "invalid command directory ownership or mode",
        ));
    }
    Ok(())
}
fn anchor(fd: BorrowedFd<'_>) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn open_error(_: linux_fd::OpenError) -> io::Error {
    invalid("cannot open command directory safely")
}
fn check(cancel: &Cancellation) -> io::Result<()> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())
}

fn digest(bytes: &[u8], cancel: &Cancellation) -> io::Result<ContentDigest> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(64 * 1024) {
        check(cancel)?;
        hash.update(chunk);
    }
    Ok(ContentDigest::from_sha256_hash(
        hash.finalize().into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{PreparedCommandDirectory, WRAPPER};
    use crate::deployment::manifest::commands::PreparedCommandIndex;
    use crate::{cancellation::Cancellation, store::ContentDigest};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const SOCKET: crate::platform::linux::fd::FileIdentity =
        crate::platform::linux::fd::FileIdentity {
            device: 1,
            inode: 2,
        };

    const SESSION: &str = "1234567890abcdef1234567890abcdef";

    fn context(index: &PreparedCommandIndex<'_>) -> crate::runtime::command_proxy::ProxyContext {
        crate::runtime::command_proxy::ProxyContext::new(
            &crate::execution::journal::SessionId::parse(SESSION).unwrap(),
            index.digest(),
            SOCKET,
            std::path::Path::new("/workspace/project"),
        )
        .unwrap()
    }

    fn private_parent() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn worker() -> Vec<u8> {
        // Structural ELF fixture only; no test executes this image.
        let mut bytes = crate::runtime::tests::elf(2, None, &[], None, None);
        bytes[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes
    }

    fn entries() -> BTreeMap<String, crate::deployment::manifest::ConsumerCommandKey> {
        BTreeMap::from([
            ("tool".into(), (None, "tool".into())),
            (
                "git".into(),
                (
                    Some("private-service".into()),
                    "configured".into(),
                ),
            ),
        ])
    }

    #[test]
    fn directory_contains_complete_public_wrappers_and_pinned_worker_only() {
        let temp = private_parent();
        let entries = entries();
        let index = PreparedCommandIndex::new(&entries).unwrap();
        let worker = worker();
        let cancel = Cancellation::default();
        let directory = PreparedCommandDirectory::prepare(
            &index,
            temp.path(),
            &context(&index),
            &worker,
            ContentDigest::sha256(&worker),
            &cancel,
        )
        .unwrap();
        let path = directory.path().to_path_buf();
        assert_eq!(fs::read(path.join("worker")).unwrap(), worker);
        let placeholder = fs::symlink_metadata(path.join("broker.sock")).unwrap();
        assert!(placeholder.is_file());
        assert_eq!(placeholder.len(), 0);
        assert_eq!(placeholder.permissions().mode() & 0o7777, 0o400);
        for alias in index.names() {
            assert_eq!(
                fs::read(path.join("bin").join(alias)).unwrap(),
                WRAPPER
            );
            assert_eq!(
                fs::metadata(path.join("bin").join(alias))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o500
            );
        }
        let context = fs::read_to_string(path.join("context")).unwrap();
        assert!(context.ends_with('\n'));
        assert!(!context.contains("private-service"));
        assert!(!context.contains("configured"));
        assert!(context.contains(&index.digest().to_string()));
        directory.revalidate(&cancel).unwrap();
        drop(directory);
        assert_eq!(
            fs::read(path.join("bin/git")).unwrap(),
            WRAPPER,
            "Drop conserves evidence"
        );
        // Fixture teardown, never a production settlement proof.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            path.join("bin"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn explicit_close_removes_only_its_owned_tree() {
        let temp = private_parent();
        fs::write(temp.path().join("unrelated"), b"keep").unwrap();
        let entries = entries();
        let index = PreparedCommandIndex::new(&entries).unwrap();
        let worker = worker();
        let cancel = Cancellation::default();
        let directory = PreparedCommandDirectory::prepare(
            &index,
            temp.path(),
            &context(&index),
            &worker,
            ContentDigest::sha256(&worker),
            &cancel,
        )
        .unwrap();
        let path = directory.path().to_path_buf();
        directory.close(&cancel).unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::read(temp.path().join("unrelated")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn invalid_worker_cancel_and_untrusted_parent_have_no_creation_effect() {
        let temp = private_parent();
        let entries = entries();
        let index = PreparedCommandIndex::new(&entries).unwrap();
        let worker = worker();
        let pin = ContentDigest::sha256(&worker);
        let cancel = Cancellation::default();
        assert!(
            PreparedCommandDirectory::prepare(
                &index,
                temp.path(),
                &context(&index),
                &worker,
                ContentDigest::sha256(b"other"),
                &cancel
            )
            .is_err()
        );
        assert!(
            PreparedCommandDirectory::prepare(
                &index,
                temp.path(),
                &context(&index),
                b"#!/bin/sh\n",
                ContentDigest::sha256(b"#!/bin/sh\n"),
                &cancel
            )
            .is_err()
        );
        cancel.cancel();
        assert!(
            PreparedCommandDirectory::prepare(
                &index,
                temp.path(),
                &context(&index),
                &worker,
                pin,
                &cancel
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        let cancel = Cancellation::default();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            PreparedCommandDirectory::prepare(
                &index,
                temp.path(),
                &context(&index),
                &worker,
                pin,
                &cancel
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let link = temp.path().join("link");
        symlink(temp.path(), &link).unwrap();
        assert!(
            PreparedCommandDirectory::prepare(
                &index,
                &link,
                &context(&index),
                &worker,
                pin,
                &cancel
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn replaced_wrapper_refuses_reuse_and_cleanup() {
        let temp = private_parent();
        let entries = entries();
        let index = PreparedCommandIndex::new(&entries).unwrap();
        let worker = worker();
        let cancel = Cancellation::default();
        let directory = PreparedCommandDirectory::prepare(
            &index,
            temp.path(),
            &context(&index),
            &worker,
            ContentDigest::sha256(&worker),
            &cancel,
        )
        .unwrap();
        let path = directory.path().to_path_buf();
        fs::set_permissions(
            path.join("bin"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::rename(
            path.join("bin/git"),
            temp.path().join("original-wrapper"),
        )
        .unwrap();
        fs::write(path.join("bin/git"), WRAPPER).unwrap();
        fs::set_permissions(
            path.join("bin/git"),
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        fs::set_permissions(
            path.join("bin"),
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        assert!(directory.revalidate(&cancel).is_err());
        assert!(directory.close(&cancel).is_err());
        assert!(path.join("worker").exists());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            path.join("bin"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn renamed_root_is_not_reauthorized_by_its_new_descriptor_path() {
        let temp = private_parent();
        let entries = entries();
        let index = PreparedCommandIndex::new(&entries).unwrap();
        let worker = worker();
        let cancel = Cancellation::default();
        let directory = PreparedCommandDirectory::prepare(
            &index,
            temp.path(),
            &context(&index),
            &worker,
            ContentDigest::sha256(&worker),
            &cancel,
        )
        .unwrap();
        let path = directory.path().to_path_buf();
        let moved = temp.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        assert!(directory.revalidate(&cancel).is_err());
        assert!(directory.close(&cancel).is_err());
        assert_eq!(fs::read(moved.join("worker")).unwrap(), worker);
        fs::set_permissions(&moved, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            moved.join("bin"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn unrelated_context_index_is_rejected_before_creating_directory() {
        let temp = private_parent();
        let entries = entries();
        let index = PreparedCommandIndex::new(&entries).unwrap();
        let other_entries = BTreeMap::from([("other".into(), (None, "other".into()))]);
        let other = PreparedCommandIndex::new(&other_entries).unwrap();
        let worker = worker();
        assert!(
            PreparedCommandDirectory::prepare(
                &index,
                temp.path(),
                &context(&other),
                &worker,
                ContentDigest::sha256(&worker),
                &Cancellation::default(),
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}
