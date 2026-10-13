//! Instala a release formada por `srx` e seu worker.
//!
//! A cópia e a troca da seleção usam chamadas de filesystem. A instalação
//! funciona com PATH vazio e conserva as duas imagens na mesma release.

use std::ffi::CString;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest as _, Sha256};

const WORKER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/syrox-worker.bin"));
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    /// Directory containing releases/, current and bin/srx.
    #[arg(long)]
    prefix: PathBuf,
}

pub(crate) fn run(args: &Arguments) -> ExitCode {
    match (|| {
        if WORKER.is_empty() {
            return Err("this srx has no embedded worker; build the worker first and rebuild srx with SYROX_EMBED_WORKER".to_owned());
        }
        let source = std::env::current_exe().map_err(|error| error.to_string())?;
        let size = fs::metadata(&source)
            .map_err(|error| error.to_string())?
            .len();
        if size > MAX_EXECUTABLE_BYTES || WORKER.len() as u64 > MAX_EXECUTABLE_BYTES {
            return Err("release executable exceeds 128 MiB".into());
        }
        let mut srx = Vec::new();
        File::open(source)
            .map_err(|error| error.to_string())?
            .take(MAX_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut srx)
            .map_err(|error| error.to_string())?;
        if !crate::elf_release::static_x86_64(&srx) || !crate::elf_release::static_x86_64(WORKER) {
            return Err("install-self requires static Linux x86_64 executables".into());
        }
        let prefix = std::path::absolute(&args.prefix).map_err(|error| error.to_string())?;
        let release = install(&prefix, &srx, WORKER).map_err(|error| error.to_string())?;
        println!("installed {}", release.display());
        println!("command {}", prefix.join("bin/srx").display());
        Ok(())
    })() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in hash {
        write!(text, "{byte:02x}").expect("writing into String is infallible");
    }
    text
}

fn release_manifest(srx: &[u8], worker: &[u8]) -> (String, String) {
    let manifest = format!(
        "syrox-release-v1\nsrx {} {}\nworker {} {}\n",
        digest(srx),
        srx.len(),
        digest(worker),
        worker.len()
    );
    let id = digest(manifest.as_bytes());
    (id, manifest)
}

fn directory(path: &Path) -> std::io::Result<()> {
    if let Err(error) = fs::create_dir(path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(error);
    }
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(std::io::Error::other(format!(
            "not a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn write_file(path: &Path, bytes: &[u8], executable: bool) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    if executable {
        file.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    file.sync_all()
}

fn verify_file(path: &Path, expected: &[u8]) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() != expected.len() as u64 {
        return Err(std::io::Error::other(
            "installed release file has changed",
        ));
    }
    let file = File::open(path)?;
    let mut actual = Vec::with_capacity(expected.len());
    file.take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut actual)?;
    if actual != expected {
        return Err(std::io::Error::other(
            "installed release file has changed",
        ));
    }
    Ok(())
}

fn verify_release(path: &Path, srx: &[u8], worker: &[u8], manifest: &str) -> std::io::Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(std::io::Error::other(
            "release directory was replaced",
        ));
    }
    verify_file(&path.join("srx"), srx)?;
    verify_file(&path.join("syrox-worker"), worker)?;
    verify_file(&path.join("manifest"), manifest.as_bytes())
}

fn temporary_name() -> std::io::Result<String> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(format!(
        ".syrox-{}-{}",
        std::process::id(),
        digest(&random)
    ))
}

fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    let from = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("NUL in release path"))?;
    let to = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("NUL in release path"))?;
    // SAFETY: both NUL-terminated paths are live for the syscall; the kernel
    // atomically rejects an existing destination instead of replacing a release.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn install(prefix: &Path, srx: &[u8], worker: &[u8]) -> std::io::Result<PathBuf> {
    if srx.is_empty()
        || worker.is_empty()
        || srx.len() as u64 > MAX_EXECUTABLE_BYTES
        || worker.len() as u64 > MAX_EXECUTABLE_BYTES
    {
        return Err(std::io::Error::other(
            "incomplete or oversized release",
        ));
    }
    // The caller may create its chosen prefix. Every managed component below
    // it must be a real directory rather than a symlink.
    if !prefix.exists() {
        fs::create_dir_all(prefix)?;
    }
    directory(prefix)?;
    let releases = prefix.join("releases");
    let bin = prefix.join("bin");
    directory(&releases)?;
    directory(&bin)?;
    let (id, manifest) = release_manifest(srx, worker);
    let release = releases.join(&id);
    if release.exists() {
        verify_release(&release, srx, worker, &manifest)?;
    } else {
        let staging = releases.join(temporary_name()?);
        fs::create_dir(&staging)?;
        let published = (|| {
            write_file(&staging.join("srx"), srx, true)?;
            write_file(&staging.join("syrox-worker"), worker, true)?;
            write_file(
                &staging.join("manifest"),
                manifest.as_bytes(),
                false,
            )?;
            sync_directory(&staging)?;
            match rename_noreplace(&staging, &release) {
                Ok(()) => sync_directory(&releases),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    verify_release(&release, srx, worker, &manifest)
                }
                Err(error) => Err(error),
            }
        })();
        if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        published?;
    }
    verify_release(&release, srx, worker, &manifest)?;
    let command = bin.join("srx");
    let command_present = fs::symlink_metadata(&command).is_ok();
    if command_present && fs::read_link(&command)? != Path::new("../current/srx") {
        return Err(std::io::Error::other(
            "bin/srx already selects another command",
        ));
    }
    let current = prefix.join("current");
    if let Ok(metadata) = fs::symlink_metadata(&current)
        && !metadata.file_type().is_symlink()
    {
        return Err(std::io::Error::other(
            "current release selector is not a symlink",
        ));
    }
    let selection = prefix.join(temporary_name()?);
    symlink(Path::new("releases").join(&id), &selection)?;
    if let Err(error) = fs::rename(&selection, &current) {
        let _ = fs::remove_file(&selection);
        return Err(error);
    }
    sync_directory(prefix)?;
    if !command_present {
        symlink("../current/srx", &command)?;
        sync_directory(&bin)?;
    }
    Ok(release)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_install_is_idempotent_and_refuses_a_modified_release() {
        let prefix = tempfile::tempdir().unwrap();
        let release = install(
            prefix.path(),
            b"static srx fixture",
            b"worker fixture",
        )
        .unwrap();
        assert_eq!(
            fs::read_link(prefix.path().join("current")).unwrap(),
            Path::new("releases").join(release.file_name().unwrap())
        );
        assert_eq!(
            fs::read(prefix.path().join("bin/srx")).unwrap(),
            b"static srx fixture"
        );
        assert_eq!(
            install(
                prefix.path(),
                b"static srx fixture",
                b"worker fixture"
            )
            .unwrap(),
            release
        );
        let next = install(prefix.path(), b"next static srx", b"next worker").unwrap();
        assert_ne!(release, next);
        assert_eq!(
            fs::read(release.join("syrox-worker")).unwrap(),
            b"worker fixture"
        );
        assert_eq!(
            fs::read(prefix.path().join("bin/srx")).unwrap(),
            b"next static srx"
        );
        fs::write(next.join("syrox-worker"), b"modified").unwrap();
        assert!(install(prefix.path(), b"next static srx", b"next worker").is_err());
        assert_eq!(
            fs::read_link(prefix.path().join("current")).unwrap(),
            Path::new("releases").join(next.file_name().unwrap())
        );
    }
}
