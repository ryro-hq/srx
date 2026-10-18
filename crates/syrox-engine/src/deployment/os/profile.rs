//! Local profile configuration, separate from installation and activation journals.

use crate::platform::linux::fd::{self, OpenError, OpenedPath, PublishStatus};
use serde::{Deserialize, Serialize};
use std::io::{self, Read as _};
use std::path::{Component, Path, PathBuf};

const MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsProfile {
    pub version: u32,
    pub name: String,
    pub project: PathBuf,
    pub output: String,
    pub config: Option<PathBuf>,
    pub installation: PathBuf,
    pub installation_id: String,
    pub store: PathBuf,
    pub units: PathBuf,
    pub cwd: PathBuf,
    pub scope: ProfileScope,
    pub uid: u32,
    pub gid: u32,
    pub start_timeout_seconds: u64,
    pub stop_timeout_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileScope {
    User {
        bus_socket: PathBuf,
    },
    System,
}

impl OsProfile {
    pub fn validate(&self) -> io::Result<()> {
        validate_profile_name(&self.name)?;
        if self.version != 1
            || self.uid == 0
            || self.gid == 0
            || self.uid != fd::real_uid()
            || self.uid != fd::effective_uid()
            || self.gid != fd::real_gid()
            || self.gid != fd::effective_gid()
            || !(1..=300).contains(&self.start_timeout_seconds)
            || !(1..=60).contains(&self.stop_timeout_seconds)
            || self.installation_id.len() != 32
            || !self
                .installation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.installation_id.bytes().all(|b| b == b'0')
            || self.output.is_empty()
            || self.output.len() > 256
            || !self
                .output
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(invalid(
                "unsupported profile version, identity or execution policy",
            ));
        }
        for path in [
            &self.project,
            &self.installation,
            &self.store,
            &self.units,
            &self.cwd,
        ] {
            validate_profile_path(path)?;
        }
        if let Some(config) = &self.config {
            validate_profile_path(config)?;
        }
        if let ProfileScope::User {
            bus_socket,
        } = &self.scope
        {
            validate_profile_path(bus_socket)?;
        }
        let paths = [
            &self.installation,
            &self.store,
            &self.cwd,
            &self.units,
        ];
        for (index, left) in paths.iter().enumerate() {
            for right in &paths[index + 1..] {
                if left.starts_with(right) || right.starts_with(left) {
                    return Err(invalid(
                        "installation, Store, units and working directory must not overlap",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn manager_scope(&self) -> crate::systemd::SystemdScope {
        match &self.scope {
            ProfileScope::User {
                bus_socket,
            } => crate::systemd::SystemdScope::User {
                bus_socket: bus_socket.clone(),
            },
            ProfileScope::System => crate::systemd::SystemdScope::System,
        }
    }
}

pub fn validate_profile_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(invalid(
            "profile name must contain 1..64 lowercase letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

pub fn validate_profile_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|text| text.len() > 4096 || text.chars().any(char::is_control))
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "profile paths must be bounded absolute paths without traversal or controls",
        ));
    }
    Ok(())
}

/// Create missing private directories through pinned, symlink-free parent handles.
/// Existing directories must belong to the caller and exclude group/other writes.
pub fn ensure_profile_directory(path: &Path) -> io::Result<()> {
    validate_profile_path(path)?;
    let opened = directory(path)?;
    if !opened.metadata().is_trusted_directory() {
        return Err(invalid(
            "profile directory must be owned by the caller without group/other writes",
        ));
    }
    if fd::directory_path(&opened)? != path {
        return Err(invalid("profile directory was renamed"));
    }
    Ok(())
}

fn directory(path: &Path) -> io::Result<OpenedPath> {
    match fd::open_top_directory(path) {
        Ok(opened) => Ok(opened),
        Err(OpenError::Other(error)) if error.kind() == io::ErrorKind::NotFound => {
            let parent = directory(
                path.parent()
                    .ok_or_else(|| invalid("missing directory parent"))?,
            )?;
            let name = Path::new(
                path.file_name()
                    .ok_or_else(|| invalid("missing directory name"))?,
            );
            fd::ensure_directory_beneath(parent.fd(), name).map_err(|error| {
                io::Error::other(format!(
                    "cannot create profile directory: {error:?}"
                ))
            })
        }
        Err(error) => Err(open_error(error)),
    }
}

pub fn read_os_profile(path: &Path) -> io::Result<OsProfile> {
    validate_profile_path(path)?;
    let parent = private_profile_parent(path)?;
    let file = fd::open_beneath(
        parent.fd(),
        Path::new(
            path.file_name()
                .ok_or_else(|| invalid("profile has no filename"))?,
        ),
        false,
    )
    .map_err(open_error)?;
    if !file.metadata().is_trusted_regular()
        || file.metadata().mode() & 0o7777 != 0o600
        || file.metadata().size() > MAX_BYTES
    {
        return Err(invalid(
            "profile must be one owned mode-0600 regular file of at most 64 KiB",
        ));
    }
    let mut bytes = Vec::new();
    file.into_file()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("profile exceeds 64 KiB"));
    }
    let profile: OsProfile = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid profile JSON or unknown fields"))?;
    profile.validate()?;
    Ok(profile)
}

/// Atomically create a profile; an existing profile is never overwritten.
pub fn create_os_profile(path: &Path, profile: &OsProfile) -> io::Result<()> {
    profile.validate()?;
    validate_profile_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("profile has no parent"))?;
    ensure_profile_directory(parent)?;
    let directory = private_profile_parent(path)?;
    let mut bytes = serde_json::to_vec_pretty(profile).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("profile exceeds 64 KiB"));
    }
    let mut temporary =
        fd::create_atomic_beneath_with_prefix(directory.fd(), ".syrox-profile.tmp.")
            .map_err(|error| error.source)?;
    temporary.write_all(&bytes)?;
    match temporary
        .publish_noreplace(Path::new(
            path.file_name()
                .ok_or_else(|| invalid("profile has no filename"))?,
        ))
        .map_err(|error| error.source)?
    {
        PublishStatus::Published => Ok(()),
        PublishStatus::AlreadyExists => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "profile already exists; existing configuration preserved",
        )),
    }
}

fn private_profile_parent(path: &Path) -> io::Result<OpenedPath> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("profile has no parent"))?;
    let directory = fd::open_top_directory(parent).map_err(open_error)?;
    if !directory.metadata().is_trusted_directory() || directory.metadata().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "profile configuration directory must be owned mode-0700",
        ));
    }
    Ok(directory)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn open_error(error: OpenError) -> io::Error {
    match error {
        OpenError::Symlink => invalid("profile path traverses a symlink"),
        OpenError::Other(error) | OpenError::Unsupported(error) => error,
    }
}

/// Credentials used by the existing unprivileged Os execution contract.
pub fn profile_credentials() -> io::Result<(u32, u32)> {
    let (uid, gid) = (fd::real_uid(), fd::real_gid());
    if uid == 0 || gid == 0 || uid != fd::effective_uid() || gid != fd::effective_gid() {
        return Err(invalid(
            "profiles require matching non-root real/effective user and group",
        ));
    }
    Ok((uid, gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    fn fixture(root: &Path) -> OsProfile {
        let (uid, gid) = profile_credentials().unwrap();
        OsProfile {
            version: 1,
            name: "web".into(),
            project: root.join("project"),
            output: "os".into(),
            config: None,
            installation: root.join("installation"),
            installation_id: "1234567890abcdef1234567890abcdef".into(),
            store: root.join("store"),
            units: root.join("units"),
            cwd: root.join("work"),
            scope: ProfileScope::User {
                bus_socket: root.join("bus"),
            },
            uid,
            gid,
            start_timeout_seconds: 30,
            stop_timeout_seconds: 5,
        }
    }
    #[test]
    fn profile_publication_is_private_atomic_and_never_overwrites_existing_configuration() {
        if profile_credentials().is_err() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("configuration/os/web.json");
        let profile = fixture(root.path());
        create_os_profile(&path, &profile).unwrap();
        assert_eq!(
            std::fs::metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(read_os_profile(&path).unwrap(), profile);
        let original = std::fs::read(&path).unwrap();
        assert_eq!(
            create_os_profile(&path, &profile)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!profile.store.exists());
        assert!(!profile.installation.exists());
    }
    #[test]
    fn profile_rejects_symlinks_permissions_unknown_fields_and_identity_changes() {
        if profile_credentials().is_err() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = root.path().join("web.json");
        let profile = fixture(root.path());
        create_os_profile(&path, &profile).unwrap();
        let alias = root.path().join("alias.json");
        symlink(&path, &alias).unwrap();
        assert!(read_os_profile(&alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_os_profile(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut json = serde_json::to_value(&profile).unwrap();
        json["surprise"] = true.into();
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(read_os_profile(&path).is_err());
        let mut bad = profile.clone();
        bad.uid += 1;
        assert!(bad.validate().is_err());
        bad = profile.clone();
        bad.store = bad.installation.join("store");
        assert!(bad.validate().is_err());
        for collision in [
            &profile.installation,
            &profile.store,
            &profile.cwd,
        ] {
            bad = profile.clone();
            bad.units = collision.join("units");
            assert!(bad.validate().is_err());
        }
        let linked = root.path().join("linked");
        symlink(root.path(), &linked).unwrap();
        assert!(create_os_profile(&linked.join("elsewhere.json"), &profile).is_err());
        assert!(!root.path().join("elsewhere.json").exists());
    }

    #[test]
    fn units_may_be_publicly_readable_but_profile_configuration_must_be_private() {
        if profile_credentials().is_err() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let profile = fixture(root.path());
        std::fs::create_dir(&profile.units).unwrap();
        std::fs::set_permissions(
            &profile.units,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        ensure_profile_directory(&profile.units).unwrap();
        let path = root.path().join("profiles/web.json");
        create_os_profile(&path, &profile).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(
            read_os_profile(&path)
                .unwrap_err()
                .to_string()
                .contains("0700")
        );
        assert!(
            create_os_profile(&path.with_file_name("other.json"), &profile)
                .unwrap_err()
                .to_string()
                .contains("0700")
        );
        assert!(!path.with_file_name("other.json").exists());
    }

    #[test]
    fn concurrent_initializers_publish_exactly_one_complete_profile() {
        if profile_credentials().is_err() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("profiles/web.json");
        let mut other = fixture(root.path());
        other.output = "other".into();
        let profiles = [fixture(root.path()), other];
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let path = &path;
            let barrier = &barrier;
            let handles = profiles
                .iter()
                .map(|profile| {
                    scope.spawn(move || {
                        barrier.wait();
                        create_os_profile(path, profile)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results
                .iter()
                .filter(|result| result.is_ok())
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .find_map(|result| result.as_ref().err())
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            read_os_profile(&path).unwrap(),
            profiles[results.iter().position(Result::is_ok).unwrap()]
        );
    }
}
