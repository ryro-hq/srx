use super::{OpenedPath, open_beneath, open_top_directory};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Directory(OpenedPath);

pub(crate) fn invalid() -> io::Error {
    io::Error::other("unsafe or conflicting private-tree entry")
}
fn mapped(error: super::OpenError) -> io::Error {
    match error {
        super::OpenError::Other(error) | super::OpenError::Unsupported(error) => error,
        super::OpenError::Symlink => invalid(),
    }
}
fn valid_name(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || name.len() > 255
    {
        return Err(invalid());
    }
    Ok(())
}
impl Directory {
    pub(crate) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.fd()
    }
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        open_top_directory(path).map(Self).map_err(mapped)
    }
    pub(crate) fn from_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<Self> {
        open_beneath(fd, Path::new("."), true)
            .map(Self)
            .map_err(mapped)
    }
    pub(crate) fn parent(path: &Path) -> io::Result<(Self, OsString)> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(invalid());
        }
        let name = path.file_name().ok_or_else(invalid)?.to_owned();
        valid_name(&name)?;
        Ok((
            Self::open(path.parent().ok_or_else(invalid)?)?,
            name,
        ))
    }
    pub(crate) fn path(&self, name: &OsStr) -> io::Result<PathBuf> {
        valid_name(name)?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.0.fd().as_raw_fd()
        ))
        .join(name))
    }
    pub(crate) fn metadata(&self, name: &OsStr) -> io::Result<Option<Metadata>> {
        match fs::symlink_metadata(self.path(name)?) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn child(&self, name: &OsStr) -> io::Result<Self> {
        valid_name(name)?;
        open_beneath(self.0.fd(), Path::new(name), true)
            .map(Self)
            .map_err(mapped)
    }
    pub(crate) fn ensure_child(&self, name: &OsStr) -> io::Result<Self> {
        match self.child(name) {
            Ok(directory) => Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (directory, created) =
                    super::ensure_directory_beneath_with_status(self.0.fd(), Path::new(name))
                        .map_err(|_| invalid())?;
                if created {
                    fs::set_permissions(
                        format!("/proc/self/fd/{}", directory.fd().as_raw_fd()),
                        fs::Permissions::from_mode(0o755),
                    )?;
                }
                Ok(Self(directory))
            }
            Err(error) => Err(error),
        }
    }
    pub(crate) fn ensure_relative(&self, path: &Path) -> io::Result<Self> {
        let mut current = Self::from_fd(self.0.fd())?;
        for part in path.components() {
            let Component::Normal(name) = part else {
                return Err(invalid());
            };
            current = current.ensure_child(name)?;
        }
        Ok(current)
    }
    pub(crate) fn ensure(path: &Path) -> io::Result<Self> {
        let relative = path.strip_prefix("/").map_err(|_| invalid())?;
        Self::open(Path::new("/"))?.ensure_relative(relative)
    }
    pub(crate) fn entries(&self, limit: usize) -> io::Result<Vec<OsString>> {
        let mut count = 0;
        super::read_directory(&self.0, |name| {
            valid_name(name)?;
            count += 1;
            if count > limit {
                return Err(invalid());
            }
            Ok(())
        })
        .map_err(|error| match error {
            super::ReadDirectoryError::Io(error) | super::ReadDirectoryError::Admission(error) => {
                error
            }
        })
    }
    pub(crate) fn read_file(&self, name: &OsStr) -> io::Result<File> {
        valid_name(name)?;
        let opened = open_beneath(self.0.fd(), Path::new(name), false).map_err(mapped)?;
        if opened.metadata().file_type() != super::FileType::Regular {
            return Err(invalid());
        }
        Ok(opened.into_file())
    }
    pub(crate) fn set_mode(&self, mode: u32) -> io::Result<()> {
        if mode & !0o777 != 0 {
            return Err(invalid());
        }
        fs::set_permissions(
            format!("/proc/self/fd/{}", self.0.fd().as_raw_fd()),
            fs::Permissions::from_mode(mode),
        )
    }
    pub(crate) fn read_link(&self, name: &OsStr) -> io::Result<PathBuf> {
        let target = fs::read_link(self.path(name)?)?;
        if target.as_os_str().len() > 4096 {
            return Err(invalid());
        }
        Ok(target)
    }
    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        fs::remove_file(self.path(name)?)
    }
    pub(crate) fn remove_directory(&self, name: &OsStr) -> io::Result<()> {
        fs::remove_dir(self.path(name)?)
    }
    pub(crate) fn rename(
        &self,
        name: &OsStr,
        destination: &Self,
        target: &OsStr,
    ) -> io::Result<()> {
        fs::rename(self.path(name)?, destination.path(target)?)
    }

    pub(crate) fn write_file(
        &self,
        name: &OsStr,
        source: &mut dyn Read,
        maximum: u64,
        mode: u32,
        replace: bool,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<u64> {
        self.write_file_inner(
            name,
            source,
            maximum,
            (mode, replace, None),
            check,
        )
    }

    /// Source archives use a fixed modification time so extraction order cannot
    /// make generated release files appear older than their prerequisites.
    pub(crate) fn write_source_file(
        &self,
        name: &OsStr,
        source: &mut dyn Read,
        maximum: u64,
        mode: u32,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<u64> {
        self.write_file_inner(
            name,
            source,
            maximum,
            (mode, false, Some(std::time::UNIX_EPOCH)),
            check,
        )
    }

    fn write_file_inner(
        &self,
        name: &OsStr,
        source: &mut dyn Read,
        maximum: u64,
        (mode, replace, modified): (u32, bool, Option<std::time::SystemTime>),
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<u64> {
        if mode & !0o777 != 0 {
            return Err(invalid());
        }
        self.validate_destination(name, replace)?;
        let temporary = super::operation_name()?;
        let (opened, created) = super::initialize_regular(self.0.fd(), Path::new(&temporary))?;
        if !created {
            return Err(invalid());
        }
        let mut file = opened.into_file();
        let result = (|| {
            let count = copy_checked(source, &mut file, maximum, check)?;
            if count != maximum {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            if let Some(modified) = modified {
                file.set_times(fs::FileTimes::new().set_modified(modified))?;
            }
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            check()?;
            self.validate_destination(name, replace)?;
            if replace {
                self.rename(OsStr::new(&temporary), self, name)?;
            } else {
                fs::hard_link(
                    self.path(OsStr::new(&temporary))?,
                    self.path(name)?,
                )?;
                self.remove_file(OsStr::new(&temporary))?;
            }
            Ok(count)
        })();
        if result.is_err() {
            let _ = self.remove_file(OsStr::new(&temporary));
        }
        result
    }
    pub(crate) fn write_link(&self, name: &OsStr, target: &Path, replace: bool) -> io::Result<()> {
        if target.as_os_str().len() > 4096 {
            return Err(invalid());
        }
        self.validate_destination(name, replace)?;
        if !replace {
            return std::os::unix::fs::symlink(target, self.path(name)?);
        }
        let temporary = super::operation_name()?;
        std::os::unix::fs::symlink(target, self.path(OsStr::new(&temporary))?)?;
        let result = self.rename(OsStr::new(&temporary), self, name);
        if result.is_err() {
            let _ = self.remove_file(OsStr::new(&temporary));
        }
        result
    }
    fn validate_destination(&self, name: &OsStr, replace: bool) -> io::Result<()> {
        if let Some(metadata) = self.metadata(name)?
            && (!replace || !metadata.is_file())
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) fn copy_checked(
    source: &mut dyn Read,
    destination: &mut dyn Write,
    maximum: u64,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<u64> {
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        check()?;
        let amount = source.read(&mut buffer)?;
        if amount == 0 {
            return Ok(bytes);
        }
        bytes = bytes
            .checked_add(amount as u64)
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(invalid)?;
        check()?;
        destination.write_all(&buffer[..amount])?;
    }
}
