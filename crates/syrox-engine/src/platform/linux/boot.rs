use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::io::{self, Read as _};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BootError {
    #[error("boot identity unavailable: {0}")]
    Invalid(&'static str),
    #[error("boot identity observation cancelled")]
    Cancelled,
    #[error("boot identity observation deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] io::Error),
}
type Result<T> = std::result::Result<T, BootError>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct BootId(String);
impl BootId {
    pub(crate) fn parse(text: &str) -> Result<Self> {
        if text.len() != 36
            || text.bytes().enumerate().any(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte != b'-'
                } else {
                    !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)
                }
            })
            || text
                .bytes()
                .filter(|byte| *byte != b'-')
                .all(|byte| byte == b'0')
        {
            return Err(BootError::Invalid("invalid boot identifier"));
        }
        Ok(Self(text.into()))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn current(cancellation: &Cancellation, deadline: Instant) -> Result<Self> {
        check(cancellation, deadline)?;
        let file =
            linux_fd::open_top(Path::new("/proc/sys/kernel/random/boot_id")).map_err(open_error)?;
        let bytes = read_boot_file(file)?;
        check(cancellation, deadline)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| BootError::Invalid("non-UTF8 boot identifier"))?;
        Self::parse(text.strip_suffix('\n').unwrap_or(text))
    }
}

impl<'de> serde::Deserialize<'de> for BootId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<()> {
    if cancellation.is_cancelled() {
        return Err(BootError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(BootError::Deadline);
    }
    Ok(())
}
fn read_boot_file(file: linux_fd::OpenedPath) -> Result<Vec<u8>> {
    if linux_fd::filesystem_type(file.fd())? != 0x9fa0 {
        return Err(BootError::Invalid(
            "boot property is not on procfs",
        ));
    }
    if file.metadata().file_type() != linux_fd::FileType::Regular {
        return Err(BootError::Invalid(
            "boot property is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.into_file()
        .take(65)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 {
        return Err(BootError::Invalid("boot property exceeds bound"));
    }
    Ok(bytes)
}
fn open_error(error: linux_fd::OpenError) -> BootError {
    match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => error.into(),
        linux_fd::OpenError::Symlink => BootError::Invalid("boot property traverses a symlink"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }
    #[test]
    fn boot_identifiers_are_canonical_nonzero_and_read_from_procfs() {
        let valid = "01234567-89ab-cdef-0123-456789abcdef";
        assert_eq!(BootId::parse(valid).unwrap().as_str(), valid);
        for text in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "01234567-89AB-cdef-0123-456789abcdef",
            "0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcdeg",
        ] {
            assert!(BootId::parse(text).is_err());
        }
        let current = BootId::current(&Cancellation::default(), deadline()).unwrap();
        assert_eq!(BootId::parse(current.as_str()).unwrap(), current);
    }

    #[test]
    fn cancellation_and_deadline_precede_boot_filesystem_access() {
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            BootId::current(&cancel, deadline()),
            Err(BootError::Cancelled)
        ));
        assert!(matches!(
            BootId::current(&Cancellation::default(), Instant::now()),
            Err(BootError::Deadline)
        ));
    }

    #[test]
    fn ordinary_file_and_invalid_serialized_identity_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("boot-id");
        std::fs::write(&path, b"01234567-89ab-cdef-0123-456789abcdef\n").unwrap();
        assert!(read_boot_file(linux_fd::open_top(&path).unwrap()).is_err());
        assert!(
            serde_json::from_str::<BootId>("\"00000000-0000-0000-0000-000000000000\"").is_err()
        );
        let boot = BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(
            serde_json::from_slice::<BootId>(&serde_json::to_vec(&boot).unwrap()).unwrap(),
            boot
        );
    }
}
