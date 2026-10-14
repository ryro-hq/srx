//! Resolving a GitHub input and verifying the received snapshot.
//!
//! Resolving a revision over the network belongs to an explicit lock update.
//! Afterward, the project uses the commit and bytes pinned in the lock.

use std::path::PathBuf;

use crate::{acquire::https::HttpsTransportPolicy, cancellation::Cancellation};

#[cfg(target_os = "linux")]
mod snapshot;
#[cfg(target_os = "linux")]
pub(crate) use snapshot::{GithubSession, InputMode, Snapshot};
#[cfg(all(test, target_os = "linux"))]
mod tests;

/// Operational options, supplied by the caller rather than project source text.
#[derive(Clone, Debug, Default)]
pub struct GithubConfiguration {
    /// Defaults to `<top-level project>/.syrox/github`, shared by its entire graph.
    pub cache: Option<PathBuf>,
    pub transport: HttpsTransportPolicy,
    pub cancellation: Cancellation,
}

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("invalid GitHub locator; expected github:owner/repository[/ref]")]
    InvalidLocator,
    #[error("GitHub input `{0}` is not pinned in Syrox.lock; run srx project lock")]
    Unpinned(String),
    #[error("GitHub snapshot {0} is absent; run srx project lock --fetch")]
    MissingSnapshot(String),
    #[error("GitHub returned an invalid commit identity")]
    InvalidCommit,
    #[error("GitHub snapshot differs from its locked content identity")]
    ContentMismatch,
    #[error("GitHub snapshot contains an unsafe or unsupported archive entry")]
    InvalidArchive,
    #[error("GitHub project inputs exceed the cumulative snapshot budget")]
    Limit,
    #[error("GitHub project acquisition was cancelled")]
    Cancelled,
    #[error("GitHub project snapshot session has already failed")]
    FailedSession,
    #[error(
        "a GitHub project cannot resolve path:../ outside its repository; declare a github: input"
    )]
    ExternalPath,
    #[error(transparent)]
    Https(#[from] crate::acquire::https::HttpsError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Archive(#[from] crate::acquire::archive::ArchiveError),
    #[error("GitHub snapshot I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GithubLocator {
    pub(crate) owner: String,
    pub(crate) repository: String,
    pub(crate) reference: String,
    pub(crate) origin: String,
}

impl GithubLocator {
    // Git ref names are case-sensitive, including the reserved `.lock` suffix.
    #[allow(clippy::case_sensitive_file_extension_comparisons)] // Repository archive suffixes are protocol literals and case-sensitive by contract.
    pub(crate) fn parse(value: &str) -> Result<Self, GithubError> {
        let tail = value
            .strip_prefix("github:")
            .ok_or(GithubError::InvalidLocator)?;
        let mut parts = tail.splitn(3, '/');
        let owner = parts.next().unwrap_or_default();
        let repository = parts.next().unwrap_or_default();
        let reference = parts.next().unwrap_or("HEAD");
        let component = |text: &str, maximum: usize| {
            !text.is_empty()
                && text.len() <= maximum
                && !matches!(text, "." | "..")
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        };
        if !component(owner, 39)
            || !component(repository, 100)
            || reference.len() > 255
            || !reference
                .split('/')
                .all(|part| component(part, 255))
            || reference.contains("..")
            || reference.ends_with(".lock")
        {
            return Err(GithubError::InvalidLocator);
        }
        Ok(Self {
            owner: owner.into(),
            repository: repository.into(),
            reference: reference.into(),
            origin: value.into(),
        })
    }

    #[cfg(target_os = "linux")]
    fn commit_url(&self) -> String {
        // A ref is one API path component even when its Git spelling contains '/'.
        format!(
            "https://api.github.com/repos/{}/{}/commits/{}",
            self.owner,
            self.repository,
            self.reference.replace('/', "%2F")
        )
    }

    #[cfg(target_os = "linux")]
    fn archive_url(&self, pin: &GithubPin) -> String {
        format!(
            "https://codeload.github.com/{}/{}/tar.gz/{}",
            self.owner, self.repository, pin.commit
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GithubPin {
    pub(crate) commit: String,
    pub(crate) archive: [u8; 32],
}

impl GithubPin {
    pub(crate) fn new(commit: &str, archive: [u8; 32]) -> Result<Self, GithubError> {
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(GithubError::InvalidCommit);
        }
        Ok(Self {
            commit: commit.into(),
            archive,
        })
    }
}
