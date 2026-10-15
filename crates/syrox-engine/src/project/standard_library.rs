use super::lock;
use syrox_lang::{
    MAX_SOURCE_BYTES, MAX_SOURCES,
    source::{Source, SourceError},
};
use thiserror::Error;

impl AuthenticatedStandardLibrary {
    /// The checked-in standard library embedded in the executable, with each
    /// source authenticated and inventoried separately in the project Lock.
    pub fn bundled() -> Self {
        let sources = [
            (
                "std/main.srx",
                include_str!("../../../../std/main.srx"),
            ),
            (
                "std/option.srx",
                include_str!("../../../../std/option.srx"),
            ),
            (
                "std/result.srx",
                include_str!("../../../../std/result.srx"),
            ),
            (
                "std/recipe.srx",
                include_str!("../../../../std/recipe.srx"),
            ),
            (
                "std/package_traits.srx",
                include_str!("../../../../std/package_traits.srx"),
            ),
            (
                "std/collections/list.srx",
                include_str!("../../../../std/collections/list.srx"),
            ),
            (
                "std/collections/map.srx",
                include_str!("../../../../std/collections/map.srx"),
            ),
            (
                "std/package.srx",
                include_str!("../../../../std/package.srx"),
            ),
            (
                "std/build.srx",
                include_str!("../../../../std/build.srx"),
            ),
            (
                "std/deployment.srx",
                include_str!("../../../../std/deployment.srx"),
            ),
        ]
        .into_iter()
        .map(|(name, text)| {
            AuthenticatedStandardSource::from_authenticated(name, text)
                .expect("checked-in standard-library source is valid")
        })
        .collect();
        Self::from_authenticated(sources).expect("checked-in standard-library metadata is valid")
    }
}

/// Source text authenticated and pinned as standard-library content by the caller.
///
/// Constructing this value is an assertion at the engine trust boundary. The CLI does not
/// construct these values from project text or filesystem names.
#[derive(Clone, Debug)]
pub struct AuthenticatedStandardSource {
    source: Source,
}

impl AuthenticatedStandardSource {
    pub fn from_authenticated(
        name: impl Into<std::sync::Arc<str>>,
        text: impl Into<std::sync::Arc<str>>,
    ) -> Result<Self, SourceError> {
        Ok(Self {
            source: Source::new(name, text)?,
        })
    }

    pub fn name(&self) -> &str {
        self.source.name()
    }

    pub fn text(&self) -> &str {
        self.source.text()
    }
}

/// A caller-authenticated, canonically ordered standard-library snapshot.
#[derive(Clone, Debug)]
pub struct AuthenticatedStandardLibrary {
    sources: Vec<AuthenticatedStandardSource>,
    digest: [u8; 32],
}

impl AuthenticatedStandardLibrary {
    /// Asserts that `sources` were authenticated by the caller.
    pub fn from_authenticated(
        mut sources: Vec<AuthenticatedStandardSource>,
    ) -> Result<Self, StandardLibraryError> {
        if sources.is_empty() || sources.len() > MAX_SOURCES - 1 {
            return Err(StandardLibraryError::InvalidSourceCount);
        }
        sources.sort_by(|left, right| left.name().cmp(right.name()));
        if sources.iter().any(|source| {
            source.name().len() > MAX_SOURCE_BYTES
                || !lock::is_canonical_logical_path(source.name().as_bytes())
        }) {
            return Err(StandardLibraryError::InvalidSourceName);
        }
        if sources
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(StandardLibraryError::DuplicateSource);
        }
        let digest = lock::standard_library_digest(&sources);
        Ok(Self {
            sources,
            digest,
        })
    }

    pub fn sources(&self) -> impl ExactSizeIterator<Item = &AuthenticatedStandardSource> {
        self.sources.iter()
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StandardLibraryError {
    #[error("standard library must contain between 1 and {} sources", MAX_SOURCES - 1)]
    InvalidSourceCount,
    #[error("standard-library source names must be unique")]
    DuplicateSource,
    #[error("standard-library source names must be nonempty and bounded")]
    InvalidSourceName,
}
