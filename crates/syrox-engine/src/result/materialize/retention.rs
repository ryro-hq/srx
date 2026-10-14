use super::{IndexedArtifact, MaterializationError, MaterializedArtifact, check, invalid, problem};
use crate::{cancellation::Cancellation, store::ContentDigest, store::RootName};

/// Evidence used to authorize a retained output. Imported results never fabricate
/// build receipts or claim that their source and toolchain are present.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutputOrigin {
    Built {
        receipt: ContentDigest,
    },
    Imported {
        manifest: ContentDigest,
    },
}

/// Portable output identity, revalidated when `RetainedOutput::open` is called.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputIdentity {
    pub action: ContentDigest,
    pub origin: OutputOrigin,
    pub artifact: ContentDigest,
    pub output: String,
}

/// A durable root association suitable for a generation manifest. Built outputs
/// retain the receipt closure, including build inputs; imported outputs retain
/// the pinned consumption manifest and all its artifacts.
/// Dropping this record does not remove that root; retirement uses Store GC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedOutput {
    pub root: RootName,
    pub identity: OutputIdentity,
}

impl MaterializedArtifact {
    pub(crate) fn open_artifact(
        &self,
        cancellation: &Cancellation,
    ) -> Result<crate::store::VerifiedReader, MaterializationError> {
        check(cancellation)?;
        self.lease
            .open_verified_checked(
                self.artifact(),
                crate::result::artifact::MAX_OUTPUT_BYTES,
                || super::cancellation_io(cancellation),
            )
            .map_err(|error| super::cancellation_store_error(error, cancellation))?
            .ok_or(MaterializationError::MissingResult)
    }

    pub const fn identity(&self) -> &OutputIdentity {
        &self.identity
    }

    /// Publish an immutable consumer root while the live lease prevents GC.
    /// Cancellation covers verification before the durable publication. A published root
    /// survives this handle and must be recorded/retired by its generation owner.
    pub fn retain(
        &self,
        root: &RootName,
        cancellation: &Cancellation,
    ) -> Result<RetainedOutput, MaterializationError> {
        check(cancellation)?;
        self.lease
            .publish_root_checked(root, &self.references, || {
                if cancellation.is_cancelled() {
                    Err(crate::cancellation::cancellation_io())
                } else {
                    Ok(())
                }
            })
            .map_err(|error| match error {
                crate::store::StoreError::Io(ref source)
                    if crate::cancellation::is_cancellation_io(source) =>
                {
                    MaterializationError::Cancelled
                }
                other => MaterializationError::Store(other),
            })?;
        Ok(RetainedOutput {
            root: root.clone(),
            identity: self.identity.clone(),
        })
    }

    /// Read a bounded regular file (or contained alias) from the verified Artifact,
    /// independently of the physical view. Consumers can copy these bytes into a
    /// generation without embedding Store cache paths in their configuration.
    pub fn read_file(
        &self,
        path: &str,
        maximum_bytes: u64,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, MaterializationError> {
        check(cancellation)?;
        if !crate::result::artifact::relative_path(path)
            || maximum_bytes > crate::result::artifact::MAX_OUTPUT_BYTES
        {
            return Err(invalid("invalid output file path or byte limit"));
        }
        let input = self
            .lease
            .open_verified_checked(
                self.artifact(),
                crate::result::artifact::MAX_OUTPUT_BYTES,
                || super::cancellation_io(cancellation),
            )
            .map_err(|error| super::cancellation_store_error(error, cancellation))?
            .ok_or(MaterializationError::MissingResult)?;
        let mut indexed =
            IndexedArtifact::open_checked(input, "", cancellation).map_err(|error| {
                if cancellation.is_cancelled() {
                    MaterializationError::Cancelled
                } else {
                    problem(error)
                }
            })?;
        let (files, reader) = indexed.parts();
        let file = files
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| invalid("file is absent from the output"))?;
        if file.size > maximum_bytes {
            return Err(invalid("output file exceeds the byte limit"));
        }
        let length = usize::try_from(file.size).map_err(problem)?;
        IndexedArtifact::range_from(reader, &file, 0, length, cancellation).map_err(|error| {
            if cancellation.is_cancelled() {
                MaterializationError::Cancelled
            } else {
                error.into()
            }
        })
    }
}
