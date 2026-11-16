//! Inspect expanded sources under the action budget without helper effects.

use super::{BuildError, SystemBuildAction, SystemBuildInputs};
use crate::{
    acquire::archive::{self, ArchiveError, ArchiveFormat, ArchiveInventory, SystemArchiveLimits},
    build::BuildSourceFormat,
    cancellation::Cancellation,
};
use std::{fs::File, io::Seek as _};

impl SystemBuildAction {
    pub fn source_archive_limits(&self) -> Result<SystemArchiveLimits, BuildError> {
        let format = match self.program().source_format {
            BuildSourceFormat::Gzip => ArchiveFormat::GzipTar,
            BuildSourceFormat::Xz => ArchiveFormat::XzTar,
            BuildSourceFormat::Raw => return Err(BuildError::InvalidRequest),
        };
        SystemArchiveLimits::new(self.budget(), self.source_limit(), format).map_err(error)
    }
}
impl SystemBuildInputs {
    /// Hash/metadata validation brackets inspection of the held readonly source.
    /// This neither extracts files nor starts a worker or contacts the helper.
    pub fn inspect_source_archive(
        &self,
        cancellation: &Cancellation,
    ) -> Result<ArchiveInventory, BuildError> {
        cancellation.check()?;
        let limits = self.action.source_archive_limits()?;
        let mut source = File::from(self.source_descriptor(cancellation)?);
        source.rewind()?;
        let inventory =
            archive::inspect_system_archive(source, &limits, cancellation).map_err(error)?;
        self.revalidate(cancellation)?;
        Ok(inventory)
    }
}
fn error(value: ArchiveError) -> BuildError {
    match value {
        ArchiveError::Cancelled => BuildError::Cancelled,
        value => BuildError::Execution(format!("System source archive: {value}")),
    }
}
