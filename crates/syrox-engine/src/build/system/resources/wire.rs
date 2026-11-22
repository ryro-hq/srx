use super::{BuildError, ContentDigest, SystemBuildAction};
use crate::result::artifact::ArtifactLimits;
use serde::{Deserialize, Serialize};
use syrox_encoding::formats;

const HEADER: &[u8] = formats::SYSTEM_INPUT_RESOURCES_LINE.as_bytes();
pub(super) const MAX_BYTES: usize = 32 * 1024;
pub(super) const MINIMUM_RESERVE: u32 = 32;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub version: u32,
    pub action: String,
    pub reserved: u32,
    pub slots: u32,
    pub inputs: Vec<Input>,
    pub retention: String,
    pub retention_device: u64,
    pub retention_inode: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub storage: String,
    pub artifact_slots: u32,
    pub maximum_bytes: u64,
    pub maximum_files: u64,
}

impl Input {
    pub fn limits(&self) -> Result<ArtifactLimits, BuildError> {
        if self.artifact_slots == 0 || self.maximum_bytes == 0 || self.maximum_files == 0 {
            return Err(BuildError::InvalidRequest);
        }
        match self.storage.as_str() {
            "blob"
                if self.artifact_slots == 1
                    && self.maximum_bytes == ArtifactLimits::PACKAGE.bytes
                    && self.maximum_files == ArtifactLimits::PACKAGE.files as u64 => {}
            "chunked"
                if self.artifact_slots
                    <= u32::try_from(crate::store::chunked::MAX_CHUNKS)
                        .expect("bounded format")
                        + 1
                    && self.maximum_bytes <= crate::store::chunked::MAX_ARTIFACT_BYTES
                    && self.maximum_files <= 1_000_000 => {}
            _ => return Err(BuildError::InvalidRequest),
        }
        Ok(ArtifactLimits {
            bytes: self.maximum_bytes,
            expanded_bytes: self.maximum_bytes,
            files: usize::try_from(self.maximum_files).map_err(|_| BuildError::InvalidRequest)?,
        })
    }
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>, BuildError> {
        let mut bytes = HEADER.to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| BuildError::InvalidRequest)?);
        if bytes.len() > MAX_BYTES {
            return Err(BuildError::InvalidRequest);
        }
        Ok(bytes)
    }

    pub fn parse(
        bytes: &[u8],
        expected: ContentDigest,
        action: &SystemBuildAction,
        reserved: u32,
    ) -> Result<Self, BuildError> {
        if bytes.len() > MAX_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(BuildError::InputChanged);
        }
        let value: Self = serde_json::from_slice(
            bytes
                .strip_prefix(HEADER)
                .ok_or(BuildError::InvalidRequest)?,
        )
        .map_err(|_| BuildError::InvalidRequest)?;
        let count = value
            .inputs
            .iter()
            .try_fold(1_u32, |sum, input| {
                input.limits()?;
                sum.checked_add(1)
                    .and_then(|sum| sum.checked_add(input.artifact_slots))
                    .ok_or(BuildError::InvalidRequest)
            })?;
        let _: ContentDigest = value
            .retention
            .parse()
            .map_err(|_| BuildError::InvalidRequest)?;
        if value.version != 1
            || value.action != action.digest().to_string()
            || value.reserved != reserved
            || value.inputs.len() != action.selected_inputs().len()
            || value.slots != count
            || value.encode()? != bytes
        {
            return Err(BuildError::InputChanged);
        }
        check_slots(count, reserved, action)?;
        Ok(value)
    }
}

pub(super) fn check_slots(
    slots: u32,
    reserved: u32,
    action: &SystemBuildAction,
) -> Result<(), BuildError> {
    if reserved < MINIMUM_RESERVE
        || slots == 0
        || slots
            .checked_add(reserved)
            .is_none_or(|total| total > action.budget().request().descriptors)
    {
        return Err(BuildError::UnsupportedInputs);
    }
    Ok(())
}
