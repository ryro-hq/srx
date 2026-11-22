use super::{
    BuildBudget, BuildError, BuilderLimits, Cancellation, ContentDigest, File, SystemBuildAction,
    WorkspaceObservation,
};
use serde::{Deserialize, Serialize};
use std::io::Read as _;
use syrox_encoding::formats;

const HEADER: &[u8] = formats::SYSTEM_BUILD_PAYLOAD_LINE.as_bytes();
const MAX_RECORD: u64 = 8192;

/// Carries the coordinator's already selected policy and helper observation.
/// Its own bytes/digest alone never establish coordinator or helper authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    action: String,
    maximum: BuildBudget,
    request: BuildBudget,
    observation: WorkspaceObservation,
}
impl Record {
    pub(super) fn new(
        inputs: &super::super::SystemBuildInputs,
        observation: WorkspaceObservation,
    ) -> Self {
        Self {
            action: inputs.action.digest().to_string(),
            maximum: *inputs.configuration.limits().maximum(),
            request: *inputs.action.budget().request(),
            observation,
        }
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, BuildError> {
        let mut bytes = HEADER.to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| BuildError::InvalidRequest)?);
        if bytes.len() as u64 > MAX_RECORD {
            return Err(BuildError::InvalidRequest);
        }
        Ok(bytes)
    }
    fn parse(
        bytes: &[u8],
        expected: ContentDigest,
        action: ContentDigest,
    ) -> Result<Self, BuildError> {
        if bytes.len() as u64 > MAX_RECORD || ContentDigest::sha256(bytes) != expected {
            return Err(BuildError::InputChanged);
        }
        let record: Self = serde_json::from_slice(
            bytes
                .strip_prefix(HEADER)
                .ok_or(BuildError::InvalidRequest)?,
        )
        .map_err(|_| BuildError::InvalidRequest)?;
        if record.encode()? != bytes || record.action != action.to_string() {
            return Err(BuildError::InputChanged);
        }
        Ok(record)
    }
}

/// Internal exec entry after trusted namespace/resource preparation. Neither
/// argv nor the record is an independent execution authorization.
///
/// # Safety
/// Dedicated single-threaded payload process only; exit after return/error.
/// Caller guarantees authenticated namespace/resource/manager admission, as for
/// `run_system_build_worker`. Policy installation closes all descriptors >=3.
#[allow(unsafe_code)]
pub unsafe fn run_payload(
    args: &[std::ffi::OsString],
    cancellation: &Cancellation,
) -> Result<(), BuildError> {
    if args.len() != 2 {
        return Err(BuildError::InvalidRequest);
    }
    let pin = |value: &std::ffi::OsString| -> Result<ContentDigest, BuildError> {
        value
            .to_str()
            .ok_or(BuildError::InvalidRequest)?
            .parse()
            .map_err(|_| BuildError::InvalidRequest)
    };
    let action_pin = pin(&args[0])?;
    let record_pin = pin(&args[1])?;
    let mut bytes = Vec::new();
    File::open("/build-system-policy")?
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)?;
    let record = Record::parse(&bytes, record_pin, action_pin)?;
    let budget = BuilderLimits::new(record.maximum)?.admit(record.request)?;
    bytes.clear();
    File::open("/build-action")?
        .take((2 * crate::build::MAX_BUILD_PROGRAM_BYTES + 64 * 1024 + 1) as u64)
        .read_to_end(&mut bytes)?;
    let action = SystemBuildAction::parse(&bytes, &budget)?;
    if action.digest() != action_pin {
        return Err(BuildError::InputChanged);
    }
    crate::execution::native::build_policy::validate_system_record()?;
    // SAFETY: caller guarantees the dedicated payload and admission contract.
    unsafe { crate::worker::run_system_build_worker(&action, &record.observation, cancellation) }
}

#[cfg(test)]
pub(in crate::build::system) fn test_record(
    inputs: &super::super::SystemBuildInputs,
) -> Result<(), BuildError> {
    // Bad role observations are pure parser fixtures, never passed to a mount.
    let observation: WorkspaceObservation = serde_json::from_value(serde_json::json!({
        "layout_sha256": vec![0; 32],
        "scratch": {"device": 1, "inode": 2, "filesystem_bytes": 1, "inodes": 1},
        "output": {"device": 2, "inode": 2, "filesystem_bytes": 1, "inodes": 1}
    }))
    .map_err(|_| BuildError::InvalidRequest)?;
    let record = Record::new(inputs, observation);
    let bytes = record.encode()?;
    let pin = ContentDigest::sha256(&bytes);
    let parsed = Record::parse(&bytes, pin, inputs.action.digest())?;
    assert_eq!(parsed.request, *inputs.action.budget().request());
    assert!(
        Record::parse(
            &bytes,
            ContentDigest::sha256(b"wrong"),
            inputs.action.digest()
        )
        .is_err()
    );
    assert!(
        Record::parse(
            &bytes,
            pin,
            ContentDigest::sha256(b"other-action")
        )
        .is_err()
    );
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert!(
        Record::parse(
            &padded,
            ContentDigest::sha256(&padded),
            inputs.action.digest()
        )
        .is_err()
    );
    let admitted = BuilderLimits::new(parsed.maximum)?.admit(parsed.request)?;
    assert_eq!(
        SystemBuildAction::parse(&inputs.action.encode(), &admitted)?,
        inputs.action
    );
    Ok(())
}
