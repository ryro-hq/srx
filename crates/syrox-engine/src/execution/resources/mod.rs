//! Resource descriptions with descriptor slots.
//!
//! Slots describe each resource's role, rather than the sender's FD numbers.
//! Receiving a description is only a handoff. The launcher still checks the
//! session, attempt, command, owner and manager invocation before admitting
//! execution.

use crate::execution::configuration::WorkerRequest;
use crate::{runtime::RuntimeError, store::ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use thiserror::Error;

mod transfer;
pub(crate) use transfer::{ResourceReceiver, receive_resources, send_resources};
#[cfg(test)]
mod tests;

pub(crate) const MAX_SERVICE_FDS: usize = 126;
pub(crate) const MAX_SERVICE_ARGUMENTS: usize = 256;
pub(crate) const MAX_SERVICE_ARGUMENT_BYTES: usize = 4096;
pub(crate) const MAX_SPEC_BYTES: usize = 8 * 1024 * 1024;
const HEADER: &[u8] = b"syrox-service-body-v1\n";

#[derive(Debug, Error)]
pub(crate) enum ServiceSpecError {
    #[error("invalid service specification: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}
type Result<T> = std::result::Result<T, ServiceSpecError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceMountKind {
    Output,
    Configuration,
    Secret,
    Working,
    State,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceMount {
    pub kind: ServiceMountKind,
    pub slot: u16,
    pub target: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceSpec {
    pub mounts: Vec<ServiceMount>,
    pub masked_store: Option<String>,
    pub cwd: String,
    pub locale: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub program: String,
    pub arguments: Vec<String>,
}
impl ServiceSpec {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = BoundedBytes(HEADER.to_vec());
        serde_json::to_writer(&mut writer, self)?;
        Ok(writer.0)
    }
    pub(crate) fn digest(&self) -> Result<ContentDigest> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }
    pub(crate) fn decode(bytes: &[u8], expected_pin: ContentDigest) -> Result<Self> {
        require(
            bytes.len() <= MAX_SPEC_BYTES,
            "service body exceeds byte bound",
        )?;
        require(
            ContentDigest::sha256(bytes) == expected_pin,
            "service body pin mismatch",
        )?;
        let body = bytes
            .strip_prefix(HEADER)
            .ok_or(ServiceSpecError::Invalid(
                "unsupported service body version",
            ))?;
        structural_budget(body)?;
        let spec: Self = serde_json::from_slice(body)?;
        require(
            spec.canonical_bytes()? == bytes,
            "noncanonical service body",
        )?;
        Ok(spec)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            !self.mounts.is_empty() && self.mounts.len() <= MAX_SERVICE_FDS,
            "invalid service descriptor count",
        )?;
        let mut targets = BTreeSet::new();
        for (index, mount) in self.mounts.iter().enumerate() {
            require(
                usize::from(mount.slot) == index,
                "service descriptor slots must be dense and ordered",
            )?;
            require(
                path_text(&mount.target) && targets.insert(&mount.target),
                "invalid or duplicate mount target",
            )?;
        }
        require(
            self.mounts
                .iter()
                .any(|mount| mount.kind == ServiceMountKind::Output),
            "service requires an output mount",
        )?;
        require(
            path_text(&self.cwd)
                && path_text(&self.program)
                && self.locale.as_deref().is_none_or(path_text)
                && self.masked_store.as_deref().is_none_or(path_text),
            "invalid service path encoding or bound",
        )?;
        require(
            valid_managed_working_directory(Path::new(&self.cwd)),
            "working directory overlaps a managed runtime filesystem",
        )?;
        require(
            self.arguments.len() <= MAX_SERVICE_ARGUMENTS
                && self.arguments.iter().all(|argument| {
                    argument.len() <= MAX_SERVICE_ARGUMENT_BYTES && !argument.contains('\0')
                }),
            "invalid service argument count or bytes",
        )?;
        let limits = crate::execution::configuration::MAX_RUNTIME_ENVIRONMENT_ENTRIES;
        require(
            self.environment.len() <= limits,
            "service environment count exceeded",
        )?;
        let mut environment_bytes = 0usize;
        for (name, value) in &self.environment {
            require(
                crate::execution::configuration::valid_runtime_environment_name(name)
                    && value.len()
                        <= crate::execution::configuration::MAX_RUNTIME_ENVIRONMENT_VALUE
                    && !value.contains('\0'),
                "invalid service environment",
            )?;
            environment_bytes += name.len() + value.len() + 2;
            require(
                environment_bytes <= crate::execution::configuration::MAX_RUNTIME_ENVIRONMENT_BYTES,
                "service environment total exceeded",
            )?;
        }
        // Pure parse reuses runtime's exact mount/namespace, environment, cwd,
        // program and locale contracts. Synthetic FD numbers are local stand-ins
        // only; they never enter canonical bytes or access descriptors.
        WorkerRequest::parse(&self.runtime_arguments(|slot| i32::from(slot) + 3))?;
        Ok(())
    }
    pub(crate) fn worker_request(&self, descriptors: &[OwnedFd]) -> Result<WorkerRequest> {
        self.validate()?;
        self.validate_descriptors(
            &descriptors
                .iter()
                .map(std::os::fd::AsFd::as_fd)
                .collect::<Vec<_>>(),
        )?;
        Ok(WorkerRequest::parse(&self.runtime_arguments(
            |slot| descriptors[usize::from(slot)].as_raw_fd(),
        ))?)
    }
    fn runtime_arguments(&self, descriptor: impl Fn(u16) -> i32) -> Vec<OsString> {
        let mut arguments = Vec::new();
        for mount in &self.mounts {
            arguments.push(
                match mount.kind {
                    ServiceMountKind::Output => "--ro",
                    ServiceMountKind::Configuration => "--config-ro",
                    ServiceMountKind::Secret => "--secret-ro",
                    ServiceMountKind::Working => "--rw",
                    ServiceMountKind::State => "--state-rw",
                }
                .into(),
            );
            arguments.push(format!("/proc/self/fd/{}", descriptor(mount.slot)).into());
            arguments.push((&mount.target).into());
        }
        if let Some(mask) = &self.masked_store {
            arguments.extend([OsString::from("--mask"), mask.into()]);
        }
        arguments.extend([
            OsString::from("--cwd"),
            (&self.cwd).into(),
        ]);
        if let Some(locale) = &self.locale {
            arguments.extend([
                OsString::from("--locale"),
                locale.into(),
            ]);
        }
        for (name, value) in &self.environment {
            arguments.extend([
                OsString::from("--env"),
                format!("{name}={value}").into(),
            ]);
        }
        arguments.extend([
            OsString::from("--"),
            (&self.program).into(),
        ]);
        arguments.extend(self.arguments.iter().map(OsString::from));
        arguments
    }
    fn validate_descriptors(&self, descriptors: &[BorrowedFd<'_>]) -> Result<()> {
        require(
            descriptors.len() == self.mounts.len(),
            "service descriptor count mismatch",
        )?;
        let mut identities = BTreeSet::new();
        for (mount, descriptor) in self.mounts.iter().zip(descriptors) {
            require(
                descriptor.as_raw_fd() >= 3,
                "service directory descriptor aliases standard IO",
            )?;
            if mount.kind == ServiceMountKind::Secret {
                crate::platform::linux::fd::sealed_file::validate(*descriptor)?;
                continue;
            }
            let metadata = crate::platform::linux::fd::metadata(*descriptor)?;
            require(
                metadata.file_type() == crate::platform::linux::fd::FileType::Directory,
                "service descriptor is not a directory",
            )?;
            require(
                identities.insert((
                    metadata.identity().device,
                    metadata.identity().inode,
                )),
                "service descriptor roles alias the same directory",
            )?;
            if mount.kind == ServiceMountKind::State {
                crate::execution::configuration::validate_state_directory(*descriptor)?;
            }
            if mount.kind == ServiceMountKind::Configuration {
                crate::execution::configuration::validate_configuration_directory(*descriptor)?;
            }
        }
        Ok(())
    }
}
fn validate_retention(descriptor: BorrowedFd<'_>) -> Result<()> {
    let metadata = crate::platform::linux::fd::metadata(descriptor)?;
    // Runtime handoff carries an immutable ObjectLease interest, not the
    // writable global Store barrier or a durable hold. Match its producer.
    require(
        descriptor.as_raw_fd() >= 3
            && metadata.is_trusted_regular()
            && metadata.mode() & 0o7777 == 0o400,
        "retention must be an owned single-linked mode0400 regular descriptor",
    )
}
fn path_text(path: &str) -> bool {
    !path.is_empty() && path.len() <= 4096 && !path.contains('\0')
}
fn require(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(ServiceSpecError::Invalid(reason))
    }
}
struct BoundedBytes(Vec<u8>);
impl io::Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_SPEC_BYTES - self.0.len() {
            return Err(io::Error::other(
                "service body exceeds byte bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn structural_budget(bytes: &[u8]) -> Result<()> {
    let (mut string, mut escaped, mut depth, mut nodes) = (false, false, 0usize, 0usize);
    for byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                string = true;
                nodes += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                nodes += 1;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' => nodes += 1,
            _ => {}
        }
        require(
            depth <= 8 && nodes <= 8192,
            "service body structural budget exceeded",
        )?;
    }
    Ok(())
}

/// Managed mounts establish private proc/dev/tmp before declared working binds.
/// A subtree of private tmp may contain an explicitly declared working directory.
pub(crate) fn valid_managed_working_directory(cwd: &Path) -> bool {
    cwd != Path::new("/")
        && cwd != Path::new("/tmp")
        && !cwd.starts_with("/proc")
        && !cwd.starts_with("/dev")
        && !cwd.starts_with("/sys")
}

/// Managed working mounts cannot expose a cgroup control filesystem even when
/// an administrator bind-mounted it under an unrelated pathname.
pub(crate) fn validate_managed_working_descriptor(fd: BorrowedFd<'_>) -> io::Result<()> {
    if managed_control_filesystem(crate::platform::linux::fd::filesystem_type(fd)?) {
        return Err(io::Error::other(
            "managed cwd cannot expose a cgroup control filesystem",
        ));
    }
    Ok(())
}
fn managed_control_filesystem(kind: u64) -> bool {
    // Linux cgroup v1 and unified cgroup v2 superblock magic values.
    matches!(kind, 0x0027_e0eb | 0x6367_7270)
}
