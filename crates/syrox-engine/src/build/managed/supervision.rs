use super::{
    BuildError, journal::managed::ManagedAttemptContext, manager_error,
    preparation::PreparedManagedBuild,
};
use crate::build::managed::remaining_request_duration as remaining;
use crate::platform::linux::boot::BootId;
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    systemd::SystemdBuildLimits, systemd::SystemdManager, systemd::SystemdScope,
    systemd::SystemdService, systemd::SystemdServiceProfile, systemd::SystemdUnitName,
};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;
use std::time::{Duration, Instant};

/// Description only; the managed worker dispatch and execution gate are not enabled.
#[derive(Clone)]
pub struct ManagedBuildServiceSpecification {
    service: SystemdService,
    context: ManagedAttemptContext,
    nonce: String,
}
impl std::fmt::Debug for ManagedBuildServiceSpecification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedBuildServiceSpecification")
            .field("unit", &self.context.unit)
            .finish_non_exhaustive()
    }
}
impl ManagedBuildServiceSpecification {
    pub(in crate::build) fn context(&self) -> &ManagedAttemptContext {
        &self.context
    }
    pub(in crate::build) fn nonce(&self) -> &str {
        &self.nonce
    }
    pub(in crate::build) fn service(&self) -> &SystemdService {
        &self.service
    }
}
/// Observed manager, image and invocation identity, not execution authorization.
/// This cannot be constructed from caller-provided PIDs or unit-name strings.
pub struct ObservedManagedBuildBinding {
    context: ManagedAttemptContext,
    nonce: String,
    invocation: [u8; 16],
    main_pid: u32,
    contract: ContentDigest,
}
impl std::fmt::Debug for ObservedManagedBuildBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservedManagedBuildBinding")
            .field("unit", &self.context.unit)
            .finish_non_exhaustive()
    }
}
impl ObservedManagedBuildBinding {
    pub(in crate::build) fn duplicate_evidence(&self) -> Self {
        Self {
            context: self.context.clone(),
            nonce: self.nonce.clone(),
            invocation: self.invocation,
            main_pid: self.main_pid,
            contract: self.contract,
        }
    }
    #[cfg(test)]
    pub(in crate::build) fn for_test(
        context: ManagedAttemptContext,
        nonce: String,
        invocation: [u8; 16],
        main_pid: u32,
        contract: ContentDigest,
    ) -> Self {
        Self {
            context,
            nonce,
            invocation,
            main_pid,
            contract,
        }
    }
    pub(in crate::build) fn context(&self) -> &ManagedAttemptContext {
        &self.context
    }
    pub(in crate::build) fn nonce(&self) -> &str {
        &self.nonce
    }
    pub(in crate::build) fn invocation(&self) -> &[u8; 16] {
        &self.invocation
    }
    pub(in crate::build) fn main_pid(&self) -> u32 {
        self.main_pid
    }
    pub(in crate::build) fn contract(&self) -> ContentDigest {
        self.contract
    }
}
pub(in crate::build) fn prepare_local_service(
    prepared: &PreparedManagedBuild,
    manager: &mut SystemdManager,
    endpoint: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
    local: &mut super::journal::managed::LocalManagedPreparation<'_>,
) -> Result<ManagedBuildServiceSpecification, BuildError> {
    check(cancellation, deadline)?;
    validate_endpoint(endpoint)?;
    prepared.verify_preparation(cancellation)?;
    prepared.verify_service_worker(cancellation)?;
    if linux_fd::real_uid() != linux_fd::effective_uid()
        || linux_fd::real_gid() != linux_fd::effective_gid()
    {
        return Err(invalid());
    }
    let identity = manager
        .observe_identity(remaining(deadline)?, cancellation)
        .map_err(|error| manager_error(&error))?;
    let context = ManagedAttemptContext {
        action: prepared.action_digest(),
        worker: prepared.worker_digest(),
        boot: BootId::current(cancellation, deadline)
            .map_err(|error| boot_error(&error))?
            .as_str()
            .into(),
        manager: identity.fingerprint(),
        scope: scope_key(identity.scope())?,
        unit: SystemdUnitName::new(format!(
            "syrox-build-{}.service",
            &prepared.operation_id()[3..]
        ))
        .map_err(|error| manager_error(&error))?,
        uid: linux_fd::effective_uid(),
        gid: linux_fd::effective_gid(),
    };
    let nonce = local.install(&context, cancellation, deadline)?;
    let service = specification(
        prepared.worker_path(),
        prepared.operation_path(),
        prepared.resources(),
        prepared.timeout_seconds(),
        &context,
        &nonce,
        endpoint,
    )?;
    check(cancellation, deadline)?;
    Ok(ManagedBuildServiceSpecification {
        service,
        context,
        nonce,
    })
}
fn specification(
    worker: std::path::PathBuf,
    operation: &Path,
    resources: super::BuildResources,
    timeout_seconds: u32,
    context: &ManagedAttemptContext,
    nonce: &str,
    endpoint: &Path,
) -> Result<SystemdService, BuildError> {
    let limits = resources.envelope();
    let mut service = SystemdService::new(context.unit.clone(), worker);
    if context.scope == "system" {
        service.credentials = Some(crate::systemd::SystemdCredentials {
            uid: context.uid,
            gid: context.gid,
        });
    }
    service.arguments = vec![
        "__managed-build".into(),
        operation.to_str().ok_or_else(invalid)?.into(),
        context.action.to_string(),
        nonce.into(),
        endpoint.to_str().ok_or_else(invalid)?.into(),
    ];
    // The static launcher may inherit other manager variables. Its payload must
    // still use env_clear; these settings are not an environment allowlist.
    service.environment = [
        ("PATH", ""),
        ("LC_ALL", "C"),
        ("HOME", "/tmp"),
        ("SOURCE_DATE_EPOCH", "0"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    service.profile = SystemdServiceProfile::Notify {
        fd_store_max: 2,
        start_timeout: Duration::from_secs(30),
    };
    service.runtime_max = Some(Duration::from_secs(u64::from(timeout_seconds)));
    service.stop_timeout = Duration::from_secs(5);
    service.memory_max = Some(limits.memory);
    service.tasks_max = Some(u64::from(limits.tasks));
    service.build_limits = Some(SystemdBuildLimits {
        cpu_percent: limits.cpu_percent,
        nofile: u64::from(limits.nofile),
        file_size: limits.output_bytes,
    });
    Ok(service)
}
pub fn observe_managed_build_binding(
    prepared: &PreparedManagedBuild,
    specification: &ManagedBuildServiceSpecification,
    manager: &mut SystemdManager,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ObservedManagedBuildBinding, BuildError> {
    check(cancellation, deadline)?;
    prepared.verify_preparation(cancellation)?;
    prepared.verify_service_worker(cancellation)?;
    let context = &specification.context;
    if prepared.action_digest() != context.action
        || prepared.worker_digest() != context.worker
        || context.unit.as_str()
            != format!(
                "syrox-build-{}.service",
                &prepared.operation_id()[3..]
            )
        || scope_key(
            manager
                .observe_identity(remaining(deadline)?, cancellation)
                .map_err(|error| manager_error(&error))?
                .scope(),
        )? != context.scope
        || BootId::current(cancellation, deadline)
            .map_err(|error| boot_error(&error))?
            .as_str()
            != context.boot
    {
        return Err(invalid());
    }
    let first = manager
        .observe_build_unit(
            &specification.service,
            remaining(deadline)?,
            cancellation,
        )
        .map_err(|error| manager_error(&error))?;
    if first.manager.fingerprint() != context.manager {
        return Err(invalid());
    }
    let pidfd = linux_fd::pidfd_open(first.status.main_pid)?;
    verify_image(
        first.status.main_pid,
        &first.status.control_group,
        context,
        cancellation,
        deadline,
    )?;
    let second = manager
        .observe_build_unit(
            &specification.service,
            remaining(deadline)?,
            cancellation,
        )
        .map_err(|error| manager_error(&error))?;
    if first.manager != second.manager
        || first.contract != second.contract
        || first.status.main_pid != second.status.main_pid
        || first.status.invocation != second.status.invocation
        || first.status.control_group != second.status.control_group
        || linux_fd::pidfd_exited(pidfd.as_fd())?
    {
        return Err(invalid());
    }
    check(cancellation, deadline)?;
    Ok(ObservedManagedBuildBinding {
        context: context.clone(),
        nonce: specification.nonce.clone(),
        invocation: second
            .status
            .invocation
            .try_into()
            .map_err(|_| invalid())?,
        main_pid: second.status.main_pid,
        contract: second.contract,
    })
}
fn verify_image(
    pid: u32,
    control_group: &str,
    context: &ManagedAttemptContext,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    let proc =
        linux_fd::open_top_directory(Path::new(&format!("/proc/{pid}"))).map_err(|_| invalid())?;
    if linux_fd::filesystem_type(proc.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    verify_membership(&proc, control_group, cancellation, deadline)?;
    let status = linux_fd::open_existing_regular(proc.fd(), Path::new("status"))?;
    let mut text = String::new();
    status
        .into_file()
        .take(65537)
        .read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(invalid());
    }
    verify_credentials(&text, context.uid, context.gid)?;
    // Kernel procfs magic link, relative to the pinned numeric PID directory.
    let mut image = File::open(format!(
        "/proc/self/fd/{}/exe",
        proc.fd().as_raw_fd()
    ))?;
    if !image.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut hash = Sha256::new();
    let mut total = 0usize;
    let mut bytes = [0u8; 16384];
    loop {
        check(cancellation, deadline)?;
        let count = image.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total += count;
        if total > 128 * 1024 * 1024 {
            return Err(invalid());
        }
        hash.update(&bytes[..count]);
    }
    if ContentDigest::from_sha256_hash(hash.finalize().into()) != context.worker {
        return Err(invalid());
    }
    verify_membership(&proc, control_group, cancellation, deadline)
}
fn verify_credentials(text: &str, uid: u32, gid: u32) -> Result<(), BuildError> {
    for (key, expected) in [("Uid:", uid), ("Gid:", gid)] {
        let values = text
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(invalid)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        if values.len() != 4 || values.iter().any(|value| *value != expected) {
            return Err(invalid());
        }
    }
    Ok(())
}
fn verify_membership(
    proc: &linux_fd::OpenedPath,
    expected: &str,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    check(cancellation, deadline)?;
    let file = linux_fd::open_existing_regular(proc.fd(), Path::new("cgroup"))?;
    let mut bytes = Vec::new();
    file.into_file()
        .take(8193)
        .read_to_end(&mut bytes)?;
    check(cancellation, deadline)?;
    exact_membership(&bytes, expected)
}
// Membership observation only. This path never authorizes opening, removing or
// otherwise manipulating a cgroup. Accept only the unified cgroup-v2 record.
fn exact_membership(bytes: &[u8], expected: &str) -> Result<(), BuildError> {
    if bytes.len() > 8192
        || expected.len() > 4096
        || !expected.starts_with('/')
        || expected.len() == 1
        || expected.bytes().any(|b| b.is_ascii_control())
        || expected[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if text
        .strip_prefix("0::")
        .and_then(|value| value.strip_suffix('\n'))
        != Some(expected)
    {
        return Err(invalid());
    }
    Ok(())
}
fn scope_key(scope: &SystemdScope) -> Result<String, BuildError> {
    Ok(match scope {
        SystemdScope::System => "system".into(),
        SystemdScope::User {
            bus_socket,
        } => {
            format!(
                "user:{}",
                bus_socket.to_str().ok_or_else(invalid)?
            )
        }
    })
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), BuildError> {
    cancellation.check()?;
    remaining(deadline).map(|_| ())
}
fn boot_error(error: &crate::platform::linux::boot::BootError) -> BuildError {
    if matches!(
        error,
        crate::platform::linux::boot::BootError::Cancelled
    ) {
        BuildError::Cancelled
    } else {
        invalid()
    }
}
fn invalid() -> BuildError {
    BuildError::InvalidRequest
}

pub(in crate::build) fn validate_endpoint(endpoint: &Path) -> Result<(), BuildError> {
    let text = endpoint.to_str().ok_or_else(invalid)?;
    if !endpoint.is_absolute()
        || text.len() >= 108
        || text.contains('\0')
        || text[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_description_uses_authenticated_worker_literal_arguments_and_full_envelope() {
        let context = ManagedAttemptContext {
            action: ContentDigest::sha256(b"action"),
            worker: ContentDigest::sha256(b"worker"),
            boot: "12345678-1234-1234-1234-123456789abc".into(),
            manager: ContentDigest::sha256(b"manager"),
            scope: "user:/run/user/1000/bus".into(),
            unit: SystemdUnitName::new("syrox-build-test.service").unwrap(),
            uid: 1000,
            gid: 1000,
        };
        for resources in [
            super::super::BuildResources::Standard,
            super::super::BuildResources::Large,
        ] {
            let service = specification(
                "/private/op/stage/worker".into(),
                Path::new("/private/op"),
                resources,
                120,
                &context,
                "0123456789abcdef0123456789abcdef",
                Path::new("/private/build.sock"),
            )
            .unwrap();
            let limits = resources.envelope();
            assert_eq!(
                service.executable,
                Path::new("/private/op/stage/worker")
            );
            assert_eq!(
                service.arguments,
                [
                    "__managed-build",
                    "/private/op",
                    &context.action.to_string(),
                    "0123456789abcdef0123456789abcdef",
                    "/private/build.sock"
                ]
            );
            assert_eq!(service.environment["PATH"], "");
            assert!(service.credentials.is_none());
            assert_eq!(service.memory_max, Some(limits.memory));
            assert_eq!(service.tasks_max, Some(u64::from(limits.tasks)));
            assert_eq!(
                service.runtime_max,
                Some(Duration::from_secs(120))
            );
            assert_eq!(
                service.build_limits,
                Some(SystemdBuildLimits {
                    cpu_percent: limits.cpu_percent,
                    nofile: u64::from(limits.nofile),
                    file_size: limits.output_bytes
                })
            );
            assert!(matches!(
                service.profile,
                SystemdServiceProfile::Notify {
                    fd_store_max: 2,
                    ..
                }
            ));
        }
        let mut system_context = context;
        system_context.scope = "system".into();
        let service = specification(
            "/private/worker".into(),
            Path::new("/private/op"),
            super::super::BuildResources::Standard,
            120,
            &system_context,
            "0123456789abcdef0123456789abcdef",
            Path::new("/private/build.sock"),
        )
        .unwrap();
        assert_eq!(
            service.credentials,
            Some(crate::systemd::SystemdCredentials {
                uid: 1000,
                gid: 1000
            })
        );
    }
    #[test]
    fn description_work_does_not_override_cancellation_or_expired_deadline() {
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            check(&cancel, Instant::now() + Duration::from_secs(1)),
            Err(BuildError::Cancelled)
        ));
        assert!(check(&Cancellation::default(), Instant::now()).is_err());
    }

    #[test]
    fn membership_requires_exact_canonical_unified_unit_path() {
        let group = "/user.slice/syrox-build-test.service";
        exact_membership(format!("0::{group}\n").as_bytes(), group).unwrap();
        for actual in [
            "0::/user.slice/syrox-build-test.service-child\n",
            "0::/user.slice/syrox-build-test.service/child\n",
            "0::/user.slice/syrox-build-other.service\n",
            "0::/user.slice/syrox-build-test.service\n0::/other\n",
            "1:name=systemd:/user.slice/syrox-build-test.service\n",
            "0::/user.slice/syrox-build-test.service",
        ] {
            assert!(exact_membership(actual.as_bytes(), group).is_err());
        }
        for invalid in [
            "",
            "/",
            "relative",
            "/unit/",
            "/unit//child",
            "/unit/./child",
            "/unit/../child",
            "/unit\nother",
        ] {
            assert!(exact_membership(format!("0::{invalid}\n").as_bytes(), invalid).is_err());
        }
        assert!(exact_membership(&vec![b'x'; 8193], group).is_err());
    }

    #[test]
    fn observed_process_credentials_require_all_ids_to_match_the_context() {
        verify_credentials(
            "Uid:\t1000 1000 1000 1000\nGid:\t1001 1001 1001 1001\n",
            1000,
            1001,
        )
        .unwrap();
        for status in [
            "Uid: 0 0 0 0\nGid: 1001 1001 1001 1001\n",
            "Uid: 1000 0 1000 1000\nGid: 1001 1001 1001 1001\n",
            "Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\n",
            "Uid: 1000 1000 1000\nGid: 1001 1001 1001 1001\n",
        ] {
            assert!(verify_credentials(status, 1000, 1001).is_err());
        }
    }
}
