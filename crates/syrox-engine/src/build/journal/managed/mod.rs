use super::{Operation, boot_id, invalid, lock_existing, read, write};
use crate::{
    build::BuildError, cancellation::Cancellation, platform::linux::fd as linux_fd,
    store::ContentDigest, systemd::SystemdUnitName,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::os::fd::AsFd as _;
use std::time::Instant;

pub(in crate::build) const LIMIT: usize = 16 * 1024;
const FILE: &str = "managed-attempt";
mod preparation;
mod settlement;
pub(in crate::build) use preparation::LocalManagedPreparation;
pub(in crate::build) use settlement::settled_managed;
pub(super) use settlement::{settle_local_awaiting, validate_settled_identity};
pub(super) const SETTLED_FILE: &str = "managed-settled";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::build) struct ManagedAttemptContext {
    pub action: ContentDigest,
    pub worker: ContentDigest,
    pub boot: String,
    pub manager: ContentDigest,
    pub scope: String,
    pub unit: SystemdUnitName,
    pub uid: u32,
    pub gid: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    action: String,
    worker: String,
    boot: String,
    manager: String,
    scope: String,
    unit: String,
    uid: u32,
    gid: u32,
    nonce: String,
    state: State,
    binding: Option<Binding>,
    namespace: Option<NamespaceRecord>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Awaiting,
    StartAuthorized,
    LocalAborted,
    Bound,
    NamespacePrepared,
    CommitAuthorized,
    CommitConsumed,
    Revoked,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    invocation: String,
    main_pid: u32,
    contract: String,
}

/// Persisted historical evidence only; numeric identities never authorize a
/// reopen, signal, cleanup, gate release or inference that a namespace is alive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::build) struct ManagedNamespaceSnapshot {
    pub resources: ContentDigest,
    pub pid: u32,
    pub device: u64,
    pub inode: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceRecord {
    resources: String,
    pid: u32,
    device: u64,
    inode: u64,
}
impl NamespaceRecord {
    fn snapshot(&self) -> Result<ManagedNamespaceSnapshot, BuildError> {
        Ok(ManagedNamespaceSnapshot {
            resources: digest(&self.resources)?,
            pid: self.pid,
            device: self.device,
            inode: self.inode,
        })
    }
}

impl Record {
    fn context(&self) -> Result<ManagedAttemptContext, BuildError> {
        Ok(ManagedAttemptContext {
            action: digest(&self.action)?,
            worker: digest(&self.worker)?,
            boot: self.boot.clone(),
            manager: digest(&self.manager)?,
            scope: self.scope.clone(),
            unit: SystemdUnitName::new(self.unit.clone())
                .map_err(|_| invalid("invalid managed unit"))?,
            uid: self.uid,
            gid: self.gid,
        })
    }
    fn encode(&self) -> Result<Vec<u8>, BuildError> {
        serde_json::to_vec(self).map_err(|_| invalid("managed record encoding failed"))
    }
    fn parse(bytes: &[u8]) -> Result<Self, BuildError> {
        if bytes.len() > LIMIT {
            return Err(invalid("oversized managed attempt"));
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid managed attempt"))?;
        let context = value.context()?;
        validate_context(&context)?;
        if value.version != 4
            || (!hex(&value.nonce, 32) || value.nonce.bytes().all(|byte| byte == b'0'))
            || value.encode()? != bytes
            || (matches!(
                value.state,
                State::Awaiting | State::StartAuthorized | State::LocalAborted
            ) && (value.binding.is_some() || value.namespace.is_some()))
            || (value.state == State::Bound
                && (value.binding.is_none() || value.namespace.is_some()))
            || (matches!(
                value.state,
                State::NamespacePrepared | State::CommitAuthorized | State::CommitConsumed
            ) && (value.binding.is_none() || value.namespace.is_none()))
            || (value.namespace.is_some() && value.binding.is_none())
        {
            return Err(invalid("noncanonical managed attempt"));
        }
        if let Some(binding) = &value.binding {
            if !hex(&binding.invocation, 32)
                || binding.invocation.bytes().all(|b| b == b'0')
                || binding.main_pid <= 1
                || binding.main_pid > i32::MAX as u32
            {
                return Err(invalid("invalid managed process binding"));
            }
            digest(&binding.contract)?;
        }
        if let Some(namespace) = &value.namespace {
            namespace.snapshot()?;
            if namespace.pid <= 1
                || namespace.pid > i32::MAX as u32
                || namespace.device == 0
                || namespace.inode == 0
                || value
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.main_pid == namespace.pid)
            {
                return Err(invalid("invalid managed namespace evidence"));
            }
        }
        Ok(value)
    }
    fn commit_transition(
        &mut self,
        expected: &Record,
        namespace: ManagedNamespaceSnapshot,
        from: State,
        to: State,
    ) -> Result<(), BuildError> {
        if self.state != from
            || self.context()? != expected.context()?
            || self.nonce != expected.nonce
            || self.binding != expected.binding
            || self
                .namespace
                .as_ref()
                .map(NamespaceRecord::snapshot)
                .transpose()?
                != Some(namespace)
            || !matches!(
                (from, to),
                (State::NamespacePrepared, State::CommitAuthorized)
                    | (State::CommitAuthorized, State::CommitConsumed)
            )
        {
            return Err(invalid(
                "managed commit evidence or phase differs",
            ));
        }
        self.state = to;
        Self::parse(&self.encode()?)?;
        Ok(())
    }
    fn matches_observed(
        &self,
        observed: &crate::build::managed::supervision::ObservedManagedBuildBinding,
    ) -> Result<bool, BuildError> {
        Ok(self.context()? == *observed.context()
            && self.nonce == observed.nonce()
            && self.binding.as_ref().is_some_and(|binding| {
                binding.main_pid == observed.main_pid()
                    && binding.contract == observed.contract().to_string()
                    && binding.invocation == invocation_text(observed.invocation())
            }))
    }
    fn namespace_prepared(
        &mut self,
        observed: &crate::build::managed::supervision::ObservedManagedBuildBinding,
        namespace: NamespaceRecord,
    ) -> Result<(), BuildError> {
        if self.state != State::Bound || !self.matches_observed(observed)? {
            return Err(invalid(
                "namespace observation differs from the bound attempt",
            ));
        }
        self.state = State::NamespacePrepared;
        self.namespace = Some(namespace);
        Self::parse(&self.encode()?)?;
        Ok(())
    }
}
fn invocation_text(invocation: &[u8; 16]) -> String {
    invocation
        .iter()
        .fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").expect("String write");
            text
        })
}
fn digest(text: &str) -> Result<ContentDigest, BuildError> {
    let value: ContentDigest = text
        .parse()
        .map_err(|_| invalid("invalid managed digest"))?;
    Ok(value)
}
fn hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_context(context: &ManagedAttemptContext) -> Result<(), BuildError> {
    let canonical_boot = crate::platform::linux::boot::BootId::parse(&context.boot).is_ok();
    let scope = context.scope == "system"
        || context
            .scope
            .strip_prefix("user:")
            .is_some_and(|path| {
                path.starts_with('/')
                    && !path.contains(['\0', '\n', '\r'])
                    && path.len() <= 4096
                    && !path
                        .split('/')
                        .skip(1)
                        .any(|part| part.is_empty() || part == "." || part == "..")
            });
    if !canonical_boot
        || !scope
        || matches!(context.uid, 0 | u32::MAX)
        || matches!(context.gid, 0 | u32::MAX)
    {
        return Err(invalid("invalid managed attempt context"));
    }
    Ok(())
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), BuildError> {
    cancellation.check()?;
    if Instant::now() >= deadline {
        return Err(invalid("managed attempt deadline elapsed"));
    }
    Ok(())
}
fn guard(
    operation: &Operation,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<linux_fd::OpenedPath, BuildError> {
    let guard = acquire_guard(operation, cancellation, deadline)?;
    if read(&operation.directory, SETTLED_FILE, LIMIT)?.is_some() {
        return Err(invalid("managed attempt is terminal"));
    }
    if let Some(bytes) = read(&operation.directory, FILE, LIMIT)?
        && Record::parse(&bytes)?.state == State::LocalAborted
    {
        return Err(invalid("managed local preparation was aborted"));
    }
    Ok(guard)
}
fn acquire_guard(
    operation: &Operation,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<linux_fd::OpenedPath, BuildError> {
    loop {
        check(cancellation, deadline)?;
        if let Some(guard) = lock_existing(&operation.directory, "gate")? {
            validate_guard(operation, &guard)?;
            return Ok(guard);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
fn validate_guard(operation: &Operation, guard: &linux_fd::OpenedPath) -> Result<(), BuildError> {
    validate_operation(operation)?;
    let gate = linux_fd::open_existing_regular(
        operation.directory.fd(),
        std::path::Path::new("gate"),
    )?;
    let metadata = gate.metadata();
    if metadata.identity() != guard.metadata().identity()
        || !metadata.is_trusted_regular()
        || metadata.size() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(invalid("managed operation lock changed"));
    }
    Ok(())
}
fn validate_operation(operation: &Operation) -> Result<(), BuildError> {
    let parent_path = operation
        .path
        .parent()
        .ok_or_else(|| invalid("managed operation parent missing"))?;
    let parent = linux_fd::open_top_directory(parent_path).map_err(super::problem)?;
    let current = super::directory(&parent, &operation.name)?;
    if current.metadata().identity() != operation.directory.metadata().identity() {
        return Err(invalid("managed operation namespace changed"));
    }
    super::validate_identity(&parent, &operation.directory, &operation.name)?;
    Ok(())
}
fn validate_current_context(
    operation: &Operation,
    context: &ManagedAttemptContext,
) -> Result<(), BuildError> {
    if context.boot != boot_id()?
        || context.uid != linux_fd::real_uid()
        || context.uid != linux_fd::effective_uid()
        || context.gid != linux_fd::real_gid()
        || context.gid != linux_fd::effective_gid()
        || context.unit.as_str() != operation.unit()
    {
        return Err(invalid(
            "managed attempt context differs from this operation",
        ));
    }
    Ok(())
}
pub(super) fn present(directory: &linux_fd::OpenedPath) -> Result<bool, BuildError> {
    if let Some(bytes) = read(directory, FILE, LIMIT)? {
        Record::parse(&bytes)?;
        settled_managed(directory)?;
        Ok(true)
    } else if read(directory, SETTLED_FILE, LIMIT)?.is_some() {
        Err(invalid(
            "managed settlement is missing its attempt",
        ))
    } else {
        Ok(false)
    }
}
impl Operation {
    #[cfg(test)]
    pub(in crate::build) fn prepare_managed(
        &self,
        context: &ManagedAttemptContext,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String, BuildError> {
        let guard = guard(self, cancellation, deadline)?;
        validate_context(context)?;
        validate_current_context(self, context)?;
        validate_shared_attempt(&self.directory, context.action)?;
        for name in [
            FILE,
            "authorized",
            "revoked",
            "cleaned",
            "cgroup",
        ] {
            if read(&self.directory, name, LIMIT)?.is_some() {
                return Err(invalid("operation already has admission state"));
            }
        }
        let record = awaiting_record(context)?;
        let nonce = record.nonce.clone();
        let bytes = record.encode()?;
        Record::parse(&bytes)?;
        check(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        write(&self.directory, FILE, &bytes)?;
        Ok(nonce)
    }
    /// Persist single-use dispatch authority before sending anything to the manager.
    pub(in crate::build) fn authorize_managed_start(
        &self,
        context: &ManagedAttemptContext,
        nonce: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let guard = guard(self, cancellation, deadline)?;
        let mut record = Record::parse(
            &read(&self.directory, FILE, LIMIT)?
                .ok_or_else(|| invalid("managed attempt missing"))?,
        )?;
        validate_current_context(self, context)?;
        if record.state != State::Awaiting || record.context()? != *context || record.nonce != nonce
        {
            return Err(invalid(
                "managed Start authorization is stale or already consumed",
            ));
        }
        record.state = State::StartAuthorized;
        let bytes = record.encode()?;
        Record::parse(&bytes)?;
        check(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        write(&self.directory, FILE, &bytes)
    }
    pub(in crate::build) fn bind_managed(
        &self,
        observation: &crate::build::managed::supervision::ObservedManagedBuildBinding,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let guard = guard(self, cancellation, deadline)?;
        let mut record = Record::parse(
            &read(&self.directory, FILE, LIMIT)?
                .ok_or_else(|| invalid("managed attempt missing"))?,
        )?;
        if record.state != State::StartAuthorized
            || record.context()? != *observation.context()
            || record.nonce != observation.nonce()
            || record.boot != boot_id()?
        {
            return Err(invalid(
                "managed observation is stale, mismatched or already bound",
            ));
        }
        validate_current_context(self, &record.context()?)?;
        record.state = State::Bound;
        record.binding = Some(Binding {
            invocation: invocation_text(observation.invocation()),
            main_pid: observation.main_pid(),
            contract: observation.contract().to_string(),
        });
        let bytes = record.encode()?;
        Record::parse(&bytes)?;
        check(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        write(&self.directory, FILE, &bytes)
    }
    /// Record only an independently observed, still-pinned namespace. This
    /// consumes the Bound phase once; it never authorizes payload execution.
    pub(in crate::build) fn record_managed_namespace(
        &self,
        observation: &crate::build::managed::ObservedManagedBuildNamespace<'_>,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        // Full revalidation takes its own journal read lock: do it before the
        // mutation lock, then compare its complete binding under this lock.
        observation.revalidate(cancellation, deadline)?;
        let guard = guard(self, cancellation, deadline)?;
        let mut record = Record::parse(
            &read(&self.directory, FILE, LIMIT)?
                .ok_or_else(|| invalid("managed attempt missing"))?,
        )?;
        validate_current_context(self, &record.context()?)?;
        let namespace = observation.namespace_identity();
        let identity = namespace.file_identity();
        record.namespace_prepared(
            observation.binding(),
            NamespaceRecord {
                resources: observation.resources_digest().to_string(),
                pid: namespace.pid(),
                device: identity.device,
                inode: identity.inode,
            },
        )?;
        let bytes = record.encode()?;
        check(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        // This kernel-only check does not reacquire the journal gate.
        namespace.revalidate(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        write(&self.directory, FILE, &bytes)
    }
    /// Persist authorization before sending COMMIT, under the same revocation
    /// lock. The callback must only perform bounded sending, never await a peer
    /// acknowledgement or reenter this journal. Failure never permits replay.
    pub(in crate::build) fn authorize_managed_commit<T>(
        &self,
        observation: &crate::build::managed::ObservedManagedBuildNamespace<'_>,
        cancellation: &Cancellation,
        deadline: Instant,
        send: impl FnOnce() -> Result<T, BuildError>,
    ) -> Result<T, BuildError> {
        observation.revalidate(cancellation, deadline)?;
        let guard = guard(self, cancellation, deadline)?;
        let bytes = read(&self.directory, FILE, LIMIT)?
            .ok_or_else(|| invalid("managed attempt missing"))?;
        let mut record = Record::parse(&bytes)?;
        validate_current_context(self, &record.context()?)?;
        if !record.matches_observed(observation.binding())? {
            return Err(invalid("managed commit binding differs"));
        }
        let namespace = observation.namespace_identity();
        let identity = namespace.file_identity();
        record.commit_transition(
            &Record::parse(&bytes)?,
            ManagedNamespaceSnapshot {
                resources: observation.resources_digest(),
                pid: namespace.pid(),
                device: identity.device,
                inode: identity.inode,
            },
            State::NamespacePrepared,
            State::CommitAuthorized,
        )?;
        namespace.revalidate(cancellation, deadline)?;
        commit_send(
            self,
            &guard,
            &record,
            cancellation,
            deadline,
            send,
        )
    }
    pub(in crate::build) fn revoke_managed(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let guard = guard(self, cancellation, deadline)?;
        let mut record = Record::parse(
            &read(&self.directory, FILE, LIMIT)?
                .ok_or_else(|| invalid("managed attempt missing"))?,
        )?;
        if record.state == State::Revoked {
            return Ok(());
        }
        record.state = State::Revoked;
        check(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        write(&self.directory, FILE, &record.encode()?)
    }
}

fn commit_send<T>(
    operation: &Operation,
    guard: &linux_fd::OpenedPath,
    record: &Record,
    cancellation: &Cancellation,
    deadline: Instant,
    send: impl FnOnce() -> Result<T, BuildError>,
) -> Result<T, BuildError> {
    check(cancellation, deadline)?;
    validate_guard(operation, guard)?;
    write(&operation.directory, FILE, &record.encode()?)?;
    check(cancellation, deadline)?;
    validate_guard(operation, guard)?;
    send()
}

/// Consume once before releasing the local gate. The caller authenticates the
/// COMMIT packet first; this function independently joins it to local retained
/// namespace evidence and the durable authorized record. The callback may only
/// perform bounded gate release and must not reacquire journal locks.
pub(in crate::build) fn consume_managed_commit<T>(
    published: &mut crate::build::managed::PublishedManagedBuildNamespace<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
    release: impl FnOnce(
        &mut crate::build::managed::PublishedManagedBuildNamespace<'_>,
    ) -> Result<T, BuildError>,
) -> Result<T, BuildError> {
    published.revalidate_for_commit(cancellation, deadline)?;
    let inspection = published.inspection();
    let expected = Record::parse(inspection.record_bytes())?;
    let attempt = inspect_worker_attempt(
        inspection.operation_path(),
        inspection.action_digest(),
        inspection.nonce(),
        cancellation,
        deadline,
    )?;
    let mut record = Record::parse(&attempt.record)?;
    if record
        .binding
        .as_ref()
        .is_none_or(|binding| binding.main_pid != std::process::id())
    {
        return Err(invalid("managed commit is not for this worker"));
    }
    let namespace = record
        .namespace
        .as_ref()
        .ok_or_else(|| invalid("managed namespace missing"))?
        .snapshot()?;
    let identity = linux_fd::require_unique_pidfd(published.namespace_pidfd())?.identity();
    if namespace.resources != published.resources_digest()
        || namespace.device != identity.device
        || namespace.inode != identity.inode
    {
        return Err(invalid("managed commit namespace differs"));
    }
    record.commit_transition(
        &expected,
        namespace,
        State::CommitAuthorized,
        State::CommitConsumed,
    )?;
    // Kernel-only checks under the gate, never a nested journal inspection.
    let current_pidfd = linux_fd::pidfd_open(namespace.pid)?;
    if linux_fd::require_unique_pidfd(current_pidfd.as_fd())?.identity() != identity
        || linux_fd::pidfd_exited(published.namespace_pidfd())?
    {
        return Err(invalid(
            "managed namespace is no longer the pinned process",
        ));
    }
    commit_worker_release(&attempt, &record, cancellation, deadline, || {
        release(published)
    })
}
fn commit_worker_release<T>(
    attempt: &WorkerAttempt,
    record: &Record,
    cancellation: &Cancellation,
    deadline: Instant,
    release: impl FnOnce() -> Result<T, BuildError>,
) -> Result<T, BuildError> {
    check(cancellation, deadline)?;
    attempt.revalidate()?;
    let bytes = record.encode()?;
    write(&attempt.directory, FILE, &bytes)?;
    check(cancellation, deadline)?;
    attempt.revalidate_record(&bytes)?;
    release()
}

fn awaiting_record(context: &ManagedAttemptContext) -> Result<Record, BuildError> {
    let nonce = linux_fd::operation_name()?
        .trim_start_matches("op-")
        .to_owned();
    let record = Record {
        version: 4,
        action: context.action.to_string(),
        worker: context.worker.to_string(),
        boot: context.boot.clone(),
        manager: context.manager.to_string(),
        scope: context.scope.clone(),
        unit: context.unit.as_str().into(),
        uid: context.uid,
        gid: context.gid,
        nonce,
        state: State::Awaiting,
        binding: None,
        namespace: None,
    };
    Ok(record)
}

fn validate_shared_attempt(
    directory: &linux_fd::OpenedPath,
    action: ContentDigest,
) -> Result<(), BuildError> {
    if super::Attempt::read(directory)?.is_some_and(|attempt| attempt.action != action) {
        return Err(invalid(
            "shared attempt differs from managed action",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// Read lock only. It is dropped before any inspection handle is returned.
pub(in crate::build) struct WorkerAttempt {
    pub directory: linux_fd::OpenedPath,
    pub stage: linux_fd::OpenedPath,
    pub context: ManagedAttemptContext,
    pub record: Vec<u8>,
    parent: linux_fd::OpenedPath,
    parent_path: std::path::PathBuf,
    name: String,
    read_guard: linux_fd::OpenedPath,
}
impl WorkerAttempt {
    pub(in crate::build) fn commit_consumed(&self) -> Result<bool, BuildError> {
        Ok(Record::parse(&self.record)?.state == State::CommitConsumed)
    }
    /// Compare immutable authenticated context across legitimate phase changes.
    pub(in crate::build) fn matches_original(&self, original: &[u8]) -> Result<bool, BuildError> {
        let current = Record::parse(&self.record)?;
        let original = Record::parse(original)?;
        Ok(current.context()? == original.context()?
            && current.nonce == original.nonce
            && current.binding == original.binding)
    }
    /// Historical journal evidence only, never a live process or gate authority.
    pub(in crate::build) fn bound_process(&self) -> Result<Option<([u8; 16], u32)>, BuildError> {
        let record = Record::parse(&self.record)?;
        if !matches!(
            record.state,
            State::Bound
                | State::NamespacePrepared
                | State::CommitAuthorized
                | State::CommitConsumed
        ) {
            return Ok(None);
        }
        let binding = record
            .binding
            .ok_or_else(|| invalid("managed binding missing"))?;
        let mut invocation = [0; 16];
        for (index, byte) in invocation.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&binding.invocation[index * 2..index * 2 + 2], 16)
                .map_err(|_| invalid("managed invocation encoding changed"))?;
        }
        Ok(Some((invocation, binding.main_pid)))
    }
    pub(in crate::build) fn namespace_snapshot(
        &self,
    ) -> Result<Option<ManagedNamespaceSnapshot>, BuildError> {
        Record::parse(&self.record)?
            .namespace
            .as_ref()
            .map(NamespaceRecord::snapshot)
            .transpose()
    }
    pub(in crate::build) fn gate_identity(&self) -> linux_fd::FileIdentity {
        self.read_guard.metadata().identity()
    }
    pub(in crate::build) fn revalidate(&self) -> Result<(), BuildError> {
        self.revalidate_record(&self.record)
    }
    fn revalidate_record(&self, expected_record: &[u8]) -> Result<(), BuildError> {
        if read(&self.directory, SETTLED_FILE, LIMIT)?.is_some() {
            return Err(invalid("managed worker attempt is terminal"));
        }
        let parent = linux_fd::open_top_directory(&self.parent_path).map_err(super::problem)?;
        super::validate_operation_directory(&parent)?;
        if parent.metadata().identity() != self.parent.metadata().identity() {
            return Err(invalid("managed operation parent changed"));
        }
        let current = super::directory(&parent, &self.name)?;
        let gate = linux_fd::open_existing_regular(current.fd(), std::path::Path::new("gate"))?;
        if gate.metadata().identity() != self.read_guard.metadata().identity() {
            return Err(invalid("managed inspection lock changed"));
        }
        for name in [
            "authorized",
            "revoked",
            "cleaned",
            "cgroup",
        ] {
            if read(&current, name, LIMIT)?.is_some() {
                return Err(invalid("managed legacy admission appeared"));
            }
        }
        validate_shared_attempt(&current, self.context.action)?;
        super::validate_tree(&current)?;
        let stage = super::directory(&current, "stage")?;
        if current.metadata().identity() != self.directory.metadata().identity()
            || stage.metadata().identity() != self.stage.metadata().identity()
            || read(&current, FILE, LIMIT)?.as_deref() != Some(expected_record)
        {
            return Err(invalid(
                "managed inspection namespace or record changed",
            ));
        }
        super::validate_identity(&self.parent, &current, &self.name)?;
        Ok(())
    }
}
pub(in crate::build) fn inspect_worker_attempt(
    path: &std::path::Path,
    action: ContentDigest,
    nonce: &str,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<WorkerAttempt, BuildError> {
    check(cancellation, deadline)?;
    if path
        .components()
        .collect::<std::path::PathBuf>()
        .as_os_str()
        != path.as_os_str()
        || !path.is_absolute()
        || path.components().any(|part| {
            !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(invalid("noncanonical managed operation path"));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| super::valid_name(name, "op-"))
        .ok_or_else(|| invalid("invalid managed operation name"))?;
    let parent = linux_fd::open_top_directory(
        path.parent()
            .ok_or_else(|| invalid("operation parent missing"))?,
    )
    .map_err(super::problem)?;
    super::validate_operation_directory(&parent)?;
    let directory = super::directory(&parent, name)?;
    if super::validate_identity(&parent, &directory, name)? != boot_id()? {
        return Err(invalid(
            "managed operation belongs to another boot",
        ));
    }
    let guard = loop {
        check(cancellation, deadline)?;
        if let Some(guard) = lock_existing(&directory, "gate")? {
            break guard;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let bytes = read(&directory, FILE, LIMIT)?.ok_or_else(|| invalid("managed attempt missing"))?;
    let record = Record::parse(&bytes)?;
    let context = record.context()?;
    if read(&directory, SETTLED_FILE, LIMIT)?.is_some()
        || matches!(
            record.state,
            State::Awaiting | State::LocalAborted | State::Revoked
        )
        || context.action != action
        || record.nonce != nonce
        || context.boot != boot_id()?
        || context.unit.as_str() != super::unit(name)
        || context.uid != linux_fd::real_uid()
        || context.uid != linux_fd::effective_uid()
        || context.gid != linux_fd::real_gid()
        || context.gid != linux_fd::effective_gid()
    {
        return Err(invalid(
            "managed worker arguments or caller differ from attempt",
        ));
    }
    for name in [
        "authorized",
        "revoked",
        "cleaned",
        "cgroup",
    ] {
        if read(&directory, name, LIMIT)?.is_some() {
            return Err(invalid(
                "managed attempt contains legacy admission state",
            ));
        }
    }
    validate_shared_attempt(&directory, context.action)?;
    super::validate_tree(&directory)?;
    let stage = super::directory(&directory, "stage")?;
    let attempt = WorkerAttempt {
        directory,
        stage,
        context,
        record: bytes,
        parent,
        parent_path: path
            .parent()
            .expect("validated parent")
            .to_path_buf(),
        name: name.into(),
        read_guard: guard,
    };
    attempt.revalidate()?;
    check(cancellation, deadline)?;
    Ok(attempt)
}
