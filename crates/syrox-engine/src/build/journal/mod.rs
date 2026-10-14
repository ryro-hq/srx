//! Durable records of a build and the execution that still owns its resources.
//!
//! Recovery uses this record to settle an interrupted attempt. Removing staging
//! requires revoking the possibility of another start and observing execution end.
//! `Drop` does not remove this state.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::{
    BuildError, BuildRecoveryEntry, BuildRecoveryReport, BuildRecoveryState, BuildResult, sandbox,
};
use crate::platform::linux::fd::{self as fd, FileIdentity, FlockMode, OpenedPath};
use crate::store::OperationLease;
use crate::{store::ContentDigest, store::Store};

pub(super) mod managed;

pub(super) const MAX_OPERATIONS: usize = 1024;
const MAX_FILES: usize = 32;
const TEMP_PREFIX: &str = ".syrox-build.tmp.";
const AUTHORIZED: &[u8] = b"syrox-build-authorized\n";
const REVOKED: &[u8] = b"syrox-build-revoked\n";
const CLEANED: &[u8] = b"syrox-build-cleaned\n";

/// Producer-owned budget, persisted before admission releases its namespace
/// lock. It is not part of the reusable result or mounted into the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Attempt {
    pub action: ContentDigest,
    pub timeout_seconds: u32,
}

impl Attempt {
    pub(super) fn new(action: ContentDigest, timeout_seconds: u32) -> Result<Self, BuildError> {
        if !(1..=1800).contains(&timeout_seconds) {
            return Err(BuildError::InvalidRequest);
        }
        Ok(Self {
            action,
            timeout_seconds,
        })
    }

    fn encode(self) -> String {
        format!(
            "syrox-build-attempt-v1\naction {}\ntimeout {}\n",
            self.action, self.timeout_seconds
        )
    }

    pub(super) fn read(directory: &OpenedPath) -> Result<Option<Self>, BuildError> {
        read(directory, "action", 256)?
            .map(|bytes| Self::parse(&bytes))
            .transpose()
    }

    fn parse(bytes: &[u8]) -> Result<Self, BuildError> {
        let text = std::str::from_utf8(bytes).map_err(problem)?;
        let mut lines = text.lines();
        if lines.next() != Some("syrox-build-attempt-v1") {
            return Err(invalid("unsupported build attempt"));
        }
        let action = lines
            .next()
            .and_then(|line| line.strip_prefix("action "))
            .ok_or_else(|| invalid("missing attempt action"))?
            .parse()
            .map_err(problem)?;
        let timeout = lines
            .next()
            .and_then(|line| line.strip_prefix("timeout "))
            .ok_or_else(|| invalid("missing attempt deadline"))?
            .parse()
            .map_err(problem)?;
        let attempt = Self::new(action, timeout)?;
        if attempt.encode().as_bytes() != bytes {
            return Err(invalid("noncanonical build attempt"));
        }
        Ok(attempt)
    }
}

#[derive(Debug)]
pub(super) struct Operation {
    pub(super) name: String,
    pub(super) path: PathBuf,
    pub(super) directory: OpenedPath,
    _coordinator: OpenedPath,
    pub(super) producer_budget: Option<fs::File>,
}

impl Operation {
    pub(super) fn create(lease: &OperationLease) -> Result<Self, BuildError> {
        let parent = lease.build_directory()?;
        let _mutation = lock_namespace(&parent)?;
        Self::create_locked(&parent)
    }

    /// Caller holds the journal namespace lock through admission and action binding.
    pub(super) fn create_locked(parent: &OpenedPath) -> Result<Self, BuildError> {
        if entries(parent, MAX_OPERATIONS)?.len() >= MAX_OPERATIONS {
            return Err(invalid(
                "operation limit reached; run srx store recover",
            ));
        }
        let name = fd::operation_name()?;
        let initializing = format!("init-{}", &name[3..]);
        let (directory, created) =
            fd::ensure_directory_beneath_with_status(parent.fd(), Path::new(&initializing))
                .map_err(problem)?;
        if !created {
            return Err(invalid("operation name collision"));
        }
        let (coordinator, _) = fd::initialize_regular(directory.fd(), Path::new("lease"))?;
        if !fd::flock(coordinator.fd(), FlockMode::ExclusiveNonblocking)? {
            return Err(invalid("new operation lease is busy"));
        }
        let (gate, _) = fd::initialize_regular(directory.fd(), Path::new("gate"))?;
        fd::sync_file(coordinator.fd())?;
        fd::sync_file(gate.fd())?;
        for name in ["consumers", "observers"] {
            let (file, _) = fd::initialize_regular(directory.fd(), Path::new(name))?;
            fd::sync_file(file.fd())?;
        }
        fd::ensure_directory_beneath(directory.fd(), Path::new("stage")).map_err(problem)?;
        write(
            &directory,
            "identity",
            identity(
                &name,
                &boot_id()?,
                parent.metadata().identity(),
                directory.metadata().identity(),
            )
            .as_bytes(),
        )?;
        fd::rename_directory(
            parent.fd(),
            Path::new(&initializing),
            Path::new(&name),
            directory.metadata().identity(),
        )?;
        let path = fd::directory_path(&directory)?;
        Ok(Self {
            name,
            path,
            directory,
            _coordinator: coordinator,
            producer_budget: None,
        })
    }

    pub(super) fn stage_path(&self) -> PathBuf {
        self.path.join("stage")
    }
    pub(super) fn unit(&self) -> String {
        unit(&self.name)
    }

    pub(super) fn write_stage(
        &self,
        name: &str,
        bytes: &[u8],
        executable: bool,
    ) -> Result<(), BuildError> {
        use std::os::unix::fs::PermissionsExt as _;
        let stage = directory(&self.directory, "stage")?;
        write(&stage, name, bytes)?;
        let file = fd::open_existing_regular(stage.fd(), Path::new(name))?.into_file();
        file.set_permissions(fs::Permissions::from_mode(if executable {
            0o500
        } else {
            0o400
        }))?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn authorize(
        &self,
        action: ContentDigest,
        _runtime: Option<ContentDigest>,
    ) -> Result<(), BuildError> {
        self.bind(Attempt::new(action, 30)?)?;
        write(&self.directory, "authorized", AUTHORIZED)
    }

    pub(super) fn authorize_program(
        &self,
        action: &super::records::Action,
        timeout_seconds: u32,
    ) -> Result<(), BuildError> {
        if action.program.profile == super::BuildProfile::Managed
            || managed::present(&self.directory)?
        {
            return Err(invalid(
                "managed preparation cannot use host authorization",
            ));
        }
        if Attempt::read(&self.directory)? != Some(Attempt::new(action.digest(), timeout_seconds)?)
        {
            return Err(invalid(
                "launch differs from admitted build attempt",
            ));
        }
        self.write_stage("build-action", &action.encode(), false)?;
        self.write_stage("build-program", &action.program.encode(), false)?;
        write(&self.directory, "authorized", AUTHORIZED)
    }

    pub(super) fn bind(&self, attempt: Attempt) -> Result<(), BuildError> {
        if managed::present(&self.directory)? {
            return Err(invalid(
                "managed attempt cannot use legacy admission",
            ));
        }
        write(
            &self.directory,
            "action",
            attempt.encode().as_bytes(),
        )
    }

    pub(super) fn record_origin(&self, origin: &str) -> Result<(), BuildError> {
        if origin.len() > 64 * 1024 {
            return Err(invalid("build origin exceeds journal limit"));
        }
        // Diagnostic provenance only, never cache or recovery authority.
        write(&self.directory, "origin", origin.as_bytes())
    }

    pub(super) fn log(&self, bytes: &[u8]) -> Result<(), BuildError> {
        write(
            &self.directory,
            "log",
            &bytes[bytes.len().saturating_sub(16 * 1024)..],
        )
    }

    pub(super) fn clean_stage(&self) -> Result<(), BuildError> {
        if managed::present(&self.directory)? {
            return Err(invalid(
                "managed attempt requires explicit reconciliation",
            ));
        }
        let Some(_gate) = lock_existing(&self.directory, "gate")? else {
            return Err(invalid(
                "launch gate still active; staging retained",
            ));
        };
        write(&self.directory, "revoked", REVOKED)?;
        prove_empty(&self.directory, &self.name)?;
        remove_stage(&self.directory)?;
        write(&self.directory, "cleaned", CLEANED)
    }

    pub(super) fn finish(
        &self,
        result: Result<BuildResult, BuildError>,
    ) -> Result<BuildResult, BuildError> {
        let text = match &result {
            Ok(result) => format!(
                "syrox-build-outcome\npublished {} {}\n",
                result.root, result.receipt
            ),
            Err(error) => {
                let message = error.to_string();
                // UTF-8 diagnostic text is informational, never recovery authority.
                let end = message.floor_char_boundary(2048.min(message.len()));
                format!(
                    "syrox-build-outcome\nfailed\n{}\n",
                    &message[..end]
                )
            }
        };
        match write(&self.directory, "outcome", text.as_bytes()) {
            Ok(()) => result,
            Err(journal) => Err(match result {
                Ok(result) => BuildError::PublishedAndJournal {
                    root: result.root,
                    journal: journal.to_string(),
                },
                Err(primary) => BuildError::FailureAndJournal {
                    primary: Box::new(primary),
                    journal: journal.to_string(),
                },
            }),
        }
    }
}

/// Held for the entire service-side bwrap lifetime, independently of the CLI.
pub(super) struct LaunchGate {
    _guard: OpenedPath,
    description: super::records::Action,
}

impl LaunchGate {
    pub(super) fn description(&self) -> &super::records::Action {
        &self.description
    }
}

pub(super) fn enter_gate(path: &Path) -> Result<LaunchGate, BuildError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|name| valid_name(name, "op-"))
        .ok_or_else(|| invalid("invalid launch operation path"))?;
    let parent_path = path
        .parent()
        .ok_or_else(|| invalid("missing operation parent"))?;
    let parent = fd::open_top_directory(parent_path).map_err(problem)?;
    validate_operation_directory(&parent)?;
    let directory = directory(&parent, name)?;
    let recorded_boot = validate_identity(&parent, &directory, name)?;
    if recorded_boot != boot_id()? {
        return Err(invalid("launch belongs to a previous boot"));
    }
    let guard = lock_existing(&directory, "gate")?.ok_or_else(|| invalid("launch gate is busy"))?;
    // A recoverer may have renamed/deleted the operation after our first open.
    let reopened = self::directory(&parent, name)?;
    if reopened.metadata().identity() != directory.metadata().identity() {
        return Err(invalid("operation path changed"));
    }
    if managed::present(&directory)? {
        return Err(invalid(
            "managed attempt cannot enter the host gate",
        ));
    }
    if read(&directory, "authorized", 64)?.as_deref() != Some(AUTHORIZED)
        || read(&directory, "revoked", 64)?.is_some()
        || read(&directory, "cleaned", 64)?.is_some()
        || read(&directory, "cgroup", 8192)?.is_some()
    {
        return Err(invalid(
            "launch authorization absent, revoked or already consumed",
        ));
    }
    let attempt = Attempt::read(&directory)?.ok_or_else(|| invalid("launch attempt is missing"))?;
    let stage = self::directory(&directory, "stage")?;
    let bytes = read(
        &stage,
        "build-action",
        usize::try_from(super::records::MAX_RECORD_BYTES).expect("bounded record size"),
    )?
    .ok_or_else(|| invalid("build action missing"))?;
    let description = super::records::Action::parse(&bytes)?;
    if description.program.profile == super::BuildProfile::Managed {
        return Err(invalid(
            "managed action cannot enter the host gate",
        ));
    }
    if description.digest() != attempt.action {
        return Err(invalid("build action changed"));
    }
    // Persist the actual host cgroup BEFORE spawning bwrap. If this write or its
    // fsync is uncertain, no payload is launched. A late activation must pass
    // the revocable gate again; a PID or mere unit absence is never authority.
    let membership = read_host_file(Path::new("/proc/self/cgroup"), 8192)?;
    let text = std::str::from_utf8(&membership).map_err(problem)?;
    let relative = text
        .strip_prefix("0::/")
        .and_then(|v| v.strip_suffix('\n'))
        .filter(|v| valid_group(v, name))
        .ok_or_else(|| invalid("service is not in its owned cgroup v2 unit"))?;
    let group = open_group(relative)?.ok_or_else(|| invalid("service cgroup disappeared"))?;
    let id = group.metadata().identity();
    write(
        &directory,
        "cgroup",
        format!(
            "syrox-build-cgroup\n{relative}\n{} {}\n",
            id.device, id.inode
        )
        .as_bytes(),
    )?;
    Ok(LaunchGate {
        _guard: guard,
        description,
    })
}

pub(super) fn recover(store: &Store) -> Result<BuildRecoveryReport, BuildError> {
    let lease = store.operation()?;
    let parent = lease.build_directory()?;
    let _mutation = lock_namespace(&parent)?;
    let names = entries(&parent, MAX_OPERATIONS)?;
    if names.iter().any(|name| {
        !["op-", "init-", "gc-"]
            .iter()
            .any(|prefix| valid_name(name, prefix))
    }) {
        return Err(invalid(
            "unexpected entry in build operation namespace",
        ));
    }
    let boot = boot_id()?;
    let mut report = BuildRecoveryReport::default();
    for name in names {
        let state = match recover_one(&parent, &name, &boot) {
            Ok(state) => state,
            Err(error) => BuildRecoveryState::Retained(error.to_string()),
        };
        report.entries.push(BuildRecoveryEntry {
            operation: name,
            state,
        });
    }
    Ok(report)
}

fn recover_one(
    parent: &OpenedPath,
    name: &str,
    boot: &str,
) -> Result<BuildRecoveryState, BuildError> {
    let directory = directory(parent, name)?;
    if managed::present(&directory)? {
        return recover_managed(parent, name, &directory);
    }
    if !name.starts_with("op-") {
        // init-* has never been launchable. gc-* was durably revoked and renamed
        // only after quiescence. Neither is an accepted service entry path.
        validate_tree(&directory)?;
        remove_tree(parent, name, &directory)?;
        return Ok(BuildRecoveryState::Recovered);
    }
    let Some(_coordinator) = lock_existing(&directory, "lease")? else {
        return Ok(BuildRecoveryState::Active);
    };
    let mut observers = Vec::new();
    for name in ["consumers", "observers"] {
        read(&directory, name, 0)?.ok_or_else(|| invalid("incomplete operation journal"))?;
        let Some(guard) = lock_existing(&directory, name)? else {
            return Ok(BuildRecoveryState::Active);
        };
        observers.push(guard);
    }
    let recorded_boot = validate_identity(parent, &directory, name)?;
    validate_tree(&directory)?;
    let mut gate = lock_existing(&directory, "gate")?;
    if gate.is_none() && recorded_boot == boot {
        // The orphaned service may still be executing. Stop only the uniquely
        // named owned unit; never send signals to a journal PID.
        sandbox::stop_unit(&unit(name));
        gate = lock_existing(&directory, "gate")?;
    }
    let _gate = gate.ok_or_else(|| invalid("service launch gate remains busy"))?;
    write(&directory, "revoked", REVOKED)?;
    if recorded_boot == boot {
        if read(&directory, "authorized", 64)?.is_some()
            && read(&directory, "cleaned", 64)?.is_none()
        {
            sandbox::recover_unit(&unit(name)).map_err(invalid)?;
        }
        prove_empty(&directory, name)?;
    }
    remove_stage(&directory)?;
    let garbage = format!("gc-{}", &name[3..]);
    fd::rename_directory(
        parent.fd(),
        Path::new(name),
        Path::new(&garbage),
        directory.metadata().identity(),
    )?;
    remove_tree(parent, &garbage, &directory)?;
    Ok(BuildRecoveryState::Recovered)
}

fn recover_managed(
    parent: &OpenedPath,
    name: &str,
    directory: &OpenedPath,
) -> Result<BuildRecoveryState, BuildError> {
    if name.starts_with("init-") {
        return Ok(BuildRecoveryState::Retained(
            "managed attempt requires explicit reconciliation".into(),
        ));
    }
    let mut guards = Vec::new();
    for name in [
        "lease",
        "consumers",
        "observers",
        "gate",
    ] {
        let Some(guard) = lock_existing(directory, name)? else {
            return Ok(BuildRecoveryState::Active);
        };
        guards.push(guard);
    }
    let original = format!("op-{}", &name[3..]);
    let recorded_boot = validate_identity(parent, directory, &original)?;
    validate_tree(directory)?;
    if !managed::settled_managed(directory)?
        && (!name.starts_with("op-")
            || !managed::settle_local_awaiting(directory, &unit(&original), &recorded_boot)?)
    {
        return Ok(BuildRecoveryState::Retained(
            "managed attempt requires explicit reconciliation".into(),
        ));
    }
    managed::validate_settled_identity(directory, &unit(&original), &recorded_boot)?;
    remove_stage(directory)?;
    let garbage = format!("gc-{}", &name[3..]);
    if name != garbage {
        fd::rename_directory(
            parent.fd(),
            Path::new(name),
            Path::new(&garbage),
            directory.metadata().identity(),
        )?;
    }
    remove_tree(parent, &garbage, directory)?;
    Ok(BuildRecoveryState::Recovered)
}

/// Host and Managed terminal evidence are distinct; never accept a legacy
/// cleaned marker as a substitute for Managed settlement.
pub(super) fn terminal_settlement(directory: &OpenedPath) -> Result<bool, BuildError> {
    if managed::present(directory)? {
        managed::settled_managed(directory)
    } else {
        Ok(read(directory, "cleaned", 64)?.as_deref() == Some(CLEANED))
    }
}

fn identity(name: &str, boot: &str, parent: FileIdentity, directory: FileIdentity) -> String {
    let fields = format!(
        "syrox-build-operation\n{name}\n{boot}\n{} {}\n{} {}\n",
        parent.device, parent.inode, directory.device, directory.inode
    );
    format!(
        "{fields}sha256 {}\n",
        ContentDigest::sha256(fields.as_bytes())
    )
}

pub(super) fn validate_identity(
    parent: &OpenedPath,
    directory: &OpenedPath,
    name: &str,
) -> Result<String, BuildError> {
    let bytes =
        read(directory, "identity", 1024)?.ok_or_else(|| invalid("operation identity missing"))?;
    let text = std::str::from_utf8(&bytes).map_err(problem)?;
    let boot = text
        .lines()
        .nth(2)
        .filter(|value| valid_boot(value))
        .ok_or_else(|| invalid("invalid operation boot identity"))?;
    if text
        != identity(
            name,
            boot,
            parent.metadata().identity(),
            directory.metadata().identity(),
        )
    {
        return Err(invalid(
            "operation identity or Store namespace changed",
        ));
    }
    Ok(boot.to_owned())
}

fn unit(name: &str) -> String {
    format!("syrox-build-{}.service", &name[3..])
}
pub(super) fn valid_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn valid_boot(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub(super) fn boot_id() -> Result<String, BuildError> {
    let bytes = read_host_file(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(problem)?
        .strip_suffix('\n')
        .filter(|value| valid_boot(value))
        .ok_or_else(|| invalid("kernel boot identity unavailable"))?;
    Ok(text.to_owned())
}
fn valid_group(relative: &str, name: &str) -> bool {
    relative.len() <= 4096
        && relative.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.@:-".contains(&b))
        })
        && relative.ends_with(&format!("/{}", unit(name)))
}

fn open_group(relative: &str) -> Result<Option<OpenedPath>, BuildError> {
    let root = fd::open_top_directory(Path::new("/sys/fs/cgroup")).map_err(problem)?;
    match fd::open_beneath(root.fd(), Path::new(relative), true) {
        Ok(group) => Ok(Some(group)),
        Err(fd::OpenError::Other(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(problem(error)),
    }
}

fn prove_empty(directory: &OpenedPath, name: &str) -> Result<(), BuildError> {
    let Some(bytes) = read(directory, "cgroup", 8192)? else {
        return Ok(());
    };
    let text = std::str::from_utf8(&bytes).map_err(problem)?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 3
        || lines[0] != "syrox-build-cgroup"
        || !text.ends_with('\n')
        || !valid_group(lines[1], name)
    {
        return Err(invalid("invalid cgroup record"));
    }
    let (device, inode) = lines[2]
        .split_once(' ')
        .ok_or_else(|| invalid("invalid cgroup identity"))?;
    let expected = FileIdentity {
        device: device.parse().map_err(problem)?,
        inode: inode.parse().map_err(problem)?,
    };
    if lines[2] != format!("{} {}", expected.device, expected.inode) {
        return Err(invalid("noncanonical cgroup identity"));
    }
    let Some(group) = open_group(lines[1])? else {
        return Ok(());
    };
    let id = group.metadata().identity();
    if id != expected {
        return Err(invalid("cgroup identity changed"));
    }
    let events =
        fd::open_beneath(group.fd(), Path::new("cgroup.events"), false).map_err(problem)?;
    let mut bytes = Vec::new();
    events
        .into_file()
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid("oversized cgroup state"));
    }
    let text = std::str::from_utf8(&bytes).map_err(problem)?;
    let populated: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("populated "))
        .collect();
    if populated != ["populated 0"] {
        return Err(invalid(
            "payload cgroup is still populated or unconfirmed",
        ));
    }
    Ok(())
}

pub(super) fn lock_namespace(parent: &OpenedPath) -> Result<OpenedPath, BuildError> {
    let guard = directory(parent, ".")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !fd::flock(guard.fd(), FlockMode::ExclusiveNonblocking)? {
        if std::time::Instant::now() >= deadline {
            return Err(invalid("build journal namespace is busy"));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Ok(guard)
}
pub(super) fn lock_existing(
    directory: &OpenedPath,
    name: &str,
) -> Result<Option<OpenedPath>, BuildError> {
    let guard = fd::open_existing_regular(directory.fd(), Path::new(name))?;
    if !fd::flock(guard.fd(), FlockMode::ExclusiveNonblocking)? {
        return Ok(None);
    }
    let reopened = fd::open_existing_regular(directory.fd(), Path::new(name))?;
    if reopened.metadata().identity() != guard.metadata().identity() || guard.metadata().size() != 0
    {
        return Err(invalid("operation lock identity changed"));
    }
    Ok(Some(guard))
}
pub(super) fn directory(parent: &OpenedPath, name: &str) -> Result<OpenedPath, BuildError> {
    let opened = fd::open_beneath(parent.fd(), Path::new(name), true).map_err(problem)?;
    validate_operation_directory(&opened)?;
    Ok(opened)
}
fn validate_operation_directory(directory: &OpenedPath) -> Result<(), BuildError> {
    if !directory.metadata().is_trusted_directory() {
        return Err(invalid("untrusted operation directory"));
    }
    Ok(())
}
pub(super) fn read(
    directory: &OpenedPath,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, BuildError> {
    match fd::open_beneath(directory.fd(), Path::new(name), false) {
        Ok(file) => {
            if !file.metadata().is_trusted_regular() {
                return Err(invalid("untrusted operation file"));
            }
            let mut bytes = Vec::new();
            file.into_file()
                .take(maximum as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > maximum {
                return Err(invalid("oversized operation file"));
            }
            Ok(Some(bytes))
        }
        Err(fd::OpenError::Other(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(problem(error)),
    }
}
pub(super) fn write(directory: &OpenedPath, name: &str, bytes: &[u8]) -> Result<(), BuildError> {
    fd::write_atomic_beneath_with_prefix(
        directory.fd(),
        Path::new(name),
        bytes,
        TEMP_PREFIX,
    )
    .map_err(problem)
}
pub(super) fn entries(directory: &OpenedPath, limit: usize) -> Result<Vec<String>, BuildError> {
    let mut count = 0;
    fd::read_directory(directory, |_| {
        count += 1;
        if count > limit {
            Err(())
        } else {
            Ok(())
        }
    })
    .map_err(problem)?
    .into_iter()
    .map(|name| {
        name.into_string()
            .map_err(|_| invalid("non-UTF-8 operation entry"))
    })
    .collect()
}
fn read_host_file(path: &Path, maximum: usize) -> Result<Vec<u8>, BuildError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid("oversized kernel identity"));
    }
    Ok(bytes)
}

fn validate_tree(directory: &OpenedPath) -> Result<(), BuildError> {
    managed::present(directory)?;
    for name in entries(directory, MAX_FILES)? {
        if name == "stage" {
            validate_stage(&self::directory(directory, "stage")?)?;
            continue;
        }
        let limit = match name.as_str() {
            "lease" | "gate" | "consumers" | "observers" => 0,
            "identity" => 1024,
            "action" => 256,
            "managed-attempt" | "managed-settled" => managed::LIMIT as u64,
            "origin" => 64 * 1024,
            "authorized" | "revoked" | "cleaned" | "closing" => 64,
            "cgroup" => 8192,
            "log" => 16 * 1024,
            "outcome" => 4096,
            name if valid_name(name, TEMP_PREFIX) => 16 * 1024,
            _ => return Err(invalid("unexpected operation file")),
        };
        let file = fd::open_existing_regular(directory.fd(), Path::new(&name))?;
        if file.metadata().size() > limit {
            return Err(invalid("oversized operation record"));
        }
    }
    for (name, expected) in [
        ("authorized", AUTHORIZED),
        ("revoked", REVOKED),
        ("cleaned", CLEANED),
        ("closing", super::shared::CLOSING),
    ] {
        if let Some(bytes) = read(directory, name, 64)?
            && bytes != expected
        {
            return Err(invalid("malformed operation state marker"));
        }
    }
    Ok(())
}
fn validate_stage(stage: &OpenedPath) -> Result<(), BuildError> {
    for name in entries(stage, MAX_FILES)? {
        let limit = match name.as_str() {
            "source" => super::MAX_LARGE_SOURCE_BYTES,
            "build-action" => super::records::MAX_RECORD_BYTES,
            "build-program" => super::MAX_BUILD_PROGRAM_BYTES as u64,
            "worker" => 128 * 1024 * 1024,
            "seccomp" => 16 * 1024,
            name if valid_name(name, TEMP_PREFIX) => 128 * 1024 * 1024,
            _ => return Err(invalid("unexpected staging file")),
        };
        let file = fd::open_existing_regular(stage.fd(), Path::new(&name))?;
        if file.metadata().size() > limit {
            return Err(invalid("oversized staging file"));
        }
    }
    Ok(())
}
fn remove_stage(directory: &OpenedPath) -> Result<(), BuildError> {
    let stage = match fd::open_beneath(directory.fd(), Path::new("stage"), true) {
        Ok(stage) => stage,
        Err(fd::OpenError::Other(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(problem(error)),
    };
    validate_operation_directory(&stage)?;
    validate_stage(&stage)?;
    remove_files(&stage)?;
    fd::remove_directory(
        directory.fd(),
        Path::new("stage"),
        stage.metadata().identity(),
    )?;
    Ok(())
}
fn remove_files(directory: &OpenedPath) -> Result<(), BuildError> {
    for name in entries(directory, MAX_FILES)? {
        let file = fd::open_existing_regular(directory.fd(), Path::new(&name))?;
        fd::unlink_opened(
            directory.fd(),
            Path::new(&name),
            file.metadata().identity(),
        )?;
    }
    fd::sync_directory(directory.fd())?;
    Ok(())
}
fn remove_tree(parent: &OpenedPath, name: &str, directory: &OpenedPath) -> Result<(), BuildError> {
    remove_stage(directory)?;
    remove_files(directory)?;
    fd::remove_directory(
        parent.fd(),
        Path::new(name),
        directory.metadata().identity(),
    )?;
    Ok(())
}
fn invalid(reason: &str) -> BuildError {
    BuildError::Journal(reason.to_owned())
}
fn problem(error: impl std::fmt::Debug) -> BuildError {
    invalid(&format!("{error:?}"))
}

#[cfg(test)]
mod tests;
