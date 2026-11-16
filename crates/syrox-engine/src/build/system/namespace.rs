//! A System namespace held at a closed local gate with both helper roots alive.
//!
//! This is mount/content preparation, not manager admission or a build receipt.
//! The coordinator must retain the helper control lease outside the user
//! namespace and settle this namespace before releasing either loop filesystem.

use super::{BuildError, SystemBuildAction, SystemBuildInputResources, SystemBuildWorkspace};
use crate::{
    build::managed::namespace::{NamespaceLayout, NamespaceMount},
    cancellation::Cancellation,
    execution::native::build::{NamespaceResources, PreparedNamespace},
    store::ContentDigest,
    system::{
        budget::{BuildBudget, BuilderLimits},
        workspace::{ReceivedWorkspace, WorkspaceObservation},
    },
};
use std::{
    fs::File,
    io,
    os::fd::{AsFd as _, AsRawFd, BorrowedFd, OwnedFd},
    path::Path,
    time::Instant,
};

mod record;
pub use record::run_payload;
#[cfg(test)]
pub(super) use record::test_record;
mod snapshot;

// Includes stdio, fixed immutable files, the two roots, native gate/capture/
// diagnostic/signal channels and verification's one-group temporary readers.
// The input resource reader charges its own artifact-group descriptor copies.
const EXECUTOR_RESERVE: u32 = 64;

pub struct SystemBuildNamespaceResources<'a> {
    action: SystemBuildAction,
    evidence: SystemBuildInputResources,
    fixed: Vec<OwnedFd>,
    scratch: File,
    output: File,
    observation: WorkspaceObservation,
    record: ContentDigest,
    _snapshots: tempfile::TempDir,
    _custody: std::marker::PhantomData<&'a SystemBuildWorkspace<'a>>,
}

impl std::fmt::Debug for SystemBuildNamespaceResources<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemBuildNamespaceResources")
            .field("action", &self.action.digest())
            .finish_non_exhaustive()
    }
}

/// Owns namespace init before any of its resource descriptions can be dropped.
/// No public method grants execution authority or releases its local gate.
pub struct PreparedSystemBuildNamespace<'a> {
    native: PreparedNamespace,
    resources: SystemBuildNamespaceResources<'a>,
}
impl std::fmt::Debug for PreparedSystemBuildNamespace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSystemBuildNamespace")
            .field("action", &self.action_digest())
            .finish_non_exhaustive()
    }
}
impl PreparedSystemBuildNamespace<'_> {
    pub fn action_digest(&self) -> ContentDigest {
        self.resources.action.digest()
    }
    pub fn namespace_pidfd(&self) -> BorrowedFd<'_> {
        self.native.pidfd()
    }
}

impl SystemBuildWorkspace<'_> {
    /// Validate source/input custody and the authenticated role observations,
    /// then capture immutable namespace resources. No mount, process, manager
    /// admission or journal attempt starts. The helper control lease stays here;
    /// only data/root descriptions belong in the dedicated namespace monitor.
    pub fn prepare_namespace_resources(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemBuildNamespaceResources<'_>, BuildError> {
        super::scratch::check(cancellation, deadline)?;
        let inputs = self.inputs();
        let (scratch, output) = self.root_descriptors(cancellation, deadline)?;
        let evidence = inputs
            .prepare_input_resources(EXECUTOR_RESERVE, cancellation)?
            .into_namespace_receiver(cancellation)?;
        let record = record::Record::new(inputs, *self.observation());
        let record_bytes = record.encode()?;
        let snapshots = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let mut fixed = Vec::new();
        for (name, bytes, mode) in [
            ("action", inputs.action.encode(), 0o400),
            ("program", inputs.action.program().encode(), 0o400),
        ] {
            fixed.push(snapshot::bytes(snapshots.path(), name, &bytes, mode, cancellation)?.into());
        }
        fixed.push(inputs.source.duplicate_readonly_descriptor()?);
        fixed.push(
            snapshot::bytes(
                snapshots.path(),
                "worker",
                &inputs.worker,
                0o500,
                cancellation,
            )?
            .into(),
        );
        fixed.push(
            snapshot::bytes(
                snapshots.path(),
                "policy",
                &record_bytes,
                0o400,
                cancellation,
            )?
            .into(),
        );
        let resources = SystemBuildNamespaceResources {
            action: inputs.action.clone(),
            evidence,
            fixed,
            scratch,
            output,
            observation: *self.observation(),
            record: ContentDigest::sha256(&record_bytes),
            _snapshots: snapshots,
            _custody: std::marker::PhantomData,
        };
        layout(&inputs.action)?;
        super::scratch::check(cancellation, deadline)?;
        Ok(resources)
    }
}

impl<'a> SystemBuildNamespaceResources<'a> {
    /// Exact readonly data/root descriptions needed by a dedicated monitor.
    /// A caller arranging fork/exec must close every other inherited descriptor;
    /// this list conveys no journal, manager or helper control authorization.
    pub fn data_descriptors(&self) -> Vec<BorrowedFd<'_>> {
        self.fixed
            .iter()
            .chain(self.evidence.descriptors())
            .map(|fd| fd.as_fd())
            .chain([
                self.scratch.as_fd(),
                self.output.as_fd(),
            ])
            .collect()
    }
    /// Prepare readonly input binds and the private scratch/output mounts at a
    /// closed local gate. This does not authorize recipe execution.
    ///
    /// # Safety
    /// Dedicated single-threaded non-root monitor only; exit after return/error.
    /// Changes the monitor's user namespace and forks PID/mount namespaces.
    /// Closes every fd>=3 outside `data_descriptors` before changing namespaces.
    /// Caller retains helper control in the original coordinator. Never access
    /// or drop other inherited Rust descriptor owners after this call, including
    /// errors: terminate via process exit. Custody stays live until settlement.
    #[allow(unsafe_code)]
    pub unsafe fn prepare_namespace(
        self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<PreparedSystemBuildNamespace<'a>, BuildError> {
        super::scratch::check(cancellation, deadline)?;
        self.evidence.revalidate(cancellation)?;
        snapshot::verify(
            &self.fixed[2],
            self.action.source_digest(),
            self.action.source_limit(),
            cancellation,
        )?;
        ReceivedWorkspace::from_authorized_roots(
            &self.action.workspace_layout()?,
            &self.observation,
            self.scratch.try_clone()?,
            self.output.try_clone()?,
        )?
        .revalidate()?;
        let layout = layout(&self.action)?;
        let kept: Vec<_> = self
            .data_descriptors()
            .iter()
            .map(AsRawFd::as_raw_fd)
            .collect();
        crate::execution::native::close_inherited_descriptors(&kept)?;
        // SAFETY: caller guarantees dedicated lifecycle and namespace fork safety.
        let native = unsafe {
            crate::execution::native::build::prepare(&layout, &self, cancellation, deadline)
        }?;
        Ok(PreparedSystemBuildNamespace {
            native,
            resources: self,
        })
    }
}

fn layout(action: &SystemBuildAction) -> Result<NamespaceLayout, BuildError> {
    let mut mounts: Vec<_> = [
        "/build-action",
        "/build-program",
        "/source",
        "/syrox-worker",
        "/build-system-policy",
    ]
    .into_iter()
    .enumerate()
    .map(|(slot, target)| NamespaceMount {
        slot,
        target: target.into(),
        directory: false,
    })
    .collect();
    let mut unique = std::collections::BTreeMap::new();
    for (index, input) in action.selected_inputs().iter().enumerate() {
        let target = format!("/syrox/store/{}/{}", input.action, input.output);
        if let Some(previous) = unique.insert(target.clone(), input) {
            if previous != input {
                return Err(BuildError::InputChanged);
            }
            continue;
        }
        mounts.push(NamespaceMount {
            slot: 5 + index,
            target,
            directory: true,
        });
    }
    Ok(NamespaceLayout {
        source_directory: action.source_directory().into(),
        action: action.digest(),
        mounts,
        work_bytes: action.budget().request().scratch_bytes,
        output_bytes: action.budget().request().output_bytes,
        output_parent: format!("/out/syrox/store/{}", action.digest()),
        outputs: action.program().outputs.clone(),
    })
}

impl NamespaceResources for SystemBuildNamespaceResources<'_> {
    fn descriptor(&self, slot: usize) -> io::Result<BorrowedFd<'_>> {
        if slot < 5 {
            self.fixed
                .get(slot)
                .map(|fd| fd.as_fd())
                .ok_or_else(|| io::Error::other("invalid System fixed role"))
        } else {
            self.evidence
                .mount_descriptor(slot - 5)
                .map_err(io::Error::other)
        }
    }
    fn verify_inputs(&self, cancellation: &Cancellation, deadline: Instant) -> io::Result<()> {
        super::scratch::check_io(cancellation, deadline)?;
        for (slot, digest, maximum) in [
            (
                0,
                self.action.digest(),
                2 * crate::build::MAX_BUILD_PROGRAM_BYTES as u64 + 64 * 1024,
            ),
            (
                1,
                ContentDigest::sha256(&self.action.program().encode()),
                crate::build::MAX_BUILD_PROGRAM_BYTES as u64,
            ),
            (
                2,
                self.action.source_digest(),
                self.action.source_limit(),
            ),
            (3, self.action.worker_digest(), 128 * 1024 * 1024),
            (4, self.record, 8192),
        ] {
            snapshot::verify(&self.fixed[slot], digest, maximum, cancellation)
                .map_err(io::Error::other)?;
        }
        self.evidence
            .verify_namespace_inputs(cancellation)
            .map_err(io::Error::other)?;
        super::scratch::check_io(cancellation, deadline)
    }
    fn payload_arguments(&self, _: &NamespaceLayout) -> Vec<String> {
        vec![
            "__build-system-worker".into(),
            self.action.digest().to_string(),
            self.record.to_string(),
        ]
    }
    #[allow(unsafe_code)]
    fn install_workspace(
        &self,
        root: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> io::Result<bool> {
        let workspace = ReceivedWorkspace::from_authorized_roots(
            &self
                .action
                .workspace_layout()
                .map_err(io::Error::other)?,
            &self.observation,
            self.scratch.try_clone()?,
            self.output.try_clone()?,
        )?;
        for name in ["work", "out", "tmp"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(name))?;
        }
        // SAFETY: reachable only from native::build::prepare's dedicated init in
        // its freshly cloned private user/mount namespace. Errors discard init.
        let attached = unsafe {
            workspace.attach(
                File::open(root.join("work"))?,
                File::open(root.join("out"))?,
                || super::scratch::check_io(cancellation, deadline),
            )
        }?;
        attached.revalidate()?;
        let temporary = root.join("work/.syrox-tmp");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&temporary)?;
        // A bind within scratch charges the same byte/inode ceiling. Never add
        // a third writable tmpfs or expose an existing host temporary directory.
        crate::execution::native::mount(
            Some(&temporary),
            &root.join("tmp"),
            None,
            libc::MS_BIND,
        )?;
        super::scratch::check_io(cancellation, deadline)?;
        Ok(true)
    }
}

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

#[cfg(test)]
mod tests;
