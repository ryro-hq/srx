use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::time::Instant;

use super::{BuildError, records::Action, retention_protocol::ManagedBuildRetentionPublished};
use crate::{cancellation::Cancellation, store::ContentDigest};

#[derive(Debug)]
pub(crate) struct NamespaceMount {
    pub slot: usize,
    pub target: String,
    pub directory: bool,
}
#[derive(Debug)]
pub(crate) struct NamespaceLayout {
    pub source_directory: String,
    pub action: ContentDigest,
    pub mounts: Vec<NamespaceMount>,
    pub work_bytes: u64,
    pub output_bytes: u64,
    pub output_parent: String,
    pub outputs: Vec<String>,
}
impl NamespaceLayout {
    fn from_action(action: &Action) -> Result<Self, BuildError> {
        let mut mounts = vec![];
        for (slot, target) in [
            (0, "/build-action"),
            (1, "/build-program"),
            (2, "/source"),
            (3, "/syrox-worker"),
        ] {
            mounts.push(NamespaceMount {
                slot,
                target: target.into(),
                directory: false,
            });
        }
        let mut unique = BTreeMap::new();
        for (index, input) in action.inputs.iter().enumerate() {
            let target = format!("/syrox/store/{}/{}", input.action, input.output);
            if let Some(previous) = unique.insert(target.clone(), input) {
                if previous != input {
                    return Err(BuildError::InputChanged);
                }
                continue;
            }
            mounts.push(NamespaceMount {
                slot: 4 + 2 * index,
                target,
                directory: true,
            });
        }
        let limits = action.program.resources.envelope();
        Ok(Self {
            source_directory: action.directory.clone(),
            action: action.digest(),
            mounts,
            work_bytes: limits.work_tmpfs,
            output_bytes: limits.output_tmpfs,
            output_parent: format!("/out/syrox/store/{}", action.digest()),
            outputs: action.program.outputs.clone(),
        })
    }
}
/// Owns and settles namespace PID 1 before its borrowed resource publisher can
/// disappear. There is deliberately no method authorizing or executing payloads.
pub struct PreparedManagedBuildNamespace<'a> {
    native: crate::execution::native::build::PreparedNamespace,
    pub(in crate::build) published: &'a ManagedBuildRetentionPublished,
    action: ContentDigest,
}
impl std::fmt::Debug for PreparedManagedBuildNamespace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedManagedBuildNamespace")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}
impl PreparedManagedBuildNamespace<'_> {
    pub(in crate::build) fn check_stop(
        &self,
        cancellation: &Cancellation,
    ) -> Result<(), BuildError> {
        if self.native.check_stop()? {
            cancellation.cancel();
        }
        Ok(cancellation.check()?)
    }
    pub(in crate::build) fn release_gate(
        &mut self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        self.check_stop(cancellation)?;
        Ok(self.native.release_gate(cancellation, deadline)?)
    }
    pub(in crate::build) fn await_exec(
        &mut self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        self.check_stop(cancellation)?;
        Ok(self.native.await_exec(cancellation, deadline)?)
    }
    pub(in crate::build) fn try_wait(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, BuildError> {
        Ok(self.native.try_wait()?)
    }
    pub(in crate::build) fn take_capture(
        &mut self,
    ) -> Result<crate::execution::native::build::BuildCapture, BuildError> {
        Ok(self.native.take_capture()?)
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.action
    }
    /// Pin of the prepared namespace init; it conveys no journal authorization.
    pub fn namespace_pidfd(&self) -> BorrowedFd<'_> {
        self.native.pidfd()
    }
}
/// Prepare mounts and wait at a closed, non-executing gate. Notification barrier
/// processing is not proof of coordinator confirmation or FDSTORE admission.
///
/// # Safety
/// Only a dedicated single-threaded worker may call this function. It changes
/// the calling thread's user namespace and must not return to general app work.
#[allow(unsafe_code)]
pub unsafe fn prepare_managed_build_namespace<'a>(
    published: &'a ManagedBuildRetentionPublished,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<PreparedManagedBuildNamespace<'a>, BuildError> {
    published.revalidate(cancellation, deadline)?;
    let resources = published.resources();
    let action = resources.namespace_action(cancellation, deadline)?;
    let layout = NamespaceLayout::from_action(&action)?;
    // SAFETY: caller guarantees the dedicated worker lifecycle and fork safety.
    let native = unsafe {
        crate::execution::native::build::prepare(&layout, resources, cancellation, deadline)
    }
    .map_err(|error| {
        if crate::cancellation::is_cancellation_io(&error) {
            BuildError::Cancelled
        } else {
            BuildError::Io(error)
        }
    })?;
    Ok(PreparedManagedBuildNamespace {
        native,
        published,
        action: action.digest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{
        BuildPath, BuildProfile, BuildProgram, BuildResources, BuildSourceFormat, BuildStep,
        records::InputIdentity,
    };
    fn action() -> Action {
        Action {
            program: BuildProgram {
                profile: BuildProfile::Managed,
                resources: BuildResources::Standard,
                source_format: BuildSourceFormat::Raw,
                outputs: vec!["out".into()],
                steps: vec![BuildStep::Directory(BuildPath::Work(
                    "data".into(),
                ))],
            },
            source: ContentDigest::sha256(b"source"),
            toolchain: None,
            worker: ContentDigest::sha256(b"worker"),
            directory: "source-1".into(),
            inputs: vec![InputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: ContentDigest::sha256(b"receipt"),
                },
                action: ContentDigest::sha256(b"producer"),
                artifact: ContentDigest::sha256(b"artifact"),
                output: "out".into(),
            }],
        }
    }
    #[test]
    fn layout_uses_only_pinned_slots_and_explicit_writable_roots() {
        let action = action();
        let layout = NamespaceLayout::from_action(&action).unwrap();
        assert_eq!(layout.mounts.len(), 5);
        assert_eq!(layout.mounts[0].target, "/build-action");
        assert_eq!(layout.mounts[3].target, "/syrox-worker");
        assert_eq!(layout.mounts[4].slot, 4);
        assert_eq!(
            layout.mounts[4].target,
            format!("/syrox/store/{}/out", action.inputs[0].action)
        );
        assert!(layout.mounts[4].directory);
        assert!(
            layout
                .mounts
                .iter()
                .all(|entry| !entry.target.starts_with("/usr"))
        );
        assert_eq!(
            layout.work_bytes,
            BuildResources::Standard.envelope().work_tmpfs
        );
        assert_eq!(
            layout.output_bytes,
            BuildResources::Standard.envelope().output_tmpfs
        );
        assert_eq!(
            layout.output_parent,
            format!("/out/syrox/store/{}", action.digest())
        );
    }
    #[test]
    fn aliases_share_one_mount_but_conflicting_selected_identity_is_rejected() {
        let mut action = action();
        action.inputs.push(action.inputs[0].clone());
        assert_eq!(
            NamespaceLayout::from_action(&action)
                .unwrap()
                .mounts
                .len(),
            5
        );
        action.inputs[1].artifact = ContentDigest::sha256(b"different");
        assert!(NamespaceLayout::from_action(&action).is_err());
    }
    #[test]
    fn large_profile_uses_its_authenticated_limits() {
        let mut action = action();
        action.program.resources = BuildResources::Large;
        let layout = NamespaceLayout::from_action(&action).unwrap();
        assert_eq!(
            layout.work_bytes,
            BuildResources::Large.envelope().work_tmpfs
        );
        assert_eq!(
            layout.output_bytes,
            BuildResources::Large.envelope().output_tmpfs
        );
    }
}
