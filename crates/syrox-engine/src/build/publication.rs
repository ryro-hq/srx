//! Admissão dos outputs depois de encerrar a execução do build.
//!
//! O chamador precisa ter conferido o settlement antes de chegar aqui. Este
//! helper valida e publica os arquivos; a prova de fechamento fica com o backend.

use std::collections::BTreeMap;
use std::fs::File;

use super::bootstrap::group;
use super::cancellation::BuildControl;
use super::records::{Action, Receipt};
use super::{BuildError, BuildExecution, BuildProfile, BuildResult};
use crate::store::ContentDigest;

pub(super) fn publish_outputs(
    lease: &crate::store::OperationLease,
    operation: &str,
    action: &Action,
    inventory: Option<&[u8]>,
    framed: &mut File,
    retained_inputs: &[ContentDigest],
    cancellation: &dyn BuildControl,
) -> Result<BuildResult, BuildError> {
    cancellation.check()?;
    match (
        action.program.profile,
        action.toolchain,
        inventory,
    ) {
        (BuildProfile::HostBootstrap, Some(pin), Some(bytes)) => {
            if ContentDigest::sha256(bytes) != pin {
                return Err(BuildError::InputChanged);
            }
        }
        (BuildProfile::Managed, None, None) => {}
        _ => return Err(BuildError::UnsupportedProfile),
    }
    // Validate the declared closure before staging output bytes. The placeholder
    // output digest does not claim admission and never escapes this preflight.
    Receipt::new(action, ContentDigest::sha256(b""), 0)
        .with_inputs(action, retained_inputs.to_vec())?;
    let entries = action
        .program
        .outputs
        .iter()
        .map(|name| (name.clone(), String::new()))
        .collect::<BTreeMap<_, _>>();
    let mut outputs = group::unpack(framed, &entries, lease, cancellation)?;
    let primary = outputs.remove("out").ok_or(BuildError::Output)?;
    if primary.size > action.program.resources.envelope().output_bytes
        || outputs
            .values()
            .any(|output| output.size > action.program.resources.envelope().output_bytes)
    {
        return Err(BuildError::Output);
    }
    let mut receipt_description = Receipt::new(action, primary.digest, primary.files);
    if !outputs.is_empty() {
        let named = outputs
            .iter()
            .map(|(name, output)| (name.clone(), group::named_output(output)))
            .collect();
        receipt_description = receipt_description.with_outputs(action, named)?;
    }
    if !retained_inputs.is_empty() {
        receipt_description = receipt_description.with_inputs(action, retained_inputs.to_vec())?;
    }
    let action_bytes = action.encode();
    let receipt_bytes = receipt_description.encode();
    let root = receipt_description.root();
    let mut objects = vec![
        (action_bytes.as_slice(), action.digest()),
        (
            receipt_bytes.as_slice(),
            receipt_description.digest(),
        ),
    ];
    if let (Some(bytes), Some(pin)) = (inventory, action.toolchain) {
        objects.insert(0, (bytes, pin));
    }
    let artifacts = std::iter::once(primary)
        .chain(outputs.into_values())
        .collect::<Vec<_>>();
    super::bootstrap::linux::publish_result(
        lease,
        &root,
        &receipt_description.references(),
        &objects,
        artifacts,
        cancellation,
    )?;
    let retention = lease
        .retain_objects(&receipt_description.references(), &[])
        .map_err(|source| BuildError::PublishedAndRetention {
            root: root.clone(),
            source,
        })?;
    Ok(BuildResult {
        retention,
        execution: BuildExecution::Built {
            operation: operation.to_owned(),
        },
        action: action.digest(),
        artifact: receipt_description
            .output("out")
            .expect("primary output")
            .artifact,
        receipt: receipt_description.digest(),
        toolchain: action.toolchain,
        files: receipt_description
            .output("out")
            .expect("primary output")
            .files,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::{Action, BuildError, BuildProfile, ContentDigest, Receipt, publish_outputs};
    use crate::build::records::InputIdentity;
    use crate::build::{
        BuildPath, BuildProgram, BuildResources, BuildSourceFormat, BuildStep, bootstrap::group,
    };
    use crate::result::artifact;
    use crate::{cancellation::Cancellation, store::Store};
    use std::fs::File;
    use std::io::{Seek as _, Write as _};

    fn action(profile: BuildProfile, inventory: Option<&[u8]>) -> Action {
        Action {
            program: BuildProgram {
                profile,
                resources: BuildResources::Standard,
                source_format: BuildSourceFormat::Raw,
                outputs: vec!["dev".into(), "out".into()],
                steps: vec![BuildStep::Directory(BuildPath::Work(
                    "work".into(),
                ))],
            },
            source: ContentDigest::sha256(b"source"),
            toolchain: inventory.map(ContentDigest::sha256),
            worker: ContentDigest::sha256(b"worker"),
            directory: "source".into(),
            inputs: Vec::new(),
        }
    }

    fn frame(root: &std::path::Path) -> (File, Vec<ContentDigest>) {
        let mut digests = Vec::new();
        for (name, contents) in [
            ("out", b"runtime bytes".as_slice()),
            ("dev", b"header bytes"),
        ] {
            let directory = root.join(name);
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("data"), contents).unwrap();
            let mut bytes = Vec::new();
            artifact::pack(&directory, &mut bytes).unwrap();
            digests.push(ContentDigest::sha256(&bytes));
        }
        let mut file = tempfile::tempfile().unwrap();
        group::pack(
            &[
                ("out", &root.join("out")),
                ("dev", &root.join("dev")),
            ],
            &mut file,
        )
        .unwrap();
        file.rewind().unwrap();
        (file, digests)
    }

    #[test]
    fn both_profiles_publish_named_outputs_with_only_their_declared_inventory() {
        for profile in [
            BuildProfile::HostBootstrap,
            BuildProfile::Managed,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::initialize(&directory.path().join("store")).unwrap();
            let lease = store.operation().unwrap();
            let inventory = (profile == BuildProfile::HostBootstrap)
                .then_some(b"observed inventory".as_slice());
            let action = action(profile, inventory);
            lease
                .ingest(b"source".as_slice(), action.source, 6)
                .unwrap();
            let (mut framed, artifacts) = frame(directory.path());
            let cancel = Cancellation::default();
            let result = publish_outputs(
                &lease,
                "settled-fixture",
                &action,
                inventory,
                &mut framed,
                &[],
                &cancel,
            )
            .unwrap();
            assert_eq!(result.toolchain, action.toolchain);
            assert_eq!(result.artifact, artifacts[0]);
            let bytes = lease
                .read_verified(result.receipt, 1024 * 1024)
                .unwrap()
                .unwrap();
            let receipt = Receipt::parse(bytes.as_bytes()).unwrap();
            assert_eq!(receipt.toolchain, action.toolchain);
            assert_eq!(
                receipt.output("dev").unwrap().artifact,
                artifacts[1]
            );
            assert!(receipt.matches_action(&action));
            receipt
                .verify_inputs(&lease, &action, &cancel)
                .unwrap();
            receipt
                .verify_retained_inputs(&lease, &action, || Ok(()))
                .unwrap();
            let references = lease
                .build_references(&result.root)
                .unwrap()
                .unwrap();
            assert_eq!(references, receipt.references());
            assert_eq!(
                references.contains(&ContentDigest::sha256(b"observed inventory")),
                inventory.is_some()
            );
            assert_eq!(
                references.len(),
                if inventory.is_some() {
                    6
                } else {
                    5
                }
            );
            for digest in artifacts {
                assert!(lease.verify(digest).unwrap().is_some());
            }
        }
    }

    #[test]
    fn profile_inventory_mismatches_fail_before_consuming_or_publishing_artifacts() {
        let cases = [
            (BuildProfile::HostBootstrap, None, None),
            (
                BuildProfile::HostBootstrap,
                Some(b"pin".as_slice()),
                None,
            ),
            (
                BuildProfile::HostBootstrap,
                None,
                Some(b"pin".as_slice()),
            ),
            (
                BuildProfile::HostBootstrap,
                Some(b"pin".as_slice()),
                Some(b"wrong".as_slice()),
            ),
            (
                BuildProfile::Managed,
                Some(b"pin".as_slice()),
                Some(b"pin".as_slice()),
            ),
            (
                BuildProfile::Managed,
                None,
                Some(b"pin".as_slice()),
            ),
            (
                BuildProfile::Managed,
                Some(b"pin".as_slice()),
                None,
            ),
        ];
        for (profile, pin, supplied) in cases {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::initialize(&directory.path().join("store")).unwrap();
            let lease = store.operation().unwrap();
            let action = action(profile, pin);
            let (mut framed, artifacts) = frame(directory.path());
            let error = publish_outputs(
                &lease,
                "fixture",
                &action,
                supplied,
                &mut framed,
                &[],
                &Cancellation::default(),
            )
            .unwrap_err();
            assert!(matches!(
                error,
                BuildError::UnsupportedProfile | BuildError::InputChanged
            ));
            assert_eq!(framed.stream_position().unwrap(), 0);
            assert!(lease.verify(action.digest()).unwrap().is_none());
            for digest in artifacts {
                assert!(lease.verify(digest).unwrap().is_none());
            }
        }
    }

    #[test]
    fn omitted_retained_input_closure_fails_before_reading_output() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(&directory.path().join("store")).unwrap();
        let lease = store.operation().unwrap();
        let mut action = action(BuildProfile::Managed, None);
        action.inputs.push(InputIdentity {
            origin: crate::result::OutputOrigin::Built {
                receipt: ContentDigest::sha256(b"provider-receipt"),
            },
            action: ContentDigest::sha256(b"provider-action"),
            artifact: ContentDigest::sha256(b"provider-artifact"),
            output: "out".into(),
        });
        let mut framed = tempfile::tempfile().unwrap();
        framed.write_all(b"not a group").unwrap();
        framed.rewind().unwrap();
        assert!(
            publish_outputs(
                &lease,
                "fixture",
                &action,
                None,
                &mut framed,
                &[],
                &Cancellation::default()
            )
            .is_err()
        );
        assert_eq!(framed.stream_position().unwrap(), 0);
        assert!(lease.verify(action.digest()).unwrap().is_none());
    }

    #[test]
    fn published_cached_and_materialized_handles_keep_continuous_granular_custody() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(&directory.path().join("store")).unwrap();
        let lease = store.operation().unwrap();
        let action = action(BuildProfile::Managed, None);
        lease
            .ingest(b"source".as_slice(), action.source, 6)
            .unwrap();
        let garbage = ContentDigest::sha256(b"unrelated garbage");
        lease
            .ingest(b"unrelated garbage".as_slice(), garbage, 17)
            .unwrap();
        let (mut framed, _) = frame(directory.path());
        let cancellation = Cancellation::default();
        let result = publish_outputs(
            &lease,
            "settled-fixture",
            &action,
            None,
            &mut framed,
            &[],
            &cancellation,
        )
        .unwrap();
        let clone = result.clone();
        let root = result.root.clone();
        let artifact = result.artifact;
        let references = lease.build_references(&root).unwrap().unwrap();
        drop(lease);
        drop(result);
        let collect = |remove_roots| {
            store
                .maintenance()
                .unwrap()
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    remove_roots,
                    ..crate::store::GcRequest::default()
                })
                .unwrap()
        };
        assert_eq!(
            collect(vec![root.clone()]).removed_objects,
            [garbage]
        );
        let lease = store.operation().unwrap();
        lease.publish_root(&root, &references).unwrap();
        super::super::cache::record(&lease, &action, &clone).unwrap();
        let cached = super::super::cache::lookup(&lease, &action, None, &cancellation)
            .unwrap()
            .unwrap();
        drop(lease);
        drop(clone);
        assert!(
            collect(vec![root.clone()])
                .removed_objects
                .is_empty()
        );
        let lease = store.operation().unwrap();
        lease.publish_root(&root, &references).unwrap();
        let view = crate::result::materialize_artifact(&store, &root, cached.receipt).unwrap();
        drop(lease);
        drop(cached);
        assert!(collect(vec![root]).removed_objects.is_empty());
        drop(view);
        let report = collect(Vec::new());
        assert!(report.removed_objects.contains(&artifact));
        assert!(
            references
                .iter()
                .all(|pin| report.removed_objects.contains(pin))
        );
    }
}
