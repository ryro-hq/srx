use super::{RealizeContext, RealizeOptions};
#[cfg(test)]
use crate::config::UserConfiguration;
#[cfg(test)]
use std::path::Path;

use crate::{
    build::BuildResult, cancellation::Cancellation, plan::PlanImportedResult, plan::PlanOutputRef,
    project::PreparedPlan, realize::BuildProgress, realize::RealizeError, realize::ResolvedBuild,
    result::AdmittedResult, result::MaterializationError, result::MaterializedArtifact,
    result::RetainedOutput, store::Store,
};

#[cfg(test)]
mod imported_tests {
    use super::*;
    use crate::{
        project::AuthenticatedStandardLibrary, project::CheckConfiguration, store::ContentDigest,
        store::RootName,
    };
    use std::fs;

    fn admitted(store: &Store) -> ContentDigest {
        let path = b"bin/cc";
        let content = crate::runtime::tests::elf(2, None, &[], None, None);
        let mut bytes = crate::result::artifact::HEADER.to_vec();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(path);
        bytes.push(1);
        bytes.extend_from_slice(&(content.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&content);
        let artifact = ContentDigest::sha256(&bytes);
        store
            .operation()
            .unwrap()
            .ingest(bytes.as_slice(), artifact, bytes.len() as u64)
            .unwrap();
        let action = ContentDigest::sha256(b"opaque imported action, no build record");
        let manifest = crate::result::ResultManifest::parse(format!(
            "syrox-result-v2\n{{\"outputs\":{{\"compiler\":{{\"action\":\"{action}\",\"output\":\"out\",\"artifact\":\"{artifact}\",\"files\":1}}}},\"commands\":{{}}}}\n"
        ).as_bytes()).unwrap();
        let pin = manifest.digest().unwrap();
        crate::result::admit_result(
            store,
            &RootName::new("bootstrap").unwrap(),
            &manifest,
            pin,
            &Cancellation::default(),
        )
        .unwrap();
        assert!(
            store
                .operation()
                .unwrap()
                .verify(action)
                .unwrap()
                .is_none()
        );
        pin
    }

    fn prepared(project: &Path, pin: ContentDigest, output: &str, key: &str) -> PreparedPlan {
        fs::create_dir_all(project).unwrap();
        fs::write(project.join("main.srx"), format!(r#"
            fn tool() -> std::Recipe {{ std::Recipe {{
                package = std::Package {{ id = "offline-tool"; dependencies = []; }};
                imported = std::Option::Some(std::ImportedResult {{ root = "bootstrap"; manifest = "{pin}";
                    entries = [std::ImportedOutput {{ output = "{output}"; key = "{key}"; }}]; }});
                commands = [std::Command {{ name = "cc"; output = "{output}"; path = "bin/cc"; }}];
            }} }}
            outputs {{
                shell: std::Shell = std::Shell {{ pkgs = [std::select_command(std::recipe_ref(tool), "{output}", "cc")]; services = []; }};
            }}
        "#)).unwrap();
        let checks = CheckConfiguration {
            standard_library: Some(AuthenticatedStandardLibrary::bundled()),
            ..CheckConfiguration::default()
        };
        crate::project::lock_project_with(project, &checks).unwrap();
        crate::project::prepare_project_consumer_with(project, &checks, "shell").unwrap()
    }

    #[test]
    fn imported_output_command_and_consumer_need_no_build_worker_or_sources() {
        let temp = tempfile::tempdir().unwrap();
        let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
        let store = Store::initialize(user.store()).unwrap();
        let pin = admitted(&store);
        let project = temp.path().join("project");
        let plan = prepared(&project, pin, "out", "compiler");
        assert_eq!(plan.plan().builds().len(), 0);
        let package = plan
            .plan()
            .imports()
            .next()
            .unwrap()
            .package()
            .clone();
        let reference = PlanOutputRef {
            package: package.clone(),
            output: "out".into(),
        };
        let output = resolve_plan_output(&plan, &reference).unwrap();
        assert!(output.build().is_none());
        let command = crate::realize::resolve_plan_command(
            &plan,
            &crate::plan::PlanCommandRef {
                package,
                name: "cc".into(),
            },
        )
        .unwrap();
        fs::remove_dir_all(project).unwrap();
        let cancellation = Cancellation::default();
        let nonexistent_worker = temp.path().join("worker-does-not-exist");
        let view = realize_output(
            &output,
            RealizeOptions {
                configuration: &user,
                worker: &nonexistent_worker,
                offline: true,
            },
            &cancellation,
            |_| panic!("no build phase for imported output"),
        )
        .unwrap();
        assert!(
            matches!(view.identity().origin, crate::result::OutputOrigin::Imported { manifest } if manifest == pin)
        );
        let closure = crate::realize::realize_command(
            &command,
            &user,
            &nonexistent_worker,
            true,
            &cancellation,
            |_, _| panic!("no build"),
        )
        .unwrap();
        assert!(closure.entry().ends_with("/out/bin/cc"));
        let consumer = crate::deployment::manifest::prepare_consumer(
            plan,
            "shell",
            &user,
            &nonexistent_worker,
            true,
            &cancellation,
            |_, _| panic!("no build"),
        )
        .unwrap();
        assert_eq!(consumer.outputs().len(), 1);
        assert_eq!(consumer.invocations().len(), 1);
        drop((output, view, closure));
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                remove_roots: vec![RootName::new("bootstrap").unwrap()],
                ..crate::store::GcRequest::default()
            })
            .unwrap();
        let held = &consumer.outputs()[&reference];
        assert_eq!(
            held.read_file("bin/cc", 4096, &cancellation)
                .unwrap(),
            crate::runtime::tests::elf(2, None, &[], None, None)
        );
    }

    #[test]
    fn imported_output_does_not_rename_manifest_entries_or_accept_missing_keys() {
        let temp = tempfile::tempdir().unwrap();
        let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
        let store = Store::initialize(user.store()).unwrap();
        let pin = admitted(&store);
        for (index, (name, key, pin)) in [
            ("dev", "compiler", pin),
            ("out", "absent", pin),
            (
                "out",
                "compiler",
                ContentDigest::sha256(b"wrong pin"),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let plan = prepared(
                &temp.path().join(format!("project-{index}")),
                pin,
                name,
                key,
            );
            let reference = PlanOutputRef {
                package: plan
                    .plan()
                    .imports()
                    .next()
                    .unwrap()
                    .package()
                    .clone(),
                output: name.into(),
            };
            let selected = resolve_plan_output(&plan, &reference).unwrap();
            assert!(
                realize_output(
                    &selected,
                    RealizeOptions {
                        configuration: &user,
                        worker: Path::new("/missing-worker"),
                        offline: true
                    },
                    &Cancellation::default(),
                    |_| panic!("no fallback build")
                )
                .is_err()
            );
        }
        let cancelled = Cancellation::default();
        cancelled.cancel();
        let plan = prepared(
            &temp.path().join("cancelled"),
            pin,
            "out",
            "compiler",
        );
        let selected = crate::deployment::manifest::select_consumer(&plan, "shell").unwrap();
        let output = resolve_plan_output(&plan, selected.outputs().next().unwrap()).unwrap();
        assert!(matches!(
            realize_output(
                &output,
                RealizeOptions {
                    configuration: &user,
                    worker: Path::new("/missing-worker"),
                    offline: true
                },
                &cancelled,
                |_| {}
            ),
            Err(RealizeError::Cancelled)
        ));
        // Imported admission publishes its declared root, not a synthetic build root.
        let lease = store.operation().unwrap();
        assert!(lease.managed_build_roots().unwrap().is_empty());
        let manifest = AdmittedResult::open(
            &store,
            &RootName::new("bootstrap").unwrap(),
            pin,
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(
            lease
                .build_references(&RootName::new("bootstrap").unwrap())
                .unwrap()
                .unwrap(),
            manifest.manifest().references().unwrap()
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        project::AuthenticatedStandardLibrary, project::CheckConfiguration, store::ContentDigest,
        store::GcLimits, store::GcRequest, store::RootName,
    };
    use std::fs;

    #[test]
    #[ignore = "requires syrox-worker, user systemd, Bubblewrap, Landlock and the /usr toolchain"]
    fn host_named_output_survives_evaluation_build_cache_and_generation_handoff() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join("assets")).unwrap();
        fs::write(
            project.join("assets/source"),
            b"configuration template",
        )
        .unwrap();
        fs::write(project.join("main.srx"), format!(r#"
            fn recipe() -> std::Recipe {{ std::Recipe {{
                package = std::Package {{ id = "template"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("project:assets/source", "{}", 1024)]; }});
                build = std::Option::Some(std::Build {{ profile = std::BuildProfile::HostBootstrap;
                    source_directory = "template"; timeout_seconds = 30;
                    source_format = std::BuildSourceFormat::Raw; produces = ["out", "dev"];
                    steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("dev", "template")),
                        std::BuildStep::Write(std::BuildFile {{ path = std::BuildPath::Output("out", "manifest"); text = std::build_text("main output"); }})];
                }});
            }} }}
            outputs {{ configuration: std::Shell = std::Shell {{ pkgs = [std::select_output(std::recipe_ref(recipe), "dev")]; services = []; }}; }}
        "#, ContentDigest::sha256(b"configuration template"))).unwrap();
        let config = CheckConfiguration {
            standard_library: Some(AuthenticatedStandardLibrary::bundled()),
            ..CheckConfiguration::default()
        };
        crate::project::lock_project_with(&project, &config).unwrap();
        let locked = crate::project::open_locked_project_with(&project, &config).unwrap();
        let mut evaluation = locked.evaluation().unwrap();
        evaluation.evaluate_root("configuration").unwrap();
        let prepared = evaluation.into_prepared_plan().unwrap();
        let reference = prepared
            .plan()
            .consumers()
            .find(|consumer| consumer.name() == "configuration")
            .unwrap()
            .pkgs()[0]
            .output()
            .clone();
        let resolved = resolve_plan_output(&prepared, &reference).unwrap();
        drop((prepared, locked));
        // Realization consumes the preparation, without rechecking changed editor text.
        fs::write(project.join("main.srx"), "not a valid project").unwrap();
        let user = UserConfiguration::parse(
            "[build]\nhost-toolchain = \"/usr\"\n",
            temporary.path().join("store"),
        )
        .unwrap();
        let store = Store::initialize(user.store()).unwrap();
        let executable = std::env::current_exe().unwrap();
        let worker = executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("syrox-worker");
        assert!(
            worker.is_file(),
            "build syrox-worker before this test"
        );
        let cancellation = Cancellation::default();
        let first = realize_output(
            &resolved,
            RealizeOptions {
                configuration: &user,
                worker: &worker,
                offline: true,
            },
            &cancellation,
            |_| {},
        )
        .unwrap();
        assert_eq!(first.identity().output, "dev");
        assert_eq!(
            first
                .read_file("template", 1024, &cancellation)
                .unwrap(),
            b"configuration template"
        );
        assert_live_view_allows_unrelated_gc(&store, &first, &cancellation);
        let cached = realize_output(
            &resolved,
            RealizeOptions {
                configuration: &user,
                worker: &worker,
                offline: true,
            },
            &cancellation,
            |stage| {
                assert!(!matches!(stage, BuildProgress::AcquiringSource));
            },
        )
        .unwrap();
        assert_eq!(first.identity(), cached.identity());
        let retained = first
            .retain(
                &RootName::new("configuration_generation_1").unwrap(),
                &cancellation,
            )
            .unwrap();
        let crate::result::OutputOrigin::Built {
            receipt,
        } = retained.identity.origin
        else {
            panic!("locally built output must retain its receipt origin");
        };
        let build_root = RootName::new(format!("build_{receipt}")).unwrap();
        drop((first, cached, resolved));
        {
            let mut maintenance = store.maintenance().unwrap();
            crate::result::clear_materializations(&mut maintenance).unwrap();
            let report = maintenance
                .garbage_collect(&GcRequest {
                    collect: true,
                    remove_roots: vec![build_root],
                    limits: GcLimits::default(),
                })
                .unwrap();
            assert!(!report.uncertain);
            assert!(report.removed_objects.is_empty());
        }
        let reopened = retained.open(&store, &cancellation).unwrap();
        assert_eq!(
            reopened
                .read_file("template", 1024, &cancellation)
                .unwrap(),
            b"configuration template"
        );
    }

    fn assert_live_view_allows_unrelated_gc(
        store: &Store,
        first: &MaterializedArtifact,
        cancellation: &Cancellation,
    ) {
        // A live view holds granular object interests, not the global Store barrier.
        // Maintenance can collect unrelated data without invalidating that view.
        let junk = b"unrelated named-output garbage";
        let junk_pin = ContentDigest::sha256(junk);
        store
            .operation()
            .unwrap()
            .ingest(&junk[..], junk_pin, junk.len() as u64)
            .unwrap();
        let collected = store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .unwrap();
        assert!(!collected.uncertain && collected.failures.is_empty());
        assert!(collected.removed_objects.contains(&junk_pin));
        assert_eq!(
            first
                .read_file("template", 1024, cancellation)
                .unwrap(),
            b"configuration template"
        );
    }
}
/// A structural output selection tied to one authenticated preparation.
#[derive(Debug)]
pub struct ResolvedOutput {
    origin: OutputSource,
    reference: PlanOutputRef,
}

#[derive(Debug)]
enum OutputSource {
    Built(ResolvedBuild),
    Imported(PlanImportedResult),
}

impl ResolvedOutput {
    pub const fn reference(&self) -> &PlanOutputRef {
        &self.reference
    }
    /// Imported outputs have no build or source acquisition strategy.
    pub const fn build(&self) -> Option<&ResolvedBuild> {
        match &self.origin {
            OutputSource::Built(build) => Some(build),
            OutputSource::Imported(_) => None,
        }
    }
}

/// Resolve an `OutputRef` without opening a Store or reevaluating a factory.
pub fn resolve_plan_output(
    prepared: &PreparedPlan,
    reference: &PlanOutputRef,
) -> Result<ResolvedOutput, RealizeError> {
    let plan = prepared.plan();
    if plan
        .named_output(&reference.package, &reference.output)
        .is_none()
    {
        return Err(RealizeError::MissingOutput(reference.clone()));
    }
    let origin = if let Some(import) = plan
        .imports()
        .find(|item| item.package() == &reference.package)
    {
        OutputSource::Imported(import.clone())
    } else {
        let build = plan
            .builds()
            .find(|build| build.package() == &reference.package)
            .ok_or_else(|| RealizeError::MissingOutput(reference.clone()))?
            .clone();
        let package = plan
            .packages()
            .find(|package| package.id() == &reference.package)
            .expect("validated output package");
        OutputSource::Built(super::resolved_node(
            prepared.project().to_path_buf(),
            package
                .export()
                .unwrap_or(package.id().as_str())
                .to_owned(),
            prepared.clone(),
            build,
        ))
    };
    Ok(ResolvedOutput {
        origin,
        reference: reference.clone(),
    })
}

/// One verified result per package, shared by all selected outputs and roles.
/// Built and imported results retain verified objects without a global Store
/// barrier while other packages are being realized.
pub(crate) enum RealizedPackage {
    Built(BuildResult),
    Catalog {
        outputs: std::collections::BTreeMap<String, String>,
        admitted: AdmittedResult,
    },
    Imported {
        declaration: PlanImportedResult,
        admitted: AdmittedResult,
    },
}
impl RealizedPackage {
    pub(crate) fn materialize(
        &self,
        store: &Store,
        name: &str,
        cancellation: &Cancellation,
    ) -> Result<(MaterializedArtifact, RetainedOutput), RealizeError> {
        match self {
            Self::Built(result) => {
                if !result.retention.same_store(store)? {
                    return Err(MaterializationError::Invalid(
                        "build result belongs to another Store".into(),
                    )
                    .into());
                }
                let view = crate::result::materialize::materialize_named_with_cancellation(
                    store,
                    &result.root,
                    result.receipt,
                    name,
                    cancellation,
                )?;
                if view.action() != result.action {
                    return Err(MaterializationError::Invalid(
                        "realized output Action disagrees with build result".into(),
                    )
                    .into());
                }
                let retained = RetainedOutput {
                    root: result.root.clone(),
                    identity: view.identity().clone(),
                };
                Ok((view, retained))
            }
            Self::Imported {
                declaration,
                admitted,
            } => {
                let selected = declaration
                    .outputs()
                    .get(name)
                    .and_then(|key| admitted.output(key))
                    .filter(|output| output.identity.output == name)
                    .ok_or_else(|| {
                        MaterializationError::Invalid(
                            "imported output key is absent or changes the declared output name"
                                .into(),
                        )
                    })?;
                let view = admitted.materialize_output(&selected.identity, cancellation)?;
                Ok((view, selected))
            }
            Self::Catalog {
                outputs,
                admitted,
            } => {
                let selected = outputs
                    .get(name)
                    .and_then(|key| admitted.output(key))
                    .filter(|output| output.identity.output == name)
                    .ok_or_else(|| {
                        MaterializationError::Invalid(
                            "authorized runtime closure does not provide this output".into(),
                        )
                    })?;
                let view = admitted.materialize_output(&selected.identity, cancellation)?;
                Ok((view, selected))
            }
        }
    }
}

pub(crate) fn realize_package(
    resolved: &ResolvedOutput,
    context: &RealizeContext<'_>,
    cancellation: &Cancellation,
    progress: impl FnMut(BuildProgress),
) -> Result<RealizedPackage, RealizeError> {
    cancellation.check()?;
    match &resolved.origin {
        OutputSource::Built(build) => {
            let selection = crate::catalog::artifacts::ArtifactSelection::resolve(
                &build.prepared,
                context.options.configuration.artifacts(),
            )?;
            if let Some(artifact) = selection.select(&resolved.reference)?
                && let Some(imported) = artifact.import(context.store()?, cancellation)?
            {
                return Ok(RealizedPackage::Catalog {
                    outputs: imported.outputs,
                    admitted: imported.admitted,
                });
            }
            Ok(RealizedPackage::Built(context.realize_build(
                build,
                cancellation,
                progress,
            )?))
        }
        OutputSource::Imported(declaration) => Ok(RealizedPackage::Imported {
            admitted: AdmittedResult::open(
                context.store()?,
                declaration.root(),
                declaration.manifest(),
                cancellation,
            )?,
            declaration: declaration.clone(),
        }),
    }
}

/// Materialize an output with continuous retention. Imported results require
/// only their pinned Store objects; worker, toolchain and source are not opened.
pub fn realize_output(
    resolved: &ResolvedOutput,
    options: RealizeOptions<'_>,
    cancellation: &Cancellation,
    progress: impl FnMut(BuildProgress),
) -> Result<MaterializedArtifact, RealizeError> {
    cancellation.check()?;
    let context = RealizeContext::new(options);
    let package = realize_package(resolved, &context, cancellation, progress)?;
    Ok(package
        .materialize(
            context.store()?,
            &resolved.reference.output,
            cancellation,
        )?
        .0)
}
