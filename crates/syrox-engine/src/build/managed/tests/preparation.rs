use super::*;
use crate::build::cache;
use std::fs;
use std::io::Write as _;

fn fixture() -> (tempfile::TempDir, Plan, Store, BuildSpecification) {
    fixture_with_input(false)
}
fn fixture_with_input(with_input: bool) -> (tempfile::TempDir, Plan, Store, BuildSpecification) {
    let temp = tempfile::tempdir().unwrap();
    let digest = ContentDigest::sha256(b"source bytes");
    fs::write(temp.path().join("main.srx"), format!(r#"fn make() -> std::Recipe {{ std::Recipe {{
      package = std::Package {{id="data";dependencies=[];}};
      acquisition = std::Option::Some(std::Acquisition {{sources=[std::SourceRequest {{url="https://example.invalid/source";sha256="{digest}";maximum_bytes=1024;}}];}});
      build = std::Option::Some(std::Build {{profile=std::BuildProfile::Managed;source_directory="source-1";timeout_seconds=120;source_format=std::BuildSourceFormat::Raw;steps=[std::BuildStep::Directory(std::BuildPath::Work("data"))];}});
    }} }} mod factories::recipe {{ pub fn recipe() -> std::Recipe {{ project::make() }} }}
    pub publish(factories, recipe): std::Recipe;"#)).unwrap();
    if with_input {
        let path = temp.path().join("main.srx");
        let text = fs::read_to_string(&path).unwrap().replace("package = std::Package", "build_inputs = std::Option::Some(std::BuildInputs {selected=[std::recipe_output(std::recipe_ref(provider), \"out\")];}); package = std::Package");
        let provider = format!(
            r#"fn provider() -> std::Recipe {{ std::Recipe {{
          package=std::Package {{id="producer";dependencies=[];}};
          acquisition=std::Option::Some(std::Acquisition {{sources=[std::SourceRequest {{url="https://example.invalid/source";sha256="{digest}";maximum_bytes=1024;}}];}});
          build=std::Option::Some(std::Build {{profile=std::BuildProfile::HostBootstrap;source_directory="producer-1";timeout_seconds=120;source_format=std::BuildSourceFormat::Raw;steps=[std::BuildStep::Directory(std::BuildPath::Work("producer"))];}});
        }} }}"#
        );
        fs::write(path, provider + &text).unwrap();
    }
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(temp.path(), &checks).unwrap();
    let locked = crate::project::open_locked_project_with(temp.path(), &checks).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    evaluation.select_package("recipe").unwrap();
    let plan = evaluation.into_selected_plan().unwrap();
    let request = plan
        .builds()
        .find(|build| build.program().profile == BuildProfile::Managed)
        .unwrap()
        .request();
    let store = Store::initialize(&temp.path().join("store")).unwrap();
    store
        .operation()
        .unwrap()
        .ingest(&b"source bytes"[..], digest, 12)
        .unwrap();
    (temp, plan, store, request)
}

#[test]
fn preparation_pins_readonly_stage_and_preserves_unreleased_operation() {
    let (_temp, plan, store, request) = fixture();
    let cancel = Cancellation::default();
    let prepared =
        prepare_managed_build(&plan, &request, &store, b"pinned worker", &cancel).unwrap();
    let layout = prepared.layout();
    assert_eq!(layout.working, Path::new("/work"));
    assert!(layout.inputs.is_empty());
    assert_eq!(prepared.action.toolchain, None);
    assert_eq!(
        prepared.action.worker,
        ContentDigest::sha256(b"pinned worker")
    );
    for pinned in &prepared.files {
        let file = fs::File::from(pinned.file.fd().try_clone_to_owned().unwrap());
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o777,
            if pinned.name == "worker" {
                0o500
            } else {
                0o400
            }
        );
        assert!(
            (&file)
                .write_all(b"cannot write through read descriptor")
                .is_err()
        );
    }
    assert_eq!(
        fs::metadata(layout.staging.parent().unwrap().join("gate"))
            .unwrap()
            .len(),
        0
    );
    prepared.verify_preparation(&cancel).unwrap();
    let original = fs::read(layout.staging.join("worker")).unwrap();
    fs::rename(
        layout.staging.join("worker"),
        layout.staging.join("saved-worker"),
    )
    .unwrap();
    fs::write(layout.staging.join("worker"), b"replacement").unwrap();
    let pinned = prepared
        .files
        .iter()
        .find(|file| file.name == "worker")
        .unwrap();
    verify_file(pinned, &cancel).unwrap();
    assert_eq!(original, b"pinned worker");
    assert!(prepared.verify_preparation(&cancel).is_err());
    fs::remove_file(layout.staging.join("worker")).unwrap();
    fs::rename(
        layout.staging.join("saved-worker"),
        layout.staging.join("worker"),
    )
    .unwrap();
    drop(prepared);
    assert!(layout.staging.join("worker").is_file());
}

#[test]
fn cancelled_invalid_and_corrupt_sources_create_no_operations() {
    let (temp, plan, store, mut request) = fixture();
    let cancel = Cancellation::default();
    let before = fs::read_dir(temp.path().join("store/.syrox-store/builds"))
        .map(Iterator::count)
        .ok();
    cancel.cancel();
    assert!(matches!(
        prepare_managed_build(&plan, &request, &store, b"worker", &cancel),
        Err(BuildError::Cancelled)
    ));
    let cancel = Cancellation::default();
    request.inputs.push(crate::build::BuildInput {
        output: crate::result::RetainedOutput {
            root: crate::store::RootName::new("foreign").unwrap(),
            identity: crate::result::OutputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: ContentDigest::sha256(b"foreign"),
                },
                action: ContentDigest::sha256(b"foreign action"),
                artifact: ContentDigest::sha256(b"foreign artifact"),
                output: "out".into(),
            },
        },
    });
    assert!(prepare_managed_build(&plan, &request, &store, b"worker", &cancel).is_err());
    request.inputs.clear();
    let pin = ContentDigest::sha256(b"source bytes").to_string();
    fs::write(
        temp.path()
            .join("store/objects/sha256")
            .join(&pin[..2])
            .join(&pin),
        b"corrupt",
    )
    .unwrap();
    assert!(prepare_managed_build(&plan, &request, &store, b"worker", &cancel).is_err());
    let after = fs::read_dir(temp.path().join("store/.syrox-store/builds"))
        .map(Iterator::count)
        .ok();
    assert_eq!(before, after);
}

#[test]
fn source_copy_rechecks_digest_and_bound_after_store_verification() {
    let cancel = Cancellation::default();
    let expected = ContentDigest::sha256(b"original");
    assert!(matches!(
        read_source(&mut &b"replaced"[..], expected, 8, &cancel),
        Err(BuildError::InputChanged)
    ));
    assert!(matches!(
        read_source(
            &mut &b"original appended"[..],
            expected,
            8,
            &cancel
        ),
        Err(BuildError::InvalidRequest)
    ));
}

#[test]
fn retained_input_survives_root_removal_but_tampered_view_is_rejected() {
    let (_temp, plan, store, mut request) = fixture_with_input(true);
    let provider = plan
        .builds()
        .find(|build| build.program().profile == BuildProfile::HostBootstrap)
        .unwrap()
        .request();
    let cancel = Cancellation::default();
    let baseline = cache::tests::action();
    let action = Action::new(
        &provider,
        ContentDigest::sha256(b"source bytes"),
        baseline.toolchain,
        baseline.worker,
    );
    let result = {
        let lease = store.operation().unwrap();
        cache::tests::retained(&lease, &action, b"producer output")
    };
    request.inputs.push(crate::build::BuildInput {
        output: crate::result::RetainedOutput {
            root: result.root.clone(),
            identity: crate::result::OutputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: result.receipt,
                },
                action: result.action,
                artifact: result.artifact,
                output: "out".into(),
            },
        },
    });
    let prepared = prepare_managed_build(&plan, &request, &store, b"worker", &cancel).unwrap();
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![result.root],
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(!report.removed_objects.contains(&result.artifact));
    prepared.verify_preparation(&cancel).unwrap();
    let path = prepared.inputs[0]
        .directory()
        .unwrap()
        .join("bin/hello");
    let permissions = fs::metadata(&path).unwrap().permissions();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, b"tampered input").unwrap();
    fs::set_permissions(path, permissions).unwrap();
    assert!(prepared.verify_preparation(&cancel).is_err());
}

#[test]
fn correctly_pinned_source_exceeding_declared_limit_creates_no_operation() {
    let (temp, _plan, store, _request) = fixture();
    let project = temp.path().join("main.srx");
    let text = fs::read_to_string(&project)
        .unwrap()
        .replace("maximum_bytes=1024", "maximum_bytes=4");
    fs::write(project, text).unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(temp.path(), &checks).unwrap();
    let plan = crate::project::plan_project_package_with(temp.path(), &checks, "recipe").unwrap();
    let request = plan.builds().next().unwrap().request();
    let directory = store
        .operation()
        .unwrap()
        .build_directory()
        .unwrap();
    let path = linux_fd::directory_path(&directory).unwrap();
    assert!(
        prepare_managed_build(
            &plan,
            &request,
            &store,
            b"worker",
            &Cancellation::default()
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn managed_preparation_cannot_fall_back_to_legacy_host_authorization() {
    let (_temporary, plan, store, request) = fixture();
    let cancellation = Cancellation::default();
    let prepared =
        prepare_managed_build(&plan, &request, &store, b"worker", &cancellation).unwrap();
    prepared
        .operation
        .bind(
            super::super::journal::Attempt::new(prepared.action_digest(), request.timeout_seconds)
                .unwrap(),
        )
        .unwrap();
    assert!(
        prepared
            .operation
            .authorize_program(&prepared.action, request.timeout_seconds)
            .is_err()
    );
    assert!(
        !prepared
            .operation
            .path
            .join("authorized")
            .exists()
    );
    assert!(
        prepared
            .verify_service_worker(&cancellation)
            .is_err()
    );
}

pub(in crate::build) fn handoff_fixture() -> (
    tempfile::TempDir,
    Store,
    PreparedManagedBuild,
    crate::build::BuildResult,
) {
    handoff_fixture_with_worker(b"worker")
}
pub(in crate::build) fn handoff_fixture_with_worker(
    worker: &[u8],
) -> (
    tempfile::TempDir,
    Store,
    PreparedManagedBuild,
    crate::build::BuildResult,
) {
    let (temporary, plan, store, mut request) = fixture_with_input(true);
    let provider = plan
        .builds()
        .find(|build| build.program().profile == BuildProfile::HostBootstrap)
        .unwrap()
        .request();
    let baseline = cache::tests::action();
    let action = Action::new(
        &provider,
        ContentDigest::sha256(b"source bytes"),
        baseline.toolchain,
        baseline.worker,
    );
    let result = cache::tests::retained(
        &store.operation().unwrap(),
        &action,
        b"producer output",
    );
    request.inputs.push(crate::build::BuildInput {
        output: crate::result::RetainedOutput {
            root: result.root.clone(),
            identity: crate::result::OutputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: result.receipt,
                },
                action: result.action,
                artifact: result.artifact,
                output: "out".into(),
            },
        },
    });
    let prepared = prepare_managed_build(
        &plan,
        &request,
        &store,
        worker,
        &Cancellation::default(),
    )
    .unwrap();
    (temporary, store, prepared, result)
}
fn handoff_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(5)
}
#[test]
fn handoff_interest_and_process_description_survive_coordinator_drop_and_concurrent_gc() {
    // A foreign harness fork can inherit the process-retention OFD before exec.
    if linux_fd::retention_fork_tests::isolate_test(
        "build::managed::preparation::tests::handoff_interest_and_process_description_survive_coordinator_drop_and_concurrent_gc",
        "SYROX_MANAGED_HANDOFF_GC_ISOLATED",
    ) {
        return;
    }
    let (_temporary, store, prepared, provider) = handoff_fixture();
    let cancellation = Cancellation::default();
    let retained = prepared
        .retain_for_handoff(&cancellation, handoff_deadline())
        .unwrap();
    assert_eq!(retained.action_digest(), prepared.action_digest());
    let source = prepared.action.source;
    let view = prepared.inputs[0].directory().unwrap();
    let garbage = ContentDigest::sha256(b"unrelated garbage");
    store
        .operation()
        .unwrap()
        .ingest(&b"unrelated garbage"[..], garbage, 100)
        .unwrap();
    let provider_root = provider.root.clone();
    let provider_artifact = provider.artifact;
    let provider_receipt = provider.receipt;
    drop((prepared, provider));
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![provider_root],
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_objects.contains(&garbage));
    assert!(!report.removed_objects.contains(&source));
    assert!(
        !report
            .removed_objects
            .contains(&provider_artifact)
    );
    assert_eq!(
        crate::result::clear_materializations(&mut maintenance).unwrap(),
        0
    );
    drop(maintenance);
    retained
        .revalidate(&cancellation, handoff_deadline())
        .unwrap();
    let mut process = retained
        .process_retention(&cancellation, handoff_deadline())
        .unwrap();
    assert!(
        process
            .write_all(b"cannot mutate interest")
            .is_err()
    );
    let transferred = process.try_clone().unwrap();
    drop((retained, process));
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(!report.removed_objects.contains(&source));
    assert!(!report.removed_objects.contains(&provider_receipt));
    assert!(
        !report
            .removed_objects
            .contains(&provider_artifact)
    );
    assert_eq!(
        crate::result::clear_materializations(&mut maintenance).unwrap(),
        0
    );
    assert!(view.exists());
    drop(maintenance);
    drop(transferred);
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_objects.contains(&source));
    assert!(report.removed_objects.contains(&provider_receipt));
    assert!(
        report
            .removed_objects
            .contains(&provider_artifact)
    );
    assert_eq!(
        crate::result::clear_materializations(&mut maintenance).unwrap(),
        1
    );
    assert!(!view.exists());
}
#[test]
fn handoff_revalidates_cancellation_deadline_and_corrupt_inputs() {
    let (_temporary, _store, prepared, _provider) = handoff_fixture();
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        prepared.retain_for_handoff(&cancelled, handoff_deadline()),
        Err(BuildError::Cancelled)
    ));
    let cancellation = Cancellation::default();
    assert!(
        prepared
            .retain_for_handoff(&cancellation, std::time::Instant::now())
            .is_err()
    );
    let retained = prepared
        .retain_for_handoff(&cancellation, handoff_deadline())
        .unwrap();
    assert!(matches!(
        retained.process_retention(&cancelled, handoff_deadline()),
        Err(BuildError::Cancelled)
    ));
    let path = prepared.inputs[0]
        .directory()
        .unwrap()
        .join("bin/hello");
    let permissions = fs::metadata(&path).unwrap().permissions();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, b"corrupt").unwrap();
    fs::set_permissions(path, permissions).unwrap();
    assert!(
        retained
            .process_retention(&cancellation, handoff_deadline())
            .is_err()
    );
    assert!(
        prepared
            .retain_for_handoff(&cancellation, handoff_deadline())
            .is_err()
    );
}
#[test]
fn held_source_descriptor_survives_unlink_but_not_byte_corruption() {
    let (_temporary, plan, store, request) = fixture();
    let cancellation = Cancellation::default();
    let prepared =
        prepare_managed_build(&plan, &request, &store, b"worker", &cancellation).unwrap();
    let retained = prepared
        .retain_for_handoff(&cancellation, handoff_deadline())
        .unwrap();
    let source_path = prepared.operation.stage_path().join("source");
    drop(prepared);
    fs::remove_file(source_path).unwrap();
    retained
        .revalidate(&cancellation, handoff_deadline())
        .unwrap();
    let fdpath = format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(&retained.source)
    );
    retained
        .source
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    fs::write(fdpath, b"tamper bytes").unwrap();
    retained
        .source
        .set_permissions(fs::Permissions::from_mode(0o400))
        .unwrap();
    assert!(
        retained
            .process_retention(&cancellation, handoff_deadline())
            .is_err()
    );
}

#[test]
fn retention_refuses_source_pin_or_selected_output_mismatch() {
    let (_temporary, _store, mut prepared, _provider) = handoff_fixture();
    let cancellation = Cancellation::default();
    let expected = prepared.action.source;
    prepared.action.source = ContentDigest::sha256(b"different source");
    assert!(
        prepared
            .retain_for_handoff(&cancellation, handoff_deadline())
            .is_err()
    );
    prepared.action.source = expected;
    prepared.action.inputs[0].output = "other".into();
    assert!(
        prepared
            .retain_for_handoff(&cancellation, handoff_deadline())
            .is_err()
    );
}

#[test]
fn input_preparation_retains_source_without_creating_an_operation_or_blocking_gc() {
    let (temporary, plan, store, request) = fixture();
    let cancel = Cancellation::default();
    let garbage = ContentDigest::sha256(b"unrelated");
    store
        .operation()
        .unwrap()
        .ingest(&b"unrelated"[..], garbage, 9)
        .unwrap();
    let inputs = prepare_managed_build_inputs(&plan, &request, &store, b"worker", &cancel).unwrap();
    let action = inputs.action_digest();
    let operations = temporary.path().join("store/.syrox-store/builds");
    assert!(
        !operations.exists()
            || fs::read_dir(&operations).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("op-")
            })
    );
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_objects.contains(&garbage));
    assert!(
        !report
            .removed_objects
            .contains(&ContentDigest::sha256(b"source bytes"))
    );
    let prepared = inputs.stage(&cancel).unwrap();
    assert_eq!(prepared.action_digest(), action);
    prepared.verify_preparation(&cancel).unwrap();
}

#[test]
fn cancelled_staging_does_not_create_an_operation() {
    let (temporary, plan, store, request) = fixture();
    let cancel = Cancellation::default();
    let inputs = prepare_managed_build_inputs(&plan, &request, &store, b"worker", &cancel).unwrap();
    cancel.cancel();
    assert!(matches!(
        inputs.stage(&cancel),
        Err(BuildError::Cancelled)
    ));
    let operations = temporary.path().join("store/.syrox-store/builds");
    assert!(
        !operations.exists()
            || fs::read_dir(&operations).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("op-")
            })
    );
}

#[test]
fn shared_staging_reuses_the_admitted_operation() {
    let (_temp, plan, store, request) = fixture();
    let cancel = Cancellation::default();
    let inputs = prepare_managed_build_inputs(&plan, &request, &store, b"worker", &cancel).unwrap();
    let lease = store.operation().unwrap();
    let operation = std::sync::Arc::new(Operation::create(&lease).unwrap());
    operation
        .bind(
            super::super::journal::Attempt::new(inputs.action_digest(), inputs.timeout_seconds)
                .unwrap(),
        )
        .unwrap();
    drop(lease);
    let prepared = inputs
        .stage_in(std::sync::Arc::clone(&operation), &cancel)
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &prepared.operation,
        &operation
    ));
    assert_eq!(prepared.layout().staging, operation.stage_path());
    prepared.verify_preparation(&cancel).unwrap();
}

#[test]
fn shared_staging_rejects_different_action_timeout_and_store_before_writes() {
    let (temp, plan, store, request) = fixture();
    let cancel = Cancellation::default();
    let foreign = Store::initialize(&temp.path().join("foreign-store")).unwrap();
    for mismatch in ["action", "timeout", "store"] {
        let inputs =
            prepare_managed_build_inputs(&plan, &request, &store, b"worker", &cancel).unwrap();
        let lease = if mismatch == "store" {
            foreign.operation()
        } else {
            store.operation()
        }
        .unwrap();
        let operation = std::sync::Arc::new(Operation::create(&lease).unwrap());
        let action = if mismatch == "action" {
            ContentDigest::sha256(b"another action")
        } else {
            inputs.action_digest()
        };
        let timeout = if mismatch == "timeout" {
            inputs.timeout_seconds + 1
        } else {
            inputs.timeout_seconds
        };
        operation
            .bind(super::super::journal::Attempt::new(action, timeout).unwrap())
            .unwrap();
        drop(lease);
        assert!(
            matches!(
                inputs.stage_in(std::sync::Arc::clone(&operation), &cancel),
                Err(BuildError::InputChanged)
            ),
            "{mismatch}"
        );
        assert_eq!(
            fs::read_dir(operation.stage_path())
                .unwrap()
                .count(),
            0,
            "{mismatch}"
        );
    }
}

#[test]
fn execution_refuses_unpinned_nonstatic_and_foreign_candidates_before_admission() {
    let (temp, plan, store, request) = fixture();
    let foreign = Store::initialize(&temp.path().join("foreign-store")).unwrap();
    let cancel = Cancellation::default();
    for refusal in ["pin", "static", "store"] {
        let inputs =
            prepare_managed_build_inputs(&plan, &request, &store, b"worker", &cancel).unwrap();
        let pin = ContentDigest::sha256(if refusal == "pin" {
            b"other"
        } else {
            b"worker"
        });
        let user = crate::config::UserConfiguration::parse(&format!(
            "[build.managed]\nworker='/unused-worker'\nworker-sha256='{pin}'\nscope='user'\nuser-bus='/unused-bus'\nsocket-parent='/unused-sockets'\n"
        ), temp.path().join("store")).unwrap();
        let result = inputs.execute(
            if refusal == "store" {
                &foreign
            } else {
                &store
            },
            user.managed_build().unwrap(),
            None,
            &cancel,
        );
        assert!(
            matches!(
                result,
                Err(BuildError::InputChanged | BuildError::InvalidRequest)
            ),
            "{refusal}: {result:?}"
        );
    }
    for selected in [&store, &foreign] {
        let directory = selected
            .operation()
            .unwrap()
            .build_directory()
            .unwrap();
        assert!(
            linux_fd::read_directory(&directory, |_| Ok::<_, ()>(()))
                .unwrap()
                .is_empty()
        );
    }
}
