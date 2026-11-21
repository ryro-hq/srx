use super::*;

fn materialized_file(
    output: MaterializedArtifact,
    path: &str,
) -> RuntimeFile<MaterializedArtifact> {
    RuntimeFile {
        output,
        path: path.to_owned(),
    }
}

fn imported_runtime_roundtrip(source: &Store, closure: &RuntimeClosure) {
    let cancellation = crate::cancellation::Cancellation::default();
    let manifest = crate::result::ResultManifest::from_views(
        BTreeMap::from([
            ("app".into(), &closure.application().output),
            ("loader".into(), &closure.loader().unwrap().output),
            ("library".into(), &closure.libraries()[0]),
        ]),
        BTreeMap::from([(
            "run".into(),
            crate::result::ResultCommand {
                application: "app".into(),
                application_path: closure.application().path.as_str().to_owned(),
                loader: Some("loader".into()),
                loader_path: closure
                    .loader()
                    .map(|file| file.path.as_str())
                    .map(str::to_owned),
                libraries: vec!["library".into()],
            },
        )]),
    )
    .unwrap();
    let receiver = tempfile::tempdir().unwrap();
    let destination = Store::open(receiver.path()).unwrap();
    for output in manifest.outputs().values() {
        let input = source
            .operation()
            .unwrap()
            .open_verified(output.artifact, build::MAX_OUTPUT_BYTES)
            .unwrap()
            .unwrap();
        destination
            .operation()
            .unwrap()
            .ingest(input, output.artifact, build::MAX_OUTPUT_BYTES)
            .unwrap();
    }
    let admitted = crate::result::admit_result(
        &destination,
        &RootName::new("portable_runtime").unwrap(),
        &manifest,
        manifest.digest().unwrap(),
        &cancellation,
    )
    .unwrap();
    let runtime = admitted.command("run").unwrap();
    assert!(matches!(
        runtime.application.output.identity.origin,
        crate::result::OutputOrigin::Imported { .. }
    ));
    drop(admitted);
    let imported = runtime.open(&destination, &cancellation).unwrap();
    assert_eq!(imported.entry(), closure.entry());
    assert_eq!(imported.mounts().unwrap().len(), 3);
    crate::store::take_verified_read_bytes();
    runtime.open(&destination, &cancellation).unwrap();
    let shared_admission_bytes = crate::store::take_verified_read_bytes();
    verify_materialized_runtime(
        materialized_file(
            runtime
                .application
                .output
                .open(&destination, &cancellation)
                .unwrap(),
            &runtime.application.path,
        ),
        Some(materialized_file(
            runtime
                .loader
                .as_ref()
                .unwrap()
                .output
                .open(&destination, &cancellation)
                .unwrap(),
            &runtime.loader.as_ref().unwrap().path,
        )),
        vec![
            runtime.libraries[0]
                .open(&destination, &cancellation)
                .unwrap(),
        ],
        &cancellation,
    )
    .unwrap();
    let independent_admission_bytes = crate::store::take_verified_read_bytes();
    assert!(
        shared_admission_bytes < independent_admission_bytes,
        "shared={shared_admission_bytes}, independent={independent_admission_bytes}"
    );
    let crate::result::OutputOrigin::Built {
        receipt,
    } = closure.application().output.identity().origin
    else {
        panic!("source fixture was not built");
    };
    assert!(
        destination
            .operation()
            .unwrap()
            .read_verified(receipt, 1024 * 1024)
            .unwrap()
            .is_none()
    );
    drop(imported);
    crate::result::clear_materializations(&mut destination.maintenance().unwrap()).unwrap();
    assert_eq!(
        runtime
            .open(&destination, &cancellation)
            .unwrap()
            .entry(),
        closure.entry()
    );
}

#[test]
fn materialized_runtime_keeps_distinct_outputs_of_one_action() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    let (root, receipt, action) = build::cache::tests::retained_split_runtime(
        &store,
        &elf(3, None, &[], None, None),
        &elf(3, None, &[], Some("libsplit.so.1"), None),
    );
    let interpreter = format!("/syrox/store/{action}/out/bin/hello");
    let runpath = format!("/syrox/store/{action}/lib/usr/lib");
    let app = retained(
        &store,
        "split-consumer",
        &elf(
            2,
            Some(&interpreter),
            &["libsplit.so.1"],
            None,
            Some(&runpath),
        ),
        None,
    );
    let application = crate::result::materialize_artifact(&store, &app.root, app.receipt).unwrap();
    let loader = crate::result::materialize_artifact(&store, &root, receipt).unwrap();
    let library = crate::result::materialize_named_artifact(&store, &root, receipt, "lib").unwrap();
    let closure = verify_materialized_runtime(
        materialized_file(application, "bin/hello"),
        Some(materialized_file(loader, "bin/hello")),
        vec![library],
        &cancellation,
    )
    .unwrap();
    let targets = closure
        .mounts()
        .unwrap()
        .into_iter()
        .map(|mount| mount.target)
        .collect::<BTreeSet<_>>();
    assert_eq!(targets.len(), 3);
    assert!(targets.contains(&format!("/syrox/store/{action}/out")));
    assert!(targets.contains(&format!("/syrox/store/{action}/lib")));
    assert!(matches!(
        verify_materialized_runtime(
            materialized_file(
                closure.application.output.share(),
                closure.application().path.as_str()
            ),
            closure
                .loader
                .as_ref()
                .map(|file| materialized_file(file.output.share(), &file.path)),
            vec![],
            &cancellation
        ),
        Err(RuntimeError::Invalid(_))
    ));
    imported_runtime_roundtrip(&store, &closure);
    cancellation.cancel();
    assert!(matches!(
        verify_materialized_runtime(
            materialized_file(
                closure.application.output.share(),
                closure.application().path.as_str()
            ),
            closure
                .loader
                .as_ref()
                .map(|file| materialized_file(file.output.share(), &file.path)),
            closure
                .libraries
                .iter()
                .map(MaterializedArtifact::share)
                .collect(),
            &cancellation
        ),
        Err(RuntimeError::Cancelled)
    ));
}

#[test]
fn materialized_runtime_rejects_two_artifacts_for_the_same_prefix() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let first = retained(
        &store,
        "conflicting",
        &elf(2, None, &[], None, None),
        None,
    );
    let second = retained(
        &store,
        "conflicting",
        &elf(3, None, &[], None, None),
        None,
    );
    assert_eq!(first.action, second.action);
    assert_ne!(first.artifact, second.artifact);
    let application =
        crate::result::materialize_artifact(&store, &first.root, first.receipt).unwrap();
    let loader = crate::result::materialize_artifact(&store, &second.root, second.receipt).unwrap();
    let error = verify_materialized_runtime(
        materialized_file(application, "bin/hello"),
        Some(materialized_file(loader, "bin/hello")),
        vec![],
        &crate::cancellation::Cancellation::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, RuntimeError::Invalid(message) if message.contains("conflicting identities"))
    );
}
