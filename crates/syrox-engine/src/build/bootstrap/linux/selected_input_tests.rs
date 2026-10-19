use crate::build::BuildResources;
use super::*;

fn fixture() -> (tempfile::TempDir, Plan, Store) {
    let temp = tempfile::tempdir().unwrap();
    let source = cache::tests::action().source;
    fs::write(temp.path().join("main.srx"), format!(r#"fn make_provider() -> std::Recipe {{ std::Recipe {{
        package = std::Package {{ id = "provider"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [std::SourceRequest {{url="https://example.invalid/source";sha256="{source}";maximum_bytes=1024;}}]; }});
        build = std::Option::Some(std::autotools(std::BuildOptions {{source_directory="provider-1";timeout_seconds=120;}}));
      }} }}
      fn make_consumer() -> std::Recipe {{ std::Recipe {{
          package = std::Package {{ id = "consumer"; dependencies = []; }};
          acquisition = std::Option::Some(std::Acquisition {{ sources = [std::SourceRequest {{url="https://example.invalid/source";sha256="{source}";maximum_bytes=1024;}}]; }});
          build = std::Option::Some(std::autotools(std::BuildOptions {{source_directory="consumer-1";timeout_seconds=120;}}));
          build_inputs = std::Option::Some(std::BuildInputs {{ selected = [std::recipe_output(std::recipe_ref(make_provider), "out")]; }});
        }} }}
      mod factories::consumer {{ pub fn recipe() -> std::Recipe {{ project::make_consumer() }} }}
      pub publish(factories, recipe): std::Recipe;"#)).unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(temp.path(), &checks).unwrap();
    let plan = crate::project::plan_project_package_with(temp.path(), &checks, "consumer").unwrap();
    let store = Store::initialize(&temp.path().join("store")).unwrap();
    (temp, plan, store)
}

#[test]
fn selected_producer_uses_its_own_retained_worker_and_inventory_identity() {
    let (temp, plan, store) = fixture();
    let request = plan
        .builds()
        .find(|build| build.source_directory() == "provider-1")
        .unwrap()
        .request();
    let cancel = Cancellation::default();
    let lease = store.operation().unwrap();
    let baseline = cache::tests::action();
    let inventory = b"syrox-host-toolchain\nindependent producer";
    let digest = ContentDigest::sha256(inventory);
    lease
        .ingest(&inventory[..], digest, inventory.len() as u64)
        .unwrap();
    let action = Action::new(
        &request,
        baseline.source,
        Some(digest),
        ContentDigest::sha256(b"different producer worker"),
    );
    assert_ne!(action.worker, baseline.worker);
    assert_ne!(action.toolchain, baseline.toolchain);
    let result = cache::tests::retained(&lease, &action, b"output");
    let (verified, _) =
        cache::retained_result(&lease, &result.root, result.receipt, &cancel).unwrap();
    verify_selected_input(
        &plan,
        &request.package,
        &verified,
        &lease,
        &cancel,
        &mut 0,
    )
    .unwrap();
    for alteration in [
        "source",
        "program",
        "directory",
        "inputs",
    ] {
        let mut other = verified.clone();
        match alteration {
            "source" => other.source = ContentDigest::sha256(b"other source"),
            "program" => other.program.resources = BuildResources::Large,
            "directory" => other.directory = "different".into(),
            _ => other
                .inputs
                .push(super::super::records::InputIdentity {
                    origin: crate::result::OutputOrigin::Built {
                        receipt: result.receipt,
                    },
                    action: result.action,
                    artifact: result.artifact,
                    output: "out".into(),
                }),
        }
        assert!(
            verify_selected_input(
                &plan,
                &request.package,
                &other,
                &lease,
                &cancel,
                &mut 0
            )
            .is_err()
        );
    }
    let text = digest.to_string();
    fs::write(
        temp.path()
            .join("store")
            .join("objects/sha256")
            .join(&text[..2])
            .join(&text),
        b"tampered",
    )
    .unwrap();
    assert!(cache::retained_result(&lease, &result.root, result.receipt, &cancel).is_err());
}

#[test]
fn transitive_producer_identity_is_independent_but_its_own_inputs_are_required() {
    for missing in ["source", "inventory"] {
        let (temp, plan, store) = fixture();
        let consumer = plan
            .builds()
            .find(|build| build.source_directory() == "consumer-1")
            .unwrap();
        let selected = &consumer.inputs()[0];
        let provider = plan
            .builds()
            .find(|build| build.package() == &selected.package)
            .unwrap();
        let lease = store.operation().unwrap();
        let cancel = Cancellation::default();
        let baseline = cache::tests::action();
        let inventory = b"syrox-host-toolchain\ntransitive producer";
        let pin = ContentDigest::sha256(inventory);
        lease
            .ingest(&inventory[..], pin, inventory.len() as u64)
            .unwrap();
        let producer = Action::new(
            &provider.request(),
            baseline.source,
            Some(pin),
            ContentDigest::sha256(b"producer-only worker"),
        );
        let retained = cache::tests::retained(&lease, &producer, b"retained input");
        let mut action = Action::new(
            &consumer.request(),
            baseline.source,
            baseline.toolchain,
            baseline.worker,
        );
        action
            .inputs
            .push(super::super::records::InputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: retained.receipt,
                },
                action: retained.action,
                artifact: retained.artifact,
                output: selected.output.clone(),
            });
        verify_selected_input(
            &plan,
            consumer.package(),
            &action,
            &lease,
            &cancel,
            &mut 0,
        )
        .unwrap();
        let mut wrong_output = action.clone();
        wrong_output.inputs[0].output = "dev".into();
        assert!(
            verify_selected_input(
                &plan,
                consumer.package(),
                &wrong_output,
                &lease,
                &cancel,
                &mut 0
            )
            .is_err()
        );
        let mut wrong_artifact = action.clone();
        wrong_artifact.inputs[0].artifact = ContentDigest::sha256(b"unselected artifact");
        assert!(
            verify_selected_input(
                &plan,
                consumer.package(),
                &wrong_artifact,
                &lease,
                &cancel,
                &mut 0
            )
            .is_err()
        );
        let missing = if missing == "source" {
            baseline.source
        } else {
            pin
        }
        .to_string();
        fs::remove_file(
            temp.path()
                .join("store/objects/sha256")
                .join(&missing[..2])
                .join(&missing),
        )
        .unwrap();
        assert!(
            verify_selected_input(
                &plan,
                consumer.package(),
                &action,
                &lease,
                &cancel,
                &mut 0
            )
            .is_err()
        );
    }
}
