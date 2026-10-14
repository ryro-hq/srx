use super::{BuildSpecification, Cancellation, ContentDigest, Plan, Store, prepare_managed_build};
use crate::{
    build::BuildInput, result::ResultManifest, result::RetainedOutput, store::GcRequest,
    store::RootName,
};
use std::fs;

struct Fixture {
    directory: tempfile::TempDir,
    store: Store,
    manifest: ResultManifest,
    root: RootName,
    selected: RetainedOutput,
    sibling: ContentDigest,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(&directory.path().join("store")).unwrap();
        let lease = store.operation().unwrap();
        let mut artifacts = Vec::new();
        for name in ["compiler", "sibling"] {
            let path = directory.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("data"), name.as_bytes()).unwrap();
            let mut bytes = Vec::new();
            crate::result::artifact::pack(&path, &mut bytes).unwrap();
            let digest = ContentDigest::sha256(&bytes);
            lease
                .ingest(bytes.as_slice(), digest, bytes.len() as u64)
                .unwrap();
            artifacts.push(digest);
        }
        let logical = ContentDigest::sha256(b"imported identity, not an Action object");
        let wire = format!(
            "syrox-result-v2\n{{\"outputs\":{{\"compiler\":{{\"action\":\"{logical}\",\"output\":\"out\",\"artifact\":\"{}\",\"files\":1}},\"sibling\":{{\"action\":\"{logical}\",\"output\":\"dev\",\"artifact\":\"{}\",\"files\":1}}}},\"commands\":{{}}}}\n",
            artifacts[0], artifacts[1]
        );
        let manifest = ResultManifest::parse(wire.as_bytes()).unwrap();
        let root = RootName::new("import-fixture").unwrap();
        let admitted = crate::result::admit_result(
            &store,
            &root,
            &manifest,
            manifest.digest().unwrap(),
            &Cancellation::default(),
        )
        .unwrap();
        let selected = admitted.output("compiler").unwrap();
        drop(admitted);
        let source = b"consumer source";
        lease
            .ingest(
                source.as_slice(),
                ContentDigest::sha256(source),
                source.len() as u64,
            )
            .unwrap();
        drop(lease);
        Self {
            directory,
            store,
            manifest,
            root,
            selected,
            sibling: artifacts[1],
        }
    }
    fn plan(
        &self,
        root: &RootName,
        pin: ContentDigest,
        output: &str,
    ) -> (Plan, BuildSpecification) {
        let project = self
            .directory
            .path()
            .join(format!("project-{}-{output}", root.as_str()));
        fs::create_dir_all(&project).unwrap();
        let source = ContentDigest::sha256(b"consumer source");
        fs::write(project.join("main.srx"), format!(r#"
        fn provider() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "provider"; dependencies = []; }};
            imported = std::Option::Some(std::ImportedResult {{ root = "{root}"; manifest = "{pin}";
                entries = [std::ImportedOutput {{ output = "{output}"; key = "compiler"; }}]; }});
        }} }}
        fn make_consumer() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "consumer"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("https://example.invalid/consumer", "{source}", 1024)]; }});
                build = std::Option::Some(std::Build {{ profile = std::BuildProfile::Managed; source_directory = "src"; timeout_seconds = 30; source_format = std::BuildSourceFormat::Raw;
                    steps = [std::BuildStep::Copy(std::BuildPath::Input(0, "data"), std::BuildPath::Output("out", "data"))]; }});
                build_inputs = std::Option::Some(std::BuildInputs {{ selected = [std::recipe_output(std::recipe_ref(provider), "{output}")]; }});
            }} }} mod factories::consumer {{ pub fn recipe() -> std::Recipe {{ project::make_consumer() }} }}
        pub publish(factories, recipe): std::Recipe;"#)).unwrap();
        let checks = crate::project::CheckConfiguration {
            standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
            ..crate::project::CheckConfiguration::default()
        };
        crate::project::lock_project_with(&project, &checks).unwrap();
        let plan =
            crate::project::plan_project_package_with(&project, &checks, "consumer").unwrap();
        let mut request = plan.builds().next().unwrap().request();
        request.inputs = vec![BuildInput {
            output: RetainedOutput {
                root: root.clone(),
                identity: self.selected.identity.clone(),
            },
        }];
        (plan, request)
    }
}

#[test]
fn authentic_import_prepares_without_producer_action_receipt_or_source_and_survives_gc() {
    let fixture = Fixture::new();
    let pin = fixture.manifest.digest().unwrap();
    let (plan, request) = fixture.plan(&fixture.root, pin, "out");
    let cancel = Cancellation::default();
    assert!(
        fixture
            .store
            .operation()
            .unwrap()
            .verify(fixture.selected.identity.action)
            .unwrap()
            .is_none()
    );
    let prepared = prepare_managed_build(
        &plan,
        &request,
        &fixture.store,
        b"worker fixture",
        &cancel,
    )
    .unwrap();
    assert_eq!(
        prepared.inputs[0].identity(),
        &fixture.selected.identity
    );
    fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![fixture.root.clone()],
            ..GcRequest::default()
        })
        .unwrap();
    prepared.verify_preparation(&cancel).unwrap();
    let lease = fixture.store.operation().unwrap();
    for digest in fixture.manifest.references().unwrap() {
        assert!(lease.verify(digest).unwrap().is_some());
    }
    assert!(
        lease
            .build_references(&fixture.root)
            .unwrap()
            .is_none()
    );
}

#[test]
fn identical_import_under_another_root_preserves_action_identity() {
    let fixture = Fixture::new();
    let pin = fixture.manifest.digest().unwrap();
    let alternate = RootName::new("alternate-import").unwrap();
    drop(
        crate::result::admit_result(
            &fixture.store,
            &alternate,
            &fixture.manifest,
            pin,
            &Cancellation::default(),
        )
        .unwrap(),
    );
    let (first_plan, first) = fixture.plan(&fixture.root, pin, "out");
    let (second_plan, second) = fixture.plan(&alternate, pin, "out");
    let cancel = Cancellation::default();
    let a = prepare_managed_build(
        &first_plan,
        &first,
        &fixture.store,
        b"worker",
        &cancel,
    )
    .unwrap();
    let b = prepare_managed_build(
        &second_plan,
        &second,
        &fixture.store,
        b"worker",
        &cancel,
    )
    .unwrap();
    assert_eq!(a.action_digest(), b.action_digest());
}

#[test]
fn declared_manifest_output_and_selected_identity_must_all_agree() {
    let fixture = Fixture::new();
    let pin = fixture.manifest.digest().unwrap();
    let cancel = Cancellation::default();
    for (declared, output) in [
        (ContentDigest::sha256(b"wrong manifest"), "out"),
        (pin, "dev"),
    ] {
        let (plan, request) = fixture.plan(&fixture.root, declared, output);
        assert!(
            prepare_managed_build(
                &plan,
                &request,
                &fixture.store,
                b"worker",
                &cancel
            )
            .is_err()
        );
    }
    let (plan, mut request) = fixture.plan(&fixture.root, pin, "out");
    request.inputs[0].output.identity.artifact = fixture.sibling;
    assert!(
        prepare_managed_build(
            &plan,
            &request,
            &fixture.store,
            b"worker",
            &cancel
        )
        .is_err()
    );
}

#[test]
fn missing_or_corrupt_unselected_sibling_invalidates_the_import_closure() {
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        let (plan, request) = fixture.plan(
            &fixture.root,
            fixture.manifest.digest().unwrap(),
            "out",
        );
        let pin = fixture.sibling.to_string();
        let path = fixture
            .directory
            .path()
            .join("store/objects/sha256")
            .join(&pin[..2])
            .join(&pin);
        fs::remove_file(&path).unwrap();
        if corrupt {
            fs::write(path, b"corrupt sibling").unwrap();
        }
        assert!(
            prepare_managed_build(
                &plan,
                &request,
                &fixture.store,
                b"worker",
                &Cancellation::default()
            )
            .is_err()
        );
    }
}
