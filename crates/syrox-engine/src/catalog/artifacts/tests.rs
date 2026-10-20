use super::*;
use crate::{
    config::UserConfiguration,
    project::{AuthenticatedStandardLibrary, CheckConfiguration},
    result::{OutputOrigin, ResultManifest},
    store::{RootName, Store},
};
use std::fs;

const RECIPE: &str = r#"
fn recipe(message: BuildLiteral) -> Recipe { Recipe {
    package = Package { id = "same-public-label"; dependencies = []; };
    acquisition = Option::Some(Acquisition { sources = [source_request("https://example.test/source", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1024)]; });
    build = Option::Some(Build { profile = BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 30; source_format = BuildSourceFormat::Raw; produces = ["out"];
        steps = [BuildStep::Write(BuildFile { path = BuildPath::Output("out", "share/message"); text = build_text(message); })]; });
    commands = [Command { name = "fixture"; output = "out"; path = "share/message"; }];
} }
pub fn variant(message: BuildLiteral) -> RecipeRef<Recipe> { recipe_ref(fn() -> Recipe { recipe(message) }) }
pub let fixture = variant("authorized bytes");
"#;
fn checks() -> CheckConfiguration {
    CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    }
}
fn plan(project: &Path, export: &str) -> PreparedPlan {
    crate::project::lock_project_with(project, &checks()).unwrap();
    let locked = crate::project::open_locked_project_with(project, &checks()).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package(export).unwrap());
    evaluation.into_selected_prepared_plan().unwrap()
}
struct Fixture {
    temp: tempfile::TempDir,
    prepared: PreparedPlan,
    reference: PlanOutputRef,
    descriptor: ArtifactDescriptor,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let catalog = temp.path().join("catalog");
        fs::create_dir(&catalog).unwrap();
        fs::write(catalog.join("main.srx"), RECIPE).unwrap();
        let prepared = plan(&catalog, "fixture");
        let package = prepared
            .plan()
            .packages()
            .find(|package| package.has_export("fixture"))
            .unwrap();
        let reference = PlanOutputRef {
            package: package.id().clone(),
            output: "out".into(),
        };
        let recipe_sha256 = fingerprints(&prepared).unwrap()[package.id()].clone();
        let source_pin = prepared.recipe_source_pin(package).unwrap();
        assert_eq!(
            source_pin,
            ContentDigest::sha256(&fs::read(catalog.join("Syrox.lock")).unwrap())
        );
        let store = Store::initialize(&temp.path().join("producer")).unwrap();
        let path = b"share/message";
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
        let action = ContentDigest::sha256(b"qualified action");
        let manifest = ResultManifest::parse(format!("syrox-result-v2\n{{\"outputs\":{{\"application\":{{\"action\":\"{action}\",\"output\":\"out\",\"artifact\":\"{artifact}\",\"files\":1}}}},\"commands\":{{\"fixture\":{{\"application\":\"application\",\"application_path\":\"share/message\",\"loader\":null,\"loader_path\":null,\"libraries\":[]}}}}}}\n").as_bytes()).unwrap();
        let root = RootName::new("producer").unwrap();
        let cancel = Cancellation::default();
        let digest = manifest.digest().unwrap();
        crate::result::admit_result(&store, &root, &manifest, digest, &cancel).unwrap();
        let mut bundle = Vec::new();
        crate::bundle::export_bundle(&store, &root, digest, &mut bundle, &cancel).unwrap();
        fs::write(temp.path().join("fixture.bundle"), &bundle).unwrap();
        let package = crate::catalog::PackageVersion {
            name: "fixture".into(),
            version: "1.0.0".into(),
            variant: "default".into(),
            system: "linux-x86_64-gnu".into(),
            source_url: "https://example.test/source".into(),
            source_sha256: "a".repeat(64),
            source_maximum_bytes: 1024,
            signature_url: None,
            recipe: "main.srx".into(),
            factory: "fixture".into(),
            export: "fixture".into(),
            source: "main.srx".into(),
            contract: "contract.srx".into(),
            contract_type: "Settings".into(),
            toolchain: "toolchain.toml".into(),
            qualification: None,
            recipe_inputs: vec![],
        };
        let inputs = BTreeMap::from([(
            "main.srx".into(),
            ContentDigest::sha256(RECIPE.as_bytes()).to_string(),
        )]);
        let identity =
            ContentDigest::sha256(&serde_json::to_vec(&(&package, &inputs)).unwrap()).to_string();
        let descriptor = ArtifactDescriptor {
            schema: 1,
            catalog_lock_sha256: ContentDigest::sha256(b"catalog lock").to_string(),
            project_lock_sha256: source_pin.to_string(),
            release_sha256: ContentDigest::sha256(b"qualified release").to_string(),
            entries: vec![ArtifactEntry {
                locked: crate::catalog::LockedVersion {
                    package,
                    inputs,
                    identity,
                },
                recipe_sha256: recipe_sha256.clone(),
                bundle: "fixture.bundle".into(),
                bundle_sha256: ContentDigest::sha256(&bundle).to_string(),
                manifest_sha256: digest.to_string(),
                manifest,
                toolchain: ContentDigest::sha256(b"toolchain").to_string(),
                outputs: vec![ArtifactOutput {
                    recipe_sha256,
                    output: "out".into(),
                    key: "application".into(),
                }],
            }],
        };
        Self {
            temp,
            prepared,
            reference,
            descriptor,
        }
    }
    fn user(&self, policy: &str, store: &str) -> UserConfiguration {
        let bytes = self.descriptor.encode().unwrap();
        let descriptor = self.temp.path().join("artifacts.json");
        fs::write(&descriptor, &bytes).unwrap();
        UserConfiguration::parse(&format!("[artifacts]\npolicy = \"{policy}\"\ndescriptor = {:?}\ndescriptor-sha256 = \"{}\"\n",descriptor,ContentDigest::sha256(&bytes)),self.temp.path().join(store)).unwrap()
    }
}

#[test]
fn catalog_owned_input_alias_survives_consumer_edits_but_local_wrapper_is_not_authority() {
    let fixture = Fixture::new();
    let user = fixture.user("require", "receiver");
    let project = fixture.temp.path().join("consumer");
    fs::create_dir(&project).unwrap();
    for extra in ["", "let unrelated = 42;"] {
        fs::write(project.join("main.srx"),format!("inputs {{ pkgs = \"path:../catalog\"; }}\npub let selected = pkgs::fixture;\n{extra}\n")).unwrap();
        let prepared = plan(&project, "selected");
        let package = prepared
            .plan()
            .packages()
            .find(|package| package.has_export("selected"))
            .unwrap();
        assert_eq!(
            prepared
                .recipe_source_pin(package)
                .unwrap()
                .to_string(),
            fixture.descriptor.project_lock_sha256
        );
        let reference = PlanOutputRef {
            package: package.id().clone(),
            output: "out".into(),
        };
        assert!(
            ArtifactSelection::resolve(&prepared, user.artifacts())
                .unwrap()
                .select(&reference)
                .unwrap()
                .is_some()
        );
    }
    // Copying the ID and exact build program into the consumer does not give it
    // the source owner's authority. Neither does a caller-created lazy wrapper.
    for source in [
        format!("{RECIPE}\nlet copied = true;\n"),
        "inputs { pkgs = \"path:../catalog\"; }\npub let fixture = recipe_ref(fn() -> Recipe { recipe_value(pkgs::fixture) });".into(),
        "inputs { pkgs = \"path:../catalog\"; }\npub let fixture = pkgs.variant(\"different program\");".into(),
    ] {
        fs::write(project.join("main.srx"),&source).unwrap();
        let prepared=plan(&project,"fixture");
        let package=prepared.plan().packages().find(|package|package.has_export("fixture")).unwrap();
        if source.contains("different program") {
            assert_eq!(prepared.recipe_source_pin(package).unwrap().to_string(),fixture.descriptor.project_lock_sha256);
        }
        let reference=PlanOutputRef{package:package.id().clone(),output:"out".into()};
        assert!(matches!(ArtifactSelection::resolve(&prepared,user.artifacts()).unwrap().select(&reference),Err(ArtifactError::Missing(_))));
    }
}

#[test]
fn automatic_import_preserves_provenance_and_offline_cache_without_worker_or_receipt() {
    let fixture = Fixture::new();
    let user = fixture.user("require", "receiver");
    let resolved =
        crate::realize::resolve_plan_output(&fixture.prepared, &fixture.reference).unwrap();
    let realize = || {
        crate::realize::realize_output(
            &resolved,
            crate::realize::RealizeOptions {
                configuration: &user,
                worker: Path::new("/missing-worker"),
                offline: true,
            },
            &Cancellation::default(),
            |_| panic!("must not build"),
        )
        .unwrap()
    };
    let output = realize();
    assert!(matches!(
        output.identity().origin,
        OutputOrigin::Imported { .. }
    ));
    assert_eq!(
        output
            .read_file("share/message", 4096, &Cancellation::default())
            .unwrap(),
        crate::runtime::tests::elf(2, None, &[], None, None)
    );
    let store = Store::open(user.store()).unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .verify(output.action())
            .unwrap()
            .is_none()
    );
    fs::remove_file(fixture.temp.path().join("fixture.bundle")).unwrap();
    assert_eq!(realize().identity(), output.identity());
}

#[test]
fn prefer_falls_back_only_for_absence_and_require_refuses_absence() {
    let fixture = Fixture::new();
    let prefer = fixture.user("prefer", "receiver");
    let resolved =
        crate::realize::resolve_plan_output(&fixture.prepared, &fixture.reference).unwrap();
    fs::write(
        fixture.temp.path().join("fixture.bundle"),
        b"corrupt",
    )
    .unwrap();
    let run = |user: &UserConfiguration| {
        crate::realize::realize_output(
            &resolved,
            crate::realize::RealizeOptions {
                configuration: user,
                worker: Path::new("/missing-worker"),
                offline: true,
            },
            &Cancellation::default(),
            |_| {},
        )
    };
    assert!(matches!(
        run(&prefer),
        Err(crate::realize::RealizeError::Artifact(error)) if matches!(*error, ArtifactError::Invalid(_))
    ));
    fs::remove_file(fixture.temp.path().join("fixture.bundle")).unwrap();
    assert!(matches!(
        run(&prefer),
        Err(crate::realize::RealizeError::MissingToolchain)
    ));
    let require = fixture.user("require", "required");
    assert!(matches!(
        run(&require),
        Err(crate::realize::RealizeError::Artifact(error)) if matches!(*error, ArtifactError::Missing(_))
    ));
}

#[test]
fn changed_descriptor_and_conflicting_closure_are_rejected_before_store() {
    let mut fixture = Fixture::new();
    let user = fixture.user("prefer", "receiver");
    fs::write(fixture.temp.path().join("artifacts.json"), b"{}").unwrap();
    assert!(ArtifactSelection::resolve(&fixture.prepared, user.artifacts()).is_err());
    assert!(!user.store().exists());
    let mut second = fixture.descriptor.entries[0].clone();
    second.locked.package.version = "2.0.0".into();
    second.locked.identity = ContentDigest::sha256(
        &serde_json::to_vec(&(&second.locked.package, &second.locked.inputs)).unwrap(),
    )
    .to_string();
    let mut value = serde_json::to_value(&second.manifest).unwrap();
    value["outputs"]["application"]["action"] = ContentDigest::sha256(b"other toolchain output")
        .to_string()
        .into();
    second.manifest = serde_json::from_value(value).unwrap();
    second.manifest_sha256 = second.manifest.digest().unwrap().to_string();
    fixture.descriptor.entries.push(second);
    let user = fixture.user("prefer", "receiver");
    assert!(
        matches!(ArtifactSelection::resolve(&fixture.prepared,user.artifacts()),Err(ArtifactError::Invalid(message)) if message.contains("shared runtime output"))
    );
}

#[test]
fn artifact_configuration_is_strict_and_defaults_to_compile() {
    let root = Path::new("/tmp/unused-artifact-config-test");
    assert_eq!(
        UserConfiguration::parse("", root.to_owned())
            .unwrap()
            .artifacts()
            .policy(),
        crate::config::ArtifactPolicy::Compile
    );
    for text in [
        "[artifacts]\npolicy='maybe'",
        "[artifacts]\npolicy='require'",
        "[artifacts]\npolicy='prefer'\ndescriptor='/tmp/a'",
        "[artifacts]\nunknown=true",
    ] {
        assert!(UserConfiguration::parse(text, root.to_owned()).is_err());
    }
}

#[test]
fn shared_output_can_use_another_authorized_bundle_on_a_miss_but_not_corruption() {
    let mut fixture = Fixture::new();
    let mut second = fixture.descriptor.entries[0].clone();
    second.locked.package.version = "2.0.0".into();
    second.locked.identity = ContentDigest::sha256(
        &serde_json::to_vec(&(&second.locked.package, &second.locked.inputs)).unwrap(),
    )
    .to_string();
    second.bundle = "other.bundle".into();
    fixture.descriptor.entries.push(second);
    fs::rename(
        fixture.temp.path().join("fixture.bundle"),
        fixture.temp.path().join("other.bundle"),
    )
    .unwrap();
    let user = fixture.user("require", "receiver");
    let store = Store::initialize(user.store()).unwrap();
    let selection = ArtifactSelection::resolve(&fixture.prepared, user.artifacts()).unwrap();
    let selected = selection
        .select(&fixture.reference)
        .unwrap()
        .unwrap();
    assert!(
        selected
            .import(&store, &Cancellation::default())
            .unwrap()
            .is_some()
    );
    fs::write(
        fixture.temp.path().join("fixture.bundle"),
        b"corrupt preferred transport",
    )
    .unwrap();
    let other = Store::initialize(&fixture.temp.path().join("empty")).unwrap();
    assert!(matches!(
        selected.import(&other, &Cancellation::default()),
        Err(ArtifactError::Invalid(_))
    ));
}

#[test]
fn authorizer_selects_exact_factory_and_rejects_stale_locks_or_failed_qualification() {
    let fixture = Fixture::new();
    let catalog_path = fixture.temp.path().join("catalog");
    fs::create_dir(catalog_path.join("recipes")).unwrap();
    fs::write(
        catalog_path.join("recipes/contract.srx"),
        "pub struct Settings {}\n",
    )
    .unwrap();
    fs::write(catalog_path.join("main.srx"),format!(r#"
inputs {{ catalog = "modules:recipes"; }}
{RECIPE}
pub struct Selection {{ version: PackagePinText; variant: PackagePinText; system: PackagePinText; }}
pub fn select(request: Selection) -> PackageRef<catalog::contract::Settings> {{
    package_ref(variant("authorized bytes"), request.version, request.variant, request.system, "contract-pin", fn(settings: catalog::contract::Settings) -> ConfigText {{ ConfigText("") }})
}}
"#)).unwrap();
    fs::write(
        catalog_path.join("toolchain.toml"),
        "build_system = \"linux-x86_64-gnu\"\nresult_system = \"linux-x86_64-gnu\"\n",
    )
    .unwrap();
    let mut package = fixture.descriptor.entries[0]
        .locked
        .package
        .clone();
    package.factory = "select".into();
    package.export = "historical_alias_is_not_the_factory".into();
    package.contract = "recipes/contract.srx".into();
    let catalog = crate::catalog::Catalog {
        schema: 1,
        defaults: BTreeMap::from([("fixture".into(), "1.0.0".into())]),
        channels: vec![crate::catalog::Channel {
            name: "fixture".into(),
            releases: "https://example.test/releases".into(),
            origin: "https://example.test/".into(),
            archive_prefix: "fixture-".into(),
            archive_suffix: ".tar.gz".into(),
            signing_key: None,
            key_file: None,
            release_policy: "numeric".into(),
        }],
        packages: vec![package],
    };
    fs::write(
        catalog_path.join("catalog.toml"),
        toml::to_string(&catalog).unwrap(),
    )
    .unwrap();
    let lock = catalog.lock(&catalog_path).unwrap();
    fs::write(
        catalog_path.join("Catalog.lock"),
        lock.encode().unwrap(),
    )
    .unwrap();
    crate::project::lock_project_with(&catalog_path, &checks()).unwrap();
    let entry = &fixture.descriptor.entries[0];
    fs::copy(
        fixture.temp.path().join("fixture.bundle"),
        fixture
            .temp
            .path()
            .join(format!("{}.bundle", lock.versions[0].identity)),
    )
    .unwrap();
    let app = &entry.manifest.outputs()["application"];
    let mut release = serde_json::json!({"schema":1,"catalog_lock_sha256":ContentDigest::sha256(&fs::read(catalog_path.join("Catalog.lock")).unwrap()).to_string(),"project_lock_sha256":ContentDigest::sha256(&fs::read(catalog_path.join("Syrox.lock")).unwrap()).to_string(),"packages":[{"schema":1,"identity":lock.versions[0].identity,"name":"fixture","version":"1.0.0","variant":"default","system":"linux-x86_64-gnu","native_execution":true,"offline_import_and_execution":true,"service_preparation":false,"bundle_sha256":entry.bundle_sha256,"manifest":entry.manifest_sha256,"toolchain":entry.toolchain,"action":app.action.to_string(),"artifact":app.artifact.to_string()}]});
    let release_path = fixture.temp.path().join("release.json");
    fs::write(
        &release_path,
        serde_json::to_vec(&release).unwrap(),
    )
    .unwrap();
    let authorize = || {
        authorize_artifacts(
            &catalog_path,
            &release_path,
            fixture.temp.path(),
            &checks(),
            &Cancellation::default(),
        )
    };
    let descriptor = authorize().unwrap();
    assert_eq!(descriptor.entries.len(), 1);
    assert_ne!(
        descriptor.entries[0].recipe_sha256,
        entry.recipe_sha256
    );
    release["packages"][0]["native_execution"] = false.into();
    fs::write(
        &release_path,
        serde_json::to_vec(&release).unwrap(),
    )
    .unwrap();
    assert!(
        matches!(authorize(),Err(ArtifactError::Invalid(message)) if message.contains("successful qualification"))
    );
    release["packages"][0]["native_execution"] = true.into();
    fs::write(
        &release_path,
        serde_json::to_vec(&release).unwrap(),
    )
    .unwrap();
    fs::write(
        catalog_path.join("toolchain.toml"),
        "changed toolchain bytes",
    )
    .unwrap();
    assert!(
        matches!(authorize(),Err(ArtifactError::Invalid(message)) if message.contains("catalog lock"))
    );
}
