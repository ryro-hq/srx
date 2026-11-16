use super::*;
use crate::{
    config::UserConfiguration,
    project::{
        AuthenticatedStandardLibrary, CheckConfiguration, lock_project_with, plan_project_with,
    },
    store::GcRequest,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
};

mod resources;
mod scratch;

#[test]
#[cfg(target_arch = "x86_64")]
fn payload_record_binds_administrator_policy_action_and_helper_roles_canonically() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    namespace::test_record(&inputs).unwrap();
    assert_eq!(fixture.operations(), 0);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn source_archive_inspection_binds_declared_pin_and_budget_without_helper_or_attempt() {
    let mut fixture = fixture(12);
    let mut header = [0_u8; 512];
    let name = b"component-1/file";
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000005\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&header).unwrap();
    encoder.write_all(b"hello").unwrap();
    encoder.write_all(&[0; 507]).unwrap();
    encoder.write_all(&[0; 1024]).unwrap();
    let bytes = encoder.finish().unwrap();
    let old = ContentDigest::sha256(&[0x5a; 12]);
    let pin = ContentDigest::sha256(&bytes);
    let path = fixture.directory.path().join("main.srx");
    let declaration = fs::read_to_string(&path)
        .unwrap()
        .replace(&old.to_string(), &pin.to_string())
        .replace(
            "std::BuildSourceFormat::Raw;",
            "std::BuildSourceFormat::Gzip;",
        );
    fs::write(path, declaration).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(fixture.directory.path(), &checks).unwrap();
    fixture.plan = plan_project_with(fixture.directory.path(), &checks).unwrap();
    fixture.request = fixture
        .plan
        .builds()
        .find(|b| b.package().as_str() == "system-component")
        .unwrap()
        .request();
    fixture
        .store
        .operation()
        .unwrap()
        .ingest(bytes.as_slice(), pin, bytes.len() as u64)
        .unwrap();
    let prepared = fixture.prepare().unwrap();
    let limits = prepared.action().source_archive_limits().unwrap();
    assert_eq!(limits.budget(), prepared.action().budget());
    assert_eq!(
        limits.limits().compressed_bytes,
        prepared.action().source_limit()
    );
    let inventory = prepared
        .inspect_source_archive(&Cancellation::default())
        .unwrap();
    assert_eq!(inventory.entries(), 1);
    assert_eq!(inventory.expanded_bytes(), 5);
    assert_eq!(fixture.operations(), 0);
    let source = fixture.directory.path().join(format!(
        "store/objects/sha256/{}/{pin}",
        &pin.to_string()[..2]
    ));
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(source, b"changed").unwrap();
    assert!(matches!(
        prepared.inspect_source_archive(&Cancellation::default()),
        Err(BuildError::InputChanged)
    ));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn source_archive_raw_format_and_cancellation_do_not_create_an_attempt() {
    let fixture = fixture(12);
    let prepared = fixture.prepare().unwrap();
    assert!(matches!(
        prepared.action().source_archive_limits(),
        Err(BuildError::InvalidRequest)
    ));
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        prepared.inspect_source_archive(&cancelled),
        Err(BuildError::Cancelled)
    ));
    assert_eq!(fixture.operations(), 0);
}

fn worker() -> Vec<u8> {
    // A minimal static ELF parser fixture, not an implemented System worker.
    let mut bytes = vec![0; 129];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_0078_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&129_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&129_u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    bytes[120..].copy_from_slice(&[
        0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05,
    ]);
    crate::runtime::validate_static_worker_image(&bytes).unwrap();
    bytes
}

struct Fixture {
    directory: tempfile::TempDir,
    plan: Plan,
    request: BuildSpecification,
    store: Store,
    configuration: SystemBuildConfiguration,
    worker: Vec<u8>,
}

fn configuration(pin: ContentDigest) -> SystemBuildConfiguration {
    configuration_at(pin, "/run/syrox/system-helper.sock")
}

fn configuration_at(pin: ContentDigest, endpoint: &str) -> SystemBuildConfiguration {
    let text = format!(
        "[build.system]\nworker='/explicit/system-worker'\nworker-sha256='{pin}'\nscope='user'\nuser-bus='/explicit/bus'\nsocket-parent='/explicit/sockets'\nhelper-socket='/run/syrox/system-helper.sock'\n[build.system.maximum]\nmemory-bytes=1073741824\ncpu-percent=100\nprocesses=256\ndescriptors=1024\nscratch-bytes=1073741824\nfiles=100000\noutput-bytes=268435456\nduration-seconds=7200\n"
    );
    let text = text.replace("/run/syrox/system-helper.sock", endpoint);
    UserConfiguration::parse(&text, "/explicit/store".into())
        .unwrap()
        .system_build()
        .unwrap()
        .clone()
}

fn fixture(size: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let mut hash = Sha256::new();
    let buffer = vec![0x5a; 64 * 1024];
    let mut remaining = size;
    while remaining != 0 {
        let n = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    let pin = ContentDigest::from_sha256_hash(hash.finalize().into());
    let component = format!(
        r#"fn component() -> std::Recipe {{ std::Recipe {{
        package = std::Package {{ id = "system-component"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [std::SourceRequest {{ url = "https://example.invalid/system-source"; sha256 = "{pin}"; maximum_bytes = 67108864; }}]; }});
        build = std::Option::Some(std::Build {{ profile = std::BuildProfile::Managed; source_directory = "component-1"; timeout_seconds = 120; source_format = std::BuildSourceFormat::Raw;
            steps = [std::BuildStep::Directory(std::BuildPath::Work("build"))]; }});
    }} }}
    "#
    );
    let outside = component
        .replace("fn component()", "fn make_outside()")
        .replace("id = \"system-component\"", "id = \"outside\"");
    let published = "mod factories::outside { pub fn recipe() -> std::Recipe { project::make_outside() } } pub publish(factories, recipe): std::Recipe;";
    let reference = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../syrox/tests/system/plan-system.srx"
    ));
    let (_, declaration) = reference.split_once("let selected =").unwrap();
    fs::write(
        directory.path().join("main.srx"),
        component + &outside + published + "let selected =" + declaration,
    )
    .unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(directory.path(), &checks).unwrap_or_else(|e| panic!("fixture lock: {e}"));
    let plan = plan_project_with(directory.path(), &checks)
        .unwrap_or_else(|e| panic!("fixture plan: {e}"));
    let request = plan
        .builds()
        .find(|b| b.package().as_str() == "system-component")
        .unwrap()
        .request();
    let store = Store::initialize(&directory.path().join("store")).unwrap();
    store
        .operation()
        .unwrap()
        .ingest(std::io::repeat(0x5a).take(size), pin, size)
        .unwrap();
    let worker = worker();
    let configuration = configuration(ContentDigest::sha256(&worker));
    Fixture {
        directory,
        plan,
        request,
        store,
        configuration,
        worker,
    }
}

impl Fixture {
    fn prepare(&self) -> Result<SystemBuildInputs, BuildError> {
        prepare_system_build_inputs(
            &self.plan,
            "system",
            &self.request,
            &self.store,
            &self.configuration,
            &self.worker,
            &Cancellation::default(),
        )
    }
    fn operations(&self) -> usize {
        fs::read_dir(
            self.directory
                .path()
                .join("store/.syrox-store/builds"),
        )
        .map_or(0, Iterator::count)
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn prepared_action_workspace_preserves_locked_budget_and_does_not_contact_helper() {
    let fixture = fixture(12);
    let prepared = fixture.prepare().unwrap();
    let action = prepared.action();
    let before = action.encode();
    let workspace = action.workspace_layout().unwrap();
    assert_eq!(workspace.budget(), action.budget());
    assert_eq!(
        workspace.scratch_geometry().image_bytes(),
        1_073_741_824
    );
    assert_eq!(
        workspace.output_geometry().image_bytes(),
        268_435_456
    );
    assert!(
        workspace.scratch_geometry().requested_inodes()
            + workspace.output_geometry().requested_inodes()
            <= 100_000
    );
    let parsed = SystemBuildAction::parse(&before, action.budget()).unwrap();
    assert_eq!(parsed.workspace_layout().unwrap(), workspace);
    assert_eq!(before, action.encode());
    assert_eq!(fixture.operations(), 0);
    prepared
        .revalidate(&Cancellation::default())
        .unwrap();
}

#[test]
fn preparation_binds_real_source_and_effective_system_budget_without_creating_an_attempt() {
    let fixture = fixture(12);
    let prepared = fixture.prepare().unwrap();
    let action = prepared.action();
    assert_eq!(action.program(), &fixture.request.program);
    assert_eq!(action.source_directory(), "component-1");
    assert_eq!(action.budget().request().duration_seconds, 7200);
    assert_eq!(fixture.request.timeout_seconds, 120);
    assert_eq!(action.source_limit(), 64 * 1024 * 1024);
    assert_eq!(prepared.source_size(), 12);
    assert_eq!(
        SystemBuildAction::parse(&action.encode(), action.budget()).unwrap(),
        *action
    );
    assert!(Action::parse(&action.encode()).is_err());
    let mut source = File::from(
        prepared
            .source_descriptor(&Cancellation::default())
            .unwrap(),
    );
    assert!(source.write_all(b"unwritable").is_err());
    let mut bytes = Vec::new();
    source.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, [0x5a; 12]);
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn system_source_exceeds_common_standard_limit_without_raising_the_ordinary_limit() {
    let fixture = fixture(17 * 1024 * 1024 + 19);
    assert_eq!(
        fixture.request.program.maximum_source_bytes(),
        16 * 1024 * 1024
    );
    assert!(
        crate::build::managed::prepare_managed_build_inputs(
            &fixture.plan,
            &fixture.request,
            &fixture.store,
            &fixture.worker,
            &Cancellation::default()
        )
        .is_err()
    );
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.source_size(), 17 * 1024 * 1024 + 19);
    prepared
        .revalidate(&Cancellation::default())
        .unwrap();
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn source_custody_allows_gc_and_outlives_only_the_preparation_owner() {
    let fixture = fixture(12);
    let prepared = fixture.prepare().unwrap();
    let pin = prepared.action().source_digest();
    let gc = || {
        let report = fixture
            .store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .unwrap();
        assert!(!report.uncertain);
        assert!(report.failures.is_empty());
    };
    gc();
    assert!(
        fixture
            .store
            .operation()
            .unwrap()
            .verify(pin)
            .unwrap()
            .is_some()
    );
    prepared
        .revalidate(&Cancellation::default())
        .unwrap();
    drop(prepared);
    gc();
    assert!(
        fixture
            .store
            .operation()
            .unwrap()
            .verify(pin)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        fixture.prepare(),
        Err(BuildError::MissingSource)
    ));
}

#[test]
fn scope_request_worker_and_policy_mismatches_never_create_an_operation() {
    let fixture = fixture(12);
    let outside = fixture
        .plan
        .builds()
        .find(|b| b.package().as_str() == "outside")
        .unwrap()
        .request();
    assert!(!belongs_to_system(
        &fixture.plan,
        fixture.plan.systems().next().unwrap(),
        &outside.package
    ));
    assert!(
        prepare_system_build_inputs(
            &fixture.plan,
            "system",
            &outside,
            &fixture.store,
            &fixture.configuration,
            &fixture.worker,
            &Cancellation::default()
        )
        .is_err()
    );
    assert!(
        prepare_system_build_inputs(
            &fixture.plan,
            "missing",
            &fixture.request,
            &fixture.store,
            &fixture.configuration,
            &fixture.worker,
            &Cancellation::default()
        )
        .is_err()
    );
    assert!(
        prepare_system_build_inputs(
            &fixture.plan,
            "system",
            &fixture.request,
            &fixture.store,
            &configuration(ContentDigest::sha256(b"different")),
            &fixture.worker,
            &Cancellation::default()
        )
        .is_err()
    );
    for changed in 0..3 {
        let mut request = fixture.request.clone();
        match changed {
            0 => request.timeout_seconds += 1,
            1 => request.source_directory = "different".into(),
            2 => request.program.profile = BuildProfile::HostBootstrap,
            _ => unreachable!(),
        }
        assert!(
            prepare_system_build_inputs(
                &fixture.plan,
                "system",
                &request,
                &fixture.store,
                &fixture.configuration,
                &fixture.worker,
                &Cancellation::default()
            )
            .is_err()
        );
    }
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn source_changes_and_cancellation_cannot_handoff_a_prepared_descriptor() {
    let fixture = fixture(12);
    let prepared = fixture.prepare().unwrap();
    let pin = prepared.action().source_digest().to_string();
    let path = fixture.directory.path().join(format!(
        "store/objects/sha256/{}/{pin}",
        &pin[..2]
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, [0x41; 12]).unwrap();
    assert!(
        prepared
            .revalidate(&Cancellation::default())
            .is_err()
    );
    assert!(
        prepared
            .source_descriptor(&Cancellation::default())
            .is_err()
    );
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        prepare_system_build_inputs(
            &fixture.plan,
            "system",
            &fixture.request,
            &fixture.store,
            &fixture.configuration,
            &fixture.worker,
            &cancel
        ),
        Err(BuildError::Cancelled)
    ));
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn service_local_packages_and_transitive_build_inputs_belong_to_the_system() {
    for service in [false, true] {
        let mut fixture = fixture(12);
        let path = fixture.directory.path().join("main.srx");
        let source = fs::read_to_string(&path).unwrap();
        let source = if service {
            source.replace("services = std::Services { pkgs = []; services = []; };", "services = std::Services { pkgs = []; services = [std::Service { id = \"data\"; pkgs = [std::select_package(outside)]; }]; };")
        } else {
            source.replacen("package = std::Package", "build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(outside, \"out\")]; }); package = std::Package", 1)
        };
        assert_ne!(source, fs::read_to_string(&path).unwrap());
        fs::write(path, source).unwrap();
        let checks = CheckConfiguration {
            standard_library: Some(AuthenticatedStandardLibrary::bundled()),
            ..CheckConfiguration::default()
        };
        lock_project_with(fixture.directory.path(), &checks)
            .unwrap_or_else(|e| panic!("fixture lock: {e}"));
        fixture.plan = plan_project_with(fixture.directory.path(), &checks)
            .unwrap_or_else(|e| panic!("fixture plan: {e}"));
        let outside = fixture
            .plan
            .builds()
            .find(|b| b.package().as_str() == "outside")
            .unwrap()
            .request();
        assert!(belongs_to_system(
            &fixture.plan,
            fixture.plan.systems().next().unwrap(),
            &outside.package
        ));
        prepare_system_build_inputs(
            &fixture.plan,
            "system",
            &outside,
            &fixture.store,
            &fixture.configuration,
            &fixture.worker,
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(fixture.operations(), 0);
    }
}

#[test]
fn worker_format_and_budget_denials_precede_source_or_operation_access() {
    let fixture = fixture(12);
    let bad_image = b"not an ELF worker";
    assert!(matches!(
        prepare_system_build_inputs(
            &fixture.plan,
            "system",
            &fixture.request,
            &fixture.store,
            &configuration(ContentDigest::sha256(bad_image)),
            bad_image,
            &Cancellation::default()
        ),
        Err(BuildError::InvalidRequest)
    ));
    let text = format!(
        "[build.system]\nworker='/worker'\nworker-sha256='{}'\nscope='system'\nsocket-parent='/sockets'\nhelper-socket='/run/helper.sock'\n[build.system.maximum]\nmemory-bytes=1\ncpu-percent=1\nprocesses=1\ndescriptors=1\nscratch-bytes=1\nfiles=1\noutput-bytes=1\nduration-seconds=1",
        ContentDigest::sha256(&fixture.worker)
    );
    let denied = UserConfiguration::parse(&text, "/store".into()).unwrap();
    assert!(matches!(
        prepare_system_build_inputs(
            &fixture.plan,
            "system",
            &fixture.request,
            &fixture.store,
            denied.system_build().unwrap(),
            &fixture.worker,
            &Cancellation::default()
        ),
        Err(BuildError::Budget(_))
    ));
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn chunked_v3_tool_inputs_are_authenticated_and_bound_to_the_component_action() {
    use crate::result::{ResultManifest, admit_system_result, stage_system_output};
    use crate::store::RootName;
    let mut fixture = fixture(12);
    let cancel = Cancellation::default();
    let budget = fixture
        .configuration
        .admit(fixture.plan.systems().next().unwrap().budget)
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("tool-data"),
        b"declared tool input",
    )
    .unwrap();
    let output = stage_system_output(
        &fixture.store,
        File::open(directory.path()).unwrap(),
        ContentDigest::sha256(b"explicit input identity"),
        "out",
        &budget,
        &cancel,
    )
    .unwrap();
    let manifest = ResultManifest::for_system(
        BTreeMap::from([("data".into(), output.metadata().clone())]),
        BTreeMap::new(),
        &budget,
    )
    .unwrap();
    let pin = manifest.digest().unwrap();
    let admitted = admit_system_result(
        &fixture.store,
        &RootName::new("system_input").unwrap(),
        &manifest,
        pin,
        &budget,
        &cancel,
    )
    .unwrap();
    let provider = format!(
        r#"fn input_provider() -> std::Recipe {{ std::Recipe {{
        package = std::Package {{ id = "imported-tool"; dependencies = []; }};
        imported = std::Option::Some(std::ImportedResult {{ root = "system_input"; manifest = "{pin}";
            entries = [std::ImportedOutput {{ output = "out"; key = "data"; }}]; }});
    }} }}"#
    );
    let path = fixture.directory.path().join("main.srx");
    let source = fs::read_to_string(&path).unwrap().replacen("package = std::Package", "build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(std::recipe_ref(input_provider), \"out\")]; }); package = std::Package", 1);
    fs::write(path, provider + &source).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(fixture.directory.path(), &checks)
        .unwrap_or_else(|e| panic!("fixture lock: {e}"));
    fixture.plan = plan_project_with(fixture.directory.path(), &checks)
        .unwrap_or_else(|e| panic!("fixture plan: {e}"));
    fixture.request = fixture
        .plan
        .builds()
        .find(|b| b.package().as_str() == "system-component")
        .unwrap()
        .request();
    fixture.request.inputs = vec![crate::build::BuildInput {
        output: admitted.output("data").unwrap(),
    }];
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.action().selected_inputs().len(), 1);
    assert!(
        crate::build::managed::prepare_managed_build_inputs(
            &fixture.plan,
            &fixture.request,
            &fixture.store,
            &fixture.worker,
            &cancel
        )
        .is_err()
    );
    assert_eq!(
        prepared.action().selected_inputs()[0].artifact,
        output.metadata().artifact
    );
    assert_eq!(
        prepared.action().selected_inputs()[0].origin,
        crate::result::OutputOrigin::Imported {
            manifest: pin
        }
    );
    assert_eq!(
        prepared.inputs[0]
            .read_file("tool-data", 1024, &cancel)
            .unwrap(),
        b"declared tool input"
    );
    prepared.revalidate(&cancel).unwrap();
    assert!(
        prepared
            .chunked_input_descriptors(0, 1, &cancel)
            .is_err()
    );
    assert!(
        prepared
            .chunked_input_descriptors(1, 2, &cancel)
            .is_err()
    );
    assert!(matches!(
        prepared.chunked_input_descriptors(
            0,
            prepared.action().budget().request().descriptors + 1,
            &cancel
        ),
        Err(BuildError::InvalidRequest)
    ));
    let descriptors = prepared
        .chunked_input_descriptors(0, 2, &cancel)
        .unwrap();
    assert_eq!(
        descriptors.manifest_digest(),
        prepared.action().selected_inputs()[0].artifact
    );
    drop(admitted);
    drop(output);
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![RootName::new("system_input").unwrap()],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain);
    assert!(report.failures.is_empty());
    prepared.revalidate(&cancel).unwrap();
    let reader = crate::store::chunked::ChunkedDescriptorReader::from_received(
        descriptors.manifest_digest(),
        descriptors
            .descriptors()
            .iter()
            .map(|fd| fd.try_clone().unwrap())
            .collect(),
        prepared.inputs[0].artifact_limits().bytes,
        2,
        &cancel,
    )
    .unwrap();
    let mut indexed = crate::result::artifact::IndexedArtifact::open_with_limits(
        reader,
        "",
        prepared.inputs[0].artifact_limits(),
        &cancel,
    )
    .unwrap();
    let (files, reader) = indexed.parts();
    let file = files.find("tool-data").unwrap();
    let mut content = Vec::new();
    crate::result::artifact::IndexedArtifact::reader_from(reader, &file)
        .unwrap()
        .read_to_end(&mut content)
        .unwrap();
    assert_eq!(content, b"declared tool input");
    assert_eq!(
        prepared.inputs[0]
            .read_file("tool-data", 1024, &cancel)
            .unwrap(),
        b"declared tool input"
    );
    assert_eq!(fixture.operations(), 0);
}
