use super::*;
use crate::{
    result::{ResultManifest, admit_result, admit_system_result, stage_system_output},
    store::RootName,
};
use std::fmt::Write as _;
use std::{
    io::Seek as _,
    os::{
        fd::{AsFd as _, AsRawFd as _},
        unix::fs::MetadataExt as _,
    },
};

mod transfer;

fn imported(kinds: &[bool], files: usize) -> Fixture {
    let mut fixture = fixture(12);
    let cancellation = Cancellation::default();
    let budget = fixture
        .configuration
        .admit(fixture.plan.systems().next().unwrap().budget)
        .unwrap();
    let mut outputs = Vec::new();
    let mut providers = String::new();
    let mut selections = Vec::new();
    for (index, chunked) in kinds.iter().enumerate() {
        let tree = fixture
            .directory
            .path()
            .join(format!("input-{index}"));
        fs::create_dir(&tree).unwrap();
        for file in 0..files {
            fs::write(
                tree.join(format!("data_{file:06}")),
                format!("input-{index}-{file}"),
            )
            .unwrap();
        }
        let logical = ContentDigest::sha256(format!("provider-{index}").as_bytes());
        let root = RootName::new(format!("input_{index}")).unwrap();
        let manifest = if *chunked {
            let output = stage_system_output(
                &fixture.store,
                File::open(&tree).unwrap(),
                logical,
                "out",
                &budget,
                &cancellation,
            )
            .unwrap();
            ResultManifest::for_system(
                BTreeMap::from([("data".into(), output.metadata().clone())]),
                BTreeMap::new(),
                &budget,
            )
            .unwrap()
        } else {
            let mut bytes = Vec::new();
            crate::result::artifact::pack(&tree, &mut bytes).unwrap();
            let pin = ContentDigest::sha256(&bytes);
            fixture
                .store
                .operation()
                .unwrap()
                .ingest(bytes.as_slice(), pin, bytes.len() as u64)
                .unwrap();
            ResultManifest::parse(format!("syrox-package-result\n{{\"outputs\":{{\"data\":{{\"action\":\"{logical}\",\"output\":\"out\",\"artifact\":\"{pin}\",\"files\":{files}}}}},\"commands\":{{}}}}\n").as_bytes()).unwrap()
        };
        let pin = manifest.digest().unwrap();
        let admitted = if *chunked {
            admit_system_result(
                &fixture.store,
                &root,
                &manifest,
                pin,
                &budget,
                &cancellation,
            )
        } else {
            admit_result(
                &fixture.store,
                &root,
                &manifest,
                pin,
                &cancellation,
            )
        }
        .unwrap();
        outputs.push(crate::build::BuildInput {
            output: admitted.output("data").unwrap(),
        });
        write!(
            providers,
            r#"fn provider_{index}() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "provider-{index}"; dependencies = []; }};
            imported = std::Option::Some(std::ImportedResult {{ root = "{root}"; manifest = "{pin}";
                entries = [std::ImportedOutput {{ output = "out"; key = "data"; }}]; }});
        }} }} "#
        )
        .unwrap();
        selections.push(format!(
            "std::recipe_output(std::recipe_ref(provider_{index}), \"out\")"
        ));
    }
    let path = fixture.directory.path().join("main.srx");
    let source = fs::read_to_string(&path).unwrap().replacen("package = std::Package", &format!("build_inputs = std::Option::Some(std::BuildInputs {{ selected = [{}]; }}); package = std::Package", selections.join(", ")), 1);
    fs::write(path, providers + &source).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(fixture.directory.path(), &checks)
        .unwrap_or_else(|e| panic!("resource fixture lock: {e}"));
    fixture.plan = plan_project_with(fixture.directory.path(), &checks)
        .unwrap_or_else(|e| panic!("resource fixture plan: {e}"));
    fixture.request = fixture
        .plan
        .builds()
        .find(|b| b.package().as_str() == "system-component")
        .unwrap()
        .request();
    fixture.request.inputs = outputs;
    fixture
}

fn duplicate(resources: &SystemBuildInputResources) -> Vec<OwnedFd> {
    resources
        .descriptors()
        .iter()
        .map(|fd| fd.try_clone().unwrap())
        .collect()
}

fn receive(
    action: &SystemBuildAction,
    resources: &SystemBuildInputResources,
) -> SystemBuildInputResources {
    SystemBuildInputResources::from_received(
        action,
        resources.manifest_digest(),
        resources.manifest(),
        resources.reserved_descriptors(),
        duplicate(resources),
        &Cancellation::default(),
    )
    .unwrap()
}

#[test]
fn mixed_inputs_transfer_independent_retention_and_survive_sender_and_original_root_removal() {
    let fixture = imported(&[false, true], 2);
    let cancellation = Cancellation::default();
    let inputs = fixture.prepare().unwrap();
    let action = inputs.action().clone();
    let resources = inputs
        .prepare_input_resources(40, &cancellation)
        .unwrap();
    assert_eq!(resources.descriptors().len(), 6);
    assert_eq!(resources.action_digest(), action.digest());
    assert_eq!(
        SystemBuildInputResources::expected_descriptor_count(
            &action,
            resources.manifest_digest(),
            resources.manifest(),
            40
        )
        .unwrap(),
        6
    );
    for fd in resources.descriptors() {
        if File::from(fd.try_clone().unwrap())
            .metadata()
            .unwrap()
            .is_file()
        {
            File::from(fd.try_clone().unwrap())
                .seek(std::io::SeekFrom::End(0))
                .unwrap();
        }
    }
    let received = receive(&action, &resources);
    drop(resources);
    drop(inputs);
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![
                RootName::new("input_0").unwrap(),
                RootName::new("input_1").unwrap(),
            ],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    received.revalidate(&cancellation).unwrap();
    for index in 0..2 {
        let fd = received
            .view_descriptor(index, &cancellation)
            .unwrap();
        assert_eq!(
            fs::read(format!(
                "/proc/self/fd/{}/data_000000",
                fd.as_raw_fd()
            ))
            .unwrap(),
            format!("input-{index}-0").as_bytes()
        );
    }
    assert!(
        received
            .view_descriptor(2, &cancellation)
            .is_err()
    );
    let process_interest = received
        .retention_descriptor(&cancellation)
        .unwrap()
        .try_clone_to_owned()
        .unwrap();
    drop(received);
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    assert!(
        fixture
            .store
            .operation()
            .unwrap()
            .open_verified(action.source_digest(), 1024)
            .unwrap()
            .is_some()
    );
    drop(process_interest);
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    assert!(
        fixture
            .store
            .operation()
            .unwrap()
            .open_verified(action.source_digest(), 1024)
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn fd_budget_and_cancel_fail_before_an_interest_is_created() {
    let fixture = imported(&[false, true], 1);
    let inputs = fixture.prepare().unwrap();
    let interest_count = || {
        fs::read_dir(
            fixture
                .directory
                .path()
                .join("store/.syrox-store/interests"),
        )
        .unwrap()
        .count()
    };
    let before = interest_count();
    for reserve in [0, 31, 1019, 1024, u32::MAX] {
        assert!(matches!(
            inputs.prepare_input_resources(reserve, &Cancellation::default()),
            Err(BuildError::UnsupportedInputs)
        ));
        assert_eq!(interest_count(), before);
    }
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        inputs.prepare_input_resources(40, &cancel),
        Err(BuildError::Cancelled)
    ));
    assert_eq!(interest_count(), before);
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn authentic_manifest_is_required_before_any_descriptor_offer_is_accepted() {
    let fixture = imported(&[true], 1);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    let mut wire: serde_json::Value = serde_json::from_slice(
        resources
            .manifest()
            .splitn(2, |b| *b == b'\n')
            .nth(1)
            .unwrap(),
    )
    .unwrap();
    for key in ["slots", "reserved", "retention_inode"] {
        let old = wire[key].clone();
        wire[key] = serde_json::Value::from(u32::MAX);
        let mut bytes = b"syrox-system-input-resources\n".to_vec();
        bytes.extend(serde_json::to_vec(&wire).unwrap());
        assert!(
            SystemBuildInputResources::expected_descriptor_count(
                inputs.action(),
                resources.manifest_digest(),
                &bytes,
                40
            )
            .is_err()
        );
        wire[key] = old;
    }
    assert!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            resources.manifest_digest(),
            resources.manifest(),
            41,
            duplicate(&resources),
            &Cancellation::default()
        )
        .is_err()
    );
    let mut fds = duplicate(&resources);
    fds.pop();
    assert!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            resources.manifest_digest(),
            resources.manifest(),
            40,
            fds,
            &Cancellation::default()
        )
        .is_err()
    );
    let mut bytes = resources.manifest().to_vec();
    bytes.push(b'\n');
    assert!(
        SystemBuildInputResources::expected_descriptor_count(
            inputs.action(),
            ContentDigest::sha256(&bytes),
            &bytes,
            40
        )
        .is_err()
    );
}

#[test]
fn changed_view_chunk_and_byte_identical_fake_interest_are_refused() {
    let fixture = imported(&[true], 1);
    let inputs = fixture.prepare().unwrap();
    let cancel = Cancellation::default();
    let resources = inputs
        .prepare_input_resources(40, &cancel)
        .unwrap();
    let mut fds = duplicate(&resources);
    let retention = fds.last().unwrap();
    let mut bytes = Vec::new();
    File::from(retention.try_clone().unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    let path = fixture
        .directory
        .path()
        .join("same-interest-bytes");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let last = fds.len() - 1;
    fds[last] = File::open(&path).unwrap().into();
    assert!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            resources.manifest_digest(),
            resources.manifest(),
            40,
            fds,
            &cancel
        )
        .is_err()
    );
    let mut fds = duplicate(&resources);
    fds.swap(1, 2);
    assert!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            resources.manifest_digest(),
            resources.manifest(),
            40,
            fds,
            &cancel
        )
        .is_err()
    );
    let directory = inputs.inputs[0].directory().unwrap();
    fs::set_permissions(
        directory.join("data_000000"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(directory.join("data_000000"), b"changed view").unwrap();
    assert!(resources.revalidate(&cancel).is_err());
}

#[test]
fn wide_chunked_view_keeps_its_producer_limits_without_expanding_unchunked_inputs() {
    let fixture = imported(&[true], 16_385);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    let received = receive(inputs.action(), &resources);
    assert_eq!(resources.descriptors().len(), 4);
    assert!(
        received
            .view_descriptor(0, &Cancellation::default())
            .is_ok()
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
}

#[test]
fn canonical_resource_metadata_has_an_independent_fixed_identity_and_strict_fields() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    assert_eq!(
        inputs.action().digest().to_string(),
        "10be61616bd863239feec1d5332ae60c7fdd99af6add3164ac87d9547189f2ce"
    );
    // Independently assembled using Python hashlib/struct and the documented
    // ordered JSON schema; no real interest or worker authority is represented.
    let bytes = b"syrox-system-input-resources\n{\"action\":\"10be61616bd863239feec1d5332ae60c7fdd99af6add3164ac87d9547189f2ce\",\"reserved\":40,\"slots\":1,\"inputs\":[],\"retention\":\"828408e40d4fe651488b14696b60b613c9683ab9862e03f4e72aec7c1fda7635\",\"retention_device\":123,\"retention_inode\":456}";
    assert_eq!(bytes.len(), 266);
    let pin: ContentDigest = "f30f0ad4988e5d404b3b9d8f219894552d6476cf9ecedddf67d40349ddc3e624"
        .parse()
        .unwrap();
    assert_eq!(ContentDigest::sha256(bytes), pin);
    assert_eq!(
        SystemBuildInputResources::expected_descriptor_count(inputs.action(), pin, bytes, 40)
            .unwrap(),
        1
    );
    let text = std::str::from_utf8(bytes).unwrap();
    for bad in [text.replace("{\"action\"", "{\"version\":1,\"action\""), text.replace("\"slots\":1", "\"slots\":0"), text.replace("\"slots\":1", "\"slots\":1,\"slots\":1"), text.replace("\"slots\":1", "\"slots\":1,\"extra\":true"), text.replace("\"reserved\":40", "\"reserved\":31"), format!("{text}\n"), text.replace("\"inputs\":[]", "\"inputs\":[{\"storage\":\"blob\",\"artifact_slots\":1,\"maximum_bytes\":18446744073709551615,\"maximum_files\":1}]")] {
        assert!(SystemBuildInputResources::expected_descriptor_count(inputs.action(), ContentDigest::sha256(bad.as_bytes()), bad.as_bytes(), 40).is_err());
    }
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    let other = super::fixture(13);
    assert!(
        SystemBuildInputResources::from_received(
            other.prepare().unwrap().action(),
            resources.manifest_digest(),
            resources.manifest(),
            40,
            duplicate(&resources),
            &Cancellation::default()
        )
        .is_err()
    );
}

#[test]
fn receiver_checks_retention_coverage_even_when_its_hash_and_identity_match() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    let cancel = Cancellation::default();
    let resources = inputs
        .prepare_input_resources(40, &cancel)
        .unwrap();
    let operation = fixture.store.operation().unwrap();
    let unrelated = ContentDigest::sha256(b"unrelated");
    operation
        .ingest(b"unrelated".as_slice(), unrelated, 64)
        .unwrap();
    let interest = operation
        .retain_objects(&[unrelated], &[])
        .unwrap();
    drop(operation);
    let retained = interest.process_retention().unwrap();
    let metadata = retained.metadata().unwrap();
    let mut record = Vec::new();
    File::from(retained.as_fd().try_clone_to_owned().unwrap())
        .read_to_end(&mut record)
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(
        resources
            .manifest()
            .splitn(2, |b| *b == b'\n')
            .nth(1)
            .unwrap(),
    )
    .unwrap();
    let text = String::from_utf8(resources.manifest().to_vec())
        .unwrap()
        .replace(
            &format!("\"retention\":{}", original["retention"]),
            &format!(
                "\"retention\":\"{}\"",
                ContentDigest::sha256(&record)
            ),
        )
        .replace(
            &format!(
                "\"retention_device\":{}",
                original["retention_device"]
            ),
            &format!("\"retention_device\":{}", metadata.dev()),
        )
        .replace(
            &format!(
                "\"retention_inode\":{}",
                original["retention_inode"]
            ),
            &format!("\"retention_inode\":{}", metadata.ino()),
        );
    assert!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            ContentDigest::sha256(text.as_bytes()),
            text.as_bytes(),
            40,
            vec![retained.into()],
            &cancel
        )
        .is_err()
    );
}

#[test]
fn blob_corruption_and_cancellation_do_not_yield_a_usable_receiver() {
    let fixture = imported(&[false], 1);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            resources.manifest_digest(),
            resources.manifest(),
            40,
            duplicate(&resources),
            &cancel
        ),
        Err(BuildError::Cancelled)
    ));
    assert!(matches!(
        resources.revalidate(&cancel),
        Err(BuildError::Cancelled)
    ));
    let pin = inputs.action().selected_inputs()[0]
        .artifact
        .to_string();
    fs::write(
        fixture.directory.path().join(format!(
            "store/objects/sha256/{}/{pin}",
            &pin[..2]
        )),
        b"bad blob",
    )
    .unwrap();
    assert!(
        SystemBuildInputResources::from_received(
            inputs.action(),
            resources.manifest_digest(),
            resources.manifest(),
            40,
            duplicate(&resources),
            &Cancellation::default()
        )
        .is_err()
    );
}

#[test]
#[expect(
    unsafe_code,
    reason = "fcntl FFI clears close-on-exec on test-owned descriptor clones"
)]
fn directly_received_roles_are_normalized_to_close_on_exec() {
    let fixture = imported(&[true], 1);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    let fds = duplicate(&resources);
    for descriptor in &fds {
        // SAFETY: change only the descriptor-local flags of test-owned clones.
        assert_eq!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
    }
    let received = SystemBuildInputResources::from_received(
        inputs.action(),
        resources.manifest_digest(),
        resources.manifest(),
        40,
        fds,
        &Cancellation::default(),
    )
    .unwrap();
    for descriptor in received.descriptors() {
        // SAFETY: fixed integer observation on an owned, live description.
        assert_ne!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    received
        .revalidate(&Cancellation::default())
        .unwrap();
}
